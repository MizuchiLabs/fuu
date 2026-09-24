// Package vault is the on disk vault: one TOML file per repository, meant to
// be committed and passed around in public.
//
// Only four things are readable without the vault key: the format version,
// the vault identity, the write counter and the envelopes themselves. Key
// names never appear in the file. Values are addressed by a stable token
// derived from the name under the vault key, and the names plus the device
// registry live in one encrypted payload. A reader without the key learns how
// many entries there are and roughly how long they were, nothing else.
//
// The vault key never appears in the file. It is sealed once per device and
// once to the recovery passphrase, so enrolling or revoking a device rewrites
// a single block and leaves every secret value untouched.
package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/mizuchilabs/kata/fsutil"

	"github.com/mizuchilabs/fuu/internal/seal"
	"github.com/mizuchilabs/fuu/internal/sig"
)

const (
	Version      = 2
	vaultKeySize = 32

	// blobAAD and valueAAD bind encrypted bodies to their slot, so one cannot
	// be pasted over another.
	blobAAD  = "fuu/v2/blob"
	valueAAD = "fuu/v2/value\x00"
)

var (
	ErrNoDevice  = errors.New("no such device")
	ErrDupDevice = errors.New("public key already enrolled")
	ErrDupName   = errors.New("device name already taken")
	ErrLast      = errors.New("cannot revoke the last device, enroll another one first")
	ErrBadName   = errors.New("key is not a valid environment variable name")
	ErrEmptyPass = errors.New("recovery passphrase is empty")
	ErrNoKey     = errors.New("no such key")
	ErrNoSig     = errors.New("no signature over the vault contents")
	ErrNoSignPub = errors.New("device has no signing public key")
	// ErrTokenClash is unreachable in practice. It exists so two names can
	// never merge into one entry, however unlikely.
	ErrTokenClash = errors.New("two key names map to one token")
	errBadVersion = errors.New("unsupported version")

	// canonEscaper keeps every Canonical field on its own line, so no value can forge a line.
	canonEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

// Device is one enrolled chip's wrap of the vault key, addressed by the public
// key rather than a name, because names live in the encrypted payload.
type Device struct {
	Pub  string `toml:"pub"`
	EPub string `toml:"epub"`
	Wrap string `toml:"wrap"`
}

type Recovery struct {
	KDF  string `toml:"kdf"`
	Salt string `toml:"salt"`
	Mem  uint32 `toml:"mem"`
	Time uint32 `toml:"time"`
	Wrap string `toml:"wrap"`
}

// DeviceMeta is what the payload says about an enrolled chip.
type DeviceMeta struct {
	Name    string `toml:"name"`
	Created string `toml:"created"`
	SignPub string `toml:"signpub"`
}

// Payload is the encrypted half of the vault: the device names and the key
// names. Nothing here is readable without the vault key.
type Payload struct {
	Device map[string]DeviceMeta `toml:"device"`
	Names  []string              `toml:"names"`
}

// File is the whole vault. Everything but Version, VaultID and Seq is either
// an envelope or a token, so the readable surface is fixed.
type File struct {
	Version  int               `toml:"version"`
	VaultID  string            `toml:"vaultid"`
	Seq      uint64            `toml:"seq"`
	Blob     string            `toml:"blob"`
	Sig      string            `toml:"sig,omitempty"`
	Signer   string            `toml:"signer,omitempty"`
	Device   map[string]Device `toml:"device"`
	Recovery Recovery          `toml:"recovery"`
	Secret   map[string]string `toml:"secret"`

	raw     []byte
	payload *Payload
	dirty   bool
}

func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", path, err)
	}
	return Parse(data, path)
}

// Parse reads vault bytes and remembers them, so Digest reports exactly what
// was loaded rather than what a later encode would produce.
func Parse(data []byte, path string) (*File, error) {
	f := new(File)
	if err := toml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("vault: parse %s: %w", path, err)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("%w %d in %s, this build reads %d", errBadVersion, f.Version, path, Version)
	}
	if f.VaultID == "" {
		return nil, fmt.Errorf("vault: %s names no vault", path)
	}
	if f.Device == nil {
		f.Device = map[string]Device{}
	}
	// The map key is what lookups match a device by, so it has to be the key
	// the wrap is sealed to. A renamed slot would leave a device unable to find
	// its own wrap, so bind the two rather than trust the file to agree.
	for pub, d := range f.Device {
		if pub != d.Pub {
			return nil, fmt.Errorf("vault: %s device %q does not match its key %q", path, pub, d.Pub)
		}
	}
	if f.Secret == nil {
		f.Secret = map[string]string{}
	}
	f.raw = data
	return f, nil
}

// Digest is the hash of the bytes as loaded, the identity a stored signature
// and a stored write counter speak for.
func (f *File) Digest() string {
	sum := sha256.Sum256(f.raw)
	return hex.EncodeToString(sum[:])
}

func (f *File) Save(path string) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(f); err != nil {
		return fmt.Errorf("vault: encode: %w", err)
	}
	if err := fsutil.WriteIfChanged(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("vault: write %s: %w", path, err)
	}
	f.raw = buf.Bytes()
	return nil
}

// Canonical is the deterministic byte form the signature covers, built by hand
// so a TOML encoder upgrade cannot silently change what a stored signature
// means.
func (f *File) Canonical() []byte {
	var b strings.Builder
	b.WriteString("fuu/v2/vault\n")
	canonField(&b, "version", strconv.Itoa(f.Version))
	canonField(&b, "vaultid", f.VaultID)
	canonField(&b, "seq", strconv.FormatUint(f.Seq, 10))
	canonField(&b, "blob", f.Blob)
	for _, pub := range slices.Sorted(maps.Keys(f.Device)) {
		d := f.Device[pub]
		canonField(&b, "device", d.Pub)
		canonField(&b, "epub", d.EPub)
		canonField(&b, "wrap", d.Wrap)
	}
	r := f.Recovery
	canonField(&b, "kdf", r.KDF)
	canonField(&b, "salt", r.Salt)
	canonField(&b, "mem", strconv.FormatUint(uint64(r.Mem), 10))
	canonField(&b, "time", strconv.FormatUint(uint64(r.Time), 10))
	canonField(&b, "wrap", r.Wrap)
	for _, token := range slices.Sorted(maps.Keys(f.Secret)) {
		canonField(&b, "token", token)
		canonField(&b, "body", f.Secret[token])
	}
	return []byte(b.String())
}

// canonField writes one labeled line with the value escaped, so labels stay unambiguous and two different vaults cannot produce the same bytes.
func canonField(b *strings.Builder, label, value string) {
	b.WriteString(label)
	b.WriteByte(' ')
	b.WriteString(canonEscaper.Replace(value))
	b.WriteByte('\n')
}

// Stamp signs Canonical with sk and records the envelope.
func (f *File) Stamp(sk sig.Signer) error {
	env, err := sig.Sign(sk, f.Canonical())
	if err != nil {
		return fmt.Errorf("vault: stamp: %w", err)
	}
	f.Sig = env.Sig
	f.Signer = env.Signer
	return nil
}

// Verify checks the stored signature over Canonical against pubs, which must
// come from outside the file. Trust anchors read out of the vault being
// verified would let anyone who can write the file mint a self certified one,
// so callers pin the keys themselves and only pass ones they already trust.
func (f *File) Verify(pubs []*ecdsa.PublicKey) error {
	if f.Sig == "" {
		return ErrNoSig
	}
	if err := sig.Verify(pubs, f.Canonical(), sig.Envelope{Signer: f.Signer, Sig: f.Sig}); err != nil {
		return fmt.Errorf("vault: verify: %w", err)
	}
	return nil
}

// SignerPubs parses every enrolled device's signing key out of the payload.
// Reading them needs the vault key, so this is the key set the vault vouches
// for only after it has been opened.
func (f *File) SignerPubs(key []byte) ([]*ecdsa.PublicKey, error) {
	p, err := f.Payload(key)
	if err != nil {
		return nil, err
	}
	pubs := make([]*ecdsa.PublicKey, 0, len(p.Device))
	for _, pub := range slices.Sorted(maps.Keys(p.Device)) {
		meta := p.Device[pub]
		if meta.SignPub == "" {
			return nil, fmt.Errorf("%w %q", ErrNoSignPub, meta.Name)
		}
		signer, err := sig.ParseSigner(meta.SignPub)
		if err != nil {
			return nil, fmt.Errorf("%w in device %q", err, meta.Name)
		}
		pubs = append(pubs, signer)
	}
	return pubs, nil
}

// Signers returns every enrolled device's signing key encoding, the set a
// first contact pins.
func (f *File) Signers(key []byte) ([]string, error) {
	p, err := f.Payload(key)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(p.Device))
	for _, pub := range slices.Sorted(maps.Keys(p.Device)) {
		meta := p.Device[pub]
		if meta.SignPub == "" {
			return nil, fmt.Errorf("%w %q", ErrNoSignPub, meta.Name)
		}
		out = append(out, meta.SignPub)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// New creates a vault holding a fresh vault key sealed to dk and to
// passphrase, recording signPub as this device's signing key.
func New(dk seal.DeviceKey, passphrase, name string, signPub *ecdsa.PublicKey) (*File, error) {
	key, err := newVaultKey()
	if err != nil {
		return nil, err
	}
	defer clear(key)

	f := &File{
		Version: Version,
		VaultID: newVaultID(),
		Seq:     1,
		Device:  map[string]Device{},
		Secret:  map[string]string{},
		payload: &Payload{Device: map[string]DeviceMeta{}, Names: []string{}},
		dirty:   true,
	}
	if err := f.AddDevice(key, name, time.Now().Format("2006-01-02"), dk.Public(), signPub); err != nil {
		return nil, err
	}
	if err := f.setRecovery(key, passphrase); err != nil {
		return nil, err
	}
	if err := f.Seal(key); err != nil {
		return nil, err
	}
	return f, nil
}

// Match reports which enrolled device dk is, by comparing public keys.
func (f *File) Match(dk seal.DeviceKey) (string, error) {
	want := Pub(dk.Public())
	if _, ok := f.Device[want]; !ok {
		return "", ErrNoDevice
	}
	return want, nil
}

// VaultKey unseals the vault key with this machine's device key.
func (f *File) VaultKey(dk seal.DeviceKey) ([]byte, error) {
	want := Pub(dk.Public())
	d, ok := f.Device[want]
	if !ok {
		return nil, ErrNoDevice
	}
	return seal.UnwrapKey(dk, seal.KeyWrap{EPub: d.EPub, Body: d.Wrap})
}

// VaultKeyPass unseals the vault key with the recovery passphrase.
func (f *File) VaultKeyPass(passphrase string) ([]byte, error) {
	// An empty passphrase is not a secret. A vault from before the length
	// floor would otherwise let anyone join with a bare newline.
	if passphrase == "" {
		return nil, fmt.Errorf(
			"%w, a vault from before the length floor needs fuu rotate from an enrolled machine",
			ErrEmptyPass,
		)
	}
	r := f.Recovery
	return seal.UnwrapPassphrase(passphrase, seal.PassWrap{
		KDF:  r.KDF,
		Salt: r.Salt,
		Mem:  r.Mem,
		Time: r.Time,
		Body: r.Wrap,
	})
}

// Payload decrypts the names and the device registry and keeps them for the
// mutators that have to keep the blob in step.
func (f *File) Payload(key []byte) (*Payload, error) {
	if f.payload != nil {
		return f.payload, nil
	}
	raw, err := seal.UnwrapValue(key, f.Blob, blobAAD)
	if err != nil {
		return nil, fmt.Errorf("vault: open payload: %w", err)
	}
	p := new(Payload)
	if err := toml.Unmarshal(raw, p); err != nil {
		return nil, fmt.Errorf("vault: parse payload: %w", err)
	}
	if p.Device == nil {
		p.Device = map[string]DeviceMeta{}
	}
	f.payload = p
	return p, nil
}

// Seal writes the payload back into the blob. A value edit that adds and drops
// no name leaves the blob alone, so git still shows which entry changed.
func (f *File) Seal(key []byte) error {
	if !f.dirty || f.payload == nil {
		return nil
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(f.payload); err != nil {
		return fmt.Errorf("vault: encode payload: %w", err)
	}
	body, err := seal.WrapValue(key, buf.Bytes(), blobAAD)
	if err != nil {
		return err
	}
	f.Blob = body
	f.dirty = false
	return nil
}

// AddDevice seals key to pub and records the device as name with signing key
// signPub. Only this block changes, no secret value is touched.
func (f *File) AddDevice(key []byte, name, created string, pub *ecdh.PublicKey, signPub *ecdsa.PublicKey) error {
	if !ValidName(name) {
		return fmt.Errorf("%w %q", ErrBadName, name)
	}
	// A taken name is never overwritten, that would revoke whatever device
	// held it without a word.
	want := Pub(pub)
	p, err := f.Payload(key)
	if err != nil {
		return err
	}
	for other, meta := range p.Device {
		if meta.Name == name {
			return fmt.Errorf("%w %q, pick another name or revoke it first", ErrDupName, name)
		}
		if other == want {
			return fmt.Errorf("%w %s, already enrolled as %q", ErrDupDevice, want, meta.Name)
		}
	}

	w, err := seal.WrapKey(pub, key)
	if err != nil {
		return err
	}
	signer, err := sig.EncodeSigner(signPub)
	if err != nil {
		return err
	}
	f.Device[want] = Device{Pub: want, EPub: w.EPub, Wrap: w.Body}
	p.Device[want] = DeviceMeta{Name: name, Created: created, SignPub: signer}
	f.dirty = true
	return f.Seal(key)
}

// RemoveDevice revokes pub from here on. It is not retroactive: anyone who
// already unsealed the vault key keeps it. Run Rotate when a device burned.
func (f *File) RemoveDevice(key []byte, pub string) error {
	if _, ok := f.Device[pub]; !ok {
		return fmt.Errorf("%w %q", ErrNoDevice, pub)
	}
	// With no signer left the signature can never verify again and the vault
	// becomes unopenable, so the last one has to stay.
	if len(f.Device) == 1 {
		return ErrLast
	}
	p, err := f.Payload(key)
	if err != nil {
		return err
	}
	delete(f.Device, pub)
	delete(p.Device, pub)
	f.dirty = true
	return f.Seal(key)
}

// Rotate replaces the vault key, rewrapping every device and every value.
func (f *File) Rotate(old []byte, passphrase string) error {
	key, err := newVaultKey()
	if err != nil {
		return err
	}
	defer clear(key)

	p, err := f.Payload(old)
	if err != nil {
		return err
	}
	values, err := f.Values(old)
	if err != nil {
		return err
	}

	devices := f.Device
	meta := p.Device
	f.Device = map[string]Device{}
	p.Device = map[string]DeviceMeta{}
	for pub, d := range devices {
		recipient, err := ParsePub(d.Pub)
		if err != nil {
			return fmt.Errorf("%w in device %q", err, meta[pub].Name)
		}
		signer, err := sig.ParseSigner(meta[pub].SignPub)
		if err != nil {
			return fmt.Errorf("%w in device %q", err, meta[pub].Name)
		}
		if err := f.AddDevice(key, meta[pub].Name, meta[pub].Created, recipient, signer); err != nil {
			return err
		}
	}

	f.Secret = map[string]string{}
	p.Names = []string{}
	f.dirty = true
	for name, plain := range values {
		if err := f.Set(key, name, []byte(plain)); err != nil {
			return err
		}
	}

	if err := f.setRecovery(key, passphrase); err != nil {
		return err
	}
	return f.Seal(key)
}

func (f *File) setRecovery(key []byte, passphrase string) error {
	w, err := seal.WrapPassphrase(passphrase, key)
	if err != nil {
		return err
	}
	f.Recovery = Recovery{KDF: w.KDF, Salt: w.Salt, Mem: w.Mem, Time: w.Time, Wrap: w.Body}
	return nil
}

// Set stores one value under the token its name derives to. An existing name
// only rewrites its body, so the blob and every other entry stay put.
func (f *File) Set(key []byte, name string, value []byte) error {
	if !ValidName(name) {
		return fmt.Errorf("%w %q", ErrBadName, name)
	}
	token, err := seal.NameToken(key, name)
	if err != nil {
		return err
	}
	p, err := f.Payload(key)
	if err != nil {
		return err
	}
	if !slices.Contains(p.Names, name) {
		// A token collision would silently merge two keys into one entry.
		for _, other := range p.Names {
			clash, err := seal.NameToken(key, other)
			if err != nil {
				return err
			}
			if clash == token {
				return fmt.Errorf("%w: %q and %q", ErrTokenClash, name, other)
			}
		}
		p.Names = append(p.Names, name)
		slices.Sort(p.Names)
		f.dirty = true
	}
	body, err := seal.WrapValue(key, value, valueAAD+token)
	if err != nil {
		return err
	}
	f.Secret[token] = body
	return f.Seal(key)
}

func (f *File) Unset(key []byte, name string) error {
	token, err := seal.NameToken(key, name)
	if err != nil {
		return err
	}
	if _, ok := f.Secret[token]; !ok {
		return fmt.Errorf("%w %q", ErrNoKey, name)
	}
	p, err := f.Payload(key)
	if err != nil {
		return err
	}
	delete(f.Secret, token)
	p.Names = slices.DeleteFunc(p.Names, func(n string) bool { return n == name })
	f.dirty = true
	return f.Seal(key)
}

func (f *File) Get(key []byte, name string) ([]byte, error) {
	token, err := seal.NameToken(key, name)
	if err != nil {
		return nil, err
	}
	body, ok := f.Secret[token]
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrNoKey, name)
	}
	return seal.UnwrapValue(key, body, valueAAD+token)
}

// Names lists the keys this vault holds, in sorted order.
func (f *File) Names(key []byte) ([]string, error) {
	p, err := f.Payload(key)
	if err != nil {
		return nil, err
	}
	if err := f.checkNames(key, p); err != nil {
		return nil, err
	}
	return slices.Sorted(slices.Values(p.Names)), nil
}

// Devices lists the enrolled chips by name.
func (f *File) Devices(key []byte) (map[string]DeviceMeta, error) {
	p, err := f.Payload(key)
	if err != nil {
		return nil, err
	}
	return maps.Clone(p.Device), nil
}

// Values unseals every value as name to plaintext. Names come from the file,
// so the eval-safety guard lives here rather than in callers.
func (f *File) Values(key []byte) (map[string]string, error) {
	names, err := f.Names(key)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		if !ValidName(name) {
			return nil, fmt.Errorf("%w %q", ErrBadName, name)
		}
		plain, err := f.Get(key, name)
		if err != nil {
			return nil, fmt.Errorf("vault: %s: %w", name, err)
		}
		out[name] = string(plain)
		clear(plain)
	}
	return out, nil
}

// checkNames refuses a payload whose names and bodies disagree, so a half
// written vault fails loudly instead of dropping a key.
func (f *File) checkNames(key []byte, p *Payload) error {
	seen := make(map[string]string, len(p.Names))
	for _, name := range p.Names {
		if !ValidName(name) {
			return fmt.Errorf("%w %q", ErrBadName, name)
		}
		token, err := seal.NameToken(key, name)
		if err != nil {
			return err
		}
		if _, ok := f.Secret[token]; !ok {
			return fmt.Errorf("%w %q", ErrNoKey, name)
		}
		seen[token] = name
	}
	for token := range f.Secret {
		if _, ok := seen[token]; !ok {
			return fmt.Errorf("vault: entry %s has no name", token)
		}
	}
	return nil
}

// ValidName reports whether name is safe to emit as a shell variable name,
// because fuu print and fuu env are eval'd by the shell. A hand edited vault
// must not be able to smuggle shell syntax past that eval.
func ValidName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// Pub encodes a P-256 public key as "p256:" plus the compressed point.
func Pub(pub *ecdh.PublicKey) string {
	b := pub.Bytes()
	point := elliptic.MarshalCompressed(
		elliptic.P256(),
		new(big.Int).SetBytes(b[1:33]),
		new(big.Int).SetBytes(b[33:65]),
	)
	return "p256:" + base64.RawURLEncoding.EncodeToString(point)
}

// ParsePub reads what Pub writes.
func ParsePub(s string) (*ecdh.PublicKey, error) {
	rest, ok := strings.CutPrefix(s, "p256:")
	if !ok {
		return nil, fmt.Errorf("vault: parse public key: %q has no p256: prefix", s)
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, fmt.Errorf("vault: parse public key: %w", err)
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw)
	if x == nil {
		return nil, fmt.Errorf("vault: parse public key: not a compressed P-256 point")
	}

	// crypto/ecdh only takes uncompressed points.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:65])

	pub, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("vault: parse public key: %w", err)
	}
	return pub, nil
}

func newVaultKey() ([]byte, error) {
	key := make([]byte, vaultKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("vault: generate vault key: %w", err)
	}
	return key, nil
}

// newVaultID mints the identity pins and paths are recorded against. It is
// what tells two copies of one vault from two different vaults.
func newVaultID() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return "v_" + base64.RawURLEncoding.EncodeToString(raw)
}
