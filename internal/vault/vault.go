// Package vault is the on disk vault: one TOML file holding the device
// registry, the recovery wrap and every secret value.
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
	"encoding/base64"
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
	Version      = 1
	vaultKeySize = 32
)

var (
	ErrNoDevice   = errors.New("no such device")
	ErrDupDevice  = errors.New("public key already enrolled")
	ErrDupName    = errors.New("device name already taken")
	ErrLastDevice = errors.New("cannot revoke the last device, enroll another one first")
	ErrBadName    = errors.New("key is not a valid environment variable name")
	ErrEmptyPass  = errors.New("recovery passphrase is empty")
	ErrNoProject  = errors.New("no such project")
	ErrNoKey      = errors.New("no such key")
	ErrNoSig      = errors.New("no signature over the vault contents")
	ErrNoSignPub  = errors.New("device has no signing public key")
	errBadVersion = errors.New("unsupported version")

	// canonEscaper keeps every Canonical field on its own line, so no value can forge a line.
	canonEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

type Device struct {
	Created string `toml:"created"`
	Pub     string `toml:"pub"`
	SignPub string `toml:"signpub"`
	EPub    string `toml:"epub"`
	Wrap    string `toml:"wrap"`
}

type Recovery struct {
	KDF  string `toml:"kdf"`
	Salt string `toml:"salt"`
	Mem  uint32 `toml:"mem"`
	Time uint32 `toml:"time"`
	Wrap string `toml:"wrap"`
}

type File struct {
	Version  int                          `toml:"version"`
	Sig      string                       `toml:"sig,omitempty"`
	Signer   string                       `toml:"signer,omitempty"`
	Device   map[string]Device            `toml:"device"`
	Recovery Recovery                     `toml:"recovery"`
	Secret   map[string]map[string]string `toml:"secret"`
}

func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", path, err)
	}

	f := new(File)
	if err := toml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("vault: parse %s: %w", path, err)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("%w %d in %s, this build reads %d", errBadVersion, f.Version, path, Version)
	}
	if f.Device == nil {
		f.Device = map[string]Device{}
	}
	if f.Secret == nil {
		f.Secret = map[string]map[string]string{}
	}
	return f, nil
}

func (f *File) Save(path string) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(f); err != nil {
		return fmt.Errorf("vault: encode: %w", err)
	}
	if err := fsutil.WriteIfChanged(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("vault: write %s: %w", path, err)
	}
	return nil
}

// Canonical is the deterministic byte form the signature covers, built by hand so a TOML encoder upgrade cannot silently change what a stored signature means.
func (f *File) Canonical() []byte {
	var b strings.Builder
	b.WriteString("fuu/v1/vault\n")
	canonField(&b, "version", strconv.Itoa(f.Version))
	for _, name := range slices.Sorted(maps.Keys(f.Device)) {
		d := f.Device[name]
		canonField(&b, "name", name)
		canonField(&b, "created", d.Created)
		canonField(&b, "pub", d.Pub)
		canonField(&b, "signpub", d.SignPub)
		canonField(&b, "epub", d.EPub)
		canonField(&b, "wrap", d.Wrap)
	}
	r := f.Recovery
	canonField(&b, "kdf", r.KDF)
	canonField(&b, "salt", r.Salt)
	canonField(&b, "mem", strconv.FormatUint(uint64(r.Mem), 10))
	canonField(&b, "time", strconv.FormatUint(uint64(r.Time), 10))
	canonField(&b, "wrap", r.Wrap)
	for _, project := range slices.Sorted(maps.Keys(f.Secret)) {
		keys := f.Secret[project]
		for _, key := range slices.Sorted(maps.Keys(keys)) {
			canonField(&b, "project", project)
			canonField(&b, "key", key)
			canonField(&b, "body", keys[key])
		}
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

// SignerPubs parses every enrolled device's signing key, the key set the vault's own registry vouches for. First contact with a vault starts from these.
func (f *File) SignerPubs() ([]*ecdsa.PublicKey, error) {
	pubs := make([]*ecdsa.PublicKey, 0, len(f.Device))
	for _, name := range slices.Sorted(maps.Keys(f.Device)) {
		d := f.Device[name]
		if d.SignPub == "" {
			return nil, fmt.Errorf("%w %q", ErrNoSignPub, name)
		}
		pub, err := sig.ParseSigner(d.SignPub)
		if err != nil {
			return nil, fmt.Errorf("%w in device %q", err, name)
		}
		pubs = append(pubs, pub)
	}
	return pubs, nil
}

// New creates a vault holding a fresh vault key sealed to dk and to passphrase, recording signPub as this device's signing key.
func New(dk seal.DeviceKey, name, passphrase string, signPub *ecdsa.PublicKey) (*File, error) {
	key, err := newVaultKey()
	if err != nil {
		return nil, err
	}
	defer clear(key)

	f := &File{
		Version: Version,
		Device:  map[string]Device{},
		Secret:  map[string]map[string]string{},
	}
	if err := f.AddDevice(key, name, dk.Public(), signPub); err != nil {
		return nil, err
	}
	if err := f.setRecovery(key, passphrase); err != nil {
		return nil, err
	}
	return f, nil
}

// Match reports which enrolled device dk is, by comparing public keys.
func (f *File) Match(dk seal.DeviceKey) (string, error) {
	want := Pub(dk.Public())
	for name, d := range f.Device {
		if d.Pub == want {
			return name, nil
		}
	}
	return "", ErrNoDevice
}

// VaultKey unseals the vault key with this machine's device key.
func (f *File) VaultKey(dk seal.DeviceKey) ([]byte, error) {
	name, err := f.Match(dk)
	if err != nil {
		return nil, err
	}
	d := f.Device[name]
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

// AddDevice seals key to pub and records the device as name with signing key
// signPub. Only this block changes, no secret value is touched.
func (f *File) AddDevice(key []byte, name string, pub *ecdh.PublicKey, signPub *ecdsa.PublicKey) error {
	// A taken name is never overwritten, that would revoke whatever device
	// held it without a word.
	if _, ok := f.Device[name]; ok {
		return fmt.Errorf("%w %q, pick another name or revoke it first", ErrDupName, name)
	}
	want := Pub(pub)
	for other, d := range f.Device {
		if d.Pub == want {
			return fmt.Errorf("%w %s, already enrolled as %q", ErrDupDevice, want, other)
		}
	}
	return f.addDevice(key, name, time.Now().Format("2006-01-02"), pub, signPub)
}

func (f *File) addDevice(key []byte, name, created string, pub *ecdh.PublicKey, signPub *ecdsa.PublicKey) error {
	w, err := seal.WrapKey(pub, key)
	if err != nil {
		return err
	}
	signer, err := sig.EncodeSigner(signPub)
	if err != nil {
		return err
	}
	f.Device[name] = Device{
		Created: created,
		Pub:     Pub(pub),
		SignPub: signer,
		EPub:    w.EPub,
		Wrap:    w.Body,
	}
	return nil
}

// RemoveDevice revokes name from here on. It is not retroactive: anyone who
// already unsealed the vault key keeps it. Run Rotate when a device burned.
func (f *File) RemoveDevice(name string) error {
	if _, ok := f.Device[name]; !ok {
		return fmt.Errorf("%w %q", ErrNoDevice, name)
	}
	// With no signer left the signature can never verify again and the vault
	// becomes unopenable, so the last one has to stay.
	if len(f.Device) == 1 {
		return ErrLastDevice
	}
	delete(f.Device, name)
	return nil
}

// Rotate replaces the vault key, rewrapping every device and every value.
func (f *File) Rotate(old []byte, passphrase string) error {
	key, err := newVaultKey()
	if err != nil {
		return err
	}
	defer clear(key)

	devices := f.Device
	values := f.Secret

	f.Device = map[string]Device{}
	for name, d := range devices {
		pub, err := ParsePub(d.Pub)
		if err != nil {
			return fmt.Errorf("%w in device %q", err, name)
		}
		signPub, err := sig.ParseSigner(d.SignPub)
		if err != nil {
			return fmt.Errorf("%w in device %q", err, name)
		}
		if err := f.addDevice(key, name, d.Created, pub, signPub); err != nil {
			return err
		}
	}

	f.Secret = map[string]map[string]string{}
	for project, keys := range values {
		for name, body := range keys {
			plain, err := seal.UnwrapValue(old, body)
			if err != nil {
				return fmt.Errorf("vault: %s:%s: %w", project, name, err)
			}
			if err := f.Set(key, project, name, plain); err != nil {
				return err
			}
			clear(plain)
		}
	}

	return f.setRecovery(key, passphrase)
}

func (f *File) setRecovery(key []byte, passphrase string) error {
	w, err := seal.WrapPassphrase(passphrase, key)
	if err != nil {
		return err
	}
	f.Recovery = Recovery{KDF: w.KDF, Salt: w.Salt, Mem: w.Mem, Time: w.Time, Wrap: w.Body}
	return nil
}

func (f *File) Set(key []byte, project, name string, value []byte) error {
	if !ValidName(name) {
		return fmt.Errorf("%w %q", ErrBadName, name)
	}
	body, err := seal.WrapValue(key, value)
	if err != nil {
		return err
	}
	if f.Secret[project] == nil {
		f.Secret[project] = map[string]string{}
	}
	f.Secret[project][name] = body
	return nil
}

func (f *File) Unset(project, name string) error {
	keys, ok := f.Secret[project]
	if !ok {
		return fmt.Errorf("%w %q", ErrNoProject, project)
	}
	if _, ok := keys[name]; !ok {
		return fmt.Errorf("%w %q", ErrNoKey, name)
	}
	delete(keys, name)
	if len(keys) == 0 {
		delete(f.Secret, project)
	}
	return nil
}

func (f *File) Get(key []byte, project, name string) ([]byte, error) {
	body, ok := f.Secret[project][name]
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrNoKey, name)
	}
	return seal.UnwrapValue(key, body)
}

// Project unseals every value in a project as KEY to plaintext. Names come
// from the file, so the eval-safety guard lives here rather than in callers.
func (f *File) Project(key []byte, project string) (map[string]string, error) {
	keys, ok := f.Secret[project]
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrNoProject, project)
	}

	for name := range keys {
		if !ValidName(name) {
			return nil, fmt.Errorf("%w %q", ErrBadName, name)
		}
	}

	out := make(map[string]string, len(keys))
	for name, body := range keys {
		plain, err := seal.UnwrapValue(key, body)
		if err != nil {
			return nil, fmt.Errorf("vault: %s:%s: %w", project, name, err)
		}
		out[name] = string(plain)
		clear(plain)
	}
	return out, nil
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
