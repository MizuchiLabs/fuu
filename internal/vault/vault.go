// Package vault is the on disk vault: one TOML file per repository, meant to
// be committed and passed around in public.
//
// Only the format version, the envelopes and the opaque entry tokens are
// readable without the vault key. Key names never appear in the file: each
// name is sealed inside its own entry's ciphertext. The vault key is sealed
// once per enrolled device and once to the recovery passphrase, so enrolling
// or revoking a device rewrites one block and leaves every value untouched.
package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/mizuchilabs/kata/fsutil"
)

const (
	// Version is the vault file format this build writes and reads.
	Version      = 1
	vaultKeySize = 32
)

var (
	ErrNotEnrolled = errors.New("this machine is not enrolled in this vault")
	ErrConflict    = errors.New("the vault changed on disk while fuu was working, run the command again")
	ErrNoKey       = errors.New("no such key")
	ErrDisabled    = errors.New("this key is commented out in fuu edit, uncomment it there to use it")
	ErrNoDevice    = errors.New("no such device")
	ErrDupName     = errors.New("device name already taken")
	ErrDupDevice   = errors.New("this device is already enrolled")
	ErrLast        = errors.New("cannot remove the last device")
	ErrBadName     = errors.New("not a valid name, want a shell identifier that does not configure the shell itself")
	ErrNulValue    = errors.New("values cannot contain NUL bytes, the shell would drop them")

	errBadVersion = errors.New("unsupported version")
)

// Recovery is the vault key sealed to the recovery passphrase.
type Recovery struct {
	Salt string `toml:"salt"`
	Wrap string `toml:"wrap"`
}

// Device is one enrolled chip's wrap of the vault key and its name, sealed
// under the vault key so the file says nothing about whose chips are enrolled.
type Device struct {
	EPub string `toml:"epub"`
	Wrap string `toml:"wrap"`
	Name string `toml:"name"`
}

// File is the whole vault. Everything but Version is an envelope, a salt or an
// opaque token, so the readable surface is fixed.
type File struct {
	Version  int               `toml:"version"`
	Recovery Recovery          `toml:"recovery"`
	Device   map[string]Device `toml:"device"`
	Secret   map[string]string `toml:"secret"`
	Disabled map[string]string `toml:"disabled,omitempty"`

	raw []byte
}

// Load reads the vault file at path.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse reads vault bytes and remembers them, so Save can tell whether the
// file changed under it.
func Parse(data []byte) (*File, error) {
	f := new(File)
	if err := toml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("vault: parse: %w", err)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("%w %d, this build reads %d", errBadVersion, f.Version, Version)
	}
	if f.Device == nil {
		f.Device = map[string]Device{}
	}
	if f.Secret == nil {
		f.Secret = map[string]string{}
	}
	if f.Disabled == nil {
		f.Disabled = map[string]string{}
	}
	f.raw = data
	return f, nil
}

// New creates a vault holding a fresh vault key sealed to dk and to
// passphrase, and returns that key for this session.
func New(dk DeviceKey, name, passphrase string) (*File, []byte, error) {
	key := make([]byte, vaultKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("vault: generate vault key: %w", err)
	}
	f := &File{
		Version:  Version,
		Device:   map[string]Device{},
		Secret:   map[string]string{},
		Disabled: map[string]string{},
	}
	if err := f.AddDevice(key, dk.Public(), name); err != nil {
		return nil, nil, err
	}
	if err := f.setRecovery(key, passphrase); err != nil {
		return nil, nil, err
	}
	return f, key, nil
}

// Save writes the vault, refusing when the file on disk is not the bytes this
// File was loaded or saved as. That covers both a vault written over an
// existing file and a concurrent writer, so nothing is ever silently clobbered.
func (f *File) Save(path string) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(f); err != nil {
		return fmt.Errorf("vault: encode: %w", err)
	}
	current, err := os.ReadFile(path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		current = nil
	default:
		return fmt.Errorf("vault: read %s: %w", path, err)
	}
	if !bytes.Equal(current, f.raw) {
		return ErrConflict
	}
	if err := fsutil.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("vault: write %s: %w", path, err)
	}
	f.raw = buf.Bytes()
	return nil
}

// Unseal opens the vault key with this machine's device key.
func (f *File) Unseal(dk DeviceKey) ([]byte, error) {
	d, ok := f.Device[Pub(dk.Public())]
	if !ok {
		return nil, ErrNotEnrolled
	}
	return unwrapKey(dk, d.EPub, d.Wrap)
}

// UnsealPassphrase opens the vault key with the recovery passphrase.
func (f *File) UnsealPassphrase(pass string) ([]byte, error) {
	return unwrapPassphrase(pass, f.Recovery.Salt, f.Recovery.Wrap)
}

// Secrets opens and validates the enabled entries as name to value. It
// authenticates every entry it returns: any entry that is not sealed under
// this key is a refusal.
func (f *File) Secrets(key []byte) (map[string]string, error) {
	return f.entries(key, f.Secret, entryAAD)
}

// DisabledSecrets opens the commented out entries the same way, so a vault
// that holds any authenticates as a whole.
func (f *File) DisabledSecrets(key []byte) (map[string]string, error) {
	return f.entries(key, f.Disabled, disabledAAD)
}

// entries opens one whole table under the aad its bodies were sealed with.
func (f *File) entries(key []byte, table map[string]string, aad string) (map[string]string, error) {
	out := make(map[string]string, len(table))
	for tok, body := range table {
		name, value, err := openEntry(key, tok, body, aad)
		if err != nil {
			return nil, err
		}
		out[name] = value
	}
	return out, nil
}

// openEntry opens one sealed body and checks it is the entry its token
// addresses, the check that makes a pasted or tampered body a refusal.
func openEntry(key []byte, tok, body, aad string) (string, string, error) {
	plain, err := openValue(key, body, aad+tok)
	if err != nil {
		return "", "", fmt.Errorf("vault: secret %s: %w", tok, err)
	}
	name, value, ok := bytes.Cut(plain, []byte{0})
	if !ok || !ValidName(string(name)) || tok != token(key, string(name)) {
		return "", "", fmt.Errorf(
			"vault: secret %s is not sealed under this vault key, the file was tampered with",
			tok,
		)
	}
	return string(name), string(value), nil
}

// Devices opens every device name and parses every public key, as pub to name.
// A name that does not open means someone added a device entry behind the key,
// which is exactly what a revocation or a rotation must not swallow.
func (f *File) Devices(key []byte) (map[string]string, error) {
	out := make(map[string]string, len(f.Device))
	for pub, d := range f.Device {
		if _, err := parsePub(pub); err != nil {
			return nil, err
		}
		name, err := openValue(key, d.Name, deviceAAD+pub)
		if err != nil {
			return nil, fmt.Errorf(
				"vault: device %s is not sealed under this vault key, the file was tampered with",
				pub,
			)
		}
		out[pub] = string(name)
	}
	return out, nil
}

// Set stores one value under the token its name derives to. An existing name
// only rewrites its body, so every other entry stays put.
func (f *File) Set(key []byte, name, value string) error {
	if !ValidName(name) {
		return fmt.Errorf("%w %q", ErrBadName, name)
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("%w %q", ErrNulValue, name)
	}
	tok := token(key, name)
	body, err := sealValue(key, []byte(name+"\x00"+value), entryAAD+tok)
	if err != nil {
		return err
	}
	f.Secret[tok] = body
	return nil
}

// Disable comments one key out: the entry moves to the [disabled] table under
// a seal of its own, so it stops loading into shells without being lost.
func (f *File) Disable(key []byte, name string) error {
	tok := token(key, name)
	body, ok := f.Secret[tok]
	if !ok {
		return fmt.Errorf("%w %q", ErrNoKey, name)
	}
	_, value, err := openEntry(key, tok, body, entryAAD)
	if err != nil {
		return err
	}
	sealed, err := sealValue(key, []byte(name+"\x00"+value), disabledAAD+tok)
	if err != nil {
		return err
	}
	f.Disabled[tok] = sealed
	delete(f.Secret, tok)
	return nil
}

// Enable stores one value under name and drops any disabled entry of the same
// name, so an uncommented or overwritten key is back in the shell.
func (f *File) Enable(key []byte, name, value string) error {
	if err := f.Set(key, name, value); err != nil {
		return err
	}
	delete(f.Disabled, token(key, name))
	return nil
}

// Unset drops one entry, commented out or not.
func (f *File) Unset(key []byte, name string) error {
	tok := token(key, name)
	_, active := f.Secret[tok]
	_, off := f.Disabled[tok]
	if !active && !off {
		return fmt.Errorf("%w %q", ErrNoKey, name)
	}
	delete(f.Secret, tok)
	delete(f.Disabled, tok)
	return nil
}

// AddDevice seals key to pub and records the device as name. Only this block
// changes, no secret value is touched.
func (f *File) AddDevice(key []byte, pub *ecdh.PublicKey, name string) error {
	if !validDeviceName(name) {
		return fmt.Errorf("%w %q", ErrBadName, name)
	}
	// Devices authenticates every entry first, so a name or wrap smuggled in
	// outside the key is caught before anything is sealed to it.
	devices, err := f.Devices(key)
	if err != nil {
		return err
	}
	want := Pub(pub)
	if _, ok := devices[want]; ok {
		return fmt.Errorf("%w %s, already enrolled as %q", ErrDupDevice, want, devices[want])
	}
	// A taken name is never overwritten, that would revoke whatever device
	// held it without a word.
	for _, other := range devices {
		if other == name {
			return fmt.Errorf("%w %q, pick another name or revoke it first", ErrDupName, name)
		}
	}

	ePub, body, err := wrapKey(pub, key)
	if err != nil {
		return err
	}
	sealed, err := sealValue(key, []byte(name), deviceAAD+want)
	if err != nil {
		return err
	}
	f.Device[want] = Device{EPub: ePub, Wrap: body, Name: sealed}
	return nil
}

// RemoveDevice drops pub from the vault. It is not retroactive: anyone who
// already unsealed the vault key keeps it. Callers rotate right after, so a
// removed device is cut off from the future too.
func (f *File) RemoveDevice(pub string) error {
	if _, ok := f.Device[pub]; !ok {
		return fmt.Errorf("%w %q", ErrNoDevice, pub)
	}
	if len(f.Device) == 1 {
		return ErrLast
	}
	delete(f.Device, pub)
	return nil
}

// Rotate replaces the vault key, rewrapping every device and every value, and
// seals the new key to a fresh recovery passphrase. Everything unauthenticated
// aborts the rotation before the new key is ever wrapped to it.
func (f *File) Rotate(old []byte, passphrase string) ([]byte, error) {
	devices, err := f.Devices(old)
	if err != nil {
		return nil, err
	}
	secrets, err := f.Secrets(old)
	if err != nil {
		return nil, err
	}
	disabled, err := f.DisabledSecrets(old)
	if err != nil {
		return nil, err
	}

	key := make([]byte, vaultKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("vault: generate vault key: %w", err)
	}

	f.Device = map[string]Device{}
	for pub, name := range devices {
		recipient, err := parsePub(pub)
		if err != nil {
			return nil, err
		}
		ePub, body, err := wrapKey(recipient, key)
		if err != nil {
			return nil, err
		}
		sealed, err := sealValue(key, []byte(name), deviceAAD+pub)
		if err != nil {
			return nil, err
		}
		f.Device[pub] = Device{EPub: ePub, Wrap: body, Name: sealed}
	}

	f.Secret = map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(secrets)) {
		if err := f.Set(key, name, secrets[name]); err != nil {
			return nil, err
		}
	}
	f.Disabled = map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(disabled)) {
		if err := f.Set(key, name, disabled[name]); err != nil {
			return nil, err
		}
		if err := f.Disable(key, name); err != nil {
			return nil, err
		}
	}

	if err := f.setRecovery(key, passphrase); err != nil {
		return nil, err
	}
	return key, nil
}

func (f *File) setRecovery(key []byte, passphrase string) error {
	salt, body, err := wrapPassphrase(passphrase, key)
	if err != nil {
		return err
	}
	f.Recovery = Recovery{Salt: salt, Wrap: body}
	return nil
}

// Fingerprint names a vault key, the identity a folder is pinned to.
func Fingerprint(key []byte) string {
	return tokenOf(key, fingerprintInfo)
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

// parsePub reads what Pub writes.
func parsePub(s string) (*ecdh.PublicKey, error) {
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
		return nil, errors.New("vault: parse public key: not a compressed P-256 point")
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
