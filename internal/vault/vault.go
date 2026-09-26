// Package vault is the on disk vault: one TOML file per repository, meant to be committed in public.
// Only the format version, the salt and the opaque entry tokens are readable without the vault key.
package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/mizuchilabs/kata/fsutil"
)

const (
	vaultKeySize = 32

	// saltSize and idSize are the random bytes behind a vault's salt and its id.
	saltSize = 16
	idSize   = 16

	// maxFileBytes caps the untrusted file before any hashing or parsing.
	maxFileBytes = 5 << 20 // 5MB
)

var (
	ErrWrongAccount = errors.New("this vault is not sealed to the account on this machine")
	ErrConflict     = errors.New("the vault changed on disk while fuu was working, run the command again")
	ErrNoKey        = errors.New("no such key")
	ErrDisabled     = errors.New("this key is commented out in fuu edit, uncomment it there to use it")
	ErrBadName      = errors.New("not a valid name, want a shell identifier that does not configure the shell itself")
	ErrNulValue     = errors.New("values cannot contain NUL bytes, the shell would drop them")
)

// File is the whole vault. Everything but Version is a salt, an envelope or an opaque token.
type File struct {
	Version  int               `toml:"version"`
	Salt     string            `toml:"salt"`
	Check    string            `toml:"check"`
	Secret   map[string]string `toml:"secret"`
	Disabled map[string]string `toml:"disabled,omitempty"`

	raw []byte
}

// Read reads the vault file at path, refusing anything too large to be one.
func Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", path, err)
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("vault: %s is over %d bytes, refusing it as a vault", path, maxFileBytes)
	}
	return data, nil
}

// Load reads the vault file at path.
func Load(path string) (*File, error) {
	data, err := Read(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse remembers the bytes it read, so Save can tell whether the file changed under it.
func Parse(data []byte) (*File, error) {
	f := new(File)
	if err := toml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("vault: parse: %w", err)
	}
	if err := checkVersion("vault", f.Version); err != nil {
		return nil, err
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

// New creates a vault under a fresh salt and id, its key derived from the
// account seed, and returns that key and id for this session.
func New(account []byte) (*File, []byte, string, error) {
	id := make([]byte, idSize)
	if _, err := rand.Read(id); err != nil {
		return nil, nil, "", fmt.Errorf("vault: generate vault id: %w", err)
	}
	f := &File{
		Version:  Version,
		Secret:   map[string]string{},
		Disabled: map[string]string{},
	}
	key, err := f.reseal(account, id)
	if err != nil {
		return nil, nil, "", err
	}
	return f, key, encodeID(id), nil
}

// Save refuses when the file on disk is not the bytes this File was loaded
// or saved as, so nothing is silently clobbered.
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

// Open derives this vault's key from the account seed and returns it with the
// vault id. A vault sealed to any other account is ErrWrongAccount.
func (f *File) Open(account []byte) ([]byte, string, error) {
	salt, err := base64.RawURLEncoding.DecodeString(f.Salt)
	if err != nil || len(salt) != saltSize {
		return nil, "", errors.New("vault: the salt is not 16 bytes of base64, the file was tampered with")
	}
	key, err := deriveVaultKey(account, salt)
	if err != nil {
		return nil, "", err
	}
	id, err := f.id(key)
	if err != nil {
		return nil, "", err
	}
	return key, id, nil
}

// id opens the vault id, the identity a folder is pinned to. Only the right
// key opens it, so it is also the proof of which account the vault belongs to.
func (f *File) id(key []byte) (string, error) {
	id, err := openValue(key, f.Check, checkAAD)
	if err != nil {
		return "", ErrWrongAccount
	}
	if len(id) != idSize {
		return "", errors.New("vault: the vault id is not 16 bytes, the file was tampered with")
	}
	return encodeID(id), nil
}

// Secrets opens the enabled entries as name to value, refusing any entry
// not sealed under this key.
func (f *File) Secrets(key []byte) (map[string]string, error) {
	return entries(key, f.Secret, entryAAD)
}

// DisabledSecrets opens the commented out entries the same way, so a vault
// holding any authenticates as a whole.
func (f *File) DisabledSecrets(key []byte) (map[string]string, error) {
	return entries(key, f.Disabled, disabledAAD)
}

// entries opens one whole table under the aad its bodies were sealed with.
func entries(key []byte, table map[string]string, aad string) (map[string]string, error) {
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

// openEntry checks the body is the entry its token addresses, so a pasted
// or tampered body is a refusal.
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
	if bytes.ContainsRune(value, 0) {
		return "", "", fmt.Errorf("vault: secret %s: %w", tok, ErrNulValue)
	}
	return string(name), string(value), nil
}

// Set stores one value under the token its name derives to, rewriting only that body.
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

// Disable moves the entry to the [disabled] table under a seal of its own,
// so it stops loading without being lost.
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

// Enable drops any disabled entry of the same name, so an uncommented key is
// back in the shell.
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

// Rotate reseals every value under a fresh salt of account, which may be a
// new account seed, keeping the vault id. Anything unauthenticated aborts first.
func (f *File) Rotate(old, account []byte) ([]byte, error) {
	id, err := f.id(old)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return nil, fmt.Errorf("vault: decode vault id: %w", err)
	}
	secrets, err := f.Secrets(old)
	if err != nil {
		return nil, err
	}
	disabled, err := f.DisabledSecrets(old)
	if err != nil {
		return nil, err
	}
	key, err := f.reseal(account, raw)
	if err != nil {
		return nil, err
	}
	if err := f.fill(key, secrets, disabled); err != nil {
		return nil, err
	}
	return key, nil
}

// reseal picks a fresh salt, derives its key and seals the id under it,
// emptying both tables for fill.
func (f *File) reseal(account, id []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("vault: generate salt: %w", err)
	}
	key, err := deriveVaultKey(account, salt)
	if err != nil {
		return nil, err
	}
	check, err := sealValue(key, id, checkAAD)
	if err != nil {
		return nil, err
	}
	f.Salt = base64.RawURLEncoding.EncodeToString(salt)
	f.Check = check
	f.Secret = map[string]string{}
	f.Disabled = map[string]string{}
	return key, nil
}

// fill seals every value under key, in name order so a rewrite is reproducible to read.
func (f *File) fill(key []byte, secrets, disabled map[string]string) error {
	for _, name := range slices.Sorted(maps.Keys(secrets)) {
		if err := f.Set(key, name, secrets[name]); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(disabled)) {
		if err := f.Set(key, name, disabled[name]); err != nil {
			return err
		}
		if err := f.Disable(key, name); err != nil {
			return err
		}
	}
	return nil
}

func encodeID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}
