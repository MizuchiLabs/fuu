package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type softKey struct{ key *ecdh.PrivateKey }

var _ DeviceKey = (*softKey)(nil)

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	return &softKey{key: key}
}

func (k *softKey) Public() *ecdh.PublicKey { return k.key.PublicKey() }

func (k *softKey) ECDH(peer *ecdh.PublicKey) ([]byte, error) { return k.key.ECDH(peer) }

// newAccount is a random account seed, argon2id is too slow to run per test.
func newAccount(t *testing.T) []byte {
	t.Helper()
	return vaultKey(t)
}

// newFixture builds a vault under a fresh account with two values.
func newFixture(t *testing.T) (f *File, account, key []byte) {
	t.Helper()
	account = newAccount(t)

	f, key, _, err := New(account)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for name, value := range map[string]string{"API_KEY": "s3cret", "DATABASE_URL": "postgres://x"} {
		if err := f.Set(key, name, value); err != nil {
			t.Fatalf("Set %s: %v", name, err)
		}
	}
	return f, account, key
}

// The open path the shell hook uses, with values that need quoting to survive in a shell.
func TestRoundTrip(t *testing.T) {
	f, account, key := newFixture(t)
	if err := f.Set(key, "QUOTED", "line one\nit's \"fine\""); err != nil {
		t.Fatalf("Set: %v", err)
	}

	path := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	unsealed, _, err := got.Open(account)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	values, err := got.Secrets(unsealed)
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	want := map[string]string{
		"API_KEY":      "s3cret",
		"DATABASE_URL": "postgres://x",
		"QUOTED":       "line one\nit's \"fine\"",
	}
	if !maps.Equal(values, want) {
		t.Fatalf("values = %v, want %v", values, want)
	}
}

// The point of the format: nothing in the readable bytes reveals what the vault holds.
func TestFileHidesNames(t *testing.T) {
	f, _, _ := newFixture(t)

	path := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw := string(mustRead(t, path))
	for _, leak := range []string{"API_KEY", "DATABASE_URL", "laptop"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("the vault file leaks %q", leak)
		}
	}
}

// The body carries its token as additional data, so it will not open pasted into another entry.
func TestSecretsRefusesSwappedBodies(t *testing.T) {
	f, _, key := newFixture(t)

	mine := token(key, "API_KEY")
	other := token(key, "DATABASE_URL")
	f.Secret[other] = f.Secret[mine]

	if _, err := f.Secrets(key); err == nil {
		t.Fatal("Secrets accepted two entries carrying one body")
	}
}

// A vault sealed to one account does not open under another.
func TestOpenRefusesOtherAccount(t *testing.T) {
	f, _, _ := newFixture(t)
	if _, _, err := f.Open(newAccount(t)); !errors.Is(err, ErrWrongAccount) {
		t.Fatalf("Open under another account = %v, want ErrWrongAccount", err)
	}
}

// A salt or check lifted from another vault of the same account is refused, not reinterpreted.
func TestOpenRefusesSpliced(t *testing.T) {
	f, account, _ := newFixture(t)
	other, _, _, err := New(account)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	spliced := *f
	spliced.Check = other.Check
	if _, _, err := spliced.Open(account); !errors.Is(err, ErrWrongAccount) {
		t.Fatalf("Open with another vault's check = %v, want ErrWrongAccount", err)
	}

	// Both halves from the other vault open as that vault, whose key then refuses these entries.
	spliced.Salt = other.Salt
	key, _, err := spliced.Open(account)
	if err != nil {
		t.Fatalf("Open with both halves swapped: %v", err)
	}
	if _, err := spliced.Secrets(key); err == nil {
		t.Fatal("entries of one vault opened under another vault's key")
	}

	spliced.Salt = "short"
	if _, _, err := spliced.Open(account); err == nil {
		t.Fatal("Open accepted a malformed salt")
	}
}

// A rotated vault keeps every value and its id, under a new salt and key.
func TestRotateKeepsID(t *testing.T) {
	f, account, key := newFixture(t)
	_, id, err := f.Open(account)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	salt := f.Salt

	fresh, err := f.Rotate(key, account)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if f.Salt == salt || bytes.Equal(fresh, key) {
		t.Fatal("Rotate kept the salt or the key")
	}
	opened, rotatedID, err := f.Open(account)
	if err != nil {
		t.Fatalf("Open after rotate: %v", err)
	}
	if !bytes.Equal(opened, fresh) || rotatedID != id {
		t.Fatal("the rotated vault opens to another key or id")
	}
	values, err := f.Secrets(fresh)
	if err != nil {
		t.Fatalf("Secrets after rotate: %v", err)
	}
	if values["API_KEY"] != "s3cret" {
		t.Fatalf("values after rotate = %v", values)
	}
	if _, err := f.Secrets(key); err == nil {
		t.Fatal("the old vault key still opens the entries")
	}
}

// Moving a vault to a new account seed cuts the old seed off.
func TestRotateToNewAccount(t *testing.T) {
	f, account, key := newFixture(t)
	next := newAccount(t)

	if _, err := f.Rotate(key, next); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, _, err := f.Open(next); err != nil {
		t.Fatalf("Open under the new account: %v", err)
	}
	if _, _, err := f.Open(account); !errors.Is(err, ErrWrongAccount) {
		t.Fatalf("Open under the old account = %v, want ErrWrongAccount", err)
	}
}

// Rotate authenticates the whole file before sealing anything new.
func TestRotateRefusesTampered(t *testing.T) {
	f, account, key := newFixture(t)
	f.Secret[token(key, "API_KEY")] = f.Secret[token(key, "DATABASE_URL")]
	if _, err := f.Rotate(key, account); err == nil {
		t.Fatal("Rotate ran past a tampered entry")
	}
}

// The passphrase survives the ways people copy it, and nothing else opens the same seed.
func TestDeriveAccount(t *testing.T) {
	want := DeriveAccount("ABCDEFGH23456")
	if !bytes.Equal(DeriveAccount(" abcd-efgh-2345 6\n"), want) {
		t.Fatal("case, dashes and spaces changed the account seed")
	}
	if bytes.Equal(DeriveAccount("ABCDEFGH23457"), want) {
		t.Fatal("two passphrases derived one seed")
	}
}

// Both writers losing: overwriting an existing file, and a save racing another machine.
func TestSaveConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	f, _, key := newFixture(t)

	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// A vault from scratch would overwrite an existing file.
	fresh := &File{Version: Version, Secret: map[string]string{}}
	if err := fresh.Save(path); !errors.Is(err, ErrConflict) {
		t.Fatalf("Save over an existing file = %v, want ErrConflict", err)
	}

	second, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := f.Set(key, "API_KEY", "rotated"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := second.Set(key, "API_KEY", "rotated"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := second.Save(path); !errors.Is(err, ErrConflict) {
		t.Fatalf("Save of the stale copy = %v, want ErrConflict", err)
	}
}

// Names that would take the shell over once the hook evals the export line.
func TestValidName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"API_KEY", true},
		{"_", true},
		{"a1", true},
		{"1A", false},
		{"", false},
		{"A=B", false},
		{"A B", false},
		{"A-B", false},
		{"A\nB", false},
		{"$(id)", false},
		{"PATH", false},
		{"path", false},
		{"LD_PRELOAD", false},
		{"FUU_STATE", false},
	} {
		if got := ValidName(tc.name); got != tc.want {
			t.Fatalf("ValidName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The comment out contract: the value leaves the shell's map and survives under DisabledSecrets.
func TestDisableKeepsEntry(t *testing.T) {
	f, _, key := newFixture(t)

	if err := f.Disable(key, "API_KEY"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	values, err := f.Secrets(key)
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	if _, ok := values["API_KEY"]; ok {
		t.Fatal("a disabled key is still in Secrets")
	}
	if values["DATABASE_URL"] != "postgres://x" {
		t.Fatalf("Disable moved a key it was not asked to: %v", values)
	}
	off, err := f.DisabledSecrets(key)
	if err != nil {
		t.Fatalf("DisabledSecrets: %v", err)
	}
	if off["API_KEY"] != "s3cret" {
		t.Fatalf("disabled entries = %v, want API_KEY with its value", off)
	}
	if err := f.Disable(key, "MISSING"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Disable of a missing key = %v, want ErrNoKey", err)
	}

	path := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if f.Version != Version {
		t.Fatalf("version = %d, want %d", f.Version, Version)
	}
	if !strings.Contains(string(mustRead(t, path)), "[disabled]") {
		t.Fatal("the file carries no [disabled] table")
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load of a vault with disabled entries: %v", err)
	}
	if reloaded.Disabled == nil {
		t.Fatal("Parse handed out a vault with a nil disabled map")
	}
	off, err = reloaded.DisabledSecrets(key)
	if err != nil {
		t.Fatalf("DisabledSecrets after reload: %v", err)
	}
	if off["API_KEY"] != "s3cret" {
		t.Fatalf("disabled entries after reload = %v", off)
	}

	if err := reloaded.Enable(key, "API_KEY", "s3cret"); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if err := reloaded.Save(path); err != nil {
		t.Fatalf("Save after Enable: %v", err)
	}
	if strings.Contains(string(mustRead(t, path)), "[disabled]") {
		t.Fatal("an emptied disabled table is still written")
	}
	values, err = reloaded.Secrets(key)
	if err != nil {
		t.Fatalf("Secrets after Enable: %v", err)
	}
	if values["API_KEY"] != "s3cret" {
		t.Fatalf("values after Enable = %v", values)
	}
	if off, err = reloaded.DisabledSecrets(key); err != nil || len(off) != 0 {
		t.Fatalf("disabled entries after Enable = %v, %v", off, err)
	}
}

// Deleting a commented out key leaves both tables, not just the visible one.
func TestUnsetDropsDisabled(t *testing.T) {
	f, _, key := newFixture(t)
	if err := f.Disable(key, "API_KEY"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := f.Unset(key, "API_KEY"); err != nil {
		t.Fatalf("Unset of a disabled key: %v", err)
	}
	if values, err := f.Secrets(key); err != nil || len(values) != 1 {
		t.Fatalf("values after Unset = %v, %v", values, err)
	}
	if off, err := f.DisabledSecrets(key); err != nil || len(off) != 0 {
		t.Fatalf("disabled entries after Unset = %v, %v", off, err)
	}
}

// A disabled body pasted back into [secret] is a refusal, it is sealed to the slot it belongs to.
func TestDisabledBodyRefusesTableMove(t *testing.T) {
	f, _, key := newFixture(t)
	if err := f.Disable(key, "API_KEY"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	for tok, body := range f.Disabled {
		f.Secret[tok] = body
		delete(f.Disabled, tok)
	}
	if _, err := f.Secrets(key); err == nil {
		t.Fatal("Secrets accepted a body moved out of the disabled table")
	}
}

// A rotation reseals commented out entries too, under the disabled slot of the new key.
func TestRotateKeepsDisabled(t *testing.T) {
	f, account, key := newFixture(t)
	if err := f.Disable(key, "API_KEY"); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	fresh, err := f.Rotate(key, account)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	off, err := f.DisabledSecrets(fresh)
	if err != nil {
		t.Fatalf("DisabledSecrets after rotate: %v", err)
	}
	if off["API_KEY"] != "s3cret" {
		t.Fatalf("disabled entries after rotate = %v, want API_KEY with its value", off)
	}
	if values, err := f.Secrets(fresh); err != nil || values["DATABASE_URL"] != "postgres://x" {
		t.Fatalf("values after rotate = %v, %v", values, err)
	}
	if _, err = f.DisabledSecrets(key); err == nil {
		t.Fatal("the old vault key still opens the disabled entries")
	}
}

// This build reads its own format version and nothing else.
func TestParseRefusesUnknownVersion(t *testing.T) {
	if _, err := Parse([]byte("version = 3\n")); !errors.Is(err, errBadVersion) {
		t.Fatalf("Parse of version 3 = %v, want errBadVersion", err)
	}
}

// Every label is built on domain, so domain has to name the version it claims.
func TestDomainMatchesVersion(t *testing.T) {
	if want := fmt.Sprintf("fuu/v%d/", Version); domain != want {
		t.Fatalf("domain = %q, want %q to match Version", domain, want)
	}
}

// A value smuggled in with a NUL byte is refused on read, not just on write.
func TestSecretsRefusesNULValue(t *testing.T) {
	f, _, key := newFixture(t)
	tok := token(key, "API_KEY")
	body, err := sealValue(key, []byte("API_KEY\x00a\x00b"), entryAAD+tok)
	if err != nil {
		t.Fatalf("sealValue: %v", err)
	}
	f.Secret[tok] = body
	if _, err := f.Secrets(key); err == nil {
		t.Fatal("Secrets accepted a value with a NUL byte")
	}
}

func TestReadRefusesHugeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.toml")
	if err := os.WriteFile(path, make([]byte, maxFileBytes+1), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("Read accepted a file over the size cap")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
