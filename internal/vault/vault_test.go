package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
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

// newFixture builds a vault with one device and two values.
func newFixture(t *testing.T) (f *File, dk *softKey, key []byte) {
	t.Helper()
	dk = newSoftKey(t)

	f, key, err := New(dk, "laptop", "open sesame")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for name, value := range map[string]string{"API_KEY": "s3cret", "DATABASE_URL": "postgres://x"} {
		if err := f.Set(key, name, value); err != nil {
			t.Fatalf("Set %s: %v", name, err)
		}
	}
	return f, dk, key
}

// TestRoundTrip is the open path the shell hook uses, with values that need
// quoting to survive in a shell at all.
func TestRoundTrip(t *testing.T) {
	f, dk, key := newFixture(t)
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
	unsealed, err := got.Unseal(dk)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
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

// TestFileHidesNames is the point of the format: nothing in the readable bytes
// reveals what the vault holds or whose chips are enrolled.
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

// TestSecretsRefusesSwappedBodies covers swapping two entries in the file: the
// body carries its token as additional data, so it will not open pasted into
// another entry.
func TestSecretsRefusesSwappedBodies(t *testing.T) {
	f, _, key := newFixture(t)

	mine := token(key, "API_KEY")
	other := token(key, "DATABASE_URL")
	f.Secret[other] = f.Secret[mine]

	if _, err := f.Secrets(key); err == nil {
		t.Fatal("Secrets accepted two entries carrying one body")
	}
}

// TestForeignDeviceRefused is the attack fuu must not swallow: someone with
// repo write access adds a device entry of their own, and the next rotation
// would seal the new key to it. The entry cannot carry a name under the vault
// key, so that is what gives it away before anything is wrapped to it.
func TestForeignDeviceRefused(t *testing.T) {
	f, _, key := newFixture(t)

	attacker := newSoftKey(t)
	ePub, body, err := wrapKey(attacker.Public(), make([]byte, vaultKeySize))
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	pub := Pub(attacker.Public())
	f.Device[pub] = Device{EPub: ePub, Wrap: body, Name: "pwned"}

	if _, err := f.Secrets(key); err != nil {
		t.Fatalf("Secrets of the honest entries: %v", err)
	}
	if _, err := f.Devices(key); err == nil {
		t.Fatal("Devices accepted a device entry sealed outside the vault key")
	}
	if _, err := f.Rotate(key, "new passphrase"); err == nil {
		t.Fatal("Rotate ran past a device entry sealed outside the vault key")
	}
}

// TestRotateRewraps verifies a rotated vault opens for the same device under
// the new key, keeps every value, and moves recovery to the new passphrase.
func TestRotateRewraps(t *testing.T) {
	f, dk, key := newFixture(t)

	fresh, err := f.Rotate(key, "new passphrase")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	values, err := f.Secrets(fresh)
	if err != nil {
		t.Fatalf("Secrets after rotate: %v", err)
	}
	if values["API_KEY"] != "s3cret" {
		t.Fatalf("values after rotate = %v", values)
	}
	unsealed, err := f.Unseal(dk)
	if err != nil {
		t.Fatalf("Unseal after rotate: %v", err)
	}
	if !bytes.Equal(unsealed, fresh) {
		t.Fatal("the device unsealed a different key than the rotated one")
	}
	if _, err := f.Secrets(key); err == nil {
		t.Fatal("the old vault key still opens the entries")
	}
	if _, err := f.UnsealPassphrase("new passphrase"); err != nil {
		t.Fatalf("the new recovery wrap does not open: %v", err)
	}
	if _, err := f.UnsealPassphrase("open sesame"); err == nil {
		t.Fatal("the old recovery passphrase still works after rotate")
	}
}

// TestRemoveLastDeviceIsRefused keeps the vault from losing its last device.
func TestRemoveLastDeviceIsRefused(t *testing.T) {
	f, dk, _ := newFixture(t)

	if err := f.RemoveDevice(Pub(dk.Public())); !errors.Is(err, ErrLast) {
		t.Fatalf("RemoveDevice of the last device = %v, want ErrLast", err)
	}
	if len(f.Device) != 1 {
		t.Fatalf("the last device was removed anyway, %d left", len(f.Device))
	}
}

// TestSaveConflict covers both writers losing: a vault that would overwrite an
// existing file and a save that raced with another machine's write.
func TestSaveConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	f, _, key := newFixture(t)

	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// A vault from scratch would overwrite an existing file.
	fresh := &File{Version: Version, Device: map[string]Device{}, Secret: map[string]string{}}
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

// TestWrongPassphraseFails is the whole recovery barrier.
func TestWrongPassphraseFails(t *testing.T) {
	f, _, _ := newFixture(t)

	if _, err := f.UnsealPassphrase("wrong"); err == nil {
		t.Fatal("the wrong passphrase opened the recovery wrap")
	}
}

// TestValidName guards the eval the shell hook runs the output through, and
// the names that would take the shell over.
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

func TestValidDeviceName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"my-laptop.local", true},
		{"laptop", true},
		{"", false},
		{"has space", false},
	} {
		if got := validDeviceName(tc.name); got != tc.want {
			t.Fatalf("validDeviceName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestDisableKeepsEntry is the comment out contract: the value leaves the
// shell's map, survives under DisabledSecrets, and comes back on Enable with
// the file version tracking the table's presence.
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

// TestUnsetDropsDisabled covers deleting a commented out key: it leaves both
// tables, not just the visible one.
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

// TestDisabledBodyRefusesTableMove covers pasting a disabled body back into
// the [secret] table: the body is sealed to the slot it belongs to, so
// uncommenting through the file rather than fuu edit is a refusal.
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

// TestRotateKeepsDisabled verifies a rotation rewraps commented out entries
// too, under the disabled slot of the new key.
func TestRotateKeepsDisabled(t *testing.T) {
	f, dk, key := newFixture(t)
	if err := f.Disable(key, "API_KEY"); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	fresh, err := f.Rotate(key, "new passphrase")
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
	if _, err = f.Unseal(dk); err != nil {
		t.Fatalf("Unseal after rotate: %v", err)
	}
}

// TestParseRefusesUnknownVersion keeps a future format loud: this build says
// what it reads and nothing else sneaks past.
func TestParseRefusesUnknownVersion(t *testing.T) {
	if _, err := Parse([]byte("version = 3\n")); !errors.Is(err, errBadVersion) {
		t.Fatalf("Parse of version 3 = %v, want errBadVersion", err)
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
