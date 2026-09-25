package vault

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mizuchilabs/fuu/internal/seal"
	"github.com/mizuchilabs/fuu/internal/sig"
)

type softKey struct{ key *ecdh.PrivateKey }

var _ seal.DeviceKey = (*softKey)(nil)

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

type softSigner struct{ key *ecdsa.PrivateKey }

var _ sig.Signer = (*softSigner)(nil)

func newSoftSigner(t *testing.T) *softSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	return &softSigner{key: key}
}

func (s *softSigner) Public() *ecdsa.PublicKey { return &s.key.PublicKey }

func (s *softSigner) Sign(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

// newFixture builds a vault with one device and two values, sealed and signed.
func newFixture(t *testing.T) (f *File, dk *softKey, key []byte) {
	t.Helper()
	dk, signer := newSoftKey(t), newSoftSigner(t)

	f, err := New(dk, "open sesame", "laptop", signer.Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key, err = f.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	t.Cleanup(func() { clear(key) })

	for name, value := range map[string]string{"API_KEY": "s3cret", "DATABASE_URL": "postgres://x"} {
		if err := f.Set(key, name, []byte(value)); err != nil {
			t.Fatalf("Set %s: %v", name, err)
		}
	}
	if err := f.Stamp(signer); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	return f, dk, key
}

// TestFileHidesNames is the point of the format: nothing in the readable
// bytes reveals what the vault holds or whose chips are enrolled.
func TestFileHidesNames(t *testing.T) {
	f, _, _ := newFixture(t)

	path := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw := string(mustRead(t, path))

	for _, leak := range []string{"API_KEY", "DATABASE_URL", "postgres://x", "s3cret", "laptop", "open sesame"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("the vault file leaks %q", leak)
		}
	}
	for _, want := range []string{"version", "vaultid", "seq", "blob", "device", "recovery", "secret"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("the vault file is missing its %q field", want)
		}
	}
}

// TestValuesRoundTrip covers the open path the shell hook uses.
func TestValuesRoundTrip(t *testing.T) {
	f, dk, _ := newFixture(t)

	key, err := f.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	defer clear(key)

	values, err := f.Values(key)
	if err != nil {
		t.Fatalf("Values: %v", err)
	}
	if values["API_KEY"] != "s3cret" || values["DATABASE_URL"] != "postgres://x" {
		t.Fatalf("values = %v", values)
	}

	names, err := f.Names(key)
	if err != nil {
		t.Fatalf("Names: %v", err)
	}
	if len(names) != 2 || names[0] != "API_KEY" {
		t.Fatalf("names = %v", names)
	}
}

// TestSaveLoadRoundTrip verifies the file form survives git, which is the
// whole point of the format.
func TestSaveLoadRoundTrip(t *testing.T) {
	f, dk, _ := newFixture(t)

	path := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.VaultID != f.VaultID {
		t.Fatalf("vaultid = %q, want %q", got.VaultID, f.VaultID)
	}
	if got.Digest() != f.Digest() {
		t.Fatal("digest differs after a reload")
	}
	pubs, err := got.SignerPubs(mustKey(t, got, dk))
	if err != nil {
		t.Fatalf("SignerPubs: %v", err)
	}
	if err := got.Verify(pubs); err != nil {
		t.Fatalf("Verify after reload: %v", err)
	}
}

// TestEditKeepsUnchangedEntriesUntouched keeps git diffs small: a value edit
// rewrites one body and leaves the payload blob alone.
func TestEditKeepsUnchangedEntriesUntouched(t *testing.T) {
	f, _, key := newFixture(t)

	before := f.Blob
	if err := f.Set(key, "API_KEY", []byte("rotated")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if f.Blob != before {
		t.Fatal("a value edit rewrote the name blob, the diff would show everything")
	}
	got, err := f.Get(key, "API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "rotated" {
		t.Fatalf("got %q", got)
	}

	// a new name does change the blob, it has to
	if err := f.Set(key, "NEW_KEY", []byte("x")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if f.Blob == before {
		t.Fatal("adding a name left the name blob alone")
	}
}

// TestValueBoundToItsName covers swapping two bodies in the file.
func TestValueBoundToItsName(t *testing.T) {
	f, _, key := newFixture(t)

	mine, err := seal.NameToken(key, "API_KEY")
	if err != nil {
		t.Fatalf("NameToken: %v", err)
	}
	other, err := seal.NameToken(key, "DATABASE_URL")
	if err != nil {
		t.Fatalf("NameToken: %v", err)
	}
	f.Secret[other] = f.Secret[mine]

	// the body carries its own name as additional data, so it will not open
	// under the entry it was pasted into
	if _, err := f.Get(key, "DATABASE_URL"); err == nil {
		t.Fatal("a pasted body opened under the wrong name")
	}
	got, err := f.Get(key, "API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "s3cret" {
		t.Fatalf("got %q", got)
	}
}

// TestRotateRewraps verifies a rotated vault opens for the same device with
// the new key and keeps every value.
func TestRotateRewraps(t *testing.T) {
	f, dk, key := newFixture(t)

	if err := f.Rotate(key, "new passphrase"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	clear(key)

	fresh, err := f.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey after rotate: %v", err)
	}
	defer clear(fresh)

	values, err := f.Values(fresh)
	if err != nil {
		t.Fatalf("Values after rotate: %v", err)
	}
	if values["API_KEY"] != "s3cret" {
		t.Fatalf("values after rotate = %v", values)
	}
	if _, err := f.VaultKeyPass("new passphrase"); err != nil {
		t.Fatalf("the new recovery wrap does not open: %v", err)
	}
	if _, err := f.VaultKeyPass("open sesame"); err == nil {
		t.Fatal("the old recovery passphrase still works after rotate")
	}
}

// TestDeviceLifecycle covers enrolling, revoking and the guard on the last
// device, with no leftover side effects on the values.
func TestDeviceLifecycle(t *testing.T) {
	f, _, key := newFixture(t)

	other := newSoftKey(t)
	otherSigner := newSoftSigner(t)
	if err := f.AddDevice(key, "desktop", "2026-09-24", other.Public(), otherSigner.Public()); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := f.AddDevice(
		key,
		"desktop",
		"2026-09-24",
		newSoftKey(t).Public(),
		newSoftSigner(t).Public(),
	); !errors.Is(
		err,
		ErrDupName,
	) {
		t.Fatalf("AddDevice with a taken name = %v, want ErrDupName", err)
	}

	pub := Pub(other.Public())
	if err := f.RemoveDevice(key, pub); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
	if _, err := f.VaultKey(other); err == nil {
		t.Fatal("a revoked device still opens the vault key")
	}
	if err := f.RemoveDevice(key, pub); err == nil {
		t.Fatal("RemoveDevice accepted a device that is already gone")
	}

	values, err := f.Values(key)
	if err != nil {
		t.Fatalf("Values after revocation: %v", err)
	}
	if values["API_KEY"] != "s3cret" {
		t.Fatalf("revocation dropped values: %v", values)
	}
}

// TestRemoveLastDeviceIsRefused keeps the vault from becoming unverifiable.
func TestRemoveLastDeviceIsRefused(t *testing.T) {
	f, dk, key := newFixture(t)

	if err := f.RemoveDevice(key, Pub(dk.Public())); !errors.Is(err, ErrLast) {
		t.Fatalf("RemoveDevice of the last device = %v, want ErrLast", err)
	}
	if len(f.Device) != 1 {
		t.Fatalf("the last device was removed anyway, %d left", len(f.Device))
	}
}

// TestCanonicalCoversEverything is what makes a tamper visible: every field
// the file holds is in the signed bytes.
func TestCanonicalCoversEverything(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *File)
	}{
		{"seq", func(f *File) { f.Seq++ }},
		{"vaultid", func(f *File) { f.VaultID = "v_other" }},
		{"blob", func(f *File) { f.Blob += "x" }},
		{"device wrap", func(f *File) {
			for pub, d := range f.Device {
				d.Wrap += "x"
				f.Device[pub] = d
			}
		}},
		{"recovery mem", func(f *File) { f.Recovery.Mem++ }},
		{"secret body", func(f *File) {
			for token := range f.Secret {
				f.Secret[token] = "tampered"
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _ := newFixture(t)
			before := got.Canonical()
			tc.mutate(got)
			if string(before) == string(got.Canonical()) {
				t.Fatal("Canonical did not cover the mutated field")
			}
		})
	}
}

// TestVerifyRejectsTampering covers the read path the shell hook takes.
func TestVerifyRejectsTampering(t *testing.T) {
	f, _, key := newFixture(t)
	pubs, err := f.SignerPubs(key)
	if err != nil {
		t.Fatalf("SignerPubs: %v", err)
	}
	if err := f.Verify(pubs); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	f.Seq = 99
	if err := f.Verify(pubs); !errors.Is(err, sig.ErrUnverified) {
		t.Fatalf("Verify after tampering = %v, want ErrUnverified", err)
	}
}

// TestValidName guards the eval the shell hook runs the output through.
func TestValidName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"API_KEY", true},
		{"_", true},
		{"a1", true},
		{"1a", false},
		{"", false},
		{"A=B", false},
		{"A B", false},
		{"A\nB", false},
		{"$(id)", false},
	} {
		if got := ValidName(tc.name); got != tc.want {
			t.Fatalf("ValidName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestParseDeviceKeyBinding keeps the lookup key bound to the key the wrap is
// sealed to, so a doctored file cannot rename a device out of its slot.
func TestParseDeviceKeyBinding(t *testing.T) {
	matched := []byte(
		"version = 1\nvaultid = \"v_test\"\n\n[device.\"p256:AAAA\"]\npub = \"p256:AAAA\"\nepub = \"e\"\nwrap = \"w\"\n",
	)
	if _, err := Parse(matched, ".fuu.toml"); err != nil {
		t.Fatalf("Parse matching device: %v", err)
	}

	renamed := []byte(
		"version = 1\nvaultid = \"v_test\"\n\n[device.\"p256:AAAA\"]\npub = \"p256:BBBB\"\nepub = \"e\"\nwrap = \"w\"\n",
	)
	if _, err := Parse(renamed, ".fuu.toml"); err == nil {
		t.Fatal("Parse accepted a device whose map key does not match its key")
	}
}

func mustKey(t *testing.T, f *File, dk seal.DeviceKey) []byte {
	t.Helper()
	key, err := f.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	return key
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
