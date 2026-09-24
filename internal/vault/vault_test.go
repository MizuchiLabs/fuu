package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
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
		t.Fatalf("generate signer key: %v", err)
	}
	return &softSigner{key: key}
}

func (s *softSigner) Public() *ecdsa.PublicKey { return &s.key.PublicKey }

func (s *softSigner) Sign(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

// newFixture builds a vault with two devices, a recovery wrap and two secret values, with laptop enrolled first and desktop second.
func newFixture(t *testing.T) (f *File, laptop, desktop *softSigner) {
	t.Helper()
	dk, other := newSoftKey(t), newSoftKey(t)
	laptop, desktop = newSoftSigner(t), newSoftSigner(t)

	f, err := New(dk, "laptop", "open sesame", laptop.Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key, err := f.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	defer clear(key)

	if err := f.AddDevice(key, "desktop", other.Public(), desktop.Public()); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := f.Set(key, "shop", "DATABASE_URL", []byte("postgres://x")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Set(key, "shop", "API_KEY", []byte("s3cret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	return f, laptop, desktop
}

// stampAndCheck stamps f and asserts the untampered vault verifies, so a later rejection is down to the mutation.
func stampAndCheck(t *testing.T, f *File, signer *softSigner) {
	t.Helper()
	if err := f.Stamp(signer); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Verify(registryPubs(t, f)); err != nil {
		t.Fatalf("Verify after Stamp: %v", err)
	}
}

// registryPubs stands in for the pinned trust anchors a caller brings from
// outside the file, pinned to the fixture's own registry.
func registryPubs(t *testing.T, f *File) []*ecdsa.PublicKey {
	t.Helper()
	pubs, err := f.SignerPubs()
	if err != nil {
		t.Fatalf("SignerPubs: %v", err)
	}
	return pubs
}

func TestPubRoundTrip(t *testing.T) {
	for range 8 {
		dk := newSoftKey(t)
		want := dk.Public()

		got, err := ParsePub(Pub(want))
		if err != nil {
			t.Fatalf("ParsePub: %v", err)
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatal("ParsePub(Pub(k)) did not return the same point")
		}
	}
}

func TestParsePubRejectsJunk(t *testing.T) {
	for _, in := range []string{"", "age1qqqq", "p256:AAAA", "p256:!!!"} {
		if _, err := ParsePub(in); err == nil {
			t.Fatalf("ParsePub(%q) accepted junk", in)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dk := newSoftKey(t)
	signer := newSoftSigner(t)
	f, err := New(dk, "laptop", "open sesame", signer.Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key, err := f.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	defer clear(key)
	if err := f.Set(key, "shop", "DATABASE_URL", []byte("postgres://x")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Stamp(signer); err != nil {
		t.Fatalf("Stamp: %v", err)
	}

	path := filepath.Join(t.TempDir(), "fuu.toml")
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != Version {
		t.Fatalf("Version = %d, want %d", got.Version, Version)
	}
	if _, ok := got.Device["laptop"]; !ok {
		t.Fatal("device laptop did not survive the TOML round trip")
	}
	if _, ok := got.Secret["shop"]["DATABASE_URL"]; !ok {
		t.Fatal("secret shop:DATABASE_URL did not survive the TOML round trip")
	}
	if err := got.Verify(registryPubs(t, got)); err != nil {
		t.Fatalf("Verify after reload: %v", err)
	}

	reloaded, err := got.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey after reload: %v", err)
	}
	defer clear(reloaded)
	value, err := got.Get(reloaded, "shop", "DATABASE_URL")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(value) != "postgres://x" {
		t.Fatalf("Get = %q, want %q", value, "postgres://x")
	}
}

func TestVaultKeyUnsealsTwice(t *testing.T) {
	dk := newSoftKey(t)
	f, err := New(dk, "laptop", "open sesame", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	viaDevice, err := f.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	defer clear(viaDevice)

	viaPass, err := f.VaultKeyPass("open sesame")
	if err != nil {
		t.Fatalf("VaultKeyPass: %v", err)
	}
	defer clear(viaPass)

	if !bytes.Equal(viaDevice, viaPass) {
		t.Fatal("the device wrap and the recovery wrap hold different vault keys")
	}

	if _, err := f.VaultKeyPass("wrong"); err == nil {
		t.Fatal("VaultKeyPass accepted the wrong passphrase")
	}
}

func TestAddDeviceThenRotate(t *testing.T) {
	laptop := newSoftKey(t)
	desktop := newSoftKey(t)

	f, err := New(laptop, "laptop", "open sesame", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	old, err := f.VaultKey(laptop)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	if err := f.AddDevice(old, "desktop", desktop.Public(), newSoftSigner(t).Public()); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := f.Set(old, "shop", "API_KEY", []byte("s3cret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	signPub := f.Device["desktop"].SignPub

	if err := f.Rotate(old, "new passphrase"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	clear(old)

	if f.Device["desktop"].SignPub != signPub {
		t.Fatal("Rotate did not preserve the device signing key")
	}

	fresh, err := f.VaultKey(desktop)
	if err != nil {
		t.Fatalf("VaultKey after rotate: %v", err)
	}
	defer clear(fresh)

	value, err := f.Get(fresh, "shop", "API_KEY")
	if err != nil {
		t.Fatalf("Get after rotate: %v", err)
	}
	if string(value) != "s3cret" {
		t.Fatalf("Get after rotate = %q, want %q", value, "s3cret")
	}

	if _, err := f.VaultKeyPass("new passphrase"); err != nil {
		t.Fatalf("recovery wrap after rotate: %v", err)
	}
	if _, err := f.VaultKeyPass("open sesame"); err == nil {
		t.Fatal("the old recovery passphrase still works after rotate")
	}
}

func TestRemoveDeviceRevokes(t *testing.T) {
	laptop := newSoftKey(t)
	desktop := newSoftKey(t)

	f, err := New(laptop, "laptop", "open sesame", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key, err := f.VaultKey(laptop)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	defer clear(key)

	if err := f.AddDevice(key, "desktop", desktop.Public(), newSoftSigner(t).Public()); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := f.RemoveDevice("desktop"); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
	if _, err := f.VaultKey(desktop); err == nil {
		t.Fatal("a revoked device still unseals the vault key")
	}
	if err := f.RemoveDevice("desktop"); err == nil {
		t.Fatal("RemoveDevice accepted a name that is already gone")
	}
}

func TestRemoveLastDeviceIsRefused(t *testing.T) {
	dk := newSoftKey(t)
	f, err := New(dk, "laptop", "open sesame", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := f.RemoveDevice("laptop"); !errors.Is(err, ErrLastDevice) {
		t.Fatalf("RemoveDevice of the last device = %v, want ErrLastDevice", err)
	}
	if len(f.Device) != 1 {
		t.Fatalf("the last device was removed anyway, %d left", len(f.Device))
	}
}

func TestUnsetDropsEmptyProject(t *testing.T) {
	dk := newSoftKey(t)
	f, err := New(dk, "laptop", "open sesame", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key, err := f.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	defer clear(key)

	if err := f.Set(key, "shop", "ONLY", []byte("x")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Unset("shop", "ONLY"); err != nil {
		t.Fatalf("Unset: %v", err)
	}
	if _, ok := f.Secret["shop"]; ok {
		t.Fatal("Unset left an empty project behind")
	}
	if err := f.Unset("shop", "ONLY"); err == nil {
		t.Fatal("Unset accepted a key that is already gone")
	}
}

func TestCanonicalStable(t *testing.T) {
	f, _, _ := newFixture(t)
	first := f.Canonical()
	second := f.Canonical()
	if !bytes.Equal(first, second) {
		t.Fatal("Canonical changed between two calls")
	}
}

func TestCanonicalChanges(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *File)
	}{
		{"device field", func(f *File) {
			d := f.Device["desktop"]
			d.Wrap += "x"
			f.Device["desktop"] = d
		}},
		{"recovery mem", func(f *File) { f.Recovery.Mem++ }},
		{"secret value", func(f *File) { f.Secret["shop"]["API_KEY"] = "tampered" }},
		{"secret key name", func(f *File) {
			keys := f.Secret["shop"]
			body := keys["API_KEY"]
			delete(keys, "API_KEY")
			keys["API_URL"] = body
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _ := newFixture(t)
			before := f.Canonical()
			tc.mutate(f)
			if bytes.Equal(before, f.Canonical()) {
				t.Fatal("Canonical did not change after the mutation")
			}
		})
	}
}

func TestStampVerifyRoundTrip(t *testing.T) {
	f, laptop, _ := newFixture(t)
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Verify(registryPubs(t, f)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedDevice(t *testing.T) {
	f, laptop, _ := newFixture(t)
	stampAndCheck(t, f, laptop)

	d := f.Device["desktop"]
	d.Wrap = "tampered"
	f.Device["desktop"] = d

	if err := f.Verify(registryPubs(t, f)); !errors.Is(err, sig.ErrUnverified) {
		t.Fatalf("Verify = %v, want ErrUnverified", err)
	}
}

// TestVerifyRejectsKDFDowngrade covers rewriting recovery mem or time, which would let an outsider crack the passphrase offline against weakened argon2id parameters.
func TestVerifyRejectsKDFDowngrade(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *File)
	}{
		{"mem", func(f *File) { f.Recovery.Mem = 1 }},
		{"time", func(f *File) { f.Recovery.Time = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, laptop, _ := newFixture(t)
			stampAndCheck(t, f, laptop)

			tc.mutate(f)
			if err := f.Verify(registryPubs(t, f)); !errors.Is(err, sig.ErrUnverified) {
				t.Fatalf("Verify = %v, want ErrUnverified", err)
			}
		})
	}
}

func TestVerifyRejectsDeletedSecret(t *testing.T) {
	f, laptop, _ := newFixture(t)
	stampAndCheck(t, f, laptop)

	delete(f.Secret["shop"], "API_KEY")

	if err := f.Verify(registryPubs(t, f)); !errors.Is(err, sig.ErrUnverified) {
		t.Fatalf("Verify = %v, want ErrUnverified", err)
	}
}

func TestVerifyRejectsDeletedDevice(t *testing.T) {
	f, laptop, _ := newFixture(t)
	stampAndCheck(t, f, laptop)

	delete(f.Device, "desktop")

	if err := f.Verify(registryPubs(t, f)); !errors.Is(err, sig.ErrUnverified) {
		t.Fatalf("Verify = %v, want ErrUnverified", err)
	}
}

func TestVerifyRejectsEmptySig(t *testing.T) {
	f, laptop, _ := newFixture(t)
	if err := f.Verify(registryPubs(t, f)); !errors.Is(err, ErrNoSig) {
		t.Fatalf("Verify of an unsigned vault = %v, want ErrNoSig", err)
	}

	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	f.Sig = ""
	if err := f.Verify(registryPubs(t, f)); !errors.Is(err, ErrNoSig) {
		t.Fatalf("Verify with an empty Sig = %v, want ErrNoSig", err)
	}
}

func TestVerifyAcceptsSecondDeviceSigner(t *testing.T) {
	f, _, desktop := newFixture(t)
	if err := f.Stamp(desktop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Verify(registryPubs(t, f)); err != nil {
		t.Fatalf("Verify with the second device signing: %v", err)
	}
}

// TestVerifyRejectsSelfCertifiedVault covers the rewrite attack: someone with
// write access to the file keeps the victim registry intact, adds their own
// signing key and re-signs. The vault is internally consistent, so anchors
// taken from the registry accept it, anchors pinned before the rewrite do not.
func TestVerifyRejectsSelfCertifiedVault(t *testing.T) {
	f, laptop, _ := newFixture(t)
	stampAndCheck(t, f, laptop)
	pins := registryPubs(t, f)

	attacker := newSoftSigner(t)
	signer, err := sig.EncodeSigner(attacker.Public())
	if err != nil {
		t.Fatalf("EncodeSigner: %v", err)
	}
	f.Device["attacker"] = Device{Created: "2026-09-24", Pub: "p256:AAA", SignPub: signer}
	if err := f.Stamp(attacker); err != nil {
		t.Fatalf("Stamp: %v", err)
	}

	if err := f.Verify(pins); !errors.Is(err, sig.ErrUnknownSigner) {
		t.Fatalf("Verify against pre-attack pins = %v, want ErrUnknownSigner", err)
	}
	// The old self-certifying behaviour, kept as documentation of the gap.
	if err := f.Verify(registryPubs(t, f)); err != nil {
		t.Fatalf("Verify against the rewritten registry = %v, want nil", err)
	}
}

func TestProjectRejectsBadKeyName(t *testing.T) {
	f, laptop, _ := newFixture(t)
	stampAndCheck(t, f, laptop)

	keys := f.Secret["shop"]
	body := keys["API_KEY"]
	delete(keys, "API_KEY")
	keys["EVIL=rm"] = body

	// The name guard runs before anything is unsealed, so a nil key is enough.
	if _, err := f.Project(nil, "shop"); !errors.Is(err, ErrBadName) {
		t.Fatalf("Project = %v, want ErrBadName", err)
	}
}

func TestAddDeviceRefusesTaken(t *testing.T) {
	laptop := newSoftKey(t)
	f, err := New(laptop, "laptop", "open sesame", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key, err := f.VaultKey(laptop)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	defer clear(key)

	// A taken name is never overwritten, that silently revokes its holder.
	err = f.AddDevice(key, "laptop", newSoftKey(t).Public(), newSoftSigner(t).Public())
	if !errors.Is(err, ErrDupName) {
		t.Fatalf("AddDevice with a taken name = %v, want ErrDupName", err)
	}
	if len(f.Device) != 1 {
		t.Fatalf("a refused AddDevice changed the registry, %d devices", len(f.Device))
	}

	other := newSoftKey(t)
	if err := f.AddDevice(key, "desktop", other.Public(), newSoftSigner(t).Public()); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	err = f.AddDevice(key, "again", other.Public(), newSoftSigner(t).Public())
	if !errors.Is(err, ErrDupDevice) {
		t.Fatalf("AddDevice with a taken key = %v, want ErrDupDevice", err)
	}
}

func TestVaultKeyPassRefusesEmpty(t *testing.T) {
	dk := newSoftKey(t)
	f, err := New(dk, "laptop", "open sesame", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := f.VaultKeyPass(""); !errors.Is(err, ErrEmptyPass) {
		t.Fatalf("VaultKeyPass with an empty passphrase = %v, want ErrEmptyPass", err)
	}
}
