package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mizuchilabs/fuu/internal/seal"
	"github.com/mizuchilabs/fuu/internal/sig"
	"github.com/mizuchilabs/fuu/internal/vault"
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

// isolatePins points the config dir at a temp dir so tests never touch the
// real pin store, and returns the vault path inside another temp dir.
func isolatePins(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := t.TempDir()
	return filepath.Join(dir, "fuu.toml")
}

// writeVault builds a vault with laptop enrolled, optionally desktop too,
// signs it with laptop and saves it to path.
func writeVault(t *testing.T, path string, withDesktop bool) (laptop, desktop *softSigner) {
	t.Helper()
	laptop, desktop = newSoftSigner(t), newSoftSigner(t)

	f, err := vault.New(newSoftKey(t), "laptop", "open sesame", laptop.Public())
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if withDesktop {
		key, err := f.VaultKeyPass("open sesame")
		if err != nil {
			t.Fatalf("VaultKeyPass: %v", err)
		}
		if err := f.AddDevice(key, "desktop", newSoftKey(t).Public(), desktop.Public()); err != nil {
			t.Fatalf("AddDevice: %v", err)
		}
		clear(key)
	}
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return laptop, desktop
}

func mustPins(t *testing.T, path string) []string {
	t.Helper()
	pins, err := loadPins(path)
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	return pins.Signers
}

// TestVerifyPinnedRejectsSelfCertifiedVault is the regression test for the
// rewrite attack: an attacker with write access to the vault file adds their
// own signing key and re-signs. Before pins, the vault certified itself and
// every read path accepted it.
func TestVerifyPinnedRejectsSelfCertifiedVault(t *testing.T) {
	path := isolatePins(t)
	writeVault(t, path, true)

	if _, err := openVerified(path); err != nil {
		t.Fatalf("first open: %v", err)
	}
	pins := mustPins(t, path)
	if len(pins) != 2 {
		t.Fatalf("TOFU pinned %d signers, want 2", len(pins))
	}

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	attacker := newSoftSigner(t)
	signer, err := sig.EncodeSigner(attacker.Public())
	if err != nil {
		t.Fatalf("EncodeSigner: %v", err)
	}
	f.Device["attacker"] = vault.Device{Created: "2026-09-24", SignPub: signer}
	if err := f.Stamp(attacker); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := openVerified(path); !errors.Is(err, sig.ErrUnknownSigner) {
		t.Fatalf("openVerified of the rewritten vault = %v, want ErrUnknownSigner", err)
	}
	if got := mustPins(t, path); len(got) != 2 {
		t.Fatalf("pins changed to %d signers after a rejected vault", len(got))
	}
}

// TestVerifyPinnedFollowsBlessedRegistry covers growth and shrinkage: a pinned
// signature that adds a device grows the pins, one that revokes a device
// shrinks them, and the revoked device's own signature stops verifying.
func TestVerifyPinnedFollowsBlessedRegistry(t *testing.T) {
	path := isolatePins(t)
	laptop, desktop := writeVault(t, path, false)

	if _, err := openVerified(path); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if got := mustPins(t, path); len(got) != 1 {
		t.Fatalf("TOFU pinned %d signers, want 1", len(got))
	}

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	key, err := f.VaultKeyPass("open sesame")
	if err != nil {
		t.Fatalf("VaultKeyPass: %v", err)
	}
	defer clear(key)
	if err := f.AddDevice(key, "desktop", newSoftKey(t).Public(), desktop.Public()); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := openVerified(path); err != nil {
		t.Fatalf("open after blessed add: %v", err)
	}
	if got := mustPins(t, path); len(got) != 2 {
		t.Fatalf("pins after blessed add = %d, want 2", len(got))
	}

	if err := f.RemoveDevice("desktop"); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := openVerified(path); err != nil {
		t.Fatalf("open after revocation: %v", err)
	}
	if got := mustPins(t, path); len(got) != 1 {
		t.Fatalf("pins after revocation = %d, want 1", len(got))
	}

	if err := f.Stamp(desktop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := openVerified(path); !errors.Is(err, sig.ErrUnknownSigner) {
		t.Fatalf("open of a vault signed by the revoked device = %v, want ErrUnknownSigner", err)
	}
}

func TestSingleLineName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"shop", true},
		{"shop-2", true},
		{"shop.x", true},
		{"", false},
		{"foo\nPROMPT_COMMAND = \"evil\"", false},
		{"foo\rBAR = \"evil\"", false},
		{"foo\vbaz", false},
		{"foo\tbaz", false},
		{"my shop", true},
		{"foo\u2028baz", false},
	}
	for _, tc := range cases {
		if got := singleLineName(tc.name); got != tc.want {
			t.Errorf("singleLineName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestLockVaultBlocks(t *testing.T) {
	path := isolatePins(t)

	release, err := lockVault(path)
	if err != nil {
		t.Fatalf("lockVault: %v", err)
	}

	b := make(chan struct{})
	go func() {
		release2, err := lockVault(path)
		if err != nil {
			t.Errorf("lockVault: %v", err)
		} else {
			release2()
		}
		close(b)
	}()

	select {
	case <-b:
		t.Fatal("lockVault returned while the lock was held")
	case <-time.After(100 * time.Millisecond):
	}
	release()

	select {
	case <-b:
	case <-time.After(5 * time.Second):
		t.Fatal("lockVault did not return after release")
	}
}

func TestTrustVaultAcceptsUnsigned(t *testing.T) {
	path := isolatePins(t)
	writeVault(t, path, true)

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f.Sig, f.Signer = "", ""
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := trustVault(path, "open sesame", newSoftKey(t)); err != nil {
		t.Fatalf("trustVault: %v", err)
	}
	registry := registrySigners(f)
	if len(registry) != 2 {
		t.Fatalf("registry has %d signers, want 2", len(registry))
	}
	if got := mustPins(t, path); !slices.Equal(got, registry) {
		t.Fatalf("pins = %v, want %v", got, registry)
	}
}

// TestTrustVaultRejectsTampered covers the self inconsistent vault: the device
// registry changed but the signature is still the old one. Nothing about the
// file can be verified, so nothing gets pinned.
func TestTrustVaultRejectsTampered(t *testing.T) {
	path := isolatePins(t)
	writeVault(t, path, true)

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d := f.Device["laptop"]
	d.Wrap = "tampered"
	f.Device["laptop"] = d
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := trustVault(path, "open sesame", newSoftKey(t)); !errors.Is(err, sig.ErrUnverified) {
		t.Fatalf("trustVault = %v, want ErrUnverified", err)
	}
	if got := mustPins(t, path); len(got) != 0 {
		t.Fatalf("pins = %v after a tampered vault, want none", got)
	}
}

func TestCheckBless(t *testing.T) {
	path := isolatePins(t)
	writeVault(t, path, true)
	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	registry := registrySigners(f)

	cases := []struct {
		name    string
		pins    []string
		wantErr bool
	}{
		{"no pins", nil, false},
		{"pins match the registry", registry, false},
		{"pins missing one entry", registry[:1], true},
		{"foreign pins", []string{"foreign"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkBless(f, pinFile{Signers: tc.pins})
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkBless(%v) = %v, want error %v", tc.pins, err, tc.wantErr)
			}
		})
	}
}

func TestPresent(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "chain keeps the sentence and the hint",
			err:  trustHint(fmt.Errorf("vault: verify: %w", sig.ErrUnknownSigner)),
			want: "signer is not among the accepted public keys\nif you knowingly replaced the vault run fuu trust, otherwise this file is not what it claims to be",
		},
		{
			name: "chain keeps the sentence",
			err:  fmt.Errorf("vault: verify: %w", sig.ErrUnverified),
			want: "signature does not verify over the payload",
		},
		{
			name: "suffix after the sentinel stays",
			err:  fmt.Errorf("%w %q", vault.ErrNoDevice, "laptop"),
			want: `no such device "laptop"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := present(tc.err); got != tc.want {
				t.Fatalf("present = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckBlessRefusesRevoked(t *testing.T) {
	path := isolatePins(t)
	writeVault(t, path, true)
	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	registry := registrySigners(f)
	pins := pinFile{Signers: registry, Revoked: registry[:1]}
	if err := checkBless(f, pins); !errors.Is(err, errRevokedSigner) {
		t.Fatalf("checkBless = %v, want errRevokedSigner", err)
	}
}

// TestRevokedSignerCannotReturnViaReplay is the regression test for the replay
// attack: a revoked device comes back through a pre-revocation copy of the
// file, and its signing key then signs again with local approval.
func TestRevokedSignerCannotReturnViaReplay(t *testing.T) {
	path := isolatePins(t)
	laptop, _ := writeVault(t, path, true)

	if _, err := openVerified(path); err != nil {
		t.Fatalf("first open: %v", err)
	}
	replay, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	desktopPub := f.Device["desktop"].SignPub
	if err := f.RemoveDevice("desktop"); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := openVerified(path); err != nil {
		t.Fatalf("open after revocation: %v", err)
	}
	pins, err := loadPins(path)
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	if !slices.Contains(pins.Revoked, desktopPub) {
		t.Fatalf("revoked = %v, want it to carry %s", pins.Revoked, desktopPub)
	}

	if err := os.WriteFile(path, replay, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := openVerified(path); !errors.Is(err, errRevokedSigner) {
		t.Fatalf("open of the replayed vault = %v, want errRevokedSigner", err)
	}
}

func TestTrustVaultForgetsRevoked(t *testing.T) {
	path := isolatePins(t)
	laptop, _ := writeVault(t, path, true)

	if _, err := openVerified(path); err != nil {
		t.Fatalf("first open: %v", err)
	}
	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := f.RemoveDevice("desktop"); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := openVerified(path); err != nil {
		t.Fatalf("open after revocation: %v", err)
	}

	if err := trustVault(path, "open sesame", newSoftKey(t)); err != nil {
		t.Fatalf("trustVault: %v", err)
	}
	pins, err := loadPins(path)
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	if len(pins.Revoked) != 0 {
		t.Fatalf("revoked = %v after fuu trust, want none", pins.Revoked)
	}
}

func TestProveKey(t *testing.T) {
	dk := newSoftKey(t)
	f, err := vault.New(dk, "laptop", "open sesame", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := proveKey(f, "open sesame", dk); err != nil {
		t.Fatalf("proveKey: %v", err)
	}
	if err := proveKey(f, "wrong", dk); err == nil {
		t.Fatal("proveKey accepted the wrong passphrase")
	}
	// Not being a device here leaves the recovery wrap as the only proof.
	if err := proveKey(f, "open sesame", newSoftKey(t)); err != nil {
		t.Fatalf("proveKey from a stranger: %v", err)
	}
}

// TestProveKeyRejectsStitchedWraps covers the bless attack: a replaced vault
// whose recovery wrap holds one vault key and whose device wrap another. No
// attacker without the recovery passphrase can build a consistent pair.
func TestProveKeyRejectsStitchedWraps(t *testing.T) {
	dk := newSoftKey(t)
	f, err := vault.New(dk, "laptop", "open sesame", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stitch, err := seal.WrapPassphrase("open sesame", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}
	f.Recovery = vault.Recovery{
		KDF:  stitch.KDF,
		Salt: stitch.Salt,
		Mem:  stitch.Mem,
		Time: stitch.Time,
		Wrap: stitch.Body,
	}

	if err := proveKey(f, "open sesame", dk); err == nil {
		t.Fatal("proveKey accepted stitched wraps")
	}
}

func TestParseValuesGuards(t *testing.T) {
	if _, err := parseValues([]byte(`X = "a\u0000b"` + "\n")); err == nil {
		t.Fatal("parseValues accepted a NUL byte")
	}
	values, err := parseValues([]byte("PROMPT_COMMAND = \"x\"\n"))
	if err != nil {
		t.Fatalf("parseValues: %v", err)
	}
	if _, ok := values["PROMPT_COMMAND"]; !ok {
		t.Fatal("a hazard name is storable, only the hook keeps it out of the shell")
	}
}

func TestCheckPassphrase(t *testing.T) {
	if err := checkPassphrase("short"); err == nil {
		t.Fatal("checkPassphrase accepted 5 characters")
	}
	if err := checkPassphrase("            "); err == nil {
		t.Fatal("checkPassphrase accepted whitespace only")
	}
	if err := checkPassphrase("12 chars long"); err != nil {
		t.Fatalf("checkPassphrase: %v", err)
	}
}
