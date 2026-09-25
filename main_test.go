package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/seal"
	"github.com/mizuchilabs/fuu/internal/sig"
	"github.com/mizuchilabs/fuu/internal/vault"
	"github.com/urfave/cli/v3"
)

const fixtureDay = "2026-01-02"

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

// isolatePins points the pin store at a temp dir so tests never touch the
// real trust anchors, and returns a vault path inside another temp dir.
func isolatePins(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	return filepath.Join(t.TempDir(), ".fuu.toml")
}

// writeVault builds a vault with laptop enrolled, optionally desktop too,
// signed by laptop and saved to path. It hands back the open file, the vault
// key and both signing keys so tests can mutate and re-sign it.
func writeVault(t *testing.T, path string, withDesktop bool) (*vault.File, []byte, *softSigner, *softSigner) {
	t.Helper()
	laptop, desktop := newSoftSigner(t), newSoftSigner(t)
	dk := newSoftKey(t)

	f, err := vault.New(dk, "open sesame", "laptop", laptop.Public())
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	key, err := f.VaultKey(dk)
	if err != nil {
		t.Fatalf("VaultKey: %v", err)
	}
	t.Cleanup(func() { clear(key) })

	if withDesktop {
		if err := f.AddDevice(key, "desktop", fixtureDay, newSoftKey(t).Public(), desktop.Public()); err != nil {
			t.Fatalf("AddDevice: %v", err)
		}
	}
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return f, key, laptop, desktop
}

func encodeSigner(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	signer, err := sig.EncodeSigner(pub)
	if err != nil {
		t.Fatalf("EncodeSigner: %v", err)
	}
	return signer
}

// captureStderr swaps the process stderr for a pipe while f runs, so a test can
// read back what warnRollback prints at the operator.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w                      //nolint:reassign // capturing what warnRollback prints
	defer func() { os.Stderr = old }() //nolint:reassign // restoring after the capture

	f()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

// TestTrustKeepsOtherFoldersAccepted covers a regression where accepting a
// second checkout replaced the folder list and silently untrusted the first.
func TestTrustKeepsOtherFoldersAccepted(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	pathA := filepath.Join(t.TempDir(), ".fuu.toml")
	_, key, _, _ := writeVault(t, pathA, false)

	fA, err := vault.Load(pathA)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := trustVault(pathA, fA, key); err != nil {
		t.Fatalf("trustVault: %v", err)
	}

	raw, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	pathB := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := os.WriteFile(pathB, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fB, err := vault.Load(pathB)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := trustVault(pathB, fB, key); err != nil {
		t.Fatalf("trustVault at the second folder: %v", err)
	}

	if _, err := openVerified(pathA); err != nil {
		t.Fatalf("accepting a second folder untrusted the first: %v", err)
	}
	if _, err := openVerified(pathB); err != nil {
		t.Fatalf("openVerified at the second folder: %v", err)
	}
}

// TestTrustIsScopedToOneFolder covers that accepting a vault in one folder
// says nothing about a copy of the same bytes in another folder until fuu
// trust runs there.
func TestTrustIsScopedToOneFolder(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	pathA := filepath.Join(t.TempDir(), ".fuu.toml")
	_, key, _, _ := writeVault(t, pathA, false)

	fA, err := vault.Load(pathA)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := trustVault(pathA, fA, key); err != nil {
		t.Fatalf("trustVault: %v", err)
	}
	if _, err := openVerified(pathA); err != nil {
		t.Fatalf("openVerified where the vault was accepted: %v", err)
	}

	pathB := filepath.Join(t.TempDir(), ".fuu.toml")
	raw, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := os.WriteFile(pathB, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := openVerified(pathB); !errors.Is(err, errUntrusted) {
		t.Fatalf("openVerified in another folder = %v, want errUntrusted", err)
	}

	fB, err := vault.Load(pathB)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := trustVault(pathB, fB, key); err != nil {
		t.Fatalf("trustVault in the new folder: %v", err)
	}
	if _, err := openVerified(pathB); err != nil {
		t.Fatalf("openVerified after trust in the new folder: %v", err)
	}
}

// TestEnvReportsRefusalOnce pins what an operator sees from the every-prompt
// hook: a vault this machine has not accepted is reported once, then the shell
// hears nothing until the situation actually changes.
func TestEnvReportsRefusalOnce(t *testing.T) {
	path := isolatePins(t)
	writeVault(t, path, false)
	t.Chdir(filepath.Dir(path))
	t.Setenv("FUU_STAMP", "")
	t.Setenv("FUU_LOADED", "")

	runEnv := func() (string, string) {
		t.Helper()
		root := &cli.Command{
			Name:     "fuu",
			Flags:    []cli.Flag{vaultFlag},
			Commands: commands,
		}
		var out string
		errOut := captureStderr(t, func() {
			out = captureOutput(t, func() {
				if err := root.Run(t.Context(), []string{"fuu", "env", "--shell=posix"}); err != nil {
					t.Fatalf("env: %v", err)
				}
			})
		})
		return out, errOut
	}

	want := "fuu: this vault has not been accepted on this machine, if this is really yours run fuu trust here\n"
	out, errOut := runEnv()
	if errOut != want {
		t.Fatalf("first refusal printed %q, want %q", errOut, want)
	}
	_, rest, ok := strings.Cut(out, "export FUU_STAMP='")
	if !ok {
		t.Fatalf("refusal output %q carries no FUU_STAMP", out)
	}
	mark, _, ok := strings.Cut(rest, "'")
	if !ok {
		t.Fatalf("refusal output %q carries no closing quote", out)
	}
	t.Setenv("FUU_STAMP", mark)

	// The hook runs again at every later prompt, and those stay quiet.
	for prompt := 2; prompt <= 3; prompt++ {
		out, errOut = runEnv()
		if out != "" || errOut != "" {
			t.Fatalf("prompt %d after the refusal printed stdout %q stderr %q, want silence",
				prompt, out, errOut)
		}
	}
}

// TestStaleWriteCounterRefused covers rollback protection: the exact bytes
// this machine accepted always load, a signed mutation loads and moves the
// record forward, and an older signed copy of the same vault is refused.
func TestStaleWriteCounterRefused(t *testing.T) {
	path := isolatePins(t)
	f, key, laptop, _ := writeVault(t, path, false)

	if err := trustVault(path, f, key); err != nil {
		t.Fatalf("trustVault: %v", err)
	}
	for range 2 {
		if _, err := openVerified(path); err != nil {
			t.Fatalf("openVerified of the accepted bytes: %v", err)
		}
	}

	older, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if err := f.Set(key, "API_KEY", []byte("s3cret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	f.Seq++
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := openVerified(path)
	if err != nil {
		t.Fatalf("openVerified after a signed mutation: %v", err)
	}
	value, err := got.Get(key, "API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(value) != "s3cret" {
		t.Fatalf("Get = %q, want %q", value, "s3cret")
	}
	clear(value)
	if err := record(path, f, key); err != nil {
		t.Fatalf("record: %v", err)
	}

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// An older signed copy of the same vault loses to what is accepted here.
	if err := os.WriteFile(path, older, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := openVerified(path); !errors.Is(err, errStale) {
		t.Fatalf("openVerified of the rolled back vault = %v, want errStale", err)
	}

	// The current bytes are fine, however often they are read.
	if err := os.WriteFile(path, current, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for range 2 {
		if _, err := openVerified(path); err != nil {
			t.Fatalf("openVerified of the current bytes: %v", err)
		}
	}
}

// TestWarnRollbackOnOlderCopy is the attack signal: accepting a copy behind the
// write counter this machine has already counted past warns loudly, while the
// accepted state stays quiet. Recovering is still allowed, the warning is what
// makes a rollback visible instead of silent.
func TestWarnRollbackOnOlderCopy(t *testing.T) {
	path := isolatePins(t)
	f, key, laptop, _ := writeVault(t, path, false)

	if err := trustVault(path, f, key); err != nil {
		t.Fatalf("trustVault: %v", err)
	}
	older, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Move this machine forward one write.
	if err := f.Set(key, "API_KEY", []byte("s3cret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	f.Seq++
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := record(path, f, key); err != nil {
		t.Fatalf("record: %v", err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// The copy this machine already accepted stays quiet.
	if err := os.WriteFile(path, current, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fCur, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := captureStderr(t, func() { warnRollback(fCur) }); got != "" {
		t.Fatalf("warnRollback on the current copy printed %q, want silence", got)
	}

	// An older copy is a rollback, it warns before anyone can accept it.
	if err := os.WriteFile(path, older, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fOld, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := captureStderr(t, func() { warnRollback(fOld) })
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "roll you back") {
		t.Fatalf("warnRollback on an older copy printed %q, want a rollback warning", got)
	}
}

// TestSelfCertifiedVaultRefused is the rewrite attack: write access to the
// file lets an attacker add a device block and re-sign it, but the pins live
// outside the vault so the fresh signer is never accepted.
func TestSelfCertifiedVaultRefused(t *testing.T) {
	path := isolatePins(t)
	_, key, laptop, _ := writeVault(t, path, false)

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := trustVault(path, f, key); err != nil {
		t.Fatalf("trustVault: %v", err)
	}

	attacker := newSoftSigner(t)
	f.Device["p256:attacker"] = vault.Device{Pub: "p256:attacker", EPub: "attacker", Wrap: "attacker"}
	if err := f.Stamp(attacker); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := openVerified(path); !errors.Is(err, errRevoked) {
		t.Fatalf("openVerified of a self certified vault = %v, want errRevoked", err)
	}
	pins, err := loadPins(f.VaultID)
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	if want := []string{encodeSigner(t, laptop.Public())}; !slices.Equal(pins.Signers, want) {
		t.Fatalf("signers after a rejected vault = %v, want %v", pins.Signers, want)
	}
}

// TestRevokedDeviceStopsBeingAccepted covers that there is no revocation
// list: the registry decides which signing keys are accepted, so a device
// that leaves stops verifying at once and one that comes back is clean.
func TestRevokedDeviceStopsBeingAccepted(t *testing.T) {
	path := isolatePins(t)
	f, key, laptop, desktop := writeVault(t, path, true)

	if err := trustVault(path, f, key); err != nil {
		t.Fatalf("trustVault: %v", err)
	}
	laptopSigner := encodeSigner(t, laptop.Public())
	desktopSigner := encodeSigner(t, desktop.Public())

	meta, err := f.Devices(key)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	desktopPub := ""
	for pub, m := range meta {
		if m.Name == "desktop" {
			desktopPub = pub
		}
	}
	if desktopPub == "" {
		t.Fatal("the fixture has no desktop device")
	}

	// While enrolled, desktop's own signature is followed.
	f.Seq++
	if err := f.Stamp(desktop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := openVerified(path); err != nil {
		t.Fatalf("openVerified signed by desktop: %v", err)
	}

	// Revocation is a registry change signed by a device that stays.
	if err := f.RemoveDevice(key, desktopPub); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
	f.Seq++
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := openVerified(path); err != nil {
		t.Fatalf("openVerified after revocation: %v", err)
	}
	if err := record(path, f, key); err != nil {
		t.Fatalf("record: %v", err)
	}
	pins, err := loadPins(f.VaultID)
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	if !slices.Equal(pins.Signers, []string{laptopSigner}) {
		t.Fatalf("signers after revocation = %v, want only %s", pins.Signers, laptopSigner)
	}
	if slices.Contains(pins.Signers, desktopSigner) {
		t.Fatalf("the revoked device's signing key is still accepted: %v", pins.Signers)
	}

	// The revoked device's own signature stops being accepted.
	f.Seq++
	if err := f.Stamp(desktop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := openVerified(path); !errors.Is(err, errRevoked) {
		t.Fatalf("openVerified signed by the revoked device = %v, want errRevoked", err)
	}

	// Re-adding the device is clean, nothing is remembered against it.
	if err := f.AddDevice(key, "desktop", fixtureDay, newSoftKey(t).Public(), desktop.Public()); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	f.Seq++
	if err := f.Stamp(laptop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := openVerified(path); err != nil {
		t.Fatalf("openVerified after re-adding desktop: %v", err)
	}
	if err := record(path, f, key); err != nil {
		t.Fatalf("record: %v", err)
	}
	pins, err = loadPins(f.VaultID)
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	signers, err := f.Signers(key)
	if err != nil {
		t.Fatalf("Signers: %v", err)
	}
	if len(signers) != 2 || !slices.Equal(pins.Signers, signers) {
		t.Fatalf("signers after re-adding = %v, want exactly the registry %v", pins.Signers, signers)
	}

	// Desktop's signature is accepted again with no leftover state.
	f.Seq++
	if err := f.Stamp(desktop); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := openVerified(path); err != nil {
		t.Fatalf("openVerified signed by the re-added desktop: %v", err)
	}
}

// TestProveKeyRefusesForeignWraps covers a stitched file: the recovery wrap
// and this machine's device wrap have to agree on one vault key, so a wrap
// taken from anywhere else is a refusal rather than a pass.
func TestProveKeyRefusesForeignWraps(t *testing.T) {
	dk := newSoftKey(t)
	f, err := vault.New(dk, "open sesame", "laptop", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	mine := vault.Pub(dk.Public())

	if err := proveKey(f, "open sesame", dk); err != nil {
		t.Fatalf("proveKey on the honest file: %v", err)
	}
	if err := proveKey(f, "wrong passphrase", dk); err == nil {
		t.Fatal("proveKey accepted the wrong recovery passphrase")
	}
	// Not enrolled here, so the recovery wrap is the only proof available.
	if err := proveKey(f, "open sesame", nil); err != nil {
		t.Fatalf("proveKey without a device key: %v", err)
	}

	// Another machine's wrap, sealed to a key this device does not hold.
	other := newSoftKey(t)
	stranger, err := vault.New(other, "open sesame", "desktop", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("vault.New stranger: %v", err)
	}
	f.Device[mine] = stranger.Device[vault.Pub(other.Public())]
	if err := proveKey(f, "open sesame", dk); err == nil {
		t.Fatal("proveKey accepted another device's wrap")
	}

	// This device's wrap from a different vault: both wraps open, but to
	// different vault keys.
	clone, err := vault.New(dk, "open sesame", "laptop", newSoftSigner(t).Public())
	if err != nil {
		t.Fatalf("vault.New clone: %v", err)
	}
	f.Device[mine] = clone.Device[mine]
	if err := proveKey(f, "open sesame", dk); err == nil {
		t.Fatal("proveKey accepted a device wrap stitched in from another vault")
	}
}

// TestSignAndSaveKeepsVaultLoadable is the write path end to end: a mutation
// saved through signAndSave loads and verifies afterwards. The signing key
// lives in the TPM, so this runs only where one is available.
func TestSignAndSaveKeepsVaultLoadable(t *testing.T) {
	if err := devkey.Available(); err != nil {
		t.Skipf("no TPM on this machine: %v", err)
	}
	path := isolatePins(t)

	sk, err := devkey.OpenSigning()
	if err != nil {
		t.Fatalf("OpenSigning: %v", err)
	}
	t.Cleanup(func() { _ = sk.Close() })

	f, err := vault.New(newSoftKey(t), "open sesame", "laptop", sk.Public())
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	key, err := f.VaultKeyPass("open sesame")
	if err != nil {
		t.Fatalf("VaultKeyPass: %v", err)
	}
	t.Cleanup(func() { clear(key) })

	if err := f.Set(key, "API_KEY", []byte("s3cret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := signAndSave(f, key, path); err != nil {
		t.Fatalf("signAndSave: %v", err)
	}

	got, err := openVerified(path)
	if err != nil {
		t.Fatalf("openVerified after signAndSave: %v", err)
	}
	value, err := got.Get(key, "API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(value) != "s3cret" {
		t.Fatalf("Get = %q, want %q", value, "s3cret")
	}
	clear(value)
}

func TestPresent(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "context prefixes drop",
			err:  fmt.Errorf("unlock: %w", fmt.Errorf("vault: verify: %w", sig.ErrUnknownSigner)),
			want: "signer is not among the accepted public keys",
		},
		{
			name: "a hint appended to the wrapped message stays",
			err: fmt.Errorf("open: %w", fmt.Errorf(
				"%w, if this is really yours run fuu trust here",
				errUnaccepted,
			)),
			want: "this vault has not been accepted on this machine, if this is really yours run fuu trust here",
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

// TestMintPassphrase covers the default path: whatever fuu generates clears
// its own floor, stays inside the base32 alphabet and never repeats.
func TestMintPassphrase(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	seen := make(map[string]struct{}, 200)
	for range 200 {
		pass, err := mintPassphrase()
		if err != nil {
			t.Fatalf("mintPassphrase: %v", err)
		}
		if err := checkPassphrase(pass); err != nil {
			t.Fatalf("generated %q does not clear its own floor: %v", pass, err)
		}
		for _, r := range pass {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("generated %q holds %q, outside the base32 alphabet", pass, r)
			}
		}
		if _, dup := seen[pass]; dup {
			t.Fatalf("generated %q twice in 200 draws", pass)
		}
		seen[pass] = struct{}{}
	}
}

func TestCheckPassphrase(t *testing.T) {
	cases := []struct {
		name       string
		passphrase string
		wantOK     bool
	}{
		{"short", "short", false},
		{"whitespace only", "                    ", false},
		{"old floor", "12 chars long", false},
		{"long enough", "correct horse battery staple", true},
		{"one character run", "aaaaaaaaaaaaaaaaaaaa", false},
		{"two character run", "abababababababababab", false},
		{"padded to look long", "          short", false},
		{"exactly at the floor", "abcdefghij klmnopqrs", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPassphrase(tc.passphrase)
			if tc.wantOK && err != nil {
				t.Fatalf("checkPassphrase(%q) = %v, want it accepted", tc.passphrase, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("checkPassphrase(%q) accepted it", tc.passphrase)
			}
		})
	}
}
