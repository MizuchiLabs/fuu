package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/vault"
)

// testPass is the recovery passphrase the fixtures seal their vault keys to.
const testPass = "open sesame"

type softKey struct{ key *ecdh.PrivateKey }

var _ vault.DeviceKey = (*softKey)(nil)

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

// isolatePins points the pin store at a temp dir so tests never touch the real
// trust anchors.
func isolatePins(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// writeVault builds a vault with laptop enrolled and saves it at path,
// handing back the vault key and the device key.
func writeVault(t *testing.T, path string) ([]byte, *softKey) {
	t.Helper()
	dk := newSoftKey(t)
	f, key, err := vault.New(dk, "laptop", testPass)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return key, dk
}

// feedStdin answers every prompt and confirm from a fixed script.
func feedStdin(t *testing.T, script string) {
	t.Helper()
	stdin = bufio.NewReader(strings.NewReader(script))
}

// TestLoadTrustedUnpinned covers the refusal a clone meets before anything
// else: no pin for this folder, no TPM access, no trust on first use.
func TestLoadTrustedUnpinned(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	writeVault(t, path)

	if _, _, err := loadTrusted(path); !errors.Is(err, errUntrusted) {
		t.Fatalf("loadTrusted of an unpinned folder = %v, want errUntrusted", err)
	}
}

// TestUnsealPinned covers both halves of the pin check: the key it was pinned
// to opens, and a vault holding another key under the same device is a loud
// refusal rather than a quiet reload.
func TestUnsealPinned(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	key, dk := writeVault(t, path)
	pin := vault.Fingerprint(key)

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := unsealPinned(f, dk, pin)
	if err != nil {
		t.Fatalf("unsealPinned: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("unsealPinned did not return the vault key")
	}

	// The file replaced by a vault that wraps a different key to the same
	// soft device key.
	other, _, err := vault.New(dk, "laptop", testPass)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	otherPath := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := other.Save(otherPath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(path, mustRead(t, otherPath), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err = vault.Load(path)
	if err != nil {
		t.Fatalf("Load of the replacement: %v", err)
	}
	if _, err := unsealPinned(f, dk, pin); !errors.Is(err, errKeyChanged) {
		t.Fatalf("unsealPinned after a key swap = %v, want errKeyChanged", err)
	}
}

// TestTrustEnrollsDevice is the join path: the recovery passphrase is the
// proof, then this machine gets a wrap of its own and the folder is pinned.
func TestTrustEnrollsDevice(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	writeVault(t, path)

	stranger := newSoftKey(t)
	feedStdin(t, testPass+"\n")
	if err := trust(path, stranger, "desktop"); err != nil {
		t.Fatalf("trust: %v", err)
	}

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	key, err := f.Unseal(stranger)
	if err != nil {
		t.Fatalf("Unseal of the enrolled device: %v", err)
	}
	devices, err := f.Devices(key)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if devices[vault.Pub(stranger.Public())] != "desktop" {
		t.Fatalf("devices = %v, want desktop enrolled", devices)
	}

	dir, err := vaultDir(path)
	if err != nil {
		t.Fatalf("vaultDir: %v", err)
	}
	pins, err := loadPins()
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	if pins[dir] != vault.Fingerprint(key) {
		t.Fatalf("pins = %v, want this folder pinned to %s", pins, vault.Fingerprint(key))
	}
}

// TestTrustWrongPassphrase leaves everything untouched: no enrollment, no
// pin, not one byte of the file.
func TestTrustWrongPassphrase(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	writeVault(t, path)
	before := mustRead(t, path)

	stranger := newSoftKey(t)
	feedStdin(t, "wrong\n")
	if err := trust(path, stranger, "desktop"); err == nil {
		t.Fatal("trust accepted the wrong recovery passphrase")
	}
	if !bytes.Equal(mustRead(t, path), before) {
		t.Fatal("a refused trust rewrote the vault file")
	}
	pins, err := loadPins()
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	if len(pins) != 0 {
		t.Fatalf("a refused trust recorded pins: %v", pins)
	}
}

// TestTrustTamperedDeviceWrap covers a file where this machine's wrap was
// swapped for one holding another key: the device half opens, the recovery
// half says otherwise, and trust refuses before recording anything.
func TestTrustTamperedDeviceWrap(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	dk := newSoftKey(t)

	f, _, err := vault.New(dk, "laptop", testPass)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	other, _, err := vault.New(dk, "laptop", testPass)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	mine := vault.Pub(dk.Public())
	f.Device[mine] = other.Device[mine]
	if err := f.Save(path); err != nil {
		t.Fatalf("Save of the doctored file: %v", err)
	}

	feedStdin(t, testPass+"\n")
	err = trust(path, dk, "laptop")
	if err == nil || !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("trust of the doctored file = %v, want the tampered error", err)
	}
	pins, err := loadPins()
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	if len(pins) != 0 {
		t.Fatalf("a refused trust recorded pins: %v", pins)
	}
}

// TestTrustSameVaultSecondFolder covers the second checkout of a vault this
// machine already trusts: one word is enough, no passphrase round trip.
func TestTrustSameVaultSecondFolder(t *testing.T) {
	isolatePins(t)
	pathA := filepath.Join(t.TempDir(), ".fuu.toml")
	key, dk := writeVault(t, pathA)

	dirA, err := vaultDir(pathA)
	if err != nil {
		t.Fatalf("vaultDir: %v", err)
	}
	if err := savePins(map[string]string{dirA: vault.Fingerprint(key)}); err != nil {
		t.Fatalf("savePins: %v", err)
	}

	pathB := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := os.WriteFile(pathB, mustRead(t, pathA), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	dirB, err := vaultDir(pathB)
	if err != nil {
		t.Fatalf("vaultDir: %v", err)
	}

	// Anything but a yes answer to the confirm would abort, so this script
	// passing proves no passphrase was asked for.
	feedStdin(t, "y\n")
	if err := trust(pathB, dk, "laptop"); err != nil {
		t.Fatalf("trust of the second folder: %v", err)
	}
	pins, err := loadPins()
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	if pins[dirB] != vault.Fingerprint(key) {
		t.Fatalf("pins = %v, want %s pinned to %s", pins, dirB, vault.Fingerprint(key))
	}
}

// TestEnvReportsRefusalOnce pins what an operator sees from the every-prompt
// hook: a folder this machine has not trusted is reported once, then the shell
// hears nothing until the situation actually changes.
func TestEnvReportsRefusalOnce(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	writeVault(t, path)
	t.Chdir(filepath.Dir(path))
	t.Setenv("FUU_STATE", "")
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

	want := "fuu: this folder is not trusted on this machine, run fuu trust\n"
	out, errOut := runEnv()
	if errOut != want {
		t.Fatalf("first refusal printed %q, want %q", errOut, want)
	}
	_, rest, ok := strings.Cut(out, "export FUU_STATE='")
	if !ok {
		t.Fatalf("refusal output %q carries no FUU_STATE", out)
	}
	state, rest, ok := strings.Cut(rest, "'")
	if !ok || rest != "\n" {
		t.Fatalf("refusal output %q carries no closing quote", out)
	}
	t.Setenv("FUU_STATE", state)

	// The hook runs again at every later prompt, and those stay quiet.
	for prompt := 2; prompt <= 3; prompt++ {
		out, errOut = runEnv()
		if out != "" || errOut != "" {
			t.Fatalf("prompt %d after the refusal printed stdout %q stderr %q, want silence",
				prompt, out, errOut)
		}
	}
}

// TestAnnounce checks what reaches the terminal when names move: the moved
// names are said out loud, and a state the shell already holds says nothing.
// The exact wording is not the contract, so nothing here pins it.
func TestAnnounce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		loaded   []string
		names    []string
		silent   bool
		contains []string
	}{
		{name: "first load", names: []string{"API_KEY", "TOKEN"}, contains: []string{"+API_KEY", "+TOKEN", "/p/.fuu.toml"}},
		{name: "unload", loaded: []string{"API_KEY", "TOKEN"}, contains: []string{"-API_KEY", "-TOKEN"}},
		{name: "switching vaults", loaded: []string{"OLD_KEY"}, names: []string{"NEW_KEY"}, contains: []string{"+NEW_KEY", "-OLD_KEY", "/p/.fuu.toml"}},
		{name: "vault without keys", loaded: []string{"OLD_KEY"}, names: []string{}, contains: []string{"-OLD_KEY", "/p/.fuu.toml"}},
		{name: "value refresh", loaded: []string{"API_KEY"}, names: []string{"API_KEY"}, silent: true},
		{name: "nothing to say", silent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := captureStderr(t, func() {
				announce("/p/.fuu.toml", tc.loaded, tc.names)
			})
			if tc.silent {
				if got != "" {
					t.Fatalf("announce printed %q, want silence", got)
				}
				return
			}
			for _, want := range tc.contains {
				if !strings.Contains(got, want) {
					t.Fatalf("announce printed %q, want it to carry %q", got, want)
				}
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
			name: "context prefixes drop",
			err:  fmt.Errorf("unlock: %w", fmt.Errorf("vault: open body: %w", vault.ErrConflict)),
			want: "the vault changed on disk while fuu was working, run the command again",
		},
		{
			name: "a hint appended to the wrapped message stays",
			err: fmt.Errorf("open: %w", fmt.Errorf(
				"%w, run fuu trust",
				vault.ErrNotEnrolled,
			)),
			want: "this machine is not enrolled in this vault, run fuu trust",
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

func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w                      //nolint:reassign // capturing what the hook prints
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

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
