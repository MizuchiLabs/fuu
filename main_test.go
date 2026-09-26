package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/vault"
)

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

// Points the pin store and the account at a temp dir, a fresh machine as far
// as fuu can tell, so tests never touch the real trust anchors.
func isolatePins(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// A random account seed, argon2id is too slow to run per test.
func newTestAccount(t *testing.T) []byte {
	t.Helper()
	account := make([]byte, 32)
	if _, err := rand.Read(account); err != nil {
		t.Fatalf("generate account: %v", err)
	}
	return account
}

// A machine logged in to a fresh account, holding one vault saved at path.
func writeVault(t *testing.T, path string) ([]byte, *softKey, string) {
	t.Helper()
	dk := newSoftKey(t)
	account := newTestAccount(t)
	if err := saveAccount(dk, vault.DefaultAccount, account); err != nil {
		t.Fatalf("saveAccount: %v", err)
	}
	f, key, id, err := vault.New(account)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return key, dk, id
}

func pinFolder(t *testing.T, path, id string) string {
	return pinFolderAs(t, path, pin{Account: vault.DefaultAccount, ID: id})
}

func pinFolderAs(t *testing.T, path string, p pin) string {
	t.Helper()
	dir, err := vaultDir(path)
	if err != nil {
		t.Fatalf("vaultDir: %v", err)
	}
	pins, err := loadPins()
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	pins[dir] = p
	if err := savePins(pins); err != nil {
		t.Fatalf("savePins: %v", err)
	}
	return dir
}

func mustPins(t *testing.T) map[string]pin {
	t.Helper()
	pins, err := loadPins()
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	return pins
}

func feedStdin(t *testing.T, script string) {
	t.Helper()
	stdin = bufio.NewReader(strings.NewReader(script))
}

// The refusal a clone meets first: no pin for this folder, no trust on first use.
func TestLoadTrustedUnpinned(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	writeVault(t, path)

	if _, _, err := loadTrusted(path); !errors.Is(err, errUntrusted) {
		t.Fatalf("loadTrusted of an unpinned folder = %v, want errUntrusted", err)
	}
}

// A vault swapped in from another folder is a loud refusal, a rotation of the same vault is not.
func TestOpenPinned(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	key, dk, id := writeVault(t, path)
	pinFolder(t, path, id)

	f, got, account, err := openPinnedAccount(path, dk)
	if err != nil {
		t.Fatalf("openPinnedAccount: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("openPinnedAccount did not return the vault key")
	}

	if _, err := f.Rotate(got, account); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, _, err := openPinned(path, dk); err != nil {
		t.Fatalf("openPinned after a rotation: %v", err)
	}

	// Another vault of the same account copied over this folder's file.
	other, _, _, err := vault.New(account)
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
	if _, _, err := openPinned(path, dk); !errors.Is(err, errKeyChanged) {
		t.Fatalf("openPinned after a vault swap = %v, want errKeyChanged", err)
	}
}

// First use: init offers the account, prints its passphrase once, and the next vault asks nothing.
func TestInitStartsAccount(t *testing.T) {
	isolatePins(t)
	dk := newSoftKey(t)
	pathA := filepath.Join(t.TempDir(), ".fuu.toml")

	feedStdin(t, "y\n")
	out := captureOutput(t, func() {
		if err := initVault(pathA, dk, vault.DefaultAccount); err != nil {
			t.Fatalf("initVault: %v", err)
		}
	})
	pass := passphraseFrom(t, out)
	if !vault.CheckPassphrase(pass) {
		t.Fatalf("init printed %q, not an account passphrase", pass)
	}

	// Anything read from stdin now would be EOF and a no, so this proves no prompt.
	feedStdin(t, "")
	pathB := filepath.Join(t.TempDir(), ".fuu.toml")
	captureOutput(t, func() {
		if err := initVault(pathB, dk, vault.DefaultAccount); err != nil {
			t.Fatalf("initVault of a second vault: %v", err)
		}
	})
	for _, path := range []string{pathA, pathB} {
		if _, _, err := openPinned(path, dk); err != nil {
			t.Fatalf("openPinned %s: %v", path, err)
		}
	}

	// A new machine with the same passphrase opens both.
	isolatePins(t)
	laptop := newSoftKey(t)
	if err := login(laptop, vault.DefaultAccount, strings.ToLower(pass)); err != nil {
		t.Fatalf("login: %v", err)
	}
	for _, path := range []string{pathA, pathB} {
		feedStdin(t, "y\n")
		if err := trust(path, laptop); err != nil {
			t.Fatalf("trust %s: %v", path, err)
		}
		if _, _, err := openPinned(path, laptop); err != nil {
			t.Fatalf("openPinned %s on the new machine: %v", path, err)
		}
	}
}

// Declining the account leaves no vault and no account behind.
func TestInitDeclined(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	feedStdin(t, "n\n")
	if err := initVault(path, newSoftKey(t), vault.DefaultAccount); !errors.Is(err, errNoAccount) {
		t.Fatalf("initVault after a no = %v, want errNoAccount", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a declined init wrote %s", path)
	}
}

func TestLoginRefusesTypo(t *testing.T) {
	isolatePins(t)
	if err := login(newSoftKey(t), vault.DefaultAccount, "ABCDEFGHIJKLMNOPQRSTUVWXYZ23"); err == nil {
		t.Fatal("login accepted a passphrase that fails its check")
	}
	if _, err := unsealAccount(newSoftKey(t), vault.DefaultAccount); !errors.Is(err, errNoAccount) {
		t.Fatalf("a refused login saved an account: %v", err)
	}
}

// After a passphrase rotation on one machine, the other logs in once and
// brings along the vault only it had checked out.
func TestRotatePassphraseThenLogin(t *testing.T) {
	isolatePins(t)
	home := newSoftKey(t)
	shared := filepath.Join(t.TempDir(), ".fuu.toml")
	feedStdin(t, "y\n")
	out := captureOutput(t, func() {
		if err := initVault(shared, home, vault.DefaultAccount); err != nil {
			t.Fatalf("initVault: %v", err)
		}
	})
	oldPass := passphraseFrom(t, out)
	homeConfig := os.Getenv("XDG_CONFIG_HOME")

	// The laptop joins, trusts the shared vault and makes one of its own.
	isolatePins(t)
	laptopConfig := os.Getenv("XDG_CONFIG_HOME")
	laptop := newSoftKey(t)
	if err := login(laptop, vault.DefaultAccount, oldPass); err != nil {
		t.Fatalf("login: %v", err)
	}
	laptopCopy := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := os.WriteFile(laptopCopy, mustRead(t, shared), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	feedStdin(t, "y\n")
	if err := trust(laptopCopy, laptop); err != nil {
		t.Fatalf("trust: %v", err)
	}
	only := filepath.Join(t.TempDir(), ".fuu.toml")
	captureOutput(t, func() {
		if err := initVault(only, laptop, vault.DefaultAccount); err != nil {
			t.Fatalf("initVault on the laptop: %v", err)
		}
	})

	// Home rotates the passphrase.
	t.Setenv("XDG_CONFIG_HOME", homeConfig)
	out = captureOutput(t, func() {
		if err := rotateAccount(home, vault.DefaultAccount); err != nil {
			t.Fatalf("rotateAccount: %v", err)
		}
	})
	newPass := passphraseFrom(t, out)
	if _, _, err := openPinned(shared, home); err != nil {
		t.Fatalf("openPinned at home after rotating: %v", err)
	}

	// The laptop pulls the shared vault, then logs in with the new passphrase.
	t.Setenv("XDG_CONFIG_HOME", laptopConfig)
	if err := os.WriteFile(laptopCopy, mustRead(t, shared), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := openPinned(laptopCopy, laptop); !errors.Is(err, vault.ErrWrongAccount) {
		t.Fatalf("openPinned before login = %v, want ErrWrongAccount", err)
	}
	captureOutput(t, func() {
		if err := login(laptop, vault.DefaultAccount, newPass); err != nil {
			t.Fatalf("login with the new passphrase: %v", err)
		}
	})
	for _, path := range []string{laptopCopy, only} {
		if _, _, err := openPinned(path, laptop); err != nil {
			t.Fatalf("openPinned %s after login: %v", path, err)
		}
	}

	// The old passphrase opens nothing any more.
	isolatePins(t)
	stranger := newSoftKey(t)
	if err := login(stranger, vault.DefaultAccount, oldPass); err != nil {
		t.Fatalf("login with the old passphrase: %v", err)
	}
	if err := trust(only, stranger); !errors.Is(err, vault.ErrWrongAccount) {
		t.Fatalf("trust with the old passphrase = %v, want ErrWrongAccount", err)
	}
}

// A team account shares its vaults and nothing else: its passphrase opens its
// vaults, never the ones of your own account, and its rotation leaves yours alone.
func TestTeamAccount(t *testing.T) {
	isolatePins(t)
	me := newSoftKey(t)
	mine := filepath.Join(t.TempDir(), ".fuu.toml")
	shared := filepath.Join(t.TempDir(), ".fuu.toml")
	captureOutput(t, func() {
		feedStdin(t, "y\n")
		if err := initVault(mine, me, vault.DefaultAccount); err != nil {
			t.Fatalf("initVault: %v", err)
		}
	})
	feedStdin(t, "y\n")
	out := captureOutput(t, func() {
		if err := initVault(shared, me, "acme"); err != nil {
			t.Fatalf("initVault --account acme: %v", err)
		}
	})
	teamPass := passphraseFrom(t, out)
	if pins := mustPins(t); pins[filepath.Dir(shared)].Account != "acme" {
		t.Fatalf("pins = %v, want the shared folder under acme", pins)
	}
	for _, path := range []string{mine, shared} {
		if _, _, err := openPinned(path, me); err != nil {
			t.Fatalf("openPinned %s: %v", path, err)
		}
	}

	// A teammate gets the team passphrase and nothing else.
	myConfig := os.Getenv("XDG_CONFIG_HOME")
	isolatePins(t)
	mate := newSoftKey(t)
	captureOutput(t, func() {
		if err := login(mate, "acme", teamPass); err != nil {
			t.Fatalf("login --account acme: %v", err)
		}
	})
	feedStdin(t, "y\n")
	if err := trust(shared, mate); err != nil {
		t.Fatalf("trust of the team vault: %v", err)
	}
	if _, _, err := openPinned(shared, mate); err != nil {
		t.Fatalf("openPinned of the team vault: %v", err)
	}
	if err := trust(mine, mate); !errors.Is(err, vault.ErrWrongAccount) {
		t.Fatalf("trust of my own vault by a teammate = %v, want ErrWrongAccount", err)
	}

	// Rotating the team passphrase moves the team vault and leaves mine untouched.
	t.Setenv("XDG_CONFIG_HOME", myConfig)
	before := mustRead(t, mine)
	captureOutput(t, func() {
		if err := rotateAccount(me, "acme"); err != nil {
			t.Fatalf("rotateAccount acme: %v", err)
		}
	})
	if !bytes.Equal(mustRead(t, mine), before) {
		t.Fatal("rotating the team account rewrote a vault of the default account")
	}
	for _, path := range []string{mine, shared} {
		if _, _, err := openPinned(path, me); err != nil {
			t.Fatalf("openPinned %s after the team rotation: %v", path, err)
		}
	}
}

// Rotating one vault keeps the passphrase and the pin.
func TestRotateVault(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	key, dk, id := writeVault(t, path)
	pinFolder(t, path, id)

	captureOutput(t, func() {
		if err := rotateVault(path, dk); err != nil {
			t.Fatalf("rotateVault: %v", err)
		}
	})
	_, fresh, err := openPinned(path, dk)
	if err != nil {
		t.Fatalf("openPinned after rotate: %v", err)
	}
	if bytes.Equal(fresh, key) {
		t.Fatal("rotateVault kept the vault key")
	}
}

// The recovery passphrase shown by showPassphrase, the one line indented by four spaces.
func passphraseFrom(t *testing.T, out string) string {
	t.Helper()
	for line := range strings.SplitSeq(out, "\n") {
		if pass, ok := strings.CutPrefix(line, "    "); ok {
			return pass
		}
	}
	t.Fatalf("no passphrase in %q", out)
	return ""
}

// A vault of this machine's account, one confirmation and nothing else.
func TestTrustConfirms(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	_, dk, id := writeVault(t, path)

	feedStdin(t, "n\n")
	if err := trust(path, dk); err == nil {
		t.Fatal("trust went ahead after a no")
	}
	if pins := mustPins(t); len(pins) != 0 {
		t.Fatalf("a declined trust recorded pins: %v", pins)
	}

	feedStdin(t, "y\n")
	if err := trust(path, dk); err != nil {
		t.Fatalf("trust: %v", err)
	}
	dir, err := vaultDir(path)
	if err != nil {
		t.Fatalf("vaultDir: %v", err)
	}
	if pins := mustPins(t); pins[dir].ID != id {
		t.Fatalf("pins = %v, want this folder pinned to %s", pins, id)
	}
}

// A stranger's vault never loads, whatever the answer would be.
func TestTrustRefusesStranger(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	writeVault(t, path)
	before := mustRead(t, path)

	me := newSoftKey(t)
	if err := saveAccount(me, vault.DefaultAccount, newTestAccount(t)); err != nil {
		t.Fatalf("saveAccount: %v", err)
	}
	feedStdin(t, "y\n")
	if err := trust(path, me); !errors.Is(err, vault.ErrWrongAccount) {
		t.Fatalf("trust of a stranger's vault = %v, want ErrWrongAccount", err)
	}
	if !bytes.Equal(mustRead(t, path), before) {
		t.Fatal("a refused trust rewrote the vault file")
	}
	if pins := mustPins(t); len(pins) != 0 {
		t.Fatalf("a refused trust recorded pins: %v", pins)
	}
}

// Entries shuffled by hand: trust refuses before recording anything.
func TestTrustTampered(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), ".fuu.toml")
	key, dk, _ := writeVault(t, path)

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, name := range []string{"A", "B"} {
		if err := f.Set(key, name, name); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}
	toks := slices.Sorted(maps.Keys(f.Secret))
	f.Secret[toks[0]], f.Secret[toks[1]] = f.Secret[toks[1]], f.Secret[toks[0]]
	if err := f.Save(path); err != nil {
		t.Fatalf("Save of the doctored file: %v", err)
	}

	feedStdin(t, "y\n")
	if err := trust(path, dk); err == nil {
		t.Fatal("trust accepted swapped entry bodies")
	}
	if pins := mustPins(t); len(pins) != 0 {
		t.Fatalf("a refused trust recorded pins: %v", pins)
	}
}

// The second checkout of a vault this machine already trusts says so in its question.
func TestTrustSameVaultSecondFolder(t *testing.T) {
	isolatePins(t)
	pathA := filepath.Join(t.TempDir(), ".fuu.toml")
	_, dk, id := writeVault(t, pathA)
	dirA := pinFolder(t, pathA, id)

	pathB := filepath.Join(t.TempDir(), ".fuu.toml")
	if err := os.WriteFile(pathB, mustRead(t, pathA), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	dirB, err := vaultDir(pathB)
	if err != nil {
		t.Fatalf("vaultDir: %v", err)
	}

	feedStdin(t, "y\n")
	question := captureStderr(t, func() {
		if err := trust(pathB, dk); err != nil {
			t.Fatalf("trust of the second folder: %v", err)
		}
	})
	if !strings.Contains(question, dirA) {
		t.Fatalf("trust asked %q, want it to name %s", question, dirA)
	}
	if pins := mustPins(t); pins[dirB].ID != id {
		t.Fatalf("pins = %v, want %s pinned to %s", pins, dirB, id)
	}
}

// An untrusted folder is reported once, then the shell hears nothing until the situation changes.
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

// Moved names are said out loud, a held state says nothing, and the exact wording is not the contract.
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
				"%w, run fuu login",
				vault.ErrWrongAccount,
			)),
			want: "this vault is not sealed to the account on this machine, run fuu login",
		},
		{
			name: "suffix after the sentinel stays",
			err:  fmt.Errorf("%w %q", vault.ErrNoKey, "API_KEY"),
			want: `no such key "API_KEY"`,
		},
		{
			name: "two causes and a hint stay in one block",
			err: fmt.Errorf("open tpm: %w", fmt.Errorf(
				"%w\n%w\n\nfix it like this",
				errors.New("this user cannot open the TPM device"),
				errors.Join(
					errors.New("open /dev/tpmrm0: permission denied"),
					errors.New("open /dev/tpm0: permission denied"),
				),
			)),
			want: "this user cannot open the TPM device\nopen /dev/tpmrm0: permission denied\n" +
				"open /dev/tpm0: permission denied\n\nfix it like this",
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

// Untrusted text cannot rewrite the terminal.
func TestSanitize(t *testing.T) {
	if got := sanitize("a\x1b]0;x\x07b"); got != "a]0;xb" {
		t.Fatalf("sanitize kept control bytes: %q", got)
	}
	if got := sanitize("plain name-1.0"); got != "plain name-1.0" {
		t.Fatalf("sanitize mangled plain text: %q", got)
	}
	if got := sanitize("line one\nline two"); got != "line one\nline two" {
		t.Fatalf("sanitize dropped newlines: %q", got)
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
