package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
	"github.com/mizuchilabs/kata/fsutil"
	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/vault"
)

// The only command that pins a folder, everywhere else there is no trust on first use.
func cmdTrust(_ context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}

	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	return trust(path, dk)
}

// Only a vault sealed to one of this machine's accounts can be trusted, so a
// stranger's repository never loads. What is left to confirm is that this
// folder, which may hold a copy of any of your vaults, should load it.
func trust(path string, dk vault.DeviceKey) error {
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	pins, err := loadPins()
	if err != nil {
		return err
	}
	dir, err := vaultDir(path)
	if err != nil {
		return err
	}
	name, key, id, err := openAny(f, dk)
	if err != nil {
		return err
	}
	p := pin{Account: name, ID: id}
	if pins[dir] == p {
		fmt.Println("already trusted")
		return nil
	}

	// The whole file authenticates before anything is recorded.
	if _, err := f.Secrets(key); err != nil {
		return err
	}
	if _, err := f.DisabledSecrets(key); err != nil {
		return err
	}

	question := "load this vault into your shell in " + sanitize(dir)
	if other, ok := pinnedElsewhere(pins, dir, p); ok {
		question = fmt.Sprintf("this is the same vault as %s, load it in %s too", sanitize(other), sanitize(dir))
	}
	if pins[dir].ID != "" {
		question = fmt.Sprintf("%s holds another vault than it was trusted for, load the new one", sanitize(dir))
	}
	if name != vault.DefaultAccount {
		question += ", from account " + name
	}
	ok, err := confirm(question)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("aborted, nothing recorded")
	}
	pins[dir] = p
	if err := savePins(pins); err != nil {
		return err
	}
	fmt.Printf("trusted %s\n", sanitize(dir))
	return nil
}

// openAny tries every account on this machine, the default one first, and
// names the one the vault belongs to.
func openAny(f *vault.File, dk vault.DeviceKey) (string, []byte, string, error) {
	accounts, err := readAccounts()
	if err != nil {
		return "", nil, "", err
	}
	if accounts == nil {
		return "", nil, "", noAccount(vault.DefaultAccount)
	}
	for _, name := range accounts.Names() {
		seed, _, err := accounts.Unseal(dk, name)
		if err != nil {
			return "", nil, "", err
		}
		if key, id, err := f.Open(seed); err == nil {
			return name, key, id, nil
		}
	}
	return "", nil, "", fmt.Errorf(
		"%w, if it was shared with you run fuu login --account <name> with its passphrase",
		vault.ErrWrongAccount,
	)
}

// Lives outside the vault on purpose: a trust anchor read from the file it
// verifies proves nothing.
func trustedPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	return filepath.Join(dir, "fuu", "trusted.toml"), nil
}

// pin is what a folder is trusted to hold: the account that opens it and the vault's id.
type pin struct {
	Account string `toml:"account"`
	ID      string `toml:"id"`
}

func loadPins() (map[string]pin, error) {
	path, err := trustedPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]pin{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", path, err)
	}
	pins := map[string]pin{}
	if err := toml.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return pins, nil
}

// Sorted so an unchanged write stays byte identical and WriteIfChanged leaves it alone.
func savePins(pins map[string]pin) error {
	path, err := trustedPath()
	if err != nil {
		return err
	}
	// The encoder sorts map keys, so an unchanged write stays byte identical.
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(pins); err != nil {
		return fmt.Errorf("trust: encode: %w", err)
	}
	if err := fsutil.WriteIfChanged(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	return nil
}

func pinnedElsewhere(pins map[string]pin, dir string, p pin) (string, bool) {
	for _, other := range slices.Sorted(maps.Keys(pins)) {
		if other != dir && pins[other] == p {
			return other, true
		}
	}
	return "", false
}

func vaultDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	// Symlinked checkouts are one place, so resolve the folder, but only the
	// directory, the vault may still be being created.
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return resolved, nil
	}
	return filepath.Dir(abs), nil
}
