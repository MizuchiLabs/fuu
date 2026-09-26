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

// Only a vault sealed to this machine's account can be trusted, so a
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
	account, err := unsealAccount(dk)
	if err != nil {
		return err
	}
	key, id, err := f.Open(account)
	if errors.Is(err, vault.ErrWrongAccount) {
		return fmt.Errorf("%w, if the passphrase was rotated elsewhere run fuu login with the new one", err)
	}
	if err != nil {
		return err
	}
	if pins[dir] == id {
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
	if other, ok := pinnedElsewhere(pins, dir, id); ok {
		question = fmt.Sprintf("this is the same vault as %s, load it in %s too", sanitize(other), sanitize(dir))
	}
	if pins[dir] != "" {
		question = fmt.Sprintf("%s holds another vault than it was trusted for, load the new one", sanitize(dir))
	}
	ok, err := confirm(question)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("aborted, nothing recorded")
	}
	pins[dir] = id
	if err := savePins(pins); err != nil {
		return err
	}
	fmt.Printf("trusted %s\n", sanitize(dir))
	return nil
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

func loadPins() (map[string]string, error) {
	path, err := trustedPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", path, err)
	}
	pins := map[string]string{}
	if err := toml.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return pins, nil
}

// Sorted so an unchanged write stays byte identical and WriteIfChanged leaves it alone.
func savePins(pins map[string]string) error {
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

func pinnedElsewhere(pins map[string]string, dir, fp string) (string, bool) {
	for _, other := range slices.Sorted(maps.Keys(pins)) {
		if other != dir && pins[other] == fp {
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
