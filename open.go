package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/vault"
)

var (
	errNoVault    = errors.New("no vault here, run fuu init or point --vault at one")
	errUntrusted  = errors.New("this folder is not trusted on this machine, run fuu trust")
	errKeyChanged = errors.New(
		"the vault key changed since this folder was trusted, run fuu trust and enter the recovery passphrase",
	)
)

// --vault wins, otherwise the nearest .fuu.toml up to and including the git root, never above it.
func vaultPath(cmd *cli.Command) (string, error) {
	if cmd.IsSet("vault") {
		return cmd.String("vault"), nil
	}
	return findVault()
}

func findVault() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	for {
		candidate := filepath.Join(dir, ".fuu.toml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("vault: %w", err)
		}

		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return "", errNoVault
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errNoVault
		}
		dir = parent
	}
}

// The repository root, so one checkout is one vault. Outside a repo it stays in the working directory.
func repoVaultPath() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("init: %w", err)
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return filepath.Join(dir, ".fuu.toml"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Join(cwd, ".fuu.toml"), nil
		}
		dir = parent
	}
}

// Touches no key material and no TPM, so a folder nobody vouched for never reaches the chip.
func loadTrusted(path string) (*vault.File, string, error) {
	f, err := vault.Load(path)
	if err != nil {
		return nil, "", err
	}
	dir, err := vaultDir(path)
	if err != nil {
		return nil, "", err
	}
	pins, err := loadPins()
	if err != nil {
		return nil, "", err
	}
	pin := pins[dir]
	if pin == "" {
		return nil, "", errUntrusted
	}
	return f, pin, nil
}

// The pin turns a vault key swap into a loud refusal instead of a quiet reload.
func unsealPinned(f *vault.File, dk vault.DeviceKey, pin string) ([]byte, error) {
	key, err := f.Unseal(dk)
	if err != nil {
		if errors.Is(err, vault.ErrNotEnrolled) {
			return nil, fmt.Errorf("%w, run fuu trust", err)
		}
		return nil, err
	}
	if vault.Fingerprint(key) != pin {
		return nil, errKeyChanged
	}
	return key, nil
}

func openPinned(path string, dk vault.DeviceKey) (*vault.File, []byte, error) {
	f, pin, err := loadTrusted(path)
	if err != nil {
		return nil, nil, err
	}
	key, err := unsealPinned(f, dk, pin)
	if err != nil {
		return nil, nil, err
	}
	return f, key, nil
}

// The device key is closed on the way out, unsealing is all it is needed for.
func unlock(cmd *cli.Command) (string, *vault.File, []byte, string, error) {
	path, err := vaultPath(cmd)
	if err != nil {
		return "", nil, nil, "", err
	}
	f, pin, err := loadTrusted(path)
	if err != nil {
		return path, nil, nil, "", err
	}
	dk, err := devkey.Open()
	if err != nil {
		return path, nil, nil, "", err
	}
	defer func() { _ = dk.Close() }()

	key, err := unsealPinned(f, dk, pin)
	if err != nil {
		return path, nil, nil, "", err
	}
	return path, f, key, vault.Pub(dk.Public()), nil
}
