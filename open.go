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

// vaultFile is the name fuu looks for and creates.
const vaultFile = ".fuu.toml"

var (
	errNoVault    = errors.New("no vault here, run fuu init or point --vault at one")
	errUntrusted  = errors.New("this folder is not trusted on this machine, run fuu trust")
	errKeyChanged = errors.New(
		"this folder holds another vault than the one it was trusted for, run fuu trust",
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
		candidate := filepath.Join(dir, vaultFile)
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
			return filepath.Join(dir, vaultFile), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Join(cwd, vaultFile), nil
		}
		dir = parent
	}
}

// Touches no key material and no TPM, so a folder nobody vouched for never reaches the chip.
func loadTrusted(path string) (*vault.File, pin, error) {
	f, err := vault.Load(path)
	if err != nil {
		return nil, pin{}, err
	}
	dir, err := vaultDir(path)
	if err != nil {
		return nil, pin{}, err
	}
	pins, err := loadPins()
	if err != nil {
		return nil, pin{}, err
	}
	p := pins[dir]
	if p.ID == "" {
		return nil, pin{}, errUntrusted
	}
	return f, p, nil
}

// The pin is the vault id, so a rotation anywhere keeps loading and a vault
// swapped in from another folder is a loud refusal.
func unsealPinned(f *vault.File, dk vault.DeviceKey, p pin) ([]byte, []byte, error) {
	account, err := unsealAccount(dk, p.Account)
	if err != nil {
		return nil, nil, err
	}
	key, id, err := f.Open(account)
	if errors.Is(err, vault.ErrWrongAccount) {
		return nil, nil, fmt.Errorf(
			"%w, if the passphrase was rotated elsewhere run fuu login%s with the new one",
			err, accountArg(p.Account),
		)
	}
	if err != nil {
		return nil, nil, err
	}
	if id != p.ID {
		return nil, nil, errKeyChanged
	}
	return key, account, nil
}

func openPinnedAccount(path string, dk vault.DeviceKey) (*vault.File, []byte, []byte, error) {
	f, pin, err := loadTrusted(path)
	if err != nil {
		return nil, nil, nil, err
	}
	key, account, err := unsealPinned(f, dk, pin)
	if err != nil {
		return nil, nil, nil, err
	}
	return f, key, account, nil
}

func openPinned(path string, dk vault.DeviceKey) (*vault.File, []byte, error) {
	f, key, _, err := openPinnedAccount(path, dk)
	return f, key, err
}

// The device key is closed on the way out, unsealing is all it is needed for.
func unlock(cmd *cli.Command) (string, *vault.File, []byte, error) {
	path, err := vaultPath(cmd)
	if err != nil {
		return "", nil, nil, err
	}
	f, pin, err := loadTrusted(path)
	if err != nil {
		return path, nil, nil, err
	}
	dk, err := devkey.Open()
	if err != nil {
		return path, nil, nil, err
	}
	defer func() { _ = dk.Close() }()

	key, _, err := unsealPinned(f, dk, pin)
	if err != nil {
		return path, nil, nil, err
	}
	return path, f, key, nil
}
