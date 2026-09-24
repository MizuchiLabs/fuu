package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/sig"
	"github.com/mizuchilabs/fuu/internal/vault"
)

var errNoVault = errors.New("no vault here, run fuu init or point --vault at one")

// vaultPath resolves the vault for the current directory. An explicit --vault
// wins. Otherwise fuu looks for the nearest fuu.toml up to and including the
// git root, so a checkout is one vault and nothing outside the repository is
// ever reached by walking upwards.
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
		candidate := filepath.Join(dir, "fuu.toml")
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

// openVerified loads the vault and checks it against what this machine has
// already accepted. Nothing about the file is believed until it verifies.
func openVerified(path string) (*vault.File, error) {
	f, err := vault.Load(path)
	if err != nil {
		return nil, err
	}
	if err := verifyPinned(path, f); err != nil {
		return nil, err
	}
	return f, nil
}

// openKey unseals the vault key with this machine's TPM.
func openKey(f *vault.File) (*devkey.Key, []byte, error) {
	dk, err := devkey.Open()
	if err != nil {
		return nil, nil, err
	}
	key, err := f.VaultKey(dk)
	if err != nil {
		_ = dk.Close()
		return nil, nil, err
	}
	return dk, key, nil
}

// unlock opens the vault and unseals the vault key, then records the state it
// accepted so the next read is a cheap comparison.
func unlock(cmd *cli.Command) (*vault.File, *devkey.Key, []byte, error) {
	path, err := vaultPath(cmd)
	if err != nil {
		return nil, nil, nil, err
	}
	f, err := openVerified(path)
	if err != nil {
		return nil, nil, nil, err
	}
	dk, key, err := openKey(f)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := record(path, f, key); err != nil {
		_ = dk.Close()
		clear(key)
		return nil, nil, nil, err
	}
	return f, dk, key, nil
}

// signAndSave stamps the vault with this machine's signing key before writing
// it, so no mutation is ever saved unsigned. It also counts the write, which
// is what makes a rolled back file refuse to load later.
func signAndSave(f *vault.File, key []byte, path string) error {
	sk, err := devkey.OpenSigning()
	if err != nil {
		return err
	}
	defer func() { _ = sk.Close() }()

	mine, err := sig.EncodeSigner(sk.Public())
	if err != nil {
		return err
	}
	signers, err := f.Signers(key)
	if err != nil {
		return err
	}
	if !slices.Contains(signers, mine) {
		return errors.New("this machine is not enrolled in this vault, join it first")
	}

	f.Seq++
	if err := f.Stamp(sk); err != nil {
		return err
	}
	if err := f.Save(path); err != nil {
		return err
	}
	return record(path, f, key)
}

// record moves this machine's view of the vault forward. The signing keys
// become exactly the ones the file vouches for, so a device that leaves the
// registry stops being accepted without any separate revocation list.
func record(path string, f *vault.File, key []byte) error {
	pins, err := loadPins(f.VaultID)
	if err != nil {
		return err
	}
	signers, err := f.Signers(key)
	if err != nil {
		return err
	}
	pins.Signers = signers
	pins.LastSeq = f.Seq
	pins.LastDigest = f.Digest()
	dir, err := vaultDir(path)
	if err != nil {
		return err
	}
	pins.Paths = addPath(pins.Paths, dir)
	return savePins(f.VaultID, pins)
}
