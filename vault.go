package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/vault"
)

func cmdRotate(_ context.Context, cmd *cli.Command) error {
	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	pass, err := prompt("new recovery passphrase", true)
	if err != nil {
		return err
	}
	if err := f.Rotate(key, pass); err != nil {
		return err
	}
	if err := signAndSave(f, cmd.String("vault")); err != nil {
		return err
	}

	fmt.Println("rotated the vault key")
	return nil
}

func cmdSign(_ context.Context, cmd *cli.Command) error {
	path := cmd.String("vault")
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	// The one blessing command, and only for a vault that was never signed. A
	// signature that no longer holds is tampering and is never blessed over.
	if err := f.Verify(); err != nil && !errors.Is(err, vault.ErrNoSig) {
		return err
	}
	if err := signAndSave(f, path); err != nil {
		return err
	}

	fmt.Printf("stamped %s\n", path)
	return nil
}

func cmdVerify(_ context.Context, cmd *cli.Command) error {
	f, err := vault.Load(cmd.String("vault"))
	if err != nil {
		return err
	}
	if err := f.Verify(); err != nil {
		return err
	}

	for _, name := range slices.Sorted(maps.Keys(f.Device)) {
		if f.Device[name].SignPub == f.Signer {
			fmt.Printf("signature ok, signed by %s\n", name)
			return nil
		}
	}
	fmt.Println("signature ok, signer is not in the device registry")
	return nil
}

// unlock loads the vault, verifies its stored signature and unseals the vault key with this machine's TPM.
func unlock(cmd *cli.Command) (*vault.File, *devkey.Key, []byte, error) {
	f, err := vault.Load(cmd.String("vault"))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := f.Verify(); err != nil {
		return nil, nil, nil, err
	}

	dk, key, err := openKey(f)
	if err != nil {
		return nil, nil, nil, err
	}
	return f, dk, key, nil
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

// signAndSave stamps the vault with this machine's signing key before writing
// it, so no mutation is ever saved unsigned. Checking happens at load time
// before anything changes, never here against a stale signature.
func signAndSave(f *vault.File, path string) error {
	sk, err := devkey.OpenSigning()
	if err != nil {
		return err
	}
	defer func() { _ = sk.Close() }()

	if err := f.Stamp(sk); err != nil {
		return err
	}
	return f.Save(path)
}
