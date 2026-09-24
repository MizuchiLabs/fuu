package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/sig"
	"github.com/mizuchilabs/fuu/internal/vault"
)

func cmdRotate(_ context.Context, cmd *cli.Command) error {
	release, err := lockVault(cmd.String("vault"))
	if err != nil {
		return err
	}
	defer release()

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
	if err := checkPassphrase(pass); err != nil {
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

	release, err := lockVault(path)
	if err != nil {
		return err
	}
	defer release()

	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	pins, err := loadPins(path)
	if err != nil {
		return err
	}
	// The one blessing command, and only for a vault with no signature. A
	// signature that no longer holds is tampering and is never blessed over.
	err = verifyPinned(path, f)
	if err == nil {
		fmt.Println("already signed, nothing to do")
		return nil
	}
	if !errors.Is(err, vault.ErrNoSig) {
		return err
	}
	if err := checkBless(f, pins); err != nil {
		return err
	}
	if len(pins.Signers) > 0 {
		fmt.Fprintln(
			os.Stderr,
			"sign: stamping a vault with no signature; if you did not just replace it, stop and check where this file came from",
		)
		ok, err := confirm("stamp this unsigned vault")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("sign: aborted, nothing written")
		}
		pass, err := prompt("recovery passphrase", false)
		if err != nil {
			return err
		}
		dk, err := devkey.Open()
		if err != nil {
			return err
		}
		defer func() { _ = dk.Close() }()
		if err := proveKey(f, pass, dk); err != nil {
			return err
		}
	}
	if err := signAndSave(f, path); err != nil {
		return err
	}

	fmt.Printf("stamped %s\n", path)
	return nil
}

func cmdVerify(_ context.Context, cmd *cli.Command) error {
	f, err := openVerified(cmd.String("vault"))
	if err != nil {
		return err
	}

	pins, err := loadPins(cmd.String("vault"))
	if err != nil {
		return err
	}
	fmt.Printf("pinned %d signer(s) for this vault\n", len(pins.Signers))
	if len(pins.Revoked) > 0 {
		fmt.Printf("revoked %d signing key(s) here\n", len(pins.Revoked))
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

// unlock loads the vault, checks it against this machine's pinned signers and unseals the vault key with this machine's TPM.
func unlock(cmd *cli.Command) (*vault.File, *devkey.Key, []byte, error) {
	f, err := openVerified(cmd.String("vault"))
	if err != nil {
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

	mine, err := sig.EncodeSigner(sk.Public())
	if err != nil {
		return err
	}
	if !slices.Contains(registrySigners(f), mine) {
		return errors.New("sign: this machine's signing key is not in the device registry of this vault, join it first")
	}

	if err := f.Stamp(sk); err != nil {
		return err
	}
	if err := f.Save(path); err != nil {
		return err
	}

	// The saved registry was just signed by a key this machine controls, so
	// the pins follow it and devices enrolled or revoked elsewhere take
	// effect here on the next pull. Revoked keys stay revoked.
	return adoptRegistry(path, registrySigners(f))
}
