package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/vault"
)

// cmdTrust is the one step that introduces a signing key this machine has
// never seen: a machine joining, a vault you knowingly replaced, or the first
// use of a clone. Everything else follows signatures it already accepts.
func cmdTrust(_ context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}

	release, err := lockVault(path)
	if err != nil {
		return err
	}
	defer release()

	f, err := vault.Load(path)
	if err != nil {
		return err
	}

	dk, key, err := openKey(f)
	switch {
	case err == nil:
		defer func() { _ = dk.Close() }()
	case errors.Is(err, vault.ErrNoDevice):
		// Not enrolled here, so the recovery passphrase is the only proof
		// this file is a continuation of the vault it claims to be.
		pass, perr := prompt("recovery passphrase", false)
		if perr != nil {
			return perr
		}
		if err := proveKey(f, pass, nil); err != nil {
			return err
		}
		if key, err = f.VaultKeyPass(pass); err != nil {
			return err
		}
		defer clear(key)
	default:
		return err
	}

	if err := showVault(f, key); err != nil {
		return err
	}
	ok, err := confirm("accept this vault here")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("trust: aborted, nothing recorded")
	}

	if err := trustVault(path, f, key); err != nil {
		return err
	}
	fmt.Printf("accepted %s, %d signing key(s) trusted here\n", path, len(mustSigners(f, key)))
	return nil
}

// joinWithPassphrase proves the file with the recovery passphrase and hands
// back the vault key. A nil device key means this machine is not enrolled yet,
// so the recovery wrap is the only proof that can be given.
func joinWithPassphrase(f *vault.File) ([]byte, error) {
	pass, err := prompt("recovery passphrase", false)
	if err != nil {
		return nil, err
	}
	if err := proveKey(f, pass, nil); err != nil {
		return nil, err
	}
	return f.VaultKeyPass(pass)
}

// showVault prints what is about to be accepted, the only thing standing
// between a knowingly replaced vault and a doctored one.
func showVault(f *vault.File, key []byte) error {
	devices, err := f.Devices(key)
	if err != nil {
		return err
	}
	fmt.Printf("vault %s, write %d, %d device(s)\n", f.VaultID, f.Seq, len(devices))
	signer := f.Signer
	for _, pub := range slices.Sorted(maps.Keys(devices)) {
		meta := devices[pub]
		fmt.Printf("  %s\t%s\t%s\n", meta.Name, meta.Created, pub)
		if meta.SignPub == signer {
			signer = meta.Name
		}
	}
	fmt.Printf("last write signed by %s\n", signer)
	return nil
}

func mustSigners(f *vault.File, key []byte) []string {
	signers, err := f.Signers(key)
	if err != nil {
		return nil
	}
	return signers
}

// cmdVerify reports the state this machine has accepted.
func cmdVerify(_ context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}
	f, err := openVerified(path)
	if err != nil {
		return err
	}

	pins, err := loadPins(f.VaultID)
	if err != nil {
		return err
	}
	fmt.Printf("vault %s, write %d\n", f.VaultID, f.Seq)
	fmt.Printf("%d signing key(s) accepted here\n", len(pins.Signers))

	dk, key, err := openKey(f)
	if err != nil {
		fmt.Println("signature ok, this machine is not enrolled here")
		return nil
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	meta, err := f.Devices(key)
	if err != nil {
		return err
	}
	for _, pub := range slices.Sorted(maps.Keys(meta)) {
		if meta[pub].SignPub == f.Signer {
			fmt.Printf("signature ok, signed by %s\n", meta[pub].Name)
			return nil
		}
	}
	fmt.Println("signature ok, signer is not enrolled in this vault")
	return nil
}

// cmdRotate replaces the vault key and rewraps everything under it.
func cmdRotate(_ context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}

	release, err := lockVault(path)
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

	pass, err := recoveryPassphrase(cmd, "new recovery passphrase")
	if err != nil {
		return err
	}
	if err := f.Rotate(key, pass); err != nil {
		return err
	}
	// The vault key changed, so the values are addressed under the new one.
	rotated, err := f.VaultKey(dk)
	if err != nil {
		return err
	}
	defer clear(rotated)
	if err := signAndSave(f, rotated, path); err != nil {
		return err
	}

	fmt.Println("rotated the vault key")
	return nil
}
