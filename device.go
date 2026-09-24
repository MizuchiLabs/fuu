package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/sig"
	"github.com/mizuchilabs/fuu/internal/vault"
)

func cmdDoctor(_ context.Context, cmd *cli.Command) error {
	if err := devkey.Available(); err != nil {
		return fmt.Errorf("doctor: %w", err)
	}

	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	fmt.Println("tpm: ok")
	fmt.Println("pub:", vault.Pub(dk.Public()))

	path := cmd.String("vault")
	f, err := vault.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("vault: none at %s\n", path)
		return nil
	}
	if err != nil {
		return err
	}

	fmt.Println("vault:", path)
	name, err := f.Match(dk)
	if err != nil {
		fmt.Println("device: not enrolled here")
		return nil
	}
	fmt.Println("device:", name)
	return nil
}

func cmdInit(_ context.Context, cmd *cli.Command) error {
	path := cmd.String("vault")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("init: %s already exists", path)
	}

	pass, err := prompt("recovery passphrase", true)
	if err != nil {
		return err
	}

	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	sk, err := devkey.OpenSigning()
	if err != nil {
		return err
	}
	defer func() { _ = sk.Close() }()

	f, err := vault.New(dk, deviceName(cmd), pass, sk.Public())
	if err != nil {
		return err
	}
	if err := signAndSave(f, path); err != nil {
		return err
	}

	fmt.Printf("created %s with device %q\n", path, deviceName(cmd))
	return nil
}

func cmdJoin(_ context.Context, cmd *cli.Command) error {
	path := cmd.String("vault")
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	// Checked before anything is added, a tampered vault is never re-stamped.
	if err := f.Verify(); err != nil {
		return err
	}

	pass, err := prompt("recovery passphrase", false)
	if err != nil {
		return err
	}

	key, err := f.VaultKeyPass(pass)
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	defer clear(key)

	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	sk, err := devkey.OpenSigning()
	if err != nil {
		return err
	}
	defer func() { _ = sk.Close() }()

	name := deviceName(cmd)
	if err := f.AddDevice(key, name, dk.Public(), sk.Public()); err != nil {
		return err
	}
	if err := signAndSave(f, path); err != nil {
		return err
	}

	fmt.Printf("enrolled device %q in %s\n", name, path)
	return nil
}

func cmdWhoami(_ context.Context, cmd *cli.Command) error {
	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	name, err := f.Match(dk)
	if err != nil {
		return fmt.Errorf("whoami: %w", err)
	}
	fmt.Println(name)
	return nil
}

func cmdDeviceLs(_ context.Context, cmd *cli.Command) error {
	f, err := vault.Load(cmd.String("vault"))
	if err != nil {
		return err
	}
	if err := f.Verify(); err != nil {
		return err
	}

	for _, name := range slices.Sorted(maps.Keys(f.Device)) {
		d := f.Device[name]
		fmt.Printf("%s\t%s\t%s\n", name, d.Created, d.Pub)
	}
	return nil
}

func cmdDevicePub(_ context.Context, _ *cli.Command) error {
	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	sk, err := devkey.OpenSigning()
	if err != nil {
		return err
	}
	defer func() { _ = sk.Close() }()

	signer, err := sig.EncodeSigner(sk.Public())
	if err != nil {
		return err
	}
	fmt.Println(vault.Pub(dk.Public()), signer)
	return nil
}

func cmdDeviceAdd(_ context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	var ecdhArg, signArg string
	switch len(args) {
	case 2:
		// device pub prints one line, which arrives whole when the line is quoted.
		fields := strings.Fields(args[1])
		if len(fields) != 2 {
			return fmt.Errorf(
				"device add: %q is not the ECDH public key and the signing public key separated by whitespace",
				args[1],
			)
		}
		ecdhArg, signArg = fields[0], fields[1]
	case 3:
		ecdhArg, signArg = args[1], args[2]
	default:
		return errors.New("device add: want <name> <pub> holding both public keys, or <name> <ecdh-pub> <sign-pub>")
	}

	pub, err := vault.ParsePub(ecdhArg)
	if err != nil {
		return err
	}
	signPub, err := sig.ParseSigner(signArg)
	if err != nil {
		return err
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	if err := f.AddDevice(key, args[0], pub, signPub); err != nil {
		return err
	}
	if err := signAndSave(f, cmd.String("vault")); err != nil {
		return err
	}

	fmt.Printf("enrolled device %q\n", args[0])
	return nil
}

func cmdDeviceRm(_ context.Context, cmd *cli.Command) error {
	name := cmd.Args().Get(0)
	if name == "" {
		return errors.New("device rm: want <name>")
	}

	path := cmd.String("vault")
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	// Checked before anything is removed, a tampered vault is never re-stamped.
	if err := f.Verify(); err != nil {
		return err
	}

	// signAndSave stamps with this machine's signing key, so it must stay
	// enrolled and cannot be the device going away.
	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	self, err := f.Match(dk)
	if err != nil {
		return fmt.Errorf("device rm: this machine is not enrolled here, revoke from an enrolled device: %w", err)
	}
	if self == name {
		return errors.New("device rm: cannot revoke the device you are on, do it from another enrolled device")
	}

	if err := f.RemoveDevice(name); err != nil {
		return err
	}
	if err := signAndSave(f, path); err != nil {
		return err
	}

	fmt.Printf("revoked device %q, rotate if it burned\n", name)
	return nil
}

func deviceName(cmd *cli.Command) string {
	if name := cmd.String("name"); name != "" {
		return name
	}
	name, err := os.Hostname()
	if err != nil {
		return "device"
	}
	return name
}
