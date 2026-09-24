package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

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

	path, err := vaultPath(cmd)
	if errors.Is(err, errNoVault) {
		fmt.Println("vault: none here")
		return nil
	}
	if err != nil {
		return err
	}
	f, err := openVerified(path)
	if err != nil {
		return err
	}
	fmt.Println("vault:", path)
	fmt.Println("write:", f.Seq)
	fmt.Println("sig: ok")

	unsealed, key, err := openKey(f)
	if errors.Is(err, vault.ErrNoDevice) {
		fmt.Println("device: not enrolled here")
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unsealed.Close() }()
	defer clear(key)

	pub, err := f.Match(dk)
	if err != nil {
		return err
	}
	meta, err := f.Devices(key)
	if err != nil {
		return err
	}
	fmt.Println("device:", meta[pub].Name)
	return nil
}

func cmdInit(_ context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	switch {
	case err == nil:
	case errors.Is(err, errNoVault):
		if path, err = repoVaultPath(); err != nil {
			return err
		}
	default:
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("init: %s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("init: %w", err)
	}

	pass, err := recoveryPassphrase(cmd, "recovery passphrase")
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

	name := deviceName(cmd)
	f, err := vault.New(dk, pass, name, sk.Public())
	if err != nil {
		return err
	}
	key, err := f.VaultKey(dk)
	if err != nil {
		return err
	}
	defer clear(key)

	if err := signAndSave(f, key, path); err != nil {
		return err
	}
	fmt.Printf("created %s as device %s\n", path, name)
	return nil
}

// repoVaultPath is where fuu init puts a new vault: the repository root, so
// one checkout is one vault. Outside any repository it stays in the working
// directory.
func repoVaultPath() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("init: %w", err)
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return filepath.Join(dir, "fuu.toml"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Join(cwd, "fuu.toml"), nil
		}
		dir = parent
	}
}

func cmdJoin(_ context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}

	release, err := lockVault(path)
	if err != nil {
		return err
	}
	defer release()

	// First contact on this machine, so there are no pins to verify against
	// yet. The recovery passphrase is the proof that this file continues a
	// vault that exists.
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	key, err := joinWithPassphrase(f)
	if err != nil {
		return err
	}
	defer clear(key)

	if err := confirmAccept(f, key, "enroll this machine into this vault"); err != nil {
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

	name := deviceName(cmd)
	created := time.Now().Format("2006-01-02")
	if err := f.AddDevice(key, name, created, dk.Public(), sk.Public()); err != nil {
		return err
	}
	if err := signAndSave(f, key, path); err != nil {
		return err
	}

	fmt.Printf("enrolled device %s\n", name)
	return nil
}

func cmdWhoami(_ context.Context, cmd *cli.Command) error {
	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	pub, err := f.Match(dk)
	if err != nil {
		return err
	}
	meta, err := f.Devices(key)
	if err != nil {
		return err
	}
	fmt.Println(meta[pub].Name)
	return nil
}

func cmdDeviceLs(_ context.Context, cmd *cli.Command) error {
	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	meta, err := f.Devices(key)
	if err != nil {
		return err
	}
	type row struct{ name, created, pub string }
	rows := make([]row, 0, len(meta))
	for pub, m := range meta {
		rows = append(rows, row{m.Name, m.Created, pub})
	}
	slices.SortFunc(rows, func(a, b row) int { return strings.Compare(a.name, b.name) })
	for _, r := range rows {
		fmt.Printf("%s\t%s\t%s\n", r.name, r.created, r.pub)
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

	name := args[0]
	created := time.Now().Format("2006-01-02")
	if err := f.AddDevice(key, name, created, pub, signPub); err != nil {
		return err
	}
	if err := signAndSave(f, key, path); err != nil {
		return err
	}

	fmt.Printf("enrolled device %s\n", name)
	return nil
}

func cmdDeviceRm(_ context.Context, cmd *cli.Command) error {
	name := cmd.Args().Get(0)
	if name == "" {
		return errors.New("device rm: want <name>")
	}

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

	meta, err := f.Devices(key)
	if err != nil {
		return err
	}
	pub := ""
	for p, m := range meta {
		if m.Name == name {
			pub = p
			break
		}
	}
	if pub == "" {
		return fmt.Errorf("%w %q", vault.ErrNoDevice, name)
	}

	// signAndSave stamps with this machine's signing key, so the device
	// doing the revoking has to stay enrolled.
	self, err := f.Match(dk)
	if err != nil {
		return err
	}
	if self == pub {
		return errors.New("device rm: cannot revoke the device you are on, do it from another enrolled device")
	}

	if err := f.RemoveDevice(key, pub); err != nil {
		return err
	}
	if err := signAndSave(f, key, path); err != nil {
		return err
	}

	fmt.Printf("revoked device %s, rotate if it burned\n", name)
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
