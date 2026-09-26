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

	"github.com/mizuchilabs/kata/fsutil"
	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/vault"
)

var errNoAccount = errors.New("no account on this machine, run fuu login, or fuu init to start one")

func cmdInit(_ context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	if errors.Is(err, errNoVault) {
		path, err = repoVaultPath()
	}
	if err != nil {
		return err
	}
	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	return initVault(path, dk)
}

// The first vault on a machine without an account offers to start one, every
// later vault needs nothing but the chip.
func initVault(path string, dk vault.DeviceKey) error {
	if fsutil.FileExists(path) {
		return fmt.Errorf("init: %s already exists", path)
	}
	account, err := unsealAccount(dk)
	if errors.Is(err, errNoAccount) {
		account, err = newAccount(dk)
	}
	if err != nil {
		return err
	}

	f, _, id, err := vault.New(account)
	if err != nil {
		return err
	}
	if err := f.Save(path); err != nil {
		if errors.Is(err, vault.ErrConflict) {
			return fmt.Errorf("init: %s already exists", path)
		}
		return err
	}

	dir, err := vaultDir(path)
	if err != nil {
		return err
	}
	pins, err := loadPins()
	if err != nil {
		return err
	}
	pins[dir] = id
	if err := savePins(pins); err != nil {
		return err
	}
	fmt.Printf("created %s, commit it\n", sanitize(displayPath(path)))
	return nil
}

// A second account splits vaults between two passphrases, so it takes a yes.
func newAccount(dk vault.DeviceKey) ([]byte, error) {
	ok, err := confirm("no account on this machine yet, start a new one (say no and run fuu login if you have one)")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errNoAccount
	}
	pass := vault.NewPassphrase()
	account := vault.DeriveAccount(pass)
	if err := saveAccount(dk, account); err != nil {
		return nil, err
	}
	showPassphrase(pass)
	return account, nil
}

func cmdLogin(_ context.Context, _ *cli.Command) error {
	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	pass, err := readSecret("account passphrase")
	if err != nil {
		return err
	}
	return login(dk, pass)
}

// Vaults still sealed to the seed this machine held before move along, so a
// rotation made elsewhere strands nothing that was only checked out here.
func login(dk vault.DeviceKey, pass string) error {
	if !vault.CheckPassphrase(pass) {
		return errors.New("that is not an account passphrase, check it for a typo")
	}
	account := vault.DeriveAccount(pass)

	old, err := unsealAccount(dk)
	switch {
	case err == nil && bytes.Equal(old, account):
		fmt.Println("already logged in")
		return nil
	case err == nil:
		if err := moveVaults(old, account); err != nil {
			return err
		}
	case errors.Is(err, errNoAccount), errors.Is(err, vault.ErrOtherDevice):
	default:
		return err
	}

	if err := saveAccount(dk, account); err != nil {
		return err
	}
	fmt.Println("logged in, run fuu trust in each repository to load it here")
	return nil
}

func cmdLogout(_ context.Context, _ *cli.Command) error {
	path, err := accountPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("account: %w", err)
	}
	fmt.Println("this machine no longer holds the account, the passphrase brings it back")
	return nil
}

func cmdRotate(_ context.Context, cmd *cli.Command) error {
	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	if cmd.Bool("passphrase") {
		return rotateAccount(dk)
	}
	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}
	return rotateVault(path, dk)
}

// One vault under a fresh salt, same account and same id, so no machine has to trust it again.
func rotateVault(path string, dk vault.DeviceKey) error {
	f, key, account, err := openPinnedAccount(path, dk)
	if err != nil {
		return err
	}
	if _, err := f.Rotate(key, account); err != nil {
		return err
	}
	if err := f.Save(path); err != nil {
		return err
	}
	fmt.Println("rotated, commit .fuu.toml. After a leak, rotate the credentials at their issuers too")
	return nil
}

// The passphrase is shown before anything moves: a crash halfway leaves
// vaults under a seed only it can bring back, and fuu login with it moves the
// rest.
func rotateAccount(dk vault.DeviceKey) error {
	old, err := unsealAccount(dk)
	if err != nil {
		return err
	}
	pass := vault.NewPassphrase()
	account := vault.DeriveAccount(pass)
	showPassphrase(pass)

	if err := moveVaults(old, account); err != nil {
		return err
	}
	if err := saveAccount(dk, account); err != nil {
		return err
	}
	fmt.Println("commit every moved .fuu.toml, then run fuu login on your other machines")
	fmt.Println("after a leak, rotate the credentials at their issuers too")
	return nil
}

// Every trusted vault still opening under from is resealed under to. One that
// opens under neither is reported and left alone.
func moveVaults(from, to []byte) error {
	return sweep("moved", func(path, pin string) (string, bool, error) {
		f, err := vault.Load(path)
		if err != nil {
			return "", false, err
		}
		if _, id, err := f.Open(to); err == nil {
			return id, false, nil
		}
		key, id, err := f.Open(from)
		if err != nil {
			return "", false, err
		}
		if id != pin {
			return "", false, errKeyChanged
		}
		if _, err := f.Rotate(key, to); err != nil {
			return "", false, err
		}
		return id, true, f.Save(path)
	})
}

// sweep runs fn once per distinct vault among the trusted folders and copies
// the result to every other checkout that held the same bytes, so two
// checkouts of one vault stay identical instead of forking. fn returns the
// folder's pin afterwards and whether it wrote anything.
func sweep(verb string, fn func(path, pin string) (string, bool, error)) error {
	pins, err := loadPins()
	if err != nil {
		return err
	}
	groups := map[string][]string{}
	for _, dir := range slices.Sorted(maps.Keys(pins)) {
		path := filepath.Join(dir, vaultFile)
		data, err := vault.Read(path)
		if err != nil {
			fmt.Printf("skipped %s: %s\n", sanitize(displayPath(dir)), sanitize(present(err)))
			continue
		}
		groups[string(data)] = append(groups[string(data)], dir)
	}

	for _, data := range slices.Sorted(maps.Keys(groups)) {
		group := groups[data]
		first := filepath.Join(group[0], vaultFile)
		pin, wrote, err := fn(first, pins[group[0]])
		if err != nil {
			for _, dir := range group {
				fmt.Printf("skipped %s: %s\n", sanitize(displayPath(dir)), sanitize(present(err)))
			}
			continue
		}
		if !wrote {
			continue
		}
		written, err := vault.Read(first)
		if err != nil {
			return err
		}
		for i, dir := range group {
			if i > 0 {
				// Same bytes, but only the first folder's pin was checked.
				if pins[dir] != pins[group[0]] {
					fmt.Printf("skipped %s: %s\n", sanitize(displayPath(dir)), present(errKeyChanged))
					continue
				}
				if err := replaceIfUnchanged(filepath.Join(dir, vaultFile), []byte(data), written); err != nil {
					fmt.Printf("skipped %s: %s\n", sanitize(displayPath(dir)), sanitize(present(err)))
					continue
				}
			}
			pins[dir] = pin
			fmt.Printf("%s %s\n", verb, sanitize(displayPath(dir)))
		}
	}
	return savePins(pins)
}

func replaceIfUnchanged(path string, was, data []byte) error {
	current, err := vault.Read(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, was) {
		return vault.ErrConflict
	}
	if err := fsutil.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("vault: write %s: %w", path, err)
	}
	return nil
}

// Lives next to the pins, sealed to this machine's chip and useless anywhere else.
func accountPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("account: %w", err)
	}
	return filepath.Join(dir, "fuu", "account.toml"), nil
}

// The account seed, opened by this machine's chip.
func unsealAccount(dk vault.DeviceKey) ([]byte, error) {
	path, err := accountPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNoAccount
	}
	if err != nil {
		return nil, fmt.Errorf("account: read %s: %w", path, err)
	}
	a, err := vault.ParseAccount(data)
	if err != nil {
		return nil, err
	}
	return a.Unseal(dk)
}

func saveAccount(dk vault.DeviceKey, account []byte) error {
	path, err := accountPath()
	if err != nil {
		return err
	}
	a, err := vault.SealAccount(dk, account)
	if err != nil {
		return err
	}
	data, err := a.Encode()
	if err != nil {
		return err
	}
	if err := fsutil.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("account: %w", err)
	}
	return nil
}
