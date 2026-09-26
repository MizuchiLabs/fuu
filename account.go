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

var errNoAccount = errors.New("no account on this machine")

// noAccount says how to get the named account onto this machine.
func noAccount(name string) error {
	if name == vault.DefaultAccount {
		return fmt.Errorf("%w, run fuu login, or fuu init to start one", errNoAccount)
	}
	return fmt.Errorf("%w named %s, run fuu login --account %s, or fuu init --account %s to start it",
		errNoAccount, name, name, name)
}

// accountArg is what a hint has to add to a command for a non-default account.
func accountArg(name string) string {
	if name == vault.DefaultAccount {
		return ""
	}
	return " --account " + name
}

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
	return initVault(path, dk, cmd.String("account"))
}

// The first vault of an account this machine lacks offers to start it, every
// later vault needs nothing but the chip.
func initVault(path string, dk vault.DeviceKey, name string) error {
	if !vault.ValidAccountName(name) {
		return fmt.Errorf("%w %q", vault.ErrBadAccountName, name)
	}
	if fsutil.FileExists(path) {
		return fmt.Errorf("init: %s already exists", path)
	}
	account, err := unsealAccount(dk, name)
	if errors.Is(err, errNoAccount) {
		account, err = newAccount(dk, name)
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
	pins[dir] = pin{Account: name, ID: id}
	if err := savePins(pins); err != nil {
		return err
	}
	fmt.Printf("created %s, commit it\n", sanitize(displayPath(path)))
	return nil
}

// Starting an account that may already exist elsewhere splits vaults between
// two passphrases, so it takes a yes.
func newAccount(dk vault.DeviceKey, name string) ([]byte, error) {
	question := "no account on this machine yet, start a new one (say no and run fuu login if you have one)"
	if name != vault.DefaultAccount {
		question = fmt.Sprintf(
			"no account %s on this machine, start it (say no and run fuu login --account %s if it exists)",
			name, name,
		)
	}
	ok, err := confirm(question)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noAccount(name)
	}
	pass := vault.NewPassphrase()
	account := vault.DeriveAccount(pass)
	if err := saveAccount(dk, name, account); err != nil {
		return nil, err
	}
	showPassphrase(name, pass)
	return account, nil
}

func cmdLogin(_ context.Context, cmd *cli.Command) error {
	name := cmd.String("account")
	if !vault.ValidAccountName(name) {
		return fmt.Errorf("%w %q", vault.ErrBadAccountName, name)
	}
	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	pass, err := readSecret("passphrase of account " + name)
	if err != nil {
		return err
	}
	return login(dk, name, pass)
}

// Vaults still sealed to the seed this machine held before move along, so a
// rotation made elsewhere strands nothing that was only checked out here.
func login(dk vault.DeviceKey, name, pass string) error {
	if !vault.CheckPassphrase(pass) {
		return errors.New("that is not an account passphrase, check it for a typo")
	}
	account := vault.DeriveAccount(pass)

	old, err := unsealAccount(dk, name)
	switch {
	case err == nil && bytes.Equal(old, account):
		fmt.Println("already logged in")
		return nil
	case err == nil:
		if err := moveVaults(name, old, account); err != nil {
			return err
		}
	case errors.Is(err, errNoAccount), errors.Is(err, vault.ErrOtherDevice):
	default:
		return err
	}

	if err := saveAccount(dk, name, account); err != nil {
		return err
	}
	fmt.Printf("logged in to %s, run fuu trust in each repository to load it here\n", name)
	return nil
}

// Without --account every account goes, the way to retire a machine.
func cmdLogout(_ context.Context, cmd *cli.Command) error {
	path, err := accountPath()
	if err != nil {
		return err
	}
	if name := cmd.String("account"); name != "" {
		accounts, err := readAccounts()
		if err != nil {
			return err
		}
		if accounts == nil || accounts.Account[name] == (vault.Seal{}) {
			return noAccount(name)
		}
		delete(accounts.Account, name)
		if len(accounts.Account) > 0 {
			if err := writeAccounts(accounts); err != nil {
				return err
			}
			fmt.Printf("this machine no longer holds %s, its passphrase brings it back\n", name)
			return nil
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("account: %w", err)
	}
	fmt.Println("this machine no longer holds any account, the passphrases bring them back")
	return nil
}

func cmdRotate(_ context.Context, cmd *cli.Command) error {
	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	if cmd.Bool("passphrase") {
		return rotateAccount(dk, cmd.String("account"))
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
func rotateAccount(dk vault.DeviceKey, name string) error {
	old, err := unsealAccount(dk, name)
	if err != nil {
		return err
	}
	pass := vault.NewPassphrase()
	account := vault.DeriveAccount(pass)
	showPassphrase(name, pass)

	if err := moveVaults(name, old, account); err != nil {
		return err
	}
	if err := saveAccount(dk, name, account); err != nil {
		return err
	}
	fmt.Printf("commit every moved .fuu.toml, then pull and run fuu login%s on the other machines\n", accountArg(name))
	fmt.Println("after a leak, rotate the credentials at their issuers too")
	return nil
}

// Every vault trusted under the account and still opening under from is
// resealed under to. One that opens under neither is reported and left alone.
func moveVaults(name string, from, to []byte) error {
	return sweep("moved", name, func(path string, p pin) (bool, error) {
		f, err := vault.Load(path)
		if err != nil {
			return false, err
		}
		if _, _, err := f.Open(to); err == nil {
			return false, nil
		}
		key, id, err := f.Open(from)
		if err != nil {
			return false, err
		}
		if id != p.ID {
			return false, errKeyChanged
		}
		if _, err := f.Rotate(key, to); err != nil {
			return false, err
		}
		return true, f.Save(path)
	})
}

// sweep runs fn once per distinct vault among the trusted folders and copies
// the result to every other checkout that held the same bytes, so two
// checkouts of one vault stay identical instead of forking. Only folders
// trusted under the account take part, fn reports whether it wrote anything.
func sweep(verb, account string, fn func(path string, p pin) (bool, error)) error {
	pins, err := loadPins()
	if err != nil {
		return err
	}
	groups := map[string][]string{}
	for _, dir := range slices.Sorted(maps.Keys(pins)) {
		if pins[dir].Account != account {
			continue
		}
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
		wrote, err := fn(first, pins[group[0]])
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
			fmt.Printf("%s %s\n", verb, sanitize(displayPath(dir)))
		}
	}
	return nil
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

// readAccounts is nil when this machine holds no account at all.
func readAccounts() (*vault.Accounts, error) {
	path, err := accountPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil //nolint:nilnil // no file is no accounts, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("account: read %s: %w", path, err)
	}
	return vault.ParseAccounts(data)
}

func writeAccounts(accounts *vault.Accounts) error {
	path, err := accountPath()
	if err != nil {
		return err
	}
	data, err := accounts.Encode()
	if err != nil {
		return err
	}
	if err := fsutil.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("account: %w", err)
	}
	return nil
}

// The seed of one account, opened by this machine's chip.
func unsealAccount(dk vault.DeviceKey, name string) ([]byte, error) {
	accounts, err := readAccounts()
	if err != nil {
		return nil, err
	}
	if accounts == nil {
		return nil, noAccount(name)
	}
	seed, ok, err := accounts.Unseal(dk, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noAccount(name)
	}
	return seed, nil
}

// Seals made for another chip open nowhere, so a cleared TPM starts the file over.
func saveAccount(dk vault.DeviceKey, name string, seed []byte) error {
	accounts, err := readAccounts()
	if err != nil {
		return err
	}
	if accounts == nil || accounts.Device != vault.Pub(dk.Public()) {
		accounts = vault.NewAccounts(dk)
	}
	if err := accounts.Set(dk, name, seed); err != nil {
		return err
	}
	return writeAccounts(accounts)
}
