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

	"github.com/BurntSushi/toml"
	"github.com/mizuchilabs/kata/fsutil"
	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/vault"
)

// cmdTrust is the one command that accepts a vault key this machine has not
// vouched for yet, and the one that enrolls this machine into a vault. There
// is no trust on first use anywhere else: every other command refuses a folder
// nobody pinned.
func cmdTrust(_ context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}

	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	return trust(path, dk, deviceName(cmd))
}

// trust accepts the vault at path for this folder and enrolls this machine
// when it is not in yet. Proving the file always takes the recovery
// passphrase, unless the vault key is already pinned somewhere on this
// machine and the operator says the two are the same vault.
func trust(path string, dk vault.DeviceKey, name string) error {
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	pins, err := loadPins()
	if err != nil {
		return err
	}
	dir, err := vaultDir(path)
	if err != nil {
		return err
	}

	key, err := f.Unseal(dk)
	enrolled := err == nil
	if err != nil && !errors.Is(err, vault.ErrNotEnrolled) {
		return err
	}

	if enrolled {
		fp := vault.Fingerprint(key)
		if pins[dir] == fp {
			fmt.Println("already trusted")
			return nil
		}
		// The same vault key is already pinned to another folder, so this is
		// a second checkout of it rather than a new vault. One word from the
		// operator is enough, no passphrase round trip.
		if other, ok := pinnedElsewhere(pins, dir, fp); ok {
			same, err := confirm(fmt.Sprintf("this is the same vault as %s, load it in %s too", other, dir))
			if err != nil {
				return err
			}
			if !same {
				return errors.New("aborted, nothing recorded")
			}
			pins[dir] = fp
			if err := savePins(pins); err != nil {
				return err
			}
			fmt.Printf("trusted %s\n", dir)
			return nil
		}
	}

	pass, err := readSecret("recovery passphrase")
	if err != nil {
		return err
	}
	pkey, err := f.UnsealPassphrase(pass)
	if err != nil {
		return errors.New("the recovery passphrase does not open this vault")
	}
	if enrolled && !bytes.Equal(key, pkey) {
		return errors.New(
			"this machine's entry holds a different key than the recovery entry, the file was tampered with",
		)
	}

	// The whole file authenticates before anything is recorded or enrolled.
	if _, err := f.Secrets(pkey); err != nil {
		return err
	}
	if _, err := f.DisabledSecrets(pkey); err != nil {
		return err
	}
	if _, err := f.Devices(pkey); err != nil {
		return err
	}

	fp := vault.Fingerprint(pkey)
	if !enrolled {
		if err := f.AddDevice(pkey, dk.Public(), name); err != nil {
			return err
		}
		if err := f.Save(path); err != nil {
			return err
		}
		fmt.Printf("enrolled this machine as %s, commit .fuu.toml\n", name)
	}

	if pins[dir] != "" {
		repin(pins, pins[dir], fp)
	}
	pins[dir] = fp
	if err := savePins(pins); err != nil {
		return err
	}
	fmt.Printf("trusted %s\n", dir)
	return nil
}

// trustedPath names this machine's record of which folders hold a vault it
// trusts, mapped to the fingerprint of the vault key inside. It lives outside
// the vault on purpose: trust anchors read out of the file being verified
// would let anyone who can write the file mint a self certified one.
func trustedPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	return filepath.Join(dir, "fuu", "trusted.toml"), nil
}

// loadPins reads the folder to fingerprint map, empty when there is none.
func loadPins() (map[string]string, error) {
	path, err := trustedPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", path, err)
	}
	pins := map[string]string{}
	if err := toml.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return pins, nil
}

// savePins writes the pin map sorted, so an unchanged write stays byte
// identical and WriteIfChanged leaves it alone.
func savePins(pins map[string]string) error {
	path, err := trustedPath()
	if err != nil {
		return err
	}
	out := map[string]string{}
	for _, dir := range slices.Sorted(maps.Keys(pins)) {
		out[dir] = pins[dir]
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(out); err != nil {
		return fmt.Errorf("trust: encode: %w", err)
	}
	if err := fsutil.WriteIfChanged(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	return nil
}

// repin moves every folder pinned to from over to to. One vault key per folder
// is what a rotation or a recovery changes, and every folder of that vault
// moves with it.
func repin(pins map[string]string, from, to string) {
	for dir, fp := range pins {
		if fp == from {
			pins[dir] = to
		}
	}
}

// pinnedElsewhere reports which other folder already trusts this vault key.
func pinnedElsewhere(pins map[string]string, dir, fp string) (string, bool) {
	for _, other := range slices.Sorted(maps.Keys(pins)) {
		if other != dir && pins[other] == fp {
			return other, true
		}
	}
	return "", false
}

// vaultDir is the folder a vault is loaded from, the unit trust is granted to.
func vaultDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	// Symlinked checkouts are one place, so resolve the folder. The vault
	// itself may still be being created, so only the directory is resolved.
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return resolved, nil
	}
	return filepath.Dir(abs), nil
}
