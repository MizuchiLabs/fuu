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

// The only command that accepts a vault key this machine has not vouched for
// yet, everywhere else there is no trust on first use.
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

// Proving the file takes the recovery passphrase, unless this vault key is
// already pinned elsewhere and the operator agrees.
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
		// A second checkout of an already pinned vault, one word from the operator is enough.
		if other, ok := pinnedElsewhere(pins, dir, fp); ok {
			same, err := confirm(fmt.Sprintf(
				"this is the same vault as %s, load it in %s too", sanitize(other), sanitize(dir),
			))
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
			fmt.Printf("trusted %s\n", sanitize(dir))
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
	fmt.Printf("trusted %s\n", sanitize(dir))
	return nil
}

// Lives outside the vault on purpose: a trust anchor read from the file it
// verifies proves nothing.
func trustedPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	return filepath.Join(dir, "fuu", "trusted.toml"), nil
}

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

// Sorted so an unchanged write stays byte identical and WriteIfChanged leaves it alone.
func savePins(pins map[string]string) error {
	path, err := trustedPath()
	if err != nil {
		return err
	}
	// The encoder sorts map keys, so an unchanged write stays byte identical.
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(pins); err != nil {
		return fmt.Errorf("trust: encode: %w", err)
	}
	if err := fsutil.WriteIfChanged(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	return nil
}

// Rotation changes one vault key, and every folder of that vault moves with it.
func repin(pins map[string]string, from, to string) {
	for dir, fp := range pins {
		if fp == from {
			pins[dir] = to
		}
	}
}

func pinnedElsewhere(pins map[string]string, dir, fp string) (string, bool) {
	for _, other := range slices.Sorted(maps.Keys(pins)) {
		if other != dir && pins[other] == fp {
			return other, true
		}
	}
	return "", false
}

func vaultDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	// Symlinked checkouts are one place, so resolve the folder, but only the
	// directory, the vault may still be being created.
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return resolved, nil
	}
	return filepath.Dir(abs), nil
}
