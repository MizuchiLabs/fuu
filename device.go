package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/vault"
)

// cmdInit creates the vault, enrolls this machine and pins the folder.
func cmdInit(_ context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	if errors.Is(err, errNoVault) {
		path, err = repoVaultPath()
	}
	if err != nil {
		return err
	}

	pass := rand.Text()

	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	f, key, err := vault.New(dk, deviceName(cmd), pass)
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
	pins[dir] = vault.Fingerprint(key)
	if err := savePins(pins); err != nil {
		return err
	}

	showPassphrase(pass)
	return nil
}

// rotateAndSave replaces the vault key, saves the vault and shows the new
// recovery passphrase. Removing a device always goes through here: removal
// without a new key revokes nothing, the old key is still out there.
func rotateAndSave(path string, f *vault.File, key []byte) error {
	pass := rand.Text()
	newKey, err := f.Rotate(key, pass)
	if err != nil {
		return err
	}
	if err := f.Save(path); err != nil {
		return err
	}
	showPassphrase(pass)
	fmt.Println("other machines run fuu trust with this passphrase after pulling")

	pins, err := loadPins()
	if err != nil {
		return err
	}
	repin(pins, vault.Fingerprint(key), vault.Fingerprint(newKey))
	return savePins(pins)
}

// cmdRotate replaces the vault key and rewraps everything under it.
func cmdRotate(_ context.Context, cmd *cli.Command) error {
	path, f, key, _, err := unlock(cmd)
	if err != nil {
		return err
	}
	return rotateAndSave(path, f, key)
}

// cmdDeviceLs lists the enrolled chips by name, marking this machine.
func cmdDeviceLs(_ context.Context, cmd *cli.Command) error {
	_, f, key, self, err := unlock(cmd)
	if err != nil {
		return err
	}
	devices, err := f.Devices(key)
	if err != nil {
		return err
	}
	rows := make([]row, 0, len(devices))
	for pub, name := range devices {
		rows = append(rows, row{name: name, pub: pub})
	}
	slices.SortFunc(rows, func(a, b row) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		return strings.Compare(a.pub, b.pub)
	})
	for _, r := range rows {
		mark := "  "
		if r.pub == self {
			mark = "* "
		}
		fmt.Printf("%s%s\t%s\n", mark, r.name, r.pub)
	}
	return nil
}

type row struct{ name, pub string }

// cmdDeviceRm removes a device and rotates the vault key, so the removed
// device is cut off from every future value too.
func cmdDeviceRm(_ context.Context, cmd *cli.Command) error {
	name := cmd.Args().Get(0)
	if name == "" {
		return errors.New("device rm: want <name>")
	}

	path, f, key, self, err := unlock(cmd)
	if err != nil {
		return err
	}
	devices, err := f.Devices(key)
	if err != nil {
		return err
	}
	pub := ""
	for p, n := range devices {
		if n == name {
			pub = p
			break
		}
	}
	if pub == "" {
		return fmt.Errorf("%w %q", vault.ErrNoDevice, name)
	}
	if pub == self {
		return errors.New("device rm: cannot remove the device you are on")
	}

	if err := f.RemoveDevice(pub); err != nil {
		return err
	}
	return rotateAndSave(path, f, key)
}

// deviceName is the name for this machine: what the caller said, or the
// hostname.
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
