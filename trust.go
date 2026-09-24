package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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
	"github.com/mizuchilabs/fuu/internal/seal"
	"github.com/mizuchilabs/fuu/internal/sig"
	"github.com/mizuchilabs/fuu/internal/vault"
)

// Pins live outside the vault file because trust anchors read out of the file
// being verified let anyone with write access mint a self certified vault.
// First contact pins the registry, trust on first use. Every later check
// accepts only pinned keys, and the pin set then follows the registry a
// pinned signature just vouched for, so enrolled devices gain trust and
// revoked ones lose it.
//
// Revocation is sticky here. A signing key that leaves the registry lands in
// Revoked and no replayed file can bring it back, because a vault carrying a
// revoked key is refused before anything is verified. Only fuu trust clears
// the list, or a registry this machine signed adding the key back.
type pinFile struct {
	Signers []string `toml:"signers"`
	Revoked []string `toml:"revoked,omitempty"`
}

var errRevokedSigner = errors.New("signing key is revoked on this machine")

// openVerified loads the vault and checks it against this machine's pins.
func openVerified(path string) (*vault.File, error) {
	f, err := vault.Load(path)
	if err != nil {
		return nil, err
	}
	if err := verifyPinned(path, f); err != nil {
		return nil, err
	}
	return f, nil
}

func verifyPinned(path string, f *vault.File) error {
	pins, err := loadPins(path)
	if err != nil {
		return err
	}
	if len(pins.Signers) == 0 {
		return pinFirstContact(path, f)
	}
	if err := refuseRevoked(f, pins); err != nil {
		return err
	}

	pubs := make([]*ecdsa.PublicKey, 0, len(pins.Signers))
	for _, s := range pins.Signers {
		pub, err := sig.ParseSigner(s)
		if err != nil {
			return fmt.Errorf("trust: pin: %w", err)
		}
		pubs = append(pubs, pub)
	}
	if err := f.Verify(pubs); err != nil {
		if errors.Is(err, sig.ErrUnknownSigner) || errors.Is(err, vault.ErrNoSig) {
			return trustHint(err)
		}
		return err
	}

	registry := registrySigners(f)
	if slices.Equal(pins.Signers, registry) {
		return nil
	}
	return adoptRegistry(path, registry)
}

// refuseRevoked blocks any vault carrying a device whose signing key was
// revoked on this machine. Without it a replayed file re-adds the burned
// device and its key signs again with local approval.
func refuseRevoked(f *vault.File, pins pinFile) error {
	for _, name := range slices.Sorted(maps.Keys(f.Device)) {
		if slices.Contains(pins.Revoked, f.Device[name].SignPub) {
			return fmt.Errorf(
				"%w, device %q still carries it. If that is really what you want run fuu trust",
				errRevokedSigner,
				name,
			)
		}
	}
	return nil
}

// pinFirstContact accepts a vault that is consistent with its own registry and
// pins that registry, the one moment self certification cannot be avoided.
// What gets pinned goes to stderr, so the eval'd hook keeps saying nothing but
// shell lines.
func pinFirstContact(path string, f *vault.File) error {
	pubs, err := f.SignerPubs()
	if err != nil {
		return err
	}
	if err := f.Verify(pubs); err != nil {
		if errors.Is(err, vault.ErrNoSig) {
			return trustHint(err)
		}
		return err
	}
	registry := registrySigners(f)
	if err := refuseRevoked(f, pinFile{Signers: registry}); err != nil {
		return err
	}
	fmt.Fprintf(
		os.Stderr,
		"trust: first contact with %s, pinning %d signer(s), check them before trusting this file\n",
		path,
		len(registry),
	)
	for _, signer := range registry {
		fmt.Fprintln(os.Stderr, " ", signer)
	}
	return adoptRegistry(path, registry)
}

func trustHint(err error) error {
	return fmt.Errorf(
		"%w\nif you knowingly replaced the vault run fuu trust, otherwise this file is not what it claims to be",
		err,
	)
}

func registrySigners(f *vault.File) []string {
	out := make([]string, 0, len(f.Device))
	for _, d := range f.Device {
		out = append(out, d.SignPub)
	}
	slices.Sort(out)
	return out
}

// loadPins reads this vault's pin file, empty when there is none.
func loadPins(vaultPath string) (pinFile, error) {
	path, err := pinPath(vaultPath)
	if err != nil {
		return pinFile{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return pinFile{}, nil
	}
	if err != nil {
		return pinFile{}, fmt.Errorf("trust: read %s: %w", path, err)
	}

	pins := new(pinFile)
	if err := toml.Unmarshal(data, pins); err != nil {
		return pinFile{}, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return *pins, nil
}

// savePins writes the pin file sorted, so an unchanged write stays byte
// identical and WriteIfChanged leaves it alone.
func savePins(vaultPath string, pins pinFile) error {
	if len(pins.Signers) == 0 {
		return errors.New("trust: refusing to pin a vault with no signers")
	}
	if slices.Contains(pins.Signers, "") {
		return errors.New("trust: refusing to pin an empty signer")
	}

	path, err := pinPath(vaultPath)
	if err != nil {
		return err
	}
	signers := slices.Clone(pins.Signers)
	slices.Sort(signers)
	revoked := slices.Clone(pins.Revoked)
	slices.Sort(revoked)
	out := pinFile{Signers: signers, Revoked: slices.Compact(revoked)}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(out); err != nil {
		return fmt.Errorf("trust: encode: %w", err)
	}
	if err := fsutil.WriteIfChanged(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	return nil
}

// adoptRegistry records the registry a pinned signature just vouched for.
// Signers that leave the registry become revoked and stay revoked. One that
// comes back in a registry this machine signed is enrolling again on purpose,
// which only the device commands reach, so the list gives way there.
func adoptRegistry(vaultPath string, registry []string) error {
	pins, err := loadPins(vaultPath)
	if err != nil {
		return err
	}

	revoked := make([]string, 0, len(pins.Revoked)+len(pins.Signers))
	for _, signer := range pins.Revoked {
		if !slices.Contains(registry, signer) {
			revoked = append(revoked, signer)
		}
	}
	for _, gone := range pins.Signers {
		if !slices.Contains(registry, gone) && !slices.Contains(revoked, gone) {
			revoked = append(revoked, gone)
		}
	}

	pins.Signers = registry
	pins.Revoked = revoked
	return savePins(vaultPath, pins)
}

// proveKey proves the wraps agree on one vault key before trust is granted:
// the recovery passphrase opens the recovery wrap and the device wrap opens to
// the same key. A wrap set swapped in by an attacker satisfies neither without
// the passphrase.
func proveKey(f *vault.File, passphrase string, dk seal.DeviceKey) error {
	viaPass, err := f.VaultKeyPass(passphrase)
	if err != nil {
		return fmt.Errorf("the recovery wrap does not open with that passphrase: %w", err)
	}
	defer clear(viaPass)

	viaDevice, err := f.VaultKey(dk)
	if errors.Is(err, vault.ErrNoDevice) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the device wrap does not open here: %w", err)
	}
	defer clear(viaDevice)

	if !bytes.Equal(viaPass, viaDevice) {
		return errors.New(
			"the recovery wrap and the device wrap hold different vault keys, this file is stitched together",
		)
	}
	return nil
}

// pinPath names this vault's pin file. The vault path is normalized here, so callers pass it as given.
func pinPath(vaultPath string) (string, error) {
	digest, err := absDigest(vaultPath)
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	return filepath.Join(dir, "fuu", "pins", digest+".toml"), nil
}

// cmdTrust re-pins the vault's current registry after checking the vault is
// consistent with it, for when a vault was knowingly replaced.
func cmdTrust(_ context.Context, cmd *cli.Command) error {
	path := cmd.String("vault")
	if _, err := vault.Load(path); err != nil {
		return err
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

	if err := trustVault(path, pass, dk); err != nil {
		return err
	}

	pins, err := loadPins(path)
	if err != nil {
		return err
	}
	for _, signer := range pins.Signers {
		fmt.Println(signer)
	}
	fmt.Printf("pinned %d signer(s) for %s\n", len(pins.Signers), path)
	if len(pins.Revoked) > 0 {
		fmt.Printf("forgotten %d revoked signing key(s), everything in this file is trusted again\n", len(pins.Revoked))
	}
	return nil
}

// trustVault pins the vault's signers after checking the vault against them
// and proving the wraps hold one vault key, the recovery step for a vault that
// was knowingly replaced. It also forgets every revoked signing key, since a
// replacement is a new baseline.
func trustVault(path, pass string, dk seal.DeviceKey) error {
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	pubs, err := f.SignerPubs()
	if err != nil {
		return err
	}
	if err := f.Verify(pubs); err != nil {
		if !errors.Is(err, vault.ErrNoSig) {
			return err
		}
		fmt.Fprintln(
			os.Stderr,
			"trust: this vault carries no signature, nothing could be verified, pinning its signers anyway",
		)
	}
	if err := proveKey(f, pass, dk); err != nil {
		return err
	}

	return savePins(path, pinFile{Signers: registrySigners(f)})
}

// checkBless decides whether this machine may stamp a vault with no signature.
// Pins matching the registry mean the registry itself is already vouched for.
func checkBless(f *vault.File, pins pinFile) error {
	if err := refuseRevoked(f, pins); err != nil {
		return err
	}
	if len(pins.Signers) == 0 || slices.Equal(pins.Signers, registrySigners(f)) {
		return nil
	}
	return errors.New(
		"sign: the vault's signers do not match this machine's pinned signers, if you knowingly replaced it run fuu trust first",
	)
}
