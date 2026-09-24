package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/atomicfile"
	"github.com/mizuchilabs/fuu/internal/sig"
	"github.com/mizuchilabs/fuu/internal/vault"
)

// Pins live outside the vault file because trust anchors read out of the file
// being verified let anyone with write access mint a self certified vault.
// First contact pins the registry, trust on first use. Every later check
// accepts only pinned keys, and the pin set then follows the registry a
// pinned signature just vouched for, so enrolled devices gain trust and
// revoked ones lose it.
type pinFile struct {
	Signers []string `toml:"signers"`
}

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
	pins, err := pinnedSigners(path)
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		return pinFirstContact(path, f)
	}

	pubs := make([]*ecdsa.PublicKey, 0, len(pins))
	for _, s := range pins {
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
	if slices.Equal(pins, registry) {
		return nil
	}
	return setPinnedSigners(path, registry)
}

// pinFirstContact accepts a vault that is consistent with its own registry and
// pins that registry, the one moment self certification cannot be avoided.
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
	return setPinnedSigners(path, registrySigners(f))
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

func pinnedSigners(vaultPath string) ([]string, error) {
	path, err := pinPath(vaultPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", path, err)
	}

	pins := new(pinFile)
	if err := toml.Unmarshal(data, pins); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return pins.Signers, nil
}

func setPinnedSigners(vaultPath string, signers []string) error {
	if len(signers) == 0 {
		return errors.New("trust: refusing to pin a vault with no signers")
	}
	if slices.Contains(signers, "") {
		return errors.New("trust: refusing to pin an empty signer")
	}

	path, err := pinPath(vaultPath)
	if err != nil {
		return err
	}
	sorted := slices.Clone(signers)
	slices.Sort(sorted)

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(pinFile{Signers: sorted}); err != nil {
		return fmt.Errorf("trust: encode: %w", err)
	}
	if err := atomicfile.Write(path, buf.Bytes()); err != nil {
		return fmt.Errorf("trust: %w", err)
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
	if err := trustVault(path); err != nil {
		return err
	}

	pins, err := pinnedSigners(path)
	if err != nil {
		return err
	}
	for _, signer := range pins {
		fmt.Println(signer)
	}
	fmt.Printf("pinned %d signer(s) for %s\n", len(pins), path)
	return nil
}

// trustVault pins the vault's signers after checking the vault against them,
// the recovery step for a vault that was knowingly replaced.
func trustVault(path string) error {
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
	return setPinnedSigners(path, registrySigners(f))
}

// checkBless decides whether this machine may stamp a vault with no signature.
// Pins matching the registry mean the registry itself is already vouched for.
func checkBless(f *vault.File, pins []string) error {
	if len(pins) == 0 || slices.Equal(pins, registrySigners(f)) {
		return nil
	}
	return errors.New(
		"sign: the vault's signers do not match this machine's pinned signers, if you knowingly replaced it run fuu trust first",
	)
}
