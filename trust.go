package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
	"github.com/mizuchilabs/kata/fsutil"

	"github.com/mizuchilabs/fuu/internal/seal"
	"github.com/mizuchilabs/fuu/internal/sig"
	"github.com/mizuchilabs/fuu/internal/vault"
)

// pinFile is this machine's record of one vault: which signing keys it
// accepts, how far the write counter has advanced, and the folders it may
// load from. It lives outside the vault on purpose. Trust anchors read out of
// the file being verified would let anyone who can write the file mint a self
// certified one.
//
// There is no revocation list. The write counter is what stops a revoked
// device coming back on an old copy of the file, which keeps revoking and
// re-enrolling a device free of side effects.
type pinFile struct {
	Signers    []string `toml:"signers"`
	LastSeq    uint64   `toml:"lastseq"`
	LastDigest string   `toml:"lastdigest"`
	Paths      []string `toml:"paths,omitempty"`
}

var (
	errUnaccepted = errors.New("this vault has not been accepted on this machine")
	errUntrusted  = errors.New("this folder is not one this machine loads that vault from")
	errStale      = errors.New("this vault is older than what this machine has already seen")
	errRevoked    = errors.New("signing key is not accepted on this machine")
)

// verifyPinned checks the file against what this machine already accepted:
// a signature from a key it trusts, at a folder it loads from, and a write
// counter that has not gone backwards.
func verifyPinned(path string, f *vault.File) error {
	pins, err := loadPins(f.VaultID)
	if err != nil {
		return err
	}
	if len(pins.Signers) == 0 {
		return fmt.Errorf(
			"%w, if this is really yours run fuu trust here",
			errUnaccepted,
		)
	}

	dir, err := vaultDir(path)
	if err != nil {
		return err
	}
	if !slices.Contains(pins.Paths, dir) {
		return fmt.Errorf(
			"%w, if you meant to use %s run fuu trust here",
			errUntrusted,
			dir,
		)
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
			return fmt.Errorf(
				"%w, if you knowingly changed it run fuu trust here",
				errRevoked,
			)
		}
		return err
	}

	// A copy of the file this machine has already accepted is always fine.
	// Anything else has to be a step forward, which is what makes a rolled
	// back or forked copy refuse to load instead of quietly winning.
	if f.Digest() != pins.LastDigest && f.Seq <= pins.LastSeq {
		return fmt.Errorf(
			"%w, this copy is at write %d and this machine is at %d. If that is what you want run fuu trust here",
			errStale,
			f.Seq,
			pins.LastSeq,
		)
	}
	return nil
}

// trustVault records the vault as accepted here: its signing keys, how far the
// write counter has got, and the folder to load it from. This is the one step
// that introduces a signing key nobody here has vouched for yet, so it is the
// only command that replaces the accepted set rather than following it.
func trustVault(path string, f *vault.File, key []byte) error {
	signers, err := f.Signers(key)
	if err != nil {
		return err
	}
	dir, err := vaultDir(path)
	if err != nil {
		return err
	}
	// The signing keys are replaced, that is what accepting means. The folders
	// accumulate, so accepting a second checkout must not untrust the first.
	pins, err := loadPins(f.VaultID)
	if err != nil {
		return err
	}
	return savePins(f.VaultID, pinFile{
		Signers:    signers,
		LastSeq:    f.Seq,
		LastDigest: f.Digest(),
		Paths:      addPath(pins.Paths, dir),
	})
}

// proveKey proves the wraps agree on one vault key before trust is granted:
// the recovery passphrase opens the recovery wrap and the device wrap opens to
// the same key. A wrap set swapped in by an attacker satisfies neither, so a
// device wrap that does not open is a refusal rather than a pass. A nil
// device key means this machine is not enrolled and only the recovery wrap
// can be proven, which is the join path.
func proveKey(f *vault.File, passphrase string, dk seal.DeviceKey) error {
	viaPass, err := f.VaultKeyPass(passphrase)
	if err != nil {
		return fmt.Errorf("the recovery wrap does not open with that passphrase: %w", err)
	}
	defer clear(viaPass)

	if dk == nil {
		return nil
	}

	viaDevice, err := f.VaultKey(dk)
	if err != nil {
		return fmt.Errorf(
			"this machine's wrap does not open in this file, it was swapped or dropped: %w",
			err,
		)
	}
	defer clear(viaDevice)

	if !bytes.Equal(viaPass, viaDevice) {
		return errors.New(
			"the recovery wrap and the device wrap hold different vault keys, this file is stitched together",
		)
	}
	return nil
}

// loadPins reads this vault's pin file, empty when there is none.
func loadPins(vaultID string) (pinFile, error) {
	path, err := pinPath(vaultID)
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
func savePins(vaultID string, pins pinFile) error {
	if len(pins.Signers) == 0 {
		return errors.New("trust: refusing to pin a vault with no signers")
	}
	if slices.Contains(pins.Signers, "") {
		return errors.New("trust: refusing to pin an empty signer")
	}

	path, err := pinPath(vaultID)
	if err != nil {
		return err
	}
	signers := slices.Clone(pins.Signers)
	slices.Sort(signers)
	paths := slices.Clone(pins.Paths)
	slices.Sort(paths)
	out := pinFile{
		Signers:    slices.Compact(signers),
		LastSeq:    pins.LastSeq,
		LastDigest: pins.LastDigest,
		Paths:      slices.Compact(paths),
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

// pinPath names this vault's pin file. It is keyed on the vault identity, so
// two copies of one vault share one record while two vaults never do. The
// identity is hashed so a hostile vault cannot name its way into another
// vault's file.
func pinPath(vaultID string) (string, error) {
	if vaultID == "" {
		return "", errors.New("trust: empty vault identity")
	}
	sum := sha256Hex([]byte(vaultID))
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	return filepath.Join(dir, "fuu", "pins", sum+".toml"), nil
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

// addPath appends one folder to a sorted list.
func addPath(paths []string, dir string) []string {
	out := append(slices.Clone(paths), dir)
	slices.Sort(out)
	return slices.Compact(out)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
