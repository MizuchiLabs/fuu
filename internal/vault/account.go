package vault

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/BurntSushi/toml"
)

var (
	ErrOtherDevice = errors.New(
		"the account on this machine is sealed to another TPM, it was cleared or the file was copied, run fuu login",
	)
	errBadAccount = errors.New("the account file does not open, run fuu login")
)

// Account is this machine's copy of the account seed, sealed to its TPM the
// same way a device wrap is. It never leaves the machine and never opens
// anywhere else.
type Account struct {
	Version int    `toml:"version"`
	Device  string `toml:"device"`
	EPub    string `toml:"epub"`
	Wrap    string `toml:"wrap"`
}

// SealAccount wraps the account seed to this machine's device key.
func SealAccount(dk DeviceKey, account []byte) (*Account, error) {
	ePub, body, err := wrapKey(dk.Public(), account, accountInfo)
	if err != nil {
		return nil, err
	}
	return &Account{Version: Version, Device: Pub(dk.Public()), EPub: ePub, Wrap: body}, nil
}

// Unseal opens the account seed with this machine's device key.
func (a *Account) Unseal(dk DeviceKey) ([]byte, error) {
	if a.Device != Pub(dk.Public()) {
		return nil, ErrOtherDevice
	}
	account, err := unwrapKey(dk, a.EPub, a.Wrap, accountInfo)
	if err != nil {
		return nil, errBadAccount
	}
	if len(account) != vaultKeySize {
		return nil, errBadAccount
	}
	return account, nil
}

// ParseAccount reads what Encode writes.
func ParseAccount(data []byte) (*Account, error) {
	a := new(Account)
	if err := toml.Unmarshal(data, a); err != nil {
		return nil, fmt.Errorf("account: parse: %w", err)
	}
	if err := checkVersion("account", a.Version); err != nil {
		return nil, err
	}
	return a, nil
}

// Encode is the account file's bytes.
func (a *Account) Encode() ([]byte, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(a); err != nil {
		return nil, fmt.Errorf("account: encode: %w", err)
	}
	return buf.Bytes(), nil
}

// Pub encodes a P-256 public key as "p256:" plus the compressed point.
func Pub(pub *ecdh.PublicKey) string {
	return "p256:" + compressPoint(pub)
}
