package vault

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/BurntSushi/toml"
)

// DefaultAccount is the account a vault uses unless told otherwise, your own.
const DefaultAccount = "default"

var (
	ErrOtherDevice = errors.New(
		"the accounts on this machine are sealed to another TPM, it was cleared or the file was copied, run fuu login",
	)
	ErrBadAccountName = errors.New("not a valid account name, want lowercase letters, digits, - and _")

	errBadAccount = errors.New("the account file does not open, run fuu login")
)

// Accounts is this machine's copy of every account seed it has logged in to,
// each sealed to its TPM the same way. It never leaves the machine and opens
// nowhere else.
type Accounts struct {
	Version int             `toml:"version"`
	Device  string          `toml:"device"`
	Account map[string]Seal `toml:"account"`
}

// Seal is one account seed wrapped to the device key.
type Seal struct {
	EPub string `toml:"epub"`
	Wrap string `toml:"wrap"`
}

// NewAccounts is an empty account file for this machine's chip.
func NewAccounts(dk DeviceKey) *Accounts {
	return &Accounts{Version: Version, Device: Pub(dk.Public()), Account: map[string]Seal{}}
}

// Set seals the account seed under name, replacing whatever that name held.
// The name is bound into the wrap, so seals cannot be swapped between names.
func (a *Accounts) Set(dk DeviceKey, name string, seed []byte) error {
	if !ValidAccountName(name) {
		return fmt.Errorf("%w %q", ErrBadAccountName, name)
	}
	if a.Device != Pub(dk.Public()) {
		return ErrOtherDevice
	}
	ePub, body, err := wrapKey(dk.Public(), seed, accountInfo+"\x00"+name)
	if err != nil {
		return err
	}
	a.Account[name] = Seal{EPub: ePub, Wrap: body}
	return nil
}

// Unseal opens the seed of one account, false when this machine has none by that name.
func (a *Accounts) Unseal(dk DeviceKey, name string) ([]byte, bool, error) {
	s, ok := a.Account[name]
	if !ok {
		return nil, false, nil
	}
	if a.Device != Pub(dk.Public()) {
		return nil, true, ErrOtherDevice
	}
	seed, err := unwrapKey(dk, s.EPub, s.Wrap, accountInfo+"\x00"+name)
	if err != nil || len(seed) != vaultKeySize {
		return nil, true, errBadAccount
	}
	return seed, true, nil
}

// Names lists the accounts, the default one first.
func (a *Accounts) Names() []string {
	names := slices.Sorted(maps.Keys(a.Account))
	if i := slices.Index(names, DefaultAccount); i > 0 {
		names = slices.Insert(slices.Delete(names, i, i+1), 0, DefaultAccount)
	}
	return names
}

// ParseAccounts reads what Encode writes.
func ParseAccounts(data []byte) (*Accounts, error) {
	a := new(Accounts)
	if err := toml.Unmarshal(data, a); err != nil {
		return nil, fmt.Errorf("account: parse: %w", err)
	}
	if err := checkVersion("account file", a.Version); err != nil {
		return nil, err
	}
	if a.Account == nil {
		a.Account = map[string]Seal{}
	}
	return a, nil
}

// Encode is the account file's bytes.
func (a *Accounts) Encode() ([]byte, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(a); err != nil {
		return nil, fmt.Errorf("account: encode: %w", err)
	}
	return buf.Bytes(), nil
}

// ValidAccountName keeps names short and plain, they are typed and printed.
func ValidAccountName(name string) bool {
	if len(name) < 1 || len(name) > 32 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// Pub encodes a P-256 public key as "p256:" plus the compressed point.
func Pub(pub *ecdh.PublicKey) string {
	return "p256:" + compressPoint(pub)
}
