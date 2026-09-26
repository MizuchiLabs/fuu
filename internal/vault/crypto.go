package vault

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Every label starts with domain, so all of them move with Version.
const (
	// accountInfo binds a machine's account wrap to its purpose.
	accountInfo = domain + "account"
	// accountSalt is the fixed argon2id salt of the account seed. The passphrase
	// is always generated with 128 bits or more, so a per user salt would buy
	// nothing against precomputation, and a fixed one lets a new machine derive
	// the seed from the passphrase alone.
	accountSalt = domain + "account-seed"
	// passphraseInfo and passphraseCheckSize make the typo check of an account passphrase.
	passphraseInfo      = domain + "passphrase\x00"
	passphraseCheckSize = 2
	// vaultInfo derives a vault key from the account seed and the vault's own salt.
	vaultInfo = domain + "vault"
	// checkAAD binds the vault id to its slot.
	checkAAD = domain + "check"
	// entryAAD binds an encrypted body to its slot, so a body cut from one entry cannot be pasted into another.
	entryAAD = domain + "secret\x00"
	// disabledAAD binds a commented out entry to the disabled table, so moving a body between the tables is a refusal.
	disabledAAD = domain + "disabled\x00"
	// nameInfo binds the token a name is stored under.
	nameInfo = domain + "token\x00"
)

const (
	// tokenSize keeps tokens collision free for a personal vault while staying short enough to read in a diff.
	tokenSize = 12

	// The argon2id cost is a constant of the format, so a hostile file can never ask for work that is free or exhausting.
	argon2Time = 3      // passes over memory
	argon2Mem  = 262144 // memory in KiB, 256 MiB
)

// DeviceKey is the ECDH P-256 exchange the device wrap needs. devkey.Key satisfies it.
type DeviceKey interface {
	Public() *ecdh.PublicKey
	ECDH(peer *ecdh.PublicKey) ([]byte, error)
}

// token is the stable opaque identifier a name is stored under, so a diff shows
// which entry changed while the name stays out of the file.
func token(key []byte, name string) string {
	return tokenOf(key, nameInfo+name)
}

// tokenOf is the HMAC truncation a token is made of.
func tokenOf(key []byte, info string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(info))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:tokenSize])
}

// DeriveAccount turns the account passphrase into the account seed every vault
// key derives from. Case, spaces and dashes do not matter, the passphrase is
// shown grouped for reading.
func DeriveAccount(passphrase string) []byte {
	return argon2.IDKey(
		[]byte(NormalizePassphrase(passphrase)), []byte(accountSalt),
		argon2Time, argon2Mem, 1, vaultKeySize,
	)
}

// NewPassphrase is 128 random bits in base32 plus two check characters, so a
// typo is caught when it is typed rather than as vaults that will not open.
func NewPassphrase() string {
	body := rand.Text()
	return body + passphraseCheck(body)
}

// CheckPassphrase reports whether passphrase carries the check characters
// NewPassphrase gave it.
func CheckPassphrase(passphrase string) bool {
	n := NormalizePassphrase(passphrase)
	if len(n) <= passphraseCheckSize {
		return false
	}
	body, sum := n[:len(n)-passphraseCheckSize], n[len(n)-passphraseCheckSize:]
	return hmac.Equal([]byte(passphraseCheck(body)), []byte(sum))
}

func passphraseCheck(body string) string {
	sum := sha256.Sum256([]byte(passphraseInfo + body))
	return base32.StdEncoding.EncodeToString(sum[:])[:passphraseCheckSize]
}

// NormalizePassphrase drops what a human adds or changes while copying one out.
func NormalizePassphrase(passphrase string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToUpper(r)
	}, passphrase)
}

// deriveVaultKey is one vault's key, the account seed under that vault's salt.
func deriveVaultKey(account, salt []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, account, salt, vaultInfo, vaultKeySize)
	if err != nil {
		return nil, fmt.Errorf("vault: hkdf: %w", err)
	}
	return key, nil
}

// wrapKey seals vaultKey to recipient under a fresh ephemeral P-256 keypair,
// echoing the point the recipient needs. info names what the wrap is for.
func wrapKey(recipient *ecdh.PublicKey, vaultKey []byte, info string) (ePub, body string, err error) {
	if recipient == nil {
		return "", "", errors.New("nil recipient")
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("vault: generate ephemeral key: %w", err)
	}
	// crypto/ecdh only hands the scalar out as this copy, scrub it when done.
	priv := eph.Bytes()
	defer clear(priv)

	shared, err := eph.ECDH(recipient)
	if err != nil {
		return "", "", fmt.Errorf("vault: ecdh: %w", err)
	}
	defer clear(shared)

	wrappingKey, err := deriveWrappingKey(shared, eph.PublicKey(), recipient, info)
	if err != nil {
		return "", "", err
	}
	defer clear(wrappingKey)

	aead, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil {
		return "", "", fmt.Errorf("vault: wrapping key: %w", err)
	}
	body, err = sealBody(aead, vaultKey, nil)
	if err != nil {
		return "", "", err
	}
	return compressPoint(eph.PublicKey()), body, nil
}

// unwrapKey opens a device wrap with the key it was sealed to.
func unwrapKey(dk DeviceKey, ePub, body, info string) ([]byte, error) {
	if dk == nil {
		return nil, errors.New("nil device key")
	}
	peer, err := parsePoint(ePub)
	if err != nil {
		return nil, err
	}
	shared, err := dk.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("vault: ecdh: %w", err)
	}
	defer clear(shared)

	wrappingKey, err := deriveWrappingKey(shared, peer, dk.Public(), info)
	if err != nil {
		return nil, err
	}
	defer clear(wrappingKey)

	aead, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("vault: wrapping key: %w", err)
	}
	return openBody(aead, body, nil)
}

// sealValue seals one plaintext under the vault key, bound to its aad slot so
// bodies cannot be swapped between entries.
func sealValue(key, plaintext []byte, aad string) (string, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", fmt.Errorf("vault: vault key: %w", err)
	}
	return sealBody(aead, plaintext, []byte(aad))
}

// openValue opens a body with the same aad it was sealed with, anything else fails as an error.
func openValue(key []byte, body, aad string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("vault: vault key: %w", err)
	}
	return openBody(aead, body, []byte(aad))
}

// deriveWrappingKey is the ECIES key schedule of age-plugin-tpm, HKDF-SHA256
// over the ECDH shared secret.
func deriveWrappingKey(shared []byte, ephemeral, recipient *ecdh.PublicKey, info string) ([]byte, error) {
	salt := make([]byte, 0, 130)
	// Binding both public points stops a substituted recipient from deriving the same wrapping key.
	salt = append(salt, ephemeral.Bytes()...)
	salt = append(salt, recipient.Bytes()...)
	key, err := hkdf.Key(sha256.New, shared, salt, info, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("vault: hkdf: %w", err)
	}
	return key, nil
}

// compressPoint encodes pub as the compressed P-256 point both wraps and
// device ids store.
func compressPoint(pub *ecdh.PublicKey) string {
	// elliptic.MarshalCompressed wants coordinates, crypto/ecdh hands out the raw point.
	b := pub.Bytes()
	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])
	return base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), x, y))
}

// parsePoint rebuilds the public key compressPoint encodes.
func parsePoint(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("vault: decode public key: %w", err)
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw)
	if x == nil {
		return nil, errors.New("public key is not a compressed P-256 point")
	}

	// crypto/ecdh only takes uncompressed points.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:65])

	peer, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("vault: parse public key: %w", err)
	}
	return peer, nil
}

// sealBody encrypts plaintext as base64 of nonce || ciphertext, a fresh random nonce on every call.
func sealBody(aead cipher.AEAD, plaintext, aad []byte) (string, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("vault: generate nonce: %w", err)
	}
	// Sealing onto the nonce appends the ciphertext behind it in one buffer.
	body := aead.Seal(nonce, nonce, plaintext, aad)
	return base64.RawURLEncoding.EncodeToString(body), nil
}

// openBody is the inverse of sealBody.
func openBody(aead cipher.AEAD, body string, aad []byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("vault: decode body: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(raw) < nonceSize+aead.Overhead() {
		return nil, fmt.Errorf("vault: body is %d bytes, too short to open", len(raw))
	}
	plain, err := aead.Open(nil, raw[:nonceSize], raw[nonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("vault: open body: %w", err)
	}
	return plain, nil
}
