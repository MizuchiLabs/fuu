package vault

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// p256Info binds device wraps to this key schedule version.
	p256Info = "fuu/v1/p256"

	// recoveryAAD binds the recovery wrap to its slot, so it cannot be pasted over a device wrap.
	recoveryAAD = "fuu/v1/recovery"

	// entryAAD and deviceAAD bind encrypted bodies to their slot, so a body cut from one entry cannot be pasted into another.
	entryAAD  = "fuu/v1/secret\x00"
	deviceAAD = "fuu/v1/device\x00"

	// nameInfo and fingerprintInfo bind tokens and the vault fingerprint to this format version.
	nameInfo        = "fuu/v1/token\x00"
	fingerprintInfo = "fuu/v1/fingerprint"

	// tokenSize keeps tokens collision free for a personal vault while staying short enough to read in a diff.
	tokenSize = 12

	// The argon2id cost is a constant of the format, so a hostile file can never ask for work that is free or exhausting.
	argon2Time = 3      // passes over memory
	argon2Mem  = 262144 // memory in KiB, 256 MiB
	argon2Salt = 16     // random salt bytes
)

// DeviceKey is the ECDH P-256 exchange the device wrap needs. devkey.Key
// satisfies it, and its second implementation lives in this package's tests.
type DeviceKey interface {
	Public() *ecdh.PublicKey
	ECDH(peer *ecdh.PublicKey) ([]byte, error)
}

// token maps a key name to the stable opaque identifier the vault file stores
// it under. Same vault key and same name always give the same token, so a diff
// still shows which entry changed while the name stays out of the file.
func token(key []byte, name string) string {
	return tokenOf(key, nameInfo+name)
}

// tokenOf is the truncation both tokens and the fingerprint share.
func tokenOf(key []byte, info string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(info))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:tokenSize])
}

// wrapKey seals vaultKey to recipient under a fresh ephemeral P-256 keypair,
// echoing the ephemeral point the recipient needs to redo the exchange.
func wrapKey(recipient *ecdh.PublicKey, vaultKey []byte) (ePub, body string, err error) {
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

	wrappingKey, err := deriveWrappingKey(shared, eph.PublicKey(), recipient)
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
	return compressEPub(eph.PublicKey()), body, nil
}

// unwrapKey opens a device wrap with the key it was sealed to.
func unwrapKey(dk DeviceKey, ePub, body string) ([]byte, error) {
	if dk == nil {
		return nil, errors.New("nil device key")
	}
	peer, err := parseEPub(ePub)
	if err != nil {
		return nil, err
	}
	shared, err := dk.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("vault: ecdh: %w", err)
	}
	defer clear(shared)

	wrappingKey, err := deriveWrappingKey(shared, peer, dk.Public())
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

// wrapPassphrase seals vaultKey under passphrase with argon2id, echoing a fresh random salt.
func wrapPassphrase(passphrase string, vaultKey []byte) (salt, body string, err error) {
	raw := make([]byte, argon2Salt)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("vault: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(passphrase), raw, argon2Time, argon2Mem, 1, chacha20poly1305.KeySize)
	defer clear(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", "", fmt.Errorf("vault: passphrase key: %w", err)
	}
	body, err = sealBody(aead, vaultKey, []byte(recoveryAAD))
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), body, nil
}

// unwrapPassphrase replays the stored salt and opens the recovery wrap.
func unwrapPassphrase(passphrase, salt, body string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("vault: decode salt: %w", err)
	}
	key := argon2.IDKey([]byte(passphrase), raw, argon2Time, argon2Mem, 1, chacha20poly1305.KeySize)
	defer clear(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("vault: passphrase key: %w", err)
	}
	return openBody(aead, body, []byte(recoveryAAD))
}

// sealValue seals one plaintext under the vault key, bound to the aad slot so a body cannot be moved from one entry to another.
func sealValue(key, plaintext []byte, aad string) (string, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", fmt.Errorf("vault: vault key: %w", err)
	}
	return sealBody(aead, plaintext, []byte(aad))
}

// openValue opens a value body with the vault key and the same aad it was sealed with. A wrong key, a tampered body or a body moved to another slot fails as an error and no plaintext.
func openValue(key []byte, body, aad string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("vault: vault key: %w", err)
	}
	return openBody(aead, body, []byte(aad))
}

// deriveWrappingKey is the ECIES key schedule of age-plugin-tpm, HKDF-SHA256 over the ECDH shared secret.
func deriveWrappingKey(shared []byte, ephemeral, recipient *ecdh.PublicKey) ([]byte, error) {
	salt := make([]byte, 0, 130)
	// Binding both public points stops a substituted recipient from deriving the same wrapping key.
	salt = append(salt, ephemeral.Bytes()...)
	salt = append(salt, recipient.Bytes()...)
	key, err := hkdf.Key(sha256.New, shared, salt, p256Info, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("vault: hkdf: %w", err)
	}
	return key, nil
}

// compressEPub encodes pub as the compressed point a wrap stores.
func compressEPub(pub *ecdh.PublicKey) string {
	// elliptic.MarshalCompressed wants coordinates, crypto/ecdh hands out the raw point.
	b := pub.Bytes()
	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])
	return base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), x, y))
}

// parseEPub rebuilds the public key a wrap stores.
func parseEPub(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("vault: decode ephemeral public key: %w", err)
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw)
	if x == nil {
		return nil, errors.New("ephemeral public key is not a compressed P-256 point")
	}

	// crypto/ecdh only takes uncompressed points.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:65])

	peer, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("vault: parse ephemeral public key: %w", err)
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
