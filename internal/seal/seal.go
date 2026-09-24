// Package seal wraps vault key material and secret values into portable
// envelopes: XChaCha20-Poly1305 under a fresh random 24 byte nonce every
// time, keyed once per device with an ECDH P-256 wrap, once for recovery
// with an argon2id passphrase wrap, and directly by the vault key for
// secret values. Every body is nonce || ciphertext in [base64.RawURLEncoding],
// so the vault file stores nothing but base64 and envelopes copy verbatim
// between machines.
package seal

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
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

	argon2KDF  = "argon2id" // the only KDF this package writes or reads
	argon2Time = 3          // argon2id passes over memory
	argon2Mem  = 65536      // argon2id memory in KiB
	argon2Salt = 16         // random salt bytes

	// Stored cost parameters are bounded at unwrap because a vault can be
	// hostile from birth, and argon2 panics below 8 times the thread count or
	// allocates whatever the file asks for.
	argon2MinMem  = 8
	argon2MaxMem  = 1 << 20 // 1 GiB in KiB
	argon2MaxTime = 16
)

// DeviceKey is the ECDH P-256 exchange UnwrapKey needs from a device key.
// internal/devkey.Key satisfies it. This interface is a required test seam,
// its second implementation lives in this package's tests.
type DeviceKey interface {
	Public() *ecdh.PublicKey
	ECDH(peer *ecdh.PublicKey) ([]byte, error)
}

// KeyWrap is a vault key sealed to a device P-256 public key.
type KeyWrap struct {
	EPub string // base64.RawURLEncoding of the compressed P-256 ephemeral public key
	Body string // base64.RawURLEncoding of nonce || ciphertext
}

// PassWrap is a vault key sealed to a recovery passphrase.
type PassWrap struct {
	KDF  string // "argon2id", echoed so unwrap replays the stored parameters
	Salt string // base64.RawURLEncoding of the random salt
	Mem  uint32 // argon2id memory in KiB
	Time uint32 // argon2id passes
	Body string // base64.RawURLEncoding of nonce || ciphertext
}

// WrapKey seals vaultKey to recipient under a fresh ephemeral P-256 keypair.
func WrapKey(recipient *ecdh.PublicKey, vaultKey []byte) (KeyWrap, error) {
	if recipient == nil {
		return KeyWrap{}, errors.New("nil recipient")
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return KeyWrap{}, fmt.Errorf("seal: generate ephemeral key: %w", err)
	}
	// crypto/ecdh only hands the scalar out as this copy, scrub it when done.
	priv := eph.Bytes()
	defer clear(priv)

	shared, err := eph.ECDH(recipient)
	if err != nil {
		return KeyWrap{}, fmt.Errorf("seal: ecdh: %w", err)
	}
	defer clear(shared)

	wrappingKey, err := deriveWrappingKey(shared, eph.PublicKey(), recipient)
	if err != nil {
		return KeyWrap{}, err
	}
	defer clear(wrappingKey)

	aead, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil {
		return KeyWrap{}, fmt.Errorf("seal: wrapping key: %w", err)
	}
	body, err := sealBody(aead, vaultKey)
	if err != nil {
		return KeyWrap{}, err
	}
	return KeyWrap{EPub: compressEPub(eph.PublicKey()), Body: body}, nil
}

// UnwrapKey opens a wrap with the device key it was sealed to.
func UnwrapKey(dk DeviceKey, w KeyWrap) ([]byte, error) {
	if dk == nil {
		return nil, errors.New("nil device key")
	}
	peer, err := parseEPub(w.EPub)
	if err != nil {
		return nil, err
	}
	shared, err := dk.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("seal: ecdh: %w", err)
	}
	defer clear(shared)

	wrappingKey, err := deriveWrappingKey(shared, peer, dk.Public())
	if err != nil {
		return nil, err
	}
	defer clear(wrappingKey)

	aead, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("seal: wrapping key: %w", err)
	}
	return openBody(aead, w.Body)
}

// WrapPassphrase seals vaultKey under passphrase with argon2id, echoing the
// cost parameters so unwrap can replay them.
func WrapPassphrase(passphrase string, vaultKey []byte) (PassWrap, error) {
	salt := make([]byte, argon2Salt)
	if _, err := rand.Read(salt); err != nil {
		return PassWrap{}, fmt.Errorf("seal: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Mem, 1, chacha20poly1305.KeySize)
	defer clear(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return PassWrap{}, fmt.Errorf("seal: passphrase key: %w", err)
	}
	body, err := sealBody(aead, vaultKey)
	if err != nil {
		return PassWrap{}, err
	}
	return PassWrap{
		KDF:  argon2KDF,
		Salt: base64.RawURLEncoding.EncodeToString(salt),
		Mem:  argon2Mem,
		Time: argon2Time,
		Body: body,
	}, nil
}

// UnwrapPassphrase replays the stored argon2id parameters and opens the body.
func UnwrapPassphrase(passphrase string, w PassWrap) ([]byte, error) {
	if w.KDF != argon2KDF {
		return nil, fmt.Errorf("unsupported kdf %q", w.KDF)
	}
	if w.Time == 0 || w.Time > argon2MaxTime {
		return nil, fmt.Errorf("argon2 time %d is outside 1 to %d", w.Time, argon2MaxTime)
	}
	if w.Mem < argon2MinMem || w.Mem > argon2MaxMem {
		return nil, fmt.Errorf("argon2 memory %d KiB is outside %d to %d", w.Mem, argon2MinMem, argon2MaxMem)
	}
	salt, err := base64.RawURLEncoding.DecodeString(w.Salt)
	if err != nil {
		return nil, fmt.Errorf("seal: decode salt: %w", err)
	}
	key := argon2.IDKey([]byte(passphrase), salt, w.Time, w.Mem, 1, chacha20poly1305.KeySize)
	defer clear(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("seal: passphrase key: %w", err)
	}
	return openBody(aead, w.Body)
}

// WrapValue seals one secret value directly under the vault key.
func WrapValue(vaultKey, plaintext []byte) (string, error) {
	aead, err := chacha20poly1305.NewX(vaultKey)
	if err != nil {
		return "", fmt.Errorf("seal: vault key: %w", err)
	}
	return sealBody(aead, plaintext)
}

// UnwrapValue opens a value body with the vault key.
func UnwrapValue(vaultKey []byte, body string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(vaultKey)
	if err != nil {
		return nil, fmt.Errorf("seal: vault key: %w", err)
	}
	return openBody(aead, body)
}

// deriveWrappingKey is the ECIES key schedule of age-plugin-tpm, HKDF-SHA256
// over the ECDH shared secret.
func deriveWrappingKey(shared []byte, ephemeral, recipient *ecdh.PublicKey) ([]byte, error) {
	salt := make([]byte, 0, 130)
	// Binding both public points stops a substituted recipient from deriving the same wrapping key.
	salt = append(salt, ephemeral.Bytes()...)
	salt = append(salt, recipient.Bytes()...)
	key, err := hkdf.Key(sha256.New, shared, salt, p256Info, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("seal: hkdf: %w", err)
	}
	return key, nil
}

// compressEPub encodes pub as the compressed point EPub stores.
func compressEPub(pub *ecdh.PublicKey) string {
	// elliptic.MarshalCompressed wants coordinates, crypto/ecdh hands out the raw point.
	b := pub.Bytes()
	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])
	return base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), x, y))
}

// parseEPub rebuilds the public key EPub stores.
func parseEPub(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("seal: decode ephemeral public key: %w", err)
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
		return nil, fmt.Errorf("seal: ephemeral public key: %w", err)
	}
	return peer, nil
}

// sealBody encrypts plaintext as base64 of nonce || ciphertext, a fresh
// random nonce on every call.
func sealBody(aead cipher.AEAD, plaintext []byte) (string, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("seal: generate nonce: %w", err)
	}
	// Sealing onto the nonce appends the ciphertext behind it in one buffer.
	body := aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(body), nil
}

// openBody is the inverse of sealBody, a wrong key or a tampered body fails
// as an error and no plaintext.
func openBody(aead cipher.AEAD, body string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("seal: decode body: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(raw) < nonceSize+aead.Overhead() {
		return nil, fmt.Errorf("seal: body is %d bytes, too short to open", len(raw))
	}
	plain, err := aead.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("seal: open body: %w", err)
	}
	return plain, nil
}
