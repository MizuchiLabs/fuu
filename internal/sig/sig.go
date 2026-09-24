// Package sig signs a payload with a device identity and verifies detached signature envelopes against known public keys, giving tamper evidence and authorship.
package sig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// Signer is the signing capability of one device identity.
// internal/devkey.SigningKey satisfies it. This is a required test seam,
// its second implementation lives in this package's tests.
type Signer interface {
	Public() *ecdsa.PublicKey
	Sign(digest []byte) ([]byte, error)
}

// Envelope is a detached signature over a payload.
type Envelope struct {
	Signer string // base64.RawURLEncoding of the compressed P-256 signer public key
	Sig    string // base64.RawURLEncoding of the DER encoded ECDSA signature
}

var (
	ErrNoPubs        = errors.New("sig: no public keys to verify against")
	ErrBadSigner     = errors.New("sig: malformed signer public key")
	ErrBadSig        = errors.New("sig: malformed signature")
	ErrUnverified    = errors.New("sig: signature does not verify over the payload")
	ErrUnknownSigner = errors.New("sig: signer is not among the accepted public keys")
)

// Sign hashes payload with SHA-256 and returns a detached envelope over the digest.
func Sign(s Signer, payload []byte) (Envelope, error) {
	if s == nil {
		return Envelope{}, errors.New("sig: nil signer")
	}
	pub := s.Public()
	if pub == nil {
		return Envelope{}, errors.New("sig: nil signer public key")
	}
	digest := sha256.Sum256(payload)
	sig, err := s.Sign(digest[:])
	if err != nil {
		return Envelope{}, fmt.Errorf("sig: sign payload: %w", err)
	}
	signer, err := EncodeSigner(pub)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Signer: signer,
		Sig:    base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// EncodeSigner encodes pub as the compressed P-256 point Envelope.Signer stores.
func EncodeSigner(pub *ecdsa.PublicKey) (string, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return "", fmt.Errorf("sig: encode signer public key: %w", ErrBadSigner)
	}
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	return base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), x, y)), nil
}

// ParseSigner rebuilds the public key Envelope.Signer stores.
func ParseSigner(s string) (*ecdsa.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("sig: decode signer public key: %w", ErrBadSigner)
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw)
	if x == nil {
		return nil, fmt.Errorf("sig: signer public key is not a compressed P-256 point: %w", ErrBadSigner)
	}

	// crypto/ecdsa only accepts uncompressed points through its parser.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:65])

	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("sig: signer public key: %w", ErrBadSigner)
	}
	return pub, nil
}

// Verify accepts the envelope when the signature is valid under any of pubs.
func Verify(pubs []*ecdsa.PublicKey, payload []byte, env Envelope) error {
	if len(pubs) == 0 {
		return ErrNoPubs
	}
	signer, err := ParseSigner(env.Signer)
	if err != nil {
		return err
	}
	sig, err := parseSig(env.Sig)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(signer, digest[:], sig) {
		return ErrUnverified
	}
	for _, pub := range pubs {
		if pub.Equal(signer) {
			return nil
		}
	}
	return ErrUnknownSigner
}

// parseSig reads what Sign writes and separates a structurally broken signature from one that simply does not verify, so a tampered signature gets its own error instead of the payload mismatch one.
func parseSig(s string) ([]byte, error) {
	sig, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("sig: decode signature: %w", ErrBadSig)
	}
	var seq struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &seq)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("sig: parse signature: %w", ErrBadSig)
	}
	return sig, nil
}
