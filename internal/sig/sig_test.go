package sig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// softSigner is the software Signer, the second implementation that makes
// Signer a test seam instead of a concrete type.
type softSigner struct{ key *ecdsa.PrivateKey }

var _ Signer = (*softSigner)(nil)

func newSoftSigner(t *testing.T) *softSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &softSigner{key: key}
}

func (s *softSigner) Public() *ecdsa.PublicKey { return &s.key.PublicKey }

func (s *softSigner) Sign(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

// testPayload is a fixed payload so every test signs the same bytes.
func testPayload() []byte { return []byte("fuu vault payload") }

func TestSignVerifyRoundTrip(t *testing.T) {
	a := newSoftSigner(t)
	payload := testPayload()

	env, err := Sign(a, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify([]*ecdsa.PublicKey{a.Public()}, payload, env); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerifyOtherSignerRejected verifies an envelope signed by one key is
// rejected when a different key is the only accepted public key.
func TestVerifyOtherSignerRejected(t *testing.T) {
	a, b := newSoftSigner(t), newSoftSigner(t)

	env, err := Sign(a, testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	err = Verify([]*ecdsa.PublicKey{b.Public()}, testPayload(), env)
	if !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("Verify = %v, want ErrUnknownSigner", err)
	}
}

// TestVerifyTamperedPayloadRejected verifies an edited payload no longer
// verifies under the signing key.
func TestVerifyTamperedPayloadRejected(t *testing.T) {
	a := newSoftSigner(t)

	env, err := Sign(a, testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	payload := testPayload()
	payload[0] ^= 0x01
	err = Verify([]*ecdsa.PublicKey{a.Public()}, payload, env)
	if !errors.Is(err, ErrUnverified) {
		t.Fatalf("Verify = %v, want ErrUnverified", err)
	}
}

// TestVerifyTamperedSigRejected verifies a corrupted signature is rejected
// as malformed with its own error, distinct from a tampered payload.
func TestVerifyTamperedSigRejected(t *testing.T) {
	a := newSoftSigner(t)
	pubs := []*ecdsa.PublicKey{a.Public()}

	env, err := Sign(a, testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	truncated := env
	truncated.Sig = truncated.Sig[:len(truncated.Sig)-4]
	if err := Verify(pubs, testPayload(), truncated); !errors.Is(err, ErrBadSig) {
		t.Fatalf("Verify with truncated sig = %v, want ErrBadSig", err)
	}

	garbled := env
	garbled.Sig = "not a signature!"
	if err := Verify(pubs, testPayload(), garbled); !errors.Is(err, ErrBadSig) {
		t.Fatalf("Verify with garbled sig = %v, want ErrBadSig", err)
	}
}

// TestVerifyMalformedSignerRejected verifies an unusable Signer string is
// rejected before any signature check.
func TestVerifyMalformedSignerRejected(t *testing.T) {
	a := newSoftSigner(t)
	pubs := []*ecdsa.PublicKey{a.Public()}

	env, err := Sign(a, testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	notBase64 := env
	notBase64.Signer = "not base64!"
	if err := Verify(pubs, testPayload(), notBase64); !errors.Is(err, ErrBadSigner) {
		t.Fatalf("Verify with garbled signer = %v, want ErrBadSigner", err)
	}

	notAPoint := env
	notAPoint.Signer = base64.RawURLEncoding.EncodeToString(make([]byte, 10))
	if err := Verify(pubs, testPayload(), notAPoint); !errors.Is(err, ErrBadSigner) {
		t.Fatalf("Verify with non-point signer = %v, want ErrBadSigner", err)
	}
}

// TestVerifyEmptyPubsRejected verifies verification without any accepted
// public keys fails outright instead of accepting the envelope.
func TestVerifyEmptyPubsRejected(t *testing.T) {
	a := newSoftSigner(t)

	env, err := Sign(a, testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(nil, testPayload(), env); !errors.Is(err, ErrNoPubs) {
		t.Fatalf("Verify with nil pubs = %v, want ErrNoPubs", err)
	}
	if err := Verify([]*ecdsa.PublicKey{}, testPayload(), env); !errors.Is(err, ErrNoPubs) {
		t.Fatalf("Verify with empty pubs = %v, want ErrNoPubs", err)
	}
}

// TestVerifyAnyOf verifies the envelope is accepted when the signing key is
// the second of two accepted public keys, so no entry is special.
func TestVerifyAnyOf(t *testing.T) {
	a, b := newSoftSigner(t), newSoftSigner(t)

	env, err := Sign(a, testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pubs := []*ecdsa.PublicKey{b.Public(), a.Public()}
	if err := Verify(pubs, testPayload(), env); err != nil {
		t.Fatalf("Verify with the signing key second: %v", err)
	}
}
