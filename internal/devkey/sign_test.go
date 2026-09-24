package devkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"
)

// openSigning derives a signing key against this machine's TPM, skipping the test when no TPM can be used.
func openSigning(t *testing.T) *SigningKey {
	t.Helper()
	if err := Available(); err != nil {
		t.Skipf("tpm unavailable: %v", err)
	}
	k, err := OpenSigning()
	if err != nil {
		t.Fatalf("OpenSigning: %v", err)
	}
	return k
}

// TestSigningKeyDeterministic verifies reopening on the same TPM derives the same signing key pair with nothing stored on disk.
func TestSigningKeyDeterministic(t *testing.T) {
	k1 := openSigning(t)
	defer func() { _ = k1.Close() }()

	k2 := openSigning(t)
	defer func() { _ = k2.Close() }()

	if !k1.Public().Equal(k2.Public()) {
		t.Fatal("signing public key differs across reopenings of the same TPM")
	}
}

// TestSigningKeySign verifies a digest signed by the TPM verifies under its public key, and that two signatures over one digest differ while both verify because ECDSA is randomized.
func TestSigningKeySign(t *testing.T) {
	k := openSigning(t)
	defer func() { _ = k.Close() }()

	digest := sha256.Sum256([]byte("fuu vault"))
	sig1, err := k.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(k.Public(), digest[:], sig1) {
		t.Fatal("first signature verification failed")
	}

	sig2, err := k.Sign(digest[:])
	if err != nil {
		t.Fatalf("second Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(k.Public(), digest[:], sig2) {
		t.Fatal("second signature verification failed")
	}
	if bytes.Equal(sig1, sig2) {
		t.Fatal("two signatures over one digest are identical, want randomized ECDSA")
	}
}

// TestSigningKeyRejectsWrongDigest verifies Sign only accepts a 32 byte SHA-256 digest.
func TestSigningKeyRejectsWrongDigest(t *testing.T) {
	k := openSigning(t)
	defer func() { _ = k.Close() }()

	for _, n := range []int{0, 31, 33, 64} {
		if _, err := k.Sign(make([]byte, n)); err == nil {
			t.Fatalf("Sign of a %d byte digest succeeded, want rejection", n)
		}
	}
}

// TestSigningKeyClose verifies Close flushes the handle, so a closed key answers nothing.
func TestSigningKeyClose(t *testing.T) {
	k := openSigning(t)
	if err := k.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	digest := sha256.Sum256([]byte("fuu vault"))
	if _, err := k.Sign(digest[:]); err == nil {
		t.Fatal("Sign succeeded after Close, want the flushed handle rejected")
	}
}
