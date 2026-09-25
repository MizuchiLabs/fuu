package devkey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// openKey derives a key against this machine's TPM, skipping the test when no TPM can be used.
func openKey(t *testing.T) *Key {
	t.Helper()
	if err := Available(); err != nil {
		t.Skipf("tpm unavailable: %v", err)
	}
	k, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return k
}

// Reopening on the same TPM derives the same key pair with nothing stored on disk.
func TestKeyDeterministic(t *testing.T) {
	k1 := openKey(t)
	defer func() { _ = k1.Close() }()

	k2 := openKey(t)
	defer func() { _ = k2.Close() }()

	if !bytes.Equal(k1.Public().Bytes(), k2.Public().Bytes()) {
		t.Fatal("public key differs across reopenings of the same TPM")
	}
}

// The TPM exchange equals the software one, so callers cannot tell where the device key lives.
func TestKeyECDH(t *testing.T) {
	k := openKey(t)
	defer func() { _ = k.Close() }()

	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}

	got, err := k.ECDH(peer.PublicKey())
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	want, err := peer.ECDH(k.Public())
	if err != nil {
		t.Fatalf("software ECDH: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("ECDH returned %d bytes, want the 32-byte X coordinate", len(got))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("tpm ECDH %x, software ECDH %x", got, want)
	}
}

// Close flushes the handle, so a closed key answers nothing.
func TestKeyClose(t *testing.T) {
	k := openKey(t)

	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	if err := k.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := k.ECDH(peer.PublicKey()); err == nil {
		t.Fatal("ECDH succeeded after Close, want the flushed handle rejected")
	}
}
