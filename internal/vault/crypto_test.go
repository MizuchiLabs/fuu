package vault

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func vaultKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, vaultKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate vault key: %v", err)
	}
	return key
}

// Only the target chip opens a device wrap.
func TestKeyWrapRoundTrip(t *testing.T) {
	recipient, stranger := newSoftKey(t), newSoftKey(t)
	key := vaultKey(t)

	ePub, body, err := wrapKey(recipient.Public(), key)
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	got, err := unwrapKey(recipient, ePub, body)
	if err != nil {
		t.Fatalf("unwrapKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("unwrapKey did not return the wrapped key")
	}
	if _, err := unwrapKey(stranger, ePub, body); err == nil {
		t.Fatal("a wrap for one chip opened with another")
	}
}

// A body cut from one entry cannot be pasted into another.
func TestValueBoundToSlot(t *testing.T) {
	key := vaultKey(t)

	body, err := sealValue(key, []byte("s3cret"), "slot-a")
	if err != nil {
		t.Fatalf("sealValue: %v", err)
	}
	got, err := openValue(key, body, "slot-a")
	if err != nil {
		t.Fatalf("openValue: %v", err)
	}
	if string(got) != "s3cret" {
		t.Fatalf("got %q", got)
	}

	if _, err := openValue(key, body, "slot-b"); err == nil {
		t.Fatal("a body opened under a different slot")
	}
	if _, err := openValue(vaultKey(t), body, "slot-a"); err == nil {
		t.Fatal("a body opened under a different key")
	}
}
