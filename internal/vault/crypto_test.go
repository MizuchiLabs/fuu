package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
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

	ePub, body, err := wrapKey(recipient.Public(), key, accountInfo)
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	got, err := unwrapKey(recipient, ePub, body, accountInfo)
	if err != nil {
		t.Fatalf("unwrapKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("unwrapKey did not return the wrapped key")
	}
	if _, err := unwrapKey(stranger, ePub, body, accountInfo); err == nil {
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

// The vault key itself keys nothing: sealing and tokens each run under a key
// of their own, so a body or a token made straight from it is not accepted.
func TestVaultKeySplit(t *testing.T) {
	key := vaultKey(t)

	sealKey, err := subkey(key, sealKeyInfo)
	if err != nil {
		t.Fatalf("seal key: %v", err)
	}
	tokenKey, err := subkey(key, tokenKeyInfo)
	if err != nil {
		t.Fatalf("token key: %v", err)
	}
	if bytes.Equal(sealKey, tokenKey) || bytes.Equal(sealKey, key) || bytes.Equal(tokenKey, key) {
		t.Fatal("the seal key, the token key and the vault key are not three different keys")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	body, err := sealBody(aead, []byte("s3cret"), []byte("slot"))
	if err != nil {
		t.Fatalf("sealBody: %v", err)
	}
	if _, err := openValue(key, body, "slot"); err == nil {
		t.Fatal("a body sealed straight under the vault key opened")
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(nameInfo + "API_KEY"))
	direct := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:tokenSize])
	if tok, err := token(key, "API_KEY"); err != nil || tok == direct {
		t.Fatalf("token = %q, %v, want one that is not keyed by the vault key itself", tok, err)
	}
}
