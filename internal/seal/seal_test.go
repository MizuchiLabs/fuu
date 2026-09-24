package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"
)

type softKey struct{ key *ecdh.PrivateKey }

var _ DeviceKey = (*softKey)(nil)

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &softKey{key: key}
}

func (k *softKey) Public() *ecdh.PublicKey { return k.key.PublicKey() }

func (k *softKey) ECDH(peer *ecdh.PublicKey) ([]byte, error) { return k.key.ECDH(peer) }

func vaultKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate vault key: %v", err)
	}
	return key
}

// TestKeyWrapRoundTrip verifies only the target chip opens a device wrap.
func TestKeyWrapRoundTrip(t *testing.T) {
	recipient, stranger := newSoftKey(t), newSoftKey(t)
	key := vaultKey(t)

	w, err := WrapKey(recipient.Public(), key)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	got, err := UnwrapKey(recipient, w)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	defer clear(got)
	if !bytes.Equal(got, key) {
		t.Fatal("UnwrapKey did not return the wrapped key")
	}
	if _, err := UnwrapKey(stranger, w); err == nil {
		t.Fatal("a wrap for one chip opened with another")
	}
}

// TestPassWrapRoundTrip verifies the passphrase wrap and that a wrong
// passphrase yields no plaintext.
func TestPassWrapRoundTrip(t *testing.T) {
	key := vaultKey(t)

	w, err := WrapPassphrase("open sesame", key)
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}
	got, err := UnwrapPassphrase("open sesame", w)
	if err != nil {
		t.Fatalf("UnwrapPassphrase: %v", err)
	}
	defer clear(got)
	if !bytes.Equal(got, key) {
		t.Fatal("UnwrapPassphrase did not return the wrapped key")
	}
	if _, err := UnwrapPassphrase("wrong", w); err == nil {
		t.Fatal("the wrong passphrase opened the wrap")
	}
}

// TestPassWrapRejectsWeakenedCost covers a hostile vault asking for work so
// cheap that an offline attack is free, and so large it exhausts the machine.
func TestPassWrapRejectsWeakenedCost(t *testing.T) {
	key := vaultKey(t)
	w, err := WrapPassphrase("open sesame", key)
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}

	for _, tc := range []struct {
		name string
		mem  uint32
		time uint32
	}{
		{"free", 8, 1},
		{"zero time", argon2Mem, 0},
		{"exhausting", argon2MaxMem + 1, argon2Time},
	} {
		t.Run(tc.name, func(t *testing.T) {
			weak := w
			weak.Mem, weak.Time = tc.mem, tc.time
			if _, err := UnwrapPassphrase("open sesame", weak); err == nil {
				t.Fatalf("cost mem=%d time=%d was accepted", tc.mem, tc.time)
			}
		})
	}
}

// TestNameTokenStable verifies the same name under the same key always gives
// the same token, so a diff still shows which entry changed.
func TestNameTokenStable(t *testing.T) {
	key, other := vaultKey(t), vaultKey(t)

	first, err := NameToken(key, "DATABASE_URL")
	if err != nil {
		t.Fatalf("NameToken: %v", err)
	}
	again, err := NameToken(key, "DATABASE_URL")
	if err != nil {
		t.Fatalf("NameToken: %v", err)
	}
	if first != again {
		t.Fatal("the same name gave two different tokens")
	}

	for _, name := range []string{"API_KEY", "DATABASE_URL2", ""} {
		token, err := NameToken(key, name)
		if err != nil {
			t.Fatalf("NameToken(%q): %v", name, err)
		}
		if token == first && name != "DATABASE_URL" {
			t.Fatalf("two names share a token: %q", name)
		}
	}

	if swapped, err := NameToken(other, "DATABASE_URL"); err != nil {
		t.Fatalf("NameToken: %v", err)
	} else if swapped == first {
		t.Fatal("two vault keys gave the same token")
	}
}

// TestNameTokenHidesName verifies the name does not survive into the token.
func TestNameTokenHidesName(t *testing.T) {
	key := vaultKey(t)
	token, err := NameToken(key, "AWS_SECRET_ACCESS_KEY")
	if err != nil {
		t.Fatalf("NameToken: %v", err)
	}
	if strings.Contains(token, "AWS") {
		t.Fatalf("token %q carries the name", token)
	}
}

// TestValueBoundToSlot verifies a body cut from one entry cannot be pasted
// into another.
func TestValueBoundToSlot(t *testing.T) {
	key := vaultKey(t)

	body, err := WrapValue(key, []byte("s3cret"), "slot-a")
	if err != nil {
		t.Fatalf("WrapValue: %v", err)
	}
	got, err := UnwrapValue(key, body, "slot-a")
	if err != nil {
		t.Fatalf("UnwrapValue: %v", err)
	}
	if string(got) != "s3cret" {
		t.Fatalf("got %q", got)
	}

	if _, err := UnwrapValue(key, body, "slot-b"); err == nil {
		t.Fatal("a body opened under a different slot")
	}
	if _, err := UnwrapValue(vaultKey(t), body, "slot-a"); err == nil {
		t.Fatal("a body opened under a different key")
	}
}
