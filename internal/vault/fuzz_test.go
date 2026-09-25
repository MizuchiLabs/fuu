package vault

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// The one place an attacker controlled .fuu.toml enters, a malformed file must
// fail as an error, never a panic.
func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not toml at all"))
	f.Add([]byte("version = 1\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		vf, err := Parse(data)
		if err != nil {
			if vf != nil {
				t.Fatal("Parse returned a vault alongside an error")
			}
			return
		}
		if vf.Device == nil || vf.Secret == nil {
			t.Fatal("Parse handed out a vault with nil maps")
		}
	})
}

// A malformed or off curve key must fail as an error, never a panic.
func FuzzEphemeralPoint(f *testing.F) {
	f.Add("")
	f.Add("not-base64!!")
	f.Fuzz(func(t *testing.T, s string) {
		key, err := parseEPub(s)
		if err != nil && key != nil {
			t.Fatal("parseEPub returned a key alongside an error")
		}
	})
}

// A wrong key, a truncated body or a tampered tag must fail as an error, never a panic.
func FuzzOpenBody(f *testing.F) {
	aead, err := chacha20poly1305.NewX(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		f.Fatalf("aead: %v", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	seed := aead.Seal(nonce, nonce, []byte("seed"), nil)
	f.Add(base64.RawURLEncoding.EncodeToString(seed), []byte(nil))
	f.Fuzz(func(t *testing.T, body string, aad []byte) {
		plain, err := openBody(aead, body, aad)
		if err != nil && plain != nil {
			t.Fatal("openBody returned plaintext alongside an error")
		}
	})
}
