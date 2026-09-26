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
	f.Add([]byte("version = 1\nsalt = \"x\"\ncheck = \"y\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		vf, err := Parse(data)
		if err != nil {
			if vf != nil {
				t.Fatal("Parse returned a vault alongside an error")
			}
			return
		}
		if vf.Secret == nil || vf.Disabled == nil {
			t.Fatal("Parse handed out a vault with nil maps")
		}
	})
}

// A malformed or off curve key must fail as an error, never a panic.
func FuzzParsePoint(f *testing.F) {
	f.Add("")
	f.Add("not-base64!!")
	f.Fuzz(func(t *testing.T, s string) {
		key, err := parsePoint(s)
		if err != nil && key != nil {
			t.Fatal("parsePoint returned a key alongside an error")
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

// The account file sits in the config dir, a malformed one must fail as an error, never a panic.
func FuzzParseAccount(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("version = 1\ndevice = \"p256:x\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := ParseAccount(data)
		if err != nil {
			if a != nil {
				t.Fatal("ParseAccount returned an account alongside an error")
			}
			return
		}
	})
}
