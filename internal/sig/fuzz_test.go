package sig

import "testing"

// FuzzSignerKey feeds hostile base64 and point encodings to the signer public
// key parser. A malformed or off curve key must fail as an error that carries
// no key, never a panic.
func FuzzSignerKey(f *testing.F) {
	f.Add("")
	f.Add("not-base64!!")
	f.Fuzz(func(t *testing.T, s string) {
		pub, err := ParseSigner(s)
		if err != nil && pub != nil {
			t.Fatal("ParseSigner returned a key alongside an error")
		}
	})
}

// FuzzDetachedSig feeds hostile base64 and DER to the signature envelope
// parser. A malformed envelope must fail as an error that carries no bytes,
// never a panic.
func FuzzDetachedSig(f *testing.F) {
	f.Add("")
	f.Add("not-base64!!")
	f.Fuzz(func(t *testing.T, s string) {
		raw, err := parseSig(s)
		if err != nil && raw != nil {
			t.Fatal("parseSig returned bytes alongside an error")
		}
	})
}
