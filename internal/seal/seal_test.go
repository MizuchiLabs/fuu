package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// softKey is the software DeviceKey, the second implementation that makes
// DeviceKey a test seam instead of a concrete type.
type softKey struct{ key *ecdh.PrivateKey }

var _ DeviceKey = (*softKey)(nil)

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	return &softKey{key: key}
}

func (k *softKey) Public() *ecdh.PublicKey { return k.key.PublicKey() }

func (k *softKey) ECDH(peer *ecdh.PublicKey) ([]byte, error) { return k.key.ECDH(peer) }

// testVaultKey is a fixed 32 byte vault key so every test wraps the same payload.
func testVaultKey() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

// flipBit flips one bit in the middle of a stored payload, modelling a
// corrupted or edited envelope.
func flipBit(t *testing.T, body string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("empty body")
	}
	raw[len(raw)/2] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}

// nonceOf returns the leading 24 byte nonce of a stored body.
func nonceOf(t *testing.T, body string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(raw) < 24 {
		t.Fatalf("body is %d bytes, shorter than a nonce", len(raw))
	}
	return raw[:24]
}

func TestWrapKeyRoundTrip(t *testing.T) {
	dk := newSoftKey(t)
	want := testVaultKey()

	w, err := WrapKey(dk.Public(), want)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	epub, err := base64.RawURLEncoding.DecodeString(w.EPub)
	if err != nil {
		t.Fatalf("EPub is not raw base64: %v", err)
	}
	if len(epub) != 33 {
		t.Fatalf("EPub is %d bytes, want the 33 byte compressed point", len(epub))
	}

	got, err := UnwrapKey(dk, w)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("UnwrapKey = %x, want %x", got, want)
	}
}

func TestWrapKeyWrongDeviceKey(t *testing.T) {
	owner := newSoftKey(t)
	stranger := newSoftKey(t)

	w, err := WrapKey(owner.Public(), testVaultKey())
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	got, err := UnwrapKey(stranger, w)
	if err == nil {
		t.Fatal("UnwrapKey succeeded with a different device key")
	}
	if got != nil {
		t.Fatalf("UnwrapKey returned plaintext %x with a wrong key", got)
	}
}

func TestWrapKeyBodyTamper(t *testing.T) {
	dk := newSoftKey(t)

	w, err := WrapKey(dk.Public(), testVaultKey())
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	w.Body = flipBit(t, w.Body)

	got, err := UnwrapKey(dk, w)
	if err == nil {
		t.Fatal("UnwrapKey accepted a tampered body")
	}
	if got != nil {
		t.Fatalf("UnwrapKey returned plaintext %x from a tampered body", got)
	}
}

func TestWrapKeyEPubTamper(t *testing.T) {
	dk := newSoftKey(t)

	w, err := WrapKey(dk.Public(), testVaultKey())
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	w.EPub = flipBit(t, w.EPub)

	got, err := UnwrapKey(dk, w)
	if err == nil {
		t.Fatal("UnwrapKey accepted a tampered EPub")
	}
	if got != nil {
		t.Fatalf("UnwrapKey returned plaintext %x from a tampered EPub", got)
	}
}

func TestWrapValueRoundTrip(t *testing.T) {
	key := testVaultKey()
	want := []byte("hunter2")

	body, err := WrapValue(key, want)
	if err != nil {
		t.Fatalf("WrapValue: %v", err)
	}
	got, err := UnwrapValue(key, body)
	if err != nil {
		t.Fatalf("UnwrapValue: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("UnwrapValue = %q, want %q", got, want)
	}
}

func TestWrapValueTamper(t *testing.T) {
	key := testVaultKey()

	body, err := WrapValue(key, []byte("hunter2"))
	if err != nil {
		t.Fatalf("WrapValue: %v", err)
	}
	tampered := flipBit(t, body)

	got, err := UnwrapValue(key, tampered)
	if err == nil {
		t.Fatal("UnwrapValue accepted a tampered body")
	}
	if got != nil {
		t.Fatalf("UnwrapValue returned plaintext %q from a tampered body", got)
	}
}

func TestWrapPassphraseRoundTrip(t *testing.T) {
	const passphrase = "correct horse battery staple"
	want := testVaultKey()

	w, err := WrapPassphrase(passphrase, want)
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}
	if w.KDF != "argon2id" {
		t.Fatalf("KDF = %q, want argon2id", w.KDF)
	}
	if w.Mem != 65536 {
		t.Fatalf("Mem = %d, want 65536 KiB", w.Mem)
	}
	if w.Time != 3 {
		t.Fatalf("Time = %d, want 3", w.Time)
	}
	salt, err := base64.RawURLEncoding.DecodeString(w.Salt)
	if err != nil {
		t.Fatalf("Salt is not raw base64: %v", err)
	}
	if len(salt) != 16 {
		t.Fatalf("salt is %d bytes, want 16", len(salt))
	}

	got, err := UnwrapPassphrase(passphrase, w)
	if err != nil {
		t.Fatalf("UnwrapPassphrase: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("UnwrapPassphrase = %x, want %x", got, want)
	}
}

func TestUnwrapPassphraseWrongPassphrase(t *testing.T) {
	w, err := WrapPassphrase("right passphrase", testVaultKey())
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}

	got, err := UnwrapPassphrase("wrong passphrase", w)
	if err == nil {
		t.Fatal("UnwrapPassphrase succeeded with the wrong passphrase")
	}
	if got != nil {
		t.Fatalf("UnwrapPassphrase returned plaintext %x with a wrong passphrase", got)
	}
}

func TestUnwrapPassphraseTamperedBody(t *testing.T) {
	w, err := WrapPassphrase("correct horse battery staple", testVaultKey())
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}
	w.Body = flipBit(t, w.Body)

	got, err := UnwrapPassphrase("correct horse battery staple", w)
	if err == nil {
		t.Fatal("UnwrapPassphrase accepted a tampered body")
	}
	if got != nil {
		t.Fatalf("UnwrapPassphrase returned plaintext %x from a tampered body", got)
	}
}

func TestUnwrapPassphraseUnknownKDF(t *testing.T) {
	w, err := WrapPassphrase("correct horse battery staple", testVaultKey())
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}
	w.KDF = "scrypt"

	got, err := UnwrapPassphrase("correct horse battery staple", w)
	if err == nil {
		t.Fatal("UnwrapPassphrase accepted an unknown kdf")
	}
	if got != nil {
		t.Fatalf("UnwrapPassphrase returned plaintext %x for an unknown kdf", got)
	}
}

func TestUnwrapPassphraseZeroTime(t *testing.T) {
	w, err := WrapPassphrase("correct horse battery staple", testVaultKey())
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}
	w.Time = 0

	got, err := UnwrapPassphrase("correct horse battery staple", w)
	if err == nil {
		t.Fatal("UnwrapPassphrase accepted a zero argon2 round count")
	}
	if got != nil {
		t.Fatalf("UnwrapPassphrase returned plaintext %x for a zero round count", got)
	}
}

// TestWrapFreshNonce verifies every envelope gets a fresh ephemeral keypair
// or salt and a fresh non-zero nonce, a repeated nonce would leak the XOR of
// two plaintexts under XChaCha20.
func TestWrapFreshNonce(t *testing.T) {
	dk := newSoftKey(t)
	key := testVaultKey()

	w1, err := WrapKey(dk.Public(), key)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	w2, err := WrapKey(dk.Public(), key)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if w1.EPub == w2.EPub {
		t.Fatal("WrapKey reused the ephemeral keypair")
	}
	if w1.Body == w2.Body {
		t.Fatal("WrapKey repeated a nonce")
	}

	v1, err := WrapValue(key, []byte("secret"))
	if err != nil {
		t.Fatalf("WrapValue: %v", err)
	}
	v2, err := WrapValue(key, []byte("secret"))
	if err != nil {
		t.Fatalf("WrapValue: %v", err)
	}
	if v1 == v2 {
		t.Fatal("WrapValue repeated a nonce")
	}

	p1, err := WrapPassphrase("passphrase", key)
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}
	p2, err := WrapPassphrase("passphrase", key)
	if err != nil {
		t.Fatalf("WrapPassphrase: %v", err)
	}
	if p1.Salt == p2.Salt {
		t.Fatal("WrapPassphrase reused the salt")
	}
	if p1.Body == p2.Body {
		t.Fatal("WrapPassphrase repeated a nonce")
	}

	for _, body := range []string{w1.Body, v1, p1.Body} {
		if bytes.Equal(nonceOf(t, body), make([]byte, 24)) {
			t.Fatal("envelope carries a zero nonce")
		}
	}
}

// TestUnwrapPassphraseParamsOutOfRange covers hostile cost parameters, which
// would panic argon2 or allocate the machine away in a single unwrap.
func TestUnwrapPassphraseParamsOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		set  func(w *PassWrap)
	}{
		{"huge time", func(w *PassWrap) { w.Time = argon2MaxTime + 1 }},
		{"too little memory", func(w *PassWrap) { w.Mem = 1 }},
		{"too much memory", func(w *PassWrap) { w.Mem = argon2MaxMem + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := WrapPassphrase("correct horse battery staple", testVaultKey())
			if err != nil {
				t.Fatalf("WrapPassphrase: %v", err)
			}
			tc.set(&w)

			got, err := UnwrapPassphrase("correct horse battery staple", w)
			if err == nil {
				t.Fatal("UnwrapPassphrase accepted out of range cost parameters")
			}
			if got != nil {
				t.Fatalf("UnwrapPassphrase returned plaintext %x on bad parameters", got)
			}
		})
	}
}
