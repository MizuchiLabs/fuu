package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The account seed opens on the chip it was sealed to and survives the file round trip.
func TestAccountRoundTrip(t *testing.T) {
	dk := newSoftKey(t)
	account := newAccount(t)

	a, err := SealAccount(dk, account)
	if err != nil {
		t.Fatalf("SealAccount: %v", err)
	}
	data, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := ParseAccount(data)
	if err != nil {
		t.Fatalf("ParseAccount: %v", err)
	}
	opened, err := got.Unseal(dk)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(opened, account) {
		t.Fatal("Unseal returned another seed")
	}
}

// A copied account file is useless on another chip, and says so plainly.
func TestAccountOtherDevice(t *testing.T) {
	a, err := SealAccount(newSoftKey(t), newAccount(t))
	if err != nil {
		t.Fatalf("SealAccount: %v", err)
	}
	if _, err := a.Unseal(newSoftKey(t)); !errors.Is(err, ErrOtherDevice) {
		t.Fatalf("Unseal on another chip = %v, want ErrOtherDevice", err)
	}

	// Claiming the other chip's public key does not help, the wrap is not to it.
	stranger := newSoftKey(t)
	a.Device = Pub(stranger.Public())
	if _, err := a.Unseal(stranger); err == nil {
		t.Fatal("an account wrap opened on a chip it was not sealed to")
	}
}

// A wrap made for any other purpose cannot stand in for an account wrap, the info differs.
func TestAccountRefusesOtherWrap(t *testing.T) {
	dk := newSoftKey(t)
	ePub, body, err := wrapKey(dk.Public(), newAccount(t), domain+"other")
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	a := &Account{Version: Version, Device: Pub(dk.Public()), EPub: ePub, Wrap: body}
	if _, err := a.Unseal(dk); err == nil {
		t.Fatal("another wrap opened as the account seed")
	}
}

func TestParseAccountRefusesUnknownVersion(t *testing.T) {
	if _, err := ParseAccount([]byte("version = 9\n")); !errors.Is(err, errBadVersion) {
		t.Fatalf("ParseAccount of version 9 = %v, want errBadVersion", err)
	}
}

// A generated passphrase passes its own check however it is copied, and one changed character fails it.
func TestPassphraseCheck(t *testing.T) {
	pass := NewPassphrase()
	if !CheckPassphrase(pass) || !CheckPassphrase(strings.ToLower(pass[:4]+" "+pass[4:])) {
		t.Fatalf("CheckPassphrase refused %q", pass)
	}
	typo := []byte(pass)
	if typo[0] == 'A' {
		typo[0] = 'B'
	} else {
		typo[0] = 'A'
	}
	if CheckPassphrase(string(typo)) {
		t.Fatalf("CheckPassphrase accepted the typo %q", typo)
	}
	if CheckPassphrase("") || CheckPassphrase("AB") {
		t.Fatal("CheckPassphrase accepted a passphrase with nothing to check")
	}
}
