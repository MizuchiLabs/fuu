package vault

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Each seed opens under its own name on the chip it was sealed to, and survives the file round trip.
func TestAccountsRoundTrip(t *testing.T) {
	dk := newSoftKey(t)
	mine, team := newAccount(t), newAccount(t)

	a := NewAccounts(dk)
	if err := a.Set(dk, DefaultAccount, mine); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := a.Set(dk, "acme", team); err != nil {
		t.Fatalf("Set: %v", err)
	}
	data, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := ParseAccounts(data)
	if err != nil {
		t.Fatalf("ParseAccounts: %v", err)
	}
	for name, want := range map[string][]byte{DefaultAccount: mine, "acme": team} {
		seed, ok, err := got.Unseal(dk, name)
		if err != nil || !ok || !bytes.Equal(seed, want) {
			t.Fatalf("Unseal %s = %v, %v, want its seed", name, ok, err)
		}
	}
	if _, ok, err := got.Unseal(dk, "other"); ok || err != nil {
		t.Fatalf("Unseal of a missing account = %v, %v, want not found", ok, err)
	}
	if names := got.Names(); !slices.Equal(names, []string{DefaultAccount, "acme"}) {
		t.Fatalf("Names = %v, want default first", names)
	}
}

// A copied account file is useless on another chip, and says so plainly.
func TestAccountsOtherDevice(t *testing.T) {
	dk := newSoftKey(t)
	a := NewAccounts(dk)
	if err := a.Set(dk, DefaultAccount, newAccount(t)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	stranger := newSoftKey(t)
	if _, _, err := a.Unseal(stranger, DefaultAccount); !errors.Is(err, ErrOtherDevice) {
		t.Fatalf("Unseal on another chip = %v, want ErrOtherDevice", err)
	}
	if err := a.Set(stranger, "acme", newAccount(t)); !errors.Is(err, ErrOtherDevice) {
		t.Fatalf("Set on another chip = %v, want ErrOtherDevice", err)
	}

	// Claiming the other chip's public key does not help, the wrap is not to it.
	a.Device = Pub(stranger.Public())
	if _, _, err := a.Unseal(stranger, DefaultAccount); err == nil {
		t.Fatal("an account wrap opened on a chip it was not sealed to")
	}
}

// A seal moved to another name does not open there, the name is bound in.
func TestAccountsRefuseRenamedSeal(t *testing.T) {
	dk := newSoftKey(t)
	a := NewAccounts(dk)
	if err := a.Set(dk, "acme", newAccount(t)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	a.Account[DefaultAccount] = a.Account["acme"]
	if _, _, err := a.Unseal(dk, DefaultAccount); err == nil {
		t.Fatal("a seal opened under a name it was not made for")
	}
}

func TestAccountsRefuseBadName(t *testing.T) {
	dk := newSoftKey(t)
	for _, name := range []string{"", "Acme", "a b", "a/b", strings.Repeat("a", 33)} {
		if err := NewAccounts(dk).Set(dk, name, newAccount(t)); !errors.Is(err, ErrBadAccountName) {
			t.Fatalf("Set %q = %v, want ErrBadAccountName", name, err)
		}
	}
}

// An older or newer file is refused, and a newer one says what to do about it.
func TestParseAccountsVersion(t *testing.T) {
	if _, err := ParseAccounts([]byte("version = 0\n")); !errors.Is(err, errBadVersion) {
		t.Fatalf("ParseAccounts of version 0 = %v, want errBadVersion", err)
	}
	_, err := ParseAccounts([]byte("version = 9\n"))
	if !errors.Is(err, errBadVersion) || !strings.Contains(err.Error(), "upgrade fuu") {
		t.Fatalf("ParseAccounts of version 9 = %v, want the upgrade hint", err)
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
