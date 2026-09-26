package vault

import (
	"errors"
	"fmt"
)

// Version is the one format number of fuu. The vault file, the account file
// and every domain label the crypto binds to carry it, so a breaking change
// bumps it here and nowhere else, and nothing sealed under one version opens
// under another.
const Version = 1

// domain prefixes every label, it must read "fuu/v<Version>/". Go cannot
// format an int into a constant, TestDomainMatchesVersion holds the two together.
const domain = "fuu/v1/"

var errBadVersion = errors.New("unsupported version")

// checkVersion refuses anything this build did not write, what names the file.
func checkVersion(what string, v int) error {
	switch {
	case v == Version:
		return nil
	case v > Version:
		return fmt.Errorf("%s: %w %d, it was written by a newer fuu, upgrade fuu to read it", what, errBadVersion, v)
	default:
		return fmt.Errorf("%s: %w %d, this build reads %d", what, errBadVersion, v, Version)
	}
}
