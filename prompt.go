package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	minPassLen      = 20
	minPassDistinct = 6
)

func prompt(label string, repeat bool) (string, error) {
	first, err := readSecret(label)
	if err != nil {
		return "", err
	}
	if !repeat {
		return first, nil
	}

	second, err := readSecret("repeat " + label)
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("prompt: entries do not match")
	}
	return first, nil
}

// confirm takes one visible line, since the answer is not a secret. Anything
// but a plain yes means no.
func confirm(label string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", label)
	defer fmt.Fprintln(os.Stderr)

	line, err := stdin.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("prompt: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// checkPassphrase is the floor for new recovery passphrases. An offline attack
// on the recovery wrap meets argon2id and then only this.
func checkPassphrase(p string) error {
	trimmed := strings.TrimSpace(p)
	if utf8.RuneCountInString(trimmed) < minPassLen {
		return fmt.Errorf(
			"passphrase: at least %d characters, generate one with a password manager or diceware. It is the only thing slowing an offline attack on the recovery wrap",
			minPassLen,
		)
	}

	distinct := make(map[rune]struct{}, len(trimmed))
	for _, r := range trimmed {
		distinct[r] = struct{}{}
	}
	if len(distinct) < minPassDistinct {
		return fmt.Errorf(
			"passphrase: at least %d different characters, a run of one thing is the cheap answer to a length rule",
			minPassDistinct,
		)
	}
	return nil
}

// readSecret hides the input on a terminal and takes a plain line when stdin
// is a pipe, so init and set stay scriptable.
func readSecret(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	defer fmt.Fprintln(os.Stderr)

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		line, err := term.ReadPassword(fd)
		if err != nil {
			return "", fmt.Errorf("prompt: %w", err)
		}
		return string(line), nil
	}

	line, err := stdin.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("prompt: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
