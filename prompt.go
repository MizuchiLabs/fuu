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
	if utf8.RuneCountInString(strings.TrimSpace(p)) < 12 {
		return errors.New(
			"passphrase: at least 12 characters, it is the only thing slowing an offline attack on the recovery wrap",
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
