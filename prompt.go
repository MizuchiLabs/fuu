package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

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

// showPassphrase prints the one copy fuu will ever show, to stdout so that
// saving it is a redirect rather than a hunt through the scrollback.
func showPassphrase(pass string) {
	fmt.Println("your new recovery passphrase:")
	fmt.Println()
	fmt.Printf("    %s\n", pass)
	fmt.Println()
	fmt.Println("store it in your password manager now. It is the only way to enroll")
	fmt.Println("another machine or to recover from a cleared TPM, and nobody can")
	fmt.Println("recover it for you.")
}
