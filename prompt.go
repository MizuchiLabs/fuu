package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/mizuchilabs/fuu/internal/vault"
)

// Anything but a plain yes means no.
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

// Takes a plain line when stdin is a pipe, so init and set stay scriptable.
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

// Goes to stdout so saving it is a redirect rather than a hunt through the
// scrollback. Grouped in fours for reading, login ignores the dashes.
func showPassphrase(account, pass string) {
	groups := make([]string, 0, len(pass)/4+1)
	for len(pass) > 4 {
		groups = append(groups, pass[:4])
		pass = pass[4:]
	}
	groups = append(groups, pass)

	if account == vault.DefaultAccount {
		fmt.Println("your account passphrase, one for every vault:")
	} else {
		fmt.Printf("the passphrase of account %s, share it only with who should open its vaults:\n", account)
	}
	fmt.Println()
	fmt.Printf("    %s\n", strings.Join(groups, "-"))
	fmt.Println()
	fmt.Println("store it in your password manager now. It is how another machine")
	fmt.Println("logs in and how this one comes back from a cleared TPM, and nobody")
	fmt.Println("can recover it for you.")
}
