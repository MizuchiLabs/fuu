package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/mizuchilabs/fuu/internal/vault"
)

var errInterrupted = errors.New("interrupted")

// Anything but a plain yes means no.
func confirm(ctx context.Context, label string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", label)
	defer fmt.Fprintln(os.Stderr)

	line, err := awaitInput(ctx, readLine)
	if err != nil {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// Takes a plain line when stdin is a pipe, so init and set stay scriptable.
func readSecret(ctx context.Context, label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	defer fmt.Fprintln(os.Stderr)

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := awaitInput(ctx, readLine)
		return strings.TrimRight(line, "\r\n"), err
	}

	// ReadPassword turns echo off, an interrupted prompt has to turn it back on.
	state, err := term.GetState(fd)
	if err != nil {
		return "", fmt.Errorf("prompt: %w", err)
	}
	line, err := awaitInput(ctx, func() (string, error) {
		b, err := term.ReadPassword(fd)
		return string(b), err
	})
	if errors.Is(err, errInterrupted) {
		_ = term.Restore(fd, state)
		return "", err
	}
	if err != nil {
		return "", fmt.Errorf("prompt: %w", err)
	}
	return line, nil
}

func readLine() (string, error) {
	line, err := stdin.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("prompt: %w", err)
	}
	return line, nil
}

// Reads in the background so the first ctrl-c ends the prompt. The signal
// only cancels ctx, a blocked read would sit there until the second one.
func awaitInput(ctx context.Context, read func() (string, error)) (string, error) {
	type result struct {
		text string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		text, err := read()
		done <- result{text, err}
	}()
	select {
	case r := <-done:
		return r.text, r.err
	case <-ctx.Done():
		return "", errInterrupted
	}
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
