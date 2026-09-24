package main

import (
	"crypto/rand"
	"fmt"

	"github.com/urfave/cli/v3"
)

// recoveryPassphrase is the passphrase for a new vault or a rotation. fuu
// mints one unless the caller brings their own with --prompt. A vault that
// lives in public is an offline target forever, so the passphrase is the one
// thing in the design worth overdoing, and a passphrase a human invented is
// the weakest way to get one.
func recoveryPassphrase(cmd *cli.Command, label string) (string, error) {
	if cmd.Bool("prompt") {
		pass, err := prompt(label, true)
		if err != nil {
			return "", err
		}
		if err := checkPassphrase(pass); err != nil {
			return "", err
		}
		return pass, nil
	}

	pass, err := mintPassphrase()
	if err != nil {
		return "", err
	}
	showPassphrase(pass)
	return pass, nil
}

// mintPassphrase returns a passphrase fuu generated. The floor is checked so
// the contract is that anything this hands back is usable.
func mintPassphrase() (string, error) {
	pass := rand.Text()
	if err := checkPassphrase(pass); err != nil {
		return "", err
	}
	return pass, nil
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
