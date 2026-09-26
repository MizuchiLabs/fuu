package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/sigx"

	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		EnableShellCompletion: true,
		Suggest:               true,
		Name:                  "fuu",
		Version:               buildinfo.String(),
		Usage:                 "TPM-sealed secrets for your shell",
		DefaultCommand:        "help",
		Flags:                 []cli.Flag{vaultFlag},
		Commands:              commands,
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", cmd.Name, sanitize(present(err)))
		os.Exit(1)
	}
}

// Strips control characters so untrusted text cannot rewrite the terminal.
// Newlines survive, a hint block is allowed to span lines.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' {
			return -1
		}
		return r
	}, s)
}

// Keeps the deepest message and appended hint lines, drops the context prefixes.
func present(err error) string {
	inner := errors.Unwrap(err)
	if inner == nil {
		return err.Error()
	}
	text := err.Error()
	i := strings.Index(text, inner.Error())
	if i < 0 {
		return text
	}
	return present(inner) + text[i+len(inner.Error()):]
}
