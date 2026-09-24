package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

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
		fmt.Fprintf(os.Stderr, "%s: %s\n", cmd.Name, present(err))
		os.Exit(1)
	}
}

// present keeps the deepest message and anything a wrapper appended after it,
// like hint lines, and drops the chain of context prefixes on the way there.
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
