package main

import (
	"fmt"
	"os"

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
		Usage:                 "TPM-sealed secrets for .envrc",
		DefaultCommand:        "help",
		Flags:                 []cli.Flag{vaultFlag},
		Commands:              commands,
	}

	if err := cmd.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd.Name, err)
		os.Exit(1)
	}
}
