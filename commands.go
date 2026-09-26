package main

import (
	"bufio"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/vault"
)

var (
	stdin = bufio.NewReader(os.Stdin)

	shellFlag = &cli.StringFlag{
		Name:  "shell",
		Usage: "output format, posix or fish",
		Value: "posix",
	}

	vaultFlag = &cli.StringFlag{
		Name:    "vault",
		Usage:   "path to the vault file, otherwise the nearest .fuu.toml in this repository",
		Value:   "",
		Sources: cli.EnvVars("FUU_VAULT"),
	}
)

func accountFlag(usage string) *cli.StringFlag {
	return &cli.StringFlag{Name: "account", Usage: usage, Value: vault.DefaultAccount}
}

var commands = []*cli.Command{
	{
		Name:   "init",
		Usage:  "create a vault in this repository, and the account on first use",
		Action: cmdInit,
		Flags:  []cli.Flag{accountFlag("the account the vault belongs to")},
	},
	{
		Name:   "login",
		Usage:  "unlock an account on this machine with its passphrase",
		Action: cmdLogin,
		Flags:  []cli.Flag{accountFlag("the account to log in to")},
	},
	{
		Name:   "logout",
		Usage:  "forget every account on this machine, or one with --account",
		Action: cmdLogout,
		Flags:  []cli.Flag{&cli.StringFlag{Name: "account", Usage: "forget only this account"}},
	},
	{
		Name:   "trust",
		Usage:  "load this vault in this folder",
		Action: cmdTrust,
	},
	{
		Name:      "set",
		Usage:     "set a secret value",
		ArgsUsage: "<KEY> [value]",
		Action:    cmdSet,
	},
	{
		Name:      "unset",
		Usage:     "delete a secret value",
		ArgsUsage: "<KEY>",
		Action:    cmdUnset,
	},
	{
		Name:      "get",
		Usage:     "print one secret value",
		ArgsUsage: "<KEY>",
		Action:    cmdGet,
	},
	{
		Name:   "ls",
		Usage:  "list the keys in this vault",
		Action: cmdLs,
	},
	{
		Name:   "edit",
		Usage:  "edit this vault's secrets in your editor",
		Action: cmdEdit,
	},
	{
		Name:            "run",
		Usage:           "run a command with this vault's secrets in its environment",
		ArgsUsage:       "<command> [args...]",
		SkipFlagParsing: true,
		Action:          cmdRun,
	},
	{
		Name:   "env",
		Usage:  "print shell lines loading the vault for the current directory",
		Flags:  []cli.Flag{shellFlag},
		Action: cmdEnv,
	},
	{
		Name:   "hook",
		Usage:  "print the shell hook that keeps your shell's secrets up to date",
		Action: cmdHook,
	},
	{
		Name:   "rotate",
		Usage:  "reseal this vault under a fresh key, or with --passphrase every vault under a new account passphrase",
		Action: cmdRotate,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "passphrase",
				Usage: "replace the account passphrase and move every vault trusted under it on this machine",
			},
			accountFlag("the account whose passphrase --passphrase replaces"),
		},
	},
}
