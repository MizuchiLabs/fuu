package main

import (
	"bufio"
	"os"

	"github.com/urfave/cli/v3"
)

var (
	stdin = bufio.NewReader(os.Stdin)

	shellFlag = &cli.StringFlag{
		Name:  "shell",
		Usage: "output format, posix or fish, defaults to fish inside fish",
		Value: "",
	}

	vaultFlag = &cli.StringFlag{
		Name:    "vault",
		Usage:   "path to the vault file, otherwise the nearest fuu.toml in this repository",
		Value:   "",
		Sources: cli.EnvVars("FUU_VAULT"),
	}
)

var commands = []*cli.Command{
	{
		Name:   "doctor",
		Usage:  "report TPM status and what this machine is enrolled in",
		Action: cmdDoctor,
	},
	{
		Name:   "init",
		Usage:  "create a vault in this repository and enroll this machine",
		Action: cmdInit,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "device name, defaults to the hostname"},
			&cli.BoolFlag{
				Name:  "prompt",
				Usage: "ask for the recovery passphrase instead of generating one",
			},
		},
	},
	{
		Name:   "join",
		Usage:  "accept this vault and enroll this machine using the recovery passphrase",
		Action: cmdJoin,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "device name, defaults to the hostname"},
		},
	},
	{
		Name:   "whoami",
		Usage:  "show which enrolled device this machine is",
		Action: cmdWhoami,
	},
	{
		Name:  "device",
		Usage: "manage enrolled devices",
		Commands: []*cli.Command{
			{
				Name:   "ls",
				Usage:  "list enrolled devices",
				Action: cmdDeviceLs,
			},
			{
				Name:   "pub",
				Usage:  "print this machine's public key for enrollment elsewhere",
				Action: cmdDevicePub,
			},
			{
				Name:      "add",
				Usage:     "seal the vault key to another device's public key",
				ArgsUsage: "<name> <pub>",
				Action:    cmdDeviceAdd,
			},
			{
				Name:      "rm",
				Usage:     "revoke a device from here on",
				ArgsUsage: "<name>",
				Action:    cmdDeviceRm,
			},
		},
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
		Name:   "edit",
		Usage:  "edit this vault's secrets in your editor",
		Action: cmdEdit,
	},
	{
		Name:   "ls",
		Usage:  "list the keys in this vault",
		Action: cmdLs,
	},
	{
		Name:   "print",
		Usage:  "print export lines for this vault",
		Flags:  []cli.Flag{shellFlag},
		Action: cmdPrint,
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
		Name:            "run",
		Usage:           "run a command with this vault's secrets in its environment",
		ArgsUsage:       "<command> [args...]",
		SkipFlagParsing: true,
		Action:          cmdRun,
	},
	{
		Name:   "rotate",
		Usage:  "replace the vault key and rewrap everything",
		Action: cmdRotate,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "prompt",
				Usage: "ask for the recovery passphrase instead of generating one",
			},
		},
	},
	{
		Name:   "verify",
		Usage:  "check the vault signature and what is trusted here",
		Action: cmdVerify,
	},
	{
		Name:   "trust",
		Usage:  "accept this vault here, after a join or a replacement",
		Action: cmdTrust,
	},
}
