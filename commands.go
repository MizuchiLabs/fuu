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
		Usage:   "path to the vault file",
		Value:   "fuu.toml",
		Sources: cli.EnvVars("FUU_VAULT"),
	}
)

var commands = []*cli.Command{
	{
		Name:   "doctor",
		Usage:  "report TPM status and this machine's device key",
		Action: cmdDoctor,
	},
	{
		Name:   "init",
		Usage:  "create a vault with a fresh key sealed to this machine",
		Action: cmdInit,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "device name, defaults to the hostname"},
		},
	},
	{
		Name:   "join",
		Usage:  "enrol this machine using the recovery passphrase",
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
				Usage:  "print this machine's public key for enrolment elsewhere",
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
		ArgsUsage: "<project>:<KEY> [value]",
		Action:    cmdSet,
	},
	{
		Name:      "unset",
		Usage:     "delete a secret value",
		ArgsUsage: "<project>:<KEY>",
		Action:    cmdUnset,
	},
	{
		Name:      "get",
		Usage:     "print one secret value",
		ArgsUsage: "<project>:<KEY>",
		Action:    cmdGet,
	},
	{
		Name:      "edit",
		Usage:     "edit one project's secrets in your editor",
		ArgsUsage: "[project]",
		Action:    cmdEdit,
	},
	{
		Name:      "ls",
		Usage:     "list projects, or the keys in one project",
		ArgsUsage: "[project]",
		Action:    cmdLs,
	},
	{
		Name:      "print",
		Usage:     "print export lines for one project",
		ArgsUsage: "<project>",
		Flags:     []cli.Flag{shellFlag},
		Action:    cmdPrint,
	},
	{
		Name:      "env",
		Usage:     "print shell lines loading the project for the current directory",
		ArgsUsage: "[project]",
		Flags:     []cli.Flag{shellFlag},
		Action:    cmdEnv,
	},
	{
		Name:      "hook",
		Usage:     "print the shell hook that keeps your shell's secrets up to date",
		ArgsUsage: "<bash|zsh|fish>",
		Action:    cmdHook,
	},
	{
		Name:            "run",
		Usage:           "run a command with one project's secrets in its environment",
		ArgsUsage:       "<project> <command> [args...]",
		SkipFlagParsing: true,
		Action:          cmdRun,
	},
	{
		Name:   "rotate",
		Usage:  "replace the vault key and rewrap everything",
		Action: cmdRotate,
	},
	{
		Name:   "sign",
		Usage:  "stamp the vault contents with this machine's signing key",
		Action: cmdSign,
	},
	{
		Name:   "verify",
		Usage:  "check the vault signature and print the signing device",
		Action: cmdVerify,
	},
}
