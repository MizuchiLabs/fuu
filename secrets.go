package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/mizuchilabs/fuu/internal/vault"
)

func cmdSet(_ context.Context, cmd *cli.Command) error {
	name, err := secretName(cmd, "set: want <KEY> [value]")
	if err != nil {
		return err
	}

	var value string
	if cmd.Args().Len() > 1 {
		value = cmd.Args().Get(1)
		fmt.Fprintln(
			os.Stderr,
			"set: a value on the command line stays in the process list and shell history, pipe it or leave it out to be prompted",
		)
	} else if !term.IsTerminal(int(os.Stdin.Fd())) {
		// A piped value keeps newlines and leading dashes, which argv cannot do
		// since anything starting with a dash reads as a flag.
		all, err := io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("set: %w", err)
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(all), "\n"), "\r")
	} else if value, err = prompt("value", false); err != nil {
		return err
	}
	if strings.ContainsRune(value, 0) {
		return errors.New("set: values cannot contain NUL bytes, the shell would drop them")
	}
	if shellHazard(name) {
		fmt.Fprintf(os.Stderr, "set: %q configures the shell itself, the hook keeps it out of your shell\n", name)
	}

	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}
	release, err := lockVault(path)
	if err != nil {
		return err
	}
	defer release()

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	if err := f.Set(key, name, []byte(value)); err != nil {
		return err
	}
	return signAndSave(f, key, path)
}

func cmdUnset(_ context.Context, cmd *cli.Command) error {
	name, err := secretName(cmd, "unset: want <KEY>")
	if err != nil {
		return err
	}

	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}
	release, err := lockVault(path)
	if err != nil {
		return err
	}
	defer release()

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	if err := f.Unset(key, name); err != nil {
		return err
	}
	return signAndSave(f, key, path)
}

func cmdGet(_ context.Context, cmd *cli.Command) error {
	name, err := secretName(cmd, "get: want <KEY>")
	if err != nil {
		return err
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	value, err := f.Get(key, name)
	if err != nil {
		return err
	}
	out := string(value)
	// Pipes and redirects get the exact bytes. A terminal gets a newline too
	// so the prompt keeps its own line.
	if term.IsTerminal(int(os.Stdout.Fd())) && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	fmt.Print(out)
	clear(value)
	return nil
}

func cmdLs(_ context.Context, cmd *cli.Command) error {
	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	names, err := f.Names(key)
	if err != nil {
		return err
	}
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

// secretName takes the <KEY> argument and checks it before the TPM or the
// vault is touched.
func secretName(cmd *cli.Command, usage string) (string, error) {
	name := cmd.Args().Get(0)
	if name == "" {
		return "", errors.New(usage)
	}
	if !vault.ValidName(name) {
		return "", fmt.Errorf("%w %q", vault.ErrBadName, name)
	}
	return name, nil
}
