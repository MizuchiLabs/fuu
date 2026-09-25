package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
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
	switch {
	case cmd.Args().Len() > 1:
		value = cmd.Args().Get(1)
		fmt.Fprintln(
			os.Stderr,
			"set: a value on the command line stays in the process list and shell history, pipe it or leave it out to be prompted",
		)
	case !term.IsTerminal(int(os.Stdin.Fd())):
		// A piped value keeps newlines and leading dashes, which argv cannot do
		// since anything starting with a dash reads as a flag.
		all, err := io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("set: %w", err)
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(all), "\n"), "\r")
	default:
		if value, err = prompt("value"); err != nil {
			return err
		}
	}

	path, f, key, _, err := unlock(cmd)
	if err != nil {
		return err
	}
	if err := f.Set(key, name, value); err != nil {
		return err
	}
	return f.Save(path)
}

func cmdUnset(_ context.Context, cmd *cli.Command) error {
	name, err := secretName(cmd, "unset: want <KEY>")
	if err != nil {
		return err
	}

	path, f, key, _, err := unlock(cmd)
	if err != nil {
		return err
	}
	if err := f.Unset(key, name); err != nil {
		return err
	}
	return f.Save(path)
}

func cmdGet(_ context.Context, cmd *cli.Command) error {
	name, err := secretName(cmd, "get: want <KEY>")
	if err != nil {
		return err
	}

	_, f, key, _, err := unlock(cmd)
	if err != nil {
		return err
	}
	values, err := f.Secrets(key)
	if err != nil {
		return err
	}
	value, ok := values[name]
	if !ok {
		return fmt.Errorf("%w %q", vault.ErrNoKey, name)
	}
	// Pipes and redirects get the exact bytes. A terminal gets a newline too
	// so the prompt keeps its own line.
	if term.IsTerminal(int(os.Stdout.Fd())) && !strings.HasSuffix(value, "\n") {
		value += "\n"
	}
	fmt.Print(value)
	return nil
}

func cmdLs(_ context.Context, cmd *cli.Command) error {
	_, f, key, _, err := unlock(cmd)
	if err != nil {
		return err
	}
	values, err := f.Secrets(key)
	if err != nil {
		return err
	}
	names := slices.Sorted(maps.Keys(values))
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
