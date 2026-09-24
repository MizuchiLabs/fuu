package main

import (
	"context"
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
	project, name, err := splitTarget(cmd.Args().Get(0))
	if err != nil {
		return err
	}

	value := cmd.Args().Get(1)
	if value == "" {
		// A piped value keeps newlines and leading dashes, which argv cannot do
		// since anything starting with a dash reads as a flag.
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			all, err := io.ReadAll(stdin)
			if err != nil {
				return fmt.Errorf("set: %w", err)
			}
			value = strings.TrimSuffix(strings.TrimSuffix(string(all), "\n"), "\r")
		} else if value, err = prompt("value", false); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(
			os.Stderr,
			"set: a value on the command line stays in the process list and shell history, pipe it or leave it out to be prompted",
		)
	}

	release, err := lockVault(cmd.String("vault"))
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

	if err := f.Set(key, project, name, []byte(value)); err != nil {
		return err
	}
	return signAndSave(f, cmd.String("vault"))
}

func cmdUnset(_ context.Context, cmd *cli.Command) error {
	project, name, err := splitTarget(cmd.Args().Get(0))
	if err != nil {
		return err
	}

	path := cmd.String("vault")

	release, err := lockVault(path)
	if err != nil {
		return err
	}
	defer release()

	f, err := openVerified(path)
	if err != nil {
		return err
	}
	if err := f.Unset(project, name); err != nil {
		return err
	}
	return signAndSave(f, path)
}

func cmdGet(_ context.Context, cmd *cli.Command) error {
	project, name, err := splitTarget(cmd.Args().Get(0))
	if err != nil {
		return err
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	value, err := f.Get(key, project, name)
	if err != nil {
		return err
	}
	fmt.Println(string(value))
	return nil
}

func cmdLs(_ context.Context, cmd *cli.Command) error {
	f, err := vault.Load(cmd.String("vault"))
	if err != nil {
		return err
	}

	project := cmd.Args().Get(0)
	if project == "" {
		for _, name := range slices.Sorted(maps.Keys(f.Secret)) {
			fmt.Println(name)
		}
		return nil
	}

	keys, ok := f.Secret[project]
	if !ok {
		return fmt.Errorf("vault: no such project %q", project)
	}
	for _, name := range slices.Sorted(maps.Keys(keys)) {
		fmt.Println(name)
	}
	return nil
}

func splitTarget(s string) (project, name string, err error) {
	project, name, ok := strings.Cut(s, ":")
	if !ok || project == "" || name == "" {
		return "", "", fmt.Errorf("target %q is not PROJECT:KEY", s)
	}
	return project, name, nil
}
