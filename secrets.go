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
)

func cmdSet(_ context.Context, cmd *cli.Command) error {
	project, name, err := splitTarget(cmd.Args().Get(0))
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
	out := string(value)
	// Pipes and redirects get the exact bytes. A terminal gets a newline too
	// so the prompt keeps its own line.
	if term.IsTerminal(int(os.Stdout.Fd())) && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	fmt.Print(out)
	return nil
}

func cmdLs(_ context.Context, cmd *cli.Command) error {
	f, err := openVerified(cmd.String("vault"))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"ls: no vault at %s, run fuu init or point --vault or FUU_VAULT at yours",
			cmd.String("vault"),
		)
	}
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
