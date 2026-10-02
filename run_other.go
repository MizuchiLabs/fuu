//go:build !unix

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// There is no exec to replace fuu with here, so the child's exit code is
// passed on by hand.
func runChild(ctx context.Context, args, env []string) error {
	// The console hands ctrl-c to the child as well, cancelling would kill it
	// before it can clean up.
	//nolint:gosec // G204 is the whole purpose of run, it executes the caller's own command.
	child := exec.CommandContext(context.WithoutCancel(ctx), args[0], args[1:]...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = env
	err := child.Run()
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		os.Exit(exit.ExitCode())
	}
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
