//go:build unix

package main

import (
	"context"
	"fmt"
	"io/fs"
	"os/exec"
	"syscall"
)

// The child replaces fuu, so its exit code and its signals are its own.
func runChild(_ context.Context, args, env []string) error {
	bin, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	if err := syscall.Exec(bin, args, env); err != nil {
		return &fs.PathError{Op: "exec", Path: bin, Err: err}
	}
	return nil
}
