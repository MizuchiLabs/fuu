//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// lockVault takes an exclusive lock on the vault, blocking until any other
// local fuu mutation of the same file finishes, so concurrent edits cannot
// silently drop each other's changes. Released by closing the lock file, the
// OS drops the lock with it.
func lockVault(vaultPath string) (func(), error) {
	path, err := lockPath(vaultPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("lock: create %s: %w", filepath.Dir(path), err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock: open %s: %w", path, err)
	}
	h := windows.Handle(f.Fd())
	var ol windows.Overlapped
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock: %s: %w", path, err)
	}
	return func() { _ = f.Close() }, nil
}
