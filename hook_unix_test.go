//go:build unix

package main

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A pipe parked where a vault should be would hold a read forever. The hook
// never opens it, not in a folder nobody trusted and not in a trusted one.
func TestHookNeverBlocksOnPipe(t *testing.T) {
	isolatePins(t)
	path := filepath.Join(t.TempDir(), vaultFile)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}

	hook := func() error {
		done := make(chan error, 1)
		go func() {
			if _, err := vaultState(path); err != nil {
				done <- err
				return
			}
			_, _, err := loadTrusted(path)
			done <- err
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("the hook blocked on a pipe")
			return nil
		}
	}

	if err := hook(); !errors.Is(err, errUntrusted) {
		t.Fatalf("untrusted folder with a pipe = %v, want errUntrusted", err)
	}
	pinFolder(t, path, "some-vault-id")
	if err := hook(); err == nil {
		t.Fatal("a pipe was read as the vault of a trusted folder")
	}
}
