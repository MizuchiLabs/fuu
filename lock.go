package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// The lock file lives in the config dir rather than next to the vault, which
// is usually a synced git working tree that must stay clean.
func lockPath(vaultPath string) (string, error) {
	digest, err := absDigest(vaultPath)
	if err != nil {
		return "", fmt.Errorf("lock: %w", err)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("lock: %w", err)
	}
	return filepath.Join(dir, "fuu", "locks", digest+".lock"), nil
}

func absDigest(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Symlinked checkouts are one vault, so hash the resolved path. The
	// directory resolves even when the vault itself is still being created.
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		abs = filepath.Join(resolved, filepath.Base(abs))
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:]), nil
}
