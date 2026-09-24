// Package atomicfile replaces files by temp and rename so a reader never sees a half written file.
package atomicfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path with data, skipping the work when the file already holds those bytes.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}

	tmp, err := os.CreateTemp(dir, ".fuu-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	// CreateTemp already made it 0600, keep that across the rename.
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
