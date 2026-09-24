// Package resolve maps a working directory to the vault project that applies
// to it. A .fuu file names the project explicitly, otherwise the git root's
// directory name does. Neither is code, so nothing here executes.
package resolve

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Project reports the secret section for dir, or "" when dir belongs to none.
func Project(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve: %w", err)
	}

	name, err := fromMarker(abs)
	if name != "" || err != nil {
		return name, err
	}
	return fromGitRoot(abs), nil
}

// fromMarker walks up looking for a .fuu file naming the project.
func fromMarker(dir string) (string, error) {
	for {
		path := filepath.Join(dir, ".fuu")
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			name := strings.TrimSpace(string(data))
			if name == "" {
				return "", fmt.Errorf("%s names no project", path)
			}
			return name, nil
		case !errors.Is(err, os.ErrNotExist):
			return "", fmt.Errorf("resolve: read %s: %w", path, err)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

// fromGitRoot names the project after the checkout, which is wrong whenever the
// folder name drifts from the project, so a .fuu file overrides it.
func fromGitRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return filepath.Base(dir)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
