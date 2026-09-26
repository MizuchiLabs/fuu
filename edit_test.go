package main

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mizuchilabs/fuu/internal/vault"
)

func scriptEditor(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "editor")
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write editor script: %v", err)
	}
	return path
}

// Clears VISUAL so EDITOR is the one that counts.
func useEditor(t *testing.T, body string) {
	t.Helper()
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", scriptEditor(t, body))
}

// A vault with API_KEY and DATABASE_URL, pinned the way a fuu trust would.
func pinnedVault(t *testing.T) (path string, key []byte, dk *softKey) {
	t.Helper()
	isolatePins(t)
	path = filepath.Join(t.TempDir(), ".fuu.toml")
	key, dk, id := writeVault(t, path)

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for name, value := range map[string]string{"API_KEY": "s3cret", "DATABASE_URL": "postgres://x"} {
		if err := f.Set(key, name, value); err != nil {
			t.Fatalf("Set %s: %v", name, err)
		}
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	dir, err := vaultDir(path)
	if err != nil {
		t.Fatalf("vaultDir: %v", err)
	}
	if err := savePins(map[string]string{dir: id}); err != nil {
		t.Fatalf("savePins: %v", err)
	}
	return path, key, dk
}

// Only whole hash lines naming a known key count as commented out.
func TestParseCommented(t *testing.T) {
	raw := []byte(`# save and close to write the changes back
API_KEY = "new"

# API_KEY = "old"
#TODO = "not a vault key"
# just prose, no assignment
# DATABASE_URL=x
`)
	known := map[string]string{"API_KEY": "", "DATABASE_URL": ""}
	off := parseCommented(raw, known)
	want := map[string]struct{}{"API_KEY": {}, "DATABASE_URL": {}}
	if !maps.Equal(off, want) {
		t.Fatalf("parseCommented = %v, want %v", off, want)
	}
}

// A commented line keeps its value in the vault and out of the shell, uncommenting brings it back.
func TestEditCommentsOutAndBack(t *testing.T) {
	path, key, dk := pinnedVault(t)

	useEditor(t, `sed -i 's/^API_KEY =/# API_KEY =/' "$1"`)
	if err := edit(t.Context(), path, dk); err != nil {
		t.Fatalf("edit: %v", err)
	}

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load after commenting out: %v", err)
	}
	if f.Version != vault.Version {
		t.Fatalf("version = %d, want %d", f.Version, vault.Version)
	}
	if !strings.Contains(string(mustRead(t, path)), "[disabled]") {
		t.Fatal("the file carries no [disabled] table")
	}
	values, err := f.Secrets(key)
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	if _, ok := values["API_KEY"]; ok {
		t.Fatal("a commented out key still loads into the shell")
	}
	if values["DATABASE_URL"] != "postgres://x" {
		t.Fatalf("untouched keys moved: %v", values)
	}
	off, err := f.DisabledSecrets(key)
	if err != nil {
		t.Fatalf("DisabledSecrets: %v", err)
	}
	if off["API_KEY"] != "s3cret" {
		t.Fatalf("commented out entries = %v, want API_KEY with its value", off)
	}

	useEditor(t, `sed -i 's/^# API_KEY =/API_KEY =/' "$1"`)
	if err := edit(t.Context(), path, dk); err != nil {
		t.Fatalf("edit after uncommenting: %v", err)
	}

	f, err = vault.Load(path)
	if err != nil {
		t.Fatalf("Load after uncommenting: %v", err)
	}
	if f.Version != vault.Version {
		t.Fatalf("version = %d, want %d", f.Version, vault.Version)
	}
	if values, err = f.Secrets(key); err != nil || values["API_KEY"] != "s3cret" {
		t.Fatalf("values after uncommenting = %v, %v", values, err)
	}
	if off, err = f.DisabledSecrets(key); err != nil || len(off) != 0 {
		t.Fatalf("commented out entries after uncommenting = %v, %v", off, err)
	}
}

// The line gone from the buffer is the key gone from the vault.
func TestEditDropsCommentedKey(t *testing.T) {
	path, key, dk := pinnedVault(t)

	f, err := vault.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := f.Disable(key, "API_KEY"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	useEditor(t, `sed -i '/^# API_KEY/d' "$1"`)
	if err := edit(t.Context(), path, dk); err != nil {
		t.Fatalf("edit: %v", err)
	}

	f, err = vault.Load(path)
	if err != nil {
		t.Fatalf("Load after dropping: %v", err)
	}
	if values, err := f.Secrets(key); err != nil || values["DATABASE_URL"] != "postgres://x" {
		t.Fatalf("values after dropping = %v, %v", values, err)
	}
	if off, err := f.DisabledSecrets(key); err != nil || len(off) != 0 {
		t.Fatalf("commented out entries after dropping = %v, %v", off, err)
	}
}
