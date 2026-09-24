package resolve

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestMarkerWinsOverGitRoot(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "shop (2)")
	write(t, filepath.Join(repo, ".git", "HEAD"), "ref: refs/heads/main")
	write(t, filepath.Join(repo, ".fuu"), "shop\n")

	got, err := Project(filepath.Join(repo, "cmd"))
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if got != "shop" {
		t.Fatalf("Project = %q, want %q", got, "shop")
	}
}

func TestMarkerInSubdirOverridesParent(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "web")
	write(t, filepath.Join(repo, ".git", "HEAD"), "ref: refs/heads/main")
	write(t, filepath.Join(repo, ".fuu"), "web")
	write(t, filepath.Join(repo, "packages", "billing", ".fuu"), "billing")

	got, err := Project(filepath.Join(repo, "packages", "billing", "internal"))
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if got != "billing" {
		t.Fatalf("Project = %q, want %q", got, "billing")
	}
}

func TestGitRootNamesProject(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "worker")
	write(t, filepath.Join(repo, ".git", "HEAD"), "ref: refs/heads/main")

	for _, dir := range []string{repo, filepath.Join(repo, "internal", "db")} {
		got, err := Project(dir)
		if err != nil {
			t.Fatalf("Project(%s): %v", dir, err)
		}
		if got != "worker" {
			t.Fatalf("Project(%s) = %q, want %q", dir, got, "worker")
		}
	}
}

func TestNestedSameNameIsNotResolved(t *testing.T) {
	root := t.TempDir()
	outer := filepath.Join(root, "platform")
	write(t, filepath.Join(outer, ".git", "HEAD"), "ref: refs/heads/main")
	inner := filepath.Join(outer, "services")

	got, err := Project(inner)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if got != "platform" {
		t.Fatalf("Project = %q, want %q, the nested folder must not name the project", got, "platform")
	}
}

func TestNoProjectAnywhere(t *testing.T) {
	got, err := Project(t.TempDir())
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if got != "" {
		t.Fatalf("Project = %q, want no project", got)
	}
}

func TestEmptyMarkerIsAnError(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, ".fuu"), "  \n")

	if _, err := Project(root); err == nil {
		t.Fatal("Project accepted a .fuu that names nothing")
	}
}

func TestMarkerIsFoundFromNestedWorkingDir(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "checkout")
	write(t, filepath.Join(repo, ".fuu"), "shop")

	got, err := Project(filepath.Join(repo, "packages", "ui", "internal"))
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if got != "shop" {
		t.Fatalf("Project = %q, want %q", got, "shop")
	}
}
