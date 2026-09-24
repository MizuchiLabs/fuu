package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"
	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/resolve"
	"github.com/mizuchilabs/fuu/internal/vault"
)

// cmdEdit opens one project in $EDITOR and writes back only what changed. The
// buffer is TOML so values with quotes or newlines survive a round trip exactly.
func cmdEdit(ctx context.Context, cmd *cli.Command) error {
	project := cmd.Args().Get(0)
	if project == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("edit: %w", err)
		}
		if project, err = resolve.Project(wd); err != nil {
			return err
		}
	}
	if project == "" {
		return errors.New("edit: no project here, name one")
	}
	if !singleLineName(project) {
		return fmt.Errorf("edit: project name %q cannot go into the edit buffer safely", project)
	}

	path := cmd.String("vault")

	release, err := lockVault(path)
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

	before, err := f.Project(key, project)
	if errors.Is(err, vault.ErrNoProject) {
		before = map[string]string{}
	} else if err != nil {
		return err
	}

	raw, err := runEditor(ctx, project, before)
	if err != nil {
		return err
	}
	edited, err := parseValues(raw)
	if err != nil {
		return err
	}
	// An empty buffer is far more likely a botched edit than a real intention,
	// so dropping every key takes one extra word instead of being refused.
	if len(edited) == 0 && len(before) > 0 {
		ok, err := confirm(fmt.Sprintf("drop every key in %q", project))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("edit: aborted, nothing written")
		}
	}

	fresh, err := vault.Load(path)
	if err != nil {
		return err
	}
	if err := verifyPinned(path, fresh); err != nil {
		return err
	}

	var wrote, dropped []string
	for _, name := range slices.Sorted(maps.Keys(edited)) {
		if old, ok := before[name]; ok && old == edited[name] {
			continue
		}
		if err := fresh.Set(key, project, name, []byte(edited[name])); err != nil {
			return err
		}
		wrote = append(wrote, name)
	}
	for _, name := range slices.Sorted(maps.Keys(before)) {
		if _, ok := edited[name]; ok {
			continue
		}
		if err := fresh.Unset(project, name); err != nil {
			return err
		}
		dropped = append(dropped, name)
	}

	if len(wrote) == 0 && len(dropped) == 0 {
		fmt.Println("no changes")
		return nil
	}
	if err := signAndSave(fresh, path); err != nil {
		return err
	}
	for _, name := range wrote {
		fmt.Println("~", name)
	}
	for _, name := range dropped {
		fmt.Println("-", name)
	}
	return nil
}

// runEditor shows values as TOML in the user's editor and returns the result.
func runEditor(ctx context.Context, project string, values map[string]string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "fuu-editbuf-")
	if err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}
	// The buffer is plaintext, so the whole directory goes rather than one file.
	// Editors leave swap and backup copies next to it.
	defer func() { _ = os.RemoveAll(dir) }()

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# %s\n# save and close to write the changes back, delete a line to drop a key\n\n", project)
	if err := toml.NewEncoder(&buf).Encode(values); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}

	path := filepath.Join(dir, "secrets.toml")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}

	argv := strings.Fields(editor())
	if len(argv) == 0 {
		return nil, errors.New("edit: set $EDITOR or $VISUAL")
	}
	//nolint:gosec // the editor is whatever the user configured.
	child := exec.CommandContext(ctx, argv[0], append(argv[1:], path)...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Run(); err != nil {
		return nil, fmt.Errorf("edit: run editor: %w", err)
	}
	return os.ReadFile(path)
}

func editor() string {
	if e := os.Getenv("VISUAL"); e != "" {
		return e
	}
	return os.Getenv("EDITOR")
}

// parseValues reads back what runEditor wrote, with the same name guard the
// emitters use since this is still headed for eval.
func parseValues(raw []byte) (map[string]string, error) {
	values := map[string]string{}
	if err := toml.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}
	for name := range values {
		if !vault.ValidName(name) {
			return nil, fmt.Errorf("%w %q", vault.ErrBadName, name)
		}
		if strings.ContainsRune(values[name], 0) {
			return nil, fmt.Errorf("edit: %q has a NUL byte in its value, the shell would drop it", name)
		}
		if shellHazard(name) {
			fmt.Fprintf(os.Stderr, "edit: %q configures the shell itself, the hook keeps it out of your shell\n", name)
		}
	}
	return values, nil
}

// The name sits in the buffer's comment header, so anything TOML reads as a
// newline there would let the name carry its own lines past the comment and
// pre-seed keys into the buffer.
func singleLineName(name string) bool {
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return name != ""
}
