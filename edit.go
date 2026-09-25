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

	"github.com/BurntSushi/toml"
	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/vault"
)

// cmdEdit opens this vault's secrets in $EDITOR and writes back only what
// changed. The buffer is TOML so values with quotes or newlines survive a
// round trip exactly.
func cmdEdit(ctx context.Context, cmd *cli.Command) error {
	_, f, key, _, err := unlock(cmd)
	if err != nil {
		return err
	}
	before, err := f.Secrets(key)
	if err != nil {
		return err
	}

	raw, err := runEditor(ctx, before)
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
		ok, err := confirm("drop every key in this vault")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("edit: aborted, nothing written")
		}
	}

	var changed, added, dropped []string
	for _, name := range slices.Sorted(maps.Keys(edited)) {
		old, ok := before[name]
		switch {
		case ok && old == edited[name]:
		case ok:
			changed = append(changed, name)
		default:
			added = append(added, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(before)) {
		if _, ok := edited[name]; !ok {
			dropped = append(dropped, name)
		}
	}
	if len(changed) == 0 && len(added) == 0 && len(dropped) == 0 {
		fmt.Println("no changes")
		return nil
	}

	// The editor ran outside any lock, so re-open the vault and apply only the
	// diff to whatever is on disk now. A write from another shell during the
	// edit survives, only the names this edit actually touched are moved.
	path, f, key, _, err := unlock(cmd)
	if err != nil {
		return err
	}
	for _, name := range changed {
		if err := f.Set(key, name, edited[name]); err != nil {
			return err
		}
	}
	for _, name := range added {
		if err := f.Set(key, name, edited[name]); err != nil {
			return err
		}
	}
	for _, name := range dropped {
		if err := f.Unset(key, name); err != nil && !errors.Is(err, vault.ErrNoKey) {
			return err
		}
	}
	if err := f.Save(path); err != nil {
		return err
	}
	// Names entering or leaving the shell belong to the hook, which names
	// them at the next prompt. Only a moved value has no other speaker.
	for _, name := range changed {
		fmt.Println("~", name)
	}
	return nil
}

// runEditor shows the values as TOML in the user's editor and returns the result.
//
//nolint:gosec // G204: the editor is whatever the user configured. G703: the buffer paths come from a fresh temp dir under the operator's own XDG_RUNTIME_DIR, not from anything a repo supplies.
func runEditor(ctx context.Context, values map[string]string) ([]byte, error) {
	argv := strings.Fields(editor())
	if len(argv) == 0 {
		return nil, errors.New("edit: set $EDITOR or $VISUAL")
	}

	// The buffer holds the vault's secrets in plaintext, so it goes on the
	// per-user runtime dir where there is one, and the whole directory is
	// dropped rather than one file: editors leave swap and backup copies next
	// to it.
	dir := os.Getenv("XDG_RUNTIME_DIR")
	tmp, err := os.MkdirTemp(dir, "fuu-edit-")
	if err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	var buf bytes.Buffer
	fmt.Fprint(&buf, "# save and close to write the changes back, delete a line to drop a key\n\n")
	if err := toml.NewEncoder(&buf).Encode(values); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}

	path := filepath.Join(tmp, "secrets.toml")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}

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
	}
	return values, nil
}
