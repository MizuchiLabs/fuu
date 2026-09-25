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
	"time"

	"github.com/BurntSushi/toml"
	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/vault"
)

// cmdEdit opens this vault's secrets in $EDITOR and writes back only what
// changed. The buffer is TOML so values with quotes or newlines survive a
// round trip exactly.
func cmdEdit(ctx context.Context, cmd *cli.Command) error {
	sweepEditBufs()

	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}

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

	before, err := f.Values(key)
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
		if ok && old == edited[name] {
			continue
		}
		if err := f.Set(key, name, []byte(edited[name])); err != nil {
			return err
		}
		if ok {
			changed = append(changed, name)
		} else {
			added = append(added, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(before)) {
		if _, ok := edited[name]; ok {
			continue
		}
		if err := f.Unset(key, name); err != nil {
			return err
		}
		dropped = append(dropped, name)
	}

	if len(changed) == 0 && len(added) == 0 && len(dropped) == 0 {
		fmt.Println("no changes")
		return nil
	}
	if err := signAndSave(f, key, path); err != nil {
		return err
	}
	// Names entering or leaving the shell belong to the hook, which names
	// them at the next prompt. Only a moved value has no other speaker.
	for _, name := range changed {
		fmt.Println("~", name)
	}
	return nil
}

// editBufMaxAge is how long a leftover edit buffer may sit before the next
// edit sweeps it. A younger buffer may belong to an editor still open in
// another window, and deleting one out from under it loses that edit, so only
// buffers clearly abandoned by a force killed editor are touched.
const editBufMaxAge = 24 * time.Hour

// sweepEditBufs removes buffers left behind by a force killed editor, they
// hold the vault's secrets in plaintext. A buffer younger than editBufMaxAge
// is left alone, it may belong to an editor running right now.
func sweepEditBufs() {
	tmp := os.TempDir()
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "fuu-editbuf-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) < editBufMaxAge {
			continue
		}
		_ = os.RemoveAll(filepath.Join(tmp, entry.Name()))
	}
}

// runEditor shows the values as TOML in the user's editor and returns the result.
func runEditor(ctx context.Context, values map[string]string) ([]byte, error) {
	argv := strings.Fields(editor())
	if len(argv) == 0 {
		return nil, errors.New("edit: set $EDITOR or $VISUAL")
	}

	dir, err := os.MkdirTemp("", "fuu-editbuf-")
	if err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}
	// The buffer is plaintext, so the whole directory goes rather than one file.
	// Editors leave swap and backup copies next to it.
	defer func() { _ = os.RemoveAll(dir) }()

	var buf bytes.Buffer
	fmt.Fprint(&buf, "# save and close to write the changes back, delete a line to drop a key\n\n")
	if err := toml.NewEncoder(&buf).Encode(values); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}

	path := filepath.Join(dir, "secrets.toml")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
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
