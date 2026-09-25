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

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/vault"
)

// The buffer is TOML, so values with quotes or newlines survive the round trip.
func cmdEdit(ctx context.Context, cmd *cli.Command) error {
	path, err := vaultPath(cmd)
	if err != nil {
		return err
	}
	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	return edit(ctx, path, dk)
}

func edit(ctx context.Context, path string, dk vault.DeviceKey) error {
	f, key, err := openPinned(path, dk)
	if err != nil {
		return err
	}
	before, err := f.Secrets(key)
	if err != nil {
		return err
	}
	beforeOff, err := f.DisabledSecrets(key)
	if err != nil {
		return err
	}

	raw, err := runEditor(ctx, before, beforeOff)
	if err != nil {
		return err
	}
	edited, err := parseValues(raw)
	if err != nil {
		return err
	}
	known := maps.Clone(before)
	maps.Copy(known, beforeOff)
	off := parseCommented(raw, known)

	// An empty buffer is more likely a botched edit, so dropping every key
	// takes a confirmation.
	if len(edited) == 0 && len(known) > 0 && len(off) == 0 {
		ok, err := confirm("drop every key in this vault")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("edit: aborted, nothing written")
		}
	}

	var changed, added, dropped, disabled, enabled []string
	for _, name := range slices.Sorted(maps.Keys(edited)) {
		old, on := before[name]
		switch {
		case on && old == edited[name]:
		case on:
			changed = append(changed, name)
		default:
			if _, off := beforeOff[name]; off {
				enabled = append(enabled, name)
			} else {
				added = append(added, name)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(known)) {
		if _, ok := edited[name]; ok {
			continue
		}
		if _, ok := off[name]; ok {
			if _, wasOff := beforeOff[name]; !wasOff {
				disabled = append(disabled, name)
			}
			continue
		}
		dropped = append(dropped, name)
	}
	if len(changed)+len(added)+len(dropped)+len(disabled)+len(enabled) == 0 {
		fmt.Println("no changes")
		return nil
	}

	// No lock was held during the edit, so apply just the diff to the file as
	// it is now, a write from another shell survives.
	f, key, err = openPinned(path, dk)
	if err != nil {
		return err
	}
	for _, name := range slices.Concat(changed, added) {
		if err := f.Set(key, name, edited[name]); err != nil {
			return err
		}
	}
	for _, name := range enabled {
		if err := f.Enable(key, name, edited[name]); err != nil {
			return err
		}
	}
	for _, name := range disabled {
		if err := f.Disable(key, name); err != nil && !errors.Is(err, vault.ErrNoKey) {
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
	// Only moved values are printed, the hook announces added and removed names
	// at the next prompt.
	for _, name := range changed {
		fmt.Println("~", name)
	}
	return nil
}

// Commented out keys come along as commented lines, uncommenting one brings it back.
//
// the editor is whatever the user configured and the buffer paths come from a
// fresh temp dir under the operator's own XDG_RUNTIME_DIR.
//
//nolint:gosec // G204, G703
func runEditor(ctx context.Context, values, disabled map[string]string) ([]byte, error) {
	argv := strings.Fields(editor())
	if len(argv) == 0 {
		return nil, errors.New("edit: set $EDITOR or $VISUAL")
	}

	// Secrets in plaintext, so use the runtime dir and drop the whole
	// directory, editors leave swap files behind.
	dir := os.Getenv("XDG_RUNTIME_DIR")
	tmp, err := os.MkdirTemp(dir, "fuu-edit-")
	if err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	var buf bytes.Buffer
	fmt.Fprint(&buf, "# save and close to write the changes back\n")
	fmt.Fprint(&buf, "# comment out to disable a key, delete the line to drop it\n\n")
	if err := toml.NewEncoder(&buf).Encode(values); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}
	if len(disabled) > 0 {
		fmt.Fprint(&buf, "\n# disabled, kept in the vault\n")
		var dbuf bytes.Buffer
		if err := toml.NewEncoder(&dbuf).Encode(disabled); err != nil {
			return nil, fmt.Errorf("edit: %w", err)
		}
		for line := range strings.SplitSeq(strings.TrimSuffix(dbuf.String(), "\n"), "\n") {
			fmt.Fprintf(&buf, "# %s\n", line)
		}
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

// Same name guard as the emitters, this output is still headed for eval.
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

// Only names the vault already holds count as commented out, every other comment is prose.
func parseCommented(raw []byte, known map[string]string) map[string]struct{} {
	off := make(map[string]struct{})
	for line := range strings.SplitSeq(string(raw), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "#")
		if !ok {
			continue
		}
		name, _, ok := strings.Cut(rest, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if _, ok := known[name]; ok {
			off[name] = struct{}{}
		}
	}
	return off
}
