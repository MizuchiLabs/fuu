package main

import (
	"io"
	"os"
	"testing"
)

// captureOutput swaps the process stdout for a pipe while f runs. The emitters
// print there on purpose, that stream is what the shell evals.
func captureOutput(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w                      //nolint:reassign // capturing what the emitters print
	defer func() { os.Stdout = old }() //nolint:reassign // restoring after the capture

	f()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

func TestShQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "'plain'"},
		{"it's", `'it'\''s'`},
		{`back\slash`, `'back\slash'`},
		{"$(rm -rf /)", "'$(rm -rf /)'"},
		{"line\nbreak", "'line\nbreak'"},
		{"", "''"},
	}
	for _, tc := range cases {
		if got := shQuote(tc.in); got != tc.want {
			t.Errorf("shQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFishQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "'plain'"},
		{"it's", `'it\'s'`},
		{`back\slash`, `'back\\slash'`},
		{"$(rm -rf /)", "'$(rm -rf /)'"},
		{"", "''"},
	}
	for _, tc := range cases {
		if got := fishQuote(tc.in); got != tc.want {
			t.Errorf("fishQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestShellHazard(t *testing.T) {
	hazards := []string{
		"PROMPT_COMMAND", "PATH", "PS1", "IFS", "BASH_ENV", "EDITOR", "VISUAL",
		"HOME", "TMPDIR", "XDG_CONFIG_HOME", "FISH_VERSION", "GIT_SSH_COMMAND",
		"LD_PRELOAD", "LD_CUSTOM", "DYLD_INSERT_LIBRARIES", "FUU_STAMP", "FUU_LOADED",
		"NODE_OPTIONS",
	}
	for _, name := range hazards {
		if !shellHazard(name) {
			t.Errorf("shellHazard(%q) = false, want true", name)
		}
	}

	plain := []string{"API_KEY", "DATABASE_URL", "PYTHON_SDK_TOKEN", "MY_PATH", "PATHS", "LD", "FUU"}
	for _, name := range plain {
		if shellHazard(name) {
			t.Errorf("shellHazard(%q) = true, want false", name)
		}
	}
}

// TestEmitValues covers the eval boundary end to end: quoted exports for real
// secrets, a comment per hazard name, and nothing exported for either beyond
// that. A hazard name from the vault must never reach the shell, and the
// hook's own FUU_ state exports are not vault names so they stay exportable.
func TestEmitValues(t *testing.T) {
	values := map[string]string{
		"API_KEY":        "it's",
		"PROMPT_COMMAND": "evil",
		"FUU_LOADED":     "poison",
	}

	got := captureOutput(t, func() { emitValues(emitter{}, values) })
	want := "export API_KEY='it'\\''s'\n" +
		"# fuu kept FUU_LOADED out of your shell, it configures the shell itself\n" +
		"# fuu kept PROMPT_COMMAND out of your shell, it configures the shell itself\n"
	if got != want {
		t.Fatalf("emitValues = %q, want %q", got, want)
	}

	names := emitValues(emitter{}, map[string]string{"API_KEY": "x", "PATH": "evil"})
	if len(names) != 1 || names[0] != "API_KEY" {
		t.Fatalf("emitValues names = %v, want just API_KEY", names)
	}
}

func TestEmitterExportGolden(t *testing.T) {
	posix := emitter{}
	fish := emitter{fish: true}

	if got := captureOutput(t, func() { posix.export("API_KEY", "it's") }); got != "export API_KEY='it'\\''s'\n" {
		t.Errorf("posix export = %q", got)
	}
	if got := captureOutput(t, func() { fish.export("API_KEY", "it's") }); got != "set -gx API_KEY 'it\\'s'\n" {
		t.Errorf("fish export = %q", got)
	}

	// A name that is not an identifier emits nothing at all.
	if got := captureOutput(t, func() { posix.export("EVIL=1; rm", "x") }); got != "" {
		t.Errorf("bad name export = %q, want silence", got)
	}
}

func TestEmitterUnset(t *testing.T) {
	posix := emitter{}

	if got := captureOutput(t, func() { posix.unset("API_KEY") }); got != "unset API_KEY\n" {
		t.Errorf("unset = %q", got)
	}
	// Cleaning up a hazard name an older fuu exported is on purpose.
	if got := captureOutput(t, func() { posix.unset("PATH") }); got != "unset PATH\n" {
		t.Errorf("hazard unset = %q", got)
	}
	if got := captureOutput(t, func() { posix.unset("EVIL; rm") }); got != "" {
		t.Errorf("bad name unset = %q, want silence", got)
	}
}
