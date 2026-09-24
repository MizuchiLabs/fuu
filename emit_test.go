package main

import (
	"io"
	"os"
	"strings"
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

// unquoteSh reads back a string shQuote produced: single quoted segments
// joined by an escaped quote, the grammar POSIX shells parse.
func unquoteSh(t *testing.T, q string) string {
	t.Helper()
	var b strings.Builder
	for q != "" {
		rest, ok := strings.CutPrefix(q, "'")
		if !ok {
			t.Fatalf("shQuote output %q does not open with a quote", q)
		}
		end := strings.IndexByte(rest, '\'')
		if end < 0 {
			t.Fatalf("shQuote output %q has an unterminated quote", q)
		}
		b.WriteString(rest[:end])
		q = rest[end+1:]
		if q == "" {
			break
		}
		escaped, ok := strings.CutPrefix(q, `\'`)
		if !ok {
			t.Fatalf("shQuote output %q has text outside quotes", q)
		}
		b.WriteByte('\'')
		q = escaped
	}
	return b.String()
}

// unquoteFish reads back a string fishQuote produced: one single quoted run
// where backslash escapes only the backslash and the quote itself.
func unquoteFish(t *testing.T, q string) string {
	t.Helper()
	if len(q) < 2 || q[0] != '\'' || q[len(q)-1] != '\'' {
		t.Fatalf("fishQuote output %q is not single quoted", q)
	}
	body := q[1 : len(q)-1]
	var b strings.Builder
	for i := 0; i < len(body); {
		switch body[i] {
		case '\'':
			t.Fatalf("fishQuote output %q has an unescaped quote", q)
		case '\\':
			if i+1 == len(body) {
				t.Fatalf("fishQuote output %q ends mid escape", q)
			}
			if body[i+1] != '\\' && body[i+1] != '\'' {
				t.Fatalf("fishQuote output %q escapes nothing else in fish", q)
			}
			b.WriteByte(body[i+1])
			i += 2
		default:
			b.WriteByte(body[i])
			i++
		}
	}
	return b.String()
}

// quoteCases are the shapes quoting has to survive: quotes, newlines,
// backslashes and shell metacharacters.
var quoteCases = []string{
	"plain",
	"it's",
	"line\nbreak",
	`back\slash`,
	`both ' and \ plus` + "\n" + `a break`,
	`'\''`,
	`$(rm -rf /) "d" $var`,
	"",
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

func TestShQuoteRoundTrip(t *testing.T) {
	for _, in := range quoteCases {
		if got := unquoteSh(t, shQuote(in)); got != in {
			t.Errorf("posix round trip of %q = %q", in, got)
		}
	}
}

func TestFishQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "'plain'"},
		{"it's", `'it\'s'`},
		{`back\slash`, `'back\\slash'`},
		{"$(rm -rf /)", "'$(rm -rf /)'"},
		{"line\nbreak", "'line\nbreak'"},
		{"", "''"},
	}
	for _, tc := range cases {
		if got := fishQuote(tc.in); got != tc.want {
			t.Errorf("fishQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFishQuoteRoundTrip(t *testing.T) {
	for _, in := range quoteCases {
		if got := unquoteFish(t, fishQuote(in)); got != in {
			t.Errorf("fish round trip of %q = %q", in, got)
		}
	}
}

func TestShellHazard(t *testing.T) {
	hazards := []string{
		"PROMPT_COMMAND", "PATH", "PS1", "IFS", "BASH_ENV", "EDITOR", "VISUAL",
		"HOME", "TMPDIR", "XDG_CONFIG_HOME", "FISH_VERSION", "GIT_SSH_COMMAND",
		"LD_PRELOAD", "LD_CUSTOM", "DYLD_INSERT_LIBRARIES", "FUU_STAMP", "FUU_LOADED",
		"NODE_OPTIONS", "MODULE_PATH", "FISH_FUNCTION_PATH", "FISH_USER_PATHS",
		"PROMPT", "RPROMPT",
		// zsh and fish tie a lower case alias to the real thing, so the match
		// has to survive the case a secret was actually named in.
		"path", "fpath", "cdpath", "ld_preload", "Ld_Preload", "fuu_stamp",
		"prompt", "fish_function_path", "Editor",
	}
	for _, name := range hazards {
		if !shellHazard(name) {
			t.Errorf("shellHazard(%q) = false, want true", name)
		}
	}

	plain := []string{
		"API_KEY",
		"DATABASE_URL",
		"PYTHON_SDK_TOKEN",
		"MY_PATH",
		"PATHS",
		"LD",
		"FUU",
		"MYPATH",
		"fpath2",
	}
	for _, name := range plain {
		if shellHazard(name) {
			t.Errorf("shellHazard(%q) = true, want false", name)
		}
	}
}

// TestHazardsFiltered is the guarantee that both exits from the vault filter
// the same way: what the hook evals and what fuu run hands to a child. A vault
// key named PATH, LD_PRELOAD, DYLD_INSERT_LIBRARIES or PROMPT_COMMAND must
// reach neither, only its comment and a skipped pair, while a plain key with a
// quote in its value survives both quoted correctly.
func TestHazardsFiltered(t *testing.T) {
	values := map[string]string{
		"API_KEY":               "it's",
		"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
		"FUU_LOADED":            "poison",
		"LD_PRELOAD":            "/tmp/evil.so",
		"PATH":                  "/tmp/evil",
		"PROMPT_COMMAND":        "evil",
	}

	var names []string
	got := captureOutput(t, func() { names = emitValues(emitter{}, values) })
	want := "export API_KEY='it'\\''s'\n" +
		"# fuu kept DYLD_INSERT_LIBRARIES out of your shell, it configures the shell itself\n" +
		"# fuu kept FUU_LOADED out of your shell, it configures the shell itself\n" +
		"# fuu kept LD_PRELOAD out of your shell, it configures the shell itself\n" +
		"# fuu kept PATH out of your shell, it configures the shell itself\n" +
		"# fuu kept PROMPT_COMMAND out of your shell, it configures the shell itself\n"
	if got != want {
		t.Errorf("emitValues = %q, want %q", got, want)
	}
	if len(names) != 1 || names[0] != "API_KEY" {
		t.Errorf("emitValues names = %v, want just API_KEY", names)
	}

	pairs := envPairs(values)
	if len(pairs) != 1 || pairs[0] != "API_KEY=it's" {
		t.Errorf("envPairs = %v, want just API_KEY=it's", pairs)
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

	// The hook's own FUU_ state is not a vault name, so it exports directly.
	if got := captureOutput(t, func() { posix.export("FUU_STAMP", "abc") }); got != "export FUU_STAMP='abc'\n" {
		t.Errorf("state export = %q", got)
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

// TestUnload pins what the hook sources when there is no vault to load: every
// name the shell still holds, then the hook's own state, and no output at all
// for a shell that never loaded anything.
func TestUnload(t *testing.T) {
	posix := emitter{}
	fish := emitter{fish: true}

	t.Setenv("FUU_STAMP", "abc123")
	got := captureOutput(t, func() { posix.unload([]string{"API_KEY", "TOKEN"}) })
	want := "unset API_KEY\nunset TOKEN\nunset FUU_LOADED FUU_STAMP\n"
	if got != want {
		t.Errorf("posix unload = %q, want %q", got, want)
	}

	t.Setenv("FUU_STAMP", "abc123")
	got = captureOutput(t, func() { fish.unload([]string{"API_KEY"}) })
	want = "set -e API_KEY\nset -e FUU_LOADED FUU_STAMP\n"
	if got != want {
		t.Errorf("fish unload = %q, want %q", got, want)
	}

	t.Setenv("FUU_STAMP", "")
	got = captureOutput(t, func() { posix.unload(nil) })
	if got != "" {
		t.Errorf("empty unload = %q, want silence", got)
	}

	t.Setenv("FUU_STAMP", "abc123")
	got = captureOutput(t, func() { posix.unload(nil) })
	want = "unset FUU_LOADED FUU_STAMP\n"
	if got != want {
		t.Errorf("state only unload = %q, want %q", got, want)
	}
}
