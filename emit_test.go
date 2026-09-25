package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// Swaps stdout for a pipe, that stream is what the shell evals.
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

	// The hook's own state is not a vault name, so it exports directly.
	if got := captureOutput(t, func() { posix.export("FUU_STATE", "abc") }); got != "export FUU_STATE='abc'\n" {
		t.Errorf("state export = %q", got)
	}
}

func TestEmitterUnset(t *testing.T) {
	posix := emitter{}

	if got := captureOutput(t, func() { posix.unset("API_KEY") }); got != "unset API_KEY\n" {
		t.Errorf("unset = %q", got)
	}
	// A name that configures the shell never reaches the eval, not even for cleanup.
	for _, name := range []string{"PATH", "EVIL; rm"} {
		if got := captureOutput(t, func() { posix.unset(name) }); got != "" {
			t.Errorf("unset(%q) = %q, want silence", name, got)
		}
	}
	if got := captureOutput(t, func() { posix.unset("FUU_STATE") }); got != "unset FUU_STATE\n" {
		t.Errorf("state unset = %q", got)
	}
}

// Nothing at all is sourced for a shell that never loaded anything.
func TestUnload(t *testing.T) {
	posix := emitter{}
	fish := emitter{fish: true}

	t.Setenv("FUU_LOADED", "API_KEY TOKEN")
	got := captureOutput(t, func() { posix.unload([]string{"API_KEY", "TOKEN"}) })
	want := "unset API_KEY\nunset TOKEN\nunset FUU_LOADED\n"
	if got != want {
		t.Errorf("posix unload = %q, want %q", got, want)
	}

	t.Setenv("FUU_LOADED", "API_KEY")
	got = captureOutput(t, func() { fish.unload([]string{"API_KEY"}) })
	want = "set -e API_KEY\nset -e FUU_LOADED\n"
	if got != want {
		t.Errorf("fish unload = %q, want %q", got, want)
	}

	t.Setenv("FUU_LOADED", "")
	got = captureOutput(t, func() { posix.unload(nil) })
	if got != "" {
		t.Errorf("empty unload = %q, want silence", got)
	}

	t.Setenv("FUU_LOADED", "API_KEY")
	got = captureOutput(t, func() { posix.unload(nil) })
	want = "unset FUU_LOADED\n"
	if got != want {
		t.Errorf("state only unload = %q, want %q", got, want)
	}
}
