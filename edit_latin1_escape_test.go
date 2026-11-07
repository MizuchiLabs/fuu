package main

import "testing"

// A \u escape is a Unicode code point, so \u00e9 is é in UTF-8 whatever else
// is in the buffer. A binary value elsewhere in the buffer must not change it.
func TestEditLatin1BufferKeepsUnicodeEscape(t *testing.T) {
	raw := []byte("BLOB = \"\xff\xfe\"\nESC = \"\\u00e9\"\n")
	got, err := parseValues(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got["ESC"] != "é" {
		t.Fatalf("ESC = %q, want %q", got["ESC"], "é")
	}
}
