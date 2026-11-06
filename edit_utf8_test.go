package main

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
)

// The buffer edit writes must parse back to the values it was given, because
// a stored secret that is not valid UTF-8 is still a secret.
func TestEditBufferRoundTripsInvalidUTF8(t *testing.T) {
	values := map[string]string{"BLOB": "\xff\xfe binary"}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(values); err != nil {
		t.Fatal(err)
	}
	got, err := parseValues(buf.Bytes())
	if err != nil {
		t.Fatalf("buffer edit writes does not parse back: %v\nbuffer: %q", err, buf.Bytes())
	}
	if got["BLOB"] != values["BLOB"] {
		t.Fatalf("BLOB = %q, want %q", got["BLOB"], values["BLOB"])
	}
}
