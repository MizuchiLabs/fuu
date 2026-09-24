package vault

import "testing"

// FuzzParse feeds hostile bytes to the vault parser, the one place an attacker
// controlled fuu.toml enters the tool. A malformed file must fail as an error
// that carries no vault, never a panic. A file that does parse must stay self
// consistent when its signed form and identity are derived from it.
func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not toml at all"))
	f.Add([]byte("version = 2\nvaultid = \"v_seed\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		vf, err := Parse(data, "fuzz.toml")
		if err != nil {
			if vf != nil {
				t.Fatal("Parse returned a vault alongside an error")
			}
			return
		}
		_ = vf.Canonical()
		_ = vf.Digest()
		for pub, d := range vf.Device {
			if pub != d.Pub {
				t.Fatalf("device %q carries key %q", pub, d.Pub)
			}
		}
	})
}
