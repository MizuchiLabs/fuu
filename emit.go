package main

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/vault"
)

// stateNames are the hook's own variables. They are not vault names and skip
// the vault name rules, but the set is fixed so nothing else gets through.
var stateNames = map[string]struct{}{
	"FUU_LOADED": {},
	"FUU_STATE":  {},
}

// emitName reports whether name may appear on a shell line the hook evals:
// a valid vault name, or one of the hook's own state variables.
func emitName(name string) bool {
	if _, ok := stateNames[name]; ok {
		return true
	}
	return vault.ValidName(name)
}

// emitter writes shell lines for one shell dialect.
type emitter struct{ fish bool }

func emitterFor(cmd *cli.Command) (emitter, error) {
	switch shell := cmd.String("shell"); shell {
	case "posix":
		return emitter{}, nil
	case "fish":
		return emitter{fish: true}, nil
	default:
		return emitter{}, fmt.Errorf("shell: %q is not posix or fish", shell)
	}
}

// emitValues prints one export per secret, returning what actually landed in
// the shell.
func emitValues(out emitter, values map[string]string) []string {
	names := make([]string, 0, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		out.export(name, values[name])
		names = append(names, name)
	}
	return names
}

// export sets one variable in the calling shell.
func (e emitter) export(name, value string) {
	if !emitName(name) {
		return
	}
	if e.fish {
		fmt.Printf("set -gx %s %s\n", name, fishQuote(value))
		return
	}
	fmt.Printf("export %s=%s\n", name, shQuote(value))
}

// unset drops one variable from the calling shell. A name that is not a plain
// identifier never reaches the eval, FUU_LOADED is read back out of the
// environment.
func (e emitter) unset(name string) {
	if !emitName(name) {
		return
	}
	if e.fish {
		fmt.Printf("set -e %s\n", name)
		return
	}
	fmt.Printf("unset %s\n", name)
}

// unload drops everything the shell was holding. Nothing at all is printed for
// a shell that never loaded anything, so a stray cd costs no output.
func (e emitter) unload(loaded []string) {
	for _, name := range loaded {
		e.unset(name)
	}
	if len(loaded) == 0 && os.Getenv("FUU_LOADED") == "" {
		return
	}
	if e.fish {
		fmt.Println("set -e FUU_LOADED")
		return
	}
	fmt.Println("unset FUU_LOADED")
}

// dropState unsets the hook's own FUU_STATE, for the case where there is no
// vault here any more and the shell should hold no state at all.
func (e emitter) dropState() {
	if os.Getenv("FUU_STATE") == "" {
		return
	}
	if e.fish {
		fmt.Println("set -e FUU_STATE")
		return
	}
	fmt.Println("unset FUU_STATE")
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fishQuote wraps s in fish single quotes, where backslash and the quote itself
// are the only escapes. That is not POSIX quoting and getting it wrong here is
// shell injection through the hook.
func fishQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}
