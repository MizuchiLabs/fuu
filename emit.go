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

// The hook's own variables, the only names allowed to skip the vault name rules.
var stateNames = map[string]struct{}{
	"FUU_LOADED": {},
	"FUU_STATE":  {},
}

func emitName(name string) bool {
	if _, ok := stateNames[name]; ok {
		return true
	}
	return vault.ValidName(name)
}

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

func emitValues(out emitter, values map[string]string) []string {
	names := make([]string, 0, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		out.export(name, values[name])
		names = append(names, name)
	}
	return names
}

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

// A name that is not a plain identifier never reaches the eval.
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

// Prints nothing at all when nothing was loaded, so a stray cd costs no output.
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

// Not POSIX quoting, getting this wrong is shell injection through the hook.
func fishQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}
