package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/mizuchilabs/fuu/internal/vault"
)

// emitter writes shell lines for one shell dialect.
type emitter struct{ fish bool }

func emitterFor(cmd *cli.Command) (emitter, error) {
	switch shell := cmd.String("shell"); shell {
	case "posix":
		return emitter{}, nil
	case "fish":
		return emitter{fish: true}, nil
	case "":
		// fish exports FISH_VERSION and accepts POSIX export lines, so guessing
		// wrong silently corrupts values with quotes in them.
		return emitter{fish: os.Getenv("FISH_VERSION") != ""}, nil
	default:
		return emitter{}, fmt.Errorf("shell: %q is not posix or fish", shell)
	}
}

// export sets one variable in the calling shell.
func (e emitter) export(name, value string) {
	if e.fish {
		fmt.Printf("set -gx %s %s\n", name, fishQuote(value))
		return
	}
	fmt.Printf("export %s=%s\n", name, shQuote(value))
}

// unset refuses a name that is not a plain identifier, since FUU_LOADED is read
// back out of the environment and eval'd.
func (e emitter) unset(name string) {
	if !vault.ValidName(name) {
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
	if len(loaded) == 0 && os.Getenv("FUU_PROJECT") == "" && os.Getenv("FUU_STAMP") == "" {
		return
	}
	if e.fish {
		fmt.Println("set -e FUU_LOADED FUU_PROJECT FUU_STAMP")
		return
	}
	fmt.Println("unset FUU_LOADED FUU_PROJECT FUU_STAMP")
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
