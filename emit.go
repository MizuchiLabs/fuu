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

// shellHazards are variable names that reach past a plain secret once the hook
// evals the export line: they run code or take the shell over. The list is the
// price of eval integration. A key named like one of these stays in the vault,
// usable through fuu run and fuu get, and never reaches the shell.
var shellHazards = map[string]struct{}{
	"BASHOPTS":              {},
	"BASH_COMPAT":           {},
	"BASH_ENV":              {},
	"BASH_XTRACEFD":         {},
	"CDPATH":                {},
	"CLASSPATH":             {},
	"EDITOR":                {},
	"ENV":                   {},
	"FISH_VERSION":          {},
	"FPATH":                 {},
	"GCONV_PATH":            {},
	"GIT_ASKPASS":           {},
	"GIT_CONFIG_COUNT":      {},
	"GIT_CONFIG_PARAMETERS": {},
	"GIT_EXTERNAL_DIFF":     {},
	"GIT_EXEC_PATH":         {},
	"GIT_SSH":               {},
	"GIT_SSH_COMMAND":       {},
	"GIT_TEMPLATE_DIR":      {},
	"GLOBIGNORE":            {},
	"HOME":                  {},
	"IFS":                   {},
	"JAVA_TOOL_OPTIONS":     {},
	"NODE_OPTIONS":          {},
	"NODE_PATH":             {},
	"PATH":                  {},
	"PERL5LIB":              {},
	"PERL5OPT":              {},
	"PROMPT_COMMAND":        {},
	"PS0":                   {},
	"PS1":                   {},
	"PS2":                   {},
	"PS3":                   {},
	"PS4":                   {},
	"PYTHONHOME":            {},
	"PYTHONINSPECT":         {},
	"PYTHONPATH":            {},
	"PYTHONSTARTUP":         {},
	"RUBYLIB":               {},
	"RUBYOPT":               {},
	"SHELLOPTS":             {},
	"SSH_ASKPASS":           {},
	"SSH_AUTH_SOCK":         {},
	"TMPDIR":                {},
	"VISUAL":                {},
	"XDG_CONFIG_HOME":       {},
	"ZDOTDIR":               {},
	"_JAVA_OPTIONS":         {},
}

// shellHazardPrefix covers families where every member hijacks loading.
var shellHazardPrefix = []string{"DYLD_", "FUU_", "LD_"}

func shellHazard(name string) bool {
	if _, ok := shellHazards[name]; ok {
		return true
	}
	return slices.ContainsFunc(shellHazardPrefix, func(p string) bool {
		return strings.HasPrefix(name, p)
	})
}

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

// emitValues prints one export per secret the shell can hold and one comment
// per hazard name, returning what actually landed there. The hazard names come
// from the vault, so the filter lives here and the hook's own FUU_ state
// exports bypass it by not coming through.
func emitValues(out emitter, values map[string]string) []string {
	names := make([]string, 0, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		if shellHazard(name) {
			fmt.Printf("# fuu kept %s out of your shell, it configures the shell itself\n", name)
			continue
		}
		out.export(name, values[name])
		names = append(names, name)
	}
	return names
}

// export sets one variable in the calling shell.
func (e emitter) export(name, value string) {
	if !vault.ValidName(name) {
		return
	}
	if e.fish {
		fmt.Printf("set -gx %s %s\n", name, fishQuote(value))
		return
	}
	fmt.Printf("export %s=%s\n", name, shQuote(value))
}

// unset refuses a name that is not a plain identifier, since FUU_LOADED is read
// back out of the environment and eval'd. A hazard name is unsettable on
// purpose, cleaning up what an older fuu exported beats leaving it in place.
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
