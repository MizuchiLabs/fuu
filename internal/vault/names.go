package vault

import (
	"slices"
	"strings"
)

// shellHazards are variable names that reach past a plain secret once the hook
// evals the export line: they run code or take the shell over. Matching is
// case insensitive because zsh and fish tie a lower case alias to the real
// thing (path to PATH, fpath to FPATH, prompt to PS1), so a secret named path
// would hijack command resolution in zsh even though bash treats it as a plain
// variable. The list is the price of eval integration. A name like one of
// these is refused outright, it never enters the vault.
var shellHazards = map[string]struct{}{
	"BASHOPTS":              {},
	"BASH_COMPAT":           {},
	"BASH_ENV":              {},
	"BASH_XTRACEFD":         {},
	"CDPATH":                {},
	"CLASSPATH":             {},
	"EDITOR":                {},
	"ENV":                   {},
	"FISH_COMPLETE_PATH":    {},
	"FISH_FUNCTION_PATH":    {},
	"FISH_USER_PATHS":       {},
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
	"MANPATH":               {},
	"MODULE_PATH":           {},
	"NODE_OPTIONS":          {},
	"NODE_PATH":             {},
	"PATH":                  {},
	"PERL5LIB":              {},
	"PERL5OPT":              {},
	"PROMPT":                {},
	"PROMPT_COMMAND":        {},
	"PROMPT_SUBST":          {},
	"PS0":                   {},
	"PS1":                   {},
	"PS2":                   {},
	"PS3":                   {},
	"PS4":                   {},
	"PYTHONHOME":            {},
	"PYTHONINSPECT":         {},
	"PYTHONPATH":            {},
	"PYTHONSTARTUP":         {},
	"RPROMPT":               {},
	"RPS1":                  {},
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
	upper := strings.ToUpper(name)
	if _, ok := shellHazards[upper]; ok {
		return true
	}
	return slices.ContainsFunc(shellHazardPrefix, func(p string) bool {
		return strings.HasPrefix(upper, p)
	})
}

// ValidName reports whether name is safe to store and to emit as a shell
// variable name, because fuu env is eval'd by the shell. A name that is not a
// plain identifier, or that configures the shell itself, is refused.
func ValidName(name string) bool {
	return identName(name) && !shellHazard(name)
}

// identName is the shell identifier rule: what the shell would parse as one
// assignment word, no more.
func identName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// validDeviceName is what a device may be called: hostnames with dots and
// dashes have to pass, and nothing longer or stranger than that.
func validDeviceName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
