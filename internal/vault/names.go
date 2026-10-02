package vault

import (
	"slices"
	"strings"
)

// shellHazards run code or take the shell over once eval'd, or name a
// command or config file that the shell, git or a pager runs later.
// Matched case insensitively, zsh and fish alias lowercase names to the
// real thing (path to PATH). A blocklist only knows the names it knows.
var shellHazards = map[string]struct{}{
	"BASHOPTS":              {},
	"BASH_COMPAT":           {},
	"BASH_ENV":              {},
	"BASH_XTRACEFD":         {},
	"BROWSER":               {},
	"CDPATH":                {},
	"CLASSPATH":             {},
	"EDITOR":                {},
	"ENV":                   {},
	"FCEDIT":                {},
	"FISH_COMPLETE_PATH":    {},
	"FISH_FUNCTION_PATH":    {},
	"FISH_USER_PATHS":       {},
	"FISH_VERSION":          {},
	"FPATH":                 {},
	"GCONV_PATH":            {},
	"GIT_ASKPASS":           {},
	"GIT_CONFIG_COUNT":      {},
	"GIT_CONFIG_GLOBAL":     {},
	"GIT_CONFIG_PARAMETERS": {},
	"GIT_CONFIG_SYSTEM":     {},
	"GIT_EDITOR":            {},
	"GIT_EXEC_PATH":         {},
	"GIT_EXTERNAL_DIFF":     {},
	"GIT_PAGER":             {},
	"GIT_PROXY_COMMAND":     {},
	"GIT_SEQUENCE_EDITOR":   {},
	"GIT_SSH":               {},
	"GIT_SSH_COMMAND":       {},
	"GIT_TEMPLATE_DIR":      {},
	"GLOBIGNORE":            {},
	"HISTFILE":              {},
	"HOME":                  {},
	"IFS":                   {},
	"INPUTRC":               {},
	"JAVA_TOOL_OPTIONS":     {},
	"LESSCLOSE":             {},
	"LESSOPEN":              {},
	"MAILPATH":              {},
	"MANPAGER":              {},
	"MANPATH":               {},
	"MODULE_PATH":           {},
	"NODE_OPTIONS":          {},
	"NODE_PATH":             {},
	"NULLCMD":               {},
	"PAGER":                 {},
	"PATH":                  {},
	"PERL5LIB":              {},
	"PERL5OPT":              {},
	"PROMPT":                {},
	"PROMPT2":               {},
	"PROMPT3":               {},
	"PROMPT4":               {},
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
	"READNULLCMD":           {},
	"RPROMPT":               {},
	"RPROMPT2":              {},
	"RPS1":                  {},
	"RPS2":                  {},
	"RUBYLIB":               {},
	"RUBYOPT":               {},
	"SHELL":                 {},
	"SHELLOPTS":             {},
	"SPROMPT":               {},
	"SSH_ASKPASS":           {},
	"SSH_AUTH_SOCK":         {},
	"SUDO_ASKPASS":          {},
	"TMOUT":                 {},
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
// variable, because fuu env is eval'd.
func ValidName(name string) bool {
	return identName(name) && !shellHazard(name)
}

// identName is what the shell parses as one assignment word, no more.
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
