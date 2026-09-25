package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
)

// The hooks only ever call back into fuu env. Nothing from a repo is executed,
// so there is no allow gate to manage. They run before every prompt and fuu env
// says nothing while the shell already holds the current state, so a change
// saved from anywhere, including fuu edit in another window, lands without a cd.
const hookBash = `# fuu, add to .bashrc:  eval "$(fuu hook bash)"
_fuu_hook() {
	local previous_exit_status=$?
	eval "$(command fuu env --shell=posix)"
	return $previous_exit_status
}
if ! [[ "${PROMPT_COMMAND-}" =~ _fuu_hook ]]; then
	PROMPT_COMMAND="_fuu_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi
_fuu_hook
`

const hookFish = `# fuu, add to config.fish:  fuu hook fish | source
function _fuu_hook
	command fuu env --shell=fish | source
end
# PWD and fish_prompt both fire after a cd, the flag keeps that to one run.
function _fuu_pwd --on-variable PWD
	_fuu_hook
	set -g _fuu_ran 1
end
function _fuu_prompt --on-event fish_prompt
	if set -q _fuu_ran
		set -e _fuu_ran
		return
	end
	_fuu_hook
end
_fuu_hook
`

const hookZsh = `# fuu, add to .zshrc:  eval "$(fuu hook zsh)"
_fuu_hook() {
	eval "$(command fuu env --shell=posix)"
}
# chpwd and precmd both fire after a cd, the flag keeps that to one run.
_fuu_chpwd() {
	_fuu_hook
	_fuu_ran=1
}
_fuu_precmd() {
	if [[ -n ${_fuu_ran-} ]]; then
		unset _fuu_ran
		return
	fi
	_fuu_hook
}
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _fuu_chpwd
add-zsh-hook precmd _fuu_precmd
_fuu_hook
`

func cmdHook(_ context.Context, cmd *cli.Command) error {
	switch shell := cmd.Args().Get(0); shell {
	case "bash":
		fmt.Print(hookBash)
	case "zsh":
		fmt.Print(hookZsh)
	case "fish":
		fmt.Print(hookFish)
	case "":
		return errors.New("hook: want bash, zsh or fish")
	default:
		return fmt.Errorf("hook: unsupported shell %q, want bash, zsh or fish", shell)
	}
	return nil
}

// cmdEnv emits the shell lines that load this directory's vault into the
// shell, and drops what the shell holds when there is no vault here or it
// cannot be trusted.
func cmdEnv(_ context.Context, cmd *cli.Command) error {
	out, err := emitterFor(cmd)
	if err != nil {
		return err
	}
	loaded := strings.Fields(os.Getenv("FUU_LOADED"))

	path, err := vaultPath(cmd)
	if errors.Is(err, errNoVault) {
		out.unload(loaded)
		return nil
	}
	if err != nil {
		return err
	}

	stamp, err := vaultStamp(path)
	if err != nil {
		return err
	}
	// The hook runs this before every prompt, so say nothing while the shell
	// already holds exactly this state and nothing needs unsealing.
	if stamp == os.Getenv("FUU_STAMP") && len(loaded) > 0 {
		return nil
	}

	f, err := openVerified(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		out.unload(loaded)
		return nil
	case errors.Is(err, errUnaccepted), errors.Is(err, errUntrusted),
		errors.Is(err, errStale), errors.Is(err, errRevoked):
		// The hook runs at every prompt, so a refusal is a message and a
		// clean shell rather than a failed eval. FUU_STAMP remembers what
		// was already reported, so the message lands once per situation
		// and not once per prompt.
		mark := refusalMark(err, stamp)
		if len(loaded) == 0 && os.Getenv("FUU_STAMP") == mark {
			return nil
		}
		if os.Getenv("FUU_STAMP") != mark {
			fmt.Fprintf(os.Stderr, "fuu: %v\n", err)
		}
		out.unload(loaded)
		out.export("FUU_STAMP", mark)
		return nil
	case err != nil:
		return err
	}

	dk, key, err := openKey(f)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	values, err := f.Values(key)
	if err != nil {
		return err
	}
	for _, name := range loaded {
		if _, ok := values[name]; !ok {
			out.unset(name)
		}
	}
	names := emitValues(out, values)
	out.export("FUU_LOADED", strings.Join(names, " "))
	out.export("FUU_STAMP", stamp)
	return nil
}

// vaultStamp fingerprints the vault bytes so a shell can tell it is already
// current without unsealing anything.
func vaultStamp(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("env: %w", err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

// refusalMark fingerprints a refusal and the vault bytes behind it, so the
// hook can tell an already reported situation from a new one.
func refusalMark(err error, stamp string) string {
	sum := sha256.Sum256([]byte(err.Error() + "\x00" + stamp))
	return fmt.Sprintf("refused:%x", sum)
}

func cmdPrint(_ context.Context, cmd *cli.Command) error {
	out, err := emitterFor(cmd)
	if err != nil {
		return err
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	values, err := f.Values(key)
	if err != nil {
		return err
	}
	emitValues(out, values)
	return nil
}

func cmdRun(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	// SkipFlagParsing hands -- straight through, but humans read it as a separator.
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return errors.New("run: want <command> [args...]")
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	values, err := f.Values(key)
	if err != nil {
		return err
	}

	//nolint:gosec // G204 is the whole purpose of run, it executes the caller's own command.
	child := exec.CommandContext(ctx, args[0], args[1:]...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = append(os.Environ(), envPairs(values)...)
	return child.Run()
}

// envPairs builds the child environment with the same hazard filter the hook
// applies, so a vault key named PATH or LD_PRELOAD reaches no process either.
func envPairs(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		if shellHazard(name) {
			continue
		}
		out = append(out, name+"="+values[name])
	}
	return out
}
