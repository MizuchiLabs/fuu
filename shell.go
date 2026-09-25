package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
// cannot be opened. FUU_STATE is the fingerprint of what the shell holds, so
// the hook stays silent while nothing changed and a failure is reported once
// instead of once per prompt.
func cmdEnv(_ context.Context, cmd *cli.Command) error {
	out, err := emitterFor(cmd)
	if err != nil {
		return err
	}
	loaded := strings.Fields(os.Getenv("FUU_LOADED"))

	path, err := vaultPath(cmd)
	if errors.Is(err, errNoVault) {
		out.unload(loaded)
		out.dropState()
		announce(path, loaded, nil)
		return nil
	}
	if err != nil {
		return err
	}

	state, err := vaultState(path)
	if errors.Is(err, os.ErrNotExist) {
		out.unload(loaded)
		out.dropState()
		announce(path, loaded, nil)
		return nil
	}
	if err != nil {
		return err
	}
	if state == os.Getenv("FUU_STATE") {
		return nil
	}

	_, f, key, _, err := unlock(cmd)
	values := map[string]string{}
	if err == nil {
		values, err = f.Secrets(key)
	}
	if err != nil {
		// The hook runs at every prompt, so a refusal is a message and a
		// clean shell rather than a failed eval. FUU_STATE remembers what was
		// already reported: the same state stays silent at later prompts, and
		// a fuu trust or a file change alters the state and retries.
		fmt.Fprintf(os.Stderr, "fuu: %s\n", present(err))
		out.unload(loaded)
		announce(path, loaded, nil)
		out.export("FUU_STATE", state)
		return nil
	}

	for _, name := range loaded {
		if _, ok := values[name]; !ok {
			out.unset(name)
		}
	}
	names := emitValues(out, values)
	out.export("FUU_LOADED", strings.Join(names, " "))
	out.export("FUU_STATE", state)
	announce(path, loaded, names)
	return nil
}

// vaultState fingerprints the folder, the vault bytes and what this folder is
// pinned to, so a shell can tell it is already current without unsealing
// anything.
func vaultState(path string) (string, error) {
	dir, err := vaultDir(path)
	if err != nil {
		return "", err
	}
	pins, err := loadPins()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("env: %w", err)
	}
	buf := make([]byte, 0, len(dir)+len(data)+len(pins[dir])+2)
	buf = append(buf, dir...)
	buf = append(buf, 0)
	buf = append(buf, data...)
	buf = append(buf, 0)
	buf = append(buf, pins[dir]...)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// announce reports which names the hook just moved in or out of the shell,
// direnv style. Values never appear here, and a move that changes no names
// says nothing. An empty name set means the shell was unloaded.
func announce(path string, loaded, names []string) {
	parts := make([]string, 0, len(loaded)+len(names))
	for _, n := range names {
		if !slices.Contains(loaded, n) {
			parts = append(parts, "+"+n)
		}
	}
	for _, n := range loaded {
		if !slices.Contains(names, n) {
			parts = append(parts, "-"+n)
		}
	}
	if len(parts) == 0 {
		return
	}
	if len(names) == 0 {
		fmt.Fprintf(os.Stderr, "fuu: unloading %s\n", strings.Join(parts, " "))
		return
	}
	fmt.Fprintf(os.Stderr, "fuu: %s: %s\n", path, strings.Join(parts, " "))
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

	_, f, key, _, err := unlock(cmd)
	if err != nil {
		return err
	}
	values, err := f.Secrets(key)
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

// envPairs builds the child environment from the vault's values.
func envPairs(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		out = append(out, name+"="+values[name])
	}
	return out
}
