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

	"github.com/mizuchilabs/fuu/internal/resolve"
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

// cmdEnv emits the shell lines that move the environment onto the project that
// applies to the working directory, and off the one that applied before.
func cmdEnv(_ context.Context, cmd *cli.Command) error {
	out, err := emitterFor(cmd)
	if err != nil {
		return err
	}

	project := cmd.Args().Get(0)
	if project == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("env: %w", err)
		}
		if project, err = resolve.Project(wd); err != nil {
			return err
		}
	}

	path := cmd.String("vault")
	stamp, err := vaultStamp(path)
	if err != nil {
		return err
	}
	// The hook runs this before every prompt, so say nothing while the shell
	// already holds exactly this state and nothing needs unsealing.
	if os.Getenv("FUU_STAMP") == stamp && os.Getenv("FUU_PROJECT") == project {
		return nil
	}

	loaded := strings.Fields(os.Getenv("FUU_LOADED"))
	f, err := openVerified(path)
	if errors.Is(err, os.ErrNotExist) {
		out.unload(loaded)
		return nil
	}
	if err != nil {
		return err
	}
	if project == "" || f.Secret[project] == nil {
		out.unload(loaded)
		return nil
	}

	dk, key, err := openKey(f)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	values, err := f.Project(key, project)
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
	out.export("FUU_PROJECT", project)
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

func cmdPrint(_ context.Context, cmd *cli.Command) error {
	out, err := emitterFor(cmd)
	if err != nil {
		return err
	}

	project := cmd.Args().Get(0)
	if project == "" {
		return errors.New("print: want <project>")
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	values, err := f.Project(key, project)
	if err != nil {
		return err
	}
	emitValues(out, values)
	return nil
}

func cmdRun(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 2 {
		return errors.New("run: want <project> <command> [args...]")
	}
	project, rest := args[0], args[1:]
	// SkipFlagParsing hands -- straight through, but humans read it as a separator.
	if rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return errors.New("run: want <project> <command> [args...]")
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	values, err := f.Project(key, project)
	if err != nil {
		return err
	}

	//nolint:gosec // G204 is the whole purpose of run, it executes the caller's own command.
	child := exec.CommandContext(ctx, rest[0], rest[1:]...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = append(os.Environ(), envPairs(values)...)
	return child.Run()
}

func envPairs(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		out = append(out, name+"="+values[name])
	}
	return out
}
