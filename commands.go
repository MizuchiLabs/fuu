package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/mizuchilabs/fuu/internal/devkey"
	"github.com/mizuchilabs/fuu/internal/resolve"
	"github.com/mizuchilabs/fuu/internal/sig"
	"github.com/mizuchilabs/fuu/internal/vault"
)

// The hooks only ever call back into fuu env. Nothing from a repo is executed,
// so there is no allow gate to manage. They run before every prompt and fuu env
// says nothing while the shell already holds the current state, so a change
// saved from anywhere, including fuu edit in another window, lands without a cd.
const hookBash = `# fuu, add to .bashrc:  eval "$(fuu hook bash)"
_fuu_hook() {
	local previous_exit_status=$?
	eval "$(command fuu env)"
	return $previous_exit_status
}
if ! [[ "${PROMPT_COMMAND-}" =~ _fuu_hook ]]; then
	PROMPT_COMMAND="_fuu_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi
_fuu_hook
`

const hookFish = `# fuu, add to config.fish:  fuu hook fish | source
function _fuu_hook --on-variable PWD --on-event fish_prompt
	command fuu env --shell=fish | source
end
_fuu_hook
`

const hookZsh = `# fuu, add to .zshrc:  eval "$(fuu hook zsh)"
_fuu_hook() {
	eval "$(command fuu env)"
}
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _fuu_hook
add-zsh-hook precmd _fuu_hook
_fuu_hook
`

var (
	stdin = bufio.NewReader(os.Stdin)

	shellFlag = &cli.StringFlag{
		Name:  "shell",
		Usage: "output format, posix or fish, defaults to fish inside fish",
		Value: "",
	}

	vaultFlag = &cli.StringFlag{
		Name:    "vault",
		Usage:   "path to the vault file",
		Value:   "fuu.toml",
		Sources: cli.EnvVars("FUU_VAULT"),
	}
)

var commands = []*cli.Command{
	{
		Name:   "doctor",
		Usage:  "report TPM status and this machine's device key",
		Action: cmdDoctor,
	},
	{
		Name:   "init",
		Usage:  "create a vault with a fresh key sealed to this machine",
		Action: cmdInit,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "device name, defaults to the hostname"},
		},
	},
	{
		Name:   "join",
		Usage:  "enrol this machine using the recovery passphrase",
		Action: cmdJoin,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "device name, defaults to the hostname"},
		},
	},
	{
		Name:   "whoami",
		Usage:  "show which enrolled device this machine is",
		Action: cmdWhoami,
	},
	{
		Name:  "device",
		Usage: "manage enrolled devices",
		Commands: []*cli.Command{
			{
				Name:   "ls",
				Usage:  "list enrolled devices",
				Action: cmdDeviceLs,
			},
			{
				Name:   "pub",
				Usage:  "print this machine's public key for enrolment elsewhere",
				Action: cmdDevicePub,
			},
			{
				Name:      "add",
				Usage:     "seal the vault key to another device's public key",
				ArgsUsage: "<name> <pub>",
				Action:    cmdDeviceAdd,
			},
			{
				Name:      "rm",
				Usage:     "revoke a device from here on",
				ArgsUsage: "<name>",
				Action:    cmdDeviceRm,
			},
		},
	},
	{
		Name:      "set",
		Usage:     "set a secret value",
		ArgsUsage: "<project>:<KEY> [value]",
		Action:    cmdSet,
	},
	{
		Name:      "unset",
		Usage:     "delete a secret value",
		ArgsUsage: "<project>:<KEY>",
		Action:    cmdUnset,
	},
	{
		Name:      "get",
		Usage:     "print one secret value",
		ArgsUsage: "<project>:<KEY>",
		Action:    cmdGet,
	},
	{
		Name:      "edit",
		Usage:     "edit one project's secrets in your editor",
		ArgsUsage: "[project]",
		Action:    cmdEdit,
	},
	{
		Name:      "ls",
		Usage:     "list projects, or the keys in one project",
		ArgsUsage: "[project]",
		Action:    cmdLs,
	},
	{
		Name:      "print",
		Usage:     "print export lines for one project",
		ArgsUsage: "<project>",
		Flags:     []cli.Flag{shellFlag},
		Action:    cmdPrint,
	},
	{
		Name:      "env",
		Usage:     "print shell lines loading the project for the current directory",
		ArgsUsage: "[project]",
		Flags:     []cli.Flag{shellFlag},
		Action:    cmdEnv,
	},
	{
		Name:      "hook",
		Usage:     "print the shell hook that keeps your shell's secrets up to date",
		ArgsUsage: "<bash|zsh>",
		Action:    cmdHook,
	},
	{
		Name:            "run",
		Usage:           "run a command with one project's secrets in its environment",
		ArgsUsage:       "<project> <command> [args...]",
		SkipFlagParsing: true,
		Action:          cmdRun,
	},
	{
		Name:   "rotate",
		Usage:  "replace the vault key and rewrap everything",
		Action: cmdRotate,
	},
	{
		Name:   "sign",
		Usage:  "stamp the vault contents with this machine's signing key",
		Action: cmdSign,
	},
	{
		Name:   "verify",
		Usage:  "check the vault signature and print the signing device",
		Action: cmdVerify,
	},
}

func cmdDoctor(_ context.Context, cmd *cli.Command) error {
	if err := devkey.Available(); err != nil {
		return fmt.Errorf("doctor: %w", err)
	}

	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	fmt.Println("tpm: ok")
	fmt.Println("pub:", vault.Pub(dk.Public()))

	path := cmd.String("vault")
	f, err := vault.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("vault: none at %s\n", path)
		return nil
	}
	if err != nil {
		return err
	}

	fmt.Println("vault:", path)
	name, err := f.Match(dk)
	if err != nil {
		fmt.Println("device: not enrolled here")
		return nil
	}
	fmt.Println("device:", name)
	return nil
}

func cmdInit(_ context.Context, cmd *cli.Command) error {
	path := cmd.String("vault")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("init: %s already exists", path)
	}

	pass, err := prompt("recovery passphrase", true)
	if err != nil {
		return err
	}

	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	sk, err := devkey.OpenSigning()
	if err != nil {
		return err
	}
	defer func() { _ = sk.Close() }()

	f, err := vault.New(dk, deviceName(cmd), pass, sk.Public())
	if err != nil {
		return err
	}
	if err := signAndSave(f, path); err != nil {
		return err
	}

	fmt.Printf("created %s with device %q\n", path, deviceName(cmd))
	return nil
}

func cmdJoin(_ context.Context, cmd *cli.Command) error {
	path := cmd.String("vault")
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	// Checked before anything is added, a tampered vault is never re-stamped.
	if err := f.Verify(); err != nil {
		return err
	}

	pass, err := prompt("recovery passphrase", false)
	if err != nil {
		return err
	}

	key, err := f.VaultKeyPass(pass)
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	defer clear(key)

	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	sk, err := devkey.OpenSigning()
	if err != nil {
		return err
	}
	defer func() { _ = sk.Close() }()

	name := deviceName(cmd)
	if err := f.AddDevice(key, name, dk.Public(), sk.Public()); err != nil {
		return err
	}
	if err := signAndSave(f, path); err != nil {
		return err
	}

	fmt.Printf("enrolled device %q in %s\n", name, path)
	return nil
}

func cmdWhoami(_ context.Context, cmd *cli.Command) error {
	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	name, err := f.Match(dk)
	if err != nil {
		return fmt.Errorf("whoami: %w", err)
	}
	fmt.Println(name)
	return nil
}

func cmdDeviceLs(_ context.Context, cmd *cli.Command) error {
	f, err := vault.Load(cmd.String("vault"))
	if err != nil {
		return err
	}
	if err := f.Verify(); err != nil {
		return err
	}

	for _, name := range slices.Sorted(maps.Keys(f.Device)) {
		d := f.Device[name]
		fmt.Printf("%s\t%s\t%s\n", name, d.Created, d.Pub)
	}
	return nil
}

func cmdDevicePub(_ context.Context, _ *cli.Command) error {
	dk, err := devkey.Open()
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()

	sk, err := devkey.OpenSigning()
	if err != nil {
		return err
	}
	defer func() { _ = sk.Close() }()

	signer, err := sig.EncodeSigner(sk.Public())
	if err != nil {
		return err
	}
	fmt.Println(vault.Pub(dk.Public()), signer)
	return nil
}

func cmdDeviceAdd(_ context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	var ecdhArg, signArg string
	switch len(args) {
	case 2:
		// device pub prints one line, which arrives whole when the line is quoted.
		fields := strings.Fields(args[1])
		if len(fields) != 2 {
			return fmt.Errorf(
				"device add: %q is not the ECDH public key and the signing public key separated by whitespace",
				args[1],
			)
		}
		ecdhArg, signArg = fields[0], fields[1]
	case 3:
		ecdhArg, signArg = args[1], args[2]
	default:
		return errors.New("device add: want <name> <pub> holding both public keys, or <name> <ecdh-pub> <sign-pub>")
	}

	pub, err := vault.ParsePub(ecdhArg)
	if err != nil {
		return err
	}
	signPub, err := sig.ParseSigner(signArg)
	if err != nil {
		return err
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	if err := f.AddDevice(key, args[0], pub, signPub); err != nil {
		return err
	}
	if err := signAndSave(f, cmd.String("vault")); err != nil {
		return err
	}

	fmt.Printf("enrolled device %q\n", args[0])
	return nil
}

func cmdDeviceRm(_ context.Context, cmd *cli.Command) error {
	name := cmd.Args().Get(0)
	if name == "" {
		return errors.New("device rm: want <name>")
	}

	path := cmd.String("vault")
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	// Checked before anything is removed, a tampered vault is never re-stamped.
	if err := f.Verify(); err != nil {
		return err
	}
	if err := f.RemoveDevice(name); err != nil {
		return err
	}
	if err := signAndSave(f, path); err != nil {
		return err
	}

	fmt.Printf("revoked device %q, rotate if it burned\n", name)
	return nil
}

func cmdSet(_ context.Context, cmd *cli.Command) error {
	project, name, err := splitTarget(cmd.Args().Get(0))
	if err != nil {
		return err
	}

	value := cmd.Args().Get(1)
	if value == "" {
		// A piped value keeps newlines and leading dashes, which argv cannot do
		// since anything starting with a dash reads as a flag.
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			all, err := io.ReadAll(stdin)
			if err != nil {
				return fmt.Errorf("set: %w", err)
			}
			value = strings.TrimSuffix(strings.TrimSuffix(string(all), "\n"), "\r")
		} else if value, err = prompt("value", false); err != nil {
			return err
		}
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	if err := f.Set(key, project, name, []byte(value)); err != nil {
		return err
	}
	return signAndSave(f, cmd.String("vault"))
}

func cmdUnset(_ context.Context, cmd *cli.Command) error {
	project, name, err := splitTarget(cmd.Args().Get(0))
	if err != nil {
		return err
	}

	path := cmd.String("vault")
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	// Checked before anything is removed, a tampered vault is never re-stamped.
	if err := f.Verify(); err != nil {
		return err
	}
	if err := f.Unset(project, name); err != nil {
		return err
	}
	return signAndSave(f, path)
}

func cmdGet(_ context.Context, cmd *cli.Command) error {
	project, name, err := splitTarget(cmd.Args().Get(0))
	if err != nil {
		return err
	}

	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	value, err := f.Get(key, project, name)
	if err != nil {
		return err
	}
	fmt.Println(string(value))
	return nil
}

// cmdEdit opens one project in $EDITOR and writes back only what changed. The
// buffer is TOML so values with quotes or newlines survive a round trip exactly.
func cmdEdit(ctx context.Context, cmd *cli.Command) error {
	project := cmd.Args().Get(0)
	if project == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("edit: %w", err)
		}
		if project, err = resolve.Project(wd); err != nil {
			return err
		}
	}
	if project == "" {
		return errors.New("edit: no project here, name one")
	}

	path := cmd.String("vault")
	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	before, err := f.Project(key, project)
	if errors.Is(err, vault.ErrNoProject) {
		before = map[string]string{}
	} else if err != nil {
		return err
	}

	raw, err := runEditor(ctx, project, before)
	if err != nil {
		return err
	}
	edited, err := parseValues(raw)
	if err != nil {
		return err
	}
	// An empty buffer is far more likely a botched edit than a real intention,
	// so dropping every key takes one extra word instead of being refused.
	if len(edited) == 0 && len(before) > 0 {
		ok, err := confirm(fmt.Sprintf("drop every key in %q", project))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("edit: aborted, nothing written")
		}
	}

	fresh, err := vault.Load(path)
	if err != nil {
		return err
	}
	if err := fresh.Verify(); err != nil {
		return err
	}

	var wrote, dropped []string
	for _, name := range slices.Sorted(maps.Keys(edited)) {
		if old, ok := before[name]; ok && old == edited[name] {
			continue
		}
		if err := fresh.Set(key, project, name, []byte(edited[name])); err != nil {
			return err
		}
		wrote = append(wrote, name)
	}
	for _, name := range slices.Sorted(maps.Keys(before)) {
		if _, ok := edited[name]; ok {
			continue
		}
		if err := fresh.Unset(project, name); err != nil {
			return err
		}
		dropped = append(dropped, name)
	}

	if len(wrote) == 0 && len(dropped) == 0 {
		fmt.Println("no changes")
		return nil
	}
	if err := signAndSave(fresh, path); err != nil {
		return err
	}
	for _, name := range wrote {
		fmt.Println("~", name)
	}
	for _, name := range dropped {
		fmt.Println("-", name)
	}
	return nil
}

// runEditor shows values as TOML in the user's editor and returns the result.
func runEditor(ctx context.Context, project string, values map[string]string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "fuu-editbuf-")
	if err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}
	// The buffer is plaintext, so the whole directory goes rather than one file.
	// Editors leave swap and backup copies next to it.
	defer func() { _ = os.RemoveAll(dir) }()

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# %s\n# save and close to write the changes back, delete a line to drop a key\n\n", project)
	if err := toml.NewEncoder(&buf).Encode(values); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}

	path := filepath.Join(dir, "secrets.toml")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}

	argv := strings.Fields(editor())
	if len(argv) == 0 {
		return nil, errors.New("edit: set $EDITOR or $VISUAL")
	}
	//nolint:gosec // the editor is whatever the user configured.
	child := exec.CommandContext(ctx, argv[0], append(argv[1:], path)...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Run(); err != nil {
		return nil, fmt.Errorf("edit: run editor: %w", err)
	}
	return os.ReadFile(path)
}

func editor() string {
	if e := os.Getenv("VISUAL"); e != "" {
		return e
	}
	return os.Getenv("EDITOR")
}

// parseValues reads back what runEditor wrote, with the same name guard the
// emitters use since this is still headed for eval.
func parseValues(raw []byte) (map[string]string, error) {
	values := map[string]string{}
	if err := toml.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}
	for name := range values {
		if !vault.ValidName(name) {
			return nil, fmt.Errorf("%w %q", vault.ErrBadName, name)
		}
	}
	return values, nil
}

func cmdLs(_ context.Context, cmd *cli.Command) error {
	f, err := vault.Load(cmd.String("vault"))
	if err != nil {
		return err
	}

	project := cmd.Args().Get(0)
	if project == "" {
		for _, name := range slices.Sorted(maps.Keys(f.Secret)) {
			fmt.Println(name)
		}
		return nil
	}

	keys, ok := f.Secret[project]
	if !ok {
		return fmt.Errorf("vault: no such project %q", project)
	}
	for _, name := range slices.Sorted(maps.Keys(keys)) {
		fmt.Println(name)
	}
	return nil
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
	for _, name := range slices.Sorted(maps.Keys(values)) {
		if !vault.ValidName(name) {
			return fmt.Errorf("%w %q", vault.ErrBadName, name)
		}
		out.export(name, values[name])
	}
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

func cmdRotate(_ context.Context, cmd *cli.Command) error {
	f, dk, key, err := unlock(cmd)
	if err != nil {
		return err
	}
	defer func() { _ = dk.Close() }()
	defer clear(key)

	pass, err := prompt("new recovery passphrase", true)
	if err != nil {
		return err
	}
	if err := f.Rotate(key, pass); err != nil {
		return err
	}
	if err := signAndSave(f, cmd.String("vault")); err != nil {
		return err
	}

	fmt.Println("rotated the vault key")
	return nil
}

func cmdSign(_ context.Context, cmd *cli.Command) error {
	path := cmd.String("vault")
	f, err := vault.Load(path)
	if err != nil {
		return err
	}
	// The one blessing command, and only for a vault that was never signed. A
	// signature that no longer holds is tampering and is never blessed over.
	if err := f.Verify(); err != nil && !errors.Is(err, vault.ErrNoSig) {
		return err
	}
	if err := signAndSave(f, path); err != nil {
		return err
	}

	fmt.Printf("stamped %s\n", path)
	return nil
}

func cmdVerify(_ context.Context, cmd *cli.Command) error {
	f, err := vault.Load(cmd.String("vault"))
	if err != nil {
		return err
	}
	if err := f.Verify(); err != nil {
		return err
	}

	for _, name := range slices.Sorted(maps.Keys(f.Device)) {
		if f.Device[name].SignPub == f.Signer {
			fmt.Printf("signature ok, signed by %s\n", name)
			return nil
		}
	}
	fmt.Println("signature ok, signer is not in the device registry")
	return nil
}

// openKey unseals the vault key with this machine's TPM.
func openKey(f *vault.File) (*devkey.Key, []byte, error) {
	dk, err := devkey.Open()
	if err != nil {
		return nil, nil, err
	}

	key, err := f.VaultKey(dk)
	if err != nil {
		_ = dk.Close()
		return nil, nil, err
	}
	return dk, key, nil
}

// signAndSave stamps the vault with this machine's signing key before writing
// it, so no mutation is ever saved unsigned. Checking happens at load time
// before anything changes, never here against a stale signature.
func signAndSave(f *vault.File, path string) error {
	sk, err := devkey.OpenSigning()
	if err != nil {
		return err
	}
	defer func() { _ = sk.Close() }()

	if err := f.Stamp(sk); err != nil {
		return err
	}
	return f.Save(path)
}

// unlock loads the vault, verifies its stored signature and unseals the vault key with this machine's TPM.
func unlock(cmd *cli.Command) (*vault.File, *devkey.Key, []byte, error) {
	f, err := vault.Load(cmd.String("vault"))
	if err != nil {
		return nil, nil, nil, err
	}
	if err := f.Verify(); err != nil {
		return nil, nil, nil, err
	}

	dk, key, err := openKey(f)
	if err != nil {
		return nil, nil, nil, err
	}
	return f, dk, key, nil
}

func deviceName(cmd *cli.Command) string {
	if name := cmd.String("name"); name != "" {
		return name
	}
	name, err := os.Hostname()
	if err != nil {
		return "device"
	}
	return name
}

func splitTarget(s string) (project, name string, err error) {
	project, name, ok := strings.Cut(s, ":")
	if !ok || project == "" || name == "" {
		return "", "", fmt.Errorf("target %q is not PROJECT:KEY", s)
	}
	return project, name, nil
}

func envPairs(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		out = append(out, name+"="+values[name])
	}
	return out
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
	f, err := vault.Load(path)
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
	if err := f.Verify(); err != nil {
		return err
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
	names := slices.Sorted(maps.Keys(values))
	for _, name := range names {
		if !vault.ValidName(name) {
			return fmt.Errorf("%w %q", vault.ErrBadName, name)
		}
	}
	for _, name := range loaded {
		if _, ok := values[name]; !ok {
			out.unset(name)
		}
	}
	for _, name := range names {
		out.export(name, values[name])
	}
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

func prompt(label string, repeat bool) (string, error) {
	first, err := readSecret(label)
	if err != nil {
		return "", err
	}
	if !repeat {
		return first, nil
	}

	second, err := readSecret("repeat " + label)
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("prompt: entries do not match")
	}
	return first, nil
}

// confirm takes one visible line, since the answer is not a secret. Anything
// but a plain yes means no.
func confirm(label string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", label)
	defer fmt.Fprintln(os.Stderr)

	line, err := stdin.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("prompt: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// readSecret hides the input on a terminal and takes a plain line when stdin
// is a pipe, so init and set stay scriptable.
func readSecret(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	defer fmt.Fprintln(os.Stderr)

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		line, err := term.ReadPassword(fd)
		if err != nil {
			return "", fmt.Errorf("prompt: %w", err)
		}
		return string(line), nil
	}

	line, err := stdin.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("prompt: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
