<p align="center">
<img src="./.github/logo.svg" width="80">
<br><br>
<img alt="GitHub Tag" src="https://img.shields.io/github/v/tag/MizuchiLabs/fuu?label=Version">
<img alt="GitHub License" src="https://img.shields.io/github/license/MizuchiLabs/fuu">
<img alt="GitHub Issues or Pull Requests" src="https://img.shields.io/github/issues/MizuchiLabs/fuu">
</p>

# fuu

TPM-sealed secrets for your shell. One file, no server, no key material on disk.

fuu keeps a repository's environment secrets in one encrypted `.fuu.toml` and
loads them into your shell as you move between directories. The file is meant
to be committed and passed around in public, like a sops file. Key names and
values are not readable without the vault key. The key that opens the file is
sealed to a TPM 2.0 chip and never leaves the silicon, so a copied vault file
is useless on any other machine.

## Install

```bash
go install github.com/mizuchilabs/fuu@latest
```

Needs a TPM 2.0 device. Linux reads /dev/tpmrm0 and falls back to /dev/tpm0,
Windows goes through TBS. There is no software fallback on purpose. The chip is
the point.

## Quick start

```bash
# create the vault in this repository, this machine becomes the first device
fuu init

# store some secrets
fuu set DATABASE_URL postgres://localhost/mydb
fuu set API_KEY s3cret

# load them whenever you enter the repository
eval "$(fuu hook bash)"        # put into .bashrc, .zshrc or config.fish
```

`fuu init` prints a generated recovery passphrase once, so keep a password
manager to hand. It is the only way to enroll another machine or to recover
from a cleared TPM, and nobody can recover it for you.

Commit `.fuu.toml`. The file holds no readable secrets, so a public repository
is fine.

Walk into the repository and the hook names what it just put in your shell:

    fuu: /home/you/project/.fuu.toml: +DATABASE_URL +API_KEY

Walk out and they are gone again, and the hook says that too:

    fuu: unloading -DATABASE_URL -API_KEY

A vault only loads from a folder this machine has trusted to hold that vault
key. `fuu init` and `fuu trust` trust the folder they run in, so that is the
last you hear of it. Clone the repository somewhere else and the first load
there is one `fuu trust`, which asks for the recovery passphrase, after which
it is silent again. There is no trust on first use: a vault key this machine
has not seen always needs the passphrase. That gate is the whole reason a
stranger's repository cannot hand you values, or reach into yours.

`fuu run npm start` does the same thing for a single command with no shell
integration at all.

## Shells

| shell | add to your rc file       |
| ----- | ------------------------- |
| bash  | `eval "$(fuu hook bash)"` |
| zsh   | `eval "$(fuu hook zsh)"`  |
| fish  | `fuu hook fish \| source` |

With initialization guards:

```bash
command -v fuu >/dev/null 2>&1 && eval "$(fuu hook bash)" # .bashrc
command -v fuu >/dev/null 2>&1 && eval "$(fuu hook zsh)" # .zshrc

# ~/.config/fish/config.fish
if type -q fuu
    fuu hook fish | source
end
```

The hooks ask `fuu env` for their dialect explicitly, `--shell=posix` for bash
and zsh and `--shell=fish` for fish, and `fuu env` takes either. Nothing
guesses from the environment.

## How a directory finds the vault

Each repository has one vault, at its `.fuu.toml`. From the directory you stand
in, fuu looks for the nearest `.fuu.toml` up to and including the git root.
Nothing above the git root is ever reached by walking upwards.

Pass `--vault` or set `FUU_VAULT` to use an explicit file instead.

No vault in the repository means nothing loads and whatever was loaded before
is unloaded.

## Editing the vault

`fuu edit` drops the vault into `$VISUAL` or `$EDITOR` as plain TOML and
writes back only what changed when you save and close.

```toml
API_KEY = "s3cret"
DATABASE_URL = "postgres://localhost/mydb"
```

Change a value, add a line to add a key, delete a line to drop a key. Keys you
leave alone are not re-encrypted, and every key keeps its entry in the file,
so a git diff shows exactly which line changed. The vault is re-read after the
editor closes and only your changes are applied to it, so a `fuu set` from
another window while you were editing survives. Any shell with the hook picks
up what you saved at its next prompt, no cd needed.

The buffer is plaintext in a private temporary directory, on the per-user
runtime dir where there is one, that is removed when the editor closes, swap
and backup copies included. An editor with persistent state of its own, vim
registers in viminfo or a central undo dir, keeps a copy outside that
directory. Disable that per editor if it matters to you.

Nothing is written if the TOML is invalid or if a key name is not a valid
shell variable name. A name that would take over the shell rather than hold a
secret, `PROMPT_COMMAND`, `PATH` and about fifty others, is refused outright,
in `fuu set` as much as in `fuu edit`. Clearing the buffer is allowed, but
only after a confirmation, since an empty buffer is more often a botched edit
than an intention.

Values with newlines or quotes round trip exactly, the buffer is TOML so
escaping is the library's problem rather than yours. To store one from a file,
pipe it, which also works for values starting with a dash:

```bash
fuu set CERT < cert.pem
```

A value typed straight onto the command line works too, but it then sits in
the process list and your shell history, so fuu says so and piping or the
prompt is the better habit.

## Devices

A device is one machine's TPM. Each holds its own unexportable key, and the
vault key is sealed to every enrolled device plus your recovery passphrase.

```bash
fuu device ls          # what is enrolled, this machine marked with *
fuu device rm <name>   # remove a device and rotate the vault key
```

A second machine starts with a clone, then runs one command:

```bash
fuu trust              # type the recovery passphrase, this machine is enrolled
```

`fuu trust` is the only command that accepts a vault key this machine has not
seen before, and it always takes the recovery passphrase to do it. While it is
at it, it enrolls this machine and trusts this folder to hold that key. A
second checkout in another folder is the one shortcut: `fuu trust` notices the
same vault key is already trusted here and asks one question instead of the
passphrase.

Enrolling a machine needs no step anywhere else. The vault key does not change,
so every other machine simply reads the new file. Removing a device does
change it: `fuu device rm` rotates the vault key after dropping the device, so
the removed machine is cut off from every future value too. Every other
machine then runs `fuu trust` once and types the new passphrase, which is
printed on the machine that did the rotation. Rotation is also the answer to a
machine that burned.

Removing a device is not retroactive. A device that already unsealed the vault
key keeps what it read, so rotate the credentials at their issuers after a
real leak. Removing the last device is refused, and a taken name is never
reused silently, `fuu trust` refuses one that exists.

## The vault file

One `.fuu.toml` in the repository, plain TOML, safe to commit to a public git
repo and sync across your machines.

```toml title=".fuu.toml"
version = 1

[recovery]
salt = "..." # 16 random bytes, base64url
wrap = "..." # the vault key, sealed to your passphrase through argon2id

[device."p256:Bq7mZ..."]
epub = "..." # the ephemeral point of the wrap
wrap = "..." # the vault key, sealed to this device
name = "..." # the device name, sealed under the vault key

[secret]
Wq4RKx3a9fQm2Zt7 = "..." # one line per value, under an HMAC token of its name
```

Without the vault key the file gives up only the format version, the
envelopes, the salt, how many entries exist and roughly how long each one was.
Key names are not in the file at all. Each one is sealed inside its own
entry's ciphertext, addressed by an HMAC token of the name under the vault
key, and device names are sealed the same way. sops, the usual tool for a file
like this, leaves key names in the clear, fuu does not.

The token a name maps to is stable, so a git diff still shows which entry
changed without saying which one it is.

How the crypto works and what it does and does not protect live in
SECURITY.md, the truth for anything crypto related.

## Commands

| command                       | what it does                                                    |
| ----------------------------- | --------------------------------------------------------------- |
| `fuu init [--name]`           | create a vault in this repository and enroll this machine       |
| `fuu trust [--name]`          | trust this vault in this folder and enroll this machine         |
| `fuu set KEY [value]`         | store a secret, reads stdin or prompts when omitted             |
| `fuu unset KEY`               | delete a secret                                                 |
| `fuu get KEY`                 | print one value                                                 |
| `fuu ls`                      | list the keys in this vault                                     |
| `fuu edit`                    | edit this vault's secrets in your editor                        |
| `fuu run <command> [args...]` | run a command with this vault's secrets in its env              |
| `fuu env`                     | print shell lines loading the vault for the current directory   |
| `fuu hook bash\|zsh\|fish`    | the shell hook                                                  |
| `fuu rotate`                  | replace the vault key and rewrap everything                     |
| `fuu device ls\|rm`           | manage enrolled devices                                         |

Nothing loads from a folder this machine has not trusted to hold that vault
key, and the key behind a trusted folder never changes unnoticed: a rotation
elsewhere stops the load until `fuu trust` says otherwise.
