<p align="center">
<img src="./.github/logo.svg" width="80">
<br><br>
<img alt="GitHub Tag" src="https://img.shields.io/github/v/tag/MizuchiLabs/fuu?label=Version">
<img alt="GitHub License" src="https://img.shields.io/github/license/MizuchiLabs/fuu">
<img alt="GitHub Issues or Pull Requests" src="https://img.shields.io/github/issues/MizuchiLabs/fuu">
</p>

# fuu

TPM-sealed secrets for your shell. One file, no server, no key material on disk.

fuu keeps every project's environment secrets in a single encrypted file and
loads them into your shell as you move between directories. The key lives
inside a TPM 2.0 chip and never leaves it, so a copied vault file is useless on
any other machine.

## Install

    go install github.com/mizuchilabs/fuu@latest

Needs a TPM 2.0 device. Linux reads /dev/tpmrm0 and falls back to /dev/tpm0,
Windows goes through TBS. There is no software fallback on purpose. The chip is
the point.

## Quick start

    # create a vault, this machine becomes the first device
    fuu init

    # store some secrets
    fuu set shop:DATABASE_URL postgres://localhost/mydb
    fuu set shop:API_KEY s3cret

    # load them whenever you enter the project
    eval "$(fuu hook bash)"        # put into .bashrc, .zshrc or config.fish

Walk into `~/Projects/shop` and the two variables appear. Walk out and they
are gone again. No `.envrc` in the project and nothing to `allow`.

`fuu run shop -- npm start` does the same thing for a single command with no
shell integration at all.

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

`fuu env` and `fuu print` detect fish from `FISH_VERSION` and emit `set -gx`
instead of `export`, so `fuu print shop \| source` works by accident too.
`--shell=posix` or `--shell=fish` forces it.

## How a directory maps to a project

fuu looks for a project name in two places, first match wins.

1. A `.fuu` file in the directory or any parent. Its single line names the
   project. Add one when the folder name is not the project name.
2. Otherwise the name of the git root directory.

So most repos need no file at all. You only reach for `.fuu` when the checkout
folder drifts from the project, for example a second checkout like
`shop (2)` that should read the `shop` project, or a nested folder that
would otherwise be picked up by name.

If neither matches, nothing loads and whatever was loaded before is unloaded.

## Editing several at once

`fuu edit shop` (or just `fuu edit` inside a repo) drops the project into
`$EDITOR` as plain TOML and writes back only what changed when you save and close.

    API_KEY = "s3cret"
    DATABASE_URL = "postgres://localhost/mydb"

Change a value, add a line to add a key, delete a line to drop a key. Keys you
leave alone are not re-encrypted so they do not churn in git. Any shell with the
hook picks up what you saved at its next prompt, no cd needed.

The buffer is plaintext in a private temporary directory that is removed when
the editor closes, swap and backup copies included. An editor with persistent
state of its own, vim registers in viminfo or a central undo directory, keeps
a copy outside that directory. Disable that per editor if it matters to you.

Nothing is written if the TOML is invalid or if a key name is not a valid
shell variable name. A name that would take over the shell rather than hold a
secret, `PROMPT_COMMAND`, `PATH` and about fifty others, can be stored but the
hook keeps it out of your session. Clearing the buffer is allowed, but only
after a confirmation, since an empty buffer is more often a botched edit than
an intention.

Values with newlines or quotes round trip exactly, the buffer is TOML so
escaping is the library's problem rather than yours. To store one from a file,
pipe it, which also works for values starting with a dash:

    fuu set shop:CERT < cert.pem

A value typed straight onto the command line works too, but it then sits in
the process list and your shell history, so fuu says so and piping or the
prompt is the better habit.

## Devices

A device is one machine's TPM. Each holds its own unexportable key, and the
vault key is sealed to every enrolled device plus your recovery passphrase.

    fuu device ls          # what is enrolled and when
    fuu device pub         # this machine's public keys, for enrollment elsewhere
    fuu device add <name> <pub>
    fuu device rm <name>   # revoke from here on
    fuu whoami             # which entry is this machine

`fuu join` enrolls the machine you are sitting at using the recovery passphrase,
so a new laptop needs no trip to an old one. Paste nothing. New passphrases
need at least 12 characters.

Revoking the last device is refused. With no signer left the vault can never be
verified again. A taken name is never reused silently either, `fuu device add`
refuses one that exists.

`fuu device rm` is not retroactive. A device that already unsealed the vault key
keeps what it read. Run `fuu rotate` when a machine actually burned.

Revocation sticks. The revoked device's signing key is remembered on every
machine that sees the revocation and no copy of the vault brings it back, old
copies included. Only `fuu trust` forgets, or enrolling that machine again
from here.

## The vault file

Point `FUU_VAULT` at it, or pass `--vault`. It is plain TOML, safe to commit to
its own private git repo and sync across your machines.

    version = 1
    sig = "..."        # signature over everything below
    signer = "..."

    [device.laptop]
    created = "2026-09-24"
    signpub = "..."    # ECDSA key that signs the file
    pub = "p256:..."   # ECDH key that wraps the vault key
    epub = "..."
    wrap = "..."       # the vault key, sealed to this device

    [recovery]
    kdf = "argon2id"
    salt = "..."
    mem = 65536
    time = 3
    wrap = "..."       # the vault key, sealed to your passphrase

    [secret.shop]
    DATABASE_URL = "..."   # one line per value, sealed under the vault key

Project names and key names are readable. Values are not. Anyone who can read
the file learns which projects you have and what the variables are called.

How the crypto works and what it does and does not protect live in
SECURITY.md, the truth for anything crypto related.

## Commands

| command                       | what it does                                        |
| ----------------------------- | --------------------------------------------------- |
| `fuu init`                    | create a vault and enroll this machine              |
| `fuu join`                    | enroll this machine with the recovery passphrase    |
| `fuu doctor`                  | TPM status and which device this machine is         |
| `fuu whoami`                  | the name of this device                             |
| `fuu set proj:KEY [value]`    | store a secret, reads stdin or prompts when omitted |
| `fuu edit project`            | edit a whole project's secrets in your editor       |
| `fuu unset proj:KEY`          | delete a secret                                     |
| `fuu get proj:KEY`            | print one value                                     |
| `fuu ls [project]`            | list projects or the keys in one                    |
| `fuu print project`           | shell lines exporting one project                   |
| `fuu env [project]`           | shell lines for the current directory               |
| `fuu hook bash\|zsh\|fish`    | the shell hook                                      |
| `fuu run project -- cmd`      | run a command with the secrets in its env           |
| `fuu rotate`                  | new vault key, rewrap everything                    |
| `fuu sign`                    | stamp an unsigned vault                             |
| `fuu verify`                  | check the stored signature                          |
| `fuu trust`                   | pin the vault's signers after replacing it          |
| `fuu device ls\|pub\|add\|rm` | manage enrolled devices                             |

Every read and every mutation checks the stored signature against this
machine's pinned signers first. `fuu sign` is the one command that stamps
without checking, and only over a vault that was never signed. `fuu trust` is
the one command that re-pins without a prior pinned signature vouching for
the vault.
