<p align="center">
<img src="./.github/logo.svg" width="80">
<br><br>
<img alt="GitHub Tag" src="https://img.shields.io/github/v/tag/MizuchiLabs/fuu?label=Version">
<img alt="GitHub License" src="https://img.shields.io/github/license/MizuchiLabs/fuu">
<img alt="GitHub Issues or Pull Requests" src="https://img.shields.io/github/issues/MizuchiLabs/fuu">
</p>

# fuu

TPM-sealed secrets for your shell. One file, no server, no key material on disk.

fuu keeps a repository's environment secrets in one encrypted `fuu.toml` and
loads them into your shell as you move between directories. The file is meant
to be committed and passed around in public, like a sops file. Key names and
values are not readable without the vault key. The key that opens the file is
sealed to a TPM 2.0 chip and never leaves the silicon, so a copied vault file
is useless on any other machine.

## Install

    go install github.com/mizuchilabs/fuu@latest

Needs a TPM 2.0 device. Linux reads /dev/tpmrm0 and falls back to /dev/tpm0,
Windows goes through TBS. There is no software fallback on purpose. The chip is
the point.

## Quick start

    # create the vault in this repository, this machine becomes the first device
    fuu init

    # store some secrets
    fuu set DATABASE_URL postgres://localhost/mydb
    fuu set API_KEY s3cret

    # load them whenever you enter the repository
    eval "$(fuu hook bash)"        # put into .bashrc, .zshrc or config.fish

`fuu init` prints a generated recovery passphrase once, so keep a password
manager to hand. It is the only way to enroll another machine or to recover
from a cleared TPM, and nobody can recover it for you. Have one you like
already? `fuu init --prompt` asks for it instead of generating it.

Commit `fuu.toml`. The file holds no readable secrets, so a public repository
is fine.

Walk into the repository and the two variables appear. Walk out and they are
gone again.

A vault only loads from a folder this machine has accepted. `fuu init` and
`fuu join` accept the folder they run in, so that is the last you hear of it.
Clone the repository somewhere else and the first load there is one
`fuu trust`, after which it is silent again. That gate is the whole reason a
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

`fuu env` and `fuu print` detect fish from `FISH_VERSION` and emit `set -gx`
instead of `export`, so `fuu print | source` works by accident too.
`--shell=posix` or `--shell=fish` forces it.

## How a directory finds the vault

Each repository has one vault, at its `fuu.toml`. From the directory you stand
in, fuu looks for the nearest `fuu.toml` up to and including the git root.
Nothing above the git root is ever reached by walking upwards.

Pass `--vault` or set `FUU_VAULT` to use an explicit file instead.

No vault in the repository means nothing loads and whatever was loaded before
is unloaded.

## Editing the vault

`fuu edit` drops the vault into `$EDITOR` as plain TOML and writes back only
what changed when you save and close.

    API_KEY = "s3cret"
    DATABASE_URL = "postgres://localhost/mydb"

Change a value, add a line to add a key, delete a line to drop a key. Keys you
leave alone are not re-encrypted, and every key keeps its entry in the file,
so a git diff shows exactly which line changed. Any shell with the hook picks
up what you saved at its next prompt, no cd needed.

The buffer is plaintext in a private temporary directory that is removed when
the editor closes, swap and backup copies included. An editor with persistent
state of its own, vim registers in viminfo or a central undo dir, keeps a copy
outside that directory. Disable that per editor if it matters to you.

Nothing is written if the TOML is invalid or if a key name is not a valid
shell variable name. A name that would take over the shell rather than hold a
secret, `PROMPT_COMMAND`, `PATH` and about fifty others, can be stored but the
hook keeps it out of your session. Clearing the buffer is allowed, but only
after a confirmation, since an empty buffer is more often a botched edit than
an intention.

Values with newlines or quotes round trip exactly, the buffer is TOML so
escaping is the library's problem rather than yours. To store one from a file,
pipe it, which also works for values starting with a dash:

    fuu set CERT < cert.pem

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
    fuu whoami             # which device is this machine

A second machine starts with a clone, then runs one command:

    fuu join    # paste the recovery passphrase, accepts the vault and enrolls this machine

The machines that were already in the repository run `fuu trust` once each
after that, because the file is now signed by a key they have not seen yet.

`fuu trust` is also how you accept a vault you knowingly replaced. It prints
the vault identity, the write counter and the enrolled devices, then asks for
a typed confirmation. On a machine that is not enrolled it demands the
recovery passphrase first, so a replacement stitched from someone else's
wraps cannot pass.

Enrolling a machine from an enrolled machine needs no step anywhere else. Run
`fuu device pub` on the new machine, hand its two public keys to
`fuu device add <name> <pub>` on a machine that is already there, and the
accepted signature on that write vouches for the new device on every machine
that reads it.

`fuu device rm` is not retroactive. A device that already unsealed the vault
key keeps what it read. Run `fuu rotate` when a machine actually burned.

Removing a device is clean in both directions. Nothing sticks on any machine.
The removed device stops being accepted the moment the new file arrives, an
older copy of the file is refused because its write counter is behind, and
adding the same device again later needs no cleanup anywhere.

Removing the last device is refused. With no signer left the vault can never
be verified again. A taken name is never reused silently either, `fuu device
add` refuses one that exists.

## The vault file

One `fuu.toml` in the repository, plain TOML, safe to commit to a public git
repo and sync across your machines.

    version = 2
    vaultid = "v_Gk3xQ..."   # the vault identity
    seq = 7                  # the write counter, it only moves forward
    blob = "..."             # key names and device names, encrypted
    sig = "..."              # signature over the canonical contents
    signer = "..."

    [device."p256:Bq7mZ..."]
    pub = "p256:Bq7mZ..."    # ECDH key that wraps the vault key
    epub = "..."
    wrap = "..."             # the vault key, sealed to this device

    [recovery]
    kdf = "argon2id"
    salt = "..."
    mem = 262144
    time = 3
    wrap = "..."             # the vault key, sealed to your passphrase

    [secret]
    Wq4RKx3a9fQm2Zt7 = "..."     # one line per value, under an HMAC token of its name

Without the vault key the file gives up only the format version, the vault
identity, the write counter, the envelopes, how many entries exist and
roughly how long each one was. Key names are not in the file at all. They are
HMAC tokens of the names under the vault key, and the names themselves live
in the encrypted blob with the device registry. sops, the usual tool for a
file like this, leaves key names in the clear, fuu does not.

The token a name maps to is stable, so a git diff still shows which entry
changed without saying which one it is.

`seq` is a signed write counter. A copy of the file older than what this
machine has already seen refuses to load. That is what makes removing and
re-adding a device free of side effects, no machine has to remember anything
extra.

How the crypto works and what it does and does not protect live in
SECURITY.md, the truth for anything crypto related.

## Commands

| command                       | what it does                                            |
| ----------------------------- | ------------------------------------------------------- |
| `fuu init [--prompt]`         | create a vault in this repository and enroll this machine |
| `fuu join`                    | accept this vault and enroll this machine with the recovery passphrase |
| `fuu doctor`                  | report TPM status and what this machine is enrolled in  |
| `fuu whoami`                  | show which enrolled device this machine is              |
| `fuu device ls\|pub\|add\|rm` | manage enrolled devices                                 |
| `fuu set KEY [value]`         | store a secret, reads stdin or prompts when omitted     |
| `fuu unset KEY`               | delete a secret                                         |
| `fuu get KEY`                 | print one value                                         |
| `fuu edit`                    | edit this vault's secrets in your editor                |
| `fuu ls`                      | list the keys in this vault                             |
| `fuu print`                   | print export lines for this vault                       |
| `fuu env`                     | print shell lines loading the vault for the current directory |
| `fuu hook bash\|zsh\|fish`    | the shell hook                                          |
| `fuu run <command> [args...]` | run a command with this vault's secrets in its env      |
| `fuu rotate [--prompt]`       | replace the vault key and rewrap everything             |
| `fuu verify`                  | check the vault signature and what is trusted here      |
| `fuu trust`                   | accept this vault here, after a join or a replacement   |

Every read and every mutation checks the stored signature against this
machine's accepted signing keys and the write counter before anything in the
file is believed. `fuu trust` is the only command that accepts a signing key
nobody here has vouched for yet.
