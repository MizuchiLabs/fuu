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
    eval "$(fuu hook bash)"        # .bashrc, or .zshrc, or fish

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

`fuu edit shop` drops the project into `$EDITOR` as plain TOML and writes back
only what changed when you save and close.

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
shell variable name. Clearing the buffer is allowed, but only after a
confirmation, since an empty buffer is more often a botched edit than an
intention.

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
    fuu device pub         # this machine's public keys, for enrolment elsewhere
    fuu device add <name> <pub>
    fuu device rm <name>   # revoke from here on
    fuu whoami             # which entry is this machine

`fuu join` enrols the machine you are sitting at using the recovery passphrase,
so a new laptop needs no trip to an old one. Paste nothing.

Revoking the last device is refused. With no signer left the vault can never be
verified again.

`fuu device rm` is not retroactive. A device that already unsealed the vault key
keeps what it read. Run `fuu rotate` when a machine actually burned.

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

## How the crypto works

One 32 byte vault key does everything, and it is never stored in the clear.

- **Per device.** The vault key is sealed to a device with an ECIES wrap over
  P-256. A fresh ephemeral key per wrap, HKDF-SHA256 over the shared secret with
  both public points bound into the salt, then XChaCha20-Poly1305. Only the
  target chip can open it.
- **Recovery.** The same vault key sealed to your passphrase through argon2id.
  The cost parameters are stored alongside so a future version can still read
  it. This is also what lets a new machine enrol itself.
- **Values.** XChaCha20-Poly1305 under the vault key with a fresh random 24 byte
  nonce per write.

The device key is a deterministic ECC P-256 ECDH primary key derived from the
TPM owner seed, a fixed salt and a fixed template. Nothing is written to disk,
reopening the chip reproduces the same key, and the private half never exists
outside the silicon. `fuu rotate` generates a fresh vault key and rewraps
everything.

## What it protects, and what it does not

**Protects.** Anyone who reads the file without an enrolled chip or your
passphrase gets nothing but names. An outsider who edits the file cannot
introduce anything that passes verification, including weakening the argon2id
parameters to make your passphrase crackable offline, and including keeping
your device entry while adding a signing key of their own. That is what the
signature plus local pinning are really for.

The signature is checked against signing keys pinned on this machine, in your
config dir outside the vault file, never against keys read out of the file
being checked. First contact pins the enrolled signing keys, trust on first
use like ssh known_hosts. After that a vault signed by anything else is
rejected. A signature from a pinned key brings the pins along with the device
registry it vouched for, so a device enrolled from an enrolled machine becomes
trusted here and a revoked one stops verifying on the next pull. If you
deliberately replace the vault at the same path, `fuu trust` pins the new
signers. A replacement with no signature gets pinned with a warning, then
`fuu sign` stamps it when this machine is one of its devices.

**Does not protect.** First contact. A vault that is already malicious before
your machine ever sees it becomes the baseline that gets pinned, so take the
first clone of a vault repo from a source you trust. Rolling the file back
stays unprotected too. An older correctly signed vault is still correctly
signed, so someone with write access to your git remote can revert it and
resurrect a revoked device with the secrets as of that commit. `fuu rotate`
when you revoke, that changes the vault key and leaves the old wraps
worthless against anything new.

**Cannot protect.** Making a machine forget what it already read. If a device is
compromised while enrolled it has your secrets, so revoke and then rotate the
underlying credentials at their issuers. `fuu rotate` alone is not enough after
a leak, it only guards what comes next.

## Commands

| command                       | what it does                                        |
| ----------------------------- | --------------------------------------------------- |
| `fuu init`                    | create a vault and enrol this machine               |
| `fuu join`                    | enrol this machine with the recovery passphrase     |
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
