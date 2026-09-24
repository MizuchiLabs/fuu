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
    fuu set nimbus:DATABASE_URL postgres://localhost/mydb
    fuu set nimbus:API_KEY s3cret

    # load them whenever you enter the project
    eval "$(fuu hook bash)"        # .bashrc, or zsh, or fish

Walk into `~/Projects/nimbus` and the two variables appear. Walk out and they
are gone again. No `.envrc` in the project and nothing to `allow`.

`fuu run nimbus -- npm start` does the same thing for a single command with no
shell integration at all.

## Shells

| shell | add to your rc file       |
| ----- | ------------------------- |
| bash  | `eval "$(fuu hook bash)"` |
| zsh   | `eval "$(fuu hook zsh)"`  |
| fish  | `fuu hook fish \| source` |

`fuu env` and `fuu print` detect fish from `FISH_VERSION` and emit `set -gx`
instead of `export`, so `fuu print nimbus \| source` works by accident too.
`--shell=posix` or `--shell=fish` forces it.

## How a directory maps to a project

fuu looks for a project name in two places, first match wins.

1. A `.fuu` file in the directory or any parent. Its single line names the
   project. Add one when the folder name is not the project name.
2. Otherwise the name of the git root directory.

So most repos need no file at all. You only reach for `.fuu` when the checkout
folder drifts from the project, for example a second checkout like
`suimon (brew)` that should read the `suimon` project, or a nested folder that
would otherwise be picked up by name.

If neither matches, nothing loads and whatever was loaded before is unloaded.

## Editing several at once

`fuu edit nimbus` drops the project into `$EDITOR` as plain TOML and writes back
only what changed when you save and close.

	API_KEY = "s3cret"
	DATABASE_URL = "postgres://localhost/mydb"

Change a value, add a line to add a key, delete a line to drop a key. Keys you
leave alone are not re-encrypted so they do not churn in git.

The buffer is plaintext in a private temporary directory that is removed when
the editor closes, swap and backup copies included. Nothing is written if the
TOML is invalid, if the buffer would drop every key, or if a key name is not a
valid shell variable name.

Values with newlines or quotes round trip exactly, the buffer is TOML so
escaping is the library's problem rather than yours. To store one from a file,
pipe it, which also works for values starting with a dash:

	fuu set nimbus:CERT < cert.pem

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

    [secret.nimbus]
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
parameters to make your passphrase crackable offline. That last one is what the
signature is really for.

**Does not protect.** Rolling the file back. An older correctly signed vault is
still correctly signed, so someone with write access to your git remote can
revert it and resurrect a revoked device with the secrets as of that commit.
`fuu rotate` when you revoke, that changes the vault key and leaves the old
wraps worthless against anything new.

**Cannot protect.** Making a machine forget what it already read. If a device is
compromised while enrolled it has your secrets, so revoke and then rotate the
underlying credentials at their issuers. `fuu rotate` alone is not enough after
a leak, it only guards what comes next.

## Commands

| command | what it does |
| --- | --- |
| `fuu init` | create a vault and enrol this machine |
| `fuu join` | enrol this machine with the recovery passphrase |
| `fuu doctor` | TPM status and which device this machine is |
| `fuu whoami` | the name of this device |
| `fuu set proj:KEY [value]` | store a secret, reads stdin or prompts when omitted |
| `fuu edit project` | edit a whole project's secrets in your editor |
| `fuu unset proj:KEY` | delete a secret |
| `fuu get proj:KEY` | print one value |
| `fuu ls [project]` | list projects or the keys in one |
| `fuu print project` | shell lines exporting one project |
| `fuu env [project]` | shell lines for the current directory |
| `fuu hook bash\|zsh\|fish` | the shell hook |
| `fuu run project -- cmd` | run a command with the secrets in its env |
| `fuu rotate` | new vault key, rewrap everything |
| `fuu sign` | stamp an unsigned vault |
| `fuu verify` | check the stored signature |
| `fuu device ls\|pub\|add\|rm` | manage enrolled devices |

Every read and every mutation checks the stored signature first. `fuu sign` is
the one command that stamps without checking, and only over a vault that was
never signed.
