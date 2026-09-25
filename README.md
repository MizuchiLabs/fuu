<p align="center">
<img src="./.github/logo.svg" width="80">
<br><br>
<img alt="GitHub Tag" src="https://img.shields.io/github/v/tag/MizuchiLabs/fuu?label=Version">
<img alt="GitHub License" src="https://img.shields.io/github/license/MizuchiLabs/fuu">
<img alt="GitHub Issues or Pull Requests" src="https://img.shields.io/github/issues/MizuchiLabs/fuu">
</p>

# fuu

TPM-sealed secrets for your shell. One file, no server, no key material on disk.

fuu keeps a repository's secrets in one encrypted `.fuu.toml` and loads them
into your shell as you move between directories. The file is meant to be
committed and shared in public, like a sops file. Names and values stay sealed
without the vault key, and that key is sealed to a TPM 2.0 chip, so a copied
file is useless on any other machine.

## Install

```bash
go install github.com/mizuchilabs/fuu@latest
```

Needs a TPM 2.0. Linux reads `/dev/tpmrm0` and falls back to `/dev/tpm0`,
Windows goes through TBS. There is no software fallback on purpose, the chip
is the point.

## Quick start

```bash
fuu init      # creates .fuu.toml, prints a recovery passphrase once
fuu set DATABASE_URL postgres://localhost/mydb
fuu set API_KEY s3cret

eval "$(fuu hook bash)"   # goes into your rc file, see Shells
```

Walk into the repository and the hook loads what it finds, direnv style:

    fuu: loading ~/project/.fuu.toml
    fuu: export +DATABASE_URL +API_KEY

Walk out and they are gone again:

    fuu: unloading -DATABASE_URL -API_KEY

```bash
fuu run npm start   # one command, no shell integration at all
```

Keep the recovery passphrase somewhere safe. It is the only way to enroll
another machine or to recover from a cleared TPM, and nobody can recover it
for you. Commit `.fuu.toml`, the file holds no readable secrets.

## Shells

| shell | add to your rc file       |
| ----- | ------------------------- |
| bash  | `eval "$(fuu hook bash)"` |
| zsh   | `eval "$(fuu hook zsh)"`  |
| fish  | `fuu hook fish \| source` |

Guard the line if your rc file runs where fuu may not be installed:

```bash
command -v fuu >/dev/null 2>&1 && eval "$(fuu hook bash)"
```

## How it fits together

**The vault.** One `.fuu.toml` per repository. fuu looks for the nearest one
up to and including the git root, and never walks above it. Point `--vault` or
`FUU_VAULT` at a file to override.

**Trust.** A vault only loads from a folder this machine has trusted to hold
that vault key. `fuu init` and `fuu trust` trust the folder they run in.
Everywhere else the first load is one `fuu trust` that asks for the recovery
passphrase. There is no trust on first use, so a stranger's repository cannot
hand you values or reach into yours.

**Devices.** A device is one machine's TPM. Each holds its own unexportable
key, and the vault key is sealed to every enrolled device plus your recovery
passphrase. A second machine clones, runs `fuu trust` once, and types the
passphrase.

```bash
fuu device ls          # what is enrolled, this machine marked with *
fuu device rm <name>   # remove a device and rotate the vault key
```

Removing a device cuts it off from future values, not from what it already
read. After a real leak, rotate the credentials at their issuers too.

## Editing

`fuu edit` opens the vault in `$VISUAL` or `$EDITOR` as plain TOML and writes
back only what changed when you save and close. The variable is a
whitespace-separated command and its arguments, there is no shell and no
quoting.

```toml
API_KEY = "s3cret"
DATABASE_URL = "postgres://localhost/mydb"
```

Change a line to change a value, add one to add a key, delete one to drop it.
Comment a line out to disable a key instead. It stays sealed but never loads
into a shell. Keys you leave alone keep their entries, so a git diff shows
exactly which line changed. Nothing is written if the TOML is invalid or a
name is not a valid shell variable name. Names that would configure the shell
itself, `PATH`, `PROMPT_COMMAND` and about fifty others, are refused outright.

Store a value from stdin when it is long or starts with a dash:

```bash
fuu set CERT < cert.pem
```

A value typed straight onto the command line works too, but it then sits in
the process list and your shell history. fuu says so when that happens.

## Commands

| command                       | what it does                                                  |
| ----------------------------- | ------------------------------------------------------------- |
| `fuu init [--name]`           | create a vault in this repository and enroll this machine     |
| `fuu trust [--name]`          | trust this vault in this folder and enroll this machine       |
| `fuu set KEY [value]`         | store a secret, reads stdin or prompts when omitted           |
| `fuu unset KEY`               | delete a secret                                               |
| `fuu get KEY`                 | print one value                                               |
| `fuu ls`                      | list the keys in this vault                                   |
| `fuu edit`                    | edit this vault's secrets in your editor                      |
| `fuu run <command> [args...]` | run a command with this vault's secrets in its env            |
| `fuu env`                     | print shell lines loading the vault for the current directory |
| `fuu hook bash\|zsh\|fish`    | the shell hook                                                |
| `fuu rotate`                  | replace the vault key and rewrap everything                   |
| `fuu device ls\|rm`           | manage enrolled devices                                       |

## Developing

```bash
go test ./...   # tests
task lint       # fmt, vet, govulncheck, tests, golangci-lint
task fuzz       # fuzz the untrusted parsers
```

## Security

What the attack surface is, what fuu handles and what it accepts on purpose
all live in [SECURITY.md](SECURITY.md). It is the truth for anything crypto
related.

## License

Apache 2.0 License - see [LICENSE](LICENSE) for details
