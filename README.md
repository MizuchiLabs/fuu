<p align="center">
<img src="./.github/logo.svg" width="80">
<br><br>
<img alt="GitHub Tag" src="https://img.shields.io/github/v/tag/MizuchiLabs/fuu?label=Version">
<img alt="GitHub License" src="https://img.shields.io/github/license/MizuchiLabs/fuu">
<img alt="GitHub Issues or Pull Requests" src="https://img.shields.io/github/issues/MizuchiLabs/fuu">
</p>

# fuu

TPM-sealed secrets for your shell. One passphrase, no server, nothing on disk
that opens without your chip.

fuu keeps a repository's secrets in one encrypted `.fuu.toml` and loads them
into your shell as you move between directories. The file is meant to be
committed and shared in public, like a sops file. Names and values stay sealed
without the vault key. Every vault key derives from your one account, and each
machine keeps that account sealed to its TPM 2.0 chip, so a copied file is
useless anywhere else.

## Install

```bash
go install github.com/mizuchilabs/fuu@latest
```

Needs a TPM 2.0. Linux reads `/dev/tpmrm0` and falls back to `/dev/tpm0`,
Windows goes through TBS. There is no software fallback on purpose, the chip
is the point.

On Linux those device nodes belong to root and the `tss` group, so a plain
user has no access at first. Give yourself the group once, then log out and
back in.

```bash
sudo usermod -aG tss $USER
```

## Quick start

```bash
fuu init      # creates .fuu.toml, and on first use your account
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

The very first `fuu init` offers to start your account and prints its
passphrase once. Keep it in your password manager. It is one passphrase for
every vault you will ever make, the way another machine joins, and the way
back from a cleared TPM. Nobody can recover it for you. Every later
`fuu init` asks nothing. Commit `.fuu.toml`, the file holds no readable
secrets.

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

**Account.** One passphrase per person. Each vault's key derives from it
under that vault's own salt, and each machine keeps it sealed to its own TPM
in your config dir. A new machine types it once:

```bash
fuu login     # the account passphrase, once per machine
```

**Sharing.** Your own account opens every vault you make, so never hand out
its passphrase. Give a group its own account instead. Its vaults open for
whoever has its passphrase, and nothing else of yours does.

```bash
fuu init --account acme    # starts acme on first use and prints its passphrase
fuu login --account acme   # a teammate joins with that passphrase
```

`fuu trust` finds the right account by itself. Rotating one account never
touches the vaults of another, and `fuu logout --account acme` leaves the
group.

**Trust.** A vault only loads from a folder this machine has trusted to hold
it. `fuu init` trusts the folder it runs in, everywhere else it is one
`fuu trust` and a yes. A vault that does not open under your account cannot
be trusted at all, so a stranger's repository cannot hand you values, and one
of your vaults copied into another folder does not load there quietly.

**Rotation.** Pick the one that matches what leaked.

```bash
fuu rotate               # this vault's values leaked: fresh key, same passphrase
fuu rotate --passphrase  # passphrase or a machine lost: new passphrase, every vault moves
```

`--passphrase` prints the new passphrase and reseals every vault of that
account trusted on this machine, add `--account acme` for a group. Commit
them, then on your other machines pull first and run `fuu login` after.
Login moves along any vault that was only checked out there. The lost machine is
left with a seed that opens nothing new, but rotation is never retroactive:
rotate the credentials at their issuers too.

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
| `fuu init [--account]`        | create a vault in this repository, the account on first use   |
| `fuu login [--account]`       | join this machine to an account with its passphrase           |
| `fuu logout [--account]`      | forget every account on this machine, or one                  |
| `fuu trust`                   | load this vault in this folder                                |
| `fuu set KEY [value]`         | store a secret, reads stdin or prompts when omitted           |
| `fuu unset KEY`               | delete a secret                                               |
| `fuu get KEY`                 | print one value                                               |
| `fuu ls`                      | list the keys in this vault                                   |
| `fuu edit`                    | edit this vault's secrets in your editor                      |
| `fuu run <command> [args...]` | run a command with this vault's secrets in its env            |
| `fuu env`                     | print shell lines loading the vault for the current directory |
| `fuu hook bash\|zsh\|fish`    | the shell hook                                                |
| `fuu rotate [--passphrase]`   | fresh vault key, or a new passphrase for an account's vaults  |

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
