# Security

fuu keeps a repository's secrets in one TOML file that is meant to live in
public. This page is the source of truth for what that means: the attack
surface, what fuu handles, and what it accepts on purpose.

## The model in three lines

- Anyone can read or write `.fuu.toml`. The sealing is built for that.
- No key exists on disk in the clear. Every vault key derives from one account
  seed, and each machine holds that seed only sealed to its own TPM chip.
- Your machine is trusted. Anything running as you can use what is loaded,
  the same trust level as your shell config and your git credentials.

## The pieces

- **Vault file.** `.fuu.toml`, one per repository, meant for public git. It
  holds a salt, a sealed vault id and the sealed values. Nothing about your
  machines.
- **Account passphrase.** One for your own account, which covers every vault
  you make, and one per group account you share with others. fuu always
  generates it, 128 random bits from `crypto/rand` plus two check characters,
  and prints it once. Through argon2id it becomes the account seed.
- **Account seed.** 32 bytes every vault key derives from. It never touches
  disk in the clear.
- **Device key.** An ECDH key inside the TPM. Each machine keeps its account
  seeds sealed to it in `account.toml` in your config dir, and none of them
  opens on another chip.
- **Local pins.** One small file in your config dir, mapping each folder to
  the account that opens it and the id of the vault it is trusted to hold. It lives outside the vault on
  purpose, a trust anchor read from the file it verifies proves nothing.
- **The hook.** `fuu env` output eval'd by your shell at every prompt.

## How the sealing works

One 32 byte account seed does everything.

- **Account.** `argon2id(passphrase, "fuu/v1/account-seed")` at 256 MiB and 3
  passes, priced for a GPU farm rather than for a login. The salt is a fixed
  string on purpose: a new machine derives the seed from the passphrase alone,
  and since fuu generates the passphrase with 128 bits there is no dictionary
  to precompute. Case, spaces and dashes are ignored, and the check characters
  turn a typo into an error at `fuu login` rather than vaults that will not
  open. The cost parameters are constants of the program, so no file can ask
  for cheaper work or for exhausting work.
- **Per machine.** ECIES over P-256 seals each seed to the device key, with
  the account's name bound in so a seal cannot be moved to another name. A fresh
  ephemeral key per wrap, HKDF-SHA256 over the shared secret with both public
  points bound into the salt and a purpose label as info, then
  XChaCha20-Poly1305. Only that chip opens it.
- **Per vault.** The vault key is HKDF-SHA256 of the account seed under the
  vault's own random 16 byte salt. Nothing is wrapped and nothing about the
  key is stored. A fresh salt is a fresh key.
- **Vault id.** 16 random bytes picked at `fuu init`, sealed under the vault
  key as `check`. It opens only under the right account, so it doubles as the
  proof that the vault is yours, and it survives every rotation. This is what
  a folder is pinned to.
- **Versioning.** One format number covers the vault file, the account file
  and every label above, all of which start with `fuu/v1/`. A breaking change
  bumps it, and nothing sealed under one version opens under another.
- **Values.** XChaCha20-Poly1305 under the vault key, a fresh random 24 byte
  nonce per write. The plaintext is the name and the value with a NUL between
  them, and the entry's token is bound in as additional data, so a body cut
  from one entry cannot be pasted into another and a name cannot be swapped
  under an old value.
- **Names.** A key name never enters the file in the clear. Each entry is
  addressed by an HMAC token of its name under the vault key, and the name
  itself is sealed inside that entry's own ciphertext. The token is stable for
  the life of the vault key, so a diff still shows which entry changed while
  the name stays out of the file.

The device key is a deterministic P-256 ECDH primary derived from the TPM
owner seed, a fixed salt and a fixed template. Nothing about it is written to
disk, reopening the chip reproduces the same key, and the private half never
exists outside the silicon.

**One passphrase is one blast radius.** Whoever holds an account's passphrase
opens every vault of that account, including every version in git history,
because every vault key derives from it. That is the price of not keeping
twenty of them, and it is why fuu generates it rather than letting you pick
one. It is also why sharing goes through a group account: a group account
reaches only its own vaults, and everyone holding its passphrase is trusted
equally. There is no removing one person short of rotating it for everyone.
The vault file does not say which account it belongs to.

## Attack surface

### Someone reads the vault file

Handled. They get the format version, the salt, how many entries exist,
which of them are commented out, and roughly how long each one was. That is
all. Key names live inside ciphertext, values are sealed, and neither a vault
key nor anything about your machines appears in the file. The file is not an
offline guessing target on its own either, a guess has to go through argon2id
for the account seed first. sops, the usual tool for a file like this, leaves
key names in the clear. fuu does not.

That readable surface is the whole format:

```toml
version = 1
salt = "..."  # 16 random bytes, base64url, the vault key is HKDF(account seed, salt)
check = "..." # the vault id, sealed under the vault key

[secret]
Wq4RKx3a9fQm2Zt7 = "..." # one line per value, under an HMAC token of its name

[disabled]
tR9aLm2XwQp4Kd8f = "..." # commented out keys, sealed for their own table
```

The token a name maps to is stable, so a public git diff shows which entry
changed without saying which one it is.

### Someone writes the vault file

Forgery is handled, deletion is accepted. This is the line worth being
precise about.

They cannot forge anything. Without the account seed there is no vault key,
so a hand written `check` or entry does not open. A value body only opens
under the token it was sealed to, and a swapped or edited body is a tamper
error that takes the whole vault read down rather than dropping one key.
`fuu rotate` reads and authenticates the whole file before sealing anything
new. The file holds no key wraps at all, so there is nothing to inject one
into.

What they can do is take away. Deleting an entry, or copying an older body
from git history over a newer one, produces a file that opens cleanly and
says nothing. The pin does not catch that, the vault key did not change. This
is the accepted cost of a signature free format, and it is why `fuu rotate`
answers a machine that burned rather than a file you suspect was edited.

The pin is for the vault id. A rotation keeps the id, so every machine keeps
loading after a pull. What they can do with nothing but your own public files
is copy one of your vaults over another folder's `.fuu.toml`, the one kind of
swap that still opens under your account. The id no longer matches the pin
and fuu refuses to load until you run `fuu trust`, which names the folder the
vault really belongs to.

First contact is not trust on first use. A vault only loads if it opens under
your account, so a stranger's vault never loads at all, and even your own
vault loads in a new folder only after one `fuu trust` confirmation there. A
machine joins the account with `fuu login` and the passphrase, once, not once
per repository.

### Someone puts a repo on your disk

Handled. The hook maps your working directory to the nearest `.fuu.toml` up
to and including the git root. A folder this machine has never trusted loads
nothing, and `fuu trust` refuses any vault that does not open under your
account. A
vault file over 4 MiB is refused before it is hashed or parsed, so a giant one
cannot stall your prompt. Once a folder is trusted, walking into it loads the
vault into your shell. fuu runs
nothing from the repo, but anything you build or run there inherits the
environment. That is a deliberate trade. If you would not paste a key into a
terminal in that folder, do not stand in it while the hook is active.

### Someone writes your config dir

Accepted. The pin file and `account.toml` sit next to your shell and git
config with the same protection. Write access there means pointing a folder at
another of your vaults, or swapping in an account file sealed to your chip
under a seed someone else knows, which is as good as feeding values into your
shell. A copied `account.toml` opens on no other chip. A trust anchor has to
live somewhere.

### Someone runs as you, or dumps memory

Accepted, and out of scope. There is no PCR policy and no auth value, so
control of the TPM device file on a running machine is the access control for
the key. Any process of yours that can reach the chip can unseal the account
seed without a prompt, and with it every vault. The device key stops a stolen
vault file and a stolen disk image. It stops nothing already running as you.

Secrets are plaintext in your shell's environment while a repository is
loaded, that is the product. Inside fuu nothing is zeroed: strings and
garbage collected copies cannot be wiped on demand and fuu does not pretend
otherwise. A memory dump of a running fuu or of your shell sees what is
loaded.

### Someone owns a machine, or learns the passphrase

Out of scope while it lasts. Either one is the account seed, so every vault
and all of its git history. Nothing is retroactive: what was read stays read.
Run `fuu rotate --passphrase` on a machine you still trust. It prints a new
passphrase, reseals every vault trusted on that machine under the new seed,
and leaves the lost machine holding a seed that opens nothing new. Commit the
moved files, run `fuu login` once on each other machine, and it moves any
vault only checked out there along with it. Then rotate the credentials at
their issuers, the old seed still opens the old files in git history.

A single vault's values leaking is smaller: `fuu rotate` in that repository
gives it a fresh key, no new passphrase, and the credentials get rotated at
their issuers as always.

## Smaller surfaces

**The eval path.** `fuu env` output is eval'd by your shell, so key names must
be plain identifiers and anything else is an error rather than output. Names
that would be shell configuration rather than a secret, `PROMPT_COMMAND`,
`PATH`, `LD_PRELOAD`, `EDITOR` and about fifty more, are refused at `fuu set`,
at `fuu edit` and by the vault itself, so no such key can ever leak into your
shell or into `fuu run`'s child. Values are single quoted per shell dialect
and the hook asks for its dialect explicitly, so no inherited variable can
switch it under them. Values with a NUL byte are refused, the shell would
silently drop the byte.

The hook announces what it moved in or out of your shell at the terminal,
names only. Values never appear there. Control bytes are stripped from
anything fuu prints, so a hostile file cannot rewrite your terminal.

**The edit buffer.** `fuu edit` shows plaintext in a private temp dir, on the
per-user runtime dir where there is one, removed when the editor closes, swap
and backup copies included. An editor with persistent state of its own, vim
registers in viminfo or a central undo dir, keeps a copy outside that
directory. That part is between you and your editor config.

**The command line.** A value passed as `fuu set KEY value` sits in the
process list and your shell history. fuu warns when that happens. Pipe the
value or leave it out to be prompted.

**The chip.** No TPM, no fuu. There is no software fallback, the chip is the
point. fuu uses exactly three TPM commands: `TPM2_CreatePrimary` derives the
device key, `TPM2_ECDHZGen` performs the exchange that opens the account
wrap, and `TPM2_FlushContext` drops the handle again. Nothing of the chip is
stored on disk, so clearing the TPM or changing its owner seed makes
`account.toml` unopenable. `fuu login` with the passphrase brings the machine
back.

## Reporting

Open a private security advisory on GitHub, or a regular issue for anything
you consider low stakes.
