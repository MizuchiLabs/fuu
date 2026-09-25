# Security

fuu keeps secrets in one TOML file sealed to a TPM chip. There is no server
and no key material on disk, and the file itself is meant to be committed and
passed around in public. This page walks the attack surface: what an attacker
can touch, what it gets them, and where the line is drawn.

## The pieces

- **Vault file.** `.fuu.toml`, plain TOML, one per repository, meant to live in
  public git like a sops file. Holds the sealed values, the device wraps and
  the recovery wrap.
- **Device key.** An ECDH key inside the TPM. The vault key is sealed to it.
- **Recovery passphrase.** The vault key sealed through argon2id.
- **Local pins.** One small file in your config dir
  (`~/.config/fuu/trusted.toml` on Linux), mapping each folder to the
  fingerprint of the vault key it is trusted to hold. Kept outside the vault
  file on purpose.
- **The hook.** `fuu env` output eval'd by your shell at every prompt.

## How the crypto works

One 32 byte vault key does everything, and it is never stored in the clear.

- **Per device.** The vault key is sealed to a device with an ECIES wrap over
  P-256. A fresh ephemeral key per wrap, HKDF-SHA256 over the shared secret
  with both public points bound into the salt, then XChaCha20-Poly1305. Only
  the target chip can open it.
- **Recovery.** The same vault key sealed to your passphrase through argon2id
  at 256 MiB and 3 passes, priced for a GPU farm rather than for a login. The
  cost parameters are constants of the format and are not stored in the file,
  so a hostile file can never ask for cheaper work or for exhausting work.
- **Values.** XChaCha20-Poly1305 under the vault key with a fresh random 24
  byte nonce per write. The plaintext is the name and the value with a NUL
  between them, and the entry's token is bound in as additional data, so a
  body cut from one entry cannot be pasted into another and a name cannot be
  swapped under an old value.
- **Names.** A key name never enters the file in the clear. Each entry is
  addressed by an HMAC token of its name under the vault key, and the name
  itself is sealed inside that entry's own ciphertext. Device names are
  sealed the same way, bound to the device public key, so no outsider can add
  a device entry that opens. The token is stable for the life of the vault
  key, so a diff still shows which entry changed while the name stays out of
  the file.
- **Fingerprint.** An HMAC of a fixed string under the vault key. This is
  what a folder is pinned to, and what `fuu rotate` moves to the new key.

The device key is a deterministic ECC P-256 ECDH primary key derived from
the TPM owner seed, a fixed salt and a fixed template. Nothing is written to
disk, reopening the chip reproduces the same key, and the private half never
exists outside the silicon. `fuu rotate` generates a fresh vault key and
rewraps everything.

## What it protects, and what it does not

**Protects.** Anyone who reads the file without an enrolled chip or your
passphrase gets the format version, the envelopes, the salt, how many entries
there are, which of them are commented out, and roughly how long each one
was. Key names and device names are not among those things. Nothing an
outsider writes is believed: values only open under their own token, device
entries only open if they were sealed under the vault key, and accepting a
vault key this machine has not seen always takes the recovery passphrase.
There is no trust on first use.

**Does not protect.** Someone with write access to the repository can delete
an entry, or revert an entry, or the whole file, to an older value from git
history under the same key. Those bytes still open, and nothing in the design
tells them apart from the newest ones. They can also simply hold back the
newest file. What they cannot do is read anything, invent a value, or get a
vault key wrapped to a machine of their own.

**Cannot protect.** A machine that already read the secrets. If a device is
compromised while enrolled, remove it and then rotate the underlying
credentials at their issuers. `fuu rotate` alone is not enough after a leak,
it only guards what comes next.

## Someone reads the vault file

They learn the format version, the envelopes, the salt, how many entries the
vault holds, which of them are commented out, and roughly how long each one
was. The key names are HMAC tokens that reveal nothing without the vault
key, the names and the device names live inside ciphertext, the values are
sealed, and the vault key exists in the clear nowhere in the file. sops, the
usual tool for a file like this, leaves key names readable. fuu does not. The
token a name maps to is stable, so a public git diff still shows which entry
changed without saying what it is.

## Someone can write the vault file

This is the attacker the sealing is for, and the line is worth being precise
about.

They cannot forge anything. A value body only opens under the token it was
sealed to, a swapped or edited body fails with a tamper error and takes the
whole vault read down with it rather than dropping one key. A device entry
carries a name sealed under the vault key and bound to that device's public
key, so a hand written entry cannot open either. `fuu rotate` and `fuu
device rm` read and authenticate the whole file before a new vault key is
wrapped to anything, which is exactly what stops an injected wrap from
collecting the next key.

What they can do is take away. Deleting an entry, or copying an older body
from git history over a newer one, produces a file that opens cleanly and
says nothing. The pin per folder does not catch that: the vault key did not
change, so neither did its fingerprint. This is the accepted cost of a
signature free format, and it is why `fuu rotate` is the answer to a machine
that burned rather than to a file you suspect was edited.

What the pin is for is the vault key. The moment the key behind a folder
changes, on a rotation elsewhere or on a whole vault swap, the fingerprint
stops matching and fuu refuses to load until you run `fuu trust`. So nobody
can move you onto their own vault quietly.

First contact is not trust on first use. Accepting a vault key this machine
has not seen always takes the recovery passphrase, so the first clone is as
strong as the passphrase the vault owner handed you. A second checkout of a
vault this machine already trusts is the one shortcut: `fuu trust` notices
the same fingerprint pinned to another folder, shows both paths, and one
confirmation pins it without asking for the passphrase again.

`fuu trust` also enrolls this machine while it is at it, which rewrites one
device block and nothing else. Other machines do not have to do anything
about that write. Enrolling does not change the vault key.

## Someone can write your config dir

The pin file maps folders to vault key fingerprints. Write access there means
the ability to point a folder at a different vault key than the one it holds,
which is as good as feeding values into your shell there. The file sits next
to your other shell and git config with the same protection.

## Someone puts a repo on your disk

The hook maps the working directory to the nearest `.fuu.toml` up to the git
root. A clone this machine has never trusted loads nothing, and `fuu trust`
demands the recovery passphrase before it will, which only the vault owner
has. Once a folder is trusted, walking into it loads the vault into your
shell. fuu runs nothing from the repo, but anything you build or run there
inherits the environment. That is a deliberate trade. If you would not paste
a key into a terminal in that folder, do not stand in it while the hook is
active.

## The eval path

`fuu env` output is eval'd by your shell. Key names from the vault must be
plain identifiers, anything else is an error rather than output. Values are
single quoted per shell dialect, with the quote itself escaped.

Names that would be shell configuration rather than a secret cannot be stored
at all. `PROMPT_COMMAND`, `PATH`, `LD_PRELOAD`, `EDITOR` and about fifty
others turn one written vault into code running in your session, so `fuu
set`, `fuu edit` and the vault itself refuse them as not valid names. There
is no such key in a vault to leak into your shell or into `fuu run`'s child.

The bash and zsh hooks ask `fuu env` for POSIX quoting explicitly and the
fish hook for fish quoting, so no inherited variable can switch the dialect
under them. Values with a NUL byte are refused at `fuu set` and `fuu edit`,
the shell would silently drop the byte.

The hook keeps its own state in `FUU_LOADED` and `FUU_STATE`, the names it
loaded and a fingerprint of the folder, file and pin behind them. That is
what makes a refusal one message instead of one per prompt.

The hook announces what it just moved in or out of your shell at the
terminal, names only. Values never appear there, and a state the shell
already holds says nothing.

## The edit buffer

`fuu edit` shows plaintext in a private temp dir, on the per-user runtime dir
where there is one, removed after the editor closes, swap and backup copies
included. An editor with persistent state of its own, vim registers in
viminfo or a central undo dir, keeps a copy outside that directory. That part
is between you and your editor config.

## The command line

A value passed to `fuu set KEY value` sits in the process list and your
shell history. fuu warns when that happens. Pipe the value or leave it out
to be prompted.

## The passphrase

A vault in public is an offline target forever, and the recovery wrap is the
only thing standing in the way. Two things slow an attacker down. The wrap is
sealed through argon2id at 256 MiB and 3 passes, and those parameters are
part of the program rather than of the file, so no editor can quietly weaken
them and no hostile vault can ask for work that exhausts the machine.

After that it is only the passphrase. fuu generates it, always. `fuu init`,
`fuu rotate` and `fuu device rm` mint about 130 bits from `crypto/rand` and
print it once for your password manager, so the strength is a property of the
tool rather than of the person typing.

The passphrase is typed rarely: at `fuu trust` on a machine that is not
enrolled yet, at `fuu trust` when a folder holds a new vault key, and nowhere
else. A wrong one simply fails to open the wrap. It is also the proof behind
onboarding: typing it proves the vault owner handed you the vault, and it is
what enrolls your machine on the way.

## The chip

No TPM, no fuu. There is no software fallback, the chip is the point. fuu
uses exactly three TPM commands. `TPM2_CreatePrimary` derives the device key
from the owner seed, `TPM2_ECDHZGen` performs the ECDH that opens a device
wrap, and `TPM2_FlushContext` drops the handle again. There is no PCR policy
and no auth value, so control of the TPM device file on a running machine is
the access control for the key, the same trust level as everything else on
that machine. Any process of yours that can reach the chip can unseal without
a prompt.

The device key protects against a stolen vault file and a stolen disk image.
Neither carries the private half, it is derived from the TPM owner seed on
every open. It does not protect against anything already running as you.

Nothing is stored on disk, so clearing the TPM or changing its owner seed
makes this machine a stranger to its own vault. The recovery passphrase
brings it back through `fuu trust`.

## In memory

Secrets are plaintext in your shell's environment while a repository is
loaded, that is the product. Inside fuu nothing is zeroed: strings and
garbage collected copies cannot be wiped on demand, so fuu does not pretend
to. A memory dump of a running fuu or of your shell sees what is loaded.

## Reporting

Open a private security advisory on GitHub, or a regular issue for anything
you consider low stakes.
