# Security

fuu keeps a repository's secrets in one TOML file that is meant to live in
public. This page is the source of truth for what that means: the attack
surface, what fuu handles, and what it accepts on purpose.

## The model in three lines

- Anyone can read or write `.fuu.toml`. The sealing is built for that.
- The vault key never exists in the clear. It is sealed to your TPM chips and
  to a recovery passphrase, never stored on disk.
- Your machine is trusted. Anything running as you can use what is loaded,
  the same trust level as your shell config and your git credentials.

## The pieces

- **Vault file.** `.fuu.toml`, one per repository, meant for public git. It
  holds the sealed values, the device wraps and the recovery wrap.
- **Device key.** An ECDH key inside the TPM. The vault key is sealed to it.
- **Recovery passphrase.** A vault in public is an offline guessing target
  forever, and this is the only thing standing in the way. The vault key is
  sealed to it through argon2id. fuu always generates it, about 130 bits from
  `crypto/rand`, and prints it once.
- **Local pins.** One small file in your config dir, mapping each folder to
  the fingerprint of the vault key it is trusted to hold. It lives outside the
  vault on purpose, a trust anchor read from the file it verifies proves
  nothing.
- **The hook.** `fuu env` output eval'd by your shell at every prompt.

## How the sealing works

One 32 byte vault key does everything.

- **Per device.** ECIES over P-256. A fresh ephemeral key per wrap,
  HKDF-SHA256 over the shared secret with both public points bound into the
  salt, then XChaCha20-Poly1305. Only the target chip can open it.
- **Recovery.** The same key sealed to your passphrase through argon2id at
  256 MiB and 3 passes, priced for a GPU farm rather than for a login. The
  cost parameters are constants of the program, not of the file, so a hostile
  vault can never ask for cheaper work or for exhausting work.
- **Values.** XChaCha20-Poly1305 under the vault key, a fresh random 24 byte
  nonce per write. The plaintext is the name and the value with a NUL between
  them, and the entry's token is bound in as additional data, so a body cut
  from one entry cannot be pasted into another and a name cannot be swapped
  under an old value.
- **Names.** A key name never enters the file in the clear. Each entry is
  addressed by an HMAC token of its name under the vault key, and the name
  itself is sealed inside that entry's own ciphertext. Device names are
  sealed the same way and bound to the device public key. The token is stable
  for the life of the vault key, so a diff still shows which entry changed
  while the name stays out of the file.
- **Fingerprint.** An HMAC of a fixed string under the vault key. This is
  what a folder is pinned to and what rotation moves to the new key.

The device key is a deterministic P-256 ECDH primary derived from the TPM
owner seed, a fixed salt and a fixed template. Nothing is written to disk,
reopening the chip reproduces the same key, and the private half never exists
outside the silicon.

## Attack surface

### Someone reads the vault file

Handled. They get the format version, the envelopes, the salt, how many
entries exist, which of them are commented out, and roughly how long each one
was. That is all. Key names and device names live inside ciphertext, values
are sealed, and no vault key appears in the file. sops, the usual tool for a
file like this, leaves key names in the clear. fuu does not.

That readable surface is the whole format:

```toml
version = 1

[recovery]
salt = "..." # 16 random bytes, base64url
wrap = "..." # the vault key, sealed to your passphrase

[device."p256:Bq7mZ..."]
epub = "..." # the ephemeral point of the wrap
wrap = "..." # the vault key, sealed to this device
name = "..." # the device name, sealed under the vault key

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

They cannot forge anything. A value body only opens under the token it was
sealed to, and a swapped or edited body is a tamper error that takes the whole
vault read down rather than dropping one key. A hand written device entry
cannot open either, its name is sealed under the vault key and bound to that
device's public key. `fuu rotate` and `fuu device rm` read and authenticate
the whole file before a new vault key is wrapped to anything, which is exactly
what stops an injected wrap from collecting the next key.

What they can do is take away. Deleting an entry, or copying an older body
from git history over a newer one, produces a file that opens cleanly and
says nothing. The pin does not catch that, the vault key did not change. This
is the accepted cost of a signature free format, and it is why `fuu rotate`
answers a machine that burned rather than a file you suspect was edited.

The pin is for the vault key. The moment the key behind a folder changes, on
a rotation elsewhere or on a whole vault swap, the fingerprint stops matching
and fuu refuses to load until you run `fuu trust`. Nobody can move you onto
their own vault quietly.

First contact is not trust on first use. Accepting a vault key this machine
has not seen always takes the recovery passphrase, so the first clone is as
strong as the passphrase the vault owner handed you. A wrong one simply fails
to open the wrap. You type it at `fuu trust` on a machine that is not
enrolled, or on a folder holding a vault key this machine has not seen, and
nowhere else. A second checkout of a vault this machine already trusts
is the one shortcut: `fuu trust` notices the same fingerprint pinned to
another folder and one confirmation pins this one without asking again.
Enrolling adds one device block and changes no key, so other machines simply
read the new file.

### Someone puts a repo on your disk

Handled. The hook maps your working directory to the nearest `.fuu.toml` up
to and including the git root. A clone this machine has never trusted loads
nothing, and `fuu trust` demands the recovery passphrase before it will. A
vault file over 4 MiB is refused before it is hashed or parsed, so a giant one
cannot stall your prompt. Once a folder is trusted, walking into it loads the
vault into your shell. fuu runs
nothing from the repo, but anything you build or run there inherits the
environment. That is a deliberate trade. If you would not paste a key into a
terminal in that folder, do not stand in it while the hook is active.

### Someone writes your config dir

Accepted. The pin file sits next to your shell and git config with the same
protection. Write access there means pointing a folder at a different vault
key than the one it holds, which is as good as feeding values into your shell
there. A trust anchor has to live somewhere.

### Someone runs as you, or dumps memory

Accepted, and out of scope. There is no PCR policy and no auth value, so
control of the TPM device file on a running machine is the access control for
the key. Any process of yours that can reach the chip can unseal without a
prompt. The device key stops a stolen vault file and a stolen disk image. It
stops nothing already running as you.

Secrets are plaintext in your shell's environment while a repository is
loaded, that is the product. Inside fuu nothing is zeroed: strings and
garbage collected copies cannot be wiped on demand and fuu does not pretend
otherwise. A memory dump of a running fuu or of your shell sees what is
loaded.

### Someone owns an enrolled machine

Out of scope while it lasts. A device that already unsealed the vault key
keeps what it read, so removal is not retroactive. Remove the device, rotate
the vault key, and then rotate the credentials at their issuers. `fuu rotate`
alone is not enough after a leak, it only guards what comes next.

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
device key, `TPM2_ECDHZGen` performs the exchange that opens a device wrap,
and `TPM2_FlushContext` drops the handle again. Nothing is stored on disk, so
clearing the TPM or changing its owner seed makes this machine a stranger to
its own vault. The recovery passphrase brings it back through `fuu trust`.

## Reporting

Open a private security advisory on GitHub, or a regular issue for anything
you consider low stakes.
