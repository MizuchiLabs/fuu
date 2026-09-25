# Security

fuu keeps secrets in one TOML file sealed to a TPM chip. There is no server
and no key material on disk, and the file itself is meant to be committed and
passed around in public. This page walks the attack surface: what an attacker
can touch, what it gets them, and where the line is drawn.

## The pieces

- **Vault file.** `.fuu.toml`, plain TOML, one per repository, meant to live in
  public git like a sops file. Holds the sealed values, the device wraps, the
  recovery wrap and a signature over all of it.
- **Device key.** An ECDH key inside the TPM. The vault key is sealed to it.
- **Signing key.** An ECDSA key inside the same TPM. Signs vault contents.
- **Recovery passphrase.** The vault key sealed through argon2id.
- **Local pins.** The trust file in your config dir
  (`~/.config/fuu/pins/` on Linux, one small file per vault), the signing
  keys this machine accepts, how far the write counter has advanced and the
  folders it loads the vault from. Kept outside the vault file on purpose.
- **The hook.** `fuu env` output eval'd by your shell at every prompt.

## How the crypto works

One 32 byte vault key does everything, and it is never stored in the clear.

- **Per device.** The vault key is sealed to a device with an ECIES wrap over
  P-256. A fresh ephemeral key per wrap, HKDF-SHA256 over the shared secret
  with both public points bound into the salt, then XChaCha20-Poly1305. Only
  the target chip can open it.
- **Recovery.** The same vault key sealed to your passphrase through argon2id
  at 256 MiB and 3 passes, priced for a GPU farm rather than for a login. The
  cost parameters are stored alongside so a future version can still read
  them. This is also what lets a new machine enroll itself.
- **Values.** XChaCha20-Poly1305 under the vault key with a fresh random 24
  byte nonce per write, bound to their slot as additional data so a body cut
  from one entry cannot be pasted into another.
- **Names.** A key name never enters the file. Each entry is addressed by an
  HMAC token of its name under the vault key, and the names live in the
  encrypted blob next to the device registry. The token is stable for the
  life of the vault key, so a diff still shows which entry changed while the
  name stays out of the file.
- **The signature.** Every write is signed over a canonical byte form of the
  vault, the recovery wrap included, and checked against signing keys pinned
  on this machine. Keys read out of the file being checked are never trust
  anchors.

The device key is a deterministic ECC P-256 ECDH primary key derived from
the TPM owner seed, a fixed salt and a fixed template. Nothing is written to
disk, reopening the chip reproduces the same key, and the private half never
exists outside the silicon. The signing key is derived the same way with its
own salt. `fuu rotate` generates a fresh vault key and rewraps everything.

## What it protects, and what it does not

**Protects.** Anyone who reads the file without an enrolled chip or your
passphrase gets the format version, the vault identity, the write counter,
the envelopes, how many entries there are and roughly how long each one was.
Key names and device names are not among those things. Nothing an outsider
writes passes verification, not weakened argon2id parameters, not a signing
key of their own added alongside your devices, not a copy moved to a folder
this machine does not load that vault from, and not an older copy riding a
write counter this machine has already counted past.

**Does not protect.** First contact, whatever the first clone carries becomes
the accepted baseline the moment you join or trust it. Machines that have not
seen the newer write yet, they accept the state they are handed when they
first accept the vault. `fuu rotate` guards what comes next and does not
bring a rolled back file up to date.

**Cannot protect.** A machine that already read the secrets. If a device is
compromised while enrolled, remove it and then rotate the underlying
credentials at their issuers. `fuu rotate` alone is not enough after a leak,
it only guards what comes next.

## Someone reads the vault file

They learn the format version, the vault identity, the write counter, the
envelopes, how many entries the vault holds and roughly how long each one
was. The key names are HMAC tokens that reveal nothing without the vault key,
the device names sit in the encrypted blob, the values are sealed, and the
vault key exists in the clear nowhere in the file. sops, the usual tool for
a file like this, leaves key names readable. fuu does not. The token a name
maps to is stable, so a public git diff still shows which entry changed
without saying what it is.

## Someone can write the vault file

This is the attacker the signature exists for. Every read and every mutation
checks the signature against signing keys pinned on this machine, never
against keys read out of the file being checked. A rewritten vault that adds
a new signing key and self-signs fails, because the new key was never pinned
here.

First contact is trust on first use. Whatever the first clone of a vault repo
contains becomes the accepted baseline, like ssh known_hosts, so take the
first clone from a source you trust. `fuu join` accepts the vault as part of
enrolling, and `fuu trust` prints the vault identity, the write counter and
the enrolled devices and asks for a typed confirmation before anything is
recorded, so you can see what you are about to accept.

`fuu trust` is the one command that introduces a signing key nobody here has
vouched for. Everything else follows signatures it already accepts. On a
machine that is not enrolled it demands the recovery passphrase first and
proves the recovery wrap before granting anything, so a replacement stitched
together from someone else's wraps cannot pass.

A valid pinned signature moves the pins forward with the device registry it
vouched for. A device enrolled from an enrolled machine becomes accepted
here, and a device that leaves the registry stops being accepted once the
new file reaches this machine.

Rollback protection is a signed write counter. The counter only moves
forward. A copy older than what this machine has already seen refuses to
load, and so does a copy signed by a key that is no longer accepted here or a
copy from a folder this machine does not load that vault from. No machine
keeps anything else about a device, so removing one and adding it again
later is clean everywhere. Nothing sticks around after a device is gone.

Still possible: rollback against a machine that has not caught up. Someone
with write access to the git remote can revert to an older signed version,
and every machine that has not seen the newer write accepts it when it
arrives. First contact accepts whatever it is handed. `fuu rotate` guards
what comes next, it rewraps everything under a new vault key so the old one
cannot read new writes, and it does not bring a rolled back file up to date.
Rotate when you remove a device, and again after a burn.

## Someone can write your config dir

The pin file holds the accepted signing keys, the write counter and the
folders this vault loads from. Write access there means the ability to trust
any signer and to move the counter, which is as good as vault write access.
The file sits next to your other shell and git config with the same
protection.

## Someone puts a repo on your disk

The hook maps the working directory to the nearest `.fuu.toml` up to the git
root. A clone this machine has never accepted loads nothing. Accepting a
vault is a deliberate step, and the pins are keyed on the vault identity, so
somebody else's vault cannot pose as yours. Once you have accepted a vault,
walking into that folder loads it into your shell. fuu runs nothing from the
repo, but anything you build or run there inherits the environment. That is
a deliberate trade. If you would not paste a key into a terminal in that
folder, do not stand in it while the hook is active.

## The eval path

`fuu env` and `fuu print` output is eval'd by your shell. Key names from the
vault must be plain identifiers, anything else is an error rather than
output. Values are single quoted per shell dialect, with the quote itself
escaped.

Names that would be shell configuration rather than a secret never reach the
shell. `PROMPT_COMMAND`, `PATH`, `LD_PRELOAD`, `EDITOR` and about fifty
others turn one written vault into code running in your session, so the hook
prints a comment instead of an export for them, and `fuu run` keeps them out
of the child's environment the same way. The value stays in the vault and
still works through `fuu get`, and `fuu set` and `fuu edit` warn when you
store one.

The bash and zsh hooks ask `fuu env` for POSIX quoting explicitly and the
fish hook for fish quoting, so no inherited variable can switch the dialect
under them. Values with a NUL byte are refused at `fuu set` and `fuu edit`,
the shell would silently drop the byte.

## The edit buffer

`fuu edit` shows plaintext in a private temp dir, removed after the editor
closes, swap and backup copies included. An editor with persistent state of
its own, vim registers in viminfo or a central undo dir, keeps a copy outside
that directory. That part is between you and your editor config.

## The command line

A value passed to `fuu set KEY value` sits in the process list and your
shell history. fuu warns when that happens. Pipe the value or leave it out
to be prompted.

## The passphrase

A vault in public is an offline target forever, and the recovery wrap is the
only thing standing in the way. Two things slow an attacker down. The wrap is
sealed through argon2id at 256 MiB and 3 passes, and the parameters are part
of the signed content so an editor cannot quietly weaken them. Unwrap also
refuses cost parameters outside sane bounds, so a hostile vault cannot exhaust
the machine either.

After that it is only the passphrase. fuu generates one for you. `fuu init`
and `fuu rotate` mint 128 bits from `crypto/rand` and print it once for your
password manager, so the strength is a property of the tool rather than of the
person typing. `--prompt` brings your own instead. Anything typed there needs
at least 20 characters and at least 6 different ones, which is a floor and not
a guarantee, since a check like this sees length and repetition and cannot
tell a good passphrase from a sentence somebody made up.

The passphrase is typed rarely, at `fuu join` and at `fuu trust` on a machine
that is not enrolled, and nowhere else.

An empty passphrase is refused outright, so nobody can enroll with a bare
newline, and a vault made before that floor needs `fuu rotate` from an enrolled
machine before it can enroll anyone new. The passphrase is also the proof
behind onboarding, `fuu join` opens the recovery wrap with it to accept and
enroll a machine, and `fuu trust` demands it on a machine that is not enrolled.

## The chip

No TPM, no fuu. There is no software fallback, the chip is the point. fuu
uses exactly four TPM commands. `TPM2_CreatePrimary` derives both keys from
the owner seed, `TPM2_ECDHZGen` performs the ECDH that opens a device wrap,
`TPM2_Sign` stamps vault writes, and `TPM2_FlushContext` drops the handles
again. There is no PCR policy and no auth value, so control of the TPM device
file on a running machine is the access control for both keys, the same
trust level as everything else on that machine. Any process of yours that
can reach the chip can unseal and sign without a prompt.

The device keys protect against a stolen vault file and a stolen disk image.
Neither carries the private halves, they are derived from the TPM owner seed
on every open. They do not protect against anything already running as you.

Nothing is stored on disk, so clearing the TPM or changing its owner seed
makes this machine a stranger to its own vault. The recovery passphrase
brings it back through `fuu join`.

## In memory

Secrets are plaintext in your shell's environment while a repository is
loaded, that is the product. Inside fuu the key and the values are zeroed
where Go allows it, but strings and garbage collected copies cannot be wiped
on demand. A memory dump of a running fuu or of your shell sees what is
loaded.

## Reporting

Open a private security advisory on GitHub, or a regular issue for anything
you consider low stakes.
