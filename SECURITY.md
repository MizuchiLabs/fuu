# Security

fuu keeps secrets in one TOML file sealed to a TPM chip. There is no server
and no key material on disk. This page walks the attack surface: what an
attacker can touch, what it gets them, and where the line is drawn.

## The pieces

- **Vault file.** `fuu.toml`, plain TOML, meant to live in a private git repo.
  Holds sealed values, the device registry and a signature over all of it.
- **Device key.** An ECDH key inside the TPM. The vault key is sealed to it.
- **Signing key.** An ECDSA key inside the same TPM. Signs vault contents.
- **Recovery passphrase.** The vault key sealed through argon2id.
- **Local pins.** The trust file in your config dir
  (`~/.config/fuu/pins/` on Linux, one small file per vault), the signing
  keys this machine accepts and the ones it has revoked for good. Kept
  outside the vault file on purpose.
- **The hook.** `fuu env` output eval'd by your shell at every prompt.

## How the crypto works

One 32 byte vault key does everything, and it is never stored in the clear.

- **Per device.** The vault key is sealed to a device with an ECIES wrap over
  P-256. A fresh ephemeral key per wrap, HKDF-SHA256 over the shared secret with
  both public points bound into the salt, then XChaCha20-Poly1305. Only the
  target chip can open it.
- **Recovery.** The same vault key sealed to your passphrase through argon2id.
  The cost parameters are stored alongside so a future version can still read
  it. This is also what lets a new machine enroll itself.
- **Values.** XChaCha20-Poly1305 under the vault key with a fresh random 24 byte
  nonce per write.

The device key is a deterministic ECC P-256 ECDH primary key derived from the
TPM owner seed, a fixed salt and a fixed template. Nothing is written to disk,
reopening the chip reproduces the same key, and the private half never exists
outside the silicon. `fuu rotate` generates a fresh vault key and rewraps
everything.

## What it protects, and what it does not

**Protects.** Anyone who reads the file without an enrolled chip or your
passphrase gets nothing but names. Nothing an outsider writes passes
verification, not weakened argon2id parameters, not a signing key of their own
added alongside your devices, and not a revoked device riding an old copy of
the file back in.

**Does not protect.** First contact, whatever the first clone carries becomes
the pinned truth. Rolling values back, an older correctly signed vault is still
correctly signed and gives you the secrets as of that commit. `fuu rotate`
guards what comes next and does not bring a rolled back file up to date.

**Cannot protect.** A machine that already read the secrets. If a device is
compromised while enrolled, revoke it and then rotate the underlying
credentials at their issuers. `fuu rotate` alone is not enough after a leak, it
only guards what comes next.

## Someone reads the vault file

They learn project names and key names, nothing more. Values are sealed under
the vault key, and the vault key exists in the clear nowhere in the file.

## Someone can write the vault file

This is the attacker the signature exists for. Every read and every mutation
checks the signature against signing keys pinned on this machine, never
against keys read out of the file being checked. A rewritten vault that adds
a new signing key and self-signs fails, because the new key was never pinned
here.

First contact is trust on first use. Whatever the first clone of a vault repo
contains becomes the pinned baseline, like ssh known_hosts, and fuu prints the
signers it pins so you can check them. Take the first clone from a source you
trust.

If you knowingly replace the vault, `fuu trust` pins the new signers and asks
for the recovery passphrase first. The recovery wrap and this machine's device
wrap must open to the same vault key, so a replacement stitched together from
someone else's wraps cannot pass. `fuu trust` also forgets every revoked
signing key, since a replacement is a new baseline. A replacement that carries
no signature gets pinned with a warning that nothing could be verified, then
`fuu sign` stamps it when this machine is one of its devices, behind the same
passphrase proof and a typed confirmation. Without that stamp every read keeps
failing.

A valid pinned signature moves the pins with the device registry it vouched
for. A device enrolled from an enrolled machine becomes trusted here, a
revoked one stops verifying once the revocation reaches you.

Revocation is sticky per machine. A signing key that leaves the registry is
remembered in the pin file and no copy of the vault brings it back, old copies
included. A replayed file carrying a revoked key is refused outright, so a
burned device cannot sign again after one revert. Only `fuu trust` forgets the
list, or enrolling that key again on this machine. A machine that has not
pulled the revocation yet keeps accepting the old file until it does.

Still possible: rollback of values. An older correctly signed vault is still
correctly signed, so someone with write access to the git remote can revert to
a version whose signers were never revoked and you get the secrets as of that
commit. `fuu rotate` guards what comes next, it rewraps everything under a new
vault key so the old one cannot read new writes, and it does not bring a rolled
back file up to date. Rotate when you revoke, and again after a burn.

## Someone can write your config dir

The trust file holds the pinned signers and the list of revoked ones. Write
access there means the ability to trust any signer and forgive any revocation,
which is as good as vault write access. The file sits next to your other shell
and git config with the same protection.

## Someone puts a repo on your disk

The hook maps the working directory to a project. A `.fuu` file names one,
otherwise the git root's folder name does. Clone a repo, walk in, and your
secrets for that project load into the shell. fuu runs nothing from the repo,
but anything you build or run there inherits the environment. There is no
allow list, that is a deliberate trade. If you would not paste a key into a
terminal in that folder, do not stand in it while the hook is active.

## The eval path

`fuu env` and `fuu print` output is eval'd by your shell. Key names from the
vault must be plain identifiers, anything else is an error rather than
output. Values are single quoted per shell dialect, with the quote itself
escaped.

Names that would be shell configuration rather than a secret never reach the
shell. `PROMPT_COMMAND`, `PATH`, `LD_PRELOAD`, `EDITOR` and about fifty
others turn one written vault into code running in your session, so the hook
prints a comment instead of an export for them. The value stays in the vault
and still works through `fuu run` and `fuu get`, and `fuu set` and `fuu edit`
warn when you store one.

The bash and zsh hooks ask `fuu env` for POSIX quoting explicitly and the fish
hook for fish quoting, so no inherited variable can switch the dialect under
them. Values with a NUL byte are refused at `fuu set` and `fuu edit`, the
shell would silently drop the byte.

## The edit buffer

`fuu edit` shows plaintext in a private temp dir, removed after the editor
closes, swap and backup copies included. An editor with persistent state of
its own, vim registers in viminfo or a central undo dir, keeps a copy outside
that directory. That part is between you and your editor config.

## The command line

A value passed to `fuu set proj:KEY value` sits in the process list and your
shell history. fuu warns when that happens. Pipe the value or leave it out to
be prompted.

## The passphrase

A stolen vault file can be attacked offline through the recovery wrap. The
argon2id parameters are part of the signed content, so they cannot be quietly
weakened by an editor, and unwrap refuses cost parameters outside sane bounds
so a hostile vault cannot exhaust the machine either. The rest is passphrase
length, so new passphrases need at least 12 characters and whitespace alone
does not count. An empty passphrase is refused outright, so nobody can enroll
with a bare newline, and a vault made before that floor needs `fuu rotate`
from an enrolled machine before it can enroll anyone new. The passphrase is
also what proves a replaced vault is really yours when you run `fuu trust` or
bless one with `fuu sign`.

## The chip

No TPM, no fuu. There is no software fallback, the chip is the point. Control
of the TPM device file on a running machine is the access control for both
keys, which is the same trust level as everything else on that machine. Any
process of yours that can reach the chip can unseal and sign without a prompt.

The device keys are derived from the TPM owner seed and nothing is stored on
disk, so clearing the TPM or changing its owner seed makes this machine a
stranger to its own vault. The recovery passphrase brings it back through
`fuu join`.

## In memory

Secrets are plaintext in your shell's environment while a project is loaded,
that is the product. Inside fuu the key and the values are zeroed where Go
allows it, but strings and garbage collected copies cannot be wiped on
demand. A memory dump of a running fuu or of your shell sees what is loaded.

## Reporting

Open a private security advisory on GitHub, or a regular issue for anything
you consider low stakes.
