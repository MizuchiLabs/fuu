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
  keys this machine accepts. Kept outside the vault file on purpose.
- **The hook.** `fuu env` output eval'd by your shell at every prompt.

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
contains becomes the pinned baseline, like ssh known_hosts. Take the first
clone from a source you trust.

If you knowingly replace the vault, `fuu trust` pins the new signers. A
replacement that carries no signature is pinned with a warning that nothing
could be verified, then `fuu sign` stamps it when this machine is one of its
devices. Without that stamp every read keeps failing.

A valid pinned signature moves the pins with the device registry it vouched
for. A device enrolled from an enrolled machine becomes trusted here, a
revoked one stops verifying once the revocation reaches you.

Still possible: rollback. An older correctly signed vault is still correctly
signed, so someone with write access to the git remote can revert the file
and resurrect a revoked device with the secrets as of that commit. Run
`fuu rotate` when you revoke, that changes the vault key and leaves the old
wraps worthless.

## Someone can write your config dir

The trust file holds the pinned signers. Write access there means the ability
to trust any signer, which is as good as vault write access. The file sits
next to your other shell and git config with the same protection.

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
weakened by an editor. The rest is passphrase length.

## The chip

No TPM, no fuu. There is no software fallback, the chip is the point. Control
of the TPM device file on a running machine is the access control for both
keys, which is the same trust level as everything else on that machine.

## Reporting

Open a private security advisory on GitHub, or a regular issue for anything
you consider low stakes.
