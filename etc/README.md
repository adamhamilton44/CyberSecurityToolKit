# Local CSTK Program Configuration

The repository `etc/` directory no longer stores user-generated keys. Private
keys, OpenSSL output, password hashes, checksums, and other user-created
cryptographic material belong in `$HOME/.local/share/cstk/Keys/`, which is
owned by the invoking user and uses private permissions.

## Handle key material carefully

- Never commit private keys, passwords, recovery material, or unredacted
  configuration.
- Share a public key only when you intentionally need another party to use it.
- Keep private files readable only by the intended user or root.
- Store encrypted backups in a separate trusted location.
- Confirm the exact path before deleting or replacing any file.

`$HOME/.local/share/cstk/Keys/` is separate from `/etc/cstk/`, which contains CSTK's installed
root-only library key and maintenance state. Do not copy that private key into
the repository or pass it on a command line.
