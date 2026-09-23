# Local CSTK Configuration and Keys

The `etc/` directory stores sensitive files generated locally by CSTK. Its
runtime contents are excluded from Git, except for this guide.

The `etc/keys/` directory may contain:

- public and private key pairs;
- OpenSSL output;
- password hashes and checksums; and
- other user-created cryptographic material.

## Handle this directory carefully

- Never commit private keys, passwords, recovery material, or unredacted
  configuration.
- Share a public key only when you intentionally need another party to use it.
- Keep private files readable only by the intended user or root.
- Store encrypted backups in a separate trusted location.
- Confirm the exact path before deleting or replacing any file.

This directory is separate from `/etc/cstk/`, which contains CSTK's installed
root-only library key and maintenance state. Do not copy that private key into
the repository or pass it on a command line.
