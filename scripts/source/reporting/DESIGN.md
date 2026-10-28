# Notebook and reporting design

## Data model

Each notebook binds to one engagement UUID and explicit reporting snapshots of
scope revisions and source SHA256 fingerprints. Reporting answers never write
scope, action policy, lifecycle authorization, or questionnaire fingerprints in
CSTK. Report finalization is a reporting state, not engagement authorization or
formal client sign-off.

Structured activity summaries record tool, sanitized target, capture times,
source/origin, outcome, scope revision/hash and concise summary. Original raw
stdout, shell commands, environment variables and diagnostic logs are not
captured wholesale. Manual entries and imports are labeled separately from
adapter capture. A capture can be completed, partial, error, skipped or running;
unclosed running captures block finalization.

Notes hold short operator context, evidence, limitations and positive controls.
They are internal by default. Explicitly selected context can appear in the
report; evidence is included through confirmed findings. Evidence excerpts are
limited to 1800 characters per referenced note, with an explicit truncation
notice; full notes remain encrypted. Findings preserve their reviewed severity,
impact, validation, remediation, evidence references and disposition. No severity
or CVSS score is inferred as fact. False positives, excluded and duplicate
observations are counted without exporting their internal evidence as findings.

## Encryption and storage

- Random 256-bit per-notebook data keys; AES-256-GCM authenticated encryption
  with a fresh random 96-bit nonce for each saved snapshot.
- A separate salt and scrypt-derived wrapping key protects the data key under
  the passphrase. Fixed parameters: N=131072, r=8, p=1 (roughly 128 MiB memory).
  Envelope parameters are checked before derivation; arbitrary supplied cost
  parameters are refused.
- Canonical JSON is compressed before encryption. Only ciphertext and public
  format/KDF metadata are stored. The notebook key and passphrase are never
  written to a companion file. A 16 MiB limit bounds input/decompression/storage.
- Associated data binds envelope metadata. Payload and key wrapping are
  authenticated. An encrypted event hash chain records state-transition
  metadata. This is not an external signature, non-repudiation service, or
  rollback-proof journal; someone with the key can rewrite it, and restoring an
  entire older valid notebook cannot be detected without an external anchor.
- Directory components are opened without following symlinks. Notebook leaves
  require current-user ownership and mode 0700; files require mode 0600,
  regular-file type and a single hard link. Locks serialize writers. Saves use
  private encrypted temporary files, fsync and atomic replacement. Interrupted
  saves preserve the prior valid notebook; a killed process may leave encrypted
  pending files, not plaintext note files.
- Passphrase rotation generates a new data key and envelope; previously unlocked
  sessions must unlock again. Backups encrypted with an older passphrase remain
  accessible with that older passphrase.

Encryption protects stored notebooks from unauthorized users lacking the key.
It does not protect unlocked memory, terminal recording, a compromised account,
root, filesystem backups, or a weak guessed passphrase. Python cannot guarantee
key-memory zeroization; CLI core dumps are disabled where supported. Notebook
sizes and modification times remain visible to anyone who can inspect them.
Lost passphrases mean lost access. Protect a tested encrypted backup separately.

Known credential patterns, URL credentials/query/fragment data, private-key
blocks, terminal controls and bidi controls are removed from captured text.
Redaction is heuristic; it cannot recognize every secret or personal identifier.
Only deliberately sanitized, policy-approved evidence should be supplied. Client
requirements that prohibit storage or require a different encryption scheme
must be reviewed before using this prototype.

## Report review and exports

The renderer builds Word and Markdown from the same structured report model;
LibreOffice converts the Word file into PDF using a private temporary profile
and minimal environment. Only an explicitly selected executable is launched;
no shell or external template is evaluated. No target/AI service is contacted.
Report outputs are intentionally plaintext and privately permissioned, and
rendering scratch files are removed. Swap, crash artifacts, backups and external
copies are outside the cleanup guarantee.

A draft records its notebook content digest inside the encrypted notebook and
hashes of DOCX, PDF and Markdown. The public report manifest hashes only the
exported report model and files, not hidden internal notes.
Finalization refuses stale source content, edited/missing artifacts, unresolved
findings, missing reporting answers, missing evidence or required review fields,
running activities, and absent Critical-notification references. It generates a
separate final bundle and freezes notebook edits. It does not send a Critical
notification, deliver a report, attest regulatory compliance, or mark issues fixed.

If notebook registration fails before commit, the exact newly generated report
bundle is removed. If a write happened but durability cannot be confirmed, the
export is retained and the operator is told to reopen and verify status.

Reopening requires a reason and preserves historical exports. Notes can be
withdrawn from reports without deleting the encrypted notebook. Editing evidence
behind a confirmed finding returns it to candidate review. Deletion is never an
automatic consequence of report generation or closing CSTK.

## Retention and deletion

Explicit deletion requires finalized state, verified final artifacts, no legal
hold, an engagement-specific confirmation, and elapsed retention or an explicit
early-deletion reason. It deletes the local encrypted notebook/data-key wrapper
and leaves a minimal receipt containing IDs, time and final-manifest fingerprint,
not client names or findings. Reports remain. Ordinary unlink is not guaranteed
secure erasure on SSDs and does not remove backups, snapshots or old copies.
This local mechanism is not a legal retention or evidence custody service.

## Dependencies reviewed

The implementation uses the established cryptography library rather than a
custom cipher. Primary references:

- [Authenticated encryption](https://cryptography.io/en/latest/hazmat/primitives/aead/)
- [Key derivation and scrypt](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt)

The prototype has local security and workflow tests; it has not received an
independent cryptographic/security audit. Live tool capture integration remains
separate work and must preserve every existing authorization control.
