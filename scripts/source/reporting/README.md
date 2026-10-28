# CSTK encrypted engagement reporting

This component provides encrypted engagement notes and editable deterministic
reports. CSTK integrates it with its existing guarded TCP/HTTP runtime; all
examples use fictional organizations and endpoints. No AI service is contacted.

Open `sudo cstk --report ENGAGEMENT_ID`, or G → B. The root launcher switches to
the engagement owner. T/W run guarded operations in the unlocked process; normal
G → N/W unlock the notebook per run. Capture is mandatory on those routes.
The notebook lives at `Engagements/SLUG/reporting-notebook/notebook.enc`.
Current scope must be explicitly imported after revisions. Closed engagements
can still be reviewed and reported; guarded testing remains scope/state gated.
The standalone executable is at `scripts/bin/cstk-reporting` and can also be used
by the engagement owner directly with an explicit vault path.

## What works

- A separate, versioned set of 22 reporting questions supplements the existing
  in-scope/out-of-scope questionnaire. Existing authorization fingerprints are
  untouched. Client, engagement reference, delivery and retention defaults can
  be copied from an explicitly selected CSTK scope revision.
- Compact encrypted notes, evidence excerpts, activity records and candidate
  findings persist independently of optional diagnostic logging.
- Finding review supports confirmed, false positive, duplicate and excluded
  outcomes, with evidence, impact, validation, remediation, reviewer, and severity
  rationale. Changes to supporting evidence invalidate previous confirmation.
- Manual findings, notes, activities, explicit Web/TLS text imports, and a
  Python capture hook are available. Import is atomic and duplicate sources are
  rejected. Imported findings remain unconfirmed. Imported execution times and
  source authenticity are not independently verified.
- Private Word, PDF, Markdown and hash-manifest report bundles are generated
  without AI. Internal notes and excluded observations are withheld from finding
  details. Positive controls and limitations can be explicitly included.
- Drafts must be reviewed before finalization. Changed notes, altered report
  files, incomplete questions, running activities, unresolved candidates and
  incomplete confirmed findings prevent finalization. Critical findings require
  a recorded notification reference; the tool sends no notification itself.
- Finalized notebooks are frozen until explicitly reopened. Reopening preserves
  historical exports but requires a new draft/review cycle.
- Deletion is a separate action. It checks final-report integrity, legal hold,
  retention and an engagement-specific typed confirmation. An early deletion
  requires an explicit reason. A minimal deletion receipt is retained.

## Quick start

For standalone use, run as the engagement owner without sudo, from this source
directory. Create the parent directory first.
The notebook leaf is created with mode 0700; files use mode 0600.

```bash
mkdir -m 700 "$HOME/cstk-reporting-lab"
../../bin/cstk-reporting questions
../../bin/cstk-reporting --vault "$HOME/cstk-reporting-lab/notebook" init \
  --scope /absolute/path/to/selected-scope-revision.json --revision 1
../../bin/cstk-reporting --vault "$HOME/cstk-reporting-lab/notebook" \
  --soffice /absolute/path/to/soffice shell
```

The selected JSON is the explicit CSTK scope revision, containing engagement_id,
name, client, authorization, and scope.include/scope.exclude. Its original bytes
are fingerprinted. Importing it supplies report context, not authority to run
checks. Use `examples/scope_revision.json` only for a fictional demonstration.

Use a unique passphrase of at least 14 characters, ideally several randomly
selected words. Keep it separately from the notebook. There is no recovery
backdoor. Passphrases are prompted without echo and are not accepted in argv or
environment variables. Status also requires unlocking:

```bash
../../bin/cstk-reporting --vault "$HOME/cstk-reporting-lab/notebook" status
```

Use menu 1 to complete reporting questions, 2 for notes, A for manual activity,
4 for manual findings, 5 for selected Web/TLS imports, 3 for finding review,
N to browse notes, 9 to revise/withdraw notes, 6 for readiness, 7 for a draft,
and 8 to finalize a reviewed draft. C closes interrupted activity records as
error, partial, or skipped; it does not claim a successful test. S records a
newer reporting scope snapshot. R reopens a finalized notebook; K rotates its
passphrase/data key; D explicitly deletes eligible retained notes; X locks/exits.

Report export asks for a private output parent (owned by you, mode 0700). Each
bundle uses a new subdirectory; existing files are never overwritten. Exported
Word/PDF/Markdown files contain decrypted information and require the agreed
secure delivery channel. This tool does not encrypt reports for delivery.

Selected import source files are not encrypted or deleted by importing them.
Source logs/reports remain subject to their original storage policy.

## Dependencies and builds

The included binary targets Linux x86-64 and was built on Kali/glibc 2.43 with
Python 3.14. Older distributions and other architectures require rebuilding;
it is not a universal static portable executable. It includes Python and its
Python dependencies. LibreOffice remains an explicitly selected external
executable for PDF conversion. No report is finalized if conversion fails.

Source installation, in a separate environment:

```bash
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/python -m cstk_reporting questions
```

Python 3.11+ and the versions declared in pyproject.toml are required. For
source tests with PDF validation also install pypdf and lxml. Packaged
interactive smoke tests additionally require pexpect. For a binary
build, install PyInstaller in the build venv and have UPX available on PATH:

```bash
bash build_binary.sh /absolute/build-venv/bin/python /absolute/release/bin
```

The build uses PyInstaller one-file packaging and `upx -9`. No notebook key,
passphrase, example client data or sample vault is bundled into the executable.
Packaging is not encryption. Maintainable source is included in this release.

## Tests and example report

```bash
CSTK_REPORT_SOFFICE=/absolute/path/to/soffice \
  python -m unittest discover -s tests -v
mkdir -m 700 /absolute/private-sample-parent
PYTHONPATH=. python examples/build_sample.py \
  --output /absolute/private-sample-parent/example-report \
  --soffice /absolute/path/to/soffice
```

The compiled executable has an additional end-to-end smoke test:

```bash
python tests/smoke_binary.py --binary /absolute/path/to/cstk-reporting \
  --soffice /absolute/path/to/soffice
```

The example runs note capture, import, human-review fixtures, draft export,
verification and final export without contacting any target. It uses a temporary
fictional notebook and discards that demonstration notebook afterward; normal
finalization retains real notebooks. The report remains editable in Word.
Changes made directly to an exported Word/PDF file invalidate its recorded
hash; update the notebook and regenerate for official reapproval.

See DESIGN.md for storage/security boundaries and INTEGRATION.md for the
guarded capture contract and remaining adapter coverage.
