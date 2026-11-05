# CSTK AI Analyst

CSTK AI Analyst is an original, provider-neutral terminal client for defensive
security analysis. Its Textual interface uses an operator-selected
OpenAI-compatible endpoint and includes no autonomous shell, browser, exploit,
phishing, cracking, persistence, or file-discovery tools.

## Safety properties

- Remote providers require HTTPS; HTTP is accepted only on loopback.
- Keys are read from an operator-selected environment variable and are never
  stored in provider profiles.
- Redirects are refused and responses are limited to 4 MiB.
- Provider error bodies are not displayed because they may echo credentials or
  engagement data.
- Only typed text and explicitly expanded `@` context are transmitted.
- Changing provider or model clears outbound conversation history.
- Real engagement context is withheld unless the phase-two record is active.
- Questionnaire and engagement proposals are review-only candidates tied to an
  immutable base revision and SHA-256; AI output cannot authorize activity.

## Interface

Type `/` to discover commands, `@` to discover explicit context references, or
press `Ctrl+K` for the action palette. The interface continuously displays the
provider/model and engagement safety status. Below 105 columns it collapses the
side rails but retains the compact status strip.

Useful engagement commands:

```text
/engagement list
/engagement use ID
/engagement show
/engagement progress
/engagement next
/engagement answer TARGET_LIST example.test
```

Run `/setup` for a guided form with validation. It saves non-secret connection
metadata and opens a separate masked credential prompt when needed. Saved
profiles load automatically on launch. The form accepts OpenAI-compatible chat
APIs; providers using another protocol require a transport adapter. Setup sends
no network request.

Provider examples:

```text
/provider Local http://127.0.0.1:11434/v1 model-name
/provider Hosted https://provider.example/v1 model-name CSTK_AI_KEY
/credential CSTK_AI_KEY
```

`/credential` opens a password-style field. The key is held only in the
analyst process, is never displayed or saved, and is removed when the TUI
exits. This is the recommended path when `sudo` has removed the caller's
environment variables.

## Development tests

From this directory, using a Python environment containing Textual:

```bash
PYTHONPATH=. python -m unittest discover -s tests -v
python -m py_compile *.py
```

The tests are offline and do not contact a provider.

## Reproducible package build

Build outside the repository so generated PyInstaller files are not mixed with
auditable sources:

```bash
PYTHONPATH=/usr/lib/python3/dist-packages \
  /path/to/textual/python -m PyInstaller \
  --clean --noconfirm Etc_cstk_ai.spec \
  --distpath /tmp/cstk-ai-dist --workpath /tmp/cstk-ai-build
```

The spec bundles the policy engine and mandatory questionnaire. PyInstaller and
UPX packaging are not encryption; this source remains authoritative.

## Guided completion in the engagement manager

Main menu G → F resumes only missing activation requirements in a saved draft.
The policy CLI also accepts `--root /path/to/Engagements resume NAME_OR_ID`.
The wizard lives in engagement_wizard.py, saves immutable draft revisions through
the existing policy API, and never activates a record. Each completed answer or
record is saved; `:later`, EOF and Ctrl+C preserve earlier completed steps. A
conflicting revision written by another session stops the save rather than
replacing its answers. The existing testing-test record was inspected read-only;
no permission document or fingerprint was invented for it.

Rebuild only the affected packaged manager (the reporting executable is unchanged):

```bash
bash scripts/tools/build_engagement_reporting.sh /absolute/build-env/bin/python --engagement-only
```

The build records source/binary checksums in ENGAGEMENT_BUILD.json. The optional
AI chat questionnaire still captures review candidates separately; its answers
do not silently become scope authorization. Completion key F is an interactive
menu key, not a new global cstk flag, so shell option completion is unchanged.
