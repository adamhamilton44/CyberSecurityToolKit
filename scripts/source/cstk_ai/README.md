# CSTK AI Analyst candidate

This is an original, clean-room CSTK tool candidate. It does not contain or import
ZimZilla code. ZimZilla was used only to identify the broad product idea: a terminal
client that talks to an Anthropic-compatible model endpoint.

The CSTK design is deliberately different:

- defensive analysis only;
- no shell, file-write, browser, phishing, cracking, AD-campaign, exploit, or agent tools;
- no `danger`, `uncensored`, or autonomous execution mode;
- only files explicitly named with `--file` are read;
- secrets are redacted before submission and before optional session storage;
- remote endpoints require HTTPS; HTTP is accepted only on loopback;
- redirects are refused so credentials cannot be forwarded to another host;
- model responses are capped at 4 MiB;
- API keys stay in an environment variable and are never written by this program;
- `--prompt-config` accepts the endpoint and model plus a key through a hidden
  terminal prompt when CSTK's clean
  wrapper intentionally removes the caller's environment;
- transcripts are not saved unless `--save-session` is supplied;
- saved transcripts live at `$XDG_DATA_HOME/cstk/ai/sessions` (normally
  `~/.local/share/cstk/ai/sessions`) with private permissions.

## Dry run without contacting a model

```bash
python3 cstk_ai.py --print-request -f report.txt "Summarize and prioritize these findings"
```

## Local Anthropic-compatible endpoint

```bash
export CSTK_AI_MODEL='your-model-id'
export CSTK_AI_ENDPOINT='http://127.0.0.1:4000/v1/messages'
python3 cstk_ai.py -f report.txt "Explain the evidence and propose remediation"
```

## Hosted endpoint

```bash
export CSTK_AI_MODEL='your-model-id'
export CSTK_AI_ENDPOINT='https://provider.example/v1/messages'
export CSTK_AI_API_KEY='set-this-in-your-shell-or-secret-manager'
python3 cstk_ai.py "Explain this security concept"
```

For the future CSTK menu integration, the client runs with `--prompt-config`. It asks
for an endpoint, model, question, and optional key. Press Enter at the key prompt
when the local endpoint does not require one.

Do not put keys in this README, command history, endpoint URLs, or CSTK source files.

## Test

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
python3 -m py_compile cstk_ai.py
```

## Deferred integration

After protected-file signing is available, integration can add a new CSTK dispatch
option, help frame, installer entry, man-page section, tab completion, compiled candidate,
and checksum-manifest update. Those protected changes are intentionally not part of this
candidate.
