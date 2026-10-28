# CSTK reporting integration

The maintained guarded runtime is `scripts/source/cstk_ai/engagement_runtime.py`.
It imports the existing `cstk_engagement` policy and this reporting package.
The root launcher switches to the invoking engagement owner using the existing
run-as-user route. Feature-branch installation is separate from the main checkout.

## Operator workflow

1. Create and authorize the engagement with the existing scope questionnaire.
2. Open G → B, or `cstk --report ID`, to create a private encrypted notebook and
   answer the reporting questions. These answers never modify authorization.
3. T/W inside reporting run guarded TCP/HTTP checks using the unlocked notebook.
   G → N/W unlock the notebook separately for each run. No passphrase is accepted
   in arguments or environment; no background daemon/key service is installed.
4. Review and explicitly import a newer immutable scope snapshot before further
   testing after a scope revision. Declining import still permits old-note review.
5. Review observations, add findings/evidence and reporting context, export a
   draft, review it and finalize. Closed engagements remain available for review;
   the testing guard still refuses inactive/expired/changed authorizations.

## Capture contract

Before DNS/routing/traffic, the runtime binds the notebook UUID and revision/hash
to the selected immutable scope and saves an encrypted pending activity. The
pending target is represented by a fingerprint because it may be excluded.
Recording an attempt does not authorize any network operation.

Every allowed `Guard.decision` must then save a bound encrypted authorization
event before the following connection/request. That decision updates the
activity target only after authorization. Missing, stale, closed, wrong-owner or
unwritable capture stops visibly. Existing guard checks still enforce each
resolved IP, explicit exclusions, source IP, port, action, testing window,
expiry, redirect, rate, cancellation and scope revision. Target connections
remain pinned to checked numeric addresses. A notebook cannot grant permission.

Allowlisted TCP/HTTP results become evidence notes. Headers, cookies, page
bodies, arbitrary stdout, commands and environment variables are not copied.
Open ports and HTTP status codes do not automatically create vulnerabilities.
Failure/cancellation becomes error or partial; crashes can leave an interrupted
activity, which blocks finalization until the operator records its outcome.
Optional diagnostic logging never disables these notebook writes.

Existing private Runs/Audit files remain separate and retain their original
policies. Notebook encryption does not encrypt them or manually imported source
files. Private-data backups include Engagements; updates/uninstall retain it.
Finalization does not delete notes; explicit purge checks final-report hashes,
retention and legal hold. It cannot erase copies held in backups.

## Coverage and verification

Automatic capture covers the guarded TCP and HTTP adapters only. Unsupported
legacy tools remain blocked in engagement mode and need purpose-built adapters.
The explicit historical Web/TLS importer records unverified operator input; it
does not turn the legacy scanner into an engagement-safe tool.

`test_reporting_integration.py` combines real policy and encrypted storage with
substituted transports. `test_scope_regressions.py` covers destination/redirect,
DNS, normalization and policy checks. `smoke_engagement_reporting.py` exercises
the packaged CLI in a private terminal with a denied fixture destination and
real Word/PDF export. No public target is contacted. See VALIDATION.md for the
reviewed test results and deployment limits.

Rebuild both executable entry points from the repository root:

```bash
bash scripts/tools/build_engagement_reporting.sh /absolute/build-venv/bin/python
```

The build includes the unchanged authorization questionnaire as a data resource,
plus python-docx templates and its required physical intermediate directory.
Run installer/runtime synchronization only when deploying the reviewed branch;
its locally generated root-owned integrity manifest must match that checkout.
