# CSTK gap ledger

## Baseline

Based on upstream commit f6f535369218328a831c2849a9f14ac2662da9fd, version 3.0.5.
This checkout has private per-user data paths and authenticated integrity updates,
but lacks the Linux audit/DEFENSE changes described in the referenced chat.
Those changes must be reconciled when their source becomes available.

## DEFENSE roadmap

1. Linux Security Audit: prior conversation reports completion; executable absent
   from this baseline. Menu/CLI entry reserved with explicit SKIP when unavailable.
2. Web/TLS Security Assessment: implemented with launcher, frames, help, completion,
   manual, README and install/uninstall integration. Bounded read-only checks and
   per-user reports; 22 loopback/mocked regression tests cover safety and degradation.
   Continued hardening adds severity totals, bounded single-line evidence,
   redirect-origin redaction, cookie-prefix review, CSP framing alternatives,
   Report-Only distinction and duplicate-HSTS findings. Expired certificates,
   interim headers, trailers and port-80 query isolation have explicit tests.
3. File Integrity / IOC Triage: planned, not implemented.

## Assessment limitations

- No authenticated routes or exhaustive cipher enumeration.
- Legacy protocol failures remain inconclusive under local OpenSSL policy.
- Redirects are recorded, never followed; HTTPS destinations require explicit input.
- Nonstandard HTTPS ports do not imply an HTTP counterpart port.
- Header/CSP/cookie findings require application context.
