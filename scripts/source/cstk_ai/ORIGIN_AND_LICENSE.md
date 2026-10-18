# Origin and licensing record

Reviewed source: `https://github.com/Mr-Destroyer/ZimZilla`, local commit
`58a175b1008ab6097510b72160ce2b0874a7bec5`.

At review time, neither the local checkout nor the upstream repository exposed a
`LICENSE`, `LICENCE`, `COPYING`, or `NOTICE` file, and `pyproject.toml` declared no
license. Consequently, CSTK must not copy, modify, rebrand, compile, or redistribute
that implementation without a license grant from its copyright owner.

`cstk_ai.py` was written as a clean-room implementation using Python's standard library
and the publicly documented shape of an Anthropic-compatible Messages request. It does
not import ZimZilla, depend on its runtime directories, read its credentials, reproduce
its TUI, or implement its offensive commands.

Before release, repeat the upstream license check because the repository may change.
