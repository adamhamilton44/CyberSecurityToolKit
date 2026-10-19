# Origin and licensing record

Reviewed source: `https://github.com/Mr-Destroyer/ZimZilla`, local commit
`58a175b1008ab6097510b72160ce2b0874a7bec5`.

At review time, neither the local checkout nor the upstream repository exposed a
`LICENSE`, `LICENCE`, `COPYING`, or `NOTICE` file, and `pyproject.toml` declared no
license. Consequently, CSTK must not copy, modify, rebrand, compile, or redistribute
that implementation without a license grant from its copyright owner.

The CSTK implementation was written as a clean-room project using Textual and
the publicly documented OpenAI-compatible chat-completions request shape. It
does not import ZimZilla, depend on its runtime directories, read its
credentials, reproduce its source or assets, or implement its offensive
commands. ZimZilla supplied only broad interface inspiration: terminal panels,
command discovery, and a command palette.

Before release, repeat the upstream license check because the repository may change.
