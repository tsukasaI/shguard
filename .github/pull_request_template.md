<!-- What changes and why. Closes #N. -->

## Change

<!-- Files touched and what each change does. -->

## Verification

<!-- Commands run and their results. -->

## P2 audit

<!--
Required when a catalog/*.toml row is added or changed, or when a PR changes
how the loader or kernel reads a row's fields or which heads it accepts
(crates/shguard/src/catalog, crates/shguard-kernel/src; see CLAUDE.md, "Tests
and catalog"); the audit then covers each row the change reads differently.
Goal: find a spelling the row Allows that the real tool
reads as a different or code-running option. One line per spelling tried:

  spelling tried -> what the tool does with it -> shguard decision -> evidence (doc/source/run)

The decision is what a build of shguard returns (hook JSON on stdin). Cover
the spellings listed in CLAUDE.md, "Tests and catalog".

Every spelling here whose decision is not Allow is pinned as a
command-to-decision test (crates/shguard/tests/catalog_*.rs, or
tests/loader.rs for a README recipe).
-->

N/A: no catalog row or loader/kernel row-reading changes
