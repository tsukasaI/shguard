#!/usr/bin/env bash
# Pre-push guard, invoked by pre-push-refs.sh (the single lefthook
# `use_stdin: true` job) with git's pre-push stdin: before a chore/release-*
# branch is pushed, run the Nix build of the exact commit being pushed.
#
# Why: the Darwin nix sandbox denies /Users (EPERM), so a test that depends on
# the host filesystem passes `cargo test` and still fails the nix checkPhase
# (#779). This is the only nix build before the release PR merges;
# `release.yaml` re-runs it on the tagged commit and stays the fail-closed
# gate.
#
# Reads git's pre-push stdin (`<local_ref> <local_sha> <remote_ref>
# <remote_sha>` per line). Only pushes whose remote ref matches
# refs/heads/chore/release-* are checked; every other ref, tag push and branch
# deletion is skipped silently. Builds `git+file://<toplevel>?rev=<sha>`, not
# the working tree, so uncommitted edits can neither mask nor cause a failure.
# Fails closed: a release push without `nix` on PATH, or with nix not running
# sandbox = true and sandbox-fallback = false, is refused.
set -euo pipefail

zero_sha=0000000000000000000000000000000000000000

while read -r local_ref local_sha remote_ref _remote_sha; do
  [[ -n "${local_ref:-}" ]] || continue
  [[ "${remote_ref:-}" == refs/heads/* ]] || continue
  [[ "$local_sha" != "$zero_sha" ]] || continue
  [[ "$remote_ref" == refs/heads/chore/release-* ]] || continue

  if ! command -v nix >/dev/null 2>&1; then
    echo "release-nix-build: nix is required to push $remote_ref but was not found on PATH." >&2
    exit 1
  fi

  # Darwin nix defaults to no sandbox, which would let the #779 class pass;
  # `--option sandbox true` is ignored by the daemon for untrusted users.
  if ! sandbox=$(nix config show sandbox 2>/dev/null) ||
    ! sandbox_fallback=$(nix config show sandbox-fallback 2>/dev/null); then
    echo "release-nix-build: cannot read nix config (needs nix >= 2.20 with nix-command); refusing to push $remote_ref." >&2
    exit 1
  fi
  if [[ "$sandbox" != "true" || "$sandbox_fallback" != "false" ]]; then
    echo "release-nix-build: nix must run with sandbox = true and sandbox-fallback = false (see docs/distribution.md); refusing to push $remote_ref." >&2
    exit 1
  fi

  toplevel=$(git rev-parse --show-toplevel)
  if [[ ! "$toplevel" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    echo "release-nix-build: repo path '$toplevel' contains characters outside [A-Za-z0-9._/-] that the git+file:// URL cannot carry; refusing to push $remote_ref." >&2
    exit 1
  fi
  # No --rebuild: flake.nix's `src = ./.` makes every tree change (a release
  # always bumps the version) a new derivation, so a cache hit means this exact
  # tree was already built and checked under the same daemon config.
  if ! nix build -L --no-link "git+file://${toplevel}?rev=${local_sha}" </dev/null; then
    echo "release-nix-build: nix build of $local_sha ($local_ref) failed; fix it before pushing $remote_ref." >&2
    exit 1
  fi
done
