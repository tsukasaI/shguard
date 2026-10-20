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
# Fails closed: a release push without `nix` on PATH, or whose system nix
# config or effective user config (nix.conf and NIX_CONFIG merged) lacks
# sandbox = true and sandbox-fallback = false, is refused.
set -euo pipefail

# Mirrors /etc/nix/nix.conf and its includes as the client sees them; root-only
# daemon config files and the daemon's own launchd environment are not visible
# from here.
system_nix_config() {
  env -u NIX_CONF_DIR NIX_USER_CONF_FILES=/dev/null NIX_CONFIG= \
    nix --extra-experimental-features nix-command config show "$1"
}

effective_nix_config() {
  nix --extra-experimental-features nix-command config show "$1"
}

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
  # Both reads must pass (#802): an untrusted user is governed by the system
  # config, which the user's nix.conf cannot override, while a trusted user or
  # single-user install honours user-level overrides at build time, which only
  # the merged read shows.
  if ! sys_sandbox=$(system_nix_config sandbox) ||
    ! sys_fallback=$(system_nix_config sandbox-fallback) ||
    ! eff_sandbox=$(effective_nix_config sandbox) ||
    ! eff_fallback=$(effective_nix_config sandbox-fallback); then
    echo "release-nix-build: cannot read nix config (needs nix >= 2.20); refusing to push $remote_ref." >&2
    exit 1
  fi
  if [[ "$sys_sandbox" != "true" || "$sys_fallback" != "false" ||
    "$eff_sandbox" != "true" || "$eff_fallback" != "false" ]]; then
    echo "release-nix-build: nix must run with sandbox = true and sandbox-fallback = false in both the system config and your effective user config (see docs/distribution.md); refusing to push $remote_ref." >&2
    exit 1
  fi

  toplevel=$(git rev-parse --show-toplevel)
  if [[ ! "$toplevel" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    echo "release-nix-build: repo path '$toplevel' contains characters outside [A-Za-z0-9._/-] that the git+file:// URL cannot carry; refusing to push $remote_ref." >&2
    exit 1
  fi
  # No --rebuild (a cache hit skips checkPhase): flake.nix's `src = ./.` makes
  # every tree change (releases bump the version) a new derivation, so a hit
  # means this exact tree was built and checked under the same daemon config.
  if ! nix build -L --no-link "git+file://${toplevel}?rev=${local_sha}" </dev/null; then
    echo "release-nix-build: nix build of $local_sha ($local_ref) failed; fix it before pushing $remote_ref." >&2
    exit 1
  fi
done
