#!/usr/bin/env bash
# lefthook pre-push guard: refuse to push a branch that is not based on the
# current origin/main. PRs land via a server-side squash merge that no local
# hook ever sees, so the pre-push test run only vouches for what lands on
# main if HEAD already contains origin/main. Fails closed: a failed fetch
# (offline, auth) refuses the push rather than comparing against a stale ref.
set -euo pipefail

if ! git fetch --quiet origin main; then
  echo "check-up-to-date: 'git fetch origin main' failed; refusing to push without a fresh origin/main." >&2
  exit 1
fi

if ! git merge-base --is-ancestor origin/main HEAD; then
  echo "check-up-to-date: HEAD is not based on the latest origin/main; run 'git rebase origin/main' and push again." >&2
  exit 1
fi
