#!/usr/bin/env bash
# lefthook pre-push guard (`use_stdin: true`): refuse to push a branch that is
# not based on the current origin/main. PRs land via a server-side squash merge
# that no local hook ever sees, so the pre-push test run only vouches for what
# lands on main if the pushed commit already contains origin/main.
#
# Reads git's pre-push stdin (`<local_ref> <local_sha> <remote_ref>
# <remote_sha>` per line) and checks each pushed branch's commit, not HEAD.
# Tag pushes and branch deletions are skipped. Compares against FETCH_HEAD so
# the result does not depend on the remote's fetch refspec. Fails closed: a
# failed fetch (offline, auth) refuses the push rather than comparing against
# a stale ref.
set -euo pipefail

zero_sha=0000000000000000000000000000000000000000
fetched=0

while read -r local_ref local_sha remote_ref _remote_sha; do
  [[ -n "${local_ref:-}" ]] || continue
  [[ "$remote_ref" == refs/heads/* ]] || continue
  [[ "$local_sha" != "$zero_sha" ]] || continue

  if [[ "$fetched" -eq 0 ]]; then
    if ! git fetch --quiet origin main; then
      echo "check-up-to-date: 'git fetch origin main' failed; refusing to push without a fresh origin/main." >&2
      exit 1
    fi
    fetched=1
  fi

  if ! git merge-base --is-ancestor FETCH_HEAD "$local_sha"; then
    echo "check-up-to-date: $local_ref is not based on the latest origin/main; run 'git rebase origin/main' and push again." >&2
    exit 1
  fi
done
