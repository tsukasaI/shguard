#!/usr/bin/env bash
# lefthook pre-push entry point (`use_stdin: true`) for every guard that needs
# git's pre-push stdin (`<local_ref> <local_sha> <remote_ref> <remote_sha>` per
# line). lefthook's docs (docs/configuration/use_stdin.md) say: "With many
# commands or scripts having `use_stdin: true`, only one will receive the data.
# The others will have nothing." A second use_stdin job would silently starve
# one guard and let it pass on empty input (fail-open), so this script is the
# single stdin consumer: it reads the refs once and replays them to each guard.
#
# Runs check-up-to-date.sh first and stops at its first failure, so the
# expensive nix build in release-nix-build.sh only starts for a branch that is
# already based on origin/main.
set -euo pipefail

scripts_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

refs=$(cat)

printf '%s\n' "$refs" | bash "$scripts_dir/check-up-to-date.sh"
printf '%s\n' "$refs" | bash "$scripts_dir/release-nix-build.sh"
