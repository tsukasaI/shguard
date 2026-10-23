#!/usr/bin/env bash
# Pre-push guard: build the published package's tests the way crates.io
# consumers get them (see the `include` comment in Cargo.toml).
#
# Packages `git archive HEAD`, not the working tree: untracked files such as a
# local scratch test must not leak into the package, and `--allow-dirty` would
# sweep them in. A directory outside a git checkout skips cargo's dirty check.
# Uncommitted edits can neither mask nor cause a failure.
#
# CARGO_TARGET_DIR is a persistent cache under target/ so dependencies compile
# once across pushes.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
target_dir="$repo/target/package-check"

fail() {
  echo "package-compile-check: $1" >&2
  exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export CARGO_TARGET_DIR="$target_dir"

mkdir "$work/src" "$work/unpacked"
git -C "$repo" archive HEAD | tar -x -C "$work/src" ||
  fail "could not export HEAD with git archive."

# A .crate left by an earlier version would trip the exactly-one check below after a version bump.
rm -rf "$target_dir/package"

(cd "$work/src" && cargo package --no-verify) ||
  fail "cargo package failed for HEAD."

shopt -s nullglob
crates=("$target_dir"/package/*.crate)
[[ ${#crates[@]} -eq 1 && -f "${crates[0]}" ]] ||
  fail "expected exactly one .crate in $target_dir/package, found ${#crates[@]}."

# -m: cargo package pins every entry's mtime, so without it the cached target
# dir treats the unpacked sources as unchanged and the build passes vacuously.
tar -xmzf "${crates[0]}" -C "$work/unpacked" ||
  fail "could not extract ${crates[0]}."

unpacked=("$work"/unpacked/*/)
[[ ${#unpacked[@]} -eq 1 && -d "${unpacked[0]}" ]] ||
  fail "expected one directory inside the package tarball."

(cd "${unpacked[0]}" && cargo test --no-run) ||
  fail "the published package's tests do not compile (see output above; a shipped test needing the test-support feature is the usual cause)."
