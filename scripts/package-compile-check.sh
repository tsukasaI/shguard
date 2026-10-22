#!/usr/bin/env bash
# Pre-push guard: build the published package's tests the way crates.io
# consumers get them. `cargo package --no-verify` plus `cargo test --no-run`
# in the unpacked tarball fails when a shipped test needs the `test-support`
# feature, which only the self dev-dependency enables and `cargo publish`
# drops (see the `include` comment in Cargo.toml).
#
# Packages `git archive HEAD`, not the working tree: untracked files such as a
# local scratch test must not leak into the package, and `--allow-dirty` would
# sweep them in. A directory outside a git checkout skips cargo's dirty check.
# Uncommitted edits can neither mask nor cause a failure.
#
# CARGO_TARGET_DIR is a persistent cache under target/ so dependencies compile
# once across pushes; the shguard crate itself rebuilds every run because the
# extraction stamps fresh mtimes (tar -m).
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

# A stale .crate from an earlier version must not satisfy the glob below.
rm -rf "$target_dir/package"

(cd "$work/src" && cargo package --no-verify --offline) ||
  fail "cargo package failed for HEAD."

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

(cd "${unpacked[0]}" && cargo test --no-run --offline) ||
  fail "the published package's tests do not compile; a shipped test likely needs the test-support feature (see the include comment in Cargo.toml)."
