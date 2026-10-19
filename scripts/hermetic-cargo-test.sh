#!/usr/bin/env bash
# Runs the test suite with the parts of the nix checkPhase's environment that
# tests can observe: HOME=/homeless-shelter and none of the shguard config or
# test-injection variables. A test that leans on the host's ~/.config/shguard
# passes under a plain run and then breaks the nix build (darwin-rebuild).
#
# Mirrors the nix environment, not its profile: the checkPhase runs release
# tests (the `cfg(not(debug_assertions))` gates), this runs debug. Extra
# arguments go to cargo test.
#
# CARGO_HOME and RUSTUP_HOME are pinned to their real locations first, since
# both default to paths under the HOME that is about to be replaced.
set -euo pipefail

exec env \
  -u SHGUARD_CONFIG \
  -u XDG_CONFIG_HOME \
  -u SHGUARD_STRICT_CONFIG \
  -u SHGUARD_TEST_PANIC \
  -u SHGUARD_TEST_MEM_LIMIT_MB \
  -u RUST_BACKTRACE \
  CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
  RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
  HOME=/homeless-shelter \
  cargo test "$@"
