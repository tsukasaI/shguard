//! The only place a test may spawn the `shguard` binary (enforced by
//! `clippy.toml`), so no test can inherit the host's config or HOME.

#![allow(clippy::expect_used)]

use assert_cmd::Command;

/// A `shguard` command with every host-dependent variable removed. Tests that
/// need one of them set it explicitly afterwards.
pub fn shguard() -> Command {
    // Not `Command::cargo_bin` at the call sites: each one would have to
    // remember this scrub, and a forgotten one passes on a bare CI runner but
    // fails under a nix build or on a developer machine with real config.
    #[allow(clippy::disallowed_methods)]
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    cmd.env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env_remove("SHGUARD_STRICT_CONFIG")
        .env_remove("SHGUARD_TEST_PANIC")
        .env_remove("SHGUARD_TEST_MEM_LIMIT_MB")
        .env_remove("RUST_BACKTRACE");
    cmd
}
