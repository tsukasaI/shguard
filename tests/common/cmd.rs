//! Every `cargo_bin` spawn of `shguard` goes through here (`clippy.toml` bans
//! direct calls); a test that needs a `std::process::Command` uses
//! `shguard_std()`, which replays the same env scrub.

#![allow(clippy::expect_used)]

use assert_cmd::Command;

/// A `shguard` command with every host-dependent variable removed. Tests that
/// need one of them set it explicitly afterwards.
pub fn shguard() -> Command {
    // Not `Command::cargo_bin` at the call sites: each one would have to
    // remember this scrub, and a forgotten one passes on a bare CI runner but
    // fails under a nix build or on a developer machine with real config.
    #[expect(
        clippy::disallowed_methods,
        reason = "the single sanctioned cargo_bin call"
    )]
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

/// A `std::process::Command` for `shguard` carrying the same env scrub as
/// [`shguard`], for tests that must spawn without `assert_cmd` (a piped,
/// slowly fed stdin). The scrub is replayed from `shguard().get_envs()`, so a
/// variable added there reaches this command too.
#[allow(dead_code)] // not every test crate that includes this module needs a std command
pub fn shguard_std() -> std::process::Command {
    let base = shguard();
    let mut cmd = std::process::Command::new(base.get_program());
    for (key, value) in base.get_envs() {
        match value {
            Some(value) => cmd.env(key, value),
            None => cmd.env_remove(key),
        };
    }
    cmd
}
