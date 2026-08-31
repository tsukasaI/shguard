//! `shguard init` (issue #112): scaffolds a starter config at the same
//! path `Policy::load` would discover, refusing to overwrite an existing
//! file without `--force` — via the real binary with controlled env vars,
//! the same env-isolation pattern `tests/check_config.rs` uses (mutating
//! process env in a unit test is test-unsafe under parallel `cargo test`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn run_init(args: &[&str], envs: &[(&str, &str)]) -> assert_cmd::assert::Assert {
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    cmd.arg("init")
        .args(args)
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.assert()
}

#[test]
fn writes_a_loadable_config_to_a_fresh_path() {
    let dir = tempdir().expect("tempdir should create");
    let config_path = dir.path().join("nested").join("config.toml");
    let assert = run_init(&[], &[("SHGUARD_CONFIG", config_path.to_str().unwrap())]).success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains(config_path.to_str().unwrap()));

    let contents = fs::read_to_string(&config_path).expect("config file should have been written");
    assert!(contents.contains("shguard user config"));
    // The whole embedded blocklist reference is comment-only: no line
    // apart from the header/example comments is a real, active TOML
    // table -- this is the one property `--check-config` alone can't
    // verify since a comment-only file trivially has no findings either
    // way, so assert it directly.
    for line in contents.lines() {
        assert!(
            line.is_empty() || line.starts_with('#'),
            "every line must be a comment or blank, found: {line:?}"
        );
    }
}

#[test]
fn scaffolded_config_loads_cleanly_via_check_config() {
    let dir = tempdir().expect("tempdir should create");
    let config_path = dir.path().join("config.toml");
    run_init(&[], &[("SHGUARD_CONFIG", config_path.to_str().unwrap())]).success();

    Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .arg("--check-config")
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env("SHGUARD_CONFIG", &config_path)
        .assert()
        .success();
}

#[test]
fn refuses_to_overwrite_an_existing_file_without_force() {
    let dir = tempdir().expect("tempdir should create");
    let config_path = dir.path().join("config.toml");
    fs::write(&config_path, "# pre-existing user content\n").expect("seed file should write");

    run_init(&[], &[("SHGUARD_CONFIG", config_path.to_str().unwrap())])
        .failure()
        .code(1);

    let contents = fs::read_to_string(&config_path).expect("file should still exist");
    assert_eq!(contents, "# pre-existing user content\n");
}

#[test]
fn force_overwrites_an_existing_file() {
    let dir = tempdir().expect("tempdir should create");
    let config_path = dir.path().join("config.toml");
    fs::write(&config_path, "# pre-existing user content\n").expect("seed file should write");

    run_init(
        &["--force"],
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    )
    .success();

    let contents = fs::read_to_string(&config_path).expect("file should exist");
    assert!(contents.contains("shguard user config"));
}

#[test]
fn unexpected_argument_is_a_usage_error() {
    let dir = tempdir().expect("tempdir should create");
    let config_path = dir.path().join("config.toml");
    run_init(
        &["--bogus"],
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    )
    .failure()
    .code(2);
    assert!(!config_path.exists());
}

/// `init` never touches stdin -- pins that it doesn't hang or misbehave
/// if given a Bash-hook-shaped stdin payload it should ignore entirely.
#[test]
fn ignores_stdin() {
    let dir = tempdir().expect("tempdir should create");
    let config_path = dir.path().join("config.toml");
    Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .arg("init")
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env("SHGUARD_CONFIG", &config_path)
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"echo hi"}}"#)
        .assert()
        .success();
    assert!(config_path.exists());
}
