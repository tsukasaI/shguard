//! `shguard --check-config` (issue #208): a one-shot, human-/CI-triggered
//! lint pass over the resolved user config — distinct from the PreToolUse
//! hook path (`tests/hook_io.rs`/`tests/user_config.rs`), which re-loads
//! config on every single invocation and so can't safely surface this same
//! warning itself without spamming stderr on every matching command.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn write_config(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("tempdir should create");
    let path = dir.path().join("config.toml");
    fs::write(&path, contents).expect("config file should write");
    (dir, path)
}

/// Runs `shguard --check-config` with the environment fully reset except
/// for `envs`, mirroring `tests/fail_closed_exit_paths.rs`'s env-isolation
/// pattern — results here must depend only on `envs`, never on whatever
/// config happens to exist on the host machine running the test.
fn run_check_config(envs: &[(&str, &str)]) -> assert_cmd::assert::Assert {
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    cmd.arg("--check-config")
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env_remove("SHGUARD_TEST_PANIC")
        .env_remove("SHGUARD_TEST_MEM_LIMIT_MB");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.assert()
}

#[test]
fn no_config_reports_clean_and_exits_zero() {
    let assert = run_check_config(&[]).success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("no issues found"));
}

#[test]
fn clean_config_with_no_except_targets_reports_clean_and_exits_zero() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-scary-tool"
        reason = "never run this"
        command = "scary-tool"
    "#,
    );
    let assert = run_check_config(&[("SHGUARD_CONFIG", config_path.to_str().unwrap())]).success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("no issues found"));
}

#[test]
fn url_host_alone_reports_clean_and_exits_zero() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-curl-external"
        reason = "block external curl calls"
        command = "curl"
        except_targets = [{ url_host = "localhost" }]
    "#,
    );
    let assert = run_check_config(&[("SHGUARD_CONFIG", config_path.to_str().unwrap())]).success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("no issues found"));
}

#[test]
fn exact_and_prefix_together_without_url_host_reports_clean_and_exits_zero() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-curl-external"
        reason = "block external curl calls"
        command = "curl"
        except_targets = [
            { exact = "http://localhost" },
            { prefix = "http://127.0.0.1" },
        ]
    "#,
    );
    let assert = run_check_config(&[("SHGUARD_CONFIG", config_path.to_str().unwrap())]).success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("no issues found"));
}

// The check is per-rule, not per-config: a `url_host` entry on one rule
// and a `prefix` entry on an unrelated rule must not be flagged just
// because both appear somewhere in the same config file.
#[test]
fn url_host_and_prefix_in_separate_rules_reports_clean_and_exits_zero() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-curl-external"
        reason = "block external curl calls"
        command = "curl"
        except_targets = [{ url_host = "localhost" }]

        [[ask]]
        id = "user-ask-wget-external"
        reason = "confirm external wget calls"
        command = "wget"
        except_targets = [{ prefix = "http://127.0.0.1" }]
    "#,
    );
    let assert = run_check_config(&[("SHGUARD_CONFIG", config_path.to_str().unwrap())]).success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("no issues found"));
}

// The exact repro from the issue: a rule keeps a string-based
// except_targets entry *and* adds a url_host entry alongside it (rather
// than replacing the old entry), which flags on this mechanical
// co-occurrence check regardless of whether the two entries actually
// target the same host — issue #208's own scope: proving same-host intent
// isn't required.
#[test]
fn mixed_url_host_and_prefix_on_a_deny_rule_is_flagged() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-curl-external"
        reason = "block external curl calls"
        command = "curl"
        except_targets = [
            { prefix = "http://localhost:" },
            { url_host = "localhost" },
        ]
    "#,
    );
    let assert = run_check_config(&[("SHGUARD_CONFIG", config_path.to_str().unwrap())])
        .failure()
        .code(1);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(stderr.contains("user-deny-curl-external"));
    assert!(stderr.contains("url_host"));
}

#[test]
fn mixed_url_host_and_exact_on_an_ask_rule_is_flagged() {
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-curl-external"
        reason = "confirm external curl calls"
        command = "curl"
        except_targets = [
            { exact = "http://localhost" },
            { url_host = "localhost" },
        ]
    "#,
    );
    let assert = run_check_config(&[("SHGUARD_CONFIG", config_path.to_str().unwrap())])
        .failure()
        .code(1);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(stderr.contains("user-ask-curl-external"));
}

// `Allowlist` entries share `CommandRule`'s matcher shape, `except_targets`
// included (`Rules::apply_allowlist` reuses `CommandRule::matches`) — the
// same trap applies there, not just on deny/ask rules.
#[test]
fn mixed_url_host_and_prefix_on_an_allow_rule_is_flagged() {
    let (_dir, config_path) = write_config(
        r#"
        [[allow]]
        id = "user-allow-curl-external"
        reason = "trust these curl calls"
        command = "curl"
        except_targets = [
            { prefix = "http://localhost:" },
            { url_host = "localhost" },
        ]
    "#,
    );
    let assert = run_check_config(&[("SHGUARD_CONFIG", config_path.to_str().unwrap())])
        .failure()
        .code(1);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(stderr.contains("user-allow-curl-external"));
}

#[test]
fn multiple_mixed_rules_are_all_reported() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-curl-external"
        reason = "block external curl calls"
        command = "curl"
        except_targets = [
            { prefix = "http://localhost:" },
            { url_host = "localhost" },
        ]

        [[ask]]
        id = "user-ask-wget-external"
        reason = "confirm external wget calls"
        command = "wget"
        except_targets = [
            { exact = "http://localhost" },
            { url_host = "localhost" },
        ]
    "#,
    );
    let assert = run_check_config(&[("SHGUARD_CONFIG", config_path.to_str().unwrap())])
        .failure()
        .code(1);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(stderr.contains("user-deny-curl-external"));
    assert!(stderr.contains("user-ask-wget-external"));
}

#[test]
fn invalid_config_fails_to_load_and_exits_two() {
    let (_dir, config_path) = write_config("this is not valid toml [[[");
    run_check_config(&[("SHGUARD_CONFIG", config_path.to_str().unwrap())])
        .failure()
        .code(2);
}

/// `--check-config` never touches stdin — pins that it doesn't hang or
/// misbehave if given a Bash-hook-shaped stdin payload it should ignore
/// entirely.
#[test]
fn ignores_stdin() {
    let assert = Command::cargo_bin("shguard")
        .expect("shguard binary should build")
        .arg("--check-config")
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env_remove("SHGUARD_TEST_PANIC")
        .env_remove("SHGUARD_TEST_MEM_LIMIT_MB")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"echo hi"}}"#)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("no issues found"));
}
