//! End-to-end tests for the user config feature (deny/ask/allow,
//! plan.md §6 item 8): drives the real `shguard` binary with controlled
//! `SHGUARD_CONFIG`/`XDG_CONFIG_HOME`/`HOME` env vars and a real config
//! file on disk. Env vars are set on the *child process* via
//! `assert_cmd::Command::env`/`env_remove` — safe under parallel
//! `cargo test`, unlike `std::env::set_var` (which mutates the whole test
//! process and is `unsafe` in recent Rust editions).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

/// Runs the real binary against `stdin`, with the environment fully reset
/// (no `SHGUARD_CONFIG`/`XDG_CONFIG_HOME`/`HOME` inherited from the host
/// running the test) before applying `envs` — every test controls exactly
/// what shguard sees, regardless of the actual machine's real config.
fn run_hook(stdin: &str, envs: &[(&str, &str)]) -> Value {
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    cmd.env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let assert = cmd.write_stdin(stdin).assert().success();
    let output = assert.get_output();
    serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON")
}

fn bash_command(command: &str) -> String {
    serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "hook_event_name": "PreToolUse",
    })
    .to_string()
}

fn permission_decision(output: &Value) -> &str {
    output["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .expect("permissionDecision should be a string")
}

fn permission_reason(output: &Value) -> &str {
    output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("permissionDecisionReason should be a string")
}

fn write_config(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("tempdir should create");
    let path = dir.path().join("config.toml");
    fs::write(&path, contents).expect("config file should write");
    (dir, path)
}

// ==== Happy path ====

#[test]
fn deny_rule_blocks_matching_command() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-scary-tool"
        reason = "never run this"
        command = "scary-tool"
    "#,
    );

    let output = run_hook(
        &bash_command("scary-tool --run"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
    assert!(permission_reason(&output).contains("user-deny-scary-tool"));
}

#[test]
fn ask_rule_asks_before_matching_command() {
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-gh"
        reason = "confirm every gh invocation"
        command = "gh"
    "#,
    );

    let output = run_hook(
        &bash_command("gh pr view"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("user-ask-gh"));
}

#[test]
fn allow_rule_downgrades_a_matching_structural_ask() {
    let (_dir, config_path) = write_config(
        r#"
        [[allow]]
        id = "user-allow-rm"
        reason = "trust me"
        command = "rm"
    "#,
    );

    // rm -rf $HOME: rule 4's except-target refinement, a genuine
    // per-command structural Ask an allow entry can legitimately clear.
    let output = run_hook(
        &bash_command("rm -rf $HOME"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "allow");
}

// ==== except_targets (issue #30) ====

#[test]
fn except_targets_lets_curl_reach_localhost_but_asks_for_other_hosts() {
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-curl-non-localhost"
        reason = "confirm curl to a non-localhost target"
        command = "curl"
        except_targets = [
            { prefix = "http://localhost" },
            { prefix = "http://127.0.0.1" },
            { prefix = "https://localhost" },
            { prefix = "https://127.0.0.1" },
            { prefix = "http://[::1]" },
            { prefix = "https://[::1]" },
        ]
    "#,
    );
    let envs = [("SHGUARD_CONFIG", config_path.to_str().unwrap())];

    for local_url in [
        "http://localhost:8080/api",
        "http://127.0.0.1/api",
        "https://localhost/api",
        "http://[::1]:9000/",
    ] {
        let output = run_hook(&bash_command(&format!("curl {local_url}")), &envs);
        assert_eq!(
            permission_decision(&output),
            "allow",
            "curl to {local_url} should not be caught by the rule"
        );
    }

    let output = run_hook(&bash_command("curl https://evil.example.com"), &envs);
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("user-ask-curl-non-localhost"));
}

#[test]
fn except_targets_gates_rsync_only_when_a_remote_spec_is_present() {
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-rsync-remote"
        reason = "confirm rsync touching a remote host"
        command = "rsync"
        except_targets = [
            { prefix = "/" },
            { prefix = "./" },
            { prefix = "../" },
            { prefix = "~" },
            { exact = "." },
        ]
    "#,
    );
    let envs = [("SHGUARD_CONFIG", config_path.to_str().unwrap())];

    let output = run_hook(&bash_command("rsync -a ./src ./dst"), &envs);
    assert_eq!(permission_decision(&output), "allow");

    let output = run_hook(&bash_command("rsync -a ./src user@example.com:/dst"), &envs);
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("user-ask-rsync-remote"));

    let output = run_hook(
        &bash_command("rsync -a rsync://example.com/mod /dst"),
        &envs,
    );
    assert_eq!(permission_decision(&output), "ask");
}

#[test]
fn except_targets_invalid_matcher_shape_is_rejected_at_config_load() {
    // `exact` and `prefix` set together on the same except_targets entry is
    // the same "mutually exclusive" violation `targets` already rejects —
    // must fail closed (every command asks) rather than silently ignoring
    // the malformed entry.
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-curl-bad-except"
        reason = "confirm curl"
        command = "curl"
        except_targets = [{ exact = "http://localhost", prefix = "http://127.0.0.1" }]
    "#,
    );

    let output = run_hook(
        &bash_command("echo hi"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
    assert!(!permission_reason(&output).is_empty());
}

// ==== Adversarial ====

#[test]
fn allow_entry_cannot_downgrade_the_sudo_floor_ask() {
    // Issue #32 (gate rule 10): the entry below matches `sudo gh pr view`
    // (allow-entry matching resolves through `sudo` like rule matching
    // does), but consent to unprivileged `gh` is not consent to running it
    // under privilege escalation — the sudo floor's Ask must survive.
    let (_dir, config_path) = write_config(
        r#"
        [[allow]]
        id = "user-allow-gh"
        reason = "trusted"
        command = "gh"
    "#,
    );

    let output = run_hook(
        &bash_command("sudo gh pr view"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("sudo"));
}

#[test]
fn allow_entry_cannot_downgrade_an_embedded_block() {
    let (_dir, config_path) = write_config(
        r#"
        [[allow]]
        id = "user-allow-rm"
        reason = "trust me"
        command = "rm"
    "#,
    );

    let output = run_hook(
        &bash_command("rm -rf /"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}

#[test]
fn id_colliding_with_embedded_blocklist_id_fails_closed() {
    let (_dir, config_path) = write_config(
        r#"
        [[allow]]
        id = "rm-recursive-force-dangerous-target"
        reason = "totally unrelated"
        command = "totally-different-command"
    "#,
    );

    let output = run_hook(
        &bash_command("echo hi"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
    assert!(!permission_reason(&output).is_empty());
}

#[test]
fn shguard_config_pointing_at_invalid_toml_fails_closed() {
    let (_dir, config_path) = write_config("this is not [valid toml");

    let output = run_hook(
        &bash_command("echo hi"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
    assert!(!permission_reason(&output).is_empty());
}

#[test]
fn shguard_config_pointing_at_missing_file_fails_closed() {
    let dir = tempdir().expect("tempdir should create");
    let missing_path = dir.path().join("does-not-exist.toml");

    let output = run_hook(
        &bash_command("echo hi"),
        &[("SHGUARD_CONFIG", missing_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
    assert!(!permission_reason(&output).is_empty());
}

// A present-but-non-UTF-8 `SHGUARD_CONFIG` must fail closed (hard error),
// not silently collapse into "unset" and fall through to XDG/HOME
// discovery (issue #23). `run_hook` takes `&str` envs, so this test builds
// the `Command` directly, mirroring `run_hook`'s env-isolation pattern.
#[test]
#[cfg(unix)]
fn shguard_config_non_utf8_fails_closed() {
    use std::os::unix::ffi::OsStringExt;

    let non_utf8 = std::ffi::OsString::from_vec(vec![0xFF, 0xFE]);

    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env("SHGUARD_CONFIG", non_utf8)
        .write_stdin(bash_command("echo hi"))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");

    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("SHGUARD_CONFIG"));
    assert!(permission_reason(&output).contains("UTF-8"));
}

// A present-but-non-UTF-8 `HOME` must fail closed (hard error), not
// silently collapse into "unset" the way `std::env::var(..).ok()` would
// (issue #28 item 1, same class of gap `SHGUARD_CONFIG` was already fixed
// for in issue #23).
#[test]
#[cfg(unix)]
fn home_non_utf8_fails_closed() {
    use std::os::unix::ffi::OsStringExt;

    let non_utf8 = std::ffi::OsString::from_vec(vec![0xFF, 0xFE]);

    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env("HOME", non_utf8)
        .write_stdin(bash_command("echo hi"))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");

    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("HOME"));
    assert!(permission_reason(&output).contains("UTF-8"));
}

// Same as above but for `XDG_CONFIG_HOME` (issue #28 item 1).
#[test]
#[cfg(unix)]
fn xdg_config_home_non_utf8_fails_closed() {
    use std::os::unix::ffi::OsStringExt;

    let non_utf8 = std::ffi::OsString::from_vec(vec![0xFF, 0xFE]);

    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("SHGUARD_CONFIG")
        .env("XDG_CONFIG_HOME", non_utf8)
        .env_remove("HOME")
        .write_stdin(bash_command("echo hi"))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");

    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("XDG_CONFIG_HOME"));
    assert!(permission_reason(&output).contains("UTF-8"));
}

// ==== Discovery / precedence ====

#[test]
fn absent_default_path_behaves_like_zero_config() {
    let home = tempdir().expect("tempdir should create");
    // No .config/shguard/config.toml under home at all.
    let output = run_hook(
        &bash_command("gh pr view"),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "allow");
}

#[test]
fn default_path_under_home_is_used_when_present() {
    let home = tempdir().expect("tempdir should create");
    let config_dir = home.path().join(".config").join("shguard");
    fs::create_dir_all(&config_dir).expect("config dir should create");
    fs::write(
        config_dir.join("config.toml"),
        r#"
        [[ask]]
        id = "user-ask-gh"
        reason = "confirm every gh invocation"
        command = "gh"
    "#,
    )
    .expect("config file should write");

    let output = run_hook(
        &bash_command("gh pr view"),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
}

#[test]
fn xdg_config_home_takes_precedence_over_bare_home() {
    let home = tempdir().expect("tempdir should create");
    let home_config_dir = home.path().join(".config").join("shguard");
    fs::create_dir_all(&home_config_dir).expect("config dir should create");
    fs::write(
        home_config_dir.join("config.toml"),
        r#"
        [[deny]]
        id = "user-deny-from-home"
        reason = "from HOME"
        command = "from-home-tool"
    "#,
    )
    .expect("config file should write");

    let xdg = tempdir().expect("tempdir should create");
    let xdg_config_dir = xdg.path().join("shguard");
    fs::create_dir_all(&xdg_config_dir).expect("config dir should create");
    fs::write(
        xdg_config_dir.join("config.toml"),
        r#"
        [[deny]]
        id = "user-deny-from-xdg"
        reason = "from XDG_CONFIG_HOME"
        command = "from-xdg-tool"
    "#,
    )
    .expect("config file should write");

    let envs = [
        ("HOME", home.path().to_str().unwrap()),
        ("XDG_CONFIG_HOME", xdg.path().to_str().unwrap()),
    ];

    let output = run_hook(&bash_command("from-xdg-tool"), &envs);
    assert_eq!(permission_decision(&output), "deny");
    assert!(permission_reason(&output).contains("user-deny-from-xdg"));

    // The HOME-only config never gets consulted once XDG_CONFIG_HOME wins.
    let output = run_hook(&bash_command("from-home-tool"), &envs);
    assert_eq!(permission_decision(&output), "allow");
}

#[test]
fn shguard_config_takes_precedence_over_default_path() {
    let home = tempdir().expect("tempdir should create");
    let home_config_dir = home.path().join(".config").join("shguard");
    fs::create_dir_all(&home_config_dir).expect("config dir should create");
    fs::write(
        home_config_dir.join("config.toml"),
        r#"
        [[deny]]
        id = "user-deny-from-default-path"
        reason = "default path"
        command = "default-path-tool"
    "#,
    )
    .expect("config file should write");

    let (_explicit_dir, explicit_config) = write_config(
        r#"
        [[deny]]
        id = "user-deny-from-explicit-path"
        reason = "explicit path"
        command = "explicit-path-tool"
    "#,
    );

    let envs = [
        ("HOME", home.path().to_str().unwrap()),
        ("SHGUARD_CONFIG", explicit_config.to_str().unwrap()),
    ];

    let output = run_hook(&bash_command("explicit-path-tool"), &envs);
    assert_eq!(permission_decision(&output), "deny");

    // The default-path config never gets consulted once SHGUARD_CONFIG wins.
    let output = run_hook(&bash_command("default-path-tool"), &envs);
    assert_eq!(permission_decision(&output), "allow");
}

// A bare-filename SHGUARD_CONFIG (no directory component, e.g.
// `SHGUARD_CONFIG=config.toml`) must still load a valid user config --
// `Path::parent()` returns an empty path (not `None`) for a single-
// component relative path, which previously fed an empty `prefix` into
// the self-protection rule generator and failed the whole config load
// (issue #24). `run_hook` doesn't set `current_dir`, so this test builds
// the `Command` directly, mirroring `run_hook`'s env-isolation pattern.
#[test]
fn bare_filename_shguard_config_still_loads_a_valid_config() {
    let dir = tempdir().expect("tempdir should create");
    fs::write(
        dir.path().join("config.toml"),
        r#"
        [[deny]]
        id = "user-deny-scary-tool"
        reason = "never run this"
        command = "scary-tool"
    "#,
    )
    .expect("config file should write");

    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env("SHGUARD_CONFIG", "config.toml")
        .current_dir(dir.path())
        .write_stdin(bash_command("scary-tool --run"))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");

    assert_eq!(permission_decision(&output), "deny");
    assert!(permission_reason(&output).contains("user-deny-scary-tool"));
}

// A `SHGUARD_CONFIG` with an explicit relative directory (e.g.
// `SHGUARD_CONFIG=./config.toml`) hits the same equivalence class as the
// bare-filename case above -- `Path::parent()` returns `Some(".")` rather
// than `None`, which the empty-string-only filter in the original #24 fix
// didn't catch. A relative prefix like `.` can never usefully protect
// anything (`normalize.rs` never resolves the current working directory,
// so an agent can always dodge it via an absolute path) but does
// over-match unrelated dot-leading command targets through
// `TargetMatcher::matches`'s plain `starts_with(prefix)`. This test
// asserts both halves: the user's own config rule still applies, and an
// unrelated dot-leading command is no longer wrongly denied.
#[test]
fn relative_dir_shguard_config_does_not_over_match_self_protection() {
    let dir = tempdir().expect("tempdir should create");
    fs::write(
        dir.path().join("config.toml"),
        r#"
        [[deny]]
        id = "user-deny-scary-tool"
        reason = "never run this"
        command = "scary-tool"
    "#,
    )
    .expect("config file should write");

    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env("SHGUARD_CONFIG", "./config.toml")
        .current_dir(dir.path())
        .write_stdin(bash_command("scary-tool --run"))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");

    assert_eq!(permission_decision(&output), "deny");
    assert!(permission_reason(&output).contains("user-deny-scary-tool"));

    // Regression check: a `prefix = "."` self-protection rule would match
    // any dot-leading path token, wrongly denying unrelated commands like
    // this one.
    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env("SHGUARD_CONFIG", "./config.toml")
        .current_dir(dir.path())
        .write_stdin(bash_command("cp a ./b"))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");

    assert_ne!(permission_decision(&output), "deny");
}

// ==== Recursion threading ====

#[test]
fn deny_rule_recurses_into_bash_dash_c() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-scary-tool"
        reason = "never run this"
        command = "scary-tool"
    "#,
    );

    let output = run_hook(
        &bash_command("bash -c 'scary-tool --run'"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}

// A dangling symlink at the default config path must fail closed (`ask`),
// not silently fall back to embedded-only coverage (issue #39):
// `read_to_string` fails with the same `NotFound` kind a genuinely absent
// path does, so only `symlink_metadata` (`lstat`) can tell "nothing here
// at all" apart from "something's here but broken".
#[test]
#[cfg(unix)]
fn dangling_default_symlink_fails_closed() {
    let home = tempdir().expect("tempdir should create");
    let config_dir = home.path().join(".config").join("shguard");
    fs::create_dir_all(&config_dir).expect("config dir should create");
    std::os::unix::fs::symlink(
        config_dir.join("does-not-exist.toml"),
        config_dir.join("config.toml"),
    )
    .expect("dangling symlink should create");

    // grep foo bar matches no built-in blocklist entry, so an `allow`
    // verdict here would mean the config load silently fell back to
    // embedded-only instead of failing closed.
    let output = run_hook(
        &bash_command("grep foo bar"),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
    assert!(!permission_reason(&output).is_empty());
}

// ==== Self-protection ====

// A config deployed as a symlink (e.g. into a dotfiles repo) must have its
// *resolved target* protected too, not just the symlink path itself —
// otherwise an agent can rewrite the real backing file directly, bypassing
// self-protection entirely (issue #31).
#[test]
#[cfg(unix)]
fn write_to_symlinked_config_canonical_target_is_denied() {
    let real_dir = tempdir().expect("tempdir should create");
    // Canonicalize the directory itself before joining the filename: on
    // macOS a fresh tempdir lives under `/var/folders/...`, which
    // `std::fs::canonicalize` resolves to `/private/var/folders/...` (`/var`
    // is itself a symlink) — an OS quirk unrelated to this test's actual
    // config symlink. Building `real_config` from the already-canonical
    // directory keeps the command below targeting the same path
    // `self_protection_directories`'s `canonicalize` call resolves to.
    let real_dir_canonical = real_dir
        .path()
        .canonicalize()
        .expect("tempdir should canonicalize");
    let real_config = real_dir_canonical.join("config.toml");
    fs::write(&real_config, "").expect("config file should write");

    let home = tempdir().expect("tempdir should create");
    let config_dir = home.path().join(".config").join("shguard");
    fs::create_dir_all(&config_dir).expect("config dir should create");
    std::os::unix::fs::symlink(&real_config, config_dir.join("config.toml"))
        .expect("symlink should create");

    let command = format!(
        "cp evil.toml {}",
        real_config.to_str().expect("path should be valid UTF-8")
    );
    let output = run_hook(
        &bash_command(&command),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}

#[test]
fn cp_onto_resolved_config_path_is_blocked() {
    let (_dir, config_path) = write_config("");

    let command = format!(
        "cp evil.toml {}",
        config_path.to_str().expect("path should be valid UTF-8")
    );
    let output = run_hook(
        &bash_command(&command),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}

#[test]
fn cp_onto_literal_tilde_config_path_is_blocked() {
    let home = tempdir().expect("tempdir should create");
    let output = run_hook(
        &bash_command("cp evil.toml ~/.config/shguard/config.toml"),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}

// rm -r on the bare config directory (no trailing slash) is issue #22's
// core scenario: deleting the whole directory silently reverts the
// user's custom policy to embedded-only.
#[test]
fn rm_recursive_on_config_directory_is_blocked() {
    let home = tempdir().expect("tempdir should create");
    let output = run_hook(
        &bash_command("rm -r ~/.config/shguard"),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}

// mv on the bare config directory (no trailing slash) is the same class
// of bug as rm above: moving the whole directory away silently reverts
// the user's custom policy to embedded-only (issue #22).
#[test]
fn mv_on_config_directory_is_blocked() {
    let home = tempdir().expect("tempdir should create");
    let output = run_hook(
        &bash_command("mv ~/.config/shguard /tmp/backup"),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}

#[test]
fn unlink_onto_literal_tilde_config_path_is_blocked() {
    let home = tempdir().expect("tempdir should create");
    let output = run_hook(
        &bash_command("unlink ~/.config/shguard/config.toml"),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}

#[test]
fn ln_symlink_swap_onto_literal_tilde_config_path_is_blocked() {
    let home = tempdir().expect("tempdir should create");
    let output = run_hook(
        &bash_command("ln -sf /dev/null ~/.config/shguard/config.toml"),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}

#[test]
fn sed_in_place_equals_suffix_onto_resolved_config_path_is_blocked() {
    let (_dir, config_path) = write_config("");

    let command = format!(
        "sed --in-place=.bak s/x/y/ {}",
        config_path.to_str().expect("path should be valid UTF-8")
    );
    let output = run_hook(
        &bash_command(&command),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
}
