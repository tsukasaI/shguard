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

// ==== issue #96: multi-word `command` sugar (subcommand-level matching) ====

#[test]
fn multi_word_command_ask_rule_fires_for_matching_subcommand_sequence() {
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-gh-repo-delete"
        reason = "confirm repo deletion"
        command = "gh repo delete"
    "#,
    );

    let output = run_hook(
        &bash_command("gh repo delete octo/rally"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("user-ask-gh-repo-delete"));
}

#[test]
fn multi_word_command_ask_rule_does_not_over_match_a_different_subcommand() {
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-gh-repo-delete"
        reason = "confirm repo deletion"
        command = "gh repo delete"
    "#,
    );

    let output = run_hook(
        &bash_command("gh pr view"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "allow");
}

#[test]
fn multi_word_command_ask_rule_does_not_over_match_bare_or_partial_command() {
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-gh-repo-delete"
        reason = "confirm repo deletion"
        command = "gh repo delete"
    "#,
    );
    let envs = [("SHGUARD_CONFIG", config_path.to_str().unwrap())];

    let output = run_hook(&bash_command("gh"), &envs);
    assert_eq!(permission_decision(&output), "allow");

    let output = run_hook(&bash_command("gh status"), &envs);
    assert_eq!(permission_decision(&output), "allow");
}

// The headline scenario: a subcommand-scoped `[[allow]]` (sugar-derived
// required_tokens) carves an exception out of a broader whole-command
// `Ask`. Uses `[[deny]] decision = "ask"`, not the `[[ask]]` table:
// `[[ask]]` is a floor applied AFTER the allowlist downgrade, so it can
// never be lifted by an `allow` entry (src/gate.rs module docs: a broad
// `deny`/`ask` must never be overridable by a narrower `allow`) -- a
// `[[deny]]` entry with `decision = "ask"` produces a structural Ask
// instead, which IS eligible for allowlist downgrade, the mechanism this
// test actually exercises.
#[test]
fn subcommand_scoped_allow_carves_exception_out_of_broader_ask() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-gate-gh"
        reason = "confirm every gh invocation"
        decision = "ask"
        command = "gh"

        [[allow]]
        id = "user-allow-gh-pr-view"
        reason = "read-only, always safe"
        command = "gh pr view"
    "#,
    );
    let envs = [("SHGUARD_CONFIG", config_path.to_str().unwrap())];

    let output = run_hook(&bash_command("gh pr view"), &envs);
    assert_eq!(permission_decision(&output), "allow");

    let output = run_hook(&bash_command("gh repo delete octo/rally"), &envs);
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("user-gate-gh"));

    let output = run_hook(&bash_command("gh"), &envs);
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("user-gate-gh"));
}

// Dash-prefixed words between the command name and its subcommand sequence
// must not break the match -- existing required_tokens/Positionals
// behavior, the sugar just inherits it.
#[test]
fn multi_word_command_ask_rule_matches_through_leading_flags() {
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-gh-repo-delete"
        reason = "confirm repo deletion"
        command = "gh repo delete"
    "#,
    );

    let output = run_hook(
        &bash_command("gh --verbose repo delete octo/rally"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
}

// Pins the third decision path (block) for the sugar -- the tests above
// only cover ask/allow.
#[test]
fn multi_word_command_deny_rule_blocks_matching_subcommand_sequence() {
    let (_dir, config_path) = write_config(
        r#"
        [[deny]]
        id = "user-deny-gh-repo-delete"
        reason = "never delete a repo"
        command = "gh repo delete"
    "#,
    );

    let output = run_hook(
        &bash_command("gh repo delete octo/rally"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");
    assert!(permission_reason(&output).contains("user-deny-gh-repo-delete"));
}

// ==== issue #83: allowlist-downgrade eligibility must also account for a
// substitution hidden in the command-position word's own non-winning
// brace alternative, not just an ordinary argument-position one ====

#[test]
fn allow_rule_cannot_launder_a_command_position_leftover_substitution() {
    let (_dir, config_path) = write_config(
        r#"
        [[allow]]
        id = "allow-tar"
        reason = "test"
        command = "tar"
    "#,
    );

    // The issue's own repro: an allow entry for the literal command `tar`
    // must not downgrade a `tar-directory-root-or-home` Ask when the
    // command-position word's leftover brace alternative hides an
    // unresolved substitution — the winning alternative ("tar") resolves
    // cleanly and matches the allow entry, but the substitution riding
    // alongside it in the OTHER alternative is exactly as unresolved a
    // runtime value as an ordinary argument-position one.
    let output = run_hook(
        &bash_command("tar{,$($EVIL)} xf evil.tar -C /"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");

    // Same gap, reached via a process substitution instead of a command
    // substitution (issue #75's sibling construct) — collect_process_substitutions_into
    // must be scanned here too, not just collect_substitutions_into.
    let output = run_hook(
        &bash_command("tar{,<(x)} xf evil.tar -C /"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
}

#[test]
fn allow_rule_still_downgrades_a_substitution_free_leftover() {
    // The false-positive boundary: a command-position word with a brace
    // alternative that resolves to ordinary literal text (no substitution
    // anywhere in either alternative) must still downgrade normally — the
    // new guard is scoped to an actual substitution in the leftover
    // alternative, not "any brace alternation present at all". Uses `rm`
    // rather than `tar` deliberately: `tar`'s own dash-less-cluster floor
    // (issue #67) independently trips on the brace-multiplied extra token
    // this shape produces (`rm{,x}` → `rmx`... "tarx"-shaped for `tar`),
    // which would falsely confirm the wrong mechanism if used here.
    let (_dir, config_path) = write_config(
        r#"
        [[allow]]
        id = "user-allow-rm"
        reason = "trust me"
        command = "rm"
    "#,
    );

    let output = run_hook(
        &bash_command("rm{,x} -rf $HOME"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "allow");
}

// ==== issue #115: allow entries must not launder a `--directory=~`-shaped
// token past the zsh-magic_equal_subst floor either ====

#[test]
fn allow_rule_cannot_launder_a_directory_equals_tilde_token() {
    let (_dir, config_path) = write_config(
        r#"
        [[allow]]
        id = "allow-tar"
        reason = "test"
        command = "tar"
    "#,
    );

    let output = run_hook(
        &bash_command("tar -x --directory=~ -f a.tar"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");

    let output = run_hook(
        &bash_command("tar -x --directory=~alice -f a.tar"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
}

#[test]
fn user_config_ask_rule_reaches_the_directory_equals_tilde_floor_too() {
    // `Rules::match_command_directory_equals_tilde` chains `command_rules`
    // and `ask_rules` — a user-config `[[ask]]` entry with the same
    // `=`-terminated-strip + bare-`~`-target shape is just as eligible as
    // an embedded blocklist rule. Uses a made-up command name (`mytool`,
    // no embedded rule at all) so this genuinely exercises the ask_rules
    // half of the chain rather than being shadowed by an embedded tar rule.
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-mytool-directory-tilde"
        reason = "confirm mytool with a home-directory target"
        command = "mytool"
        targets = [
            { strip = "--directory=", normalized = "/" },
            { normalized = "~" },
        ]
    "#,
    );

    let output = run_hook(
        &bash_command("mytool --directory=~"),
        &[("SHGUARD_CONFIG", config_path.to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("user-ask-mytool-directory-tilde"));
}

// ==== except_targets (issue #30) ====

fn curl_localhost_except_config() -> &'static str {
    r#"
    [[ask]]
    id = "user-ask-curl-non-localhost"
    reason = "confirm curl to a non-localhost target"
    command = "curl"
    except_targets = [
        { exact = "http://localhost" }, { prefix = "http://localhost:" }, { prefix = "http://localhost/" },
        { exact = "https://localhost" }, { prefix = "https://localhost:" }, { prefix = "https://localhost/" },
        { exact = "http://127.0.0.1" }, { prefix = "http://127.0.0.1:" }, { prefix = "http://127.0.0.1/" },
        { exact = "https://127.0.0.1" }, { prefix = "https://127.0.0.1:" }, { prefix = "https://127.0.0.1/" },
        { exact = "http://[::1]" }, { prefix = "http://[::1]:" }, { prefix = "http://[::1]/" },
        { exact = "https://[::1]" }, { prefix = "https://[::1]:" }, { prefix = "https://[::1]/" },
    ]
"#
}

#[test]
fn except_targets_lets_curl_reach_localhost_but_asks_for_other_hosts() {
    let (_dir, config_path) = write_config(curl_localhost_except_config());
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

// Regression: an unanchored `{ prefix = "http://localhost" }` would also
// match a different host that merely starts with the same characters
// (`localhost.evil.example.com`) or one where "localhost" is URL userinfo
// rather than the host (`localhost@evil.example.com`) — a boundary-
// anchored except_targets list (port/path suffix or exact match) must
// reject both.
#[test]
fn except_targets_boundary_anchoring_rejects_lookalike_hosts() {
    let (_dir, config_path) = write_config(curl_localhost_except_config());
    let envs = [("SHGUARD_CONFIG", config_path.to_str().unwrap())];

    for lookalike in [
        "http://localhost.evil.example.com",
        "https://localhost@evil.example.com/x",
    ] {
        let output = run_hook(&bash_command(&format!("curl {lookalike}")), &envs);
        assert_eq!(
            permission_decision(&output),
            "ask",
            "curl to {lookalike} should not be excepted as localhost"
        );
    }
}

// Regression: a dangerous target passed as a `--flag=value` token's
// attached value must still be checked against except_targets — an
// earlier implementation filtered out every `-`-prefixed token wholesale
// when `targets` was empty, so the excepted `http://localhost` positional
// vacuously satisfied "all candidates excepted" while the real,
// non-localhost target hid inside `--url=`.
#[test]
fn except_targets_checks_a_flag_equals_value_target_not_just_positionals() {
    let (_dir, config_path) = write_config(curl_localhost_except_config());
    let envs = [("SHGUARD_CONFIG", config_path.to_str().unwrap())];

    let output = run_hook(
        &bash_command("curl http://localhost --url=https://evil.example.com"),
        &envs,
    );
    assert_eq!(permission_decision(&output), "ask");

    // The same attached-value shape must still be excepted when it really
    // is localhost — the fix must not turn into a blanket "always ask
    // when --flag=value is present".
    let output = run_hook(&bash_command("curl --url=http://localhost"), &envs);
    assert_eq!(permission_decision(&output), "allow");
}

// Fail-closed: an unresolvable word anywhere in curl's tail must never let
// except_targets suppress the rule, even when every resolved token is
// excepted — end-to-end (the unit-level guarantee is also pinned in
// src/rules.rs, but the gate/normalize wiring that actually produces an
// Unresolvable word is only exercised through the real binary here).
#[test]
fn except_targets_never_suppresses_when_argv_has_an_unresolvable_word() {
    let (_dir, config_path) = write_config(curl_localhost_except_config());
    let envs = [("SHGUARD_CONFIG", config_path.to_str().unwrap())];

    let output = run_hook(&bash_command("curl http://localhost $(echo extra)"), &envs);
    assert_ne!(permission_decision(&output), "allow");
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

// Regression (issue #96): a required_tokens word (from `command`'s
// multi-word sugar) fully covered by except_targets alternatives -- every
// required_tokens word ("repo", "delete") has its own except_targets
// entry, alongside the real carve-out ("my-org/") -- produces a working
// carve-out: the rule excepts matching invocations while still firing on
// non-excepted ones. Exercises real matching end-to-end, not just
// successful parse.
#[test]
fn except_targets_covering_every_required_tokens_word_still_excepts_correctly() {
    let (_dir, config_path) = write_config(
        r#"
        [[ask]]
        id = "user-ask-gh-repo-delete"
        reason = "confirm gh repo delete outside my-org"
        command = "gh repo delete"
        except_targets = [
            { exact = "repo" }, { exact = "delete" }, { prefix = "my-org/" },
        ]
    "#,
    );
    let envs = [("SHGUARD_CONFIG", config_path.to_str().unwrap())];

    let output = run_hook(&bash_command("gh repo delete my-org/some-repo"), &envs);
    assert_eq!(permission_decision(&output), "allow");

    let output = run_hook(&bash_command("gh repo delete other-org/some-repo"), &envs);
    assert_eq!(permission_decision(&output), "ask");
    assert!(permission_reason(&output).contains("user-ask-gh-repo-delete"));
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

// Regression for E2-2 (issue #59): `HOME=""` must not fall back to a
// CWD-relative `.config/shguard/config.toml` -- an agent that can't set
// its own `HOME` but *can* write files (Bash/Write access, the same
// threat model `src/config.rs`'s module docs describe) could otherwise
// plant a malicious config at a relative path and have it silently loaded
// on the next invocation that happens to run with an empty `HOME`. Plants
// a `[[deny]]` rule for `ls` at `<tempdir>/.config/shguard/config.toml`,
// runs the binary from that tempdir with `HOME=""` and no
// `SHGUARD_CONFIG`/`XDG_CONFIG_HOME`, and confirms `ls -la` still gets its
// ordinary built-in-rules decision (`allow`) instead of the planted `deny`.
// `run_hook` doesn't set `current_dir`, so this test builds the `Command`
// directly, mirroring `run_hook`'s env-isolation pattern.
#[test]
fn empty_home_does_not_fall_back_to_cwd_relative_config() {
    let dir = tempdir().expect("tempdir should create");
    let config_dir = dir.path().join(".config").join("shguard");
    fs::create_dir_all(&config_dir).expect("config dir should create");
    fs::write(
        config_dir.join("config.toml"),
        r#"
        [[deny]]
        id = "planted-by-agent"
        reason = "planted via a CWD-relative config, must never be loaded"
        command = "ls"
    "#,
    )
    .expect("config file should write");

    let mut cmd = Command::cargo_bin("shguard").expect("shguard binary should build");
    let assert = cmd
        .env_remove("SHGUARD_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env("HOME", "")
        .current_dir(dir.path())
        .write_stdin(bash_command("ls -la"))
        .assert()
        .success();
    let output: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout should be valid JSON");

    assert_eq!(permission_decision(&output), "allow");
}

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

// A config deployed behind a *chain* of two symlinks (e.g. a
// `stow`/`home-manager`/`chezmoi`-style layer of indirection) must have
// every hop protected, not just the literal start and the final resolved
// target -- otherwise writing directly at the intermediate hop (itself a
// symlink) bypasses self-protection and follows through to the real
// config (issue #44, widening issue #31's single-hop fix).
#[test]
#[cfg(unix)]
fn write_to_intermediate_hop_of_a_two_hop_symlink_chain_is_denied() {
    let mid_dir = tempdir().expect("tempdir should create");
    let real_dir = tempdir().expect("tempdir should create");
    // Canonicalize first (macOS quirk: /var/folders/... resolves to
    // /private/var/folders/...), same as
    // `write_to_symlinked_config_canonical_target_is_denied` above, so the
    // command below targets exactly what self-protection resolves to.
    let mid_dir_canonical = mid_dir
        .path()
        .canonicalize()
        .expect("tempdir should canonicalize");
    let real_dir_canonical = real_dir
        .path()
        .canonicalize()
        .expect("tempdir should canonicalize");

    let real_config = real_dir_canonical.join("config.toml");
    fs::write(&real_config, "").expect("config file should write");
    let mid_config = mid_dir_canonical.join("config.toml");
    std::os::unix::fs::symlink(&real_config, &mid_config).expect("symlink should create");

    let home = tempdir().expect("tempdir should create");
    let config_dir = home.path().join(".config").join("shguard");
    fs::create_dir_all(&config_dir).expect("config dir should create");
    std::os::unix::fs::symlink(&mid_config, config_dir.join("config.toml"))
        .expect("symlink should create");

    // Writing straight at the intermediate hop -- itself a symlink to the
    // real file -- must be caught even though it's neither the literal
    // config path nor the fully-resolved end.
    let command = format!(
        "cp evil.toml {}",
        mid_config.to_str().expect("path should be valid UTF-8")
    );
    let output = run_hook(
        &bash_command(&command),
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert_eq!(permission_decision(&output), "deny");

    // The fully-resolved end must still be caught too (regression check
    // against the single-hop fix this widens).
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
