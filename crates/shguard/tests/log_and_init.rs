//! M16 through the real binary: the decision log, `shguard init` and the
//! 0.9 config detection. `HOME` and `SHGUARD_CONFIG` point at temp
//! directories, so the user's own files are never read or written. Only
//! decisions and file shapes are pinned, never message text.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{e:?}"),
    }
}

fn bash(command: &str) -> Vec<u8> {
    serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": command } })
        .to_string()
        .into_bytes()
}

fn spawn(mut cmd: Command, stdin: &[u8]) -> Output {
    let mut child = ok(cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn());
    if let Some(mut pipe) = child.stdin.take() {
        drop(pipe.write_all(stdin));
    }
    ok(child.wait_with_output())
}

/// The hook with `SHGUARD_CONFIG` naming `config`, which holds `text`.
fn hook(home: &Path, config: &Path, text: &str, stdin: &[u8]) -> Output {
    ok(std::fs::write(config, text));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shguard"));
    cmd.env("HOME", home).env("SHGUARD_CONFIG", config);
    spawn(cmd, stdin)
}

fn decision(out: &Output) -> Option<String> {
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: Value = ok(serde_json::from_slice(&out.stdout));
    v.get("hookSpecificOutput")
        .and_then(|o| o.get("permissionDecision"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn log_lines(path: &Path) -> Vec<Value> {
    ok(std::fs::read_to_string(path))
        .lines()
        .map(|l| ok(serde_json::from_str(l)))
        .collect()
}

#[test]
fn decision_log_gets_one_line_per_bash_decision() {
    let dir = ok(tempfile::tempdir());
    let state = dir.path().join("state");
    ok(std::fs::create_dir(&state));
    let log = state.join("decisions.jsonl");
    let config = dir.path().join("config.toml");
    let text = format!("decision_log = {:?}\n", log.display().to_string());
    let cases = [
        ("ls -la", "allow"),
        ("rm -rf /", "deny"),
        ("unknowntool x", "deny"),
    ];
    for (cmd, want) in cases {
        let out = hook(dir.path(), &config, &text, &bash(cmd));
        assert_eq!(decision(&out).as_deref(), Some(want), "{cmd}");
    }
    // A non-Bash tool gets no decision and no line.
    let out = hook(dir.path(), &config, &text, br#"{"tool_name":"Read"}"#);
    assert_eq!(decision(&out), None);
    let lines = log_lines(&log);
    assert_eq!(lines.len(), cases.len());
    for (line, (cmd, want)) in lines.iter().zip(cases) {
        assert_eq!(line["decision"], want);
        assert_eq!(line["command"], cmd);
        assert!(line["ts"].is_u64());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = ok(std::fs::metadata(&log)).permissions().mode();
        assert_eq!(mode & 0o077, 0, "the log is readable by others");
    }
}

#[test]
fn no_decision_log_unless_configured() {
    let dir = ok(tempfile::tempdir());
    let config = dir.path().join("config.toml");
    let out = hook(dir.path(), &config, "", &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("allow"));
    let entries: Vec<_> = ok(std::fs::read_dir(dir.path())).collect();
    assert_eq!(entries.len(), 1, "only the config exists");
}

#[test]
fn a_log_that_cannot_be_written_leaves_the_answer() {
    let dir = ok(tempfile::tempdir());
    let config = dir.path().join("config.toml");
    // A directory where the log file should be.
    let log = dir.path().join("is-a-dir");
    ok(std::fs::create_dir(&log));
    let text = format!("decision_log = {:?}\n", log.display().to_string());
    for (cmd, want) in [("ls -la", "allow"), ("rm -rf /", "deny")] {
        let out = hook(dir.path(), &config, &text, &bash(cmd));
        assert_eq!(decision(&out).as_deref(), Some(want), "{cmd}");
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_log_is_not_written_through() {
    let dir = ok(tempfile::tempdir());
    let config = dir.path().join("config.toml");
    let target = dir.path().join("target.txt");
    ok(std::fs::write(&target, "keep\n"));
    let log = dir.path().join("log.jsonl");
    ok(std::os::unix::fs::symlink(&target, &log));
    let text = format!("decision_log = {:?}\n", log.display().to_string());
    let out = hook(dir.path(), &config, &text, &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("allow"));
    assert_eq!(ok(std::fs::read_to_string(&target)), "keep\n");
}

#[cfg(unix)]
#[test]
fn a_fifo_at_the_log_path_does_not_hold_the_answer() {
    let dir = ok(tempfile::tempdir());
    let config = dir.path().join("config.toml");
    let log = dir.path().join("log.jsonl");
    let made = Command::new("mkfifo").arg(&log).status();
    assert!(matches!(made, Ok(s) if s.success()), "mkfifo: {made:?}");
    let text = format!("decision_log = {:?}\n", log.display().to_string());
    let start = std::time::Instant::now();
    let out = hook(dir.path(), &config, &text, &bash("rm -rf /"));
    assert_eq!(decision(&out).as_deref(), Some("deny"));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "the hook waited"
    );
}

#[test]
fn a_missing_log_directory_is_not_created() {
    let dir = ok(tempfile::tempdir());
    let config = dir.path().join("config.toml");
    let log = dir.path().join("absent").join("log.jsonl");
    let text = format!("decision_log = {:?}\n", log.display().to_string());
    let out = hook(dir.path(), &config, &text, &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("allow"));
    assert!(!dir.path().join("absent").exists());
}

#[test]
fn a_load_error_writes_no_log_line() {
    let dir = ok(tempfile::tempdir());
    let config = dir.path().join("config.toml");
    let log = dir.path().join("log.jsonl");
    let text = format!(
        "decision_log = {:?}\nbogus = 1\n",
        log.display().to_string()
    );
    let out = hook(dir.path(), &config, &text, &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("deny"));
    assert!(!log.exists());
}

#[cfg(unix)]
#[test]
fn an_existing_log_is_made_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = ok(tempfile::tempdir());
    let config = dir.path().join("config.toml");
    let log = dir.path().join("log.jsonl");
    ok(std::fs::write(&log, ""));
    ok(std::fs::set_permissions(
        &log,
        std::fs::Permissions::from_mode(0o644),
    ));
    let text = format!("decision_log = {:?}\n", log.display().to_string());
    let out = hook(dir.path(), &config, &text, &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("allow"));
    assert_eq!(ok(std::fs::metadata(&log)).permissions().mode() & 0o077, 0);
    assert_eq!(log_lines(&log).len(), 1);
}

#[test]
fn relative_decision_log_is_a_load_error() {
    let dir = ok(tempfile::tempdir());
    let config = dir.path().join("config.toml");
    let out = hook(
        dir.path(),
        &config,
        "decision_log = \"decisions.jsonl\"\n",
        &bash("ls -la"),
    );
    assert_eq!(decision(&out).as_deref(), Some("deny"));
}

#[test]
fn a_09_config_denies_every_bash_call() {
    let dir = ok(tempfile::tempdir());
    let config = dir.path().join("config.toml");
    for text in [
        "[[ask]]\nid = \"a\"\nreason = \"r\"\ncommand = \"gh\"\n",
        "[[deny]]\nid = \"d\"\nreason = \"r\"\ncommand = \"x\"\n",
        "[[allow]]\nid = \"a\"\nreason = \"r\"\ncommand = \"rm\"\n",
        "decision_log_path = \"/tmp/x.jsonl\"\n",
        "escalation_floor = \"deny\"\n",
        "ask_outcome = { default = \"ask\" }\n",
    ] {
        let out = hook(dir.path(), &config, text, &bash("ls -la"));
        assert_eq!(decision(&out).as_deref(), Some("deny"), "{text}");
    }
}

fn init(home: &Path) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shguard"));
    cmd.arg("init")
        .env("HOME", home)
        .env_remove("SHGUARD_CONFIG");
    spawn(cmd, b"")
}

#[test]
fn init_writes_the_config_and_prints_a_blocking_hook_entry() {
    let home = ok(tempfile::tempdir());
    let out = init(home.path());
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let path = home
        .path()
        .join(".config")
        .join("shguard")
        .join("config.toml");
    let text = ok(std::fs::read_to_string(&path));
    assert!(text.lines().any(|l| l == "ask_outcome = \"ask\""));
    // The printed snippet is the last JSON object on stdout.
    let stdout = ok(String::from_utf8(out.stdout));
    let Some(start) = stdout.find("{\n") else {
        panic!("no JSON in {stdout}");
    };
    let snippet: Value = ok(serde_json::from_str(stdout[start..].trim()));
    let entry = &snippet["hooks"]["PreToolUse"][0];
    assert_eq!(entry["matcher"], "Bash");
    assert_eq!(entry["hooks"][0]["onFailure"], "block");
    assert!(entry["hooks"][0]["command"].is_string());

    // The written config is what the hook then reads: an Ask is asked.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shguard"));
    cmd.env("HOME", home.path()).env_remove("SHGUARD_CONFIG");
    let out = spawn(cmd, &bash("unknowntool x"));
    assert_eq!(decision(&out).as_deref(), Some("ask"));
}

#[test]
fn init_never_overwrites_a_config() {
    let home = ok(tempfile::tempdir());
    let dir = home.path().join(".config").join("shguard");
    ok(std::fs::create_dir_all(&dir));
    let path = dir.join("config.toml");
    let legacy = "[[deny]]\nid = \"d\"\nreason = \"r\"\ncommand = \"x\"\n";
    ok(std::fs::write(&path, legacy));
    let out = init(home.path());
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(ok(std::fs::read_to_string(&path)), legacy);
}

#[test]
fn init_needs_a_place_for_the_config() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shguard"));
    cmd.arg("init")
        .env_remove("HOME")
        .env_remove("SHGUARD_CONFIG");
    let out = spawn(cmd, b"");
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shguard"));
    cmd.arg("init").env("SHGUARD_CONFIG", "relative.toml");
    let out = spawn(cmd, b"");
    assert_ne!(out.status.code(), Some(0), "{out:?}");
}
