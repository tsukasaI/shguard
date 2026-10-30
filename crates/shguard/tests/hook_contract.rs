//! The hook contract, through the real binary: `HOME` and `SHGUARD_CONFIG`
//! point at a temp directory, so the user's own config is never read.
//!
//! The embedded core catalog is merged with every config, so the rows a test
//! adds through the config use tool names the embedded catalog does not have
//! (`mytool`, `mydel`).

use std::fmt::Debug;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// How the config is found.
enum Config<'a> {
    /// `SHGUARD_CONFIG` unset; `HOME` is an empty temp directory.
    None,
    /// `SHGUARD_CONFIG` names this file, which holds this text.
    File(&'a str),
    /// `SHGUARD_CONFIG` names a file that does not exist.
    Missing,
    /// `SHGUARD_CONFIG` is a relative path.
    Relative,
}

const ROWS: &str = r#"
[[row]]
key = ["mytool"]
source = "https://example.com"
order = "permute"
dashdash = "ends"
rest = "path"
[[row.opt]]
short = "l"
[[row.opt]]
short = "a"

[[row]]
key = ["mydel"]
source = "https://example.com"
order = "permute"
dashdash = "ends"
rest = "path"
[[row.opt]]
short = "r"
[[row.opt]]
short = "f"
"#;

fn bash(command: &str) -> Vec<u8> {
    serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": command } })
        .to_string()
        .into_bytes()
}

fn spawn(mut cmd: Command, stdin: &[u8]) -> Output {
    let Ok(mut child) = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        panic!("cannot run shguard");
    };
    if let Some(mut pipe) = child.stdin.take() {
        // The hook stops reading at its cap, so a large write may hit a
        // closed pipe; that is not a failure.
        drop(pipe.write_all(stdin));
    }
    match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => panic!("cannot wait for shguard: {e}"),
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_shguard"))
}

fn ok<T, E: Debug>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{e:?}"),
    }
}

fn run(stdin: &[u8], config: &Config<'_>) -> Output {
    let dir = ok(tempfile::tempdir());
    let mut cmd = binary();
    cmd.env("HOME", dir.path()).env_remove("SHGUARD_CONFIG");
    match config {
        Config::None => {}
        Config::File(text) => {
            let path = dir.path().join("config.toml");
            ok(std::fs::write(&path, text));
            cmd.env("SHGUARD_CONFIG", &path);
        }
        Config::Relative => {
            cmd.env("SHGUARD_CONFIG", "config.toml");
        }
        Config::Missing => {
            cmd.env("SHGUARD_CONFIG", dir.path().join("missing.toml"));
        }
    }
    spawn(cmd, stdin)
}

/// The JSON the hook wrote, after checking the status is 0.
fn answer(out: &Output) -> Value {
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: Value = ok(serde_json::from_slice(&out.stdout));
    assert_eq!(
        v.get("hookSpecificOutput")
            .and_then(|o| o.get("hookEventName"))
            .and_then(Value::as_str),
        Some("PreToolUse")
    );
    v
}

fn decision(out: &Output) -> Option<String> {
    answer(out)
        .get("hookSpecificOutput")
        .and_then(|o| o.get("permissionDecision"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn reason(out: &Output) -> String {
    answer(out)
        .get("hookSpecificOutput")
        .and_then(|o| o.get("permissionDecisionReason"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// An Ask-level input is denied by default and asked with
/// `ask_outcome = "ask"`.
fn assert_ask_pair(stdin: &[u8]) {
    let by_default = run(stdin, &Config::File(ROWS));
    assert_eq!(decision(&by_default).as_deref(), Some("deny"));
    let with_ask = run(
        stdin,
        &Config::File(&format!("ask_outcome = \"ask\"\n{ROWS}")),
    );
    assert_eq!(decision(&with_ask).as_deref(), Some("ask"));
}

#[test]
fn non_bash_gets_no_decision() {
    let out = run(
        br#"{"tool_name":"Read","tool_input":{"file_path":"/x"}}"#,
        &Config::File(ROWS),
    );
    assert_eq!(decision(&out), None);
    // Not even a broken config changes that.
    let out = run(br#"{"tool_name":"Read"}"#, &Config::Missing);
    assert_eq!(decision(&out), None);
}

#[test]
fn malformed_input_is_an_ask() {
    let mut big = bash("ls");
    big.resize(1024 * 1024 + 1, b' ');
    let inputs: Vec<Vec<u8>> = vec![
        b"not json".to_vec(),
        Vec::new(),
        br#"{"tool_input":{"command":"ls"}}"#.to_vec(),
        br#"{"tool_name":"Bash"}"#.to_vec(),
        br#"{"tool_name":"Bash","tool_input":{"command":3}}"#.to_vec(),
        big,
        b"{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"\xff\"}}".to_vec(),
    ];
    for input in inputs {
        assert_ask_pair(&input);
    }
}

#[test]
fn non_utf8_input_reason_carries_no_input_bytes() {
    let out = run(
        b"{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"\xffSECRETMARK\"}}",
        &Config::None,
    );
    assert_eq!(decision(&out).as_deref(), Some("deny"));
    assert!(!reason(&out).contains("SECRETMARK"));
}

#[test]
fn empty_and_blank_commands_are_an_ask() {
    assert_ask_pair(&bash(""));
    assert_ask_pair(&bash("   \n"));
}

#[test]
fn unsupported_syntax_is_an_ask() {
    assert_ask_pair(&bash("echo $(id)"));
}

#[test]
fn covered_command_is_allowed() {
    let out = run(&bash("mytool -la"), &Config::File(ROWS));
    assert_eq!(decision(&out).as_deref(), Some("allow"));
    assert!(!reason(&out).contains("safe"));
    // ask_outcome does not touch an Allow.
    let out = run(
        &bash("mytool -la"),
        &Config::File(&format!("ask_outcome = \"ask\"\n{ROWS}")),
    );
    assert_eq!(decision(&out).as_deref(), Some("allow"));
}

#[test]
fn uncovered_command_goes_through_ask_outcome() {
    assert_ask_pair(&bash("uname -a"));
    assert_ask_pair(&bash("ls --bogus"));
}

#[test]
fn block_rule_denies_even_with_ask_outcome_ask() {
    let rule = r#"
[[rule]]
id = "mydel-root"
key = ["mydel"]
outcome = "block"
targets = [{ pat = "/", kind = "exact" }]
"#;
    for ask in ["deny", "ask"] {
        let cfg = format!("ask_outcome = \"{ask}\"\n{ROWS}{rule}");
        let out = run(&bash("mydel -rf /"), &Config::File(&cfg));
        assert_eq!(decision(&out).as_deref(), Some("deny"), "{ask}");
        let out = run(&bash("mydel -rf /tmp/x"), &Config::File(&cfg));
        assert_eq!(decision(&out).as_deref(), Some("allow"), "{ask}");
    }
}

#[test]
fn ask_rule_is_an_ask() {
    let rule = "\n[[rule]]\nid = \"distrust-mytool\"\nkey = [\"mytool\"]\noutcome = \"ask\"\n";
    let by_default = run(&bash("mytool -la"), &Config::File(&format!("{ROWS}{rule}")));
    assert_eq!(decision(&by_default).as_deref(), Some("deny"));
    let with_ask = run(
        &bash("mytool -la"),
        &Config::File(&format!("ask_outcome = \"ask\"\n{ROWS}{rule}")),
    );
    assert_eq!(decision(&with_ask).as_deref(), Some("ask"));
}

#[test]
fn load_errors_deny_even_a_covered_command() {
    let cases = [
        "this is = not toml [",
        "bogus_field = 1\n",
        "ask_outcome = \"allow\"\n",
        // A duplicate row.
        &format!("{ROWS}{ROWS}"),
        // An option-like key next to its parent.
        &format!(
            "{ROWS}[[row]]\nkey = [\"rm\", \"-rf\"]\nsource = \"x\"\norder = \"permute\"\ndashdash = \"ends\"\n"
        ),
    ];
    for cfg in cases {
        // The Bash call is denied whatever `ask_outcome` says.
        let out = run(
            &bash("ls -la"),
            &Config::File(&format!("{cfg}\nask_outcome = \"ask\"\n")),
        );
        assert_eq!(decision(&out).as_deref(), Some("deny"), "{cfg}");
        let out = run(&bash("ls -la"), &Config::File(cfg));
        assert_eq!(decision(&out).as_deref(), Some("deny"), "{cfg}");
        let out = run(br#"{"tool_name":"Glob"}"#, &Config::File(cfg));
        assert_eq!(decision(&out), None, "{cfg}");
    }
    let out = run(&bash("ls -la"), &Config::Missing);
    assert_eq!(decision(&out).as_deref(), Some("deny"));
    let out = run(&bash("ls -la"), &Config::Relative);
    assert_eq!(decision(&out).as_deref(), Some("deny"));
}

#[test]
fn option_like_user_row_cannot_unblock_rm_root() {
    let cfg = format!(
        "ask_outcome = \"ask\"\n{ROWS}{}\n[[row]]\nkey = [\"rm\", \"-rf\"]\nsource = \"x\"\norder = \"permute\"\ndashdash = \"ends\"\nruns_code = true\n",
        "[[rule]]\nid = \"rm-root\"\nkey = [\"rm\"]\noutcome = \"block\"\ntargets = [{ pat = \"/\", kind = \"exact\" }]\n"
    );
    let out = run(&bash("rm -rf /"), &Config::File(&cfg));
    assert_eq!(decision(&out).as_deref(), Some("deny"));
}

#[test]
fn no_config_at_the_default_path_means_defaults() {
    // The embedded core catalog alone, with `ask_outcome = "deny"`.
    let table = [
        ("ls -la", Some("allow")),
        ("rm -rf /", Some("deny")),
        ("unknowntool rm -rf /", Some("deny")),
    ];
    for (cmd, want) in table {
        let out = run(&bash(cmd), &Config::None);
        assert_eq!(decision(&out).as_deref(), want, "{cmd}");
    }
    let out = run(
        br#"{"tool_name":"Read","tool_input":{"file_path":"/x"}}"#,
        &Config::None,
    );
    assert_eq!(decision(&out), None);
}

fn at_default_path(home: &Path) -> std::path::PathBuf {
    let dir = home.join(".config").join("shguard");
    ok(std::fs::create_dir_all(&dir));
    dir.join("config.toml")
}

#[test]
fn default_path_config_is_read() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        at_default_path(home.path()),
        format!("ask_outcome = \"ask\"\n{ROWS}"),
    )
    .unwrap();
    let mut cmd = binary();
    cmd.env("HOME", home.path()).env_remove("SHGUARD_CONFIG");
    let out = spawn(cmd, &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("allow"));
    // An empty SHGUARD_CONFIG means the default path too.
    let mut cmd = binary();
    cmd.env("HOME", home.path()).env("SHGUARD_CONFIG", "");
    let out = spawn(cmd, &bash("uname"));
    assert_eq!(decision(&out).as_deref(), Some("ask"));
}

#[test]
fn unreadable_default_path_is_a_load_error() {
    // A directory where the file should be.
    let home = tempfile::tempdir().unwrap();
    let path = at_default_path(home.path());
    std::fs::create_dir(&path).unwrap();
    let mut cmd = binary();
    cmd.env("HOME", home.path()).env_remove("SHGUARD_CONFIG");
    let out = spawn(cmd, &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("deny"));

    // Non-UTF-8 content.
    let home = tempfile::tempdir().unwrap();
    std::fs::write(at_default_path(home.path()), b"\xff\xfe").unwrap();
    let mut cmd = binary();
    cmd.env("HOME", home.path()).env_remove("SHGUARD_CONFIG");
    let out = spawn(cmd, &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("deny"));
}

#[cfg(unix)]
#[test]
fn permission_denied_default_path_is_a_load_error() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let path = at_default_path(home.path());
    std::fs::write(&path, format!("ask_outcome = \"ask\"\n{ROWS}")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&path).is_ok() {
        // Running as root: the mode does not stop the read.
        return;
    }
    let mut cmd = binary();
    cmd.env("HOME", home.path()).env_remove("SHGUARD_CONFIG");
    let out = spawn(cmd, &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("deny"));
}

#[test]
fn empty_home_counts_as_unset() {
    // No config is read, so only the embedded catalog applies.
    let mut cmd = binary();
    cmd.env("HOME", "").env_remove("SHGUARD_CONFIG");
    let out = spawn(cmd, &bash("ls -la"));
    assert_eq!(decision(&out).as_deref(), Some("allow"));
    let mut cmd = binary();
    cmd.env_remove("HOME").env_remove("SHGUARD_CONFIG");
    let out = spawn(cmd, &bash("uname -a"));
    assert_eq!(decision(&out).as_deref(), Some("deny"));
}

fn cli(args: &[&str]) -> Output {
    let mut cmd = binary();
    cmd.args(args);
    spawn(cmd, b"")
}

#[test]
fn cli_help_and_version() {
    for flag in ["--help", "-h"] {
        let out = cli(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("usage"),
            "{flag}"
        );
    }
    for flag in ["--version", "-V"] {
        let out = cli(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
    }
}

#[test]
fn cli_misuse_exits_2_with_usage_on_stderr() {
    for args in [&["check"][..], &["bogus"], &["--help", "extra"], &["-x"]] {
        let out = cli(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage"),
            "{args:?}"
        );
    }
}

#[test]
fn check_on_an_unreadable_file_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    // A directory cannot be read as a file.
    let out = cli(&["check", &dir.path().to_string_lossy()]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn bare_invocation_is_hook_mode() {
    let out = cli(&[]);
    // Empty stdin is malformed input, answered, with status 0.
    assert!(decision(&out).is_some());
}
