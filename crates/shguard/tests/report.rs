//! `shguard report` through the real binary, and the `class` field the hook
//! writes. `HOME` and `SHGUARD_CONFIG` point at temp directories. The class
//! strings are pinned (they are the log's contract); reason text is not.

#[expect(
    dead_code,
    reason = "each test crate uses only part of the shared helpers"
)]
mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::{bash, spawn};
use serde_json::Value;
use shguard::decision_class::DecisionClass;

const SENTINEL: &str = "echo report-fixture-sentinel-7f3a";

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{e:?}"),
    }
}

fn shguard(home: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shguard"));
    cmd.args(args)
        .env("HOME", home)
        .env("SHGUARD_CONFIG", home.join("absent.toml"));
    spawn(cmd, stdin)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn fixture(dir: &Path, body: &[u8]) -> String {
    let log = dir.join("fixture.jsonl");
    ok(std::fs::write(&log, body));
    log.display().to_string()
}

#[test]
fn counts_per_class_in_order_with_a_total_and_no_command_text() {
    let dir = ok(tempfile::tempdir());
    let body = format!(
        "{{\"class\":\"unknown:no_row\",\"command\":\"{SENTINEL}\"}}\n\
         {{\"class\":\"allow\",\"command\":\"ls\"}}\n\
         {{\"class\":\"allow\",\"command\":\"ls -l\"}}\n\
         {{\"class\":\"allow\",\"command\":\"pwd\"}}\n\
         {{\"class\":\"rule_hit\",\"command\":\"x\"}}\n\
         {{\"class\":\"rule_hit\",\"command\":\"y\"}}\n\
         {{\"ts\":1,\"decision\":\"allow\",\"command\":\"{SENTINEL}\"}}\n\
         {{\"ts\":2,\"decision\":\"ask\",\"command\":\"z\"}}\n\
         this is not json {SENTINEL}\n\
         [\"{SENTINEL}\"]\n"
    );
    let log = fixture(dir.path(), body.as_bytes());
    let out = shguard(dir.path(), &["report", &log], b"");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        text(&out.stdout),
        "3\tallow\n2\tinvalid\n2\trule_hit\n2\tunclassified\n1\tunknown:no_row\n10\ttotal\n"
    );
    assert!(!text(&out.stdout).contains("sentinel"));
    assert!(!text(&out.stderr).contains("sentinel"), "{out:?}");
}

#[test]
fn show_commands_adds_the_commands_under_their_class() {
    let dir = ok(tempfile::tempdir());
    let body = format!(
        "{{\"class\":\"unknown:no_row\",\"command\":\"{SENTINEL}\"}}\n\
         {{\"class\":\"unknown:no_row\",\"command\":\"{SENTINEL}\"}}\n"
    );
    let log = fixture(dir.path(), body.as_bytes());
    let out = shguard(dir.path(), &["report", "--show-commands", &log], b"");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = text(&out.stdout);
    assert_eq!(
        stdout,
        format!("2\tunknown:no_row\n\t2\t\"{SENTINEL}\"\n2\ttotal\n")
    );
}

#[test]
fn show_commands_escapes_control_and_bidi_characters() {
    let dir = ok(tempfile::tempdir());
    let command = "a\u{9b}b\u{7f}c\u{202e}d\u{2066}e";
    let body = format!(
        "{{\"class\":\"allow\",\"command\":{}}}\n",
        Value::from(command)
    );
    let log = fixture(dir.path(), body.as_bytes());
    let out = shguard(dir.path(), &["report", "--show-commands", &log], b"");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = text(&out.stdout);
    for raw in ['\u{9b}', '\u{7f}', '\u{202e}', '\u{2066}'] {
        assert!(!stdout.contains(raw), "raw {raw:?} in {stdout:?}");
    }
    assert!(
        stdout.contains("\"a\\u{009B}b\\u{007F}c\\u{202E}d\\u{2066}e\""),
        "{stdout:?}"
    );
}

#[test]
fn an_overlong_line_is_invalid_and_later_lines_are_counted() {
    let dir = ok(tempfile::tempdir());
    let mut body = String::from("{\"class\":\"allow\"}\n{\"class\":\"");
    body.push_str(&"x".repeat(3 * 1024 * 1024));
    body.push_str("\"}\n{\"class\":\"allow\"}\n");
    let log = fixture(dir.path(), body.as_bytes());
    let out = shguard(dir.path(), &["report", &log], b"");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(text(&out.stdout), "2\tallow\n1\tinvalid\n3\ttotal\n");
}

#[test]
fn only_twenty_classes_are_listed_but_the_total_counts_all() {
    let dir = ok(tempfile::tempdir());
    let mut names: Vec<&str> = DecisionClass::all()
        .take(25)
        .map(DecisionClass::as_str)
        .collect();
    assert_eq!(names.len(), 25);
    let mut body = String::new();
    for name in &names {
        body.push_str(&format!("{{\"class\":\"{name}\"}}\n"));
    }
    names.sort_unstable();
    let log = fixture(dir.path(), body.as_bytes());
    let out = shguard(dir.path(), &["report", &log], b"");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = text(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 21, "{stdout}");
    assert_eq!(lines[0], format!("1\t{}", names[0]));
    assert_eq!(lines[19], format!("1\t{}", names[19]));
    assert_eq!(lines[20], "25\ttotal");
}

/// Reports a log with one line of the given `class` (command `SENT`) and one
/// valid line, without and with `--show-commands`.
fn forged_report(dir: &Path, class: &str) -> Vec<Output> {
    let body = format!(
        "{{\"class\":{},\"command\":\"SENT\"}}\n{{\"class\":\"allow\",\"command\":\"ls\"}}\n",
        Value::from(class)
    );
    let log = fixture(dir, body.as_bytes());
    let mut outs = Vec::new();
    for flags in [&[][..], &["--show-commands"]] {
        let mut args = vec!["report"];
        args.extend_from_slice(flags);
        args.push(&log);
        outs.push(shguard(dir, &args, b""));
    }
    outs
}

#[test]
fn a_command_text_in_the_class_field_is_invalid_and_never_printed() {
    let dir = ok(tempfile::tempdir());
    for out in forged_report(dir.path(), "export TOKEN=abc123") {
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let stdout = text(&out.stdout);
        assert!(stdout.contains("1\tinvalid\n"), "{stdout}");
        assert!(stdout.ends_with("2\ttotal\n"), "{stdout}");
        for stream in [stdout, text(&out.stderr)] {
            for word in ["SENT", "TOKEN", "abc123", "export"] {
                assert!(!stream.contains(word), "{word}: {stream}");
            }
        }
    }
}

#[test]
fn an_escape_byte_in_the_class_field_is_invalid_and_never_printed() {
    let dir = ok(tempfile::tempdir());
    for out in forged_report(dir.path(), "allow\u{1b}[31m") {
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let stdout = text(&out.stdout);
        assert!(stdout.contains("1\tinvalid\n"), "{stdout}");
        assert!(!out.stdout.contains(&0x1b) && !out.stderr.contains(&0x1b));
        assert!(!stdout.contains("[31m"), "{stdout}");
        assert!(!stdout.contains("SENT"), "{stdout}");
        assert!(!text(&out.stderr).contains("SENT"), "{out:?}");
    }
}

#[test]
fn a_plausible_class_this_version_does_not_know_is_invalid() {
    let dir = ok(tempfile::tempdir());
    for out in forged_report(dir.path(), "unknown:from_the_future") {
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let stdout = text(&out.stdout);
        assert!(stdout.contains("1\tinvalid\n"), "{stdout}");
        assert!(!stdout.contains("from_the_future"), "{stdout}");
    }
}

#[test]
fn a_missing_file_fails_and_a_misused_command_is_a_usage_error() {
    let dir = ok(tempfile::tempdir());
    let absent = dir.path().join("absent.jsonl").display().to_string();
    let out = shguard(dir.path(), &["report", &absent], b"");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(!out.stderr.is_empty(), "{out:?}");
    for args in [
        &["report"][..],
        &["report", "--show-commands"],
        &["report", "--bogus", "x"],
        &["report", "a", "b"],
        &["report", "a", "--show-commands"],
        &["report", "--show-commands", "a", "b"],
    ] {
        let out = shguard(dir.path(), args, b"");
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
    }
}

#[test]
fn the_hook_writes_a_class_that_report_counts() {
    let dir = ok(tempfile::tempdir());
    let log = dir.path().join("decisions.jsonl");
    let config = dir.path().join("config.toml");
    let user_row = "[[row]]\nkey = [\"uname\"]\nsource = \"https://example.com\"\n\
                    order = \"permute\"\ndashdash = \"ends\"\n";
    ok(std::fs::write(
        &config,
        format!(
            "decision_log = {:?}\n{user_row}\
             [[rule]]\nid = \"ls-a\"\nkey = [\"ls\"]\nopts = [[\"-a\"]]\noutcome = \"ask\"\n",
            log.display().to_string()
        ),
    ));
    let run = |stdin: &[u8]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shguard"));
        cmd.env("HOME", dir.path()).env("SHGUARD_CONFIG", &config);
        let out = spawn(cmd, stdin);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
    };
    let cases: [(&[u8], &str); 8] = [
        (&bash("ls -l"), "allow"),
        (&bash("uname"), "allow_user_row"),
        (&bash("ls -a"), "rule_hit"),
        (&bash("definitely-not-in-the-catalog"), "unknown:no_row"),
        (&bash("echo $(id)"), "parse_refusal:unquoted_dollar"),
        (&bash("  "), "empty_command"),
        (b"junk", "malformed_input"),
        (&bash("ls -l"), "allow"),
    ];
    for (stdin, _) in &cases {
        run(stdin);
    }
    let lines: Vec<Value> = ok(std::fs::read_to_string(&log))
        .lines()
        .map(|l| ok(serde_json::from_str(l)))
        .collect();
    assert_eq!(lines.len(), cases.len());
    for (line, (_, class)) in lines.iter().zip(&cases) {
        assert_eq!(line["class"], *class, "{line}");
    }
    let out = shguard(dir.path(), &["report", &log.display().to_string()], b"");
    assert_eq!(
        text(&out.stdout),
        "2\tallow\n1\tallow_user_row\n1\tempty_command\n\
         1\tmalformed_input\n1\tparse_refusal:unquoted_dollar\n\
         1\trule_hit\n1\tunknown:no_row\n8\ttotal\n"
    );
}
