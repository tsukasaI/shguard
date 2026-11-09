//! Helpers shared by the integration tests. Each `tests/*.rs` is its own
//! crate, so every file includes this module with `mod common;` and uses only
//! part of it.

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use shguard::catalog::{EMBEDDED, Loaded, load};
use shguard_kernel::decision::Decision;

pub fn embedded() -> Loaded {
    match load(EMBEDDED) {
        Ok(l) => l,
        Err(e) => panic!("the embedded catalog does not load: {e:?}"),
    }
}

pub fn decide(l: &Loaded, cmd: &str) -> Decision {
    let Ok(script) = shguard_syntax::parse(cmd.as_bytes()) else {
        panic!("`{cmd}` is outside the subset");
    };
    shguard_kernel::decide::decide(&l.catalog, &l.rules, script).decision()
}

pub fn assert_all(cmds: &[&str], want: Decision) {
    let l = embedded();
    for cmd in cmds {
        assert_eq!(decide(&l, cmd), want, "`{cmd}`");
    }
}

pub fn assert_allow(cmds: &[&str]) {
    assert_all(cmds, Decision::Allow);
}

pub fn assert_not_allow(cmds: &[&str]) {
    let l = embedded();
    for cmd in cmds {
        assert_ne!(decide(&l, cmd), Decision::Allow, "`{cmd}`");
    }
}

/// The hook input for a Bash call.
pub fn bash(command: &str) -> Vec<u8> {
    serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": command } })
        .to_string()
        .into_bytes()
}

/// Does not isolate the child from the developer's environment: the caller
/// must set or remove both `HOME` and `SHGUARD_CONFIG`.
pub fn spawn(mut cmd: Command, stdin: &[u8]) -> Output {
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

/// The JSON the hook wrote, after checking the status is 0.
pub fn answer(out: &Output) -> Value {
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(e) => panic!("{e:?}"),
    };
    assert_eq!(
        v.get("hookSpecificOutput")
            .and_then(|o| o.get("hookEventName"))
            .and_then(Value::as_str),
        Some("PreToolUse")
    );
    v
}

pub fn decision(out: &Output) -> Option<String> {
    answer(out)
        .get("hookSpecificOutput")
        .and_then(|o| o.get("permissionDecision"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}
