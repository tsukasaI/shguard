//! The acceptance corpora under the embedded catalog and no user config.
//! Only the `command` field of a row is read; the old engine's fields are
//! not expectations.

use shguard::catalog::{EMBEDDED, Loaded, load};
use shguard_kernel::decision::Decision;

/// Guardfall commands that the catalog is meant to Allow, by exact text. Each
/// entry must be in the corpus and must be Allow, so the list cannot rot.
const GUARDFALL_ALLOWED: &[&str] = &[
    "cat /etc/bash.bashrc",
    "cat file | grep x | head",
    "cp src dst",
    "echo \"(:wq)\"",
    "echo \"(eee)\"",
    "echo \"f(x)\"",
    "echo \"x(:h)\"",
    "echo hi | cat | wc -l",
    "git log --format='%(refname)'",
    "git log --oneline",
    "git log | grep x | head",
    "git push --set-upstream origin x",
    "git push origin main",
    "rm -f 'notes(1).txt'",
    "rm -f file",
];

fn embedded() -> Loaded {
    match load(EMBEDDED) {
        Ok(l) => l,
        Err(e) => panic!("the embedded catalog does not load: {e:?}"),
    }
}

/// The `command` of every row of a corpus file.
fn commands(name: &str) -> Vec<String> {
    let path = format!("{}/../../acceptance/{name}", env!("CARGO_MANIFEST_DIR"));
    let Ok(text) = std::fs::read_to_string(&path) else {
        panic!("cannot read {path}");
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let Ok(row) = serde_json::from_str::<serde_json::Value>(l) else {
                panic!("{name}: not JSON: {l}");
            };
            match row.get("command").and_then(serde_json::Value::as_str) {
                Some(c) => c.to_owned(),
                None => panic!("{name}: no `command` string in {l}"),
            }
        })
        .collect()
}

/// A command the parser rejects is not Allow.
fn is_allow(l: &Loaded, cmd: &str) -> bool {
    match shguard_syntax::parse(cmd.as_bytes()) {
        Ok(script) => {
            shguard_kernel::decide::decide(&l.catalog, &l.rules, script).decision()
                == Decision::Allow
        }
        Err(_) => false,
    }
}

#[test]
fn no_must_not_allow_command_is_allowed() {
    let l = embedded();
    let cmds = commands("must_not_allow.jsonl");
    assert!(!cmds.is_empty());
    let allowed: Vec<&String> = cmds.iter().filter(|c| is_allow(&l, c)).collect();
    assert!(allowed.is_empty(), "allowed: {allowed:#?}");
}

#[test]
fn guardfall_commands_are_not_allowed_except_the_listed_ones() {
    let l = embedded();
    let cmds = commands("guardfall.jsonl");
    assert!(!cmds.is_empty());
    let unlisted: Vec<&String> = cmds
        .iter()
        .filter(|c| is_allow(&l, c) && !GUARDFALL_ALLOWED.contains(&c.as_str()))
        .collect();
    assert!(
        unlisted.is_empty(),
        "allowed but not listed:\n{unlisted:#?}"
    );
    for entry in GUARDFALL_ALLOWED {
        assert!(
            cmds.iter().any(|c| c == entry),
            "`{entry}` is not in the corpus"
        );
        assert!(is_allow(&l, entry), "`{entry}` is not Allow");
    }
}

/// #1082: `-t` is GNU only, so the cp row lacks it and these are Unknown.
#[test]
fn cp_target_directory_into_dev_is_not_allowed() {
    let l = embedded();
    let cmds = commands("guardfall.jsonl");
    for cmd in [
        "cp --target-directory=/dev/sda payload",
        "cp -t/dev/sda payload",
    ] {
        assert!(
            cmds.iter().any(|c| c == cmd),
            "`{cmd}` is not in the corpus"
        );
        assert!(!is_allow(&l, cmd), "`{cmd}`");
    }
}
