//! Golden-snapshot gate for the RFC #658 stage-1 refactor (issue #659).
//!
//! Stage 1 folds every decision into one `policy::decide`, and must not
//! change any `Decision`. The oracle is a recording of
//! `command -> (decision, matched_rule, deny_message)` from
//! `shguard::analyze()` (before `ask_outcome`; per-mode outcomes stay with
//! `tests/ask_outcome_per_mode.rs`), one JSONL file per corpus under
//! `tests/golden/`, sorted and deduplicated by command.
//!
//! Each corpus is checked next to its own case tables, so no table is
//! copied: every test is named `golden_snapshot_*`, and
//! `cargo test golden_snapshot` runs all of them.
//!
//! | Snapshot                   | Source                                      |
//! |----------------------------|---------------------------------------------|
//! | `guardfall.jsonl`          | `tests/guardfall.rs`                        |
//! | `bypass_corpus.jsonl`      | `tests/bypass_corpus.toml`                  |
//! | `benign_corpus.jsonl`      | `tests/benign_corpus.rs`                    |
//! | `fuzz.jsonl`               | `tests/fuzz_differential.rs`, pinned seed   |
//! | `denials.jsonl`            | `tests/golden/denials_input.jsonl`          |
//!
//! `denials_input.jsonl` is one `{"command": ...}` object per line, so a
//! multi-line command keeps its real newlines through JSON escaping. It is
//! required: a missing file fails the test.
//!
//! Bless with `SHGUARD_GOLDEN_UPDATE=1 cargo test golden_snapshot`; without
//! that variable the tests only compare, and blessing under `LEFTHOOK` or
//! `CI` fails so an exported variable cannot rewrite a gate. Blessing prints
//! what changed against the previous snapshot. `analyze()` reads only the
//! embedded rules and never the filesystem, `HOME`, or cwd, so the
//! snapshot reproduces on any machine.
//!
//! The snapshot directory comes from the run-time `CARGO_MANIFEST_DIR` and
//! must equal the compile-time one of both this test crate and the linked
//! `shguard` lib (`shguard::BUILD_MANIFEST_DIR`), so a binary or lib reused
//! from another checkout's shared `CARGO_TARGET_DIR` fails loudly instead of
//! passing against (or blessing into) that checkout's snapshots.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/golden.rs"]
mod golden;

use std::path::Path;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InputLine {
    command: String,
}

fn parse_commands(path: &Path, text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<InputLine>(line)
                .unwrap_or_else(|err| {
                    panic!(
                        "{}:{}: malformed input line: {err}",
                        path.display(),
                        index + 1
                    )
                })
                .command
        })
        .collect()
}

#[test]
fn golden_snapshot_denials() {
    let input = golden::golden_dir().join("denials_input.jsonl");
    let text = std::fs::read_to_string(&input)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", input.display()));
    golden::check("denials", parse_commands(&input, &text));
}

#[test]
fn golden_snapshot_denials_input_keeps_real_newlines() {
    let path = Path::new("denials_input.jsonl");
    let commands = parse_commands(
        path,
        "{\"command\":\"echo a\\necho b\"}\n\n{\"command\":\"ls\"}\n",
    );
    assert_eq!(commands, ["echo a\necho b", "ls"]);
}

#[test]
#[should_panic(expected = "malformed input line")]
fn golden_snapshot_denials_input_rejects_a_raw_command_line() {
    parse_commands(Path::new("denials_input.jsonl"), "rm -rf /tmp/x\n");
}

#[test]
fn golden_snapshot_update_is_off_unless_exactly_one() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| std::ffi::OsString::from(value))
        }
    };
    assert_eq!(golden::update_requested(env(&[])), Ok(false));
    assert_eq!(
        golden::update_requested(env(&[("SHGUARD_GOLDEN_UPDATE", "0")])),
        Ok(false)
    );
    assert_eq!(
        golden::update_requested(env(&[("SHGUARD_GOLDEN_UPDATE", "1")])),
        Ok(true)
    );
    assert_eq!(
        golden::update_requested(env(&[("LEFTHOOK", "1")])),
        Ok(false)
    );
}

#[test]
fn golden_snapshot_update_refuses_under_lefthook_or_ci() {
    for guard in ["LEFTHOOK", "CI"] {
        let err = golden::update_requested(|name| {
            (name == "SHGUARD_GOLDEN_UPDATE" || name == guard).then(|| "1".into())
        })
        .unwrap_err();
        assert!(err.contains(guard), "{err}");
        assert!(err.contains("unset SHGUARD_GOLDEN_UPDATE"), "{err}");
    }
}

const SOURCE_WITH_ONE_TABLE: &str = "const A_CASES: &[(&str, Decision)] = &[\n];\n";

#[test]
fn golden_snapshot_registry_accepts_matching_sets() {
    assert_eq!(
        golden::check_table_registry(SOURCE_WITH_ONE_TABLE, &["A_CASES"], &[]),
        Ok(())
    );
    assert_eq!(
        golden::check_table_registry(SOURCE_WITH_ONE_TABLE, &[], &["A_CASES"]),
        Ok(())
    );
}

#[test]
fn golden_snapshot_registry_flags_an_unregistered_table_of_any_shape() {
    for source in [
        "const B_CASES: &[(&str, Decision)] = &[\n];\n",
        "const B_CASES: &[(&str, &str)] = &[\n];\n",
        "const B_CASES: &[(&str, Decision, &str)] = &[\n];\n",
        "pub const B_CASES: &[(\n    &str,\n    Decision,\n)] = &[\n];\n",
        "const B_CASES:\n    &[(&str, Decision)] = &[\n];\n",
        "static B_CASES: &[(&str, Decision)] = &[\n];\n",
    ] {
        let err = golden::check_table_registry(source, &[], &[]).unwrap_err();
        assert!(
            err.contains("B_CASES is declared but neither"),
            "{source}: {err}"
        );
    }
}

#[test]
fn golden_snapshot_registry_flags_a_reintroduced_inline_table() {
    for source in [
        "fn t() {\n    let cases = &[\n        (\"ls\", Decision::Allow),\n    ];\n}\n",
        "fn t() {\n    let table: &[(&str, Decision)] = &[];\n}\n",
    ] {
        let err = golden::check_table_registry(source, &[], &[]).unwrap_err();
        assert!(err.contains("not a module const"), "{source}: {err}");
    }
}

#[test]
fn golden_snapshot_registry_flags_a_duplicate_hiding_a_missing_table() {
    let source = "const A: &[(&str, Decision)] = &[];\nconst B: &[(&str, Decision)] = &[];\n";
    let err = golden::check_table_registry(source, &["A", "A"], &[]).unwrap_err();
    assert!(err.contains("B is declared but neither"), "{err}");
    assert!(err.contains("A is registered more than once"), "{err}");
}

#[test]
fn golden_snapshot_registry_flags_stale_and_overlapping_names() {
    let err =
        golden::check_table_registry(SOURCE_WITH_ONE_TABLE, &["A_CASES", "GONE"], &["A_CASES"])
            .unwrap_err();
    assert!(
        err.contains("registered name GONE is not a declared"),
        "{err}"
    );
    assert!(
        err.contains("A_CASES is both registered and exempt"),
        "{err}"
    );
    let err =
        golden::check_table_registry(SOURCE_WITH_ONE_TABLE, &["A_CASES"], &["OLD"]).unwrap_err();
    assert!(err.contains("exempt name OLD is not a declared"), "{err}");
}

#[test]
fn golden_snapshot_registry_ignores_plain_string_lists() {
    let source = "const INLINE: &[&str] = &[\"ls\"];\nlet dirs: &[&str] = &[\"a\"];\n";
    assert_eq!(golden::check_table_registry(source, &[], &[]), Ok(()));
}

const FOREIGN: &str = "/nonexistent/other-checkout";

#[test]
fn golden_snapshot_dir_resolution_accepts_the_same_checkout() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(
        golden::resolve(here, here, Some(here.as_os_str())),
        Ok(here.to_path_buf())
    );
    assert_eq!(golden::golden_dir(), here.join("tests/golden"));
}

#[test]
fn golden_snapshot_dir_resolution_names_the_direct_run_cases_when_unset() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let err = golden::resolve(here, here, None).unwrap_err();
    assert!(err.contains("CARGO_MANIFEST_DIR is not set at run time"));
    assert!(err.contains("directly"));
    assert!(err.contains("nextest"));
}

#[test]
fn golden_snapshot_dir_resolution_rejects_a_foreign_test_binary() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let err = golden::resolve(Path::new(FOREIGN), here, Some(here.as_os_str())).unwrap_err();
    assert!(err.contains("this test binary was built for"));
    assert!(err.contains("per-checkout CARGO_TARGET_DIR"));
}

#[test]
fn golden_snapshot_dir_resolution_rejects_a_foreign_lib() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let err = golden::resolve(here, Path::new(FOREIGN), Some(here.as_os_str())).unwrap_err();
    assert!(err.contains("this shguard lib was built for"));
    assert!(err.contains("per-checkout CARGO_TARGET_DIR"));
}

#[test]
fn golden_snapshot_dir_resolution_rejects_when_both_builds_differ_from_runtime() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let err = golden::resolve(
        Path::new(FOREIGN),
        Path::new(FOREIGN),
        Some(here.as_os_str()),
    )
    .unwrap_err();
    assert!(err.contains("this test binary was built for"));
}

#[test]
fn golden_snapshot_dir_resolution_rejects_two_existing_distinct_checkouts() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    assert!(golden::resolve(a.path(), a.path(), Some(b.path().as_os_str())).is_err());
    assert!(golden::resolve(b.path(), a.path(), Some(b.path().as_os_str())).is_err());
}

#[cfg(unix)]
#[test]
fn golden_snapshot_dir_resolution_treats_a_symlinked_checkout_as_the_same() {
    let real = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let link = scratch.path().join("link");
    std::os::unix::fs::symlink(real.path(), &link).unwrap();
    assert_eq!(
        golden::resolve(real.path(), &link, Some(link.as_os_str())),
        Ok(link.clone())
    );
    assert!(golden::resolve(&link, real.path(), Some(real.path().as_os_str())).is_ok());
}
