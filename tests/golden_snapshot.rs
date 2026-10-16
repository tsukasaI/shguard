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
//! | `denials.jsonl`            | `tests/golden/denials.txt`, when present    |
//!
//! `denials.txt` is one raw command per line (blank lines skipped), so a
//! multi-line command cannot live there. Without it, its test is a no-op.
//!
//! Bless with `SHGUARD_GOLDEN_UPDATE=1 cargo test golden_snapshot`; without
//! that variable the tests only compare. `analyze()` reads only the
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

#[test]
fn golden_snapshot_denials() {
    let golden_dir = golden::golden_dir();
    let input = golden_dir.join("denials.txt");
    match std::fs::read_to_string(&input) {
        Ok(text) => golden::check("denials", text.lines().filter(|line| !line.is_empty())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            assert!(
                !golden_dir.join("denials.jsonl").exists(),
                "tests/golden/denials.jsonl exists without its input tests/golden/denials.txt"
            );
            eprintln!("golden corpus denials: {} absent, skipped", input.display());
        }
        Err(err) => panic!("failed to read {}: {err}", input.display()),
    }
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
