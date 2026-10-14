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
//! must equal the compile-time one, so a binary reused from another
//! checkout's shared `CARGO_TARGET_DIR` fails loudly instead of passing
//! against (or blessing into) that checkout's snapshots.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/golden.rs"]
mod golden;

use std::ffi::OsStr;
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

#[test]
fn golden_snapshot_dir_resolution_detects_a_foreign_build() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(
        golden::resolve(here, Some(here.as_os_str())),
        Ok(here.to_path_buf())
    );
    assert!(golden::resolve(here, None).is_err());
    let other = golden::resolve(here, Some(OsStr::new("/nonexistent/other-checkout")));
    assert!(other.is_err_and(|msg| msg.contains("per-checkout CARGO_TARGET_DIR")));
}
