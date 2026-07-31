//! Dev-facing probe for the `bypass-hunt` workflow (`.claude/workflows/`):
//! prints [`shguard::analyze`]'s verdict for one or more payload strings as
//! compact JSON, one line per payload, in argument order.
//!
//! Usage: `cargo run -q --example probe -- '<payload>' ['<payload>' ...]`
//!
//! ## Output contract
//!
//! Exactly one JSON line is emitted per payload, unconditionally, in
//! argument order — a consumer may map line N to argument N with no
//! exceptions. On the success path:
//! `{"command": <payload>, "decision": <variant>, "reason": <string or null>}`
//!
//! If a given payload's verdict fails to serialise, that line is replaced
//! in-position with `{"command": <payload>, "error": <message>}` rather than
//! being skipped — skipping would shift every later payload's line up by
//! one, silently re-attributing a later payload's verdict to an earlier
//! position. The process still exits 2 and logs to stderr in that case.
//!
//! ## Decision vocabulary
//!
//! `decision` is the [`shguard::verdict::Decision`] variant name verbatim —
//! `"Allow"` / `"Ask"` / `"Block"` — NOT the hook adapter's wire vocabulary
//! (`allow`/`deny`/`ask`, see `src/adapter.rs`). This is deliberate: the
//! hunt workflow's deliverable is proposed `tests/guardfall.rs` table lines
//! written in terms of `Decision::…`, and an earlier draft of this harness
//! translated the hook vocabulary (`deny`) into the enum vocabulary and got
//! it wrong (`Decision::Deny`, which does not exist — the variant is
//! `Decision::Block`). Speaking the enum's own vocabulary here removes that
//! translation layer instead of fixing it.
//!
//! ## Rule source
//!
//! Evaluates via [`shguard::analyze`], which uses shguard's built-in rules
//! only and reads no environment — the result is reproducible across
//! machines and independent of `~/.config/shguard/config.toml`.
//! [`shguard::analyze_with_policy`] is the escape hatch if someone later
//! wants to probe against a real user policy instead; this example
//! intentionally does not use it.
//!
//! ## Safety
//!
//! The payload is never executed. It is only ever passed as a `&str` into
//! [`shguard::analyze`]. This file contains no `std::process::Command`, no
//! shelling out, and no other form of execution.

use shguard::verdict::{Decision, Reason};

fn main() {
    let payloads: Vec<String> = std::env::args().skip(1).collect();

    if payloads.is_empty() {
        eprintln!("usage: cargo run -q --example probe -- '<payload>' ['<payload>' ...]");
        eprintln!("  prints one JSON verdict line per payload; the payload is never executed");
        std::process::exit(2);
    }

    let mut had_error = false;

    for payload in &payloads {
        let verdict = shguard::analyze(payload);
        let value = serde_json::json!({
            "command": payload,
            "decision": decision_name(verdict.decision()),
            "reason": verdict.reason().map(Reason::as_str),
        });

        match serde_json::to_string(&value) {
            Ok(line) => println!("{line}"),
            Err(err) => {
                eprintln!("failed to serialise verdict for {payload:?}: {err}");
                had_error = true;
                // `Value`'s `Display` impl (unlike `serde_json::to_string`)
                // is infallible, so this in-position error line always
                // prints even though the success-path serialisation above
                // did not.
                let error_value = serde_json::json!({
                    "command": payload,
                    "error": err.to_string(),
                });
                println!("{error_value}");
            }
        }
    }

    if had_error {
        std::process::exit(2);
    }
}

/// The [`Decision`] variant name, verbatim — see the module doc comment for
/// why this must not be translated into the hook's `allow`/`ask`/`deny`
/// wire vocabulary.
fn decision_name(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "Allow",
        Decision::Ask => "Ask",
        Decision::Block => "Block",
    }
}
