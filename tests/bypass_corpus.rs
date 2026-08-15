//! Persisted bypass-candidate corpus regression suite (issue #74's
//! "persisted candidate corpus + regression/discovery split" item,
//! foundational prerequisite for #94's external-bypass-catalog ingestion).
//!
//! Unlike `tests/guardfall.rs`/`tests/benign_corpus.rs` (Rust literal
//! arrays, for shguard's own internally-discovered cases), this suite
//! parses `bypass_corpus.toml` — a checked-in, externally-attributed
//! corpus — so `.claude/workflows/bypass-hunt.js`'s hunt/verify agents can
//! read the same file to avoid re-reporting an already-covered payload
//! (the "discovery pass seeded with what has already been tried" half of
//! #74's item; this file delivers the other half, the deterministic
//! regression pass: batch-probe every known payload, diff against its
//! recorded decision, zero LLM judgment).

#![allow(clippy::expect_used)]

use std::collections::HashSet;

use serde::Deserialize;
use shguard::verdict::Decision;

// `Decision` deliberately does not derive `Deserialize` (src/verdict.rs) —
// adding one to a core public type just for this test would widen its
// contract. `expected` is parsed as a plain `String` here and converted at
// this boundary instead, so an invalid corpus entry fails loudly at parse
// time rather than silently deserializing into a wrong-but-valid variant.
#[derive(Debug, Deserialize)]
struct RawCase {
    payload: String,
    expected: String,
    source: String,
    #[serde(default)]
    #[allow(dead_code)] // documentation-only field, not asserted on
    note: String,
}

#[derive(Debug, Deserialize)]
struct Corpus {
    case: Vec<RawCase>,
}

struct Case {
    payload: String,
    expected: Decision,
    source: String,
}

/// Parses `bypass_corpus.toml` into a fully-typed `Vec<Case>` up front —
/// an unknown `expected` spelling, a missing field, or a duplicate
/// `payload` is a hard panic here, not a skipped row: a malformed or
/// silently-shadowed entry must fail the run loudly, not quietly stop
/// pinning the case it was meant to cover.
fn parse_corpus() -> Vec<Case> {
    let raw: Corpus = toml::from_str(include_str!("bypass_corpus.toml"))
        .expect("bypass_corpus.toml should be valid TOML matching the Corpus schema");

    let mut seen_payloads = HashSet::new();
    raw.case
        .into_iter()
        .map(|c| {
            let expected = match c.expected.as_str() {
                "Allow" => Decision::Allow,
                "Ask" => Decision::Ask,
                "Block" => Decision::Block,
                other => panic!(
                    "bypass_corpus.toml: case with payload {:?} has expected = {other:?}, \
                     which is not one of \"Allow\"/\"Ask\"/\"Block\"",
                    c.payload
                ),
            };
            assert!(
                seen_payloads.insert(c.payload.clone()),
                "bypass_corpus.toml: duplicate payload {:?} — each entry must be unique",
                c.payload
            );
            assert!(
                !c.source.trim().is_empty(),
                "bypass_corpus.toml: case with payload {:?} has an empty source",
                c.payload
            );
            Case {
                payload: c.payload,
                expected,
                source: c.source,
            }
        })
        .collect()
}

#[test]
fn bypass_corpus_regression() {
    let cases = parse_corpus();
    assert!(
        !cases.is_empty(),
        "bypass_corpus.toml parsed to zero cases — an emptied corpus must fail loudly, not pass \
         vacuously"
    );

    for case in &cases {
        let verdict = shguard::analyze(&case.payload);
        assert_eq!(
            verdict.decision(),
            case.expected,
            "corpus case {:?} (source: {}): expected {:?}, got {:?}",
            case.payload,
            case.source,
            case.expected,
            verdict.decision()
        );
    }
}
