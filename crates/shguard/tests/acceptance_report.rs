//! The soft acceptance report (M15). Unlike `acceptance.rs`, nothing here
//! fails on a decision: it prints numbers to compare across changes.
//!
//! - Old Ask (or Block) → new Allow: the corpus rows whose old-engine
//!   `decision` was not Allow and that the embedded catalog now Allows,
//!   compared with the committed `acceptance/baseline/old_ask_new_allow.jsonl`
//!   (outside `acceptance/*.jsonl`, which the differential test reads as
//!   corpora). A row that is new since the baseline is a decision someone
//!   should look at.
//! - `denials_input` coverage: how many commands the parser accepts, the
//!   rejected ones grouped by the first unsupported construct, and the
//!   accepted ones by decision and first reason.
//! - #1038: across every corpus, how many parsed commands are Unknown first
//!   because of a tilde-leading word or an opaque inline value in option
//!   position.
//!
//! Run it with `cargo test -p shguard --test acceptance_report -- --nocapture`.
//! Set `SHGUARD_BLESS_BASELINE=1` to rewrite the baseline from the current
//! catalog.

use std::collections::{BTreeMap, BTreeSet};

use shguard::catalog::{EMBEDDED, Loaded, load};
use shguard_kernel::ast::{Opaque, Part};
use shguard_kernel::decide::{Verdict, decide};
use shguard_kernel::verdict::{Reason, UnknownKind, simple_at};

/// Corpora whose rows carry the old engine's `decision`.
const DECIDED: &[&str] = &["benign_corpus.jsonl", "fuzz.jsonl", "guardfall.jsonl"];

const BASELINE: &str = "baseline/old_ask_new_allow.jsonl";

fn embedded() -> Loaded {
    match load(EMBEDDED) {
        Ok(l) => l,
        Err(e) => panic!("the embedded catalog does not load: {e:?}"),
    }
}

fn path(name: &str) -> String {
    format!("{}/../../acceptance/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn rows(name: &str) -> Vec<serde_json::Value> {
    let Ok(text) = std::fs::read_to_string(path(name)) else {
        panic!("cannot read {name}");
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| match serde_json::from_str(l) {
            Ok(v) => v,
            Err(e) => panic!("{name}: not JSON ({e}): {l}"),
        })
        .collect()
}

fn field<'a>(row: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    row.get(key).and_then(serde_json::Value::as_str)
}

/// One old non-Allow → new Allow row, as the baseline stores it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Flip {
    corpus: String,
    old: String,
    command: String,
}

impl Flip {
    fn to_line(&self) -> String {
        serde_json::json!({ "corpus": self.corpus, "old": self.old, "command": self.command })
            .to_string()
    }
}

fn verdict(l: &Loaded, cmd: &str) -> Option<Verdict> {
    shguard_syntax::parse(cmd.as_bytes())
        .ok()
        .map(|s| decide(&l.catalog, &l.rules, s))
}

fn flips(l: &Loaded) -> BTreeSet<Flip> {
    let mut out = BTreeSet::new();
    for corpus in DECIDED {
        for row in rows(corpus) {
            let (Some(cmd), Some(old)) = (field(&row, "command"), field(&row, "decision")) else {
                panic!("{corpus}: a row without `command` or `decision`");
            };
            if old != "Allow" && matches!(verdict(l, cmd), Some(Verdict::Allow(_))) {
                out.insert(Flip {
                    corpus: (*corpus).to_owned(),
                    old: old.to_owned(),
                    command: cmd.to_owned(),
                });
            }
        }
    }
    out
}

fn baseline() -> BTreeSet<Flip> {
    let Ok(text) = std::fs::read_to_string(path(BASELINE)) else {
        panic!("cannot read {BASELINE}; bless it with SHGUARD_BLESS_BASELINE=1");
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else {
                panic!("{BASELINE}: not JSON: {l}");
            };
            match (field(&v, "corpus"), field(&v, "old"), field(&v, "command")) {
                (Some(corpus), Some(old), Some(command)) => Flip {
                    corpus: corpus.to_owned(),
                    old: old.to_owned(),
                    command: command.to_owned(),
                },
                _ => panic!("{BASELINE}: a row without corpus, old or command: {l}"),
            }
        })
        .collect()
}

fn pct(n: usize, d: usize) -> String {
    if d == 0 {
        return "-".to_owned();
    }
    let tenths = (n * 1000 + d / 2) / d;
    format!("{}.{}%", tenths / 10, tenths % 10)
}

/// The #1038 shape of an `OpaqueOption` word: tilde-leading, or a literal
/// `--name=` (or `-x`) followed by an opaque value.
fn opaque_option_shape(addr_word: Option<&[Part]>) -> &'static str {
    match addr_word {
        Some([Part::Opaque(Opaque::Tilde), ..]) => "tilde-leading word",
        Some([Part::Lit(b), Part::Opaque(_), ..]) if b.starts_with(b"-") => "opaque inline value",
        Some(_) | None => "other",
    }
}

fn reason_label(l: &Loaded, v: &Verdict) -> String {
    let (script, reason) = match v {
        Verdict::Allow(_) => return "Allow".to_owned(),
        Verdict::Ask(s, r) | Verdict::Block(s, r) => (s, r),
    };
    match reason {
        Reason::Rule(id, _) => format!(
            "rule {}",
            l.rule_ids.get(id.0 as usize).map_or("?", String::as_str)
        ),
        Reason::Unknown(UnknownKind::OpaqueOption, addr) => {
            let word = simple_at(script, *addr)
                .zip(addr.word)
                .and_then(|(s, w)| s.words().get(w))
                .map(|w| w.parts());
            format!("OpaqueOption ({})", opaque_option_shape(word))
        }
        Reason::Unknown(kind, _) => format!("{kind:?}"),
    }
}

fn decision_label(v: &Verdict) -> &'static str {
    match v {
        Verdict::Allow(_) => "Allow",
        Verdict::Ask(_, _) => "Ask",
        Verdict::Block(_, _) => "Block",
    }
}

#[test]
fn soft_report() {
    let l = embedded();

    // Old non-Allow → new Allow.
    let now = flips(&l);
    if std::env::var_os("SHGUARD_BLESS_BASELINE").is_some() {
        let mut text = String::new();
        for f in &now {
            text.push_str(&f.to_line());
            text.push('\n');
        }
        if let Err(e) = std::fs::write(path(BASELINE), text) {
            panic!("cannot write {BASELINE}: {e}");
        }
    }
    let base = baseline();
    println!("== old non-Allow -> new Allow (baseline: acceptance/{BASELINE})");
    let mut by_old: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for f in &now {
        *by_old
            .entry((f.corpus.as_str(), f.old.as_str()))
            .or_default() += 1;
    }
    for ((corpus, old), n) in &by_old {
        println!("  {corpus}: old {old} -> Allow: {n}");
    }
    println!("  total: {} (baseline {})", now.len(), base.len());
    for f in now.difference(&base) {
        println!("  NEW since baseline: {}", f.to_line());
    }
    for f in base.difference(&now) {
        println!("  gone since baseline: {}", f.to_line());
    }

    // denials_input coverage.
    let cmds: Vec<String> = rows("denials_input.jsonl")
        .iter()
        .map(|r| match field(r, "command") {
            Some(c) => c.to_owned(),
            None => panic!("denials_input.jsonl: a row without `command`"),
        })
        .collect();
    let mut rejected: BTreeMap<String, usize> = BTreeMap::new();
    let mut decisions: BTreeMap<&str, usize> = BTreeMap::new();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut accepted = 0;
    for cmd in &cmds {
        match shguard_syntax::parse(cmd.as_bytes()) {
            Err(u) => *rejected.entry(format!("{:?}", u.kind)).or_default() += 1,
            Ok(s) => {
                accepted += 1;
                let v = decide(&l.catalog, &l.rules, s);
                *decisions.entry(decision_label(&v)).or_default() += 1;
                *reasons.entry(reason_label(&l, &v)).or_default() += 1;
            }
        }
    }
    let total = cmds.len();
    println!("== denials_input coverage");
    println!("  parsed: {accepted}/{total} ({})", pct(accepted, total));
    let mut rej: Vec<(&String, &usize)> = rejected.iter().collect();
    rej.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (kind, n) in rej {
        println!(
            "  rejected, first construct {kind}: {n} ({})",
            pct(*n, total)
        );
    }
    for (d, n) in &decisions {
        println!("  parsed and {d}: {n} ({})", pct(*n, total));
    }
    let mut rs: Vec<(&String, &usize)> = reasons.iter().collect();
    rs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (r, n) in rs {
        println!("  first reason {r}: {n} ({})", pct(*n, total));
    }

    // #1038 shapes in every corpus.
    println!("== #1038: first reason OpaqueOption, by word shape, all corpora");
    let all = [
        "benign_corpus.jsonl",
        "denials_input.jsonl",
        "fuzz.jsonl",
        "guardfall.jsonl",
        "must_not_allow.jsonl",
    ];
    for corpus in all {
        let mut parsed = 0;
        let mut shapes: BTreeMap<String, usize> = BTreeMap::new();
        for row in rows(corpus) {
            let Some(cmd) = field(&row, "command") else {
                panic!("{corpus}: a row without `command`");
            };
            if let Some(v) = verdict(&l, cmd) {
                parsed += 1;
                let label = reason_label(&l, &v);
                if label.starts_with("OpaqueOption") {
                    *shapes.entry(label).or_default() += 1;
                }
            }
        }
        println!("  {corpus}: parsed {parsed}, {shapes:?}");
    }
}
