//! Test-only recorder and replayer for `tests/golden/legacy_units.jsonl`:
//! the inputs the `gate` and `rules` unit tests feed the engine, with the
//! decision (gate) or matcher result (rules) they observe, so the corpus
//! outlives those tests (docs/rfc-redesign.md, stage R0).
//!
//! Capture: with `SHGUARD_LEGACY_CAPTURE=<path>` set, every engine call a
//! `gate::`/`rules::` unit test makes appends `<test name>\t<row>` to
//! `<path>`; `scripts/regen-legacy-units` turns that into the corpus.
//! Check: without it, the same calls must already be in the corpus with the
//! same result, so a new or changed unit test cannot escape it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::Write as _;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::normalize::{NormalizedWord, Resolution, UnresolvableKind};
use crate::rules::{Allowlist, Rules, UserConfig, merge_user_config};
use crate::verdict::Verdict;

/// Inputs above this many bytes are not recorded: the corpus is meant to be
/// read and diffed, and the only larger inputs are the stack-overflow pins
/// that build megabyte payloads with `repeat`. They are listed as
/// `excluded` rows instead.
const MAX_INPUT_BYTES: usize = 4096;

const CAPTURE_ENV: &str = "SHGUARD_LEGACY_CAPTURE";
const REGEN_HINT: &str = "add a legacy_units row (run scripts/regen-legacy-units)";
const UNREPLAYABLE_CONFIG: &str = "rule set is not reproducible from the TOML texts the test parsed \
     (path canonicalizer, home twins, or a hand-built rule set)";

static CORPUS_TEXT: &str = include_str!("../tests/golden/legacy_units.jsonl");

// ---------------------------------------------------------------------
// Row model
// ---------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    #[default]
    Embedded,
    Parse(String),
    UserConfig(String),
    Unreplayable(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    #[serde(default)]
    rules: Source,
    #[serde(default)]
    allowlist: Source,
}

impl Config {
    fn is_embedded(&self) -> bool {
        *self == Self::default()
    }

    /// An unreplayable config names no rule set, so two different rule sets
    /// share it; the result then has to be part of the row's identity.
    fn identity_of<T: Serialize>(&self, expect: &T) -> Option<Value> {
        let unreplayable = matches!(self.rules, Source::Unreplayable(_))
            || matches!(self.allowlist, Source::Unreplayable(_));
        unreplayable.then(|| serde_json::to_value(expect).unwrap())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Word {
    Plain(String),
    Full {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolved: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unresolvable: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        ifs_derived: bool,
        single_word: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tail: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        head: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        head_tilde: bool,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RulesInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argv: Option<Vec<Word>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stages: Option<Vec<Vec<Word>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tokens: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GateExpect {
    decision: String,
    reason: Option<String>,
    rule: Option<String>,
    deny_message: Option<String>,
    suppressed_by: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Row {
    Gate {
        #[serde(default, skip_serializing_if = "Config::is_embedded")]
        config: Config,
        command: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        expect: GateExpect,
    },
    Rules {
        #[serde(default, skip_serializing_if = "Config::is_embedded")]
        config: Config,
        method: String,
        input: RulesInput,
        expect: Value,
    },
    Excluded {
        test: String,
        reason: String,
    },
}

impl Row {
    fn key(&self) -> String {
        let key = match self {
            Self::Gate {
                config,
                command,
                cwd,
                expect,
            } => serde_json::json!(["gate", config, cwd, command, config.identity_of(expect)]),
            Self::Rules {
                config,
                method,
                input,
                expect,
            } => serde_json::json!(["rules", config, method, input, config.identity_of(expect)]),
            Self::Excluded { test, reason } => serde_json::json!(["excluded", test, reason]),
        };
        key.to_string()
    }
}

/// Parses the corpus strictly: every non-final line must be one valid row,
/// no key may repeat, and an empty corpus is an error.
pub(crate) fn parse_corpus(text: &str) -> Result<HashMap<String, Row>, String> {
    let mut rows = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let row: Row = serde_json::from_str(line)
            .map_err(|err| format!("legacy_units.jsonl line {number}: {err}"))?;
        if let Some(previous) = rows.insert(row.key(), row) {
            return Err(format!(
                "legacy_units.jsonl line {number}: duplicate key {}",
                previous.key()
            ));
        }
    }
    if rows.is_empty() {
        return Err("legacy_units.jsonl has no rows".to_string());
    }
    Ok(rows)
}

fn corpus() -> &'static HashMap<String, Row> {
    static CORPUS: OnceLock<HashMap<String, Row>> = OnceLock::new();
    CORPUS.get_or_init(|| parse_corpus(CORPUS_TEXT).unwrap_or_else(|err| panic!("{err}")))
}

// ---------------------------------------------------------------------
// Words
// ---------------------------------------------------------------------

const KINDS: [(UnresolvableKind, &str); 9] = [
    (UnresolvableKind::CommandSubstitution, "CommandSubstitution"),
    (UnresolvableKind::ParameterExpansion, "ParameterExpansion"),
    (UnresolvableKind::NonUtf8, "NonUtf8"),
    (UnresolvableKind::ExpansionLimit, "ExpansionLimit"),
    (UnresolvableKind::ArithmeticExpansion, "ArithmeticExpansion"),
    (UnresolvableKind::ProcessSubstitution, "ProcessSubstitution"),
    (UnresolvableKind::DevFdPath, "DevFdPath"),
    (
        UnresolvableKind::UnsupportedStructure,
        "UnsupportedStructure",
    ),
    (UnresolvableKind::EmbeddedNul, "EmbeddedNul"),
];

fn kind_name(kind: UnresolvableKind) -> &'static str {
    match kind {
        UnresolvableKind::CommandSubstitution => "CommandSubstitution",
        UnresolvableKind::ParameterExpansion => "ParameterExpansion",
        UnresolvableKind::NonUtf8 => "NonUtf8",
        UnresolvableKind::ExpansionLimit => "ExpansionLimit",
        UnresolvableKind::ArithmeticExpansion => "ArithmeticExpansion",
        UnresolvableKind::ProcessSubstitution => "ProcessSubstitution",
        UnresolvableKind::DevFdPath => "DevFdPath",
        UnresolvableKind::UnsupportedStructure => "UnsupportedStructure",
        UnresolvableKind::EmbeddedNul => "EmbeddedNul",
    }
}

fn kind_from_name(name: &str) -> UnresolvableKind {
    KINDS
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(kind, _)| *kind)
        .unwrap_or_else(|| panic!("unknown unresolvable kind {name:?}"))
}

fn word_row(word: &NormalizedWord) -> Word {
    let (resolved, unresolvable) = match word.resolution() {
        Resolution::Resolved(value) => (Some(value.clone()), None),
        Resolution::Unresolvable(kind) => (None, Some(kind_name(*kind).to_string())),
    };
    let plain = unresolvable.is_none()
        && !word.is_ifs_derived()
        && word.is_single_word()
        && word.literal_tail().is_none()
        && word.literal_head().is_none()
        && !word.literal_head_tilde();
    if plain {
        return Word::Plain(resolved.unwrap_or_default());
    }
    Word::Full {
        resolved,
        unresolvable,
        ifs_derived: word.is_ifs_derived(),
        single_word: word.is_single_word(),
        tail: word.literal_tail().map(str::to_string),
        head: word.literal_head().map(str::to_string),
        head_tilde: word.literal_head_tilde(),
    }
}

fn word_value(row: &Word) -> NormalizedWord {
    match row {
        Word::Plain(value) => NormalizedWord::resolved(value.clone()),
        Word::Full {
            resolved,
            unresolvable,
            ifs_derived,
            single_word,
            tail,
            head,
            head_tilde,
        } => {
            let resolution = match (resolved, unresolvable) {
                (Some(value), None) => Resolution::Resolved(value.clone()),
                (None, Some(kind)) => Resolution::Unresolvable(kind_from_name(kind)),
                _ => panic!("a word row needs exactly one of resolved/unresolvable"),
            };
            NormalizedWord::legacy_from_parts(
                resolution,
                *ifs_derived,
                *single_word,
                tail.clone(),
                *head_tilde,
                head.clone(),
            )
        }
    }
}

fn words(rows: &[Word]) -> Vec<NormalizedWord> {
    rows.iter().map(word_value).collect()
}

// ---------------------------------------------------------------------
// Rule-set provenance
// ---------------------------------------------------------------------

#[derive(Default)]
struct ParsedTexts {
    rules: Vec<String>,
    allowlist: Vec<String>,
    user_config: Vec<String>,
}

thread_local! {
    static PARSED: RefCell<ParsedTexts> = RefCell::new(ParsedTexts::default());
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

fn is_embedded_text(text: &str, embedded: &str) -> bool {
    std::ptr::eq(text.as_ptr(), embedded.as_ptr())
}

pub(crate) fn note_rules_toml(text: &str) {
    if is_embedded_text(text, crate::config_loader::EMBEDDED_BLOCKLIST) {
        return;
    }
    PARSED.with(|p| push_new(&mut p.borrow_mut().rules, text));
}

pub(crate) fn note_allowlist_toml(text: &str) {
    PARSED.with(|p| push_new(&mut p.borrow_mut().allowlist, text));
}

pub(crate) fn note_user_config_toml(text: &str) {
    PARSED.with(|p| push_new(&mut p.borrow_mut().user_config, text));
}

/// Deduplicated: `identify` re-parses the recorded texts, which notes them again.
fn push_new(texts: &mut Vec<String>, text: &str) {
    if !texts.iter().any(|t| t == text) {
        texts.push(text.to_string());
    }
}

fn embedded() -> &'static (Rules, Allowlist) {
    static EMBEDDED: OnceLock<(Rules, Allowlist)> = OnceLock::new();
    EMBEDDED.get_or_init(|| (Rules::embedded().unwrap(), Allowlist::embedded().unwrap()))
}

fn merged(text: &str) -> Option<(Rules, Allowlist)> {
    let (rules, allowlist) = embedded();
    let config = UserConfig::parse(text).ok()?;
    merge_user_config(rules.clone(), allowlist.clone(), config).ok()
}

/// Names the TOML provenance of `rules`/`allowlist` by rebuilding each
/// candidate from the texts this thread parsed and comparing for equality,
/// so a recorded config is one the replay can really reconstruct. `None`
/// means "the embedded default".
fn identify(rules: Option<&Rules>, allowlist: Option<&Allowlist>) -> Config {
    let (embedded_rules, embedded_allowlist) = embedded();
    let texts = PARSED.with(|p| {
        let p = p.borrow();
        (p.rules.clone(), p.allowlist.clone(), p.user_config.clone())
    });
    let mut coupled_allowlist: Option<(String, Allowlist)> = None;
    let rules_source = match rules {
        None => Source::Embedded,
        Some(rules) if !rules.legacy_has_default_canonicalizer() => {
            Source::Unreplayable(UNREPLAYABLE_CONFIG.to_string())
        }
        Some(rules) if rules == embedded_rules => Source::Embedded,
        Some(rules) => {
            let parsed = texts
                .0
                .iter()
                .find(|t| Rules::parse(t).is_ok_and(|candidate| candidate == *rules))
                .map(|t| Source::Parse(t.clone()));
            let user = || {
                texts.2.iter().find_map(|t| {
                    let (candidate, allow) = merged(t)?;
                    (candidate == *rules).then(|| {
                        coupled_allowlist = Some((t.clone(), allow));
                        Source::UserConfig(t.clone())
                    })
                })
            };
            parsed
                .or_else(user)
                .unwrap_or_else(|| Source::Unreplayable(UNREPLAYABLE_CONFIG.to_string()))
        }
    };
    let allowlist_source = match allowlist {
        None => Source::Embedded,
        Some(allowlist) if allowlist == embedded_allowlist => Source::Embedded,
        Some(allowlist) => coupled_allowlist
            .filter(|(_, coupled)| coupled == allowlist)
            .map(|(text, _)| Source::UserConfig(text))
            .or_else(|| {
                texts
                    .1
                    .iter()
                    .find(|t| Allowlist::parse(t).is_ok_and(|candidate| candidate == *allowlist))
                    .map(|t| Source::Parse(t.clone()))
            })
            .unwrap_or_else(|| Source::Unreplayable(UNREPLAYABLE_CONFIG.to_string())),
    };
    Config {
        rules: rules_source,
        allowlist: allowlist_source,
    }
}

/// Rebuilds the rule set a row was recorded with, or `None` if the row is
/// flagged unreplayable.
fn build(config: &Config) -> Option<(Rules, Allowlist)> {
    let (embedded_rules, embedded_allowlist) = embedded();
    let (rules, coupled) = match &config.rules {
        Source::Embedded => (embedded_rules.clone(), None),
        Source::Parse(text) => (Rules::parse(text).ok()?, None),
        Source::UserConfig(text) => {
            let (rules, allowlist) = merged(text)?;
            (rules, Some((text.clone(), allowlist)))
        }
        Source::Unreplayable(_) => return None,
    };
    let allowlist = match &config.allowlist {
        Source::Embedded => embedded_allowlist.clone(),
        Source::Parse(text) => Allowlist::parse(text).ok()?,
        Source::UserConfig(text) => match coupled {
            Some((coupled_text, allowlist)) if coupled_text == *text => allowlist,
            _ => merged(text)?.1,
        },
        Source::Unreplayable(_) => return None,
    };
    Some((rules, allowlist))
}

// ---------------------------------------------------------------------
// Recording / checking
// ---------------------------------------------------------------------

#[derive(PartialEq, Eq, Clone, Copy)]
enum Origin {
    Gate,
    Rules,
}

fn current_test() -> Option<(Origin, String)> {
    let thread = std::thread::current();
    let name = thread.name()?;
    if name.starts_with("gate::") {
        Some((Origin::Gate, name.to_string()))
    } else if name.starts_with("rules::") {
        Some((Origin::Rules, name.to_string()))
    } else {
        None
    }
}

fn capture_file() -> Option<&'static Mutex<std::fs::File>> {
    static FILE: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();
    FILE.get_or_init(|| {
        let path = std::env::var_os(CAPTURE_ENV)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open the legacy_units capture file");
        Some(Mutex::new(file))
    })
    .as_ref()
}

fn append_capture(file: &Mutex<std::fs::File>, line: &str) {
    let mut file = file.lock().unwrap();
    file.write_all(line.as_bytes())
        .expect("write the legacy_units capture file");
}

fn record(file: &Mutex<std::fs::File>, test: &str, row: &Row) {
    append_capture(
        file,
        &format!("{test}\t{}\n", serde_json::to_string(row).unwrap()),
    );
}

fn record_oversize(file: &Mutex<std::fs::File>, test: &str, bytes: usize) {
    append_capture(file, &format!("{test}\t{{\"oversize\":{bytes}}}\n"));
}

fn check(test: &str, row: &Row) {
    let key = row.key();
    let Some(known) = corpus().get(&key) else {
        panic!("{test}: {REGEN_HINT}: {key}");
    };
    assert_eq!(
        known, row,
        "{test}: the engine now disagrees with its legacy_units row (regenerate with \
         scripts/regen-legacy-units if the change is intended): {key}"
    );
}

fn observe(test: &str, file: Option<&Mutex<std::fs::File>>, row: &Row) {
    match file {
        Some(file) => record(file, test, row),
        None => check(test, row),
    }
}

fn gate_expect(verdict: &Verdict) -> GateExpect {
    GateExpect {
        decision: format!("{:?}", verdict.decision()).to_lowercase(),
        reason: verdict.reason().map(|r| r.as_str().to_string()),
        rule: verdict.matched_rule().map(|r| r.as_str().to_string()),
        deny_message: verdict.deny_message().map(|m| m.as_str().to_string()),
        suppressed_by: verdict.suppressed_by().map(|r| r.as_str().to_string()),
    }
}

/// Called by `gate::analyze_with_policy_in_cwd` after it decides.
pub(crate) fn observe_gate(
    command: &str,
    rules: &Rules,
    allowlist: &Allowlist,
    cwd: Option<&str>,
    verdict: &Verdict,
) {
    let Some((Origin::Gate, test)) = current_test() else {
        return;
    };
    let file = capture_file();
    if command.len() > MAX_INPUT_BYTES {
        if let Some(file) = file {
            record_oversize(file, &test, command.len());
        }
        return;
    }
    let row = Row::Gate {
        config: identify(Some(rules), Some(allowlist)),
        command: command.to_string(),
        cwd: cwd.map(str::to_string),
        expect: gate_expect(verdict),
    };
    observe(&test, file, &row);
}

pub(crate) enum Call<'a> {
    Argv(&'a [NormalizedWord]),
    Stages(&'a [Vec<NormalizedWord>]),
    Target(&'a str),
    Tokens(&'a [String]),
    ArgvToken(&'a [NormalizedWord], &'a str),
}

pub(crate) enum Receiver<'a> {
    Rules(&'a Rules),
    Allowlist(&'a Allowlist),
}

/// Held for the duration of a matcher call; matcher calls nested inside it
/// (`match_command` -> `match_command_in`) are not separate unit-test inputs.
pub(crate) struct Depth;

impl Drop for Depth {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// Called at the entry of every `Rules`/`Allowlist` matcher; observes the
/// call when a `rules::` unit test makes it directly.
pub(crate) fn rules_call(receiver: Receiver<'_>, method: &'static str, call: &Call<'_>) -> Depth {
    let outer = DEPTH.with(|d| {
        let depth = d.get();
        d.set(depth + 1);
        depth == 0
    });
    if outer && let Some((Origin::Rules, test)) = current_test() {
        let input = match *call {
            Call::Argv(argv) => RulesInput {
                argv: Some(argv.iter().map(word_row).collect()),
                ..RulesInput::default()
            },
            Call::Stages(stages) => RulesInput {
                stages: Some(
                    stages
                        .iter()
                        .map(|s| s.iter().map(word_row).collect())
                        .collect(),
                ),
                ..RulesInput::default()
            },
            Call::Target(target) => RulesInput {
                target: Some(target.to_string()),
                ..RulesInput::default()
            },
            Call::Tokens(tokens) => RulesInput {
                tokens: Some(tokens.to_vec()),
                ..RulesInput::default()
            },
            Call::ArgvToken(argv, token) => RulesInput {
                argv: Some(argv.iter().map(word_row).collect()),
                token: Some(token.to_string()),
                ..RulesInput::default()
            },
        };
        let config = match receiver {
            Receiver::Rules(rules) => identify(Some(rules), None),
            Receiver::Allowlist(allowlist) => identify(None, Some(allowlist)),
        };
        let expect =
            run_method(&receiver, method, &input).unwrap_or_else(|err| panic!("{test}: {err}"));
        let row = Row::Rules {
            config,
            method: method.to_string(),
            input,
            expect,
        };
        let size = serde_json::to_string(&row).map_or(usize::MAX, |s| s.len());
        let file = capture_file();
        if size > MAX_INPUT_BYTES * 2 {
            if let Some(file) = file {
                record_oversize(file, &test, size);
            }
        } else {
            observe(&test, file, &row);
        }
    }
    Depth
}

// ---------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------

fn id_of<T>(found: Option<&T>, id: impl Fn(&T) -> &str) -> Value {
    found.map_or(Value::Null, |rule| Value::String(id(rule).to_string()))
}

fn run_method(receiver: &Receiver<'_>, method: &str, input: &RulesInput) -> Result<Value, String> {
    let argv = input.argv.as_deref().map(words);
    let need_argv = || {
        argv.as_deref()
            .ok_or_else(|| format!("{method}: row has no argv"))
    };
    if let Receiver::Allowlist(allowlist) = receiver {
        return match method {
            "allowlist_first_match" => Ok(id_of(allowlist.first_match(need_argv()?), |r| {
                r.id().as_str()
            })),
            other => Err(format!("unknown allowlist method {other:?}")),
        };
    }
    let Receiver::Rules(rules) = receiver else {
        unreachable!("the allowlist receiver returned above");
    };
    let command = |found: Option<&crate::rules::CommandRule>| id_of(found, |r| r.id().as_str());
    Ok(match method {
        "match_command" => command(rules.match_command(need_argv()?)),
        "match_command_except_target" => command(rules.match_command_except_target(need_argv()?)),
        "match_command_except_flags" => command(rules.match_command_except_flags(need_argv()?)),
        "match_command_ascent_descent" => command(rules.match_command_ascent_descent(need_argv()?)),
        "match_command_glob" => command(rules.match_command_glob(need_argv()?)),
        "match_command_named_user_home" => {
            command(rules.match_command_named_user_home(need_argv()?))
        }
        "match_command_dirstack_tilde" => command(rules.match_command_dirstack_tilde(need_argv()?)),
        "match_command_unknown_cwd" => command(rules.match_command_unknown_cwd(need_argv()?)),
        "match_command_directory_equals_tilde" => {
            command(rules.match_command_directory_equals_tilde(need_argv()?))
        }
        "match_command_dirstack_equal_subst" => {
            command(rules.match_command_dirstack_equal_subst(need_argv()?))
        }
        "match_pipeline" => {
            let stages: Vec<Vec<NormalizedWord>> = input
                .stages
                .as_ref()
                .ok_or("match_pipeline: row has no stages")?
                .iter()
                .map(|s| words(s))
                .collect();
            id_of(rules.match_pipeline(&stages), |r| r.id().as_str())
        }
        "match_redirect_target"
        | "match_redirect_target_ascent_descent"
        | "match_redirect_target_glob"
        | "match_redirect_target_dirstack_tilde" => {
            let target = input
                .target
                .as_deref()
                .ok_or("redirect row has no target")?;
            let found = match method {
                "match_redirect_target" => rules.match_redirect_target(target),
                "match_redirect_target_ascent_descent" => {
                    rules.match_redirect_target_ascent_descent(target)
                }
                "match_redirect_target_glob" => rules.match_redirect_target_glob(target),
                _ => rules.match_redirect_target_dirstack_tilde(target),
            };
            id_of(found, |r| r.id().as_str())
        }
        "match_token" => {
            let tokens = input
                .tokens
                .as_deref()
                .ok_or("match_token: row has no tokens")?;
            id_of(rules.match_token(tokens), |r| r.id().as_str())
        }
        "target_flag_glued_value_offset" => {
            let token = input
                .token
                .as_deref()
                .ok_or("target_flag_glued_value_offset: row has no token")?;
            rules
                .target_flag_glued_value_offset(need_argv()?, token)
                .map_or(Value::Null, Value::from)
        }
        other => return Err(format!("unknown rules method {other:?}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replays every row the engine can rebuild a rule set for through the
    /// crate-internal entry points; `tests/legacy_units.rs` replays the
    /// embedded-rule gate rows through the public API on top of this.
    #[test]
    fn corpus_replays() {
        let mut gate = 0usize;
        let mut rules_rows = 0usize;
        let mut skipped = 0usize;
        let mut failures = Vec::new();
        for row in corpus().values() {
            match row {
                Row::Gate {
                    config,
                    command,
                    cwd,
                    expect,
                } => {
                    let Some((rules, allowlist)) = build(config) else {
                        skipped += 1;
                        continue;
                    };
                    let verdict = crate::gate::analyze_with_policy_in_cwd(
                        command,
                        &rules,
                        &allowlist,
                        cwd.as_deref(),
                    );
                    gate += 1;
                    let got = gate_expect(&verdict);
                    if got != *expect {
                        failures.push(format!("{command:?}: expected {expect:?}, got {got:?}"));
                    }
                }
                Row::Rules {
                    config,
                    method,
                    input,
                    expect,
                } => {
                    let Some((rules, allowlist)) = build(config) else {
                        skipped += 1;
                        continue;
                    };
                    let receiver = if method.starts_with("allowlist_") {
                        Receiver::Allowlist(&allowlist)
                    } else {
                        Receiver::Rules(&rules)
                    };
                    rules_rows += 1;
                    match run_method(&receiver, method, input) {
                        Ok(got) if got == *expect => {}
                        other => failures.push(format!(
                            "{method} {input:?}: expected {expect}, got {other:?}"
                        )),
                    }
                }
                Row::Excluded { .. } => {}
            }
        }
        eprintln!(
            "legacy_units: replayed {gate} gate rows and {rules_rows} rules rows internally, \
             skipped {skipped} unreplayable"
        );
        assert!(
            failures.is_empty(),
            "{} mismatches:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    #[test]
    fn empty_corpus_is_rejected() {
        assert!(parse_corpus("").is_err());
    }

    #[test]
    fn malformed_line_is_rejected() {
        let err =
            parse_corpus("{\"kind\":\"excluded\",\"test\":\"a\",\"reason\":\"b\"}\nnot json\n")
                .unwrap_err();
        assert!(err.contains("line 2"), "{err}");
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let line = "{\"kind\":\"excluded\",\"test\":\"a\",\"reason\":\"b\"}\n";
        let err = parse_corpus(&format!("{line}{line}")).unwrap_err();
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn unknown_field_is_rejected() {
        assert!(
            parse_corpus("{\"kind\":\"excluded\",\"test\":\"a\",\"reason\":\"b\",\"x\":1}\n")
                .is_err()
        );
    }

    #[test]
    fn word_rows_round_trip() {
        let originals = [
            NormalizedWord::resolved("plain"),
            NormalizedWord::resolved_ifs_derived("ifs"),
            NormalizedWord::unresolvable(UnresolvableKind::ParameterExpansion)
                .with_literal_tail("/tail")
                .with_literal_head("--f=")
                .with_literal_head_tilde(true),
            NormalizedWord::unresolvable_single_word(UnresolvableKind::CommandSubstitution),
        ];
        for original in originals {
            let back = word_value(&word_row(&original));
            assert_eq!(back, original);
        }
    }

    #[test]
    fn kinds_table_covers_every_kind() {
        for (kind, name) in &KINDS {
            assert_eq!(kind_name(*kind), *name);
        }
    }
}
