//! Stage 3 of the pipeline (plan.md §1.1): mechanical, exact matching of a
//! resolved argv against `rules/blocklist.toml`/`rules/allowlist.toml`.
//!
//! Two rule kinds:
//! - [`CommandRule`] matches one simple command's argv: a command-name
//!   matcher, a set of required flags, and a set of target matchers.
//! - [`PipelineRule`] matches the shape of a whole pipeline (the ported
//!   `curl|wget → sh` installer-pipe pattern only — the general decode-pipe
//!   gate is a later issue, plan.md §1.1 stage 4).
//!
//! Everything here operates on already-normalised [`NormalizedWord`] values
//! (`crate::normalize`, B2) — no raw strings, no regex over the command
//! line. An [`Resolution::Unresolvable`] word never matches any matcher and
//! never panics (module tests cover this).
//!
//! # Parse, don't validate
//!
//! [`CommandRuleDto`]/[`PipelineRuleDto`]/[`RulesFileDto`] are the only
//! serde-aware types in this module, private to it — the rest of the crate
//! (and every other module) never sees a serde attribute or a TOML type
//! (`coding-guidelines/principles.md`, "dependencies point inward"). Loading
//! is a one-step boundary: [`Rules::parse`]/[`Allowlist::parse`] either
//! return a fully-valid, typed rule set, or an [`RulesError`] — a duplicate
//! id, an empty id/reason, or a matcher with no command identifier is a
//! load-time `Err`, never a silently-skipped rule — security controls
//! default to fail-closed.
//!
//! # File I/O stays out of this module
//!
//! Every constructor here takes TOML text (`&str`), never a path. The
//! composition root (a later issue) reads `rules/blocklist.toml`/an
//! operator-supplied override file and hands the contents in as strings.
//!
//! `analyze()` (`src/lib.rs`) calls [`Rules::embedded`]/[`Rules::match_command`]/
//! [`Rules::match_pipeline`] via `src/gate.rs`. [`Rules::with_override`] and
//! everything in the [allowlist](#allowlist) section below remain unwired —
//! see `src/gate.rs`'s module docs for why allowlist application is
//! deferred — so those entry points are still reachable only from their own
//! tests, hence their `#[allow(dead_code)]`.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::normalize::{NormalizedWord, Resolution};
use crate::verdict::{Decision, Reason, RuleId, Verdict};

// ---------------------------------------------------------------------
// Embedded defaults
// ---------------------------------------------------------------------

/// The default blocklist, embedded in the binary so the hook works with
/// zero setup (plan.md §1.1 stage 3, issue #11 scope).
const EMBEDDED_BLOCKLIST: &str = include_str!("../rules/blocklist.toml");

/// The default allowlist, embedded the same way. Ships empty (no entries)
/// per issue #11 scope — a commented example lives in the file itself.
const EMBEDDED_ALLOWLIST: &str = include_str!("../rules/allowlist.toml");

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Everything that can go wrong loading a rule set. Every variant is a
/// load-time failure — this crate never falls back to "skip the bad rule
/// and keep going" (fail-closed).
#[derive(Debug, thiserror::Error)]
pub(crate) enum RulesError {
    /// The input is not valid TOML at all.
    #[error("invalid TOML: {0}")]
    Syntax(#[from] toml::de::Error),
    /// A rule failed a semantic check (empty id, empty reason, a matcher
    /// with no command identifier, an unrecognised flag spec, …).
    #[error("rule {id:?}: {problem}")]
    InvalidRule { id: String, problem: String },
    /// Two rules in the same rule set share an id. Rule ids are the audit
    /// trail (`matched_rule`/suppression reporting) — a collision would
    /// make that trail ambiguous, so it is rejected outright rather than
    /// silently keeping "whichever one parsed last".
    #[error("duplicate rule id {0:?}")]
    DuplicateId(String),
}

impl RulesError {
    fn invalid(id: impl Into<String>, problem: impl Into<String>) -> Self {
        Self::InvalidRule {
            id: id.into(),
            problem: problem.into(),
        }
    }
}

// ---------------------------------------------------------------------
// Domain matcher types
// ---------------------------------------------------------------------

/// How a rule identifies the command name (argv\[0\]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandMatch {
    /// The exact command name, e.g. `"rm"`.
    Exact(String),
    /// A command-name prefix, e.g. `"mkfs."` for the `mkfs.*` family. An
    /// explicit field, not regex, per issue #11 scope.
    Prefix(String),
}

impl CommandMatch {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(exact) => name == exact,
            Self::Prefix(prefix) => name.starts_with(prefix.as_str()),
        }
    }
}

/// A required flag. Short-flag-aware: `-rf` in argv satisfies required
/// flags `r` and `f`, and so does the separated form `-r -f` — both are
/// combined-cluster tokens of length 1. [`Self::Token`] covers flags that
/// are never letter-combinable: GNU long options (`--recursive`) and
/// BSD-style single-dash long flags (`find -delete`).
///
/// [`Self::AnyOf`] expresses "this requirement is satisfied by any one of
/// several equivalent spellings" — e.g. a rule that must not be dodged by
/// swapping `-rf` for `--recursive --force` requires `r` **or**
/// `--recursive`, not just `r`. Built from a `spec.split('|')` in
/// [`Self::parse`], never nested (each alternative is itself a `Short` or
/// `Token`, never another `AnyOf` — a spec string can't produce one, since
/// splitting removes every `|`).
#[derive(Debug, Clone, PartialEq, Eq)]
enum FlagMatcher {
    /// A single short-option letter.
    Short(char),
    /// An exact argv token, matched verbatim.
    Token(String),
    /// Satisfied if any one alternative is satisfied.
    AnyOf(Vec<FlagMatcher>),
}

impl FlagMatcher {
    /// `spec` is a single ASCII alphabetic character for a short flag
    /// (`"r"`), a `-`-prefixed string for an exact-token flag
    /// (`"-delete"`, `"--recursive"`), or a `|`-separated list of either
    /// (`"r|--recursive"`) meaning "any one of these" — parsed into
    /// [`Self::AnyOf`]. An empty alternative (`"r|"`, `"|f"`, `"r||f"`) is
    /// a malformed rule, same as any other unrecognised spec.
    fn parse(spec: &str) -> Result<Self, String> {
        if spec.contains('|') {
            let alternatives = spec
                .split('|')
                .map(|part| {
                    if part.is_empty() {
                        return Err(format!(
                            "invalid flag spec {spec:?}: empty alternative between \
                             '|' separators"
                        ));
                    }
                    Self::parse_single(part)
                })
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(Self::AnyOf(alternatives));
        }
        Self::parse_single(spec)
    }

    /// Parses one `|`-free alternative: a single short-option letter, or a
    /// `-`-prefixed exact-token flag.
    fn parse_single(spec: &str) -> Result<Self, String> {
        let mut chars = spec.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) if c.is_ascii_alphabetic() => Ok(Self::Short(c)),
            _ if spec.starts_with('-') && spec.len() > 1 => Ok(Self::Token(spec.to_string())),
            _ => Err(format!(
                "invalid flag spec {spec:?}: expected a single letter (short flag) or a \
                 '-'-prefixed token"
            )),
        }
    }

    /// Whether this flag is present anywhere in `argv` (already reduced to
    /// resolved strings — module docs on why unresolvable tokens never
    /// match).
    fn satisfied(&self, argv: &[&str]) -> bool {
        match self {
            Self::Short(c) => argv
                .iter()
                .any(|token| short_cluster_chars(token).contains(c)),
            Self::Token(token) => argv.contains(&token.as_str()),
            Self::AnyOf(alternatives) => alternatives.iter().any(|alt| alt.satisfied(argv)),
        }
    }
}

/// The characters of a short-option cluster token (`-rf` → `{'r', 'f'}`,
/// `-r` → `{'r'}`), or an empty set for anything that isn't one: a bare
/// `-`, a `--`-prefixed long option, or a token with no leading `-` at all.
fn short_cluster_chars(token: &str) -> HashSet<char> {
    match token.strip_prefix('-') {
        Some(rest) if !rest.is_empty() && !rest.starts_with('-') => rest.chars().collect(),
        _ => HashSet::new(),
    }
}

/// One alternative shape a dangerous target may take. A [`CommandRule`]'s
/// `targets` list is a set of OR'd alternatives — the rule matches if any
/// argv token satisfies any one of them (e.g. rm's target list holds `/`,
/// `/*`, `~`, and a `/dev/` prefix as separate alternatives).
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetMatcher {
    Exact(String),
    Prefix(String),
}

impl TargetMatcher {
    fn matches(&self, token: &str) -> bool {
        match self {
            Self::Exact(exact) => token == exact,
            Self::Prefix(prefix) => token.starts_with(prefix.as_str()),
        }
    }
}

/// A rule matching one simple command's resolved argv: a command name, a
/// set of required flags (all must be present, ANDed — though a single
/// entry may itself be a [`FlagMatcher::AnyOf`], ORing equivalent
/// spellings), and a set of target matchers (any one must be hit by some
/// token, ORed — an empty list means "no target constraint", e.g.
/// `shred`'s "any target" rule).
///
/// Also the allowlist entry shape (issue #11 scope: "same command-rule
/// shape") — [`Allowlist`] holds a `Vec<CommandRule>` of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandRule {
    id: RuleId,
    reason: Reason,
    command: CommandMatch,
    required_flags: Vec<FlagMatcher>,
    targets: Vec<TargetMatcher>,
}

impl CommandRule {
    #[must_use]
    pub(crate) fn id(&self) -> &RuleId {
        &self.id
    }

    #[must_use]
    pub(crate) fn reason(&self) -> &Reason {
        &self.reason
    }

    /// Whether this rule's command name and required flags match `argv`,
    /// ignoring the target constraint entirely — the shared building block
    /// behind [`Self::matches`] (which also checks targets) and
    /// [`Self::matches_except_target`] (plan.md §4's NEW argument-position
    /// bare-`$VAR` refinement, `src/gate.rs`).
    #[must_use]
    fn matches_command_and_flags(&self, argv: &[NormalizedWord]) -> bool {
        let Some(name) = command_name(argv) else {
            return false;
        };
        if !self.command.matches(name) {
            return false;
        }
        let rest = resolved_strings(&argv[1..]);
        self.required_flags.iter().all(|flag| flag.satisfied(&rest))
    }

    /// Whether this rule matches `argv`, the normalised argv of one simple
    /// command. Matching is mechanical and shape-based, not positional: a
    /// resolved-but-empty token (a bash quoted empty, `''`) never breaks
    /// the scan, and an [`Resolution::Unresolvable`] token — including the
    /// command name itself — never matches anything.
    #[must_use]
    fn matches(&self, argv: &[NormalizedWord]) -> bool {
        if !self.matches_command_and_flags(argv) {
            return false;
        }
        if self.targets.is_empty() {
            return true;
        }
        let rest = resolved_strings(&argv[1..]);
        rest.iter()
            .any(|token| self.targets.iter().any(|t| t.matches(token)))
    }

    /// Partial-match probe for the structural gate (plan.md §4 NEW rule,
    /// `src/gate.rs`): `true` when this rule's command+flags match `argv`
    /// (the dangerous shape is present), this rule *has* a target
    /// constraint (an empty `targets` list means "any target" and is
    /// already a full match via [`Self::matches`] — nothing left to
    /// refine), and `argv` contains at least one unresolvable word — so the
    /// target itself could not be statically checked and might be exactly
    /// the value this rule guards against (`rm -rf $HOME`).
    ///
    /// This is a "would this be dangerous if the target were known" probe,
    /// never a match on its own: the gate uses it only to route an
    /// otherwise-Allow argument-position bare `$VAR` to Ask, never to
    /// Block — an unresolvable target must never silently upgrade to a
    /// rule hit here.
    #[must_use]
    pub(crate) fn matches_except_target(&self, argv: &[NormalizedWord]) -> bool {
        !self.targets.is_empty()
            && self.matches_command_and_flags(argv)
            && argv
                .iter()
                .any(|word| matches!(word.resolution(), Resolution::Unresolvable(_)))
    }
}

/// A rule matching the shape of a whole pipeline: an earlier stage's
/// command name in `sources`, and the final stage's command name in
/// `sinks` — the literal ported `curl|wget → sh` installer-pipe pattern
/// (plan.md §1.1 stage 3). The general decode-fed-pipe gate is a later
/// issue (plan.md §4), out of scope here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PipelineRule {
    id: RuleId,
    reason: Reason,
    sources: Vec<String>,
    sinks: Vec<String>,
}

impl PipelineRule {
    #[must_use]
    pub(crate) fn id(&self) -> &RuleId {
        &self.id
    }

    #[must_use]
    pub(crate) fn reason(&self) -> &Reason {
        &self.reason
    }

    /// `stages` is one entry per pipeline stage, each the normalised argv
    /// of that stage's simple command, in pipeline order.
    #[must_use]
    fn matches(&self, stages: &[Vec<NormalizedWord>]) -> bool {
        let Some((sink_stage, source_stages)) = stages.split_last() else {
            return false;
        };
        if source_stages.is_empty() {
            return false;
        }
        let Some(sink_name) = command_name(sink_stage) else {
            return false;
        };
        if !self.sinks.iter().any(|sink| sink == sink_name) {
            return false;
        }
        source_stages.iter().any(|stage| {
            command_name(stage).is_some_and(|name| self.sources.iter().any(|src| src == name))
        })
    }
}

/// The command name (argv\[0\]) of a simple command, or `None` if it is
/// empty or the first word did not statically resolve.
fn command_name(argv: &[NormalizedWord]) -> Option<&str> {
    match argv.first()?.resolution() {
        Resolution::Resolved(s) => Some(s.as_str()),
        Resolution::Unresolvable(_) => None,
    }
}

/// The resolved strings of `argv`, in order, silently skipping any
/// unresolvable word — never a guess at its value, never a panic. Skipping
/// (rather than threading through a placeholder) is safe here because
/// every matcher in this module is membership-based, not positional
/// (module docs).
fn resolved_strings(argv: &[NormalizedWord]) -> Vec<&str> {
    argv.iter()
        .filter_map(|w| match w.resolution() {
            Resolution::Resolved(s) => Some(s.as_str()),
            Resolution::Unresolvable(_) => None,
        })
        .collect()
}

// ---------------------------------------------------------------------
// Serde DTOs (private to this module — parse, don't validate)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RulesFileDto {
    #[serde(default)]
    command: Vec<CommandRuleDto>,
    #[serde(default)]
    pipeline: Vec<PipelineRuleDto>,
}

#[derive(Debug, Deserialize)]
struct AllowlistFileDto {
    #[serde(default)]
    entry: Vec<CommandRuleDto>,
}

#[derive(Debug, Deserialize)]
struct CommandRuleDto {
    id: String,
    reason: String,
    command: Option<String>,
    command_prefix: Option<String>,
    #[serde(default)]
    required_flags: Vec<String>,
    #[serde(default)]
    targets: Vec<TargetDto>,
}

#[derive(Debug, Deserialize)]
struct TargetDto {
    exact: Option<String>,
    prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PipelineRuleDto {
    id: String,
    reason: String,
    sources: Vec<String>,
    sinks: Vec<String>,
}

/// Converts a [`CommandRuleDto`] into a [`CommandRule`], rejecting every
/// semantically-invalid shape at this one boundary: empty id, empty
/// reason, neither/both of `command`/`command_prefix` set, a malformed
/// flag spec, or a target with neither/both of `exact`/`prefix` set.
fn convert_command_rule(dto: CommandRuleDto) -> Result<CommandRule, RulesError> {
    if dto.id.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "id must not be empty"));
    }
    if dto.reason.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "reason must not be empty"));
    }

    let command = match (dto.command, dto.command_prefix) {
        (Some(exact), None) => CommandMatch::Exact(exact),
        (None, Some(prefix)) => CommandMatch::Prefix(prefix),
        (None, None) => {
            return Err(RulesError::invalid(
                &dto.id,
                "exactly one of `command`/`command_prefix` is required",
            ));
        }
        (Some(_), Some(_)) => {
            return Err(RulesError::invalid(
                &dto.id,
                "`command` and `command_prefix` are mutually exclusive",
            ));
        }
    };

    let required_flags = dto
        .required_flags
        .iter()
        .map(|spec| {
            FlagMatcher::parse(spec).map_err(|problem| RulesError::invalid(&dto.id, problem))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let targets = dto
        .targets
        .into_iter()
        .map(|t| convert_target(&dto.id, t))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CommandRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        command,
        required_flags,
        targets,
    })
}

fn convert_target(rule_id: &str, dto: TargetDto) -> Result<TargetMatcher, RulesError> {
    match (dto.exact, dto.prefix) {
        (Some(exact), None) => Ok(TargetMatcher::Exact(exact)),
        (None, Some(prefix)) => Ok(TargetMatcher::Prefix(prefix)),
        (None, None) => Err(RulesError::invalid(
            rule_id,
            "target requires exactly one of `exact`/`prefix`",
        )),
        (Some(_), Some(_)) => Err(RulesError::invalid(
            rule_id,
            "target's `exact` and `prefix` are mutually exclusive",
        )),
    }
}

fn convert_pipeline_rule(dto: PipelineRuleDto) -> Result<PipelineRule, RulesError> {
    if dto.id.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "id must not be empty"));
    }
    if dto.reason.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "reason must not be empty"));
    }
    if dto.sources.is_empty() || dto.sinks.is_empty() {
        return Err(RulesError::invalid(
            &dto.id,
            "`sources` and `sinks` must both be non-empty",
        ));
    }

    Ok(PipelineRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        sources: dto.sources,
        sinks: dto.sinks,
    })
}

/// Checks that no id in `ids` repeats — the duplicate-id-is-`Err` half of
/// "parse, don't validate" (module docs).
fn reject_duplicate_ids<'a>(ids: impl Iterator<Item = &'a str>) -> Result<(), RulesError> {
    let mut seen = HashSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(RulesError::DuplicateId(id.to_string()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Rules (blocklist)
// ---------------------------------------------------------------------

/// A loaded, validated rule set: [`CommandRule`]s and [`PipelineRule`]s,
/// every id unique within the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rules {
    command_rules: Vec<CommandRule>,
    pipeline_rules: Vec<PipelineRule>,
}

impl Rules {
    /// Parses `toml` into a validated [`Rules`] set.
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] for invalid TOML syntax, a semantically
    /// invalid rule (empty id/reason, an empty/contradictory matcher, a
    /// malformed flag spec), or a duplicate rule id — fail-closed, never a
    /// silently-skipped rule.
    pub(crate) fn parse(toml: &str) -> Result<Self, RulesError> {
        let dto: RulesFileDto = toml::from_str(toml)?;

        let command_rules = dto
            .command
            .into_iter()
            .map(convert_command_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let pipeline_rules = dto
            .pipeline
            .into_iter()
            .map(convert_pipeline_rule)
            .collect::<Result<Vec<_>, _>>()?;

        reject_duplicate_ids(
            command_rules
                .iter()
                .map(|r| r.id.as_str())
                .chain(pipeline_rules.iter().map(|r| r.id.as_str())),
        )?;

        Ok(Self {
            command_rules,
            pipeline_rules,
        })
    }

    /// Parses the embedded default blocklist (`rules/blocklist.toml`,
    /// baked in via `include_str!` so the hook works with zero setup).
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] if the embedded file itself is malformed —
    /// a unit test below asserts this never happens, so this is a startup
    /// error only if a future edit to `rules/blocklist.toml` breaks it.
    pub(crate) fn embedded() -> Result<Self, RulesError> {
        Self::parse(EMBEDDED_BLOCKLIST)
    }

    /// Parses the embedded default blocklist, then layers `override_toml`
    /// on top: a rule in `override_toml` whose id matches a builtin rule
    /// **replaces** it; a new id **adds** to the set. Duplicate ids
    /// *within* `override_toml` itself are still a load-time `Err` (that
    /// check happens inside [`Self::parse`], before layering).
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] if either the embedded blocklist or
    /// `override_toml` fails to parse/validate.
    #[allow(dead_code)]
    pub(crate) fn with_override(override_toml: &str) -> Result<Self, RulesError> {
        let base = Self::embedded()?;
        let overrides = Self::parse(override_toml)?;
        Ok(base.layer(overrides))
    }

    /// Merges `overrides` on top of `self` by id: same-id rules from
    /// `overrides` replace `self`'s, new ids are appended.
    fn layer(self, overrides: Self) -> Self {
        let mut command_by_id: HashMap<String, CommandRule> = self
            .command_rules
            .into_iter()
            .map(|r| (r.id.as_str().to_string(), r))
            .collect();
        let mut command_order: Vec<String> = command_by_id.keys().cloned().collect();
        for rule in overrides.command_rules {
            let id = rule.id.as_str().to_string();
            if !command_by_id.contains_key(&id) {
                command_order.push(id.clone());
            }
            command_by_id.insert(id, rule);
        }

        let mut pipeline_by_id: HashMap<String, PipelineRule> = self
            .pipeline_rules
            .into_iter()
            .map(|r| (r.id.as_str().to_string(), r))
            .collect();
        let mut pipeline_order: Vec<String> = pipeline_by_id.keys().cloned().collect();
        for rule in overrides.pipeline_rules {
            let id = rule.id.as_str().to_string();
            if !pipeline_by_id.contains_key(&id) {
                pipeline_order.push(id.clone());
            }
            pipeline_by_id.insert(id, rule);
        }

        Self {
            command_rules: command_order
                .into_iter()
                .filter_map(|id| command_by_id.remove(&id))
                .collect(),
            pipeline_rules: pipeline_order
                .into_iter()
                .filter_map(|id| pipeline_by_id.remove(&id))
                .collect(),
        }
    }

    /// The first [`CommandRule`] that matches `argv`, if any.
    #[must_use]
    pub(crate) fn match_command(&self, argv: &[NormalizedWord]) -> Option<&CommandRule> {
        self.command_rules.iter().find(|rule| rule.matches(argv))
    }

    /// The first [`PipelineRule`] that matches `stages` (one normalised
    /// argv per pipeline stage, in order), if any.
    #[must_use]
    pub(crate) fn match_pipeline(&self, stages: &[Vec<NormalizedWord>]) -> Option<&PipelineRule> {
        self.pipeline_rules.iter().find(|rule| rule.matches(stages))
    }

    /// The first [`CommandRule`] for which [`CommandRule::matches_except_target`]
    /// holds, if any — plan.md §4's NEW argument-position bare-`$VAR`
    /// refinement (`src/gate.rs`). Like [`Self::match_command`]/
    /// [`Self::match_pipeline`], this is a read-only probe: it never
    /// mutates rule state and never itself constitutes a `Block`.
    #[must_use]
    pub(crate) fn match_command_except_target(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        self.command_rules
            .iter()
            .find(|rule| rule.matches_except_target(argv))
    }
}

// ---------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------

/// A loaded, validated allowlist: entries share [`CommandRule`]'s matcher
/// shape (issue #11 scope). See [`apply_allowlist`] for the
/// Block-immunity/suppression-reporting semantics (plan.md §6 item 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Allowlist {
    entries: Vec<CommandRule>,
}

impl Allowlist {
    /// Parses `toml` into a validated [`Allowlist`].
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] under the same conditions as
    /// [`Rules::parse`] (invalid TOML, a semantically invalid entry, or a
    /// duplicate id).
    #[allow(dead_code)]
    pub(crate) fn parse(toml: &str) -> Result<Self, RulesError> {
        let dto: AllowlistFileDto = toml::from_str(toml)?;
        let entries = dto
            .entry
            .into_iter()
            .map(convert_command_rule)
            .collect::<Result<Vec<_>, _>>()?;
        reject_duplicate_ids(entries.iter().map(|r| r.id.as_str()))?;
        Ok(Self { entries })
    }

    /// Parses the embedded default allowlist (`rules/allowlist.toml`).
    /// Ships empty (issue #11 scope) — a startup error here would only
    /// mean a future edit broke the (currently all-comment) file.
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] if the embedded file fails to parse.
    #[allow(dead_code)]
    pub(crate) fn embedded() -> Result<Self, RulesError> {
        Self::parse(EMBEDDED_ALLOWLIST)
    }

    /// The first allowlist entry that matches `argv`, if any.
    fn first_match(&self, argv: &[NormalizedWord]) -> Option<&CommandRule> {
        self.entries.iter().find(|entry| entry.matches(argv))
    }
}

/// The result of attempting to apply the allowlist to a [`Verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AllowlistOutcome {
    /// Nothing changed: either no entry matched, or `verdict` was not
    /// `Ask` to begin with. A `Block` verdict *always* lands here — see
    /// [`apply_allowlist`]'s docs.
    Unchanged,
    /// `verdict` was `Ask` and an allowlist entry matched; the caller
    /// should build the downgraded `Allow` verdict and surface
    /// `suppressed_by`/`reason` in it (the audit trail:
    /// `~/dotfiles/claude-code/rules/security.md`, "suppressions need an
    /// audit trail").
    Downgraded {
        suppressed_by: RuleId,
        reason: Reason,
    },
}

/// Applies `allowlist` to `verdict` per plan.md §6 item 8's semantics: an
/// allowlist match may downgrade **`Ask` → `Allow` only**, never
/// **`Block` → `Allow`**.
///
/// # Block immunity
///
/// The very first check is `verdict.decision() == Decision::Ask` — for
/// any other decision (`Block` *or* `Allow`) this returns
/// [`AllowlistOutcome::Unchanged`] unconditionally, before the allowlist
/// is even consulted. A `Block` verdict can therefore never reach the
/// matching logic below, let alone be downgraded by it — enforced by this
/// one guard clause, not by the caller remembering to check.
///
/// The matched entry's id is always returned in the `Downgraded` case
/// (never silently applied) — the audit-trail requirement.
#[allow(dead_code)]
#[must_use]
pub(crate) fn apply_allowlist(verdict: &Verdict, allowlist: &Allowlist) -> AllowlistOutcome {
    if verdict.decision() != Decision::Ask {
        return AllowlistOutcome::Unchanged;
    }

    match allowlist.first_match(verdict.normalized_argv()) {
        Some(entry) => AllowlistOutcome::Downgraded {
            suppressed_by: entry.id().clone(),
            reason: Reason::new(format!(
                "allowlisted by {:?}: {}",
                entry.id().as_str(),
                entry.reason().as_str()
            )),
        },
        None => AllowlistOutcome::Unchanged,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ---- test helpers: build NormalizedWord argv without going through
    // the parser/normalize stages (rules.rs matches on NormalizedWord, per
    // issue #11's "consume normalize.rs's public/crate API only") ----

    fn argv(words: &[&str]) -> Vec<NormalizedWord> {
        words.iter().map(|w| NormalizedWord::resolved(*w)).collect()
    }

    fn unresolvable_first(rest: &[&str]) -> Vec<NormalizedWord> {
        let mut out = vec![NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::ParameterExpansion,
        )];
        out.extend(rest.iter().map(|w| NormalizedWord::resolved(*w)));
        out
    }

    // ==== DoD 1: ["rm","-rf","/"] matches, carries reason + rule id ====

    #[test]
    fn dod_1_rm_rf_root_matches() {
        let rules = Rules::embedded().unwrap();
        let matched = rules.match_command(&argv(&["rm", "-rf", "/"]));
        // rm -rf / must match a blocklist rule
        let rule = matched.unwrap();
        assert!(!rule.reason().as_str().is_empty());
        assert!(!rule.id().as_str().is_empty());
    }

    #[test]
    fn dod_1_rm_fr_root_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(rules.match_command(&argv(&["rm", "-fr", "/"])).is_some());
    }

    #[test]
    fn dod_1_rm_separated_flags_root_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rm", "-r", "-f", "/"]))
                .is_some()
        );
    }

    #[test]
    fn dod_1_rm_rf_glob_root_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(rules.match_command(&argv(&["rm", "-rf", "/*"])).is_some());
    }

    // ---- rm -rf on a non-dangerous target stays clean ----
    #[test]
    fn rm_rf_build_dir_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rm", "-rf", "./build"]))
                .is_none()
        );
    }

    // ---- long-option spellings must not dodge the rule ----
    #[test]
    fn rm_long_options_root_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rm", "--recursive", "--force", "/"]))
                .is_some()
        );
    }

    #[test]
    fn rm_mixed_short_and_long_options_root_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rm", "-r", "--force", "/"]))
                .is_some()
        );
    }

    #[test]
    fn rm_recursive_without_force_root_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rm", "--recursive", "/"]))
                .is_none()
        );
    }

    // ---- home root is dangerous; a path under home is routine cleanup ----
    #[test]
    fn rm_rf_home_root_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(rules.match_command(&argv(&["rm", "-rf", "~/"])).is_some());
    }

    #[test]
    fn rm_rf_under_home_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rm", "-rf", "~/old-build"]))
                .is_none()
        );
    }

    // ==== DoD 2: the dangerous string as a data argument matches nothing ====

    #[test]
    fn dod_2_dangerous_string_as_argument_does_not_match() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["git", "commit", "-m", "rm -rf /"]);
        assert!(rules.match_command(&cmd).is_none());
    }

    // ==== DoD 3: malformed TOML fixtures -> Err ====

    #[test]
    fn dod_3_bad_syntax_toml_is_err() {
        let bad = "this is not [valid toml";
        assert!(Rules::parse(bad).is_err());
    }

    #[test]
    fn dod_3_duplicate_id_is_err() {
        let toml = r#"
            [[command]]
            id = "dup"
            reason = "first"
            command = "rm"

            [[command]]
            id = "dup"
            reason = "second"
            command = "shred"
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::DuplicateId(id)) if id == "dup"
        ));
    }

    #[test]
    fn dod_3_empty_reason_is_err() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = ""
            command = "rm"
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn empty_id_is_err() {
        let toml = r#"
            [[command]]
            id = ""
            reason = "some reason"
            command = "rm"
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn malformed_flag_alternatives_spec_is_loader_err() {
        let trailing_pipe = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "rm"
            required_flags = ["r|"]
        "#;
        assert!(matches!(
            Rules::parse(trailing_pipe),
            Err(RulesError::InvalidRule { .. })
        ));

        let leading_pipe = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "rm"
            required_flags = ["|f"]
        "#;
        assert!(matches!(
            Rules::parse(leading_pipe),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn matcher_with_neither_command_nor_prefix_is_err() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn matcher_with_both_command_and_prefix_is_err() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "rm"
            command_prefix = "mkfs."
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn pipeline_rule_with_empty_sources_is_err() {
        let toml = r#"
            [[pipeline]]
            id = "x"
            reason = "some reason"
            sources = []
            sinks = ["sh"]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // ==== DoD 4: allowlist Block-immunity + Ask downgrade with audit trail ====

    #[test]
    fn dod_4_allowlist_cannot_convert_block_to_allow() {
        let blocklist = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "/"]);
        let rule = blocklist.match_command(&cmd).unwrap();
        let block = Verdict::block(
            Reason::new(rule.reason().as_str().to_string()),
            cmd.clone(),
            Some(rule.id().clone()),
        );

        let allowlist_toml = r#"
            [[entry]]
            id = "trusted-rm"
            reason = "operator trusts this exact shape"
            command = "rm"
            required_flags = ["r", "f"]
            targets = [{ exact = "/" }]
        "#;
        let allowlist = Allowlist::parse(allowlist_toml).unwrap();

        // sanity: the allowlist entry does match this argv
        assert!(allowlist.first_match(&cmd).is_some());

        let outcome = apply_allowlist(&block, &allowlist);
        assert_eq!(outcome, AllowlistOutcome::Unchanged);
        assert_eq!(block.decision(), Decision::Block);
    }

    #[test]
    fn dod_4_allowlist_downgrades_ask_to_allow_with_suppression_id() {
        let cmd = argv(&["ls", "/tmp"]);
        let ask = Verdict::ask(Reason::new("unresolvable construct"), cmd.clone());

        let allowlist_toml = r#"
            [[entry]]
            id = "allow-ls"
            reason = "read-only listing, always safe"
            command = "ls"
        "#;
        let allowlist = Allowlist::parse(allowlist_toml).unwrap();

        let outcome = apply_allowlist(&ask, &allowlist);
        match outcome {
            AllowlistOutcome::Downgraded { suppressed_by, .. } => {
                assert_eq!(suppressed_by.as_str(), "allow-ls");
            }
            AllowlistOutcome::Unchanged => panic!("expected the Ask verdict to be downgraded"),
        }
    }

    #[test]
    fn allowlist_no_match_leaves_ask_unchanged() {
        let cmd = argv(&["curl", "http://example.com"]);
        let ask = Verdict::ask(Reason::new("unresolvable construct"), cmd);
        let allowlist = Allowlist::parse("").unwrap();
        assert_eq!(
            apply_allowlist(&ask, &allowlist),
            AllowlistOutcome::Unchanged
        );
    }

    #[test]
    fn allowlist_never_touches_allow() {
        let cmd = argv(&["echo", "hi"]);
        let allow = Verdict::allow(cmd.clone());
        let allowlist_toml = r#"
            [[entry]]
            id = "allow-echo"
            reason = "harmless"
            command = "echo"
        "#;
        let allowlist = Allowlist::parse(allowlist_toml).unwrap();
        assert_eq!(
            apply_allowlist(&allow, &allowlist),
            AllowlistOutcome::Unchanged
        );
    }

    // ==== Embedded blocklist parses (malformed shipped file fails CI, not
    // runtime) ====

    #[test]
    fn embedded_blocklist_parses() {
        // rules/blocklist.toml must parse and validate
        Rules::embedded().unwrap();
    }

    #[test]
    fn embedded_allowlist_parses() {
        // rules/allowlist.toml must parse and validate
        Allowlist::embedded().unwrap();
    }

    // ==== Class E coverage ====

    #[test]
    fn find_delete_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["find", "/x", "-delete"]))
                .is_some()
        );
    }

    #[test]
    fn find_without_delete_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(rules.match_command(&argv(&["find", "/x"])).is_none());
    }

    #[test]
    fn dd_of_dev_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["dd", "if=/dev/zero", "of=/dev/sda"]))
                .is_some()
        );
    }

    #[test]
    fn dd_without_dev_target_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["dd", "if=/dev/zero", "of=./backup.img"]))
                .is_none()
        );
    }

    #[test]
    fn truncate_s_zero_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["truncate", "-s", "0", "x"]))
                .is_some()
        );
    }

    #[test]
    fn shred_matches_any_target() {
        let rules = Rules::embedded().unwrap();
        assert!(rules.match_command(&argv(&["shred", "/dev/sda"])).is_some());
    }

    #[test]
    fn mkfs_ext4_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["mkfs.ext4", "/dev/sda1"]))
                .is_some()
        );
    }

    // ==== Pipeline rule: curl|sh matches, cat|bash does not ====

    #[test]
    fn curl_pipe_sh_matches() {
        let rules = Rules::embedded().unwrap();
        let stages = vec![argv(&["curl", "http://x/install.sh"]), argv(&["sh"])];
        // curl | sh must match
        let rule = rules.match_pipeline(&stages).unwrap();
        assert!(!rule.id().as_str().is_empty());
        assert!(!rule.reason().as_str().is_empty());
    }

    #[test]
    fn wget_pipe_bash_matches() {
        let rules = Rules::embedded().unwrap();
        let stages = vec![
            argv(&["wget", "-O-", "http://x/install.sh"]),
            argv(&["bash"]),
        ];
        assert!(rules.match_pipeline(&stages).is_some());
    }

    #[test]
    fn cat_pipe_bash_does_not_match() {
        let rules = Rules::embedded().unwrap();
        let stages = vec![argv(&["cat", "script.sh"]), argv(&["bash"])];
        assert!(rules.match_pipeline(&stages).is_none());
    }

    // ==== NEW rule 4 partial-match API: matches_except_target /
    // match_command_except_target (plan.md §4, src/gate.rs) ====

    fn argv_with_unresolvable_tail(words: &[&str]) -> Vec<NormalizedWord> {
        let mut out: Vec<NormalizedWord> =
            words.iter().map(|w| NormalizedWord::resolved(*w)).collect();
        out.push(NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::ParameterExpansion,
        ));
        out
    }

    #[test]
    fn except_target_matches_when_flags_present_but_target_unresolvable() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["rm", "-rf"]);
        // the ordinary full match must miss (the only candidate target
        // token is unresolvable, so it can never satisfy `targets`)
        assert!(rules.match_command(&cmd).is_none());
        // but the except-target probe must catch it: same command+flags,
        // target merely unknown rather than absent
        let rule = rules.match_command_except_target(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "rm-recursive-force-dangerous-target");
    }

    #[test]
    fn except_target_does_not_match_when_fully_resolved_and_clean() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "./build"]);
        assert!(rules.match_command(&cmd).is_none());
        assert!(rules.match_command_except_target(&cmd).is_none());
    }

    #[test]
    fn except_target_never_fires_for_a_rule_with_no_target_constraint() {
        // `shred` has no `targets` list at all ("any target" is already a
        // full match) — matches_except_target has nothing left to refine
        // and must stay false even with an unresolvable argument present.
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["shred"]);
        assert!(rules.match_command(&cmd).is_some());
        assert!(rules.match_command_except_target(&cmd).is_none());
    }

    #[test]
    fn except_target_does_not_match_an_unrelated_command() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["cd"]);
        assert!(rules.match_command(&cmd).is_none());
        assert!(rules.match_command_except_target(&cmd).is_none());
    }

    #[test]
    fn except_target_requires_required_flags_too() {
        // command name matches but a required flag (`-f`/`--force`) is
        // absent — the danger shape itself is incomplete, so this must not
        // fire just because a later word happens to be unresolvable.
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["rm", "-r"]);
        assert!(rules.match_command_except_target(&cmd).is_none());
    }

    // ==== Shape robustness: unresolvable command name never matches,
    // never panics ====

    #[test]
    fn unresolvable_command_name_never_matches() {
        let rules = Rules::embedded().unwrap();
        let cmd = unresolvable_first(&["-rf", "/"]);
        assert!(rules.match_command(&cmd).is_none());
    }

    // ==== Empty-string argv entries don't break flag/target scanning ====

    #[test]
    fn empty_string_tokens_do_not_break_scanning() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "", "-rf", "", "/"]);
        assert!(rules.match_command(&cmd).is_some());
    }

    // ==== Own unit tests: matcher primitives ====

    #[test]
    fn short_cluster_chars_handles_combined_and_separated_and_long() {
        assert_eq!(short_cluster_chars("-rf"), HashSet::from(['r', 'f']));
        assert_eq!(short_cluster_chars("-r"), HashSet::from(['r']));
        assert_eq!(short_cluster_chars("--recursive"), HashSet::new());
        assert_eq!(short_cluster_chars("-"), HashSet::new());
        assert_eq!(short_cluster_chars("plain"), HashSet::new());
    }

    #[test]
    fn flag_matcher_parse_rejects_bad_specs() {
        assert!(FlagMatcher::parse("rf").is_err()); // multi-char, no dash
        assert!(FlagMatcher::parse("-").is_err()); // bare dash, no letters
        assert!(FlagMatcher::parse("").is_err());
    }

    #[test]
    fn flag_matcher_parse_any_of_alternatives() {
        assert_eq!(
            FlagMatcher::parse("r|--recursive").unwrap(),
            FlagMatcher::AnyOf(vec![
                FlagMatcher::Short('r'),
                FlagMatcher::Token("--recursive".to_string()),
            ])
        );
    }

    #[test]
    fn flag_matcher_parse_rejects_empty_alternatives() {
        assert!(FlagMatcher::parse("r|").is_err());
        assert!(FlagMatcher::parse("|f").is_err());
        assert!(FlagMatcher::parse("r||f").is_err());
    }

    #[test]
    fn command_rule_override_replaces_same_id() {
        let base = r#"
            [[command]]
            id = "shared"
            reason = "base reason"
            command = "rm"
        "#;
        let overridden = r#"
            [[command]]
            id = "shared"
            reason = "overridden reason"
            command = "shred"
        "#;
        let base_rules = Rules::parse(base).unwrap();
        let over_rules = Rules::parse(overridden).unwrap();
        let layered = base_rules.layer(over_rules);
        let rule = layered
            .match_command(&argv(&["shred", "/dev/sda"]))
            .unwrap();
        assert_eq!(rule.reason().as_str(), "overridden reason");
        assert!(layered.match_command(&argv(&["rm", "/"])).is_none());
    }

    #[test]
    fn with_override_adds_new_id_and_keeps_builtins() {
        let extra = r#"
            [[command]]
            id = "extra-rule"
            reason = "custom operator rule"
            command = "wipe-everything"
        "#;
        let layered = Rules::with_override(extra).unwrap();
        assert!(layered.match_command(&argv(&["wipe-everything"])).is_some());
        // builtin still present
        assert!(layered.match_command(&argv(&["rm", "-rf", "/"])).is_some());
    }
}
