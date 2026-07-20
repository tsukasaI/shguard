//! Stage 3 of the pipeline (plan.md §1.1): mechanical, exact matching of a
//! resolved argv against `rules/blocklist.toml`/`rules/allowlist.toml`.
//!
//! Three rule kinds:
//! - [`CommandRule`] matches one simple command's argv: a command-name
//!   matcher, a set of required flags, a set of required bare tokens
//!   (subcommands/positional arguments), and a set of target matchers.
//! - [`PipelineRule`] matches the shape of a whole pipeline (the ported
//!   `curl|wget → sh` installer-pipe pattern only — the general decode-pipe
//!   gate is a later issue, plan.md §1.1 stage 4).
//! - [`RedirectRule`] matches a redirection target (output/append only)
//!   against a dangerous-path list (block devices, critical system files).
//!
//! Everything here operates on already-normalised [`NormalizedWord`] values
//! (`crate::normalize`, B2) — no raw strings, no regex over the command
//! line. An [`Resolution::Unresolvable`] word never matches any matcher and
//! never panics (module tests cover this).
//!
//! # Parse, don't validate
//!
//! [`CommandRuleDto`]/[`PipelineRuleDto`]/[`RedirectRuleDto`]/[`RulesFileDto`] are the only
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
//! [`Rules::match_pipeline`] via `src/gate.rs`, always with an empty
//! `Allowlist`/no `ask_rules`. `analyze_with_policy()` additionally
//! threads [`Rules::match_ask`], the [allowlist](#allowlist) section, and
//! whatever [`UserConfig`]/[`merge_user_config`] contributed — see
//! `src/gate.rs`'s module docs for the evaluation order, and
//! `src/config.rs` for where a user's config file is found and merged in.

use std::collections::HashSet;

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
    decision: Decision,
    command: CommandMatch,
    required_flags: Vec<FlagMatcher>,
    required_tokens: Vec<String>,
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

    #[must_use]
    pub(crate) fn decision(&self) -> Decision {
        self.decision
    }

    /// Whether this rule's command name, required flags, and required
    /// tokens match `argv`, ignoring the target constraint entirely — the
    /// shared building block behind [`Self::matches`] (which also checks
    /// targets) and [`Self::matches_except_target`] (plan.md §4's NEW
    /// argument-position bare-`$VAR` refinement, `src/gate.rs`).
    ///
    /// Resolves through [`effective_command`] (basename + transparent-
    /// wrapper skip) rather than a raw `argv[0]`/`argv[1..]` compare — the
    /// same resolution [`PipelineRule::matches`] already applies to
    /// pipeline sinks/sources, so a path-qualified or wrapped command
    /// (`/bin/rm`, `env rm`, `env git push --force`) cannot dodge a
    /// `command = "rm"`/`command = "git"` rule (security review finding:
    /// this module previously matched `argv[0]`/`argv[1..]` verbatim,
    /// silently missing every wrapped/path-qualified invocation — and for
    /// `required_tokens`, offsetting every positional index by one for any
    /// wrapped command, since `argv[1..]` still included the wrapper's own
    /// name).
    ///
    /// `required_tokens` are matched positionally against the leading
    /// non-dash-prefixed tokens after the resolved command —
    /// `required_tokens[0]` must be the first positional, `[1]` the
    /// second, etc. This prevents a commit message or branch name
    /// containing "clean" or "rebase" from triggering the wrong rule.
    ///
    /// Known gap: `git -C <path> push` places a non-dash token (`<path>`)
    /// before the subcommand; the rule won't match in that case.
    #[must_use]
    fn matches_command_and_flags(&self, argv: &[NormalizedWord]) -> bool {
        let Some((name, rest_words)) = effective_command(argv) else {
            return false;
        };
        if !self.command.matches(name) {
            return false;
        }
        let rest = resolved_strings(rest_words);
        if !self.required_flags.iter().all(|flag| flag.satisfied(&rest)) {
            return false;
        }
        if !self.required_tokens.is_empty() {
            let positionals: Vec<&str> = rest
                .iter()
                .filter(|t| !t.starts_with('-'))
                .copied()
                .collect();
            if !self
                .required_tokens
                .iter()
                .enumerate()
                .all(|(i, tok)| positionals.get(i).is_some_and(|p| *p == tok.as_str()))
            {
                return false;
            }
        }
        true
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
        // `matches_command_and_flags` already succeeded, so `effective_command`
        // is `Some` here; fail closed (no match) rather than unwrap regardless.
        let Some((_, rest_words)) = effective_command(argv) else {
            return false;
        };
        let rest = resolved_strings(rest_words);
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
    decision: Decision,
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

    #[must_use]
    pub(crate) fn decision(&self) -> Decision {
        self.decision
    }

    /// `stages` is one entry per pipeline stage, each the normalised argv
    /// of that stage's simple command, in pipeline order. Sink and source
    /// stages are both resolved through [`effective_command`] (basename +
    /// transparent-wrapper skip), not a raw exact-match on argv[0] — a
    /// path-qualified or wrapped sink (`/bin/sh`, `nohup sh`) must not dodge
    /// this rule (security-review fix, finding 2).
    #[must_use]
    fn matches(&self, stages: &[Vec<NormalizedWord>]) -> bool {
        let Some((sink_stage, source_stages)) = stages.split_last() else {
            return false;
        };
        if source_stages.is_empty() {
            return false;
        }
        let Some((sink_name, _)) = effective_command(sink_stage) else {
            return false;
        };
        if !self.sinks.iter().any(|sink| sink == sink_name) {
            return false;
        }
        source_stages.iter().any(|stage| {
            effective_command(stage)
                .is_some_and(|(name, _)| self.sources.iter().any(|src| src == name))
        })
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
// Effective-command resolution (security-review fix: shared basename /
// transparent-wrapper handling)
// ---------------------------------------------------------------------

/// Commands whose own name is never the thing a pipeline-shape rule cares
/// about: running one delegates to whatever command its own arguments name,
/// either literally (`env sh`/`nohup sh` runs `sh`) or via argument-shaped
/// indirection (`xargs sh` invokes `sh` once per batch, feeding it piped-in
/// arguments — the same "what actually runs" question as the others). See
/// [`effective_command`].
///
/// Shared by `src/gate.rs`'s pipeline-shape rules (`is_interpreter_sink`/
/// `is_decode_stage`) and [`PipelineRule::matches`] here, so a wrapped or
/// path-qualified sink/source cannot dodge either check by construction —
/// security-review finding 2: `/bin/sh`, `./sh`, `nohup sh`, `nice sh`,
/// `env sh`, `command sh`, `exec sh`, `xargs -0 sh` must all resolve to the
/// `sh` they actually run.
///
/// # Known limitation
///
/// Wrapper-argument skipping only recognises `-`-prefixed flags (plus
/// `env`'s `NAME=value` form) as skippable; a wrapper flag that takes a
/// separate value argument (`nice -n 19 sh`, `sudo -u root sh`) is not
/// specially handled — the value token does not start with `-`, so it is
/// mistaken for the wrapped command. None of this fix's required cases use
/// such a flag; documented here rather than silently guessed around.
pub(crate) const TRANSPARENT_WRAPPERS: &[&str] = &[
    "env", "command", "nohup", "nice", "exec", "stdbuf", "setsid", "sudo", "xargs",
];

/// Shell interpreters whose `-c '<string>'` argument `crate::gate` recurses
/// into as shell syntax (rule 6a). Lives here, next to
/// [`TRANSPARENT_WRAPPERS`], so this module's allow-entry validation
/// (`matches_dangerous_allow_target`) can check a config entry against the
/// same list `crate::gate` uses, without `rules` depending on `gate`
/// ("dependencies point inward" — `gate` already depends on `rules`, not
/// the reverse).
pub(crate) const SHELL_INTERPRETERS: &[&str] = &["bash", "sh", "zsh", "dash"];

/// Interpreters a pipeline's final stage may be (`crate::gate` rule 5b/5c).
/// See [`SHELL_INTERPRETERS`]'s docs for why this lives here.
pub(crate) const PIPELINE_INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "python", "python3", "node", "perl",
];

/// The basename of a command token: `/bin/sh` -> `sh`, `./sh` -> `sh`, a
/// bare `sh` unchanged. A pure string operation on the already-normalised
/// token — never a filesystem lookup or symlink resolution (this crate
/// never touches the filesystem, module docs).
fn basename(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

/// Whether `token` has the `NAME=value` shape of a POSIX environment
/// assignment — `env`'s own leading-argument syntax (`env FOO=bar sh`): a
/// non-empty run of ASCII letters/digits/underscore, not starting with a
/// digit, followed by `=`. Used only so [`effective_command`] can skip past
/// `env`'s assignment arguments the same way it skips `-`-flags.
fn is_env_assignment_shape(token: &str) -> bool {
    let Some((name, _value)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Finds the command a pipeline stage actually runs: the basename of
/// `stage`'s command word, looking through any leading chain of
/// [`TRANSPARENT_WRAPPERS`] (`nohup nice sh` resolves through both). Returns
/// the effective command name plus the argv words after it, so a caller can
/// still inspect the wrapped command's own flags (`is_decode_stage`'s
/// `base64 -d` check must still see `-d` when reached through `env base64
/// -d`).
///
/// Returns `None` — fail-closed, never a guess — when the stage is empty,
/// the command word (or a wrapper's, mid-chain) is unresolvable, or a
/// wrapper's own arguments consume the rest of the stage with no command
/// left (`env` alone).
#[must_use]
pub(crate) fn effective_command(stage: &[NormalizedWord]) -> Option<(&str, &[NormalizedWord])> {
    let mut rest = stage;
    loop {
        let (first, tail) = rest.split_first()?;
        let Resolution::Resolved(name) = first.resolution() else {
            return None;
        };
        let base = basename(name);
        if TRANSPARENT_WRAPPERS.contains(&base) {
            rest = skip_wrapper_arguments(base, tail);
        } else {
            return Some((base, tail));
        }
    }
}

/// Skips a transparent wrapper's own leading arguments (see
/// [`effective_command`]'s docs): every `-`-prefixed token, plus
/// `NAME=value` tokens when `wrapper == "env"`. Stops at the first token
/// that is neither — that token is the wrapped command — or at the first
/// unresolvable token, which leaves `effective_command`'s next loop
/// iteration to fail closed to `None`.
fn skip_wrapper_arguments<'a>(wrapper: &str, argv: &'a [NormalizedWord]) -> &'a [NormalizedWord] {
    let mut idx = 0;
    while idx < argv.len() {
        let Resolution::Resolved(token) = argv[idx].resolution() else {
            break;
        };
        let skippable =
            token.starts_with('-') || (wrapper == "env" && is_env_assignment_shape(token));
        if !skippable {
            break;
        }
        idx += 1;
    }
    &argv[idx..]
}

// ---------------------------------------------------------------------
// Serde DTOs (private to this module — parse, don't validate)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFileDto {
    #[serde(default)]
    command: Vec<CommandRuleDto>,
    #[serde(default)]
    pipeline: Vec<PipelineRuleDto>,
    #[serde(default)]
    redirect: Vec<RedirectRuleDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowlistFileDto {
    #[serde(default)]
    entry: Vec<CommandRuleDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandRuleDto {
    id: String,
    reason: String,
    #[serde(default)]
    decision: Option<String>,
    command: Option<String>,
    command_prefix: Option<String>,
    #[serde(default)]
    required_flags: Vec<String>,
    #[serde(default)]
    required_tokens: Vec<String>,
    #[serde(default)]
    targets: Vec<TargetDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetDto {
    exact: Option<String>,
    prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineRuleDto {
    id: String,
    reason: String,
    #[serde(default)]
    decision: Option<String>,
    sources: Vec<String>,
    sinks: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedirectRuleDto {
    id: String,
    reason: String,
    #[serde(default)]
    decision: Option<String>,
    targets: Vec<TargetDto>,
}

/// Parses an optional `decision` string into a [`Decision`], defaulting to
/// `Block` when absent. Only `"block"` and `"ask"` are valid; anything else
/// is a load-time error (fail-closed).
fn parse_decision(rule_id: &str, raw: Option<&str>) -> Result<Decision, RulesError> {
    match raw {
        None | Some("block") => Ok(Decision::Block),
        Some("ask") => Ok(Decision::Ask),
        Some(other) => Err(RulesError::invalid(
            rule_id,
            format!("decision must be \"block\" or \"ask\", got {other:?}"),
        )),
    }
}

/// Converts a [`CommandRuleDto`] into a [`CommandRule`], rejecting every
/// semantically-invalid shape at this one boundary: empty id, empty
/// reason, neither/both of `command`/`command_prefix` set, an empty
/// `command`/`command_prefix` value, a malformed flag spec, an invalid
/// required_tokens entry, or a target with neither/both of
/// `exact`/`prefix` set.
fn convert_command_rule(dto: CommandRuleDto) -> Result<CommandRule, RulesError> {
    if dto.id.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "id must not be empty"));
    }
    if dto.reason.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "reason must not be empty"));
    }

    let command = match (dto.command, dto.command_prefix) {
        (Some(exact), None) => {
            if exact.trim().is_empty() {
                return Err(RulesError::invalid(&dto.id, "`command` must not be empty"));
            }
            CommandMatch::Exact(exact)
        }
        (None, Some(prefix)) => {
            // An empty `command_prefix` produces `CommandMatch::Prefix("")`,
            // which matches every command name (`"".starts_with("")` is
            // always true) — a silent universal matcher. Harmless in a
            // `deny` entry (over-broad blocking); catastrophic in an
            // `allow` entry (suppresses every `Ask` in the system).
            if prefix.trim().is_empty() {
                return Err(RulesError::invalid(
                    &dto.id,
                    "`command_prefix` must not be empty",
                ));
            }
            CommandMatch::Prefix(prefix)
        }
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

    let decision = parse_decision(&dto.id, dto.decision.as_deref())?;

    let required_flags = dto
        .required_flags
        .iter()
        .map(|spec| {
            FlagMatcher::parse(spec).map_err(|problem| RulesError::invalid(&dto.id, problem))
        })
        .collect::<Result<Vec<_>, _>>()?;

    for token in &dto.required_tokens {
        if token.trim().is_empty() {
            return Err(RulesError::invalid(
                &dto.id,
                "required_tokens entry must not be empty",
            ));
        }
        if token.starts_with('-') {
            return Err(RulesError::invalid(
                &dto.id,
                format!(
                    "required_tokens entry {token:?} starts with '-'; use required_flags for flags"
                ),
            ));
        }
    }

    let targets = dto
        .targets
        .into_iter()
        .map(|t| convert_target(&dto.id, t))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CommandRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        decision,
        command,
        required_flags,
        required_tokens: dto.required_tokens,
        targets,
    })
}

fn convert_target(rule_id: &str, dto: TargetDto) -> Result<TargetMatcher, RulesError> {
    match (dto.exact, dto.prefix) {
        (Some(exact), None) => {
            if exact.trim().is_empty() {
                return Err(RulesError::invalid(
                    rule_id,
                    "target's `exact` must not be empty",
                ));
            }
            Ok(TargetMatcher::Exact(exact))
        }
        (None, Some(prefix)) => {
            // An empty prefix produces a universal matcher
            // (`"".starts_with("")` is always true) — the same hazard
            // `convert_command_rule` already guards against for an empty
            // `command_prefix`.
            if prefix.trim().is_empty() {
                return Err(RulesError::invalid(
                    rule_id,
                    "target's `prefix` must not be empty",
                ));
            }
            Ok(TargetMatcher::Prefix(prefix))
        }
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

    let decision = parse_decision(&dto.id, dto.decision.as_deref())?;

    Ok(PipelineRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        decision,
        sources: dto.sources,
        sinks: dto.sinks,
    })
}

fn convert_redirect_rule(dto: RedirectRuleDto) -> Result<RedirectRule, RulesError> {
    if dto.id.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "id must not be empty"));
    }
    if dto.reason.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "reason must not be empty"));
    }
    if dto.targets.is_empty() {
        return Err(RulesError::invalid(
            &dto.id,
            "redirect rule requires at least one target",
        ));
    }

    let decision = parse_decision(&dto.id, dto.decision.as_deref())?;

    let targets = dto
        .targets
        .into_iter()
        .map(|t| convert_target(&dto.id, t))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RedirectRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        decision,
        targets,
    })
}

/// A rule matching the target of an output/append redirection (`>`, `>>`)
/// against a curated list of dangerous paths (block devices, critical
/// system files). Unlike [`CommandRule`], an empty `targets` list is a
/// load-time error — matching any redirection would be far too broad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedirectRule {
    id: RuleId,
    reason: Reason,
    decision: Decision,
    targets: Vec<TargetMatcher>,
}

impl RedirectRule {
    #[must_use]
    pub(crate) fn id(&self) -> &RuleId {
        &self.id
    }

    #[must_use]
    pub(crate) fn reason(&self) -> &Reason {
        &self.reason
    }

    #[must_use]
    pub(crate) fn decision(&self) -> Decision {
        self.decision
    }

    #[must_use]
    fn matches(&self, target: &str) -> bool {
        self.targets.iter().any(|t| t.matches(target))
    }
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

/// A loaded, validated rule set: [`CommandRule`]s, [`PipelineRule`]s, and
/// [`RedirectRule`]s, every id unique within the set.
///
/// `ask_rules` is always empty for a [`Self::parse`]d/[`Self::embedded`]
/// set — `RulesFileDto`/`rules/blocklist.toml` have no `[[ask]]` array of
/// their own. It is populated only by [`merge_user_config`], which is also
/// the only place a user config's `[[ask]]` entries can reach a `Rules`
/// value at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rules {
    command_rules: Vec<CommandRule>,
    pipeline_rules: Vec<PipelineRule>,
    redirect_rules: Vec<RedirectRule>,
    ask_rules: Vec<CommandRule>,
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
        let redirect_rules = dto
            .redirect
            .into_iter()
            .map(convert_redirect_rule)
            .collect::<Result<Vec<_>, _>>()?;

        reject_duplicate_ids(
            command_rules
                .iter()
                .map(|r| r.id.as_str())
                .chain(pipeline_rules.iter().map(|r| r.id.as_str()))
                .chain(redirect_rules.iter().map(|r| r.id.as_str())),
        )?;

        Ok(Self {
            command_rules,
            pipeline_rules,
            redirect_rules,
            ask_rules: Vec::new(),
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

    /// The first [`RedirectRule`] whose target list matches `target`, if any.
    #[must_use]
    pub(crate) fn match_redirect_target(&self, target: &str) -> Option<&RedirectRule> {
        self.redirect_rules.iter().find(|rule| rule.matches(target))
    }

    /// The first user-configured `ask` [`CommandRule`] that matches `argv`,
    /// if any. Always `None` for an embedded-only [`Rules`] (see the struct
    /// docs) — only [`merge_user_config`] populates `ask_rules`.
    #[must_use]
    pub(crate) fn match_ask(&self, argv: &[NormalizedWord]) -> Option<&CommandRule> {
        self.ask_rules.iter().find(|rule| rule.matches(argv))
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
// User config (deny/ask/allow) — plan.md §6 item 8
// ---------------------------------------------------------------------

/// Whether `entry`'s matcher would match any known shell interpreter or
/// transparent wrapper name (`SHELL_INTERPRETERS`/`PIPELINE_INTERPRETERS`/
/// `TRANSPARENT_WRAPPERS`) — used to reject `allow` config entries that
/// would suppress every recursion-derived `Ask` involving one of those
/// names (`bash -c` recursion, a decode-fed pipeline sink, the
/// substitution-depth-cap DoS guard's own fail-closed `Ask`), not just an
/// entry that names one exactly: `entry.command`'s own `matches` is reused
/// against every candidate name, so a `command_prefix = "b"` entry is
/// caught the same way an exact `command = "bash"` entry would be — a
/// `Prefix` matcher this permissive is exactly as dangerous as an exact
/// one.
fn matches_dangerous_allow_target(entry: &CommandRule) -> bool {
    SHELL_INTERPRETERS
        .iter()
        .chain(PIPELINE_INTERPRETERS.iter())
        .chain(TRANSPARENT_WRAPPERS.iter())
        .any(|name| entry.command.matches(name))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserConfigFileDto {
    #[serde(default)]
    deny: Vec<CommandRuleDto>,
    #[serde(default)]
    ask: Vec<CommandRuleDto>,
    #[serde(default)]
    allow: Vec<CommandRuleDto>,
}

/// A user-supplied policy config, parsed and validated but not yet merged
/// with the embedded blocklist/allowlist — see [`merge_user_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserConfig {
    deny: Vec<CommandRule>,
    ask: Vec<CommandRule>,
    allow: Vec<CommandRule>,
}

impl UserConfig {
    /// Parses `toml` (never a path — this module's "file I/O stays out of
    /// this module" convention) into a validated [`UserConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] for invalid TOML syntax, a semantically
    /// invalid entry (same checks as [`Rules::parse`]/[`Allowlist::parse`]),
    /// a duplicate id — checked across all three of `deny`/`ask`/`allow`
    /// together, one shared id-space, so an id can't dodge the check by
    /// moving arrays — or an `allow` entry matching a shell interpreter or
    /// transparent wrapper name (see [`matches_dangerous_allow_target`]).
    pub(crate) fn parse(toml: &str) -> Result<Self, RulesError> {
        let dto: UserConfigFileDto = toml::from_str(toml)?;

        let deny = dto
            .deny
            .into_iter()
            .map(convert_command_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let ask = dto
            .ask
            .into_iter()
            .map(convert_command_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let allow = dto
            .allow
            .into_iter()
            .map(convert_command_rule)
            .collect::<Result<Vec<_>, _>>()?;

        reject_duplicate_ids(
            deny.iter()
                .map(|r| r.id.as_str())
                .chain(ask.iter().map(|r| r.id.as_str()))
                .chain(allow.iter().map(|r| r.id.as_str())),
        )?;

        for entry in &allow {
            if matches_dangerous_allow_target(entry) {
                return Err(RulesError::invalid(
                    entry.id.as_str(),
                    "an `allow` entry must not match a shell interpreter or transparent \
                     wrapper name (bash, sh, env, xargs, ...) — this would suppress every \
                     recursion-derived Ask involving that name, including the substitution-\
                     depth-cap fail-closed guard's own Ask",
                ));
            }
        }

        Ok(Self { deny, ask, allow })
    }
}

/// Merges a user config's `deny`/`ask`/`allow` onto the embedded blocklist
/// plus allowlist, additively only, never replace-by-id (unlike the
/// deleted `Rules::with_override`/`layer`).
///
/// Every id the user config introduces, across all three arrays, must be
/// new versus `blocklist`'s command rule ids, `blocklist`'s pipeline rule
/// ids, and `allowlist`'s entry ids — one shared id-space. A collision is a
/// load-time [`RulesError::DuplicateId`], fail-closed, never a silent
/// replace.
///
/// `deny` entries land in the returned `Rules`' `command_rules`, the
/// existing Block-matching path, so `evaluate_simple_command` needs no
/// change to pick them up. `ask` entries land in `ask_rules` (see
/// [`Rules::match_ask`]). `allow` entries land in the returned
/// `Allowlist`'s entries; the only path from a config `allow` entry to a
/// permissive decision is [`apply_allowlist`], which is structurally
/// Block-immune before it even consults its entries.
///
/// # Errors
///
/// Returns [`RulesError::DuplicateId`] on any id collision described above.
pub(crate) fn merge_user_config(
    blocklist: Rules,
    allowlist: Allowlist,
    user_config: UserConfig,
) -> Result<(Rules, Allowlist), RulesError> {
    let existing_ids: HashSet<String> = blocklist
        .command_rules
        .iter()
        .map(|r| r.id.as_str().to_string())
        .chain(
            blocklist
                .pipeline_rules
                .iter()
                .map(|r| r.id.as_str().to_string()),
        )
        .chain(
            blocklist
                .redirect_rules
                .iter()
                .map(|r| r.id.as_str().to_string()),
        )
        .chain(
            blocklist
                .ask_rules
                .iter()
                .map(|r| r.id.as_str().to_string()),
        )
        .chain(allowlist.entries.iter().map(|r| r.id.as_str().to_string()))
        .collect();

    for id in user_config
        .deny
        .iter()
        .map(|r| r.id.as_str())
        .chain(user_config.ask.iter().map(|r| r.id.as_str()))
        .chain(user_config.allow.iter().map(|r| r.id.as_str()))
    {
        if existing_ids.contains(id) {
            return Err(RulesError::DuplicateId(id.to_string()));
        }
    }

    let mut command_rules = blocklist.command_rules;
    command_rules.extend(user_config.deny);

    let mut ask_rules = blocklist.ask_rules;
    ask_rules.extend(user_config.ask);

    let mut entries = allowlist.entries;
    entries.extend(user_config.allow);

    Ok((
        Rules {
            command_rules,
            pipeline_rules: blocklist.pipeline_rules,
            redirect_rules: blocklist.redirect_rules,
            ask_rules,
        },
        Allowlist { entries },
    ))
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

    // ==== Security review: CommandRule matching resolves basename + skips
    // transparent wrappers, the same way PipelineRule matching already does
    // (matches_command_and_flags now goes through effective_command instead
    // of a raw argv[0] compare) ====

    #[test]
    fn rm_rf_root_matches_via_absolute_path() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["/bin/rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn rm_rf_root_matches_through_env_wrapper() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["env", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn rm_rf_root_matches_through_nohup_wrapper() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["nohup", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn custom_rule_matches_absolute_path_command() {
        let toml = r#"
            [[command]]
            id = "deny-gh"
            reason = "test"
            command = "gh"
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["/opt/homebrew/bin/gh", "repo", "delete"]))
                .is_some()
        );
    }

    #[test]
    fn custom_rule_matches_wrapped_command_with_wrapper_flags() {
        let toml = r#"
            [[command]]
            id = "deny-gh"
            reason = "test"
            command = "gh"
            required_flags = ["--yes"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        // `env`'s own leading assignment argument must not be mistaken for
        // one of gh's own required flags, nor prevent them being seen.
        assert!(
            rules
                .match_command(&argv(&["env", "FOO=bar", "gh", "repo", "delete", "--yes"]))
                .is_some()
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

    // ==== Self-protection: literal ~/.config/shguard/ token ====

    #[test]
    fn self_protect_tee_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["tee", "~/.config/shguard/config.toml"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_cp_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["cp", "evil.toml", "~/.config/shguard/config.toml"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_sed_without_dash_i_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["sed", "s/x/y/", "~/.config/shguard/config.toml"]))
                .is_none()
        );
    }

    #[test]
    fn self_protect_dd_of_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "dd",
                    "if=/dev/zero",
                    "of=~/.config/shguard/config.toml"
                ]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_cp_unrelated_files_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["cp", "a.txt", "b.txt"]))
                .is_none()
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

    // ==== UserConfig::parse ====

    #[test]
    fn user_config_parses_deny_ask_allow() {
        let toml = r#"
            [[deny]]
            id = "user-deny-scary"
            reason = "never run this"
            command = "scary-tool"

            [[ask]]
            id = "user-ask-gh"
            reason = "confirm every gh invocation"
            command = "gh"

            [[allow]]
            id = "user-allow-ls"
            reason = "read-only, always safe"
            command = "ls"
        "#;
        let config = UserConfig::parse(toml).unwrap();
        assert_eq!(config.deny.len(), 1);
        assert_eq!(config.ask.len(), 1);
        assert_eq!(config.allow.len(), 1);
    }

    #[test]
    fn user_config_rejects_duplicate_id_across_arrays() {
        let toml = r#"
            [[deny]]
            id = "dup"
            reason = "a"
            command = "foo"

            [[ask]]
            id = "dup"
            reason = "b"
            command = "bar"
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::DuplicateId(id)) if id == "dup"
        ));
    }

    #[test]
    fn user_config_rejects_allow_entry_matching_shell_interpreter_exactly() {
        let toml = r#"
            [[allow]]
            id = "user-allow-bash"
            reason = "trust me"
            command = "bash"
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn user_config_rejects_allow_entry_whose_prefix_captures_a_shell_interpreter() {
        // command_prefix = "b" matches "bash" at runtime via CommandMatch::Prefix's
        // own starts_with semantics, just as validly as an exact command = "bash"
        // would — the inclusion-aware check must catch this too, not just equality.
        let toml = r#"
            [[allow]]
            id = "user-allow-b-prefix"
            reason = "trust me"
            command_prefix = "b"
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn user_config_rejects_allow_entry_matching_transparent_wrapper() {
        let toml = r#"
            [[allow]]
            id = "user-allow-env"
            reason = "trust me"
            command = "env"
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn empty_command_prefix_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command_prefix = ""
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn empty_command_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = ""
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn empty_target_prefix_is_rejected() {
        // An empty prefix is a silent universal matcher
        // ("".starts_with("") is always true) — same hazard as an empty
        // command_prefix, catastrophic once reachable from an allow entry.
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "rm"
            targets = [{ prefix = "" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn empty_target_exact_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "rm"
            targets = [{ exact = "" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn unknown_field_in_command_rule_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "rm"
            target = [{ exact = "/" }]
        "#;
        assert!(Rules::parse(toml).is_err());
    }

    // ==== merge_user_config: additive, never replace-by-id ====

    #[test]
    fn merge_user_config_adds_new_ids_and_keeps_builtins() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[deny]]
            id = "user-deny-scary"
            reason = "never run this"
            command = "scary-tool"
        "#,
        )
        .unwrap();
        let (merged, _) = merge_user_config(blocklist, allowlist, config).unwrap();
        assert!(merged.match_command(&argv(&["scary-tool"])).is_some());
        // builtin still present
        assert!(merged.match_command(&argv(&["rm", "-rf", "/"])).is_some());
    }

    #[test]
    fn merge_user_config_rejects_id_colliding_with_embedded_blocklist_id() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        // Real embedded id, reused by an unrelated-looking user rule.
        let config = UserConfig::parse(
            r#"
            [[deny]]
            id = "rm-recursive-force-dangerous-target"
            reason = "totally different rule"
            command = "totally-different-command"
        "#,
        )
        .unwrap();
        assert!(matches!(
            merge_user_config(blocklist, allowlist, config),
            Err(RulesError::DuplicateId(id)) if id == "rm-recursive-force-dangerous-target"
        ));
    }

    #[test]
    fn merge_user_config_rejects_id_colliding_with_embedded_allowlist_id() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::parse(
            r#"
            [[entry]]
            id = "shared-id"
            reason = "existing allowlist entry"
            command = "ls"
        "#,
        )
        .unwrap();
        let config = UserConfig::parse(
            r#"
            [[ask]]
            id = "shared-id"
            reason = "unrelated"
            command = "gh"
        "#,
        )
        .unwrap();
        assert!(matches!(
            merge_user_config(blocklist, allowlist, config),
            Err(RulesError::DuplicateId(id)) if id == "shared-id"
        ));
    }

    #[test]
    fn merged_allow_entry_cannot_convert_block_to_allow() {
        // End-to-end version of dod_4_allowlist_cannot_convert_block_to_allow,
        // but through the merge path — proves a config-declared allow entry
        // is structurally Block-immune, same as a hand-built Allowlist.
        let blocklist = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "/"]);
        let rule = blocklist.match_command(&cmd).unwrap();
        let block = Verdict::block(
            Reason::new(rule.reason().as_str().to_string()),
            cmd.clone(),
            Some(rule.id().clone()),
        );

        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[allow]]
            id = "user-trusts-rm"
            reason = "operator trusts this exact shape"
            command = "rm"
            required_flags = ["r", "f"]
            targets = [{ exact = "/" }]
        "#,
        )
        .unwrap();
        let (_, merged_allowlist) = merge_user_config(blocklist, allowlist, config).unwrap();

        // sanity: the merged allowlist entry does match this argv
        assert!(merged_allowlist.first_match(&cmd).is_some());

        let outcome = apply_allowlist(&block, &merged_allowlist);
        assert_eq!(outcome, AllowlistOutcome::Unchanged);
        assert_eq!(block.decision(), Decision::Block);
    }

    #[test]
    fn merge_user_config_rejects_id_colliding_with_existing_ask_rule() {
        // Adversarial-review finding: the id-collision id-space must also
        // cover ask_rules already present in `blocklist` (e.g. from a
        // prior merge, such as shguard's own self-protection pass) — not
        // just command_rules/pipeline_rules/allowlist entries.
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let first_config = UserConfig::parse(
            r#"
            [[ask]]
            id = "user-ask-gh"
            reason = "confirm every gh invocation"
            command = "gh"
        "#,
        )
        .unwrap();
        let (rules, allowlist) = merge_user_config(blocklist, allowlist, first_config).unwrap();

        let second_config = UserConfig::parse(
            r#"
            [[deny]]
            id = "user-ask-gh"
            reason = "unrelated"
            command = "totally-different-command"
        "#,
        )
        .unwrap();
        assert!(matches!(
            merge_user_config(rules, allowlist, second_config),
            Err(RulesError::DuplicateId(id)) if id == "user-ask-gh"
        ));
    }

    #[test]
    fn merge_user_config_ask_entries_are_reachable_via_match_ask() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[ask]]
            id = "user-ask-gh"
            reason = "confirm every gh invocation"
            command = "gh"
        "#,
        )
        .unwrap();
        let (merged, _) = merge_user_config(blocklist, allowlist, config).unwrap();
        assert!(merged.match_ask(&argv(&["gh", "pr", "view"])).is_some());
        assert!(merged.match_ask(&argv(&["ls"])).is_none());
    }

    // ==== required_tokens schema extension ====

    #[test]
    fn required_tokens_matches_bare_subcommand() {
        let toml = r#"
            [[command]]
            id = "git-push-force"
            reason = "force push"
            command = "git"
            required_tokens = ["push"]
            required_flags = ["f|--force"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["git", "push", "--force", "origin"]))
                .is_some()
        );
        assert!(
            rules
                .match_command(&argv(&["git", "push", "-f", "origin"]))
                .is_some()
        );
    }

    #[test]
    fn required_tokens_rejects_when_token_absent() {
        let toml = r#"
            [[command]]
            id = "git-push-force"
            reason = "force push"
            command = "git"
            required_tokens = ["push"]
            required_flags = ["f|--force"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        // "commit" present instead of "push"
        assert!(
            rules
                .match_command(&argv(&["git", "commit", "--force"]))
                .is_none()
        );
    }

    #[test]
    fn required_tokens_all_must_be_present() {
        let toml = r#"
            [[command]]
            id = "git-stash-drop"
            reason = "stash drop"
            command = "git"
            required_tokens = ["stash", "drop"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["git", "stash", "drop"]))
                .is_some()
        );
        // only one token present
        assert!(rules.match_command(&argv(&["git", "stash"])).is_none());
        assert!(rules.match_command(&argv(&["git", "drop"])).is_none());
    }

    #[test]
    fn required_tokens_rejects_dash_prefixed_at_load_time() {
        let toml = r#"
            [[command]]
            id = "bad"
            reason = "flags belong in required_flags"
            command = "git"
            required_tokens = ["--force"]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn required_tokens_rejects_empty_entry() {
        let toml = r#"
            [[command]]
            id = "bad"
            reason = "empty token"
            command = "git"
            required_tokens = [""]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn required_tokens_does_not_match_flag_spelling() {
        // "--rebase" (a flag in `git pull --rebase`) must not satisfy
        // required_tokens = ["rebase"] — they're different namespaces.
        let toml = r#"
            [[command]]
            id = "git-rebase"
            reason = "rebase"
            command = "git"
            required_tokens = ["rebase"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["git", "pull", "--rebase"]))
                .is_none()
        );
        assert!(
            rules
                .match_command(&argv(&["git", "rebase", "main"]))
                .is_some()
        );
    }

    #[test]
    fn required_tokens_positional_matching_prevents_false_positives() {
        let toml = r#"
            [[command]]
            id = "git-clean-any"
            reason = "clean"
            command = "git"
            required_tokens = ["clean"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        // "clean" as a commit message (second positional) must NOT match.
        assert!(
            rules
                .match_command(&argv(&["git", "commit", "-m", "clean"]))
                .is_none()
        );
        // "clean" as first positional DOES match.
        assert!(
            rules
                .match_command(&argv(&["git", "clean", "-fd"]))
                .is_some()
        );
    }

    #[test]
    fn required_tokens_positional_not_anywhere_in_argv() {
        let toml = r#"
            [[command]]
            id = "git-push-force"
            reason = "force push"
            command = "git"
            required_tokens = ["push"]
            required_flags = ["f|--force"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        // "push" as a branch name (second positional) must NOT match.
        assert!(
            rules
                .match_command(&argv(&["git", "checkout", "-f", "push"]))
                .is_none()
        );
        // "push" as first positional DOES match.
        assert!(
            rules
                .match_command(&argv(&["git", "push", "-f", "origin"]))
                .is_some()
        );
    }

    // ==== Merge-reconciliation finding: required_tokens must resolve
    // through effective_command too, or a wrapped/path-qualified command
    // reintroduces exactly the bypass the prerequisite effective_command
    // fix closed for required_flags/targets — matching against raw
    // argv[1..] instead of effective_command's rest_words would offset
    // every positional index by one for any wrapped invocation, making
    // required_tokens matching fail (a false negative / bypass) rather
    // than just misalign. ====

    #[test]
    fn required_tokens_matches_through_env_wrapper() {
        let toml = r#"
            [[command]]
            id = "git-push-force"
            reason = "force push"
            command = "git"
            required_tokens = ["push"]
            required_flags = ["f|--force"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["env", "git", "push", "--force", "origin"]))
                .is_some()
        );
    }

    #[test]
    fn embedded_git_push_force_rule_matches_through_env_wrapper() {
        // Same as above, but against the real embedded rule (PR #20's
        // git-push-force) rather than a hand-built fixture.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["env", "git", "push", "--force", "origin"]))
                .is_some()
        );
    }

    // ==== decision field ====

    #[test]
    fn decision_defaults_to_block() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "test"
            command = "rm"
        "#;
        let rules = Rules::parse(toml).unwrap();
        let rule = rules.match_command(&argv(&["rm", "file"])).unwrap();
        assert_eq!(rule.decision(), Decision::Block);
    }

    #[test]
    fn decision_explicit_block() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "test"
            command = "rm"
            decision = "block"
        "#;
        let rules = Rules::parse(toml).unwrap();
        let rule = rules.match_command(&argv(&["rm", "file"])).unwrap();
        assert_eq!(rule.decision(), Decision::Block);
    }

    #[test]
    fn decision_ask() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "test"
            command = "rm"
            decision = "ask"
        "#;
        let rules = Rules::parse(toml).unwrap();
        let rule = rules.match_command(&argv(&["rm", "file"])).unwrap();
        assert_eq!(rule.decision(), Decision::Ask);
    }

    #[test]
    fn decision_invalid_value_is_err() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "test"
            command = "rm"
            decision = "allow"
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn pipeline_decision_field() {
        let toml = r#"
            [[pipeline]]
            id = "x"
            reason = "test"
            decision = "ask"
            sources = ["curl"]
            sinks = ["sh"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        let stages = vec![argv(&["curl", "http://x"]), argv(&["sh"])];
        let rule = rules.match_pipeline(&stages).unwrap();
        assert_eq!(rule.decision(), Decision::Ask);
    }

    // ==== redirect rule ====

    #[test]
    fn redirect_rule_matches_target() {
        let toml = r#"
            [[redirect]]
            id = "dev-write"
            reason = "writing to block device"
            targets = [{ prefix = "/dev/sd" }]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(rules.match_redirect_target("/dev/sda").is_some());
        assert!(rules.match_redirect_target("/dev/null").is_none());
    }

    #[test]
    fn redirect_rule_empty_targets_is_err() {
        let toml = r#"
            [[redirect]]
            id = "bad"
            reason = "no targets"
            targets = []
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn redirect_rule_shares_id_namespace() {
        let toml = r#"
            [[command]]
            id = "shared-id"
            reason = "command rule"
            command = "rm"

            [[redirect]]
            id = "shared-id"
            reason = "redirect rule"
            targets = [{ exact = "/etc/passwd" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::DuplicateId(_))
        ));
    }
}
