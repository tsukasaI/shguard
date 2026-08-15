//! Stage 3 of the pipeline (plan.md §1.1): mechanical, exact matching of a
//! resolved argv against `rules/blocklist.toml`/`rules/allowlist.toml`.
//!
//! Three rule kinds:
//! - [`CommandRule`] matches one simple command's argv: a command-name
//!   matcher, a set of required flags, a set of required bare tokens
//!   (subcommands/positional arguments), a set of target matchers, and a
//!   set of except-target matchers (issue #30: "matches unless the target
//!   is one of these shapes").
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

use std::borrow::Cow;
use std::collections::HashSet;

use serde::Deserialize;

use crate::gate::{FlagScan, scan_for_flag};
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
/// BSD-style single-dash long flags (`find -delete`). A `Token` also
/// matches the GNU `--flag=value` spelling (`--in-place=.bak` satisfies a
/// required `--in-place`) — this only ever widens the match, so it cannot
/// dodge a rule that was already matching the bare flag.
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
    /// A `-`-prefixed argv token, matched verbatim or with a `=value`
    /// suffix (GNU long-option convention, e.g. `--in-place=.bak`).
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
            Self::Token(token) => argv.iter().any(|arg| {
                *arg == token.as_str()
                    || arg
                        .strip_prefix(token.as_str())
                        .is_some_and(|rest| rest.starts_with('='))
            }),
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

/// tar-specific single-letter options this crate's rules ever need to see
/// through a dash-less cluster (issue #67) — GNU tar's commonly-used
/// boolean/value-less single letters, not an attempt at exhaustive
/// coverage of tar's entire option set. `f` (`--file`) and `C`
/// (`--directory`) each consume the following
/// positional argument; every other letter here is boolean (mode/behavior
/// flags that never take a value): `x` (extract), `c` (create), `t`
/// (list), `z` (gzip), `v` (verbose), `j` (bzip2), `J` (xz), `a`
/// (auto-compress), `Z` (compress), `k` (keep-old-files), `p`
/// (preserve-permissions), `w` (interactive), `m` (no-mtime), `O`
/// (to-stdout), `h` (dereference), `S` (sparse), `P` (absolute-names — the
/// rewrite's own synthetic `-P` token is then seen by the separate
/// `tar-absolute-names-ask` rule exactly as a written-with-dashes `-P`
/// would be). This list can never be exhaustive (tar keeps adding
/// options), which is exactly why [`tar_dashless_cluster`] no longer
/// treats an unmodeled letter as "not a cluster at all" — see its own
/// docs.
const TAR_DASHLESS_CONSUMING: &[char] = &['f', 'C'];
const TAR_DASHLESS_BOOLEAN: &[char] = &[
    'x', 'c', 't', 'z', 'v', 'j', 'J', 'a', 'Z', 'k', 'p', 'w', 'm', 'O', 'h', 'S', 'P',
];

/// [`tar_dashless_cluster`]'s three-way outcome — mirrors the fail-closed
/// "definitely / definitely-not / uncertain" shape `crate::gate`'s
/// `FlagScan` uses for flag-position scans (an unresolvable word "might be
/// the flag", never "definitely not"), expressed here over a `tar` hop's
/// tail instead of a generic flag-position scan, since recognizing tar's
/// own dash-less calling convention is tar-specific, not a general
/// `FlagMatcher` concern (see [`tar_dashless_cluster`]'s docs).
pub(crate) enum TarDashlessCluster {
    /// A recognized `x`+`C` dash-less cluster, already rewritten into its
    /// dashed-token equivalent — the caller should match flags/targets
    /// against this instead of the original tail.
    Recognized(Vec<NormalizedWord>),
    /// `tail`'s first word isn't a plausible dash-less option cluster at
    /// all (unresolved, empty, `-`-prefixed, contains a non-alphabetic
    /// character, or has no `x`) — ordinary dashed-only matching applies,
    /// completely untouched.
    NotApplicable,
    /// A *plausible* dash-less cluster — fully alphabetic, contains `x` —
    /// but with at least one letter outside
    /// [`TAR_DASHLESS_CONSUMING`]/[`TAR_DASHLESS_BOOLEAN`]. Treating a
    /// single unmodeled letter (`j`, `a`, …) as disqualifying the ENTIRE
    /// cluster would silently fall through to dashed-only matching that
    /// can't see a dash-less token at all — `tar xjfC evil.tar.bz2 /`
    /// would reach `Allow`. The caller must never treat this the same as
    /// [`Self::NotApplicable`]: it must floor the decision to `Ask`
    /// instead (this crate's tar option coverage can never be
    /// exhaustive, so "next new letter I didn't think of" must fail
    /// closed, not open).
    Unmodeled,
}

/// Classifies a `tar` hop's dash-less leading option cluster (POSIX tar's
/// own old-style calling convention, e.g. `tar xfC a.tar /`) — see
/// [`TarDashlessCluster`] for the three possible outcomes and
/// [`tar_dashless_rewrite`] for the [`FlagMatcher`]/[`TargetMatcher`]-
/// facing wrapper most callers actually want.
///
/// [`TarDashlessCluster::Recognized`] fires only when `tail`'s first word
/// is [`Resolution::Resolved`], non-empty, has no leading `-`, is composed
/// entirely of ASCII alphabetic characters all drawn from
/// [`TAR_DASHLESS_CONSUMING`]/[`TAR_DASHLESS_BOOLEAN`], and contains both
/// `x` and `C` — the specific shape the dash-less form's directory-change
/// gap needs (a bare dash-less cluster with `x` but not `C`, e.g. `tar xf
/// a.tar -C /`'s leading `xf`, is left untouched: the trailing `-C /` is
/// already a normal dashed token pair that existing matching sees on its
/// own, and rewriting `xf` too would make `tar xf a.tar -C /`'s decision
/// drift from what it gets today). A value-consuming letter with no
/// positional argument left to consume (`tar fC` alone, which also lacks
/// `x` so never reaches this case anyway) falls back to
/// [`TarDashlessCluster::NotApplicable`], unchanged for that shape.
///
/// On success, [`TarDashlessCluster::Recognized`] carries the full
/// rewritten tail: one or two synthetic tokens per cluster letter,
/// followed by every argument the cluster didn't consume, unchanged
/// (including any of *those* that are already `-`-prefixed, e.g. a
/// trailing `-P` after the cluster).
pub(crate) fn tar_dashless_cluster(tail: &[NormalizedWord]) -> TarDashlessCluster {
    let Some((first, rest)) = tail.split_first() else {
        return TarDashlessCluster::NotApplicable;
    };
    let Resolution::Resolved(cluster) = first.resolution() else {
        return TarDashlessCluster::NotApplicable;
    };
    if cluster.is_empty()
        || cluster.starts_with('-')
        || !cluster.chars().all(|c| c.is_ascii_alphabetic())
    {
        return TarDashlessCluster::NotApplicable;
    }
    if !cluster.contains('x') {
        return TarDashlessCluster::NotApplicable;
    }
    if !cluster
        .chars()
        .all(|c| TAR_DASHLESS_CONSUMING.contains(&c) || TAR_DASHLESS_BOOLEAN.contains(&c))
    {
        return TarDashlessCluster::Unmodeled;
    }
    if !cluster.contains('C') {
        return TarDashlessCluster::NotApplicable;
    }

    let mut rewritten = Vec::new();
    let mut values = rest.iter();
    for c in cluster.chars() {
        rewritten.push(NormalizedWord::resolved(format!("-{c}")));
        if TAR_DASHLESS_CONSUMING.contains(&c) {
            let Some(value) = values.next() else {
                return TarDashlessCluster::NotApplicable;
            };
            rewritten.push(value.clone());
        }
    }
    rewritten.extend(values.cloned());
    TarDashlessCluster::Recognized(rewritten)
}

/// [`FlagMatcher`]/[`TargetMatcher`]-facing wrapper over
/// [`tar_dashless_cluster`]: `Some` only for
/// [`TarDashlessCluster::Recognized`], `None` for both
/// [`TarDashlessCluster::NotApplicable`] and
/// [`TarDashlessCluster::Unmodeled`] — a per-`CommandRule` flag/target
/// match has no way to express "fail this whole command line closed to
/// Ask", so an unmodeled cluster falls through here exactly like a
/// not-applicable one; `crate::gate`'s own floor
/// (`crate::rules::tar_dashless_cluster`'s `Unmodeled` arm) is what
/// actually enforces the fail-closed Ask for that case, independent of
/// whether any particular rule's flags/targets would otherwise have
/// matched.
fn tar_dashless_rewrite(tail: &[NormalizedWord]) -> Option<Vec<NormalizedWord>> {
    match tar_dashless_cluster(tail) {
        TarDashlessCluster::Recognized(rewritten) => Some(rewritten),
        TarDashlessCluster::NotApplicable | TarDashlessCluster::Unmodeled => None,
    }
}

/// The tail a rule's flag/target checks should actually see for one
/// wrapper-chain hop: `tail` rewritten via [`tar_dashless_rewrite`] when
/// `base` is `tar`, unchanged otherwise. Shared by
/// [`CommandRule::matching_rest`] and [`CommandRule::matching_rest_by_name`]
/// (issue #86) so the two walkers can't silently diverge on this point —
/// each previously duplicated this same `if base == "tar" { ... }` block
/// verbatim.
fn tar_dashless_effective_tail<'a>(
    base: &str,
    tail: &'a [NormalizedWord],
) -> Cow<'a, [NormalizedWord]> {
    if base == "tar" {
        tar_dashless_rewrite(tail).map_or(Cow::Borrowed(tail), Cow::Owned)
    } else {
        Cow::Borrowed(tail)
    }
}

/// A flag declared (via a rule's `value_flags`, issue #48) to take a
/// value that is never itself an except_targets candidate — narrows
/// [`CommandRule::matches`]'s candidate collection so a value-taking
/// flag's own value (an output path, a format string, an exclude
/// pattern) isn't mistaken for the command's actual target. `spec` (the
/// TOML string) carries no leading `-`/`--`: a single ASCII letter is a
/// short flag (`"o"` matches the bare token `-o`), anything longer is a
/// long-option name (`"exclude"` matches the bare token `--exclude` or
/// its `--exclude=value` attached form). Undeclared flags are unaffected
/// — their value keeps counting as a candidate, same fail-closed default
/// as before this field existed.
///
/// # Known limitation
///
/// [`Self::is_bare`] matches a short flag only as a standalone token
/// (`-o`), never inside a combined cluster (`-so`, `-fso`): shape-based
/// matching can't tell which cluster position "owns" a following
/// separated argument when the cluster mixes boolean and value-taking
/// flags. A declared short flag glued into a cluster falls back to
/// today's existing candidate treatment for the token that follows it —
/// this only ever *narrows* the candidate set relative to not declaring
/// the flag at all, so it cannot turn a real target invisible via this
/// path (the cluster case just doesn't get the narrowing). A short
/// flag's attached-value form with no `=` (`-oVALUE`) is likewise never
/// recognised here, the same pre-existing gap [`target_candidate`]'s own
/// docs disclose for `-xhttp://evil.example.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ValueFlag {
    /// A single short-option letter, e.g. `Short('o')` for `-o`.
    Short(char),
    /// A long-option name without its `--` prefix, e.g. `Long("exclude"
    /// .to_string())` for `--exclude`.
    Long(String),
}

impl ValueFlag {
    /// `spec` is a single ASCII alphabetic character (short flag) or an
    /// ASCII alphanumeric/hyphen string of length > 1 (long-option name),
    /// neither carrying a leading `-`. Anything else — empty, a leading
    /// `-`, a `|`-alternative list, non-ASCII — is a load-time error.
    fn parse(spec: &str) -> Result<Self, String> {
        let mut chars = spec.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) if c.is_ascii_alphabetic() => Ok(Self::Short(c)),
            (Some(first), Some(_))
                if first.is_ascii_alphabetic()
                    && spec.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') =>
            {
                Ok(Self::Long(spec.to_string()))
            }
            _ => Err(format!(
                "invalid value_flags spec {spec:?}: expected a single letter (short flag) or \
                 an alphanumeric/hyphen long-option name, neither with a leading '-'"
            )),
        }
    }

    /// Whether `token` is this flag's own bare spelling (`-o`/`--exclude`)
    /// — a match here means the *next* argv token is this flag's
    /// separated value, not a candidate itself.
    fn is_bare(&self, token: &str) -> bool {
        match self {
            Self::Short(c) => {
                let mut chars = token.chars();
                chars.next() == Some('-') && chars.next() == Some(*c) && chars.next().is_none()
            }
            Self::Long(name) => token
                .strip_prefix("--")
                .is_some_and(|rest| rest == name.as_str()),
        }
    }

    /// Whether `token` is this flag's `--name=value` attached form (long
    /// flags only — short flags have no recognised attached-value shape,
    /// see the type docs) — a match means the whole token is excluded
    /// from candidates, not just non-a-candidate-because-it-starts-with-
    /// dash.
    fn attached_value_token(&self, token: &str) -> bool {
        match self {
            Self::Short(_) => false,
            Self::Long(name) => token
                .strip_prefix("--")
                .and_then(|rest| rest.strip_prefix(name.as_str()))
                .is_some_and(|rest| rest.starts_with('=')),
        }
    }
}

/// One alternative shape a dangerous target may take. A [`CommandRule`]'s
/// `targets` list is a set of OR'd alternatives — the rule matches if any
/// argv token satisfies any one of them (e.g. rm's target list holds `/`,
/// `/*`, `~`, and a `/dev/` prefix as separate alternatives).
///
/// [`Self::Exact`]/[`Self::Prefix`] compare raw bytes only — no path
/// normalization, by deliberate choice (issue #65): many target values
/// aren't paths at all (`dd`'s `of=` prefix, a glob like `/*`, an
/// `except_targets` URL prefix), and normalizing an `except_targets` entry
/// would silently *widen* an allow. [`Self::NormalizedExact`]/
/// [`Self::NormalizedPrefix`] are the opt-in, path-aware siblings a rule
/// author reaches for explicitly when a target genuinely is a filesystem
/// path — see [`lexical_normalize`] for the normalization algorithm and
/// [`Self::matches`] for each variant's match semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetMatcher {
    Exact(String),
    Prefix(String),
    /// Path-aware equality: the token (after an optional [`strip_target`]
    /// prefix removal) is lexically normalized and compared against a
    /// pre-normalized target [`PathForm`], plus two fail-closed widenings
    /// — see [`Self::matches`].
    NormalizedExact {
        /// A literal prefix the token must carry before the path itself
        /// begins (e.g. `"of="` for `dd`'s `of=/dev/sda`, `"-C"` for
        /// tar's attached `-C/` form) — `None` when the whole token is
        /// the path.
        strip: Option<String>,
        target: PathForm,
    },
    /// Path-aware prefix match: the token (after an optional `strip`) is
    /// lexically normalized, rendered to its canonical string form via
    /// [`canonical_render`], and compared with `starts_with` against a
    /// pre-rendered `canon` — see [`Self::matches`].
    NormalizedPrefix {
        strip: Option<String>,
        canon: String,
    },
    /// Opt-in URL-aware host match (issue #102): the token is parsed as a
    /// real URL via the `url` crate (docs/adr/0002-url-crate.md) and its
    /// *host* component — not any string prefix of the token — is
    /// compared against a pre-parsed host. Closes the userinfo-spoofing
    /// gap plain `exact`/`prefix` string matching can't:
    /// `http://localhost:pw@evil.example.com` shares a string prefix with
    /// `http://localhost:` but its real host is `evil.example.com`, which
    /// this variant correctly does NOT match. See [`Self::matches`] for
    /// the fail-closed posture on an unparseable candidate.
    UrlHost(url::Host<String>),
}

impl TargetMatcher {
    fn matches(&self, token: &str) -> bool {
        match self {
            Self::Exact(exact) => token == exact,
            Self::Prefix(prefix) => token.starts_with(prefix.as_str()),
            Self::NormalizedExact { strip, target } => {
                let Some(remainder) = strip_target(strip.as_deref(), token) else {
                    return false;
                };
                let form = lexical_normalize(remainder);
                if form == *target {
                    return true;
                }
                // Fail-closed widenings (issue #65): shguard never knows
                // the invoking shell's cwd, so a pure relative ascent
                // (`..`, `../..`, `../../../..`, …) might resolve to `/`
                // at any depth, and a `~`-anchored token that pops past
                // $HOME (`~/..`) has provably left it — even though the
                // exact resulting path (and, since issue #90, any tail
                // descended into after the escape) is unknown. No other
                // target shape widens like this — `Opaque` never matches
                // anything. The tail is deliberately ignored below: this
                // arm only fires for a rule targeting bare `~`
                // (`comps.is_empty()`), and ANY escape — regardless of
                // what follows it — is still certain to have left that
                // bare-`~` target, so narrowing this to an empty tail
                // would regress a token like `~/../../home/alice` (which
                // matches no rule's dangerous namespace, so issue #90's
                // Ask-only floor can't catch it either) from Block back to
                // Allow.
                match (target, &form) {
                    (
                        PathForm::Abs(comps),
                        PathForm::Rel {
                            ascent,
                            comps: rel_comps,
                        },
                    ) => comps.is_empty() && *ascent >= 1 && rel_comps.is_empty(),
                    (PathForm::Home(comps), PathForm::EscapesHome(_)) => comps.is_empty(),
                    _ => false,
                }
            }
            Self::NormalizedPrefix { strip, canon } => {
                let Some(remainder) = strip_target(strip.as_deref(), token) else {
                    return false;
                };
                canonical_render(&lexical_normalize(remainder))
                    .is_some_and(|rendered| rendered.starts_with(canon.as_str()))
            }
            Self::UrlHost(host) => parse_url_host(token).is_some_and(|parsed| parsed == *host),
        }
    }

    /// issue #78's Ask-only floor check: true when `token` normalizes to
    /// an unresolved ascent-then-descent shape (`Rel { ascent > 0, comps:
    /// non-empty }` — pure ascent alone is already [`Self::matches`]'s
    /// existing certain widening, untouched here) whose descended-into
    /// tail plausibly lands inside this matcher's own dangerous
    /// namespace. Forward-only (`starts_with`/exact-equality, never the
    /// reverse): a token that hasn't yet spelled out enough of the
    /// dangerous prefix (`../../dev` against `/dev/sd`) must NOT trip
    /// this — that's what keeps ordinary relative paths (`tar -C
    /// ../build`) from false-positiving, since no rule's `canon`/`target`
    /// shares a prefix with `/build`. Deliberately NOT folded into
    /// `Self::matches`: shguard has no cwd to prove the ascent actually
    /// bottoms out at the right depth, so this must only ever feed a
    /// `gate.rs` floor capped at `Ask` (see
    /// `crate::gate::scan_ascent_descent_floor`), never the matched
    /// rule's own (often stricter) decision.
    ///
    /// Since issue #90, a `~`/`~username`-anchored ascent past its anchor
    /// (`~/../../dev/sda`, `~someuser/../../../dev/sda`) is covered too:
    /// [`PathForm::EscapesHome`]/[`PathForm::NamedUserHomeEscapes`] now
    /// carry the descended-into tail the same way [`PathForm::Rel`]
    /// carries `comps`, and this check consumes either shape uniformly.
    /// The candidate-building below picks ONE rendering of that tail per
    /// call — absolute (`/`) or `~`-anchored, based solely on the
    /// matched rule's own `canon` — and applies it uniformly across all
    /// three source shapes, including the two escape shapes. In
    /// particular a `~`-anchored `canon` is NOT excluded just because the
    /// token's own source shape already escaped its anchor — even though
    /// "escaped its own anchor" sounds like it should rule out a
    /// `~`-anchored candidate, shguard cannot disprove it: `$HOME=/`
    /// degenerately collapses
    /// `~/..` back to `~` itself, and a named user's home
    /// (`~someuser`) may sit anywhere relative to the invoker's own
    /// `$HOME` (e.g. a sibling directory), so a tail that looks like it
    /// escaped could still plausibly land back under `~`. This is the
    /// same fail-closed, can't-prove-it-so-Ask-not-Block posture as the
    /// `Rel` case, not a new false-positive class.
    ///
    /// Known residual gap: this check is purely forward — it can prefix-
    /// match a tail against a rule's dangerous namespace, but can't
    /// reason about the escaped-past anchor's own *basename* reappearing
    /// mid-tail (e.g. `~alice/../bob/.config/shguard/x`, where `bob`
    /// happens to be the invoking user, would need to re-descend through
    /// a name this check has no way to know). Tracked as issue #118, not
    /// fixed here.
    ///
    /// Known gaps (not yet fixed):
    /// - This check doesn't consult a rule's `except_targets`. No
    ///   embedded rule currently pairs a `normalized`/`normalized_prefix`
    ///   target with an `except_targets` carve-out, so this is latent,
    ///   not live — but a future one would have its except-carve-out
    ///   over-floored to `Ask` by this check.
    /// - A hypothetical rule with a bare `/` or `~`
    ///   `normalized_prefix` (not currently rejected by
    ///   `reject_degenerate_normalized_target`, and no embedded rule uses
    ///   one) would blanket-floor every ascent-then-descent token — the
    ///   same latent shape `TargetMatcher::matches`'s existing
    ///   `NormalizedPrefix` already has.
    fn ascent_descent_plausible(&self, token: &str) -> bool {
        let strip = match self {
            Self::NormalizedPrefix { strip, .. } | Self::NormalizedExact { strip, .. } => strip,
            Self::Exact(_) | Self::Prefix(_) | Self::UrlHost(_) => return false,
        };
        let Some(remainder) = strip_target(strip.as_deref(), token) else {
            return false;
        };
        let comps = match lexical_normalize(remainder) {
            PathForm::Rel { ascent, comps } if ascent >= 1 => comps,
            PathForm::EscapesHome(comps) | PathForm::NamedUserHomeEscapes(comps) => comps,
            _ => return false,
        };
        if comps.is_empty() {
            return false;
        }
        match self {
            Self::NormalizedPrefix { canon, .. } => {
                let candidate = if canon.starts_with('/') {
                    abs_render(&comps)
                } else if canon.starts_with('~') {
                    format!("~/{}", comps.join("/"))
                } else {
                    return false; // degenerate canon (e.g. "."), never plausible
                };
                candidate.starts_with(canon.as_str())
            }
            Self::NormalizedExact { target, .. } => matches!(
                target,
                PathForm::Abs(target_comps) | PathForm::Home(target_comps)
                    if !target_comps.is_empty() && *target_comps == comps
            ),
            Self::Exact(_) | Self::Prefix(_) | Self::UrlHost(_) => {
                unreachable!("filtered out above")
            }
        }
    }
}

/// Renders `comps` as if it were the tail of an absolute path (`/` +
/// `comps`) — used only by [`TargetMatcher::ascent_descent_plausible`] to
/// test whether an unresolved-ascent token *could plausibly* land inside a
/// dangerous rule's own namespace, never as a real canonical rendering
/// (contrast [`canonical_render`], which stays `None` for `Rel { ascent >
/// 0, .. }` precisely because it is *not* provable).
fn abs_render(comps: &[String]) -> String {
    format!("/{}", comps.join("/"))
}

impl TargetMatcher {
    /// issue #80's Ask-only floor check: true when this matcher targets a
    /// bare `~` (`NormalizedExact { target: Home(comps), .. }` with empty
    /// `comps`, e.g. `{ normalized = "~" }`) and `token` normalizes to
    /// [`PathForm::NamedUserHome`] or [`PathForm::NamedUserHomeEscapes`].
    /// Deliberately NOT folded into [`Self::matches`]'s widening table:
    /// that table's matches inherit the rule's own (often `Block`)
    /// decision, calibrated for the *certain* bare-`~` case — but
    /// `~username` only expands to a real home directory if that account
    /// exists and is reachable, which shguard cannot verify, so this must
    /// only ever feed a `gate.rs` floor capped at `Ask` (see
    /// `crate::gate::scan_named_user_home_floor`).
    fn named_user_home_plausible(&self, token: &str) -> bool {
        let Self::NormalizedExact {
            strip,
            target: PathForm::Home(comps),
        } = self
        else {
            return false;
        };
        if !comps.is_empty() {
            return false;
        }
        let Some(remainder) = strip_target(strip.as_deref(), token) else {
            return false;
        };
        matches!(
            lexical_normalize(remainder),
            PathForm::NamedUserHome | PathForm::NamedUserHomeEscapes(_)
        )
    }

    /// issue #88's Ask-only floor check: true when this matcher declares
    /// no `strip` prefix and `token` itself normalizes to
    /// [`PathForm::DirStack`]. `~+`/`~-`/`~N` expand against
    /// `$PWD`/`$OLDPWD`/a pushd-stack entry — an anchor no [`PathForm`] a
    /// target can declare represents, so unlike
    /// [`Self::named_user_home_plausible`]/[`Self::ascent_descent_plausible`]
    /// there is no target *value* to compare against (the anchor is
    /// unbounded by construction). The correlation available here is the
    /// *slot* instead: a `strip: Some(..)` target (e.g. `dd`'s `of=`)
    /// expects an ATTACHED token (`of=/dev/sda`), and a bare
    /// `~+`/`~-`/`~N` glued after that same flag (`of=~+`) doesn't
    /// tilde-expand in the first place — a separate zsh-`magic_equal_subst`
    /// question, tracked as issue #134 — so `strip: Some(..)` targets are
    /// excluded here the same way they're excluded from ever actually
    /// matching an unattached dirstack token.
    fn dirstack_plausible(&self, token: &str) -> bool {
        let strip = match self {
            Self::NormalizedExact { strip, .. } | Self::NormalizedPrefix { strip, .. } => strip,
            Self::Exact(_) | Self::Prefix(_) | Self::UrlHost(_) => return false,
        };
        if strip.is_some() {
            return false;
        }
        matches!(lexical_normalize(token), PathForm::DirStack)
    }
}

/// Strips `prefix` (a [`TargetMatcher::NormalizedExact`]/
/// [`TargetMatcher::NormalizedPrefix`]'s optional `strip`) from `token`,
/// or returns `token` unchanged when there's nothing declared to strip.
/// `None` means `token` didn't literally carry the prefix at all — a
/// non-match, never "fall back to normalizing the whole token instead".
fn strip_target<'a>(prefix: Option<&str>, token: &'a str) -> Option<&'a str> {
    match prefix {
        Some(p) => token.strip_prefix(p),
        None => Some(token),
    }
}

/// Parses `token` as a URL and extracts its host (issue #102,
/// docs/adr/0002-url-crate.md), fail-closed: `None` on any parse failure
/// or a URL with no host component (e.g. `mailto:`/relative-path
/// schemes) — never falls back to treating the token as a string to
/// prefix-match, since that would silently reopen the exact bypass class
/// [`TargetMatcher::UrlHost`] exists to close.
///
/// Rejects `token` outright — before ever calling [`url::Url::parse`] —
/// if it contains a backslash or any [`char::is_control`] code point
/// (stricter than just bytes below `0x20`: also catches DEL and the C1
/// control range): the `url` crate implements the WHATWG URL Standard,
/// which treats `\` as equivalent to `/` for "special" schemes
/// (`http`/`https`/`ws`/`wss`/`ftp`/`file`) in some parsing states, a
/// normalization other tools (`curl`, most resolvers) do not universally
/// share. Since `except_targets` matching only ever *suppresses* a rule, a
/// parser that reports a safer host than where the command actually
/// connects is the dangerous direction — this check closes that specific
/// known differential (docs/adr/0002-url-crate.md's residual-risk
/// section), not every possible WHATWG/RFC-3986 divergence.
fn parse_url_host(token: &str) -> Option<url::Host<String>> {
    if token.contains('\\') || token.chars().any(|c| c.is_control()) {
        return None;
    }
    url::Url::parse(token)
        .ok()?
        .host()
        .map(|h| strip_trailing_dot(h.to_owned()))
}

/// Strips a single trailing `.` from a [`url::Host::Domain`] (issue #102
/// review follow-up): `evil.example.com.` is the same address as
/// `evil.example.com` to a resolver (the trailing dot denotes an explicit
/// FQDN root, not a different host), but [`url::Host`]'s `PartialEq`
/// treats them as distinct. Left unstripped, a `targets`-direction (block)
/// `url_host` rule could be evaded by appending a trailing dot to the
/// candidate; applied symmetrically to both the config-side host
/// ([`convert_target`]) and the candidate-side host ([`parse_url_host`])
/// so the comparison stays correct in both directions. `Ipv4`/`Ipv6` hosts
/// have no such textual form and pass through unchanged.
fn strip_trailing_dot(host: url::Host<String>) -> url::Host<String> {
    match host {
        url::Host::Domain(domain) => {
            url::Host::Domain(domain.strip_suffix('.').unwrap_or(&domain).to_owned())
        }
        other => other,
    }
}

/// A lexically normalized rendering of a path-shaped token (issue #65):
/// [`TargetMatcher::Exact`]/[`Prefix`]'s pure byte-level comparison lets
/// `//`, `/.`, `~/..`, `../../../..`, and similar respellings of `/`/`~`
/// slip past a rule's dangerous-target list even though a real shell would
/// treat them identically. Built by [`lexical_normalize`], which collapses
/// `.`/`//`/trailing slashes and resolves `..` against components already
/// seen in the same token — exactly what a shell does lexically, before
/// ever touching the filesystem. No filesystem access, ever:
/// `std::fs::canonicalize` would be wrong here — shguard does static/
/// offline analysis (a target path may not exist yet, e.g. inside an
/// unextracted tar archive) and never knows the invoking shell's cwd.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathForm {
    /// Anchored at `/`: `Abs(comps)` renders as `/` + `comps.join("/")`;
    /// `Abs(vec![])` is `/` itself.
    Abs(Vec<String>),
    /// Anchored at `~`/`$HOME`: `Home(comps)` renders as `~/` +
    /// `comps.join("/")`; `Home(vec![])` is `~` itself.
    Home(Vec<String>),
    /// A `~`-anchored token whose `..` popped past `$HOME` — provably
    /// outside it, even though the exact resulting path is unknown. The
    /// `Vec<String>` is the tail of components seen *after* the escape
    /// point (issue #90; mirrors [`PathForm::Rel`]'s own `comps`) — e.g.
    /// `~/../../dev/sda` is `EscapesHome(["dev", "sda"])`. Empty when
    /// nothing follows the escaping `..` (`~/../..` is `EscapesHome(
    /// vec![])`).
    EscapesHome(Vec<String>),
    /// Relative to an unknown cwd: `ascent` leading `..` components that
    /// couldn't be canceled by an earlier component in the same token,
    /// followed by `comps`. `Rel { ascent: 0, comps: vec![] }` is `.`
    /// itself — the cwd shguard starts at, never itself dangerous.
    Rel { ascent: u32, comps: Vec<String> },
    /// A `~username` token that normalizes to that user's bare home
    /// (issue #80): either exactly `~username`, or `~username/` /
    /// `~username/.` / `~username//` — anything that collapses to no
    /// remaining components, the same way `~/`/`~//` collapse to bare
    /// `Home(vec![])`. Shell-expands to that account's home directory if
    /// it exists and is reachable — neither of which shguard can verify
    /// statically. A trailing subdirectory that does NOT collapse away
    /// (`~username/data`) stays [`PathForm::Opaque`]: out of scope by
    /// design, symmetric with `Home`/`EscapesHome` only ever covering `~`
    /// itself, not an arbitrary `~/subdir`.
    NamedUserHome,
    /// A `~username/..`-shaped token whose `..` popped past that user's
    /// home — provably outside it, even though the exact resulting path
    /// is unknown (mirrors [`PathForm::EscapesHome`] for a named user
    /// rather than the invoker's own `$HOME`). Carries the post-escape
    /// tail the same way `EscapesHome` does (issue #90).
    NamedUserHomeEscapes(Vec<String>),
    /// A bare `~+`/`~-`/`~N`/`~+N`/`~-N` directory-stack shorthand (`N` one
    /// or more ASCII digits) — either exactly that, or `.`/`.`-padded
    /// equivalents (`~+/.`, `~+//`) that collapse to no remaining
    /// components, the same way `~/.`/`~username/.` collapse to their own
    /// bare forms. A real shell expands `~+`/`~-` to `$PWD`/`$OLDPWD` and
    /// `~N`-shaped forms to a numbered `pushd`/`popd` directory-stack
    /// entry (issue #88) — an arbitrary, unbounded directory shguard has
    /// no cwd or directory stack to resolve against, so this only ever
    /// feeds a `gate.rs` floor capped at `Ask`
    /// (`crate::gate::scan_dirstack_tilde_floor`), the same floor a bare,
    /// literal `$PWD`/`$OLDPWD` reference already gets via the
    /// unresolved-`$VAR` floor (rule 4) — never a rule's own (often
    /// `Block`) decision, since unlike a bare `~` every shell expands
    /// identically, whether `~+`/`~-`/`~N` denote a *specific* dangerous
    /// target can't be known statically.
    ///
    /// A subdirectory tail that does NOT collapse away (`~-/etc/passwd`,
    /// `~2/dev/sda`), or a `..` that pops past the (unknown) anchor, stays
    /// [`PathForm::Opaque`] instead — deliberately out of scope for issue
    /// #88, mirroring [`PathForm::NamedUserHome`]'s own "bare anchor only,
    /// not an arbitrary subdirectory" boundary; tracked as issue #133.
    DirStack,
    /// Matches nothing: the empty string, a `~username/subdir` token (see
    /// [`PathForm::NamedUserHome`]'s docs), or a dirstack-shaped tilde
    /// token with a non-collapsing subdirectory tail or an escaping `..`
    /// (see [`PathForm::DirStack`]'s docs — issue #133).
    Opaque,
}

/// True for `+`/`-`/`N`/`+N`/`-N` (`N` one or more ASCII digits) — bash/zsh
/// directory-stack shorthand (`~+`/`~-` expand to `$PWD`/`$OLDPWD`,
/// `~N`/`~+N`/`~-N` to a numbered pushd/popd entry), never a real account
/// name. Used by [`lexical_normalize`] to route these tokens to
/// [`PathForm::DirStack`]/[`PathForm::Opaque`] (issue #88) instead of
/// [`PathForm::NamedUserHome`]/[`NamedUserHomeEscapes`].
fn is_dirstack_shape(prefix: &str) -> bool {
    if prefix == "+" || prefix == "-" {
        return true;
    }
    let digits = prefix.strip_prefix(['+', '-']).unwrap_or(prefix);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Lexically normalizes `token` into a [`PathForm`] — see the type docs
/// for why this never touches the filesystem. Mirrors what a POSIX shell
/// does to a path lexically, before any command sees it: `.`/`//`/
/// trailing-slash segments collapse away, and a `..` cancels the nearest
/// still-pending component in the same token (`a/../b` → `b`) rather than
/// literally appearing in the output. A `..` with nothing left to cancel
/// is anchor-dependent: under `/` it's a no-op (POSIX: `/..` == `/`);
/// under `~` it proves the result has left `$HOME`
/// ([`PathForm::EscapesHome`], which keeps accumulating any components
/// that follow the escaping `..` into its own tail — issue #90); otherwise
/// (a bare relative token) it becomes one unit of unresolved ascent
/// ([`PathForm::Rel`]'s `ascent`) — shguard has no cwd to resolve it
/// against.
fn lexical_normalize(token: &str) -> PathForm {
    if token.is_empty() {
        return PathForm::Opaque;
    }
    // Only a bare `~` or a `~/`-prefixed token is `$HOME`-anchored. Any
    // other `~`-prefixed token is either a directory-stack shorthand
    // (`~+`/`~-`/`~N`/`~+N`/`~-N`, issue #88) or a `~username` tilde
    // (issue #80): a real shell takes everything up to the first `/` as
    // the account name (`getpwnam`-style — no username syntax validation,
    // so any non-empty, non-dirstack prefix counts, matching this
    // project's allowlist-over-denylist preference for the *dangerous*
    // class) and expands the rest lexically against that account's home,
    // same as `~/...` does against `$HOME`.
    if token.starts_with('~') && token != "~" && !token.starts_with("~/") {
        let rest = &token[1..];
        let (user, path_rest) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        if user.is_empty() {
            return PathForm::Opaque;
        }
        let dirstack = is_dirstack_shape(user);
        let mut stack: Vec<String> = Vec::new();
        let mut escaped = false;
        for comp in path_rest.split('/') {
            if comp.is_empty() || comp == "." {
                continue;
            }
            if comp == ".." {
                if stack.pop().is_none() {
                    escaped = true;
                }
            } else {
                // issue #90: keep accumulating into `stack` past the
                // escape point (with the same cancel-nearest `..`
                // semantics) instead of dropping the tail — it becomes
                // `NamedUserHomeEscapes`'s payload below.
                stack.push(comp.to_string());
            }
        }
        // issue #88: a dirstack-shaped `user` (`+`/`-`/`N`/`+N`/`-N`) is
        // never a real account name, so it takes this separate branch
        // rather than falling into the `NamedUserHome`/`NamedUserHomeEscapes`
        // classification below — sharing the same accumulation loop above
        // so `~+/.`/`~+//` still collapse to bare `DirStack` the same way
        // `~/.`/`~username/.` collapse to their own bare forms. A
        // non-collapsing tail or an escape stays `Opaque` (issue #133).
        if dirstack {
            return if !escaped && stack.is_empty() {
                PathForm::DirStack
            } else {
                PathForm::Opaque
            };
        }
        return if escaped {
            PathForm::NamedUserHomeEscapes(stack)
        } else if stack.is_empty() {
            PathForm::NamedUserHome
        } else {
            PathForm::Opaque
        };
    }

    enum Anchor {
        Abs,
        Home,
        Rel,
    }

    let (anchor, rest) = if let Some(rest) = token.strip_prefix('/') {
        (Anchor::Abs, rest)
    } else if token == "~" {
        (Anchor::Home, "")
    } else if let Some(rest) = token.strip_prefix("~/") {
        (Anchor::Home, rest)
    } else {
        (Anchor::Rel, token)
    };

    let mut stack: Vec<String> = Vec::new();
    let mut ascent: u32 = 0;
    let mut escaped = false;
    for comp in rest.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            if stack.pop().is_some() {
                continue;
            }
            match anchor {
                Anchor::Abs => {}
                Anchor::Home => escaped = true,
                Anchor::Rel => ascent = ascent.saturating_add(1),
            }
        } else {
            // issue #90: keep accumulating into `stack` past the escape
            // point (with the same cancel-nearest `..` semantics) instead
            // of dropping the tail — it becomes `EscapesHome`'s payload
            // below. `escaped` is only ever set for `Anchor::Home`, so
            // this is a no-op change for `Abs`/`Rel`.
            stack.push(comp.to_string());
        }
    }

    match anchor {
        Anchor::Abs => PathForm::Abs(stack),
        Anchor::Home if escaped => PathForm::EscapesHome(stack),
        Anchor::Home => PathForm::Home(stack),
        Anchor::Rel => PathForm::Rel {
            ascent,
            comps: stack,
        },
    }
}

/// The canonical string rendering of a [`PathForm`], used only by
/// [`TargetMatcher::NormalizedPrefix`]'s `starts_with` comparison — `None`
/// for any shape with no unambiguous canonical string (`EscapesHome`,
/// `Opaque`, unresolved ascent, or a relative token with named components
/// but no anchor to render from: none of those have a starting point).
fn canonical_render(form: &PathForm) -> Option<String> {
    match form {
        PathForm::Abs(comps) if comps.is_empty() => Some("/".to_string()),
        PathForm::Abs(comps) => Some(format!("/{}", comps.join("/"))),
        PathForm::Home(comps) if comps.is_empty() => Some("~".to_string()),
        PathForm::Home(comps) => Some(format!("~/{}", comps.join("/"))),
        PathForm::Rel { ascent: 0, comps } if comps.is_empty() => Some(".".to_string()),
        // issue #90: an escaped-anchor tail must NEVER render here — doing
        // so would let `NormalizedPrefix::matches` treat it as a *certain*
        // match (inheriting the rule's often-`Block` decision) instead of
        // the Ask-only floor `TargetMatcher::ascent_descent_plausible`
        // deliberately keeps it capped at.
        PathForm::EscapesHome(_) | PathForm::NamedUserHomeEscapes(_) => None,
        _ => None,
    }
}

/// A rule matching one simple command's resolved argv: a command name, a
/// set of required flags (all must be present, ANDed — though a single
/// entry may itself be a [`FlagMatcher::AnyOf`], ORing equivalent
/// spellings), a set of target matchers (any one must be hit by some
/// token, ORed — an empty list means "no target constraint", e.g.
/// `shred`'s "any target" rule), and a set of except-target matchers
/// (issue #30: the opposite direction — a candidate target that would
/// otherwise make the rule fire, but shouldn't, e.g. curl restricted to
/// non-localhost targets). See [`Self::matches`] for how the two combine.
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
    except_targets: Vec<TargetMatcher>,
    value_flags: Vec<ValueFlag>,
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

    /// Whether `rest_words` (already resolved past this rule's command
    /// name) satisfies this rule's required flags and required tokens —
    /// the constraint half of matching, factored out of
    /// [`Self::matching_rest`] so it can be evaluated once per candidate
    /// hop.
    ///
    /// `required_tokens` are matched via [`Positionals`] against the
    /// leading non-dash-prefixed tokens after the resolved command —
    /// `required_tokens[0]` must be the first positional, `[1]` the
    /// second, etc. This prevents a commit message or branch name
    /// containing "clean" or "rebase" from triggering the wrong rule.
    /// [`Positionals`]' alignment ends at the first unresolvable word,
    /// except one this rule's own `value_flags` declares as a flag's
    /// value (e.g. `-m`'s argument) rather than a positional.
    ///
    /// Known gap: `git -C <path> push` places a non-dash token (`<path>`)
    /// before the subcommand; the rule won't match in that case.
    #[must_use]
    fn constraints_match(&self, rest_words: &[NormalizedWord]) -> bool {
        let rest = resolved_strings(rest_words);
        if !self.required_flags.iter().all(|flag| flag.satisfied(&rest)) {
            return false;
        }
        let consumed = value_flag_consumed(rest_words, &self.value_flags);
        if !Positionals::new(rest_words, &consumed).confirms(&self.required_tokens) {
            return false;
        }
        true
    }

    /// Finds the hop, in `argv`'s wrapper-unwrap chain, at which this
    /// rule's command name and constraints (flags/tokens) match, and
    /// returns that hop's raw tail (its own arguments, unskipped — the
    /// natural `rest` for [`Self::matches`]' subsequent target check).
    /// `None` if no hop matches at all — the shared building block behind
    /// [`Self::matches`] (which also checks targets). PR #84 switched
    /// [`Self::matches_except_target`] to [`Self::matching_rest_by_name`]
    /// instead — that function now shares this tar-dashless-rewrite step
    /// via [`tar_dashless_effective_tail`] (issue #86), so the two helpers
    /// can't diverge on this point.
    ///
    /// Unlike a single [`effective_command`] resolution, this checks the
    /// rule at *every* hop of the chain, not just the terminal one: a rule
    /// naming a wrapper itself (`command = "doas"`) must be reachable
    /// (issues #35/#36) even though the wrapped command underneath it is
    /// what [`effective_command`] alone would resolve to. A hop whose name
    /// matches but whose constraints don't is not a match — the walk keeps
    /// going past it if it's itself a transparent wrapper, exactly like
    /// [`effective_command`]'s own walk (this is fail-closed for a
    /// deny/ask rule: more chances to match, never fewer). This is also
    /// the same resolution [`PipelineRule::matches`] already applies to
    /// pipeline sinks/sources, so a path-qualified or wrapped command
    /// (`/bin/rm`, `env rm`, `env git push --force`) cannot dodge a
    /// `command = "rm"`/`command = "git"` rule.
    ///
    /// When the resolved hop's own basename is `tar`, the tail is passed
    /// through [`tar_dashless_effective_tail`]/[`tar_dashless_rewrite`]
    /// first (issue #67): tar's own calling convention allows a fully
    /// dash-less leading option cluster (`tar xfC a.tar /`), which the
    /// generic flag matching below can't see at all (`short_cluster_chars`
    /// returns an empty set for a dash-less token). The rewrite is a no-op
    /// `Cow::Borrowed` for every other command, and for any `tar`
    /// invocation that isn't the specific dash-less `x`+`C` cluster shape
    /// the rewrite targets — see that function's docs for exactly when it
    /// fires.
    #[must_use]
    fn matching_rest<'a>(&self, argv: &'a [NormalizedWord]) -> Option<Cow<'a, [NormalizedWord]>> {
        let mut rest = argv;
        loop {
            let (first, tail) = rest.split_first()?;
            let Resolution::Resolved(name) = first.resolution() else {
                return None;
            };
            let base = basename(name);
            if self.command.matches(base) {
                let effective = tar_dashless_effective_tail(base, tail);
                if self.constraints_match(&effective) {
                    return Some(effective);
                }
            }
            if !TRANSPARENT_WRAPPERS.contains(&base) {
                return None;
            }
            rest = skip_wrapper_arguments(base, tail);
        }
    }

    /// Whether this rule matches `argv`, the normalised argv of one simple
    /// command. Matching is mechanical and shape-based, not positional: a
    /// resolved-but-empty token (a bash quoted empty, `''`) never breaks
    /// the scan, and an [`Resolution::Unresolvable`] token — including the
    /// command name itself — never matches anything.
    ///
    /// When `except_targets` is non-empty (issue #30), a match found above
    /// is suppressed if every *candidate target token* — the tokens that
    /// matched `targets` (or, when `targets` is empty, every candidate
    /// yielded by [`value_flag_free_candidates`]/[`target_candidate`],
    /// since there's no narrower candidate set to draw from) — also
    /// matches an `except_targets` alternative. This is a deliberately
    /// conservative "ALL candidates excepted", not "ANY": an "ANY" reading
    /// would let one incidental excepted token (e.g. a local source path
    /// in a mixed local/remote `rsync` invocation) suppress the whole rule
    /// even though another token is exactly what the rule guards against.
    /// Suppression never triggers when `argv`'s tail contains an
    /// [`Resolution::Unresolvable`] word — fail-closed: if a token's value
    /// can't be statically known, it's never assumed to be excepted. A
    /// rule's `value_flags` (issue #48) further narrows the `targets`-
    /// empty candidate set: a declared flag's own value (separated or
    /// `--flag=value` attached) is consumed and never becomes a candidate
    /// at all, so a value-taking flag's output path/format string/pattern
    /// can't wrongly stand in the way of "all candidates excepted" for the
    /// command's actual target. An undeclared flag's value is unaffected —
    /// it keeps counting as a candidate, today's fail-closed default.
    #[must_use]
    fn matches(&self, argv: &[NormalizedWord]) -> bool {
        let Some(rest_words) = self.matching_rest(argv) else {
            return false;
        };
        let rest = resolved_strings(&rest_words);

        let matched = if self.targets.is_empty() {
            true
        } else {
            rest.iter().any(|token| self.matches_targets(token))
        };
        if !matched || self.except_targets.is_empty() {
            return matched;
        }

        // An unresolvable word anywhere in the tail means the actual
        // target set can't be fully enumerated, so it can never be proven
        // "all excepted" — keep the match rather than risk a silent bypass.
        let has_unresolvable = rest_words
            .iter()
            .any(|w| matches!(w.resolution(), Resolution::Unresolvable(_)));
        if has_unresolvable {
            return true;
        }

        let candidates: Vec<&str> = if self.targets.is_empty() {
            value_flag_free_candidates(&rest, &self.value_flags)
        } else {
            rest.iter()
                .filter(|token| self.matches_targets(token))
                .copied()
                .collect()
        };
        let all_excepted = !candidates.is_empty()
            && candidates
                .iter()
                .all(|token| self.except_targets.iter().any(|e| e.matches(token)));
        !all_excepted
    }

    #[must_use]
    fn matches_targets(&self, token: &str) -> bool {
        self.targets.iter().any(|t| t.matches(token))
    }

    /// Partial-match probe for the structural gate (plan.md §4 NEW rule,
    /// `src/gate.rs`): `true` when this rule's command matches `argv`, this
    /// rule *has* a target constraint (an empty `targets` list means "any
    /// target" and is already a full match via [`Self::matches`] — nothing
    /// left to refine), and `argv` contains at least one unresolvable word
    /// — so the target itself could not be statically checked and might be
    /// exactly the value this rule guards against. This kind-agnostic "any
    /// unresolvable word" check covers both a bare `$VAR` (`rm -rf $HOME`)
    /// and a `$()`/backtick substitution in target position (`rm -rf
    /// $(echo /)`, issue #34) — both normalise to a
    /// [`Resolution::Unresolvable`] word, so no substitution-specific
    /// handling is needed here.
    ///
    /// This is a "would this be dangerous if the target were known" probe,
    /// never a match on its own: the gate uses it only to route an
    /// otherwise-Allow argument-position bare `$VAR` or substitution to
    /// Ask, never to Block — an unresolvable target must never silently
    /// upgrade to a rule hit here.
    ///
    /// # Required flags/tokens: strict or relaxed (issue #77 follow-up)
    ///
    /// The ordinary, strict shape is [`Self::constraints_match`] holding
    /// outright — flags/tokens already resolve-and-match, only the target
    /// is ambiguous (`rm -rf $HOME`). But a required flag can itself be
    /// hidden inside the SAME unresolvable word as (or a sibling brace
    /// alternative to) the target — `rm{,$IFS-rf$IFS/$(evil)}`'s leftover
    /// branch, or plain `sed -i$(true) ~/.config/shguard/config.toml` —
    /// in which case `constraints_match` can never succeed (the flag is
    /// never a *resolved* token at all) even though the danger is exactly
    /// as real. When `constraints_match` fails, this falls back to the
    /// same coarse relaxation [`Self::matches_except_flags`] already
    /// applies to flags-only rules — an unresolvable word could plausibly
    /// BE the missing flag — but narrowed to only fire when a resolved
    /// token already matches this rule's own `targets` pattern (via
    /// [`Self::matches_targets`]): without that narrowing, ANY unresolvable
    /// argument to this rule's command (`rm some-backup-$(date).tar.gz`,
    /// no `-rf` in sight) would float to `Ask` regardless of whether the
    /// target looks remotely dangerous, which the pre-fix behavior never
    /// did and this fix must not introduce either.
    ///
    /// # A third case: flag AND target both hidden together (issue #85)
    ///
    /// The two relaxations above both assume at least ONE resolved token
    /// survives in the tail to check something against (flags via
    /// `constraints_match`, or the target via `matches_targets`). Neither
    /// fires when a required flag and the target are hidden inside the
    /// SAME unresolvable word (`sed $(echo -i ~/.config/shguard/config.toml)`)
    /// or a pair of sibling ones (`sed $(printf -- -i) $(printf
    /// ~/.config/shguard/config.toml)`) — there is no resolved token left
    /// to check either constraint against. This branch closes that gap:
    /// when the ENTIRE tail is unresolvable — not merely "some unresolvable
    /// word exists" — that's still plausibly this rule's own dangerous
    /// shape. A rule with neither `required_flags` nor `required_tokens`
    /// (a bare-target rule) never reaches this branch at all: relaxation #1
    /// (`constraints_match`, above) is vacuously true for it regardless of
    /// any resolved content, so it always returns at that earlier `if`
    /// first — this branch is reachable only for a rule that DOES declare a
    /// flag/token constraint, with no separate check needed for that here.
    /// Requiring the WHOLE tail to be opaque, not just `has_unresolvable`
    /// (already required above), is deliberate: a resolved token elsewhere
    /// in the tail is not proof the rule's own danger is absent (see the
    /// residual gap below), but at least one rule shape — sed, whose first
    /// non-option operand is its edit script, not a target — has resolved
    /// content that's part of neither the flag nor the target and must not
    /// by itself defeat this relaxation.
    ///
    /// Blast radius beyond the motivating example (mirrors
    /// [`Self::matches_except_flags`]'s own documented trade-off for
    /// `git-no-verify-any-subcommand`, which floors EVERY `git` invocation
    /// containing an unresolvable word — no per-command semantics, module
    /// docs): any `sed` invocation whose entire tail is a single
    /// unresolvable word floors to `Ask` via `self-protect-config-sed-tilde`,
    /// regardless of any actual connection to shguard's config path — e.g.
    /// `sed $(cat unrelated-script)`. Narrower than that `git` case (only
    /// an all-opaque tail counts, not "any unresolvable word anywhere") and
    /// Ask-only, never Block, same as every relaxation in this function —
    /// an accepted, intentional trade-off, not an oversight.
    ///
    /// Known residual gap (not fixed here): a decoy resolved token can
    /// still defeat this branch even when the danger is real and
    /// exploitable. GNU `sed`
    /// permutes options after operands (POSIX getopt-style), so `sed
    /// 's/a/b/' $(echo -i ~/.config/shguard/config.toml)` still performs
    /// the in-place edit at runtime — but its tail has ONE resolved token
    /// (`'s/a/b/'`), so this branch stays silent for it. Closing this fully
    /// needs sed-specific positional semantics (which operand is the
    /// script vs. a file), not a generic flag/target check — tracked as
    /// issue #117 rather than folded into this fix, which stays a
    /// command-agnostic relaxation like its two siblings above.
    #[must_use]
    pub(crate) fn matches_except_target(&self, argv: &[NormalizedWord]) -> bool {
        if self.targets.is_empty() {
            return false;
        }
        let Some(rest_words) = self.matching_rest_by_name(argv) else {
            return false;
        };
        let has_unresolvable = rest_words
            .iter()
            .any(|w| matches!(w.resolution(), Resolution::Unresolvable(_)));
        if !has_unresolvable || !self.relaxed_required_tokens_match(&rest_words) {
            return false;
        }
        if self.constraints_match(&rest_words) {
            return true;
        }
        if resolved_strings(&rest_words)
            .iter()
            .any(|token| self.matches_targets(token))
        {
            return true;
        }
        rest_words
            .iter()
            .all(|w| matches!(w.resolution(), Resolution::Unresolvable(_)))
    }

    /// Same wrapper-unwrap walk as [`Self::matching_rest`], but stopping at
    /// the first hop whose command name alone matches `self.command` —
    /// ignoring `required_flags`/`required_tokens` entirely. The shared
    /// building block behind [`Self::matches_except_flags`] (issue #42) and
    /// [`Self::matches_except_target`] (issue #86, since PR #84), both of
    /// which need a hop's tail *before* deciding whether flags/tokens are
    /// satisfied, unlike [`Self::matching_rest`], which only ever returns a
    /// hop once both the name and the constraints already hold.
    ///
    /// Applies [`tar_dashless_effective_tail`] to the returned tail — the
    /// same helper [`Self::matching_rest`] uses (issue #86), so the two
    /// walkers can't diverge on this point. Without it, a dash-less
    /// leading option cluster (`tar xfC a.tar /`) is invisible to
    /// [`Self::matches_except_target`]/[`Self::matches_except_flags`]'s own
    /// flag/token checks, even though the ordinary [`Self::matches`] path
    /// (via [`Self::matching_rest`]) already sees it — for
    /// `matches_except_target`, this silently dropped a rule's own match
    /// entirely for a dashless-cluster command, leaving only a coarser
    /// sibling rule's reason string to attribute the `Ask` to (issue #86's
    /// own repro: `tar xfC a.tar $(echo /)` loses
    /// `tar-extract-over-root-or-home`'s accurate reason, keeping only
    /// `tar-absolute-names-ask`'s, which names a flag this command doesn't
    /// have). For `matches_except_flags`, the missing rewrite only ever
    /// made `constraints_match` fail *more* often than it should (never
    /// less), which can only make `matches_except_flags` fire *more*
    /// broadly than intended — never miss a rule the way
    /// `matches_except_target` did — but left the same "resolved words
    /// alone already satisfy this rule" invariant its own docs promise
    /// (`Self::matches_except_flags`) unenforced for a dashless-cluster
    /// tar command whose flags happen to already be fully resolved.
    ///
    /// # Known latent divergence from `matching_rest`
    ///
    /// [`Self::matching_rest`] keeps walking past a hop whose name matches
    /// but whose constraints don't, as long as that hop's own base name is
    /// itself a [`TRANSPARENT_WRAPPERS`] member (e.g. a rule naming `sudo`
    /// as its `command`, reached through `env sudo ...`) — the deeper hop
    /// underneath might still satisfy the rule. This function stops at the
    /// first name match unconditionally, so for such a rule it would
    /// return the wrapper's own tail rather than continuing to unwrap.
    /// Currently unreachable — no rule in `rules/blocklist.toml` names a
    /// `TRANSPARENT_WRAPPERS` entry as its `command` — but a future rule
    /// that does would need this function taught the same continue-past-
    /// a-wrapper behavior.
    #[must_use]
    fn matching_rest_by_name<'a>(
        &self,
        argv: &'a [NormalizedWord],
    ) -> Option<Cow<'a, [NormalizedWord]>> {
        let mut rest = argv;
        loop {
            let (first, tail) = rest.split_first()?;
            let Resolution::Resolved(name) = first.resolution() else {
                return None;
            };
            let base = basename(name);
            if self.command.matches(base) {
                return Some(tar_dashless_effective_tail(base, tail));
            }
            if !TRANSPARENT_WRAPPERS.contains(&base) {
                return None;
            }
            rest = skip_wrapper_arguments(base, tail);
        }
    }

    /// Whether `self.required_tokens` could plausibly be satisfied by
    /// `rest_words` if every unresolvable word in it were replaced by some
    /// (unknown) concrete string — [`Self::matches_except_flags`]'s
    /// positional discipline, mirroring [`Self::constraints_match`]'s own
    /// positional matching for `required_tokens` (resolved, non-dash-
    /// prefixed tokens only, in order).
    ///
    /// A resolved, non-dash-prefixed word at slot `i` that does not equal
    /// `required_tokens[i]` proves the miss is real — the mismatch sits in
    /// the aligned prefix, before any unresolvable word, so nothing past it
    /// can rescue it — so this returns `false` immediately rather than
    /// treating every command sharing this rule's command name as ambiguous
    /// (e.g. `git commit -m $(echo hi)` must not float to `Ask` under
    /// `git-push-force`'s rule just because "commit" isn't "push"). A
    /// missing slot is rescuable only when alignment stopped early on an
    /// unresolvable word ([`Positionals::cannot_rule_out`]) — a slot missing
    /// from a fully-resolved sequence is a proven absence, not an unknown.
    #[must_use]
    fn relaxed_required_tokens_match(&self, rest_words: &[NormalizedWord]) -> bool {
        let consumed = value_flag_consumed(rest_words, &self.value_flags);
        Positionals::new(rest_words, &consumed).cannot_rule_out(&self.required_tokens)
    }

    /// Partial-match probe for the structural gate's flags/tokens floor
    /// (issue #42, `src/gate.rs`): the counterpart to
    /// [`Self::matches_except_target`] for a rule with no target
    /// constraint at all (`targets` empty) — `find-delete`, `truncate-zero`,
    /// `git-push-force`, and similar rules in `rules/blocklist.toml`, where
    /// the danger IS the flag/token, not a target. `true` when this rule's
    /// command name is reached through the wrapper chain, the rule declares
    /// at least one `required_flags`/`required_tokens` constraint (a rule
    /// with neither already matches on command name alone via
    /// [`Self::matches`] — nothing left to refine), that constraint is
    /// NOT satisfied by `argv`'s resolved words alone, and an unresolvable
    /// word could plausibly be exactly the missing piece (`find . $(echo
    /// -delete)`, `truncate $(echo -s) 0 file.db`, `git push $(echo
    /// --force) origin main`).
    ///
    /// Like [`Self::matches_except_target`], this is a "would this be
    /// dangerous if the flag/token were known" probe, never a match on its
    /// own: the gate uses it only to route an otherwise-Allow command to
    /// `Ask`, never to `Block`. A rule already fully satisfied by resolved
    /// words alone is [`Self::matches`]'s job, not this one's — this
    /// returns `false` in that case so the two floors never double-count.
    ///
    /// # Blast radius beyond the motivating examples
    ///
    /// `required_flags` has no positional discipline to apply (flags are
    /// presence-matched anywhere in the tail, never positionally, even in
    /// [`Self::constraints_match`]'s own strict matching), so this floor
    /// degrades to "any unresolvable word anywhere in the tail" for that
    /// half of a rule's constraints — same as [`Self::matches_except_target`]'s
    /// own target-ambiguity check. Combined with [`Self::relaxed_required_tokens_match`]
    /// trivially returning `true` when a rule has no `required_tokens` at
    /// all, a rule like `git-no-verify-any-subcommand` (`required_flags =
    /// ["--no-verify"]`, no `required_tokens`) floors EVERY `git`
    /// invocation containing an unresolvable word to `Ask`, regardless of
    /// subcommand — not just the `find-delete`/`truncate-zero`/
    /// `git-push-force` shapes this rule was written against. That is the
    /// intended fail-closed consequence of having no positional
    /// information to rule anything out (no per-command semantics, module
    /// docs), not an oversight — see
    /// `matches_except_flags_no_required_tokens_rule_fires_regardless_of_subcommand`
    /// below for a pinned example.
    #[must_use]
    pub(crate) fn matches_except_flags(&self, argv: &[NormalizedWord]) -> bool {
        if !self.targets.is_empty()
            || (self.required_flags.is_empty() && self.required_tokens.is_empty())
        {
            return false;
        }
        let Some(rest_words) = self.matching_rest_by_name(argv) else {
            return false;
        };
        if self.constraints_match(&rest_words) {
            return false;
        }
        let has_unresolvable = rest_words
            .iter()
            .zip(value_flag_consumed(&rest_words, &self.value_flags))
            .any(|(w, consumed)| {
                !consumed && matches!(w.resolution(), Resolution::Unresolvable(_))
            });
        has_unresolvable && self.relaxed_required_tokens_match(&rest_words)
    }

    /// issue #78: true when this rule's command+flags match `argv` (via
    /// [`Self::matching_rest`], the same full constraint check
    /// [`Self::matches`] uses) and some resolved tail token normalizes to
    /// an unresolved ascent-then-descent shape that plausibly lands
    /// inside one of this rule's own `NormalizedPrefix`/`NormalizedExact`
    /// targets. Read-only probe, same shape as
    /// [`Self::matches_except_target`]/[`Self::matches_except_flags`] —
    /// never itself a match, only a `gate.rs` floor's input (see
    /// `crate::gate::scan_ascent_descent_floor`).
    #[must_use]
    pub(crate) fn matches_ascent_descent_floor(&self, argv: &[NormalizedWord]) -> bool {
        if self.targets.is_empty() {
            return false;
        }
        let Some(rest_words) = self.matching_rest(argv) else {
            return false;
        };
        resolved_strings(&rest_words).iter().any(|token| {
            self.targets
                .iter()
                .any(|t| t.ascent_descent_plausible(token))
        })
    }

    /// issue #80: true when this rule's command+flags match `argv` (via
    /// [`Self::matching_rest`], the same full constraint check
    /// [`Self::matches`] uses) and some resolved tail token is a
    /// `~username` shorthand that would hit one of this rule's own
    /// bare-`~` targets if it expanded. Read-only probe, same shape as
    /// [`Self::matches_except_target`]/[`Self::matches_except_flags`] —
    /// never itself a match, only a `gate.rs` floor's input (see
    /// `crate::gate::scan_named_user_home_floor`).
    #[must_use]
    pub(crate) fn matches_named_user_home_floor(&self, argv: &[NormalizedWord]) -> bool {
        if self.targets.is_empty() {
            return false;
        }
        let Some(rest_words) = self.matching_rest(argv) else {
            return false;
        };
        resolved_strings(&rest_words).iter().any(|token| {
            self.targets
                .iter()
                .any(|t| t.named_user_home_plausible(token))
        })
    }

    /// issue #88: true when this rule's command+flags match `argv` (via
    /// [`Self::matching_rest`], the same full constraint check
    /// [`Self::matches`] uses) and some resolved tail token is a
    /// directory-stack tilde shorthand (`~+`/`~-`/`~N`/`~+N`/`~-N`,
    /// [`PathForm::DirStack`]) that could plausibly occupy one of this
    /// rule's own `targets`' slots ([`TargetMatcher::dirstack_plausible`]).
    /// Read-only probe, same shape as
    /// [`Self::matches_except_target`]/[`Self::matches_except_flags`] —
    /// never itself a match, only a `gate.rs` floor's input (see
    /// `crate::gate::scan_dirstack_tilde_floor`).
    ///
    /// Same slot-correlation shape as
    /// [`Self::matches_named_user_home_floor`]/
    /// [`Self::matches_ascent_descent_floor`], but without their target
    /// *value* comparison: `~+`/`~-`/`~N` expand against
    /// `$PWD`/`$OLDPWD`/a pushd-stack entry, an anchor no [`PathForm`] a
    /// target can declare represents, so there is nothing about a
    /// specific target's own value to check — only whether the target's
    /// slot (`strip: None`, i.e. accepts a bare, unattached token) could
    /// even receive one. `self.targets.is_empty()` is still excluded: a
    /// rule with no target constraint already matches unconditionally via
    /// [`Self::matches`], so there is nothing for this floor to add.
    #[must_use]
    pub(crate) fn matches_dirstack_tilde_floor(&self, argv: &[NormalizedWord]) -> bool {
        if self.targets.is_empty() {
            return false;
        }
        let Some(rest_words) = self.matching_rest(argv) else {
            return false;
        };
        resolved_strings(&rest_words)
            .iter()
            .any(|token| self.targets.iter().any(|t| t.dirstack_plausible(token)))
    }

    /// issue #115: true when this rule's command+flags match `argv` (via
    /// [`Self::matching_rest`], the same full constraint check
    /// [`Self::matches`] uses), this rule ALSO declares a bare-`~` target
    /// (`NormalizedExact { target: PathForm::Home(comps), .. }` with empty
    /// `comps`) among its own `targets`, and some resolved tail token
    /// attaches a tilde directly after an `=`-terminated `strip` prefix
    /// this SAME rule already declares elsewhere in `targets` (e.g.
    /// `--directory=~`, `--directory=~alice`) in a shape that would hit
    /// that bare-`~` target if it expanded.
    ///
    /// zsh's `magic_equal_subst` option (off by default) extends tilde/
    /// parameter expansion to any `word=value`-shaped argument, not just a
    /// genuine variable assignment — so under that option, `--directory=~`
    /// DOES tilde-expand (verified live against zsh 5.9), unlike the
    /// universal-across-shells bare-`~`-as-its-own-word case
    /// [`Self::matches`]'s own widening already treats as certain. `-C~`
    /// (no `=`) is unaffected — `magic_equal_subst` only ever matches an
    /// `=`-shaped word — so only `strip` values ending in `=` are eligible
    /// attach prefixes here. Deliberately NOT added directly to `targets`:
    /// doing so would make `Self::matches`'s exact-equality widening
    /// hard-match the bare-tilde case too, reintroducing the false
    /// positive the original design excluded `-C~`/`--directory=~` for
    /// (most shells never expand this at all). Scoped by what the rule
    /// itself already declares in `targets` (an existing `=`-terminated
    /// `strip` entry, an existing bare-`~` target) rather than a
    /// hardcoded flag string, so this generalizes to any future rule with
    /// the same shape with no Rust change. Read-only probe, same shape as
    /// [`Self::matches_named_user_home_floor`] — never itself a match,
    /// only a `gate.rs` floor's input (see
    /// `crate::gate::scan_directory_equals_tilde_floor`).
    #[must_use]
    pub(crate) fn matches_directory_equals_tilde_floor(&self, argv: &[NormalizedWord]) -> bool {
        if self.targets.is_empty() {
            return false;
        }
        let has_bare_tilde_target = self.targets.iter().any(|t| {
            matches!(
                t,
                TargetMatcher::NormalizedExact {
                    target: PathForm::Home(comps),
                    ..
                } if comps.is_empty()
            )
        });
        if !has_bare_tilde_target {
            return false;
        }
        let attach_prefixes: Vec<&str> = self
            .targets
            .iter()
            .filter_map(|t| match t {
                TargetMatcher::NormalizedExact {
                    strip: Some(strip), ..
                }
                | TargetMatcher::NormalizedPrefix {
                    strip: Some(strip), ..
                } if strip.ends_with('=') => Some(strip.as_str()),
                _ => None,
            })
            .collect();
        if attach_prefixes.is_empty() {
            return false;
        }
        let Some(rest_words) = self.matching_rest(argv) else {
            return false;
        };
        resolved_strings(&rest_words).iter().any(|token| {
            attach_prefixes.iter().any(|prefix| {
                token
                    .strip_prefix(*prefix)
                    .is_some_and(tilde_reachable_via_magic_equal_subst)
            })
        })
    }
}

/// Whether `remainder` (a token's content after stripping an `=`-
/// terminated flag prefix, e.g. `--directory=`) is a shape that would hit
/// a bare-`~` target if zsh's `magic_equal_subst` option expanded it
/// (issue #115) — exactly the forms that would hit that target if the
/// token were instead its own separate, unattached word: [`PathForm::Home`]
/// (empty comps) and [`PathForm::EscapesHome`] both hard-match there via
/// [`TargetMatcher::matches`]'s own widening (issues #65/#90);
/// [`PathForm::NamedUserHome`]/[`PathForm::NamedUserHomeEscapes`] instead
/// float via the existing named-user floor (issue #80,
/// [`TargetMatcher::named_user_home_plausible`]). The separate question of whether
/// the token even expands at all, glued to a flag like this, is
/// [`CommandRule::matches_directory_equals_tilde_floor`]'s own job (shell/
/// option-dependent, never provable) — this function only answers "what
/// would it expand to if it did."
///
/// Deliberately does NOT recognize [`PathForm::DirStack`] (issue #88, e.g.
/// `--directory=~+`): unlike `NamedUserHome`/`EscapesHome`, which expand
/// against the SAME anchor (`$HOME`) this function's caller already
/// requires the rule to have a bare-`~` target for, `~+`/`~-`/`~N` expand
/// to `$PWD`/`$OLDPWD`/a dirstack entry — a fundamentally different,
/// unrelated anchor. Folding it in here would produce a floor whose
/// reported reason ("would hit this rule's bare-`~` target") is not
/// actually true for a `$PWD`/`$OLDPWD`-anchored token. Tracked as a
/// follow-up (issue #134) rather than a same-shape widening here.
fn tilde_reachable_via_magic_equal_subst(remainder: &str) -> bool {
    match lexical_normalize(remainder) {
        PathForm::Home(comps) => comps.is_empty(),
        PathForm::EscapesHome(_) | PathForm::NamedUserHome | PathForm::NamedUserHomeEscapes(_) => {
            true
        }
        _ => false,
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
    /// this rule.
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

/// The positional (non-dash-prefixed) words of a tail, aligned only up to
/// the first unresolvable word — [`CommandRule::constraints_match`] and
/// [`CommandRule::relaxed_required_tokens_match`]'s shared positional
/// arithmetic (issue #149). Unlike [`resolved_strings`], an unresolvable
/// word is not skipped past: skipping it would left-shift every later
/// index, letting a resolved word downstream of an unknown one masquerade
/// as an earlier positional it never was ([`resolved_strings`]'s doc names
/// this as exactly the reasoning that doesn't hold once a matcher goes
/// positional). Stopping at the first unresolvable word instead keeps
/// `aligned`'s indices sound for everything before it, at the cost of
/// knowing nothing about anything after it. Exception: a word already
/// consumed as this rule's own declared value-flag's value (see
/// [`Self::new`]) is skipped rather than stopping alignment.
struct Positionals<'a> {
    /// The non-dash-prefixed words up to (and not including) the first
    /// unresolvable word, in order. Indices into this slice are the real
    /// positional indices — sound because nothing before the first
    /// unresolvable word could have been shifted by one being dropped.
    aligned: Vec<&'a str>,
    /// `false` when alignment stopped early because of an unresolvable
    /// word; `true` when the whole tail was resolved and `aligned` is the
    /// complete positional list.
    complete: bool,
}

impl<'a> Positionals<'a> {
    /// `consumed[i]` marks that `words[i]` is a declared `value_flags`
    /// entry's value (from [`value_flag_consumed`]), not a positional in
    /// its own right — a consumed *unresolvable* word is skipped rather
    /// than stopping alignment, since the rule's own `value_flags`
    /// declaration already says this slot isn't a positional, so treating
    /// it as transparent costs no soundness. A consumed *resolved* word
    /// still goes through the ordinary dash-prefix check unchanged.
    fn new(words: &'a [NormalizedWord], consumed: &[bool]) -> Self {
        let mut aligned = Vec::new();
        let mut complete = true;
        for (word, &is_consumed) in words.iter().zip(consumed) {
            match word.resolution() {
                Resolution::Resolved(s) if !s.starts_with('-') => aligned.push(s.as_str()),
                Resolution::Resolved(_) => {} // dash-prefixed flag: not a positional, keep scanning
                Resolution::Unresolvable(_) if is_consumed => {}
                Resolution::Unresolvable(_) => {
                    complete = false;
                    break;
                }
            }
        }
        Self { aligned, complete }
    }

    /// Strict: can we PROVE required tokens are present, in order, in the
    /// resolved prefix? Ignoring `complete` here is INTENTIONAL: `aligned`
    /// only ever contains words before the first unresolvable word, so a
    /// later unresolvable word can never disturb an already-matched
    /// prefix's indices (constraints_match's use case).
    fn confirms(&self, required: &[String]) -> bool {
        required
            .iter()
            .enumerate()
            .all(|(i, tok)| self.aligned.get(i).is_some_and(|p| *p == tok.as_str()))
    }

    /// Floor: can we fail to RULE OUT required tokens? A resolved slot that
    /// mismatches is a proven miss (real text, checked). A missing slot is
    /// rescuable only if we stopped early on an unresolvable word
    /// (`!complete`) — if the sequence was fully resolved with no
    /// unresolvable word at all, a missing slot means the token position
    /// genuinely doesn't exist (relaxed_required_tokens_match's use case).
    fn cannot_rule_out(&self, required: &[String]) -> bool {
        required
            .iter()
            .enumerate()
            .all(|(i, tok)| match self.aligned.get(i) {
                Some(p) => *p == tok.as_str(),
                None => !self.complete,
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

/// The candidate target value `token` carries, if any — used by
/// [`CommandRule::matches`]'s `except_targets` check (issue #30) when a
/// rule has no `targets` list to draw its candidate set from. A token not
/// starting with `-` is itself the candidate (an ordinary positional
/// argument). A `--flag=value` token (GNU long-option convention, the same
/// shape [`FlagMatcher::Token`] already recognises) carries its candidate
/// in `value`, not the token as a whole — a target passed as `--url=`'s
/// attached value must not silently escape the except-check just because
/// the containing token starts with `-`: excluding every `-`-prefixed
/// token wholesale would let `curl http://localhost
/// --url=https://evil.example.com` wrongly suppress the rule without the
/// dangerous target ever being examined. A bare flag (`-s`, `--verbose`,
/// a short cluster) yields no candidate.
///
/// # Known limitation — NOT merely cosmetic
///
/// A single-dash token with an attached value and no `=` separator
/// (curl's `-xhttp://evil.example.com`, its short-flag proxy syntax)
/// yields no candidate at all: this function has no way to tell that
/// shape apart from an ordinary combined short-flag cluster (`-sSL`)
/// using only the token's own text — this module has no per-command
/// flag-arity table by design (shape-based matching only, no regex, no
/// command-specific semantics, module docs). Unlike
/// [`skip_wrapper_arguments`]'s documented gap (which can only ever
/// *under-resolve* which inner rule would have blocked, never turn a
/// floor into a silent Allow), this gap really can let except_targets
/// suppress a rule it shouldn't: `curl http://localhost
/// -xhttp://evil.example.com` (or `-sxhttp://evil.example.com`) is wrongly
/// suppressed on a rule whose except_targets are all localhost prefixes —
/// the excepted `http://localhost` positional is the only *recognised*
/// candidate, so "all candidates excepted" holds vacuously while the
/// unexamined proxy target does the actual damage. Deliberately not
/// "fixed" by treating every multi-character single-dash token as a
/// candidate: that would make ordinary flag clusters like `-fsSL` fail
/// to except (since they'd never match an `except_targets` path/URL
/// shape either), defeating the feature for exactly the common case it
/// exists to serve. Not reachable by the `targets`-non-empty branch,
/// which draws its candidates from `targets` matches instead of this
/// function. Anyone gating a command with this attached-value flag idiom
/// should additionally forbid the flag via `required_flags`/a separate
/// `deny` entry rather than relying on `except_targets` alone.
fn target_candidate(token: &str) -> Option<&str> {
    if !token.starts_with('-') {
        return Some(token);
    }
    token
        .strip_prefix("--")?
        .split_once('=')
        .map(|(_, value)| value)
}

/// The except_targets candidate set drawn from `rest` (already-resolved
/// argv tail) with each declared `value_flags` entry's value consumed and
/// excluded (issue #48) — a single left-to-right positional walk, only
/// ever reached once the caller ([`CommandRule::matches`]) has already
/// confirmed no token in the tail is unresolvable, so every token here is
/// a known, concrete string. A token matching a declared flag's bare
/// spelling (`-o`, `--exclude`) consumes the *next* token as that flag's
/// separated value — neither token becomes a candidate. A token matching
/// a declared long flag's `--name=value` attached form is excluded
/// outright — its value never becomes a candidate either. Everything
/// else falls through to [`target_candidate`], unchanged from before this
/// field existed. An undeclared flag's value is untouched by any of this
/// and keeps counting as a candidate — the existing fail-closed default.
///
/// A bare `--` token (the POSIX/GNU end-of-options terminator, not itself
/// consumed as a preceding flag's separated value) permanently turns off
/// `value_flags` matching for every token after it: everything from that
/// point on is an ordinary positional argument by shell convention, so a
/// value carrying the same text as a declared flag name (`rsync ./src/
/// ./dst/ -- --exclude remote:evil`, where `--exclude`/`remote:evil` are
/// literal filenames, not the `--exclude` flag) must not be mistaken for
/// the flag and consumed — that would silently remove a genuine
/// (non-excepted) target from the candidate set. Regression-tested by
/// `value_flags_does_not_consume_positionals_after_end_of_options_terminator`
/// below.
fn value_flag_free_candidates<'a>(rest: &[&'a str], value_flags: &[ValueFlag]) -> Vec<&'a str> {
    let mut candidates = Vec::new();
    let mut skip_next = false;
    let mut past_terminator = false;
    for token in rest {
        if skip_next {
            skip_next = false;
            continue;
        }
        if !past_terminator {
            if *token == "--" {
                past_terminator = true;
                continue;
            }
            if value_flags.iter().any(|vf| vf.is_bare(token)) {
                skip_next = true;
                continue;
            }
            if value_flags.iter().any(|vf| vf.attached_value_token(token)) {
                continue;
            }
        }
        if let Some(candidate) = target_candidate(token) {
            candidates.push(candidate);
        }
    }
    candidates
}

/// `rest_words`, one `bool` per word, marking each word consumed as a
/// declared `value_flags` entry's separated value (issue #146) — the
/// counterpart to [`value_flag_free_candidates`] for
/// [`CommandRule::matches_except_flags`]'s "could this unresolvable word
/// plausibly be the missing required flag/token" floor. Unlike that
/// function's precondition, some words here may themselves be unresolvable
/// (that's the floor's whole reason for existing), so this walks
/// [`NormalizedWord`]s directly instead of pre-resolved `&str`s, and only
/// needs to know *whether* a word is consumed, not render a candidate list.
///
/// A word is consumed when the immediately preceding word is **resolved**
/// and matches a declared flag's bare spelling (`-m`, never a cluster or
/// attached-value form — same shape and same known limitations as
/// [`ValueFlag`]'s own docs); a resolved literal `--` permanently turns off
/// consumption for every word after it, mirroring
/// [`value_flag_free_candidates`]'s own terminator handling. An
/// unresolvable word can never itself be recognised as a declared flag's
/// bare spelling — its text is unknown by construction — so it never
/// triggers consumption of the word after it, only ever gets consumed
/// itself.
///
/// **The word being consumed must itself be
/// [`NormalizedWord::is_single_word`] (issue #146's own follow-up regression,
/// tracked at GitHub issue #149)** — otherwise this function would
/// mistakenly treat an *unquoted* expansion (`git commit -m $(evil)`) the
/// same as a *quoted* one (`git commit -m "$(evil)"`): bash word-splits an
/// unquoted expansion's unknown runtime value, so it can silently smuggle
/// in an entirely different, dangerous word right after the declared
/// flag's "value" — e.g. `-m $(printf "x --no-verify")` actually runs as
/// `-m x --no-verify`, and a value-flags declaration that blindly excluded
/// this position from candidacy would let the real `--no-verify` sail
/// through unnoticed. A quoted expansion carries no such risk (bash never
/// splits inside double quotes), which is exactly what
/// `is_single_word` distinguishes. A word failing this check is simply left
/// unmarked (`consumed[i]` stays `false`) — it keeps floating as an
/// ordinary unresolvable candidate, exactly as if no `value_flags` entry
/// had matched at all (the pre-issue-#146 behavior, correctly conservative).
fn value_flag_consumed(rest_words: &[NormalizedWord], value_flags: &[ValueFlag]) -> Vec<bool> {
    let mut consumed = vec![false; rest_words.len()];
    let mut skip_next = false;
    let mut past_terminator = false;
    for (i, word) in rest_words.iter().enumerate() {
        if skip_next {
            skip_next = false;
            if word.is_single_word() {
                consumed[i] = true;
            }
            continue;
        }
        if past_terminator {
            continue;
        }
        let Resolution::Resolved(token) = word.resolution() else {
            continue;
        };
        if token == "--" {
            past_terminator = true;
            continue;
        }
        if value_flags.iter().any(|vf| vf.is_bare(token)) {
            skip_next = true;
        }
    }
    consumed
}

// ---------------------------------------------------------------------
// Effective-command resolution (shared basename / transparent-wrapper
// handling)
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
/// path-qualified sink/source cannot dodge either check by construction:
/// `/bin/sh`, `./sh`, `nohup sh`, `nice sh`, `env sh`, `command sh`,
/// `exec sh`, `xargs -0 sh` must all resolve to the `sh` they actually
/// run.
///
/// # Known limitation
///
/// Wrapper-argument skipping recognises `-`-prefixed flags (plus `env`'s
/// `NAME=value` form), a per-wrapper table of flags that take a *separate*
/// value token ([`wrapper_value_flags`]), and a per-wrapper count of
/// *positional* arguments consumed before the wrapped command
/// ([`wrapper_positional_args`]). Together these close the previously
/// documented gaps for the wrappers issue #54 covers: `nice -n 19 sh`,
/// `sudo -u root sh`, `doas -u root sh`, and `su`'s positional-username
/// form `su root -c 'sh'`.
///
/// What remains open: a wrapper's flag that takes a separate value token
/// but isn't in [`wrapper_value_flags`] (e.g. `nohup`, `exec`, `stdbuf`,
/// `setsid`, `xargs`, `pkexec`, `run0` have no entries there) is still
/// mistaken for the wrapped command, the same way every wrapper behaved
/// before this table existed. `su` keeps a narrower residual gap of this
/// same shape even though its own `-c`/`--command` flag IS now in
/// [`wrapper_value_flags`] (issues #64/#66): [`skip_wrapper_flags`] only
/// recognises a value flag occurring *before*
/// [`wrapper_positional_args`]'s username slot is consumed, so `su -c 'sh'
/// root` (options-before-user order) resolves cleanly through
/// [`effective_command`], but `su root -c 'sh'` (user-before-options)
/// still has the username slot consume `root` first, leaving `-c` to be
/// mistaken for the *next* hop's command name by [`effective_command`]'s
/// own walk. This residual gap is harmless for the actual security
/// question, though, unlike the pre-#64/#66 state: [`RECURSABLE_SLOTS`]/
/// [`wrapper_shell_string_scripts`] finds `su`'s `-c` flag independent of
/// word order — it scans `su`'s whole argument tail, not just the region
/// [`skip_wrapper_flags`] stops at — so the script value is still
/// recursed into either way; only the unrelated question of what
/// [`effective_command`] itself reports as "the resolved command name"
/// stays order-sensitive. Separately, because real `su` grammar (`su
/// [options] [-] [user [arg...]]`) gives no shape-based way to tell "no
/// username, command follows directly" from "username follows", the
/// positional slot unconditionally consumes whatever token comes first —
/// so `su rm -rf /`, which pre-#54 happened to resolve `rm` as the wrapped
/// command, now reads `rm` as the username instead (this actually matches
/// real `su` behaviour more closely: without `-c`, `su rm -rf /` would not
/// execute `rm -rf /` at all). All three cases are bounded the same way:
/// [`wrapper_chain_escalation`]'s `Contains` arm fires on the vector's own
/// name alone, before any argument skipping, so this limitation can only
/// ever under-resolve which *inner* rule would have blocked — it never
/// turns an escalation floor into a silent Allow.
///
/// `flock`'s own `-c '<command>'` form (like `sh -c`/`bash -c`, real
/// `flock` runs the string via `$SHELL -c`) was a *different* kind of gap,
/// not bounded the same way: `flock` is not an [`ESCALATION_VECTORS`]
/// entry, so there was no floor to fall back on if its `-c` string were
/// merely skipped — `flock /tmp/l -c 'rm -rf /'` silently `allow`ed
/// (issue #66). Fixed (issues #64/#66) by
/// [`RECURSABLE_SLOTS`]/[`wrapper_shell_string_scripts`]: `-c`/`--command`
/// is in [`wrapper_value_flags`] so its value is never mistaken for the
/// wrapped command by ordinary matching, and `crate::gate`'s wrapper-layer
/// floor recurses that value as a shell-command string exactly like rule
/// 6a already does for `sh -c`/`bash -c`, rather than merely skipping it.
///
/// `busybox` (issue #114) is a multi-call binary: `busybox <applet> args...`
/// runs `<applet>` exactly as if invoked directly, so `busybox mkswap
/// /dev/sda1`/`busybox rm -rf /`/`busybox sh -c 'rm -rf /'` all reached
/// `Allow` before this entry, since the resolved command name was always
/// the literal string `"busybox"`, matching no rule. Deliberately no
/// [`wrapper_value_flags`]/[`wrapper_positional_args`] entry: real
/// busybox's own global options (`--help`/`--install`/`--list`/`--show`)
/// are terminal — its dispatcher handles them and exits, it never falls
/// through to run a later argv word as an applet — so there is no
/// `busybox --flag VALUE applet args...` shape whose `VALUE` could be
/// mistaken for the wrapped command; the generic dash-prefix skip in
/// [`skip_wrapper_flags`] can only ever over-resolve a global-flag
/// invocation (e.g. `busybox --show rm` resolving `rm`, the safe
/// direction), never swallow a real applet name. Not itself an
/// [`ESCALATION_VECTORS`] entry — busybox is a dispatcher, not a
/// privilege-escalation mechanism.
pub(crate) const TRANSPARENT_WRAPPERS: &[&str] = &[
    "env", "command", "nohup", "nice", "exec", "stdbuf", "setsid", "sudo", "xargs", "doas", "su",
    "pkexec", "run0", "timeout", "ionice", "flock", "chrt", "taskset", "busybox",
];

/// The subset of [`TRANSPARENT_WRAPPERS`] that escalate privileges (issues
/// #35/#36) — `crate::gate` rule 10 floors a blocklist miss to at least
/// `escalation_floor`'s configured decision (default `Ask`) whenever one of
/// these appears anywhere in a command's wrapper-unwrap chain, independent
/// of whether the wrapped command trips its own rule. See
/// [`wrapper_chain_escalation`]. Every entry here must also appear in
/// [`TRANSPARENT_WRAPPERS`] (a unit test below pins this) — the allow-entry
/// rejection in [`matches_dangerous_allow_target`] walks
/// `TRANSPARENT_WRAPPERS`, not this list, so an escalation vector missing
/// from `TRANSPARENT_WRAPPERS` would silently become allow-listable.
pub(crate) const ESCALATION_VECTORS: &[&str] = &["sudo", "doas", "su", "pkexec", "run0"];

/// Shell interpreters whose `-c '<string>'` argument `crate::gate` recurses
/// into as shell syntax (rule 6a). Lives here, next to
/// [`TRANSPARENT_WRAPPERS`], so this module's allow-entry validation
/// (`matches_dangerous_allow_target`) can check a config entry against the
/// same list `crate::gate` uses, without `rules` depending on `gate`
/// ("dependencies point inward" — `gate` already depends on `rules`, not
/// the reverse).
pub(crate) const SHELL_INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "fish", "ksh", "tcsh", "csh", "ash",
];

/// Non-shell interpreters a pipeline's final stage may additionally be
/// (`crate::gate` rule 5b/5c), beyond every shell already named in
/// [`SHELL_INTERPRETERS`]. Kept as a *separate* small list, rather than a
/// second hand-maintained copy of the shell names, specifically so the two
/// lists cannot drift apart again the way they did for issue #55: that fix
/// added `fish`/`ksh`/`tcsh`/`csh`/`ash` to `SHELL_INTERPRETERS` alone, and
/// this file's own former `PIPELINE_INTERPRETERS` literal silently kept
/// missing them, letting `base64 -d payload | ksh` reach `Allow`. See
/// [`is_pipeline_interpreter`], the single place both lists are consulted
/// together.
const EXTRA_PIPELINE_INTERPRETERS: &[&str] = &["python", "python3", "node", "perl"];

/// Whether `name` is an interpreter a pipeline's final stage may be
/// (`crate::gate` rule 5b/5c) — every [`SHELL_INTERPRETERS`] entry, plus
/// [`EXTRA_PIPELINE_INTERPRETERS`]'s non-shell interpreters. Always call
/// this rather than consulting either list alone, so a future addition to
/// `SHELL_INTERPRETERS` (a new shell) is automatically also recognised as a
/// pipeline sink, with nothing left to keep in sync by hand.
#[must_use]
pub(crate) fn is_pipeline_interpreter(name: &str) -> bool {
    SHELL_INTERPRETERS.contains(&name) || EXTRA_PIPELINE_INTERPRETERS.contains(&name)
}

/// How a [`RecursableSlot`]'s value should be recursed — see
/// [`RECURSABLE_SLOTS`]'s own docs for the two constructs this
/// distinguishes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RecurseMode {
    /// The flag's value is a shell-command string, re-tokenised and
    /// recursed the same way rule 6a (`crate::gate`'s `evaluate_dash_c`)
    /// already recurses `sh -c`/`bash -c` (issues #64/#66: `flock -c`/
    /// `su -c` run their string via `$SHELL -c` too).
    ShellString,
    /// The flag starts a direct argv — no shell involved at all (issue
    /// #72: `find -exec`/`-execdir`/`-ok`/`-okdir` run their payload
    /// directly). The span runs from the word after the flag up to the
    /// first word resolving to one of `terminators`.
    DirectArgv {
        terminators: &'static [&'static str],
    },
}

/// One command+flag combination whose value is itself a command to
/// recurse into, rather than an opaque argument
/// [`skip_wrapper_arguments`]/[`wrapper_value_flags`] can simply skip
/// (issues #64/#66/#72). Deliberately does NOT cover `bash`/`sh`/`zsh`/
/// `dash -c` — rule 6a's own `-c` search
/// (`crate::gate::evaluate_dash_c`) operates over
/// [`effective_command`]'s `rest_words` (the tokens after the resolved
/// *interpreter*, with any leading wrapper's own arguments already
/// skipped), a different coordinate system from this table's per-wrapper-
/// hop scan (`crate::gate::scan_recursable_slots`,
/// [`wrapper_shell_string_scripts`]); folding `SHELL_INTERPRETERS` into
/// this table would need reconciling the two, for no behavioural gain.
pub(crate) struct RecursableSlot {
    pub(crate) command: &'static str,
    pub(crate) flag: &'static str,
    pub(crate) mode: RecurseMode,
}

/// See [`RecursableSlot`]'s docs. `crate::gate` consumes this in two ways:
/// [`wrapper_shell_string_scripts`] walks it for every [`RecurseMode::ShellString`]
/// entry while unwrapping a stage's transparent-wrapper chain, and
/// `crate::gate::scan_recursable_slots` walks it directly for `find`'s
/// [`RecurseMode::DirectArgv`] entries (that construct has no wrapper chain
/// to unwrap — `find` itself is never in [`TRANSPARENT_WRAPPERS`]).
pub(crate) const RECURSABLE_SLOTS: &[RecursableSlot] = &[
    RecursableSlot {
        command: "flock",
        flag: "-c",
        mode: RecurseMode::ShellString,
    },
    RecursableSlot {
        command: "flock",
        flag: "--command",
        mode: RecurseMode::ShellString,
    },
    RecursableSlot {
        command: "su",
        flag: "-c",
        mode: RecurseMode::ShellString,
    },
    RecursableSlot {
        command: "su",
        flag: "--command",
        mode: RecurseMode::ShellString,
    },
    RecursableSlot {
        command: "find",
        flag: "-exec",
        mode: RecurseMode::DirectArgv {
            terminators: &[";", "+"],
        },
    },
    RecursableSlot {
        command: "find",
        flag: "-execdir",
        mode: RecurseMode::DirectArgv {
            terminators: &[";", "+"],
        },
    },
    RecursableSlot {
        command: "find",
        flag: "-ok",
        mode: RecurseMode::DirectArgv {
            terminators: &[";", "+"],
        },
    },
    RecursableSlot {
        command: "find",
        flag: "-okdir",
        mode: RecurseMode::DirectArgv {
            terminators: &[";", "+"],
        },
    },
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

/// Per-wrapper flags that take a *separate* value token (`-n 19`, `-u
/// root`) — consulted by [`skip_wrapper_arguments`] so that value token
/// isn't mistaken for the wrapped command (issue #54). `sudo`/`doas` share
/// the gap `nice` originally exposed; `timeout`/`ionice` are new wrappers
/// added by the same issue. Consumption follows the same [`ValueFlag`]
/// semantics [`value_flag_free_candidates`] already uses for
/// `except_targets` candidates: [`ValueFlag::is_bare`] matches only the
/// flag's standalone spelling (`-n`), never a glued form (`-n19`), so a
/// glued short flag still falls through to the ordinary dash-prefix skip
/// below — it consumes only itself, not a following token, exactly like
/// before this table existed. A wrapper absent from this table, or one
/// whose flag isn't listed here, keeps that pre-existing dash-prefix-only
/// behaviour; see [`TRANSPARENT_WRAPPERS`]'s doc for what stays open.
///
/// Each wrapper's short *and* long spelling is listed for every value flag
/// (e.g. `timeout`'s `-s`/`--signal`): a long-only entry left out here
/// would let its separated form (`--signal KILL 5 rm -rf /`) mistake the
/// value for the wrapped command exactly as the pre-#54 short-flag gap
/// did — [`ValueFlag::is_bare`] already treats `--signal` and `-s` as
/// distinct spellings that must each be listed to be recognised. `flock`
/// gained its own entry here for the same reason `nice`/`sudo` did: its
/// `-w`/`--timeout` and `-E`/`--conflict-exit-code` flags take a separated
/// value that would otherwise land in [`wrapper_positional_args`]'s
/// lockfile slot (making the real lockfile argument the resolved command).
fn wrapper_value_flags(wrapper: &str) -> Vec<ValueFlag> {
    match wrapper {
        "nice" => vec![
            ValueFlag::Short('n'),
            ValueFlag::Long("adjustment".to_string()),
        ],
        "sudo" => vec![
            ValueFlag::Short('u'),
            ValueFlag::Short('g'),
            ValueFlag::Long("user".to_string()),
            ValueFlag::Long("group".to_string()),
        ],
        "doas" => vec![ValueFlag::Short('u')],
        "timeout" => vec![
            ValueFlag::Short('s'),
            ValueFlag::Short('k'),
            ValueFlag::Long("signal".to_string()),
            ValueFlag::Long("kill-after".to_string()),
        ],
        "ionice" => vec![
            ValueFlag::Short('c'),
            ValueFlag::Short('n'),
            ValueFlag::Short('p'),
            ValueFlag::Long("class".to_string()),
            ValueFlag::Long("classdata".to_string()),
            ValueFlag::Long("pid".to_string()),
        ],
        "flock" => vec![
            ValueFlag::Short('w'),
            ValueFlag::Short('E'),
            ValueFlag::Short('c'),
            ValueFlag::Long("timeout".to_string()),
            ValueFlag::Long("conflict-exit-code".to_string()),
            ValueFlag::Long("command".to_string()),
        ],
        // Issues #64/#66: `su`'s own `-c`/`--command` flag (like `flock`'s)
        // takes a separated shell-command-string value. Listing it here
        // stops that string from being mistaken for the wrapped command by
        // `effective_command`'s ordinary skip — the actual recursion into
        // its content happens separately, via `RECURSABLE_SLOTS`/
        // `wrapper_shell_string_scripts`, not by this table alone (adding
        // a value flag here only ever means "skip this value", never
        // "recurse into it").
        "su" => vec![
            ValueFlag::Short('c'),
            ValueFlag::Long("command".to_string()),
        ],
        "chrt" => vec![
            ValueFlag::Short('T'),
            ValueFlag::Short('P'),
            ValueFlag::Short('D'),
            ValueFlag::Long("sched-runtime".to_string()),
            ValueFlag::Long("sched-period".to_string()),
            ValueFlag::Long("sched-deadline".to_string()),
        ],
        _ => vec![],
    }
}

/// Per-wrapper count of *positional* (not flag-attached) arguments the
/// wrapper consumes before the wrapped command itself — a separate table
/// from [`wrapper_value_flags`] because these values aren't attached to
/// any flag at all (issue #54):
///
/// - `timeout [OPTION]... DURATION COMMAND...` — the duration is a bare
///   positional; without this, `timeout 5 rm -rf /` mistakes `5` for the
///   command.
/// - `flock [options] <file|directory> command...` — the lock target
///   precedes the command. This one is load-bearing, not cosmetic: without
///   it, `flock /tmp/l rm -rf /` resolves `/tmp/l` (basename `l`) as the
///   command, `rm -rf /` never reaches the `rm` rule, and the whole
///   invocation silently allows.
/// - `su [options] [-] [user [args...]]` — the username, when present,
///   precedes the command `su` itself runs.
/// - `chrt [options] priority command [args]` — the scheduling priority is
///   a bare positional before the command, the same shape as `timeout`'s
///   duration. `chrt`'s other mode, `chrt -p [priority] pid` (operate on
///   an already-running process), never starts a new command at all, so
///   treating whatever follows the skipped positional as "the command"
///   there resolves to a bare PID and matches no rule — not a new gap,
///   since there is no command in that mode to miss.
/// - `taskset [options] mask command [args]` — the CPU affinity mask
///   precedes the command, same shape again. `taskset -p [mask] pid`
///   shares `chrt -p`'s no-new-command mode and the same non-gap.
///
/// Applied by [`skip_wrapper_arguments`] *after* flag-skipping stops, so a
/// leading run of flags (including a value-flag's separated value) is
/// consumed first and the positional count applies to whatever token
/// follows.
fn wrapper_positional_args(wrapper: &str) -> usize {
    match wrapper {
        "timeout" | "flock" | "su" | "chrt" | "taskset" => 1,
        _ => 0,
    }
}

/// The flag-skipping half of [`skip_wrapper_arguments`], factored out so
/// [`su_username_matches_blocklisted_command`] can find where `su`'s own
/// flags end — and therefore which token occupies its positional
/// "username" slot — without also applying [`wrapper_positional_args`]'s
/// skip, which is exactly the token this function's caller needs to
/// inspect rather than discard. Returns the index of the first token that
/// is neither one of `wrapper`'s bare value flags nor `-`-prefixed (nor,
/// for `env`, a `NAME=value` assignment) — i.e. where positional
/// consumption would begin.
fn skip_wrapper_flags(wrapper: &str, argv: &[NormalizedWord]) -> usize {
    let value_flags = wrapper_value_flags(wrapper);
    let mut idx = 0;
    while idx < argv.len() {
        let Resolution::Resolved(token) = argv[idx].resolution() else {
            break;
        };
        if value_flags.iter().any(|vf| vf.is_bare(token)) {
            // The flag token itself is always consumed; its separated
            // value is consumed too only when resolved: advancing past an
            // unresolvable value unconditionally would let `nice -n $X
            // ls`/`timeout -s $X 5 ls` silently resolve `ls` as the
            // wrapped command and allow it, even though the real flag
            // value — and therefore what actually runs — is unknown, the
            // same class of gap [`skip_wrapper_arguments`]'s
            // positional-skip has. Stopping here, at the value token (or
            // at the end of `argv` if the flag was the last token), leaves
            // it for the caller's own `Resolution::Resolved` check to fail
            // closed — this function never resolves anything itself.
            idx += 1;
            match argv.get(idx).map(NormalizedWord::resolution) {
                Some(Resolution::Resolved(_)) => idx += 1,
                _ => break,
            }
            continue;
        }
        let skippable =
            token.starts_with('-') || (wrapper == "env" && is_env_assignment_shape(token));
        if !skippable {
            break;
        }
        idx += 1;
    }
    idx
}

/// Skips a transparent wrapper's own leading arguments (see
/// [`effective_command`]'s docs): a token matching one of
/// [`wrapper_value_flags`]'s bare spellings skips itself *and* the
/// following token (its separated value); any other `-`-prefixed token,
/// plus `NAME=value` tokens when `wrapper == "env"`, skips only itself.
/// Flag-skipping stops at the first token matching neither shape — that
/// token starts the wrapper's [`wrapper_positional_args`] positionals, if
/// it declares any — or at the first unresolvable token, which leaves
/// `effective_command`'s next loop iteration to fail closed to `None`.
///
/// The positional count is applied once flag-skipping stops, one token at a
/// time, and — like the flag-skipping loop above — stops early on the first
/// [`Resolution::Unresolvable`] token rather than blindly counting past it:
/// counting past an unresolvable token unconditionally would let `timeout
/// $X ls`/`flock $F ls` silently resolve `ls` as the wrapped command and
/// `allow` it, even though the real positional value — and therefore what
/// actually runs — is unknown; the 0-positional `env $X ls` already
/// correctly falls to `WrapperChainEscalation::Unresolved` via the
/// flag-skipping loop's own early stop, so the positional loop must match
/// that same fail-closed shape. Left pointing at that unresolvable
/// token (not past it), so the caller's own `Resolution::Resolved` check —
/// [`effective_command`]'s loop, or [`wrapper_chain_escalation`]'s — is what
/// actually fails closed; this function only ever stops early, never
/// resolves anything itself. Also bounded by however many tokens remain: a
/// wrapper whose value or positional arguments consume the entire tail
/// (`flock -x 9` alone) leaves an empty slice, which `effective_command`'s
/// next loop iteration turns into `None` — fail-closed, never a guess past
/// the end.
///
/// A lone `--` end-of-options marker immediately after that (e.g. `flock
/// /tmp/l -- rm -rf /`) is skipped too: it is never itself a command name,
/// and without this a positional-consuming wrapper resolves it as the
/// wrapped command, which matches no rule and silently allows (issue #54
/// follow-up). A wrapper with no positional (`sudo -u root -- rm -rf /`)
/// never reaches this check — the flag-skipping loop above already
/// consumes `--` itself, since it starts with `-`.
fn skip_wrapper_arguments<'a>(wrapper: &str, argv: &'a [NormalizedWord]) -> &'a [NormalizedWord] {
    let mut idx = skip_wrapper_flags(wrapper, argv);
    let mut positionals_remaining = wrapper_positional_args(wrapper);
    while positionals_remaining > 0 {
        let Some(Resolution::Resolved(_)) = argv.get(idx).map(NormalizedWord::resolution) else {
            break;
        };
        idx += 1;
        positionals_remaining -= 1;
    }
    if let Some(Resolution::Resolved(token)) = argv.get(idx).map(NormalizedWord::resolution)
        && token == "--"
    {
        idx += 1;
    }
    &argv[idx..]
}

/// How `stage`'s wrapper-unwrap chain (the same walk as
/// [`effective_command`]) relates to [`ESCALATION_VECTORS`] — see
/// [`wrapper_chain_escalation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WrapperChainEscalation {
    /// One of [`ESCALATION_VECTORS`] appears at some hop of the chain —
    /// carries which one (the `'static` entry from that constant), so
    /// `crate::gate`'s floor reason can name it.
    Contains(&'static str),
    /// The chain passed through at least one transparent wrapper and then
    /// hit an unresolvable word — the wrapped command, possibly an
    /// escalation vector itself (`env $(echo sudo) ls`, `env $SUDO ls`),
    /// cannot be determined statically.
    Unresolved,
    /// The chain resolves and never passes through an escalation vector.
    Absent,
}

/// Classifies `stage`'s wrapper-unwrap chain against [`ESCALATION_VECTORS`]
/// at *any* hop, not just the terminal resolved command — `env sudo ls`
/// must be caught the same as a bare `sudo ls` (issue #32, generalised to
/// `doas`/`su`/`pkexec`/`run0` by issues #35/#36; `crate::gate` rule 10).
///
/// [`WrapperChainEscalation::Unresolved`] is the fail-closed arm: past the
/// first wrapper, an unresolvable word means what actually runs is
/// unknowable, so `crate::gate` floors it rather than trusting it isn't an
/// escalation vector. An unresolvable *first* word needs no such handling
/// here (`Absent`): that is command-position unresolvability, which gate
/// rules 1/2 already floor before this classification is consulted.
#[must_use]
pub(crate) fn wrapper_chain_escalation(stage: &[NormalizedWord]) -> WrapperChainEscalation {
    let mut rest = stage;
    let mut passed_wrapper = false;
    loop {
        let Some((first, tail)) = rest.split_first() else {
            return WrapperChainEscalation::Absent;
        };
        let Resolution::Resolved(name) = first.resolution() else {
            return if passed_wrapper {
                WrapperChainEscalation::Unresolved
            } else {
                WrapperChainEscalation::Absent
            };
        };
        let base = basename(name);
        if let Some(&vector) = ESCALATION_VECTORS.iter().find(|v| **v == base) {
            return WrapperChainEscalation::Contains(vector);
        }
        if !TRANSPARENT_WRAPPERS.contains(&base) {
            return WrapperChainEscalation::Absent;
        }
        passed_wrapper = true;
        rest = skip_wrapper_arguments(base, tail);
    }
}

/// One [`RecurseMode::ShellString`] slot's value, found while walking a
/// stage's transparent-wrapper chain (issues #64/#66) — see
/// [`wrapper_shell_string_scripts`].
pub(crate) enum ScriptSlot {
    /// The flag's value resolved to a concrete shell-command string, ready
    /// for `crate::gate` to recurse the same way rule 6a recurses `sh
    /// -c`/`bash -c`.
    Resolved(String),
    /// The flag's own position, or its value, could not be statically
    /// resolved — the fail-closed counterpart of [`FlagScan::Uncertain`]:
    /// an unresolvable word at either position must never read as "no
    /// script to worry about".
    Unresolvable,
}

/// Finds every [`RecurseMode::ShellString`] [`RecursableSlot`]'s script
/// value along `stage`'s transparent-wrapper chain (today: `flock`/`su`'s
/// `-c`/`--command`, issues #64/#66). Mirrors the same wrapper-unwrap walk
/// [`effective_command`]/[`wrapper_chain_escalation`] perform, but — unlike
/// both of those — does not stop at the first hop and does not rely on
/// [`skip_wrapper_flags`]'s own flag-then-positional ordering to find the
/// flag: each wrapper hop's *entire* argument tail is scanned for its
/// `RECURSABLE_SLOTS` flag via [`scan_for_flag`], independent of whether
/// that flag sits before or after the wrapper's own positional slot (see
/// [`TRANSPARENT_WRAPPERS`]'s docs on why `su -c 'sh' root` and `su root
/// -c 'sh'` must both be found, even though only the former resolves
/// cleanly through [`effective_command`] itself). This is deliberately
/// broader than [`skip_wrapper_flags`]'s own boundary — a same-hop token
/// that happens to also look like `-c`/`--command` but belongs to a
/// different, unrelated flag on some other wrapper would still be found
/// here; accepted because this function only ever produces an
/// [`ScriptSlot::Unresolvable`]/[`ScriptSlot::Resolved`] *floor* (never an
/// early-return Allow, per `crate::gate`'s wrapper-layer docs), so a
/// mismatch can only cost an extra recursion or an over-cautious Ask, never
/// a silent Allow.
#[must_use]
pub(crate) fn wrapper_shell_string_scripts(stage: &[NormalizedWord]) -> Vec<ScriptSlot> {
    let mut slots = Vec::new();
    let mut rest = stage;
    while let Some((first, tail)) = rest.split_first() {
        let Resolution::Resolved(name) = first.resolution() else {
            break;
        };
        let base = basename(name);
        if !TRANSPARENT_WRAPPERS.contains(&base) {
            break;
        }
        for slot in RECURSABLE_SLOTS
            .iter()
            .filter(|slot| slot.command == base && matches!(slot.mode, RecurseMode::ShellString))
        {
            match scan_for_flag(tail, |s| s == slot.flag) {
                FlagScan::Found(i) => match tail.get(i + 1).map(NormalizedWord::resolution) {
                    Some(Resolution::Resolved(script)) => {
                        slots.push(ScriptSlot::Resolved(script.clone()));
                    }
                    Some(Resolution::Unresolvable(_)) => slots.push(ScriptSlot::Unresolvable),
                    // No word follows the flag at all — the same shape
                    // `crate::gate::evaluate_dash_c` treats as "not this
                    // shape" (`rest_words.get(flag_index + 1)?`) rather
                    // than an Ask floor: a `-c` with nothing after it names
                    // no command to worry about.
                    None => {}
                },
                FlagScan::Uncertain(_) => slots.push(ScriptSlot::Unresolvable),
                FlagScan::Absent => {}
            }
        }
        rest = skip_wrapper_arguments(base, tail);
    }
    slots
}

/// Whether `stage`'s wrapper-unwrap chain passes through `su` with a
/// positional "username" slot such that the username *and everything after
/// it*, reinterpreted as their own command line, fully matches one of
/// `rules`' command rules — name, required flags/tokens, and targets alike
/// (issue #54 follow-up — see below for why name-only matching is wrong).
///
/// `su [options] [-] [user [args...]]` is shape-ambiguous: `su rm -rf /`
/// can't be told apart from "su into a user literally named `rm`, with no
/// command" by structure alone (see [`wrapper_positional_args`]'s docs on
/// `su`), and `crate::gate`'s rule 10 already floors that ambiguity to at
/// least `escalation_floor` (default `Ask`) because `su` is an
/// [`ESCALATION_VECTORS`] entry. But when the username slot and its
/// trailing arguments, read as a command line, *fully* match a real
/// blocklist rule — not just its command name — the coincidence is worth
/// treating as that rule's own decision (typically `deny`) rather than only
/// the generic floor: `su rm -rf /` reads at least as suspicious as `rm -rf
/// /` itself.
///
/// Matching on name alone (an earlier version of this function) was wrong:
/// `su - git` and `su git -c 'git pull'` — routine administration on any
/// git server, since `git` is a standard system account — matched
/// `git-push-force` by name and denied with a reason describing a
/// force-push that appears nowhere in the command. Reusing
/// [`CommandRule::matches`] (the same constraint/target-checked matcher
/// [`Rules::match_command`] uses everywhere else) instead of a name-only
/// check means the shadow only fires when the reinterpreted command line
/// would itself have tripped the rule — exactly reproducing the pre-#54
/// behaviour's own matching for the one case where it mattered (`su rm -rf
/// /`, where `-rf /` are read as `rm`'s own arguments and satisfy its
/// `required_flags`/targets), while leaving `su - git` at the generic Ask
/// floor like any other unresolvable-intent `su` invocation.
///
/// Only `su` gets this treatment: `sudo`/`doas`'s user argument is always
/// flag-introduced (`-u root`), so there is no bare positional slot for a
/// command name to land in by coincidence in the first place.
///
/// Walks the same wrapper-unwrap chain as [`effective_command`] so a
/// wrapped `su` (`env su rm -rf /`) is still caught, and reuses
/// [`skip_wrapper_flags`] — not [`skip_wrapper_arguments`] — at the `su`
/// hop specifically, since the whole point is to inspect the token
/// [`wrapper_positional_args`]'s skip would otherwise discard unread.
#[must_use]
pub(crate) fn su_username_matches_blocklisted_command<'a>(
    stage: &[NormalizedWord],
    rules: &'a Rules,
) -> Option<&'a CommandRule> {
    let mut rest = stage;
    loop {
        let (first, tail) = rest.split_first()?;
        let Resolution::Resolved(name) = first.resolution() else {
            return None;
        };
        let base = basename(name);
        if base == "su" {
            let idx = skip_wrapper_flags(base, tail);
            return rules
                .command_rules
                .iter()
                .find(|rule| rule.matches(&tail[idx..]));
        }
        if !TRANSPARENT_WRAPPERS.contains(&base) {
            return None;
        }
        rest = skip_wrapper_arguments(base, tail);
    }
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
    #[serde(default)]
    except_targets: Vec<TargetDto>,
    #[serde(default)]
    value_flags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetDto {
    exact: Option<String>,
    prefix: Option<String>,
    normalized: Option<String>,
    normalized_prefix: Option<String>,
    url_host: Option<String>,
    strip: Option<String>,
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

/// Parses the optional top-level `escalation_floor` user-config key
/// (issues #35/#36) into a [`Decision`], defaulting to `Decision::Ask`
/// when absent. `"ask"` and `"deny"` are the only valid values; `"allow"`
/// — which would lift the escalation floor entirely — is a load-time
/// error (fail-closed), the same posture already applied to `[[allow]]`
/// entries naming an escalation vector directly (see
/// [`matches_dangerous_allow_target`]): there is deliberately no config
/// mechanism at all that turns the floor off.
fn parse_escalation_floor(raw: Option<&str>) -> Result<Decision, RulesError> {
    match raw {
        None | Some("ask") => Ok(Decision::Ask),
        Some("deny") => Ok(Decision::Block),
        Some(other) => Err(RulesError::invalid(
            "escalation_floor",
            format!("escalation_floor must be \"ask\" or \"deny\", got {other:?}"),
        )),
    }
}

/// Rejects a `-`-prefixed word as flag-looking — shared predicate for both
/// the multi-word `command` sugar and `required_tokens` entries, each of
/// which supplies its own message so the error always names the field the
/// rule author actually wrote.
fn reject_flag_looking_word(
    id: &str,
    word: &str,
    message: impl FnOnce() -> String,
) -> Result<(), RulesError> {
    if word.starts_with('-') {
        return Err(RulesError::invalid(id, message()));
    }
    Ok(())
}

/// Finds the largest `k` such that the last `k` words of `sugar_tokens`
/// (the words a multi-word `command` prepends onto `required_tokens` as
/// subcommand sugar) equal the first `k` words of `required_tokens` — a
/// boundary overlap between what the sugar already implies and what the
/// rule author additionally wrote by hand. Deliberately partial: it only
/// catches an overlap AT THE sugar/required_tokens BOUNDARY, not a
/// duplication anywhere else — e.g. sugar_tokens = `["a", "b", "c"]` with
/// required_tokens = `["b"]` is NOT caught (sugar's 1-word tail is
/// `["c"]`, which doesn't match required_tokens' 1-word head `["b"]`).
/// Accepted trade-off: widening to "does any required_tokens word appear
/// anywhere in sugar_tokens" would raise false-positive risk for unclear
/// benefit. Also not caught: a required_tokens entry with internal
/// whitespace (e.g. `"repo delete"` as a single token) never equals a
/// single sugar word, so it can collide with sugar words without this
/// check seeing it — accepted, since permitting internal whitespace at all
/// is what makes the legitimate quoted-positional case possible.
fn sugar_required_tokens_overlap(
    sugar_tokens: &[String],
    required_tokens: &[String],
) -> Option<usize> {
    let max_k = sugar_tokens.len().min(required_tokens.len());
    (1..=max_k)
        .rev()
        .find(|&k| sugar_tokens.ends_with(&required_tokens[..k]))
}

/// Converts a [`CommandRuleDto`] into a [`CommandRule`], rejecting every
/// semantically-invalid shape at this one boundary: empty id, empty
/// reason, neither/both of `command`/`command_prefix` set, an empty
/// `command`/`command_prefix` value, a `command_prefix` containing
/// whitespace, a multi-word `command` with a flag-looking word (leading
/// `-`) after the first, a malformed flag spec, an invalid
/// required_tokens entry, a target with neither/both of `exact`/`prefix`
/// set, or a malformed `value_flags` spec. A multi-word `command` (e.g.
/// `"gh repo delete"`) desugars to the first word as the command name plus
/// the remaining words prepended onto `required_tokens`.
fn convert_command_rule(mut dto: CommandRuleDto) -> Result<CommandRule, RulesError> {
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
            let mut words = exact.split_whitespace();
            let name = match words.next() {
                Some(name) => name.to_string(),
                None => unreachable!("non-empty-after-trim string yields at least one word"),
            };
            let sugar_tokens: Vec<String> = words.map(str::to_string).collect();
            for token in &sugar_tokens {
                reject_flag_looking_word(&dto.id, token, || {
                    format!(
                        "command word {token:?} looks like a flag; use required_flags \
                         instead of a multi-word command"
                    )
                })?;
            }
            if let Some(k) = sugar_required_tokens_overlap(&sugar_tokens, &dto.required_tokens) {
                return Err(RulesError::invalid(
                    &dto.id,
                    format!(
                        "required_tokens begins with {:?}, which overlaps the last {k} word(s) \
                         `command` = {exact:?} already implies via its multi-word sugar \
                         ({sugar_tokens:?}) — if this is a mistake, remove the overlap from \
                         required_tokens; if the sequence genuinely repeats, either spell the \
                         whole thing in `command` (e.g. command = \"foo bar bar\") or drop the \
                         sugar entirely and spell every word in required_tokens by hand",
                        &dto.required_tokens[..k],
                    ),
                ));
            }
            dto.required_tokens.splice(0..0, sugar_tokens);
            CommandMatch::Exact(name)
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
            if prefix.contains(char::is_whitespace) {
                return Err(RulesError::invalid(
                    &dto.id,
                    "`command_prefix` must not contain whitespace — subcommand-sequence \
                     matching is only available via `command`, not `command_prefix`",
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

    // Explicit merge point: `required_tokens` is fully determined once the
    // `command`/`command_prefix` match above concludes (the `command` arm
    // may have spliced sugar words into it; `command_prefix` never touches
    // it). Binding it to a local here — a partial move out of `dto` — makes
    // every reader below use the post-merge value by construction; an
    // accidental later read of `dto.required_tokens` would be a compile
    // error instead of a silent pre-merge bug.
    let required_tokens = dto.required_tokens;

    let decision = parse_decision(&dto.id, dto.decision.as_deref())?;

    let required_flags = dto
        .required_flags
        .iter()
        .map(|spec| {
            FlagMatcher::parse(spec).map_err(|problem| RulesError::invalid(&dto.id, problem))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Re-walks sugar-derived tokens the `command` arm already validated —
    // redundant today (the sugar loop errors first; `split_whitespace`
    // yields no empties) and load-time cheap. The rejection predicate is
    // single-sourced in `reject_flag_looking_word`, so the sites can only
    // diverge in walk coverage; this loop backstops exactly that.
    for token in &required_tokens {
        if token.trim().is_empty() {
            return Err(RulesError::invalid(
                &dto.id,
                "required_tokens entry must not be empty",
            ));
        }
        if token != token.trim() {
            return Err(RulesError::invalid(
                &dto.id,
                format!(
                    "required_tokens entry {token:?} has leading/trailing whitespace, \
                     which can never match a resolved argv word"
                ),
            ));
        }
        reject_flag_looking_word(&dto.id, token, || {
            format!("required_tokens entry {token:?} starts with '-'; use required_flags for flags")
        })?;
    }

    let targets = dto
        .targets
        .into_iter()
        .map(|t| convert_target(&dto.id, t, false))
        .collect::<Result<Vec<_>, _>>()?;
    let except_targets = dto
        .except_targets
        .into_iter()
        .map(|t| convert_target(&dto.id, t, true))
        .collect::<Result<Vec<_>, _>>()?;

    let value_flags = dto
        .value_flags
        .iter()
        .map(|spec| ValueFlag::parse(spec).map_err(|problem| RulesError::invalid(&dto.id, problem)))
        .collect::<Result<Vec<_>, _>>()?;

    // value_flags narrows two candidate walks, both reachable only when
    // `targets` is empty (module docs on both consumers): the except_targets
    // walk in CommandRule::matches's `targets`-empty branch, and (issue
    // #146) matches_except_flags's "could this unresolvable word plausibly
    // be the missing required flag/token" floor. A rule that declares it
    // alongside a non-empty `targets` list, or with none of
    // `except_targets`/`required_flags`/`required_tokens` at all, would
    // load successfully but have the field silently do nothing. "parse,
    // don't validate" (module docs): catch that dead configuration at load
    // time rather than let a rule author's mistake pass unnoticed.
    if !value_flags.is_empty() && !targets.is_empty() {
        return Err(RulesError::invalid(
            &dto.id,
            "value_flags has no effect when `targets` is non-empty",
        ));
    }
    if !value_flags.is_empty()
        && except_targets.is_empty()
        && required_flags.is_empty()
        && required_tokens.is_empty()
    {
        return Err(RulesError::invalid(
            &dto.id,
            "value_flags has no effect without `except_targets` or `required_flags`/`required_tokens`",
        ));
    }

    // required_tokens + except_targets dead-config check (issue #96):
    // deliberately narrower than "both non-empty is
    // always an error" — a required_tokens word covered by its own
    // except_targets entry (e.g. `command = "gh repo delete"` with
    // except_targets matching "repo", "delete", and a target prefix) is a
    // legitimate, functional carve-out. Only a required_tokens word
    // matched by NONE of the except_targets alternatives is provably
    // always an except_targets candidate that can never be excepted —
    // i.e. dead. The value_flags.is_empty() gate matters because a
    // value-flag-consumed resolved word can drop out of the except_targets
    // candidate set entirely, which would make "provably dead" overclaim
    // in a contrived case.
    if targets.is_empty()
        && !except_targets.is_empty()
        && value_flags.is_empty()
        && let Some(unexcepted) = required_tokens
            .iter()
            .find(|t| !except_targets.iter().any(|e| e.matches(t)))
    {
        return Err(RulesError::invalid(
            &dto.id,
            format!(
                "except_targets can never suppress this rule: required_tokens entry {unexcepted:?} \
                 is always an except_targets candidate but matches none of the except_targets \
                 alternatives — add explicit `targets`, cover this subcommand word with its own \
                 except_targets entry, or remove except_targets"
            ),
        ));
    }

    Ok(CommandRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        decision,
        command,
        required_flags,
        required_tokens,
        targets,
        except_targets,
        value_flags,
    })
}

/// Converts one `targets`/`except_targets` TOML entry into a
/// [`TargetMatcher`]. `is_except_target` is `true` only for an
/// `except_targets` entry — [`TargetMatcher::Exact`]'s/
/// [`TargetMatcher::Prefix`]'s own docs (issue #65) explain why: an
/// `except_targets` entry must stay literal, never `normalized`/
/// `normalized_prefix`, because normalizing a carve-out would silently
/// *widen* an allow, which must always be an explicit, deliberate rule-
/// author choice, never an accidental side effect of reaching for the
/// wrong TOML key.
fn convert_target(
    rule_id: &str,
    dto: TargetDto,
    is_except_target: bool,
) -> Result<TargetMatcher, RulesError> {
    let set_count = usize::from(dto.exact.is_some())
        + usize::from(dto.prefix.is_some())
        + usize::from(dto.normalized.is_some())
        + usize::from(dto.normalized_prefix.is_some())
        + usize::from(dto.url_host.is_some());
    if set_count != 1 {
        return Err(RulesError::invalid(
            rule_id,
            "target requires exactly one of `exact`/`prefix`/`normalized`/`normalized_prefix`/\
             `url_host`",
        ));
    }
    if is_except_target && (dto.normalized.is_some() || dto.normalized_prefix.is_some()) {
        return Err(RulesError::invalid(
            rule_id,
            "except_targets entries must be `exact`/`prefix` (literal); `normalized`/\
             `normalized_prefix` would silently widen an allow by normalizing the carve-out, \
             which must always be an explicit, deliberate choice",
        ));
    }
    if dto.strip.is_some() && dto.normalized.is_none() && dto.normalized_prefix.is_none() {
        return Err(RulesError::invalid(
            rule_id,
            "target's `strip` is only valid alongside `normalized`/`normalized_prefix`",
        ));
    }
    if dto.strip.as_deref().is_some_and(str::is_empty) {
        return Err(RulesError::invalid(
            rule_id,
            "target's `strip` must not be empty",
        ));
    }

    // `set_count == 1` above guarantees exactly one of these five is
    // `Some` — the wildcard arm is unreachable, not a fallback.
    match (
        dto.exact,
        dto.prefix,
        dto.normalized,
        dto.normalized_prefix,
        dto.url_host,
    ) {
        (Some(exact), None, None, None, None) => {
            if exact.trim().is_empty() {
                return Err(RulesError::invalid(
                    rule_id,
                    "target's `exact` must not be empty",
                ));
            }
            Ok(TargetMatcher::Exact(exact))
        }
        (None, Some(prefix), None, None, None) => {
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
        (None, None, Some(normalized), None, None) => {
            if normalized.trim().is_empty() {
                return Err(RulesError::invalid(
                    rule_id,
                    "target's `normalized` must not be empty",
                ));
            }
            let target = lexical_normalize(&normalized);
            reject_degenerate_normalized_target(rule_id, &normalized, &target)?;
            Ok(TargetMatcher::NormalizedExact {
                strip: dto.strip,
                target,
            })
        }
        (None, None, None, Some(normalized_prefix), None) => {
            if normalized_prefix.trim().is_empty() {
                return Err(RulesError::invalid(
                    rule_id,
                    "target's `normalized_prefix` must not be empty",
                ));
            }
            let form = lexical_normalize(&normalized_prefix);
            reject_degenerate_normalized_target(rule_id, &normalized_prefix, &form)?;
            let Some(mut canon) = canonical_render(&form) else {
                return Err(RulesError::invalid(
                    rule_id,
                    format!(
                        "target's `normalized_prefix` {normalized_prefix:?} has no canonical \
                         rendering to prefix-match against"
                    ),
                ));
            };
            // Preserve the author's trailing-slash intent:
            // `normalized_prefix = "/dev/"` must only match tokens at or
            // below that directory boundary (today's `Prefix` behavior
            // for a slash-terminated prefix), while `normalized_prefix =
            // "/dev/sd"` (no trailing slash) keeps matching by plain
            // string prefix (`/dev/sda`, `/dev/sdb1`, …) — canonical
            // rendering alone always drops a trailing slash (`/dev/`
            // renders as `/dev`), so it's re-added here whenever the
            // author wrote one.
            if normalized_prefix.ends_with('/') && !canon.ends_with('/') {
                canon.push('/');
            }
            Ok(TargetMatcher::NormalizedPrefix {
                strip: dto.strip,
                canon,
            })
        }
        (None, None, None, None, Some(url_host)) => {
            if url_host.trim().is_empty() {
                return Err(RulesError::invalid(
                    rule_id,
                    "target's `url_host` must not be empty",
                ));
            }
            // `*` is a forbidden host code point in the URL Standard, so no
            // real URL's parsed host can ever contain one — a wildcard
            // config value would load successfully but provably never
            // match anything, silently giving a rule author zero of the
            // subdomain-wildcard coverage they likely intended. Same
            // "parse, don't validate" posture as the dead-config checks
            // above: caught at load time rather than left as a silent no-op.
            if url_host.contains('*') {
                return Err(RulesError::invalid(
                    rule_id,
                    format!(
                        "target's `url_host` {url_host:?} contains '*', which a real URL's host \
                         can never contain and so can never match — wildcard host matching is not \
                         supported"
                    ),
                ));
            }
            // Parsed via `url::Host::parse` — the config VALUE is a bare
            // host, not a full URL, unlike the match-time candidate
            // (`parse_url_host`, which extracts `.host()` from a parsed
            // `url::Url`) — but both funnel through the same `url::Host`
            // type and `PartialEq`, so "what counts as this host" is still
            // defined consistently on both sides (docs/adr/0002-url-crate.md).
            // `strip_trailing_dot` mirrors `parse_url_host`'s own call so an
            // explicit-FQDN-root config value (`"evil.example.com."`) and
            // candidate (`http://evil.example.com./`) compare equal.
            let host = url::Host::parse(&url_host).map_err(|err| {
                RulesError::invalid(
                    rule_id,
                    format!("target's `url_host` {url_host:?} is not a valid host: {err}"),
                )
            })?;
            Ok(TargetMatcher::UrlHost(strip_trailing_dot(host)))
        }
        _ => unreachable!("set_count == 1 checked above: exactly one alternative is Some"),
    }
}

/// Load-time guard for [`TargetMatcher::NormalizedExact`]/
/// [`TargetMatcher::NormalizedPrefix`]'s target value (issue #65): a
/// `normalized`/`normalized_prefix` TOML value that itself normalizes to a
/// form that could never usefully match anything — pure ascent
/// (`PathForm::Rel { ascent > 0, .. }`, e.g. a rule author wrote
/// `normalized = ".."`), [`PathForm::EscapesHome`], or [`PathForm::Opaque`]
/// — is almost certainly a mistake, not an intentional target. Fail loudly
/// at load time rather than silently at match time ("parse, don't
/// validate", module docs).
fn reject_degenerate_normalized_target(
    rule_id: &str,
    raw: &str,
    form: &PathForm,
) -> Result<(), RulesError> {
    let degenerate = match form {
        PathForm::Rel { ascent, .. } => *ascent > 0,
        PathForm::EscapesHome(_)
        | PathForm::Opaque
        | PathForm::NamedUserHome
        | PathForm::NamedUserHomeEscapes(_)
        | PathForm::DirStack => true,
        PathForm::Abs(_) | PathForm::Home(_) => false,
    };
    if degenerate {
        return Err(RulesError::invalid(
            rule_id,
            format!(
                "target's normalized value {raw:?} normalizes to a form that can never \
                 usefully match (pure ascent, escapes $HOME, a directory-stack shorthand, or \
                 opaque) — this is almost certainly a mistake"
            ),
        ));
    }
    Ok(())
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
        .map(|t| convert_target(&dto.id, t, false))
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

    /// issue #78: true when `target` (a redirect's resolved target word)
    /// normalizes to an unresolved ascent-then-descent shape that
    /// plausibly lands inside one of this rule's own targets — the same
    /// gap [`CommandRule::matches_ascent_descent_floor`] closes for
    /// argv-based targets (`dd of=...`, `tee ...`), but for shell
    /// redirect syntax (`> ...`, `>> ...`), which carries the identical
    /// `/dev/*`/`/etc/passwd`/`/etc/shadow` target namespace via
    /// `redirect-overwrite-device-or-critical-file`. Read-only probe,
    /// never itself a match (see `crate::gate::scan_redirect_ascent_descent_floor`).
    #[must_use]
    fn ascent_descent_plausible(&self, target: &str) -> bool {
        self.targets
            .iter()
            .any(|t| t.ascent_descent_plausible(target))
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
///
/// `escalation_floor` is likewise always [`Decision::Ask`] (the documented
/// default) for a [`Self::parse`]d/[`Self::embedded`] set —
/// `rules/blocklist.toml` carries no such key of its own, only a user
/// config's top-level `escalation_floor` (issues #35/#36) can override it,
/// via [`merge_user_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rules {
    command_rules: Vec<CommandRule>,
    pipeline_rules: Vec<PipelineRule>,
    redirect_rules: Vec<RedirectRule>,
    ask_rules: Vec<CommandRule>,
    escalation_floor: Decision,
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
            escalation_floor: Decision::Ask,
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

    /// The first [`RedirectRule`] for which
    /// [`RedirectRule::ascent_descent_plausible`] holds against `target`,
    /// if any — issue #78's floor extended to shell redirect syntax. Like
    /// [`Self::match_command_ascent_descent`], a read-only probe: never
    /// mutates rule state, never itself constitutes a match.
    #[must_use]
    pub(crate) fn match_redirect_target_ascent_descent(
        &self,
        target: &str,
    ) -> Option<&RedirectRule> {
        self.redirect_rules
            .iter()
            .find(|rule| rule.ascent_descent_plausible(target))
    }

    /// The first user-configured `ask` [`CommandRule`] that matches `argv`,
    /// if any. Always `None` for an embedded-only [`Rules`] (see the struct
    /// docs) — only [`merge_user_config`] populates `ask_rules`.
    #[must_use]
    pub(crate) fn match_ask(&self, argv: &[NormalizedWord]) -> Option<&CommandRule> {
        self.ask_rules.iter().find(|rule| rule.matches(argv))
    }

    /// The first [`CommandRule`] for which [`CommandRule::matches_except_target`]
    /// holds, if any — plan.md §4's NEW argument-position refinement
    /// (`src/gate.rs`), covering both a bare `$VAR` and a `$()`/backtick
    /// substitution in target position (issue #34). Like [`Self::match_command`]/
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

    /// The first [`CommandRule`] for which [`CommandRule::matches_except_flags`]
    /// holds, if any — issue #42's NEW flags/tokens-only floor
    /// (`src/gate.rs`), covering a flags-only blocklist rule (`targets`
    /// empty) whose required flag/token might itself be hidden inside an
    /// unresolvable word. Like [`Self::match_command_except_target`], this
    /// is a read-only probe: it never mutates rule state and never itself
    /// constitutes a `Block`.
    #[must_use]
    pub(crate) fn match_command_except_flags(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        self.command_rules
            .iter()
            .find(|rule| rule.matches_except_flags(argv))
    }

    /// The first [`CommandRule`] for which
    /// [`CommandRule::matches_ascent_descent_floor`] holds, if any —
    /// issue #78's unresolved-ascent-then-descent floor (`src/gate.rs`).
    /// Like [`Self::match_command_except_target`], a read-only probe:
    /// never mutates rule state, never itself constitutes a match.
    #[must_use]
    pub(crate) fn match_command_ascent_descent(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        // A user-config `[[ask]]` rule (`ask_rules`) with its own
        // `normalized`/`normalized_prefix` target is just as eligible for
        // this floor as an embedded blocklist rule (`command_rules`) —
        // both are `CommandRule`s. Scanning only `command_rules` would
        // leave the literal-vs-ascent-obfuscated-spelling asymmetry alive
        // for user config: the literal spelling correctly Asks via the
        // rule itself, but an ascent-then-descent respelling of the same
        // target silently Allowed.
        self.command_rules
            .iter()
            .chain(self.ask_rules.iter())
            .find(|rule| rule.matches_ascent_descent_floor(argv))
    }

    /// The first [`CommandRule`] for which
    /// [`CommandRule::matches_named_user_home_floor`] holds, if any —
    /// issue #80's `~username` floor (`src/gate.rs`). Like
    /// [`Self::match_command_except_target`], a read-only probe: never
    /// mutates rule state, never itself constitutes a match.
    #[must_use]
    pub(crate) fn match_command_named_user_home(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        // A user-config `[[ask]]` rule (`ask_rules`) with its own
        // bare-`~` target is just as eligible for this floor as an
        // embedded blocklist rule (`command_rules`) — both are
        // `CommandRule`s. Scanning only `command_rules` would
        // leave the same `~username`-vs-bare-`~` asymmetry #80 fixed for
        // the blocklist alive for user config.
        self.command_rules
            .iter()
            .chain(self.ask_rules.iter())
            .find(|rule| rule.matches_named_user_home_floor(argv))
    }

    /// The first [`CommandRule`] for which
    /// [`CommandRule::matches_dirstack_tilde_floor`] holds, if any — issue
    /// #88's directory-stack tilde floor (`src/gate.rs`). Like
    /// [`Self::match_command_named_user_home`], scans both `command_rules`
    /// and `ask_rules` (a user-config rule with its own targets is just as
    /// eligible for this floor as an embedded one) and is a read-only
    /// probe: never mutates rule state, never itself constitutes a match.
    #[must_use]
    pub(crate) fn match_command_dirstack_tilde(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        self.command_rules
            .iter()
            .chain(self.ask_rules.iter())
            .find(|rule| rule.matches_dirstack_tilde_floor(argv))
    }

    /// The first [`CommandRule`] for which
    /// [`CommandRule::matches_directory_equals_tilde_floor`] holds, if any
    /// — issue #115's zsh `magic_equal_subst` floor (`src/gate.rs`). Like
    /// [`Self::match_command_named_user_home`], scans both
    /// `command_rules` and `ask_rules` (a user-config rule with the same
    /// `=`-terminated-strip + bare-`~`-target shape is just as eligible)
    /// and is a read-only probe: never mutates rule state, never itself
    /// constitutes a match.
    #[must_use]
    pub(crate) fn match_command_directory_equals_tilde(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        self.command_rules
            .iter()
            .chain(self.ask_rules.iter())
            .find(|rule| rule.matches_directory_equals_tilde_floor(argv))
    }

    /// The configured escalation floor (issues #35/#36, `crate::gate` rule
    /// 10): `Decision::Ask` unless a user config set `escalation_floor =
    /// "deny"` (see the struct docs and [`merge_user_config`]). Never
    /// `Decision::Allow` — rejected at user-config load time.
    #[must_use]
    pub(crate) fn escalation_floor(&self) -> Decision {
        self.escalation_floor
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
/// transparent wrapper name (`SHELL_INTERPRETERS`/`EXTRA_PIPELINE_INTERPRETERS`/
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
        .chain(EXTRA_PIPELINE_INTERPRETERS.iter())
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
    #[serde(default)]
    escalation_floor: Option<String>,
}

/// A user-supplied policy config, parsed and validated but not yet merged
/// with the embedded blocklist/allowlist — see [`merge_user_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserConfig {
    deny: Vec<CommandRule>,
    ask: Vec<CommandRule>,
    allow: Vec<CommandRule>,
    escalation_floor: Decision,
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
    /// moving arrays — an `allow` entry matching a shell interpreter or
    /// transparent wrapper name (see [`matches_dangerous_allow_target`]) —
    /// or an invalid `escalation_floor` value (see
    /// [`parse_escalation_floor`]; only `"ask"`/`"deny"` are accepted,
    /// `"allow"` is rejected here the same as it already is for `[[allow]]`
    /// entries naming an escalation vector).
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
        let escalation_floor = parse_escalation_floor(dto.escalation_floor.as_deref())?;

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

        Ok(Self {
            deny,
            ask,
            allow,
            escalation_floor,
        })
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
/// Block-immune before it even consults its entries. `escalation_floor`
/// folds via `max` rather than overwriting — see the inline comment at
/// that line for why an overwrite would be wrong given how
/// `src/config.rs`'s `Policy::load` calls this function more than once.
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

    // `.max()`, not overwrite: `Policy::load` (src/config.rs) calls this
    // function a second time per self-protection directory, with a
    // synthetic `UserConfig` that never sets `escalation_floor` (so it
    // parses to the `Ask` default). An overwrite there would silently
    // reset a real `escalation_floor = "deny"` from the user's own config
    // back to `Ask` on that second call. Folding via `max` instead makes
    // merging monotonic — it can only ever tighten the floor, matching
    // `crate::gate`'s own floor-folding (`decision.max(...)`) and this
    // module's fail-closed posture generally.
    let escalation_floor = blocklist.escalation_floor.max(user_config.escalation_floor);

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
            escalation_floor,
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

    // ---- FlagMatcher::Token also accepts a GNU "=value" suffix ----
    #[test]
    fn flag_matcher_token_matches_bare_flag() {
        let flag = FlagMatcher::parse("--in-place").unwrap();
        assert!(flag.satisfied(&["--in-place"]));
    }

    #[test]
    fn flag_matcher_token_matches_equals_suffix() {
        let flag = FlagMatcher::parse("--in-place").unwrap();
        assert!(flag.satisfied(&["--in-place=.bak"]));
    }

    #[test]
    fn flag_matcher_token_does_not_match_unrelated_suffix_without_equals() {
        let flag = FlagMatcher::parse("--in-place").unwrap();
        assert!(!flag.satisfied(&["--in-placefoo"]));
    }

    // ---- regression: --force-with-lease must not satisfy a --force token ----
    #[test]
    fn flag_matcher_token_force_with_lease_does_not_satisfy_force() {
        let flag = FlagMatcher::parse("--force").unwrap();
        assert!(!flag.satisfied(&["--force-with-lease"]));
    }

    #[test]
    fn git_push_force_with_lease_does_not_match_force_rule() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "git",
                    "push",
                    "--force-with-lease",
                    "origin",
                    "main"
                ]))
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

    // ==== Issue #78: an unresolved ascent-then-descent token (`../../dev/
    // sda`-shaped) floors to Ask via Rules::match_command_ascent_descent,
    // when it plausibly lands inside a rule's own NormalizedPrefix/
    // NormalizedExact namespace — distinct from ordinary match_command,
    // which must stay None (the ascent can't be proven, only flagged).
    // ====

    #[test]
    fn ascent_descent_dd_write_device_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["dd", "of=../../../../dev/sda"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "dd-write-device");
    }

    #[test]
    fn ascent_descent_rm_rf_dev_prefix_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "../../dev/sda"]);
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "rm-recursive-force-dangerous-target");
    }

    #[test]
    fn ascent_descent_etc_passwd_normalized_exact_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tee", "../../../etc/passwd"]);
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "tee-write-device-or-critical-file");
    }

    #[test]
    fn ascent_descent_self_protection_home_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["cp", "x", "../../../../.config/shguard/hooks/x"]);
        assert!(rules.match_command_ascent_descent(&cmd).is_some());
    }

    // ==== Issue #78 follow-up: the same ascent-descent gap,
    // but reached via shell redirect syntax (`> ...`) rather than argv,
    // which carries the identical /dev/*//etc/passwd//etc/shadow namespace
    // through a separate Rust type (RedirectRule, not CommandRule). ====

    #[test]
    fn ascent_descent_redirect_etc_passwd_floors() {
        let rules = Rules::embedded().unwrap();
        let rule = rules
            .match_redirect_target_ascent_descent("../../../../etc/passwd")
            .unwrap();
        assert_eq!(
            rule.id().as_str(),
            "redirect-overwrite-device-or-critical-file"
        );
    }

    #[test]
    fn ascent_descent_redirect_dev_prefix_floors() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_redirect_target_ascent_descent("../../../../dev/sda1")
                .is_some()
        );
    }

    #[test]
    fn ascent_descent_redirect_ordinary_sibling_file_does_not_floor() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_redirect_target_ascent_descent("../build/output.txt")
                .is_none()
        );
    }

    #[test]
    fn ascent_descent_ordinary_sibling_dir_does_not_floor() {
        // The issue's own explicit noise-guard example: no rule targets
        // `../build`'s namespace, so this must stay Allow.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-C", "../build", "-x", "-f", "a.tar"]);
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
    }

    #[test]
    fn ascent_descent_partial_prefix_does_not_floor() {
        // Near-miss: comps = ["dev"] alone, "/dev" does not start_with
        // "/dev/" — important regression guard for the forward-only
        // design (a token that hasn't yet spelled out the full dangerous
        // prefix must not trip the floor).
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["dd", "of=../../dev"]);
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
    }

    #[test]
    fn ascent_descent_pure_ascent_no_descent_unaffected() {
        // Pure ascent (no trailing comps) is the *existing* NormalizedExact
        // widening's territory, not this floor's — confirms no double-
        // counting between the two mechanisms.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["dd", "of=../../../.."]);
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
    }

    // ==== Issue #90: a `~`/`~username`-anchored ascent-then-descent token
    // (`~/../../dev/sda`, `~someuser/../../../dev/sda`-shaped) floors to
    // Ask the same way #78's bare-relative-ascent floor does — the
    // descended-into tail is no longer dropped by lexical_normalize once
    // the token has popped past its `~`/`~username` anchor. ====

    #[test]
    fn ascent_descent_home_escape_dd_write_device_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["dd", "of=~/../../dev/sda"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "dd-write-device");
    }

    #[test]
    fn ascent_descent_home_escape_etc_passwd_normalized_exact_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tee", "~/../../../etc/passwd"]);
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "tee-write-device-or-critical-file");
    }

    #[test]
    fn ascent_descent_named_user_home_escape_dd_write_device_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["dd", "of=~someuser/../../../dev/sda"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "dd-write-device");
    }

    #[test]
    fn ascent_descent_redirect_home_escape_etc_passwd_floors() {
        // The same lexical_normalize fix also closes this bypass via
        // shell redirect syntax (RedirectRule, a separate Rust type from
        // CommandRule sharing TargetMatcher underneath).
        let rules = Rules::embedded().unwrap();
        let rule = rules
            .match_redirect_target_ascent_descent("~/../../etc/passwd")
            .unwrap();
        assert_eq!(
            rule.id().as_str(),
            "redirect-overwrite-device-or-critical-file"
        );
    }

    #[test]
    fn ascent_descent_home_escape_tail_cancels_correctly() {
        // `..` after the escape point must still cancel the nearest
        // *post-escape* component (same cancel-nearest semantics as
        // PathForm::Rel's own comps) rather than being ignored — a
        // trailing cancel-to-empty must NOT floor.
        let rules = Rules::embedded().unwrap();
        let floors = argv(&["dd", "of=~/../a/../../dev/sda"]);
        let rule = rules.match_command_ascent_descent(&floors).unwrap();
        assert_eq!(rule.id().as_str(), "dd-write-device");
        let cancels_to_empty = argv(&["dd", "of=~/../dev/.."]);
        assert!(
            rules
                .match_command_ascent_descent(&cancels_to_empty)
                .is_none()
        );
    }

    #[test]
    fn ascent_descent_home_escape_ordinary_sibling_does_not_floor() {
        // The same noise-guard as the bare-relative-ascent case: an
        // escaped `~` token descending into an ordinary, non-dangerous
        // path must stay Allow.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["cp", "x", "~/../shared/file"]);
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
    }

    #[test]
    fn ascent_descent_home_escape_partial_prefix_does_not_floor() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["dd", "of=~/../../dev"]);
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
    }

    // ==== Issue #80: `~username` (another user's home) floors to Ask via
    // Rules::match_command_named_user_home, distinct from the certain
    // bare-`~` case above, which must keep hard-matching via match_command
    // unaffected. ====

    #[test]
    fn named_user_home_rm_rf_floors_but_does_not_hard_match() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~someuser"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_named_user_home(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "rm-recursive-force-dangerous-target");
    }

    #[test]
    fn named_user_home_tar_extract_dash_c_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "-C", "~alice", "-f", "a.tar"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_named_user_home(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "tar-extract-over-root-or-home");
    }

    #[test]
    fn named_user_home_tar_directory_ask_rule_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-C", "~bob", "-f", "a.tar"]);
        let rule = rules.match_command_named_user_home(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "tar-directory-root-or-home");
    }

    #[test]
    fn named_user_home_with_underscore_and_digits_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~user_2"]);
        assert!(rules.match_command_named_user_home(&cmd).is_some());
    }

    #[test]
    fn named_user_home_dotted_username_floors() {
        // Shells don't validate username syntax (`getpwnam` takes
        // anything up to the first `/`), so a dotted account name (common
        // on macOS/AD/sssd-joined Linux) must still floor — an
        // allowlist-shaped charset check would have missed it.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~john.doe"]);
        assert!(rules.match_command_named_user_home(&cmd).is_some());
    }

    #[test]
    fn named_user_home_trailing_slash_still_floors() {
        // A real shell takes the tilde-prefix as everything up to the
        // first `/`, so `~root/` expands to the same directory as
        // `~root` — verified via `printf '[%s]' ~root/`. Must not
        // silently collapse to Opaque the way a naive "reject any
        // embedded `/`" check would.
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["rm", "-rf", "~root/"]),
            argv(&["rm", "-rf", "~root//"]),
            argv(&["rm", "-rf", "~root/."]),
        ] {
            assert!(
                rules.match_command_named_user_home(&cmd).is_some(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn named_user_home_ascent_past_named_home_floors() {
        // `~alice/..`/`~alice/../..` provably left alice's home (mirrors
        // the existing EscapesHome widening for the invoker's own
        // `$HOME`), even though the exact resulting path (`/Users`, `/`,
        // ...) is unknown statically.
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["tar", "-x", "-C", "~alice/..", "-f", "a.tar"]),
            argv(&["tar", "-x", "-C", "~alice/../..", "-f", "a.tar"]),
        ] {
            assert!(
                rules.match_command_named_user_home(&cmd).is_some(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn named_user_home_dirstack_plus_does_not_floor() {
        // `~+` is NOT "safe" — a real shell expands it to `$PWD`, an
        // un-modeled gap distinct from this floor's own `~username`
        // scope; tracked as issue #88. This only asserts the new
        // NamedUserHome floor correctly stays out of the way of it.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~+"]);
        assert!(rules.match_command(&cmd).is_none());
        assert!(rules.match_command_named_user_home(&cmd).is_none());
    }

    #[test]
    fn named_user_home_dirstack_minus_does_not_floor() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~-"]);
        assert!(rules.match_command_named_user_home(&cmd).is_none());
    }

    #[test]
    fn named_user_home_dirstack_numbered_does_not_floor() {
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["rm", "-rf", "~5"]),
            argv(&["rm", "-rf", "~+3"]),
            argv(&["rm", "-rf", "~-3"]),
        ] {
            assert!(
                rules.match_command_named_user_home(&cmd).is_none(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn named_user_home_subdir_out_of_scope_does_not_floor() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~someuser/data"]);
        assert!(rules.match_command_named_user_home(&cmd).is_none());
    }

    #[test]
    fn named_user_home_floor_reachable_through_sudo_wrapper() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["sudo", "rm", "-rf", "~someuser"]);
        assert!(rules.match_command_named_user_home(&cmd).is_some());
    }

    #[test]
    fn named_user_home_floor_reachable_through_env_wrapper() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["env", "rm", "-rf", "~someuser"]);
        assert!(rules.match_command_named_user_home(&cmd).is_some());
    }

    #[test]
    fn named_user_home_own_bare_home_still_hard_matches() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~"]);
        assert!(rules.match_command(&cmd).is_some());
    }

    #[test]
    fn named_user_home_own_subdir_stays_out_of_scope() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~/foo"]);
        assert!(rules.match_command(&cmd).is_none());
        assert!(rules.match_command_named_user_home(&cmd).is_none());
    }

    // ==== Issue #88: a `~+`/`~-`/`~N`/`~+N`/`~-N` directory-stack tilde
    // token floors to Ask via Rules::match_command_dirstack_tilde — these
    // expand to `$PWD`/`$OLDPWD`/a numbered pushd/popd entry, an arbitrary
    // directory shguard has no cwd or directory stack to resolve against,
    // the same uncertainty a literal `$PWD`/`$OLDPWD` reference already
    // gets via the unresolved-`$VAR` floor (rule 4). ====

    #[test]
    fn dirstack_tilde_plus_floors_but_does_not_hard_match() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~+"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_dirstack_tilde(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "rm-recursive-force-dangerous-target");
    }

    #[test]
    fn dirstack_tilde_minus_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~-"]);
        assert!(rules.match_command_dirstack_tilde(&cmd).is_some());
    }

    #[test]
    fn dirstack_tilde_numbered_forms_floor() {
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["rm", "-rf", "~5"]),
            argv(&["rm", "-rf", "~+3"]),
            argv(&["rm", "-rf", "~-3"]),
        ] {
            assert!(
                rules.match_command_dirstack_tilde(&cmd).is_some(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn dirstack_tilde_dot_padded_forms_still_floor() {
        // Mirrors `~/.`/`~username/.` collapsing to their own bare forms:
        // trailing `.`/`//` noise doesn't defeat the bare-anchor shape.
        let rules = Rules::embedded().unwrap();
        for cmd in [argv(&["rm", "-rf", "~+/."]), argv(&["rm", "-rf", "~+//"])] {
            assert!(
                rules.match_command_dirstack_tilde(&cmd).is_some(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn dirstack_tilde_subdir_tail_stays_out_of_scope() {
        // A real subdirectory tail (`~-/etc/passwd`, an anchor that is
        // NOT cwd-relative like `~+` is) is deliberately out of #88's
        // scope, mirroring `~username/subdir`'s own boundary — tracked as
        // issue #133, not fixed here.
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["rm", "-rf", "~+/foo"]),
            argv(&["rm", "-rf", "~-/etc/passwd"]),
            argv(&["rm", "-rf", "~2/dev/sda"]),
        ] {
            assert!(rules.match_command(&cmd).is_none(), "{cmd:?}");
            assert!(
                rules.match_command_dirstack_tilde(&cmd).is_none(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn dirstack_tilde_escape_stays_out_of_scope() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~+/.."]);
        assert!(rules.match_command_dirstack_tilde(&cmd).is_none());
    }

    #[test]
    fn dirstack_tilde_floor_reachable_through_sudo_wrapper() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["sudo", "rm", "-rf", "~+"]);
        assert!(rules.match_command_dirstack_tilde(&cmd).is_some());
    }

    #[test]
    fn dirstack_tilde_stray_token_no_longer_floors_strip_only_rule() {
        // matches_dirstack_tilde_floor is correlated to a target's own
        // slot (`strip: None`), mirroring named_user_home/ascent_descent,
        // rather than firing on any dirstack-shaped token anywhere in the
        // tail. dd-write-device's sole target requires an attached `of=`
        // prefix — a bare, unattached `~+` can never occupy that slot
        // (`of=~+` doesn't tilde-expand in the first place, issue #134) —
        // so a stray `~+` elsewhere in the tail no longer floors this
        // rule to Ask.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["dd", "of=/tmp/safe-file", "~+"]);
        assert!(rules.match_command_dirstack_tilde(&cmd).is_none());
    }

    #[test]
    fn dirstack_tilde_stray_token_no_longer_floors_self_protect_dd() {
        // Same narrowing as above, for self-protect-config-dd-tilde,
        // whose targets are also all strip="of=".
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["dd", "of=/tmp/safe-file", "~-"]);
        assert!(rules.match_command_dirstack_tilde(&cmd).is_none());
    }

    // ==== Issue #115: a tilde attached directly after an `=`-terminated
    // flag (`--directory=~`, `--directory=~user`) floors to Ask via
    // Rules::match_command_directory_equals_tilde — zsh's magic_equal_subst
    // option (off by default) makes this shape shell-option-dependent,
    // unlike the certain, universal-across-shells bare-`~`-as-its-own-word
    // case. `-C~` (no `=`) stays unaffected and out of scope. ====

    #[test]
    fn directory_equals_tilde_bare_floors_but_does_not_hard_match() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "--directory=~", "-f", "a.tar"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_directory_equals_tilde(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "tar-extract-over-root-or-home");
    }

    #[test]
    fn directory_equals_tilde_named_user_floors() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "--directory=~alice", "-f", "a.tar"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_directory_equals_tilde(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "tar-extract-over-root-or-home");
    }

    #[test]
    fn directory_equals_tilde_escaping_home_floors() {
        // `--directory=~/..`/`--directory=~/.` — still provably an escape-
        // or-collapse-to-bare-home shape if magic_equal_subst expanded it.
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["tar", "-x", "--directory=~/..", "-f", "a.tar"]),
            argv(&["tar", "-x", "--directory=~/.", "-f", "a.tar"]),
        ] {
            assert!(
                rules.match_command_directory_equals_tilde(&cmd).is_some(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn directory_equals_tilde_dash_c_short_flag_does_not_floor() {
        // magic_equal_subst only ever matches an `=`-shaped word; `-C~` has
        // no `=`, so it's unaffected by the option and stays out of scope.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "-C~", "-f", "a.tar"]);
        assert!(rules.match_command(&cmd).is_none());
        assert!(rules.match_command_directory_equals_tilde(&cmd).is_none());
    }

    #[test]
    fn directory_equals_tilde_subdir_does_not_floor() {
        // `--directory=~/subdir` would expand outside this rule's own
        // dangerous namespace even if magic_equal_subst fired — the
        // separated-word equivalent (`tar -C ~/subdir -f a.tar`) is
        // already Allow today, so the attached form must not become
        // *stricter* than the form it's no more dangerous than.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "--directory=~/subdir", "-f", "a.tar"]);
        assert!(rules.match_command_directory_equals_tilde(&cmd).is_none());
    }

    #[test]
    fn directory_equals_tilde_dirstack_form_does_not_floor() {
        // `~+`/`~-`/`~N` are directory-stack shorthand (issue #88's
        // territory), not a `~`/`~user` shape this floor covers.
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["tar", "-x", "--directory=~+", "-f", "a.tar"]),
            argv(&["tar", "-x", "--directory=~-", "-f", "a.tar"]),
            argv(&["tar", "-x", "--directory=~5", "-f", "a.tar"]),
        ] {
            assert!(
                rules.match_command_directory_equals_tilde(&cmd).is_none(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn directory_equals_tilde_separated_bare_tilde_still_hard_matches() {
        // The already-working, certain, universal-across-shells baseline
        // (a bare `~` as its own space-separated word) must be unaffected
        // by this floor's addition — it keeps matching via `matches()`'s
        // own existing widening, not this floor.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "--directory", "~", "-f", "a.tar"]);
        assert!(rules.match_command(&cmd).is_some());
    }

    #[test]
    fn directory_equals_tilde_floor_reachable_through_env_wrapper() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["env", "tar", "-x", "--directory=~", "-f", "a.tar"]);
        assert!(rules.match_command_directory_equals_tilde(&cmd).is_some());
    }

    #[test]
    fn directory_equals_tilde_requires_an_equals_terminated_strip_on_the_rule() {
        // `rm-recursive-force-dangerous-target` has a bare-`~` target but
        // no `=`-terminated `strip` entry anywhere in its own targets —
        // magic_equal_subst's mechanism has nothing to do with rm's flags
        // at all, so a rule shaped like this must never floor on an
        // arbitrary `--flag=~token`, no matter what the flag is called.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "--totally-unrelated-flag=~"]);
        assert!(rules.match_command_directory_equals_tilde(&cmd).is_none());
    }

    // ==== CommandRule matching resolves basename + skips transparent
    // wrappers, the same way PipelineRule matching already does
    // (matches_command_and_flags goes through effective_command instead
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

    // ==== Issue #54: TRANSPARENT_WRAPPERS gained timeout/ionice/flock,
    // and skip_wrapper_arguments gained per-wrapper value-flag and
    // positional-argument tables ====

    #[test]
    fn rm_rf_root_matches_through_timeout_wrapper() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["timeout", "5", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn rm_rf_root_matches_through_ionice_wrapper() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["ionice", "-c3", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn rm_rf_root_matches_through_flock_wrapper() {
        // Pins the positional lock-target skip: without it `/tmp/l`
        // (basename `l`) would be mistaken for the command and `rm -rf /`
        // would never reach the rm rule.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["flock", "/tmp/l", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn rm_rf_root_matches_through_chrt_wrapper() {
        // Pins the positional priority skip: without it `99` would be
        // mistaken for the command and `rm -rf /` would never reach the
        // rm rule.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["chrt", "-f", "99", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn rm_rf_root_matches_through_taskset_wrapper() {
        // Pins the positional CPU-mask skip: without it `0x1` would be
        // mistaken for the command and `rm -rf /` would never reach the
        // rm rule.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["taskset", "0x1", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn wrapper_chain_escalation_finds_sudo_through_timeout() {
        assert_eq!(
            wrapper_chain_escalation(&argv(&["timeout", "5", "sudo", "ls"])),
            WrapperChainEscalation::Contains("sudo")
        );
    }

    #[test]
    fn nice_value_flag_does_not_hide_the_wrapped_command() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["nice", "-n", "19", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn sudo_value_flag_does_not_hide_the_wrapped_command() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["sudo", "-u", "root", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn doas_value_flag_does_not_hide_the_wrapped_command() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["doas", "-u", "root", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn timeout_value_flag_and_duration_are_both_skipped() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["timeout", "-s", "KILL", "5", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn su_positional_username_is_skipped() {
        // `su [options] [-] [user [args...]]`: the username occupies one
        // positional slot before the command su itself runs.
        //
        // UPDATED (issues #64/#66): `su`'s own `-c`/`--command` flag IS now
        // in `wrapper_value_flags`, but that alone doesn't change this
        // test's expectation — `skip_wrapper_flags` only recognises a
        // value flag occurring BEFORE the username positional is consumed
        // (`su -c 'sh' root`, options-before-user order), and this test
        // uses the opposite, user-before-options order (`su root -c sh`):
        // `root` is consumed by the positional slot first, leaving `-c` to
        // be mistaken for the *next* hop's resolved "command" name by
        // `effective_command`'s own walk, exactly as before. This still
        // pins that shape rather than asserting full correctness of `su
        // -c` through `effective_command` specifically — the actual
        // security fix for this exact word order is
        // `wrapper_shell_string_scripts`, which finds `su`'s `-c` flag
        // independent of word order by scanning `su`'s whole argument
        // tail rather than relying on `skip_wrapper_flags`'s boundary; see
        // `crate::gate`'s `su_dash_c_user_before_options_order_still_blocks`
        // test for the end-to-end behaviour this test's own narrower
        // `effective_command` shape doesn't capture.
        let words = argv(&["su", "root", "-c", "sh"]);
        let (name, rest) = effective_command(&words).unwrap();
        assert_eq!(name, "-c");
        assert_eq!(resolved_strings(rest), vec!["sh"]);
    }

    // ---- issue #54 follow-up: su_username_matches_blocklisted_command ----

    #[test]
    fn su_username_slot_matching_a_blocklist_command_name_is_found() {
        let rules = Rules::embedded().unwrap();
        let matched =
            su_username_matches_blocklisted_command(&argv(&["su", "rm", "-rf", "/"]), &rules)
                .unwrap();
        assert_eq!(matched.id().as_str(), "rm-recursive-force-dangerous-target");
    }

    #[test]
    fn su_username_slot_naming_a_real_user_is_not_flagged() {
        let rules = Rules::embedded().unwrap();
        assert!(
            su_username_matches_blocklisted_command(&argv(&["su", "alice", "-c", "ls"]), &rules)
                .is_none()
        );
    }

    #[test]
    fn su_username_shadow_check_sees_through_an_outer_wrapper() {
        let rules = Rules::embedded().unwrap();
        let matched = su_username_matches_blocklisted_command(
            &argv(&["env", "su", "rm", "-rf", "/"]),
            &rules,
        )
        .unwrap();
        assert_eq!(matched.id().as_str(), "rm-recursive-force-dangerous-target");
    }

    #[test]
    fn su_username_shadow_check_does_not_apply_to_sudo() {
        // sudo's user argument is always flag-introduced (`-u root`), so
        // there is no bare positional slot for a command name to land in
        // by coincidence — this check is `su`-specific.
        let rules = Rules::embedded().unwrap();
        assert!(
            su_username_matches_blocklisted_command(&argv(&["sudo", "rm", "-rf", "/"]), &rules)
                .is_none()
        );
    }

    // ==== Issue #114: TRANSPARENT_WRAPPERS gained busybox ====

    #[test]
    fn mkswap_matches_through_busybox_wrapper() {
        // The issue's own reproduction: `busybox mkswap /dev/sda1` behaves
        // identically to a bare `mkswap /dev/sda1` and must match the same
        // rule.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["busybox", "mkswap", "/dev/sda1"]))
                .is_some()
        );
    }

    #[test]
    fn rm_rf_root_matches_through_busybox_wrapper() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["busybox", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn wrapper_chain_escalation_finds_every_vector_through_busybox() {
        // Mirrors wrapper_chain_escalation_finds_each_escalation_vector's
        // "through env" case, but through busybox — every ESCALATION_VECTORS
        // entry must still floor when reached via busybox's empty flag/
        // positional tables, not just su. (A "vector before busybox", e.g.
        // `sudo busybox rm -rf /`, would be vacuous coverage here: the
        // per-hop ESCALATION_VECTORS check fires on `sudo` before
        // `busybox` is ever inspected, so that ordering can't exercise
        // busybox's TRANSPARENT_WRAPPERS membership at all — this loop
        // only tests the direction that actually depends on it.)
        for vector in ESCALATION_VECTORS {
            assert_eq!(
                wrapper_chain_escalation(&argv(&["busybox", vector, "whoami"])),
                WrapperChainEscalation::Contains(vector),
                "vector {vector:?} through busybox"
            );
        }
    }

    #[test]
    fn wrapper_chain_escalation_is_absent_for_busybox_alone() {
        // Guards against a future regression that adds busybox to
        // ESCALATION_VECTORS, contradicting TRANSPARENT_WRAPPERS' doc
        // comment ("busybox is a dispatcher, not a privilege-escalation
        // mechanism") with no test failing to catch it.
        assert_eq!(
            wrapper_chain_escalation(&argv(&["busybox", "rm", "-rf", "/"])),
            WrapperChainEscalation::Absent
        );
    }

    // ---- regression: the shadow check must match a rule's full
    // constraints, not just its command name, or a username that happens
    // to share a blocklisted command's name (a routine system account
    // like `git`) gets denied for a command it never ran ----

    #[test]
    fn su_username_naming_a_blocklisted_commands_own_account_is_not_flagged() {
        // `git` is `git-push-force`'s command name, but bare `su - git`
        // never runs `push --force` — the earlier name-only shadow check
        // matched anyway. Constraint-checked matching correctly leaves this
        // to the generic su escalation floor instead.
        let rules = Rules::embedded().unwrap();
        assert!(
            su_username_matches_blocklisted_command(&argv(&["su", "-", "git"]), &rules).is_none()
        );
    }

    #[test]
    fn su_username_with_trailing_args_that_do_not_satisfy_the_rule_is_not_flagged() {
        // Same false positive, with trailing arguments present: `-c "git
        // pull"` never satisfies `git-push-force`'s required push/--force
        // flags, so this must not be flagged either.
        let rules = Rules::embedded().unwrap();
        assert!(
            su_username_matches_blocklisted_command(
                &argv(&["su", "git", "-c", "git pull"]),
                &rules
            )
            .is_none()
        );
    }

    #[test]
    fn su_username_with_trailing_args_that_do_satisfy_the_rule_is_flagged() {
        // The positive counterpart: when the username slot and its
        // trailing arguments, read as their own command line, genuinely
        // satisfy a rule's full constraints (not just its name), the shadow
        // check must still catch it.
        let rules = Rules::embedded().unwrap();
        let matched = su_username_matches_blocklisted_command(
            &argv(&["su", "git", "push", "--force", "origin", "main"]),
            &rules,
        )
        .unwrap();
        assert_eq!(matched.id().as_str(), "git-push-force");
    }

    #[test]
    fn flock_fd_form_fails_closed() {
        // `flock -x 9` with no trailing command: the flag consumes `-x`,
        // the positional table consumes `9` as the (wrong, but
        // structurally indistinguishable) lock-target slot, and nothing
        // is left — effective_command must fail closed to None rather
        // than guess past the end of argv.
        assert!(effective_command(&argv(&["flock", "-x", "9"])).is_none());
    }

    #[test]
    fn timeout_long_signal_value_flag_does_not_hide_the_wrapped_command() {
        // Regression: wrapper_value_flags originally listed only the short
        // spelling (`-s`), so `--signal`'s separated value fell through to
        // the duration positional and the real command was never reached.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "timeout", "--signal", "KILL", "5", "rm", "-rf", "/"
                ]))
                .is_some()
        );
    }

    #[test]
    fn flock_own_value_flags_do_not_hide_the_wrapped_command() {
        // Regression: flock had no wrapper_value_flags entry at all, so
        // `-w`'s separated timeout value was mistaken for the lock-target
        // positional and the lockfile path became the resolved command.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["flock", "-w", "10", "/tmp/l", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn flock_end_of_options_marker_does_not_hide_the_wrapped_command() {
        // Regression: a `--` end-of-options marker following the
        // lock-target positional (`flock <file> -- command`) was itself
        // resolved as the wrapped command, matching no rule.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["flock", "-x", "/tmp/l", "--", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    // ---- regression: a positional slot's value must fail closed the
    // same as a flag-skipped value, instead of being blindly counted past
    // regardless of resolution ----

    fn argv_with_unresolvable_at(words: &[&str], unresolvable_at: usize) -> Vec<NormalizedWord> {
        let mut out: Vec<NormalizedWord> =
            words.iter().map(|w| NormalizedWord::resolved(*w)).collect();
        out[unresolvable_at] =
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion);
        out
    }

    #[test]
    fn timeout_positional_duration_unresolvable_fails_closed_to_unresolved() {
        // An unresolvable duration must fail closed: skipping past it
        // unconditionally would resolve `ls` as the wrapped command —
        // `allow`, even though the real duration (and therefore whether
        // this is really `timeout ... ls` at all) is unknown.
        let stage = argv_with_unresolvable_at(&["timeout", "X", "ls"], 1);
        assert_eq!(
            wrapper_chain_escalation(&stage),
            WrapperChainEscalation::Unresolved
        );
        assert!(effective_command(&stage).is_none());
    }

    #[test]
    fn flock_positional_lockfile_unresolvable_fails_closed_to_unresolved() {
        let stage = argv_with_unresolvable_at(&["flock", "X", "ls"], 1);
        assert_eq!(
            wrapper_chain_escalation(&stage),
            WrapperChainEscalation::Unresolved
        );
        assert!(effective_command(&stage).is_none());
    }

    #[test]
    fn timeout_positional_duration_resolved_still_recurses_normally() {
        // Same shape, resolved value: the positional value is skipped,
        // `ls` is the wrapped command.
        let stage = argv(&["timeout", "5", "ls"]);
        let (name, rest) = effective_command(&stage).unwrap();
        assert_eq!(name, "ls");
        assert!(rest.is_empty());
    }

    // ---- regression: a value-flag's separated value must fail closed
    // the same as a positional value — the same "blind skip regardless
    // of resolution" class, found lurking one function over in
    // skip_wrapper_flags ----

    #[test]
    fn nice_value_flags_separated_value_unresolvable_fails_closed_to_unresolved() {
        // `nice -n $X ls`: skipping `-n`'s separated value unconditionally
        // would resolve `ls` as the wrapped command and verdict `allow`,
        // even though the real flag value is unknown.
        let stage = argv_with_unresolvable_at(&["nice", "-n", "X", "ls"], 2);
        assert_eq!(
            wrapper_chain_escalation(&stage),
            WrapperChainEscalation::Unresolved
        );
        assert!(effective_command(&stage).is_none());
    }

    #[test]
    fn timeout_value_flags_separated_value_unresolvable_fails_closed_to_unresolved() {
        let stage = argv_with_unresolvable_at(&["timeout", "-s", "X", "5", "ls"], 2);
        assert_eq!(
            wrapper_chain_escalation(&stage),
            WrapperChainEscalation::Unresolved
        );
        assert!(effective_command(&stage).is_none());
    }

    #[test]
    fn nice_value_flags_separated_value_resolved_still_recurses_normally() {
        // Same shape, resolved value: recurses normally.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["nice", "-n", "19", "rm", "-rf", "/"]))
                .is_some()
        );
    }

    #[test]
    fn nice_value_flag_with_no_following_token_fails_closed() {
        // `nice -n` with nothing after it: the flag is consumed, there is
        // no value token to check at all — must not guess past the end.
        assert!(effective_command(&argv(&["nice", "-n"])).is_none());
    }

    #[test]
    fn wrapper_chain_escalation_finds_sudo_through_env_wrapper() {
        assert_eq!(
            wrapper_chain_escalation(&argv(&["sudo", "whoami"])),
            WrapperChainEscalation::Contains("sudo")
        );
        assert_eq!(
            wrapper_chain_escalation(&argv(&["env", "sudo", "ls"])),
            WrapperChainEscalation::Contains("sudo")
        );
        assert_eq!(
            wrapper_chain_escalation(&argv(&["/usr/bin/sudo", "ls"])),
            WrapperChainEscalation::Contains("sudo")
        );
        assert_eq!(
            wrapper_chain_escalation(&argv(&["env", "ls"])),
            WrapperChainEscalation::Absent
        );
        assert_eq!(
            wrapper_chain_escalation(&argv(&["ls", "sudo"])),
            WrapperChainEscalation::Absent
        );
    }

    #[test]
    fn wrapper_chain_escalation_finds_each_escalation_vector() {
        // issues #35/#36: doas/su/pkexec/run0 must be classified `Contains`
        // exactly like sudo, both bare and through another wrapper.
        for vector in ESCALATION_VECTORS {
            assert_eq!(
                wrapper_chain_escalation(&argv(&[vector, "whoami"])),
                WrapperChainEscalation::Contains(vector),
                "vector {vector:?} bare"
            );
            assert_eq!(
                wrapper_chain_escalation(&argv(&["env", vector, "whoami"])),
                WrapperChainEscalation::Contains(vector),
                "vector {vector:?} through env"
            );
        }
    }

    #[test]
    fn wrapper_chain_escalation_fails_closed_on_unresolvable_wrapped_command() {
        // `env $(echo sudo) ls` / `env $SUDO ls`: past a wrapper, an
        // unresolvable word could be sudo itself — Unresolved, never Absent.
        let mut past_wrapper = argv(&["env"]);
        past_wrapper.push(NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::CommandSubstitution,
        ));
        past_wrapper.extend(argv(&["ls"]));
        assert_eq!(
            wrapper_chain_escalation(&past_wrapper),
            WrapperChainEscalation::Unresolved
        );

        // An unresolvable FIRST word is command-position unresolvability —
        // gate rules 1/2 own it, so this helper reports Absent.
        assert_eq!(
            wrapper_chain_escalation(&unresolvable_first(&["ls"])),
            WrapperChainEscalation::Absent
        );
    }

    #[test]
    fn every_escalation_vector_is_a_transparent_wrapper() {
        // matches_dangerous_allow_target (the `[[allow]]` rejection) walks
        // TRANSPARENT_WRAPPERS, not ESCALATION_VECTORS — an escalation
        // vector missing from TRANSPARENT_WRAPPERS would silently become
        // allow-listable, so this invariant must hold without relying on
        // the two lists being edited in lockstep by eye.
        for vector in ESCALATION_VECTORS {
            assert!(
                TRANSPARENT_WRAPPERS.contains(vector),
                "{vector:?} must be in TRANSPARENT_WRAPPERS"
            );
        }
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

    // issue #58 E1-1: --size long form wasn't OR'd into required_flags.
    #[test]
    fn truncate_dash_dash_size_zero_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["truncate", "--size=0", "x"]))
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

    // issue #57: mke2fs is the implementation behind mkfs.ext4 on
    // Debian/Ubuntu but isn't matched by the `mkfs.` command_prefix rule.
    #[test]
    fn mke2fs_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["mke2fs", "-t", "ext4", "/dev/sda1"]))
                .is_some()
        );
    }

    #[test]
    fn tar_extract_into_root_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["tar", "-xf", "evil.tar", "-C", "/"]))
                .is_some()
        );
    }

    #[test]
    fn tar_extract_into_relative_dir_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["tar", "-xf", "x.tar", "-C", "./build"]))
                .is_none()
        );
    }

    // ==== issue #67: tar dash-less clustered invocation (`tar xfC a.tar /`) ====

    // Headline case: the fully dash-less old-style cluster `xfC` glues
    // extract (`x`), file (`f`), and directory (`C`) together with no
    // leading `-` at all. `tar_dashless_rewrite` must see through this the
    // same way it already sees through the dashed `-xfC`/`-xf -C`
    // spellings, landing on the block rule (both `x` and `C` present,
    // `-C`'s captured value is `/`).
    #[test]
    fn tar_dashless_cluster_extract_into_root_matches_block() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "xfC", "evil.tar", "/"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    // Regression: the pre-existing dash-aware form (`x` dash-less, `-C`
    // already dashed) must keep getting exactly the decision it got before
    // this fix — `tar_dashless_rewrite` only fires when a single dash-less
    // cluster carries *both* `x` and `C` together, so a bare `xf` (no `C`)
    // is left untouched and the separate `-C /` is picked up by
    // tar-directory-root-or-home alone, same as always.
    #[test]
    fn tar_dashless_x_only_cluster_with_separate_dashed_c_still_asks() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "xf", "evil.tar", "-C", "/"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Ask);
        assert_eq!(matched.id().as_str(), "tar-directory-root-or-home");
    }

    // Critical negative: an ordinary dash-less tar invocation with no `C`
    // at all (create, gzip, verbose — no directory change) must never be
    // caught by the dash-less rewrite. `tar_dashless_rewrite` requires
    // both `x` and `C` in the same cluster before it rewrites anything, so
    // `cfz` (no `x`, no `C`) is passed through unchanged.
    #[test]
    fn tar_dashless_create_cluster_without_directory_change_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["tar", "cfz", "archive.tar.gz", "somedir/"]))
                .is_none()
        );
    }

    // Verifies the rewrite's synthetic `-P`
    // token is seen by the separate `tar-absolute-names-ask` rule exactly
    // as a written-with-dashes `-P` would be. Uses a non-root `-C` target
    // (`/tmp/foo`) so the higher-priority over-root/home block/ask rules
    // don't fire first and mask this rule's own match.
    #[test]
    fn tar_dashless_cluster_with_p_letter_matches_absolute_names_ask() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "xfCP", "evil.tar", "/tmp/foo"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Ask);
        assert_eq!(matched.id().as_str(), "tar-absolute-names-ask");
    }

    // ==== issue #86: matching_rest_by_name gained the same tar-dashless
    // rewrite matching_rest already had, so matches_except_target/
    // matches_except_flags can see a dash-less x+C cluster's flags too ====

    #[test]
    fn tar_dashless_cluster_except_target_finds_extract_over_root_rule() {
        // The issue's own repro shape: `tar xfC a.tar $(echo /)` — see
        // matching_rest_by_name's docs for why matches_except_target must
        // see `-x`/`-C` inside the un-rewritten `xfC` cluster.
        let rules = Rules::embedded().unwrap();
        let cmd = {
            let mut v = argv(&["tar", "xfC", "a.tar"]);
            v.push(NormalizedWord::unresolvable(
                crate::normalize::UnresolvableKind::CommandSubstitution,
            ));
            v
        };
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_except_target(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "tar-extract-over-root-or-home");
    }

    #[test]
    fn tar_already_dashed_except_target_unaffected_by_rewrite() {
        // Regression guard: an ordinary, already-dashed tar command (no
        // dash-less cluster to rewrite) must keep finding the same rule
        // it always did.
        let rules = Rules::embedded().unwrap();
        let cmd = {
            let mut v = argv(&["tar", "-x", "-f", "a.tar", "-C"]);
            v.push(NormalizedWord::unresolvable(
                crate::normalize::UnresolvableKind::CommandSubstitution,
            ));
            v
        };
        let rule = rules.match_command_except_target(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "tar-extract-over-root-or-home");
    }

    #[test]
    fn tar_dashless_unmodeled_cluster_except_flags_unaffected_by_rewrite() {
        // `xbfC` is a plausible dash-less cluster (all-alphabetic,
        // contains `x`) but `b` isn't in TAR_DASHLESS_CONSUMING/BOOLEAN,
        // so tar_dashless_rewrite returns None (TarDashlessCluster::Unmodeled)
        // and matching_rest_by_name's new Cow fallback must return the
        // ORIGINAL tail unchanged, exactly as it did before this fix —
        // exercising the map_or(Cow::Borrowed(tail), ...) fallback branch
        // without panicking or changing which rule matches_except_flags
        // finds. (The Unmodeled shape itself always separately floors to
        // Ask via crate::gate::scan_tar_dashless_unmodeled_floor,
        // regardless of this rewrite — untouched by this fix.)
        let rules = Rules::embedded().unwrap();
        let cmd = {
            let mut v = argv(&["tar", "xbfC", "a.tar"]);
            v.push(NormalizedWord::unresolvable(
                crate::normalize::UnresolvableKind::CommandSubstitution,
            ));
            v
        };
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "tar-absolute-names-ask");
    }

    #[test]
    fn tar_dashless_recognized_cluster_avoids_double_counting_in_except_flags() {
        // The invariant matches_except_flags's own docs promise: "a rule
        // already fully satisfied by resolved words alone is matches's
        // job, not this one's". `xPfC` rewrites to `-x -P -f a.tar -C
        // /tmp`, which fully (and strictly) satisfies tar-absolute-names-
        // ask's required_flags (x + P) via resolved words alone — before
        // this fix, matches_except_flags couldn't see that (the un-
        // rewritten `xPfC` token satisfies neither `-x` nor `-P`
        // literally), so it would have wrongly returned true here too,
        // double-counting the same rule as both a full match and a floor.
        //
        // The trailing unresolvable word is load-bearing: without it,
        // `has_unresolvable` is false and `matches_except_flags` returns
        // `None` unconditionally (via its own separate, unrelated guard),
        // regardless of whether the rewrite fires — which would make this
        // test pass even if `matching_rest_by_name`'s rewrite step were
        // deleted.
        let rules = Rules::embedded().unwrap();
        let cmd = {
            let mut v = argv(&["tar", "xPfC", "a.tar", "/tmp/foo"]);
            v.push(NormalizedWord::unresolvable(
                crate::normalize::UnresolvableKind::CommandSubstitution,
            ));
            v
        };
        let matched = rules.match_command(&cmd).unwrap();
        assert_eq!(matched.id().as_str(), "tar-absolute-names-ask");
        assert!(rules.match_command_except_flags(&cmd).is_none());
    }

    // ==== issue #68: tar -P/--absolute-names bypasses -C entirely ====

    #[test]
    fn tar_extract_with_absolute_names_short_flag_asks() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "-xf", "evil.tar", "-P"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Ask);
        assert_eq!(matched.id().as_str(), "tar-absolute-names-ask");
    }

    #[test]
    fn tar_extract_with_absolute_names_long_flag_asks() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "-xf", "evil.tar", "--absolute-names"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Ask);
        assert_eq!(matched.id().as_str(), "tar-absolute-names-ask");
    }

    // Negative: -P without an extract flag (creating an archive) must not
    // match tar-absolute-names-ask — required_flags requires BOTH the
    // extract flag and -P, not just -P alone.
    #[test]
    fn tar_create_with_absolute_names_does_not_match_absolute_names_rule() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["tar", "cf", "archive.tar", "somedir/", "-P"]))
                .is_none(),
            "tar create with -P must not match any tar rule (no extract flag present)"
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

    // tee/cp/install/sed/dd on the bare directory (no trailing slash) —
    // same class of bug as rm/mv/unlink/ln above: these five commands only
    // had a `prefix = "~/.config/shguard/"` target until issue #28 item 2
    // added the bare-directory `exact` alternative to match.
    #[test]
    fn self_protect_tee_literal_tilde_directory_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["tee", "~/.config/shguard"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_cp_literal_tilde_directory_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["cp", "-r", "~/.config/shguard", "/tmp/backup"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_install_literal_tilde_directory_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["install", "evil.toml", "~/.config/shguard"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_sed_literal_tilde_directory_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["sed", "-i", "s/x/y/", "~/.config/shguard"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_dd_of_literal_tilde_directory_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["dd", "if=/dev/zero", "of=~/.config/shguard"]))
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

    #[test]
    fn self_protect_sed_in_place_long_option_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "sed",
                    "--in-place",
                    "s/x/y/",
                    "~/.config/shguard/config.toml"
                ]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_sed_in_place_equals_suffix_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "sed",
                    "--in-place=.bak",
                    "s/x/y/",
                    "~/.config/shguard/config.toml"
                ]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_rm_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rm", "~/.config/shguard/config.toml"]))
                .is_some()
        );
    }

    // rm -r on the bare directory (no trailing slash) — issue #22's core
    // scenario, deleting the whole config directory in one shot.
    #[test]
    fn self_protect_rm_recursive_literal_tilde_directory_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rm", "-r", "~/.config/shguard"]))
                .is_some()
        );
    }

    // mv on the bare directory (no trailing slash) — same class of bug as
    // `self_protect_rm_recursive_literal_tilde_directory_matches` above:
    // moving the whole config directory away silently reverts the user's
    // custom deny policy to embedded-only, the exact impact issue #22 is
    // about.
    #[test]
    fn self_protect_mv_literal_tilde_directory_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["mv", "~/.config/shguard", "/tmp/backup"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_unlink_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["unlink", "~/.config/shguard/config.toml"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_ln_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "ln",
                    "-sf",
                    "/dev/null",
                    "~/.config/shguard/config.toml"
                ]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_rm_unrelated_file_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(rules.match_command(&argv(&["rm", "a.txt"])).is_none());
    }

    // rsync (issue #59 E2-1): same bare-destination shape as cp, so it gets
    // the same targets pattern with no required_flags.
    #[test]
    fn self_protect_rsync_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rsync", "-a", "./payload/", "~/.config/shguard/"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_rsync_unrelated_files_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rsync", "-a", "./src/", "./dst/"]))
                .is_none()
        );
    }

    // ==== issue #101 audit: additional primitives + ancestor coverage,
    // literal-tilde side ====

    #[test]
    fn self_protect_rmdir_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rmdir", "~/.config/shguard"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_perl_in_place_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "perl",
                    "-i",
                    "-pe",
                    "s/a/b/",
                    "~/.config/shguard/config.toml"
                ]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_perl_without_in_place_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "perl",
                    "-pe",
                    "s/a/b/",
                    "~/.config/shguard/config.toml"
                ]))
                .is_none()
        );
    }

    #[test]
    fn self_protect_patch_literal_tilde_matches() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["patch", "~/.config/shguard/config.toml", "p.diff"]))
                .is_some()
        );
    }

    #[test]
    fn self_protect_find_exec_literal_tilde_asks() {
        let rules = Rules::embedded().unwrap();
        let rule = rules
            .match_command(&argv(&[
                "find",
                "~/.config/shguard",
                "-exec",
                "rm",
                "{}",
                ";",
            ]))
            .unwrap();
        assert_eq!(rule.decision(), Decision::Ask);
    }

    #[test]
    fn self_protect_find_without_exec_flag_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "find",
                    "~/.config/shguard",
                    "-name",
                    "config.toml"
                ]))
                .is_none()
        );
    }

    #[test]
    fn self_protect_ancestor_rm_literal_tilde_asks() {
        let rules = Rules::embedded().unwrap();
        let rule = rules
            .match_command(&argv(&["rm", "-r", "~/.config"]))
            .unwrap();
        assert_eq!(rule.decision(), Decision::Ask);

        let rule = rules.match_command(&argv(&["rm", "-r", "~"])).unwrap();
        assert_eq!(rule.decision(), Decision::Ask);
    }

    // Regression pin (fable review of #205): the ancestor rm rule's
    // required_flags initially only recognized lowercase `-r`, missing
    // the equally-standard uppercase `-R` recursive spelling GNU/BSD rm
    // both accept (`rm -R ~/.config` resolved Allow before this fix).
    #[test]
    fn self_protect_ancestor_rm_capital_r_literal_tilde_asks() {
        let rules = Rules::embedded().unwrap();
        let rule = rules
            .match_command(&argv(&["rm", "-R", "~/.config"]))
            .unwrap();
        assert_eq!(rule.decision(), Decision::Ask);

        let rule = rules.match_command(&argv(&["rm", "-R", "~"])).unwrap();
        assert_eq!(rule.decision(), Decision::Ask);
    }

    #[test]
    fn self_protect_ancestor_mv_literal_tilde_asks() {
        let rules = Rules::embedded().unwrap();
        let rule = rules
            .match_command(&argv(&["mv", "~/.config", "/tmp/x"]))
            .unwrap();
        assert_eq!(rule.decision(), Decision::Ask);
    }

    #[test]
    fn self_protect_ancestor_rsync_delete_literal_tilde_asks() {
        let rules = Rules::embedded().unwrap();
        let rule = rules
            .match_command(&argv(&["rsync", "-a", "--delete", "/tmp/x/", "~/.config/"]))
            .unwrap();
        assert_eq!(rule.decision(), Decision::Ask);
    }

    #[test]
    fn self_protect_ancestor_rsync_without_delete_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rsync", "-a", "./src/", "~/.config/other/"]))
                .is_none()
        );
    }

    #[test]
    fn self_protect_ancestor_mv_unrelated_target_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["mv", "~/.config/other-app", "/tmp/backup"]))
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
        // `rm-recursive-force-dangerous-target` requires BOTH `r` and `f` —
        // having only `-r` must not satisfy *that* rule's flag gating, even
        // with an unresolvable tail. `match_command_except_target` may
        // still return the flagless `self-protect-config-rm-tilde` rule
        // instead (the same fail-safe "unresolvable target could be
        // anything" refinement issue #22 extends to `rm`, already present
        // for `cp`/`tee`/`mv`/`install`/`dd`) — what must not happen is the
        // *dangerous-target* rule firing on an incomplete flag set.
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["rm", "-r"]);
        let matched = rules.match_command_except_target(&cmd);
        assert_ne!(
            matched.map(|rule| rule.id().as_str()),
            Some("rm-recursive-force-dangerous-target")
        );
    }

    // Companion to the test above (same class as
    // `matches_except_flags_positional_discipline_rejects_wrong_subcommand`'s
    // own companion `matches_except_flags_still_fires_via_a_different_rule_for_the_right_subcommand`):
    // an `assert_ne` on one rule id alone would still pass if NO rule
    // matched at all — a silent regression. Pin the positive expectation:
    // the same argv still floors to `self-protect-config-rm-tilde`
    // (flagless, targets the config directory), since its lack of a
    // `required_flags` constraint means the missing `-f` never disqualifies
    // it the way it disqualifies `rm-recursive-force-dangerous-target`.
    #[test]
    fn except_target_requires_required_flags_too_still_fires_self_protect_rule() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["rm", "-r"]);
        let matched = rules.match_command_except_target(&cmd);
        assert_eq!(
            matched.map(|rule| rule.id().as_str()),
            Some("self-protect-config-rm-tilde")
        );
    }

    // ==== Issue #85: matches_except_target's third relaxation — a
    // required flag AND the target hidden together, entire tail
    // unresolvable ====

    fn all_unresolvable_tail(command: &str, n: usize) -> Vec<NormalizedWord> {
        let mut out = vec![NormalizedWord::resolved(command)];
        out.extend((0..n).map(|_| {
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution)
        }));
        out
    }

    #[test]
    fn except_target_fires_when_flag_and_target_share_one_opaque_word() {
        // sed $(echo -i ~/.config/shguard/config.toml) — one substitution
        // supplying both the flag and the target at runtime.
        let rules = Rules::embedded().unwrap();
        let cmd = all_unresolvable_tail("sed", 1);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_except_target(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-sed-tilde");
    }

    #[test]
    fn except_target_fires_when_flag_and_target_are_two_sibling_opaque_words() {
        // sed $(printf -- -i) $(printf ~/.config/shguard/config.toml) —
        // flag and target each hidden in their own separate substitution.
        let rules = Rules::embedded().unwrap();
        let cmd = all_unresolvable_tail("sed", 2);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_except_target(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-sed-tilde");
    }

    #[test]
    fn except_target_does_not_fire_when_a_resolved_token_survives_in_the_tail() {
        // sed 's/x/y/' /some/normal/file $(compute-suffix) — a resolved
        // script and a resolved, non-matching file both survive alongside
        // one incidental unresolvable arg. The third relaxation requires
        // the ENTIRE tail to be unresolvable precisely so this stays
        // Allow — resolved content elsewhere must not be swept up just
        // because *some* word in the same invocation is opaque.
        let rules = Rules::embedded().unwrap();
        let mut cmd = argv(&["sed", "s/x/y/", "/some/normal/file"]);
        cmd.push(NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::CommandSubstitution,
        ));
        assert!(rules.match_command_except_target(&cmd).is_none());
    }

    #[test]
    fn except_target_third_relaxation_requires_a_required_flag_or_token() {
        // A target-only rule (no required_flags/required_tokens) already
        // gets an all-opaque tail via the first relaxation's trivially-true
        // constraints_match — the third relaxation must not double up on
        // (or otherwise be needed for) that shape. Confirmed via `unlink`,
        // whose only command rule is the flagless
        // `self-protect-config-unlink-tilde` (no sibling target-only rule
        // to introduce ambiguity about which one `.find()` returns first).
        let rules = Rules::embedded().unwrap();
        let cmd = all_unresolvable_tail("unlink", 1);
        let rule = rules.match_command_except_target(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-unlink-tilde");
    }

    // ==== NEW rule 4b partial-match API: matches_except_flags /
    // match_command_except_flags (issue #42, src/gate.rs) ====

    #[test]
    fn matches_except_flags_finds_hidden_find_delete_flag() {
        let rules = Rules::embedded().unwrap();
        let cmd = vec![
            NormalizedWord::resolved("find"),
            NormalizedWord::resolved("."),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
        ];
        // the ordinary full match must miss (the literal "-delete"
        // spelling isn't in any resolved word)
        assert!(rules.match_command(&cmd).is_none());
        // but the except-flags probe must catch it
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "find-delete");
    }

    #[test]
    fn matches_except_flags_finds_hidden_truncate_flag() {
        let rules = Rules::embedded().unwrap();
        let cmd = vec![
            NormalizedWord::resolved("truncate"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
            NormalizedWord::resolved("0"),
            NormalizedWord::resolved("file.db"),
        ];
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "truncate-zero");
    }

    #[test]
    fn matches_except_flags_finds_hidden_git_push_force_flag() {
        let rules = Rules::embedded().unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("push"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
            NormalizedWord::resolved("origin"),
            NormalizedWord::resolved("main"),
        ];
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-push-force");
    }

    #[test]
    fn matches_except_flags_never_fires_for_a_rule_with_non_empty_targets() {
        // `rm-recursive-force-dangerous-target` (and
        // `self-protect-config-rm-tilde`) both have a `targets` list —
        // rule 4's `matches_except_target` already covers this shape;
        // rule 4b must stay out of the way.
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["rm", "-rf"]);
        assert!(rules.match_command_except_target(&cmd).is_some());
        assert!(rules.match_command_except_flags(&cmd).is_none());
    }

    #[test]
    fn matches_except_flags_never_fires_for_a_rule_with_no_flag_or_token_constraint() {
        // `shred` has no `required_flags`/`required_tokens` at all — any
        // invocation is already a full match via `matches()`; rule 4b has
        // nothing left to refine.
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["shred"]);
        assert!(rules.match_command(&cmd).is_some());
        assert!(rules.match_command_except_flags(&cmd).is_none());
    }

    #[test]
    fn matches_except_flags_does_not_fire_when_fully_resolved_and_clean() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["find", ".", "-name", "foo"]);
        assert!(rules.match_command(&cmd).is_none());
        assert!(rules.match_command_except_flags(&cmd).is_none());
    }

    #[test]
    fn matches_except_flags_is_false_when_already_a_full_strict_match() {
        // `-delete` is already present as a resolved word — the ordinary
        // match already fires; rule 4b must not also claim this case (no
        // double-counting between the two floors).
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["find", ".", "-delete"]);
        assert!(rules.match_command(&cmd).is_some());
        assert!(rules.match_command_except_flags(&cmd).is_none());
    }

    #[test]
    fn matches_except_flags_positional_discipline_rejects_wrong_subcommand() {
        // `git-push-force` requires `required_tokens = ["push"]`; a
        // resolved "commit" at that position proves the miss is real
        // regardless of what an unresolvable word elsewhere might be — this
        // rule specifically must not treat a `git commit` invocation as if
        // it might be `git push --force`.
        //
        // This does NOT mean the command floors to no rule at all in
        // general: an unresolvable word NOT immediately consumed as a
        // declared `value_flags` entry's value still matches
        // `git-commit-no-verify-short` for the right subcommand — see
        // `matches_except_flags_still_fires_for_the_right_subcommand_when_not_consumed`
        // below (an `assert_ne` on one rule ID alone can misleadingly
        // read as "no floor fires"). This particular argv (`-m`
        // immediately before the unresolvable word)
        // floors to no rule at all post-issue-#146, since
        // `git-commit-no-verify-short`'s declared `value_flags = ["m",
        // "message"]` now consumes it — see
        // `matches_except_flags_value_flags_suppresses_the_floor_for_a_consumed_word`.
        let rules = Rules::embedded().unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
        ];
        let matched = rules.match_command_except_flags(&cmd);
        assert_ne!(
            matched.map(|rule| rule.id().as_str()),
            Some("git-push-force")
        );
    }

    #[test]
    fn matches_except_flags_value_flags_suppresses_the_floor_for_a_consumed_word() {
        // issue #146: same argv as the test above (`git commit -m
        // <unresolvable>`), with the unresolvable word constructed as
        // `unresolvable_single_word` — simulating a QUOTED substitution
        // (`git commit -m "$(...)"`), which IS guaranteed to be exactly one
        // runtime word. Before `git-commit-no-verify-short` declared
        // `value_flags = ["m", "message"]`, this floored to Ask via that
        // rule (the unresolvable word looked like a possible
        // `-n|--no-verify`). Declaring `-m` as a value flag tells the floor
        // it's `-m`'s consumed value instead, so no rule matches at all —
        // this is what lets `git commit -m "$(cat <<'EOF' ... EOF)"` (a
        // heredoc commit message) resolve to Allow.
        let rules = Rules::embedded().unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::unresolvable_single_word(
                crate::normalize::UnresolvableKind::CommandSubstitution,
            ),
        ];
        assert!(rules.match_command_except_flags(&cmd).is_none());
    }

    #[test]
    fn matches_except_flags_value_flags_does_not_suppress_the_floor_for_an_unquoted_word() {
        // issue #149: same argv shape, but the unresolvable word is
        // constructed as plain `unresolvable` — simulating an UNQUOTED
        // substitution (`git commit -m $(...)`), which bash word-splits
        // at runtime. A `value_flags`
        // declaration must NOT consume this: `-m $(printf "x --no-verify")`
        // actually runs as `-m x --no-verify`, smuggling a real
        // `--no-verify` in as a separate word right after the "value" —
        // the floor must still fire so this stays `Ask`, not silently
        // become `Allow`.
        let rules = Rules::embedded().unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
        ];
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn matches_except_flags_still_fires_for_the_right_subcommand_when_not_consumed() {
        // Same shape as the test above, but the unresolvable word is NOT
        // immediately preceded by a declared value flag — `value_flags`
        // only ever narrows the specific word it consumes, never the floor
        // in general, so `git-commit-no-verify-short` (`required_tokens =
        // ["commit"]` matches the resolved "commit" positional) still fires,
        // since `required_flags = ["n|--no-verify"]` could plausibly be
        // this unresolved word.
        let rules = Rules::embedded().unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
        ];
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn matches_except_flags_no_required_tokens_rule_fires_regardless_of_subcommand() {
        // A `required_flags`-only rule with NO `required_tokens` at all has
        // no positional constraint to narrow it, so the floor degrades to
        // "any invocation of this command containing an unresolvable word,
        // regardless of subcommand." This was pinned against the embedded
        // `git-no-verify-any-subcommand` rule before issue #146 split it
        // into per-subcommand rules (each of which now has
        // `required_tokens`, precisely to avoid this over-broad shape for
        // git specifically — see `rules/blocklist.toml`'s comment on the
        // split). The underlying mechanism this test guards is general
        // rather than tied to any one embedded rule, so it's pinned here
        // against a synthetic rule instead: the floor's actual blast
        // radius is broader than the find-delete/truncate-zero/git-push-force
        // set.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "git-no-verify-any-subcommand"
            reason = "--no-verify bypasses pre-commit/commit-msg/pre-push hooks"
            command = "git"
            required_flags = ["--no-verify"]
        "#,
        )
        .unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("status"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
        ];
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-no-verify-any-subcommand");
    }

    // ==== except_targets field (issue #30): "matches unless the target is
    // one of these shapes" ====

    #[test]
    fn except_targets_suppresses_match_when_candidate_token_is_excepted() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [
                { prefix = "http://localhost" },
                { prefix = "http://127.0.0.1" },
            ]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://localhost:8080/api"]))
                .is_none()
        );
        assert!(
            rules
                .match_command(&argv(&["curl", "http://127.0.0.1/api"]))
                .is_none()
        );
        assert!(
            rules
                .match_command(&argv(&["curl", "https://evil.example.com"]))
                .is_some()
        );
    }

    #[test]
    fn except_targets_does_not_suppress_when_one_candidate_token_is_not_excepted() {
        // Mixed local/remote rsync: the local source is excepted, but the
        // remote destination isn't — suppression requires ALL candidate
        // tokens excepted, not just ANY, so the rule must still fire.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "rsync-remote"
            reason = "ask unless rsync stays local"
            decision = "ask"
            command = "rsync"
            except_targets = [
                { prefix = "/" },
                { prefix = "./" },
            ]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["rsync", "-a", "./local", "./other-local"]))
                .is_none()
        );
        assert!(
            rules
                .match_command(&argv(&["rsync", "-a", "./local", "user@host:/remote"]))
                .is_some()
        );
    }

    #[test]
    fn except_targets_ignores_flags_when_targets_field_is_absent() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
        "#,
        )
        .unwrap();
        // "-s" is a flag, not a candidate target — must not defeat the
        // exception just by being present.
        assert!(
            rules
                .match_command(&argv(&["curl", "-s", "http://localhost"]))
                .is_none()
        );
    }

    #[test]
    fn except_targets_checks_a_flag_equals_value_target_not_just_positionals() {
        // A candidate-selection pass that dropped every `-`-prefixed
        // token wholesale would let a dangerous target hiding in
        // `--url=`'s attached value silently escape the except-check —
        // the excepted `http://localhost` positional would then
        // vacuously satisfy "all candidates excepted" on its own.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "http://localhost",
                    "--url=https://evil.example.com"
                ]))
                .is_some()
        );
        // The same attached-value shape must still be excepted when it
        // really is localhost.
        assert!(
            rules
                .match_command(&argv(&["curl", "--url=http://localhost"]))
                .is_none()
        );
        // A bare flag with no `=value` (a pure flag, not a candidate at
        // all) must not be mistaken for an unexcepted target either.
        assert!(
            rules
                .match_command(&argv(&["curl", "--verbose", "http://localhost"]))
                .is_none()
        );
    }

    #[test]
    fn except_targets_known_gap_single_dash_attached_value_is_not_a_candidate() {
        // Documents a known, disclosed limitation (see `target_candidate`'s
        // doc comment and the README's except_targets caveat), pinned here
        // so it can't regress silently *worse* and so a future reader sees
        // it's a deliberate, understood trade-off rather than an oversight:
        // a single-dash token with an attached value and no `=` (curl's
        // `-xhttp://...` short proxy-flag syntax) is indistinguishable from
        // an ordinary combined short-flag cluster using shape alone, so it
        // yields no except_targets candidate at all. The excepted
        // `http://localhost` positional is the only *recognised* candidate,
        // so this rule is (wrongly) suppressed even though the unexamined
        // `-x` proxy target is exactly what it should have caught.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "http://localhost",
                    "-xhttp://evil.example.com"
                ]))
                .is_none(),
            "known gap: a single-dash attached-value target is not recognised as a candidate"
        );
    }

    #[test]
    fn except_targets_never_suppresses_when_a_token_is_unresolvable() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
        "#,
        )
        .unwrap();
        // The resolved token matches the exception, but an unrelated
        // unresolvable word is also present — fail-closed, must not
        // suppress: the unresolvable word's real value can't be proven
        // excepted.
        let cmd = argv_with_unresolvable_tail(&["curl", "http://localhost"]);
        assert!(rules.match_command(&cmd).is_some());
    }

    #[test]
    fn except_targets_is_a_no_op_when_omitted() {
        // Backward compatibility: a rule with no except_targets behaves
        // exactly as before this field existed.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-ask"
            reason = "ask on every curl"
            decision = "ask"
            command = "curl"
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://localhost"]))
                .is_some()
        );
    }

    // ==== value_flags (issue #48) ====

    fn curl_localhost_except_with_value_flags() -> &'static str {
        r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            value_flags = ["o", "w", "m"]
            except_targets = [{ prefix = "http://localhost" }]
        "#
    }

    // The exact motivating example from issue #48: -o's output path and
    // -w's format string must not stand in the way of "all candidates
    // excepted" once declared, so the real (excepted) target lets the
    // rule stay suppressed.
    #[test]
    fn value_flags_excludes_a_declared_short_flags_separated_value_from_candidates() {
        let rules = Rules::parse(curl_localhost_except_with_value_flags()).unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "http://localhost:8787/"
                ]))
                .is_none()
        );
    }

    // The rsync half of issue #48: --exclude's attached `=value` pattern
    // must not be treated as a candidate once declared.
    #[test]
    fn value_flags_excludes_a_declared_long_flags_attached_value_from_candidates() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "rsync-remote"
            reason = "ask unless rsync stays local"
            decision = "ask"
            command = "rsync"
            value_flags = ["exclude"]
            except_targets = [{ prefix = "./" }]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "rsync",
                    "-a",
                    "--exclude=.git",
                    "./src/",
                    "./dst/"
                ]))
                .is_none()
        );
    }

    // A declared long flag's separated value (no `=`) is consumed the same
    // way as its attached form.
    #[test]
    fn value_flags_excludes_a_declared_long_flags_separated_value_from_candidates() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "rsync-remote"
            reason = "ask unless rsync stays local"
            decision = "ask"
            command = "rsync"
            value_flags = ["exclude"]
            except_targets = [{ prefix = "./" }]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "rsync",
                    "-a",
                    "--exclude",
                    ".git",
                    "./src/",
                    "./dst/"
                ]))
                .is_none()
        );
    }

    // An undeclared flag's value keeps counting as a candidate — today's
    // fail-closed default is unchanged by adding value_flags support.
    #[test]
    fn undeclared_flag_value_still_counts_as_a_candidate() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "-o", "/dev/null", "http://localhost"]))
                .is_some(),
            "-o is not declared in value_flags, so /dev/null must still be an unexcepted candidate"
        );
    }

    // A declared flag consuming the ONLY candidate must not vacuously
    // suppress the rule: `all_excepted` requires a non-empty candidate set
    // — an empty set must never read as "all of zero candidates excepted".
    #[test]
    fn value_flags_consuming_the_only_candidate_does_not_vacuously_allow() {
        let rules = Rules::parse(curl_localhost_except_with_value_flags()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "-o", "https://evil.example.com"]))
                .is_some(),
            "consuming the only candidate token must not read as \
             \"all candidates excepted\" when there were none to check"
        );
    }

    // Fail-closed still holds with value_flags declared: an unresolvable
    // word anywhere in the tail must never let except_targets suppress the
    // rule, even when every resolved candidate is either excepted or
    // consumed by a declared value flag.
    #[test]
    fn value_flags_does_not_rescue_an_unresolvable_word() {
        let rules = Rules::parse(curl_localhost_except_with_value_flags()).unwrap();
        let mut cmd = argv(&["curl", "-o", "/dev/null", "http://localhost"]);
        cmd.push(NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::ParameterExpansion,
        ));
        assert!(rules.match_command(&cmd).is_some());
    }

    // Known limitation, same class as target_candidate's disclosed
    // single-dash-attached-value gap: a declared short flag glued into a
    // combined cluster (`-so` for `s` + `o`) is not recognised as the
    // flag's bare spelling, so the token after it is NOT consumed — this
    // only ever narrows the candidate set relative to not declaring the
    // flag at all, so it cannot turn a real target invisible.
    #[test]
    fn value_flags_short_flag_glued_into_a_cluster_is_not_consumed() {
        let rules = Rules::parse(curl_localhost_except_with_value_flags()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "-so", "/dev/null", "http://localhost"]))
                .is_some(),
            "known gap: -o glued into the -so cluster is not recognised as value_flags' -o"
        );
    }

    // A bare `--` end-of-options terminator must permanently turn off
    // value_flags matching for every token after it: without this, a
    // positional argument that happens to spell a declared flag's name (a
    // legitimate filename, past `--`) would be wrongly consumed as if it
    // were the flag itself, silently dropping the *next* positional — the
    // command's actual (non-excepted) target — from the candidate set and
    // turning an Ask into a fail-open Allow.
    #[test]
    fn value_flags_does_not_consume_positionals_after_end_of_options_terminator() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "rsync-remote"
            reason = "ask unless rsync stays local"
            decision = "ask"
            command = "rsync"
            value_flags = ["exclude"]
            except_targets = [{ prefix = "./" }]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "rsync",
                    "./src/",
                    "./dst/",
                    "--",
                    "--exclude",
                    "remote:evil"
                ]))
                .is_some(),
            "remote:evil is a real positional target past --, not -exclude's value"
        );
    }

    // `--` itself is never a candidate, on either side of the terminator
    // boundary (matches pre-existing target_candidate behavior for any
    // `-`-prefixed token with no `=value`).
    #[test]
    fn value_flags_end_of_options_terminator_is_never_itself_a_candidate() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "rsync-remote"
            reason = "ask unless rsync stays local"
            decision = "ask"
            command = "rsync"
            value_flags = ["exclude"]
            except_targets = [{ prefix = "./" }]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["rsync", "./src/", "--", "./dst/"]))
                .is_none(),
            "both real targets are excepted; the -- marker itself must not defeat that"
        );
    }

    // A declared flag's separated value can itself be the literal text
    // `--` (`--exclude --`) — real getopt semantics consume the very next
    // token as the flag's value unconditionally, so this `--` is NOT the
    // end-of-options terminator; value_flags matching stays live for
    // everything after it, and a genuinely unexcepted target further down
    // the tail must still be caught.
    #[test]
    fn value_flags_declared_flags_value_can_itself_be_the_terminator_text() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "rsync-remote"
            reason = "ask unless rsync stays local"
            decision = "ask"
            command = "rsync"
            value_flags = ["exclude"]
            except_targets = [{ prefix = "./" }]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "rsync",
                    "-a",
                    "--exclude",
                    "--",
                    "./src/",
                    "user@host:/remote"
                ]))
                .is_some(),
            "-- here is --exclude's own value, not the terminator; \
             user@host:/remote must still be checked and found unexcepted"
        );
    }

    #[test]
    fn value_flags_parse_rejects_bad_specs() {
        assert!(ValueFlag::parse("").is_err());
        assert!(ValueFlag::parse("-o").is_err()); // leading dash not allowed
        assert!(ValueFlag::parse("--exclude").is_err()); // leading dashes not allowed
        assert!(ValueFlag::parse("1").is_err()); // not alphabetic
        assert!(ValueFlag::parse("o|w").is_err()); // '|' alternatives not supported
    }

    #[test]
    fn value_flags_parse_accepts_short_and_long_specs() {
        assert_eq!(ValueFlag::parse("o").unwrap(), ValueFlag::Short('o'));
        assert_eq!(
            ValueFlag::parse("exclude").unwrap(),
            ValueFlag::Long("exclude".to_string())
        );
    }

    #[test]
    fn value_flags_invalid_spec_is_rejected_at_rule_load() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            value_flags = ["-o"]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // value_flags only ever narrows the except_targets candidate walk in
    // the `targets`-empty branch — declaring it with a non-empty `targets`
    // list would silently do nothing, so it's rejected at load time
    // instead (parse, don't validate).
    #[test]
    fn value_flags_with_non_empty_targets_is_rejected_at_rule_load() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            value_flags = ["o"]
            targets = [{ prefix = "http://" }]
            except_targets = [{ prefix = "http://localhost" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // Same dead-configuration hazard, the other half: value_flags with no
    // except_targets at all never reaches the candidate walk it's meant to
    // narrow.
    #[test]
    fn value_flags_without_except_targets_is_rejected_at_rule_load() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            value_flags = ["o"]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // ==== value_flags on a required_flags/required_tokens-only rule
    // (issue #146): narrows matches_except_flags's floor instead of
    // except_targets' candidate walk ====

    fn git_commit_no_verify_with_value_flags() -> &'static str {
        r#"
            [[command]]
            id = "git-commit-no-verify-short"
            reason = "git commit -n/--no-verify skips pre-commit and commit-msg hooks"
            command = "git"
            required_tokens = ["commit"]
            required_flags = ["n|--no-verify"]
            value_flags = ["m", "message"]
        "#
    }

    #[test]
    fn value_flags_on_required_flags_only_rule_loads_successfully() {
        // The counterpart to `value_flags_without_except_targets_is_rejected_at_rule_load`:
        // a `required_flags`/`required_tokens`-bearing rule with empty
        // `targets` and no `except_targets` at all is now a legal home for
        // `value_flags`, not just an `except_targets`-bearing one.
        assert!(Rules::parse(git_commit_no_verify_with_value_flags()).is_ok());
    }

    #[test]
    fn value_flags_consumes_a_declared_flags_separated_value_in_the_flags_floor() {
        // Simulates a QUOTED substitution (`-m "$(...)"`), guaranteed to be
        // exactly one runtime word — the safe case `value_flags` is meant
        // to suppress the floor for.
        let rules = Rules::parse(git_commit_no_verify_with_value_flags()).unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::unresolvable_single_word(
                crate::normalize::UnresolvableKind::CommandSubstitution,
            ),
        ];
        assert!(rules.match_command_except_flags(&cmd).is_none());
    }

    #[test]
    fn value_flags_does_not_consume_an_unquoted_declared_flags_value_in_the_flags_floor() {
        // issue #149: simulates an UNQUOTED substitution (`-m $(...)`),
        // which bash word-splits at runtime and can smuggle in an
        // additional, dangerous word right after the declared flag's
        // "value" — `value_flags` must NOT consume this; the floor keeps
        // firing.
        let rules = Rules::parse(git_commit_no_verify_with_value_flags()).unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
        ];
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn value_flags_end_of_options_terminator_stops_consumption_in_the_flags_floor() {
        // Same shape as `value_flags_does_not_consume_positionals_after_end_of_options_terminator`
        // (the except_targets counterpart) but for the flags floor: a
        // resolved literal `--` before `-m` means `-m` is an ordinary
        // positional by shell convention, not the declared flag, so it
        // must not consume the following unresolvable word.
        let rules = Rules::parse(git_commit_no_verify_with_value_flags()).unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("--"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
        ];
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn value_flags_unresolvable_flag_token_does_not_consume_in_the_flags_floor() {
        // The consumer must be a RESOLVED literal matching the declared
        // flag's bare spelling — an unresolvable word can never be
        // recognised as `-m` itself (its text is unknown by construction),
        // so it never triggers consumption of the word after it; both stay
        // candidates and the floor still fires.
        let rules = Rules::parse(git_commit_no_verify_with_value_flags()).unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
        ];
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-commit-no-verify-short");
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

    // ==== issue #98: "flag AND (target A OR target B)" composition is
    // already expressible with the existing required_flags/targets fields
    // — required_flags ANDs across entries (each entry itself an OR via
    // "|"), targets ORs across every alternative — no new schema primitive
    // needed. Pinned here at the isolated CommandRule level (not through
    // the embedded blocklist/merge_user_config) because the embedded
    // blocklist's own git-push-force rule already denies every `git push
    // --force` regardless of branch, which would mask whether THIS rule's
    // own flag/target composition is doing the work. ====

    fn protected_branch_force_push_rule() -> CommandRule {
        let toml = r#"
            [[deny]]
            id = "user-deny-protected-branch-force-push"
            reason = "force push to a protected branch"
            command = "git push"
            required_flags = ["f|--force"]
            targets = [{ exact = "main" }, { exact = "master" }]
        "#;
        UserConfig::parse(toml)
            .unwrap()
            .deny
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn flag_and_target_composition_denies_force_push_to_either_protected_branch() {
        let rule = protected_branch_force_push_rule();
        assert!(rule.matches(&argv(&["git", "push", "--force", "origin", "main"])));
        assert!(rule.matches(&argv(&["git", "push", "--force", "origin", "master"])));
    }

    #[test]
    fn flag_and_target_composition_does_not_match_an_unprotected_branch() {
        let rule = protected_branch_force_push_rule();
        assert!(!rule.matches(&argv(&["git", "push", "--force", "origin", "feature"])));
    }

    #[test]
    fn flag_and_target_composition_does_not_match_without_the_flag() {
        let rule = protected_branch_force_push_rule();
        assert!(!rule.matches(&argv(&["git", "push", "origin", "main"])));
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

    // Issue #55: SHELL_INTERPRETERS gained fish/ksh/tcsh/csh/ash — the
    // fail-closed allow-entry rejection above must catch these the same
    // way it already catches "bash".
    #[test]
    fn user_config_rejects_allow_entry_matching_fish_exactly() {
        let toml = r#"
            [[allow]]
            id = "user-allow-fish"
            reason = "trust me"
            command = "fish"
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
    fn user_config_rejects_allow_entry_matching_busybox() {
        // Issue #114: busybox joined TRANSPARENT_WRAPPERS, so an
        // `[[allow]] command = "busybox"` entry must be rejected the same
        // way `env`'s is above — otherwise it would launder every
        // busybox-wrapped Ask/Block floor to Allow.
        let toml = r#"
            [[allow]]
            id = "user-allow-busybox"
            reason = "trust me"
            command = "busybox"
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
    fn dirstack_shaped_normalized_target_is_rejected() {
        // Issue #88: a rule author declaring `normalized = "~+"` as a
        // literal target is as nonsensical as `normalized = ".."`/
        // `normalized = "~user"` — it can never usefully match, since
        // `PathForm::DirStack` only ever comes from an ARGUMENT (the
        // resolved-string classification), never a rule's own target.
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "rm"
            targets = [{ normalized = "~+" }]
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
    fn except_targets_exact_and_prefix_both_set_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            except_targets = [{ exact = "http://localhost", prefix = "http://127.0.0.1" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn except_targets_empty_prefix_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            except_targets = [{ prefix = "" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn except_targets_neither_exact_nor_prefix_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            except_targets = [{}]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // `except_targets` must stay literal (`exact`/`prefix`) —
    // `normalized`/`normalized_prefix` would silently *widen* an allow by
    // normalizing the carve-out.
    #[test]
    fn except_targets_normalized_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "tar"
            targets = [{ normalized = "/" }]
            except_targets = [{ normalized = "/tmp" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn except_targets_normalized_prefix_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "tar"
            targets = [{ normalized = "/" }]
            except_targets = [{ normalized_prefix = "/tmp/" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // A `targets` entry (not `except_targets`) must still accept
    // `normalized`/`normalized_prefix` freely — this check is scoped to
    // `except_targets` only, never a blanket rejection of the normalized
    // forms.
    #[test]
    fn targets_normalized_is_still_accepted() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "tar"
            targets = [{ normalized = "/" }]
        "#;
        assert!(Rules::parse(toml).is_ok());
    }

    // ==== issue #102: opt-in `url_host` except_targets matcher ====

    fn curl_url_host_except_rule() -> &'static str {
        r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ url_host = "localhost" }]
        "#
    }

    #[test]
    fn url_host_rejects_userinfo_spoofed_host() {
        let rules = Rules::parse(curl_url_host_except_rule()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://localhost:pw@evil.example.com"]))
                .is_some(),
            "url_host must not except a URL whose real host is evil.example.com just \
             because the raw text starts with the userinfo-adjacent string \"localhost:\""
        );
    }

    #[test]
    fn url_host_excepts_a_genuine_localhost_target() {
        let rules = Rules::parse(curl_url_host_except_rule()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://localhost:8080/api"]))
                .is_none()
        );
        assert!(
            rules
                .match_command(&argv(&["curl", "http://localhost/x"]))
                .is_none()
        );
    }

    #[test]
    fn url_host_does_not_except_a_different_real_host() {
        let rules = Rules::parse(curl_url_host_except_rule()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "https://evil.example.com"]))
                .is_some()
        );
    }

    // A candidate that doesn't parse as a URL at all (a bare flag value,
    // a local path from some other command's own except_targets rule)
    // must fail closed: never excepted, never treated as a match either
    // way — the rule still fires rather than silently passing through.
    #[test]
    fn url_host_fails_closed_on_an_unparseable_candidate() {
        let rules = Rules::parse(curl_url_host_except_rule()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "not a url at all"]))
                .is_some()
        );
    }

    // IPv6 hosts must compare correctly through the real URL parser --
    // pins the actual `url::Host` rendering this crate relies on rather
    // than assuming a specific bracket/no-bracket string form from memory.
    // `url::Host::parse` requires the bracketed form (`"[::1]"`) for a
    // standalone IPv6 host string -- bare `"::1"` is rejected as an
    // invalid domain name, confirmed empirically rather than assumed;
    // documented in the README as a real thing rule authors must know.
    #[test]
    fn url_host_matches_ipv6_localhost() {
        let toml = r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ url_host = "[::1]" }]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://[::1]:8080/"]))
                .is_none(),
            "http://[::1]:8080/ should be excepted by a url_host = \"::1\" rule"
        );
        assert!(
            rules
                .match_command(&argv(&["curl", "http://[::2]:8080/"]))
                .is_some(),
            "a different IPv6 host must not be excepted"
        );
    }

    // Fail-closed differential mitigation (docs/adr/0002-url-crate.md): a
    // candidate containing a backslash must never be excepted, even if it
    // superficially resembles the configured host, since the `url` crate's
    // WHATWG parsing of `\` for special schemes can diverge from what
    // other tools (curl, resolvers) actually do with the same text.
    #[test]
    fn url_host_never_excepts_a_candidate_containing_a_backslash() {
        let rules = Rules::parse(curl_url_host_except_rule()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http:\\\\localhost@evil.example.com"]))
                .is_some(),
            "a backslash-containing candidate must fail closed, never be excepted"
        );
    }

    #[test]
    fn except_targets_url_host_empty_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            except_targets = [{ url_host = "" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn except_targets_url_host_invalid_host_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            except_targets = [{ url_host = "not a valid host" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn except_targets_url_host_and_exact_both_set_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            except_targets = [{ url_host = "localhost", exact = "http://localhost" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn except_targets_url_host_with_strip_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            except_targets = [{ url_host = "localhost", strip = "of=" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // `url_host` is a `targets` matcher too, not except_targets-only --
    // TargetMatcher is shared and nothing in convert_target restricts
    // url_host by context the way normalized/normalized_prefix are
    // restricted away from except_targets specifically.
    #[test]
    fn url_host_also_works_in_targets_not_just_except_targets() {
        let toml = r#"
            [[command]]
            id = "curl-to-evil"
            reason = "block curl straight to evil.example.com"
            command = "curl"
            targets = [{ url_host = "evil.example.com" }]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://evil.example.com/x"]))
                .is_some()
        );
        assert!(
            rules
                .match_command(&argv(&["curl", "http://localhost.example.com/x"]))
                .is_none()
        );
    }

    #[test]
    fn url_host_targets_is_not_evaded_by_a_trailing_dot_candidate() {
        let toml = r#"
            [[command]]
            id = "curl-to-evil"
            reason = "block curl straight to evil.example.com"
            command = "curl"
            targets = [{ url_host = "evil.example.com" }]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://evil.example.com./x"]))
                .is_some(),
            "a trailing-dot FQDN is the same address a resolver would connect to and must \
             still match the block rule"
        );
    }

    #[test]
    fn url_host_config_value_with_a_trailing_dot_still_excepts_the_bare_form() {
        let toml = r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ url_host = "localhost." }]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://localhost/x"]))
                .is_none(),
            "a trailing-dot config value and a bare candidate host are the same address and \
             must compare equal"
        );
    }

    #[test]
    fn except_targets_url_host_wildcard_is_rejected() {
        let toml = r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ url_host = "*.example.com" }]
        "#;
        let err = Rules::parse(toml).unwrap_err();
        assert!(
            err.to_string().contains("wildcard"),
            "a `*` in url_host can never match a real URL's host and should be rejected at \
             load time, not silently loaded as a dead rule: {err}"
        );
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
    fn merge_user_config_escalation_floor_survives_a_second_floor_less_merge() {
        // Regression pin for issues #35/#36: `crate::config::Policy::load`
        // calls `merge_user_config` a SECOND time per self-protection
        // directory, with a synthetic config that never sets
        // `escalation_floor` (so it parses to the `Ask` default). If that
        // second call overwrote instead of folding via `max`, a real
        // `escalation_floor = "deny"` from the user's own config would be
        // silently reset back to `Ask` right after this first merge.
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let user_config = UserConfig::parse(
            r#"
            escalation_floor = "deny"
        "#,
        )
        .unwrap();
        let (rules, allowlist) = merge_user_config(blocklist, allowlist, user_config).unwrap();
        assert_eq!(rules.escalation_floor(), Decision::Block);

        // The self-protection merge: a floor-less config, same as
        // `Policy::load` generates from `self_protection_toml`.
        let self_protection = UserConfig::parse(
            r#"
            [[deny]]
            id = "self-protect-example"
            reason = "protect the config directory"
            command = "tee"
            targets = [{ prefix = "/home/user/.config/shguard" }]
        "#,
        )
        .unwrap();
        let (rules, _) = merge_user_config(rules, allowlist, self_protection).unwrap();
        assert_eq!(
            rules.escalation_floor(),
            Decision::Block,
            "a second, floor-less merge must not reset escalation_floor back to Ask"
        );
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
        // The id-collision id-space must also cover ask_rules already
        // present in `blocklist` (e.g. from a prior merge, such as
        // shguard's own self-protection pass) — not just
        // command_rules/pipeline_rules/allowlist entries.
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
    fn required_tokens_rejects_leading_or_trailing_whitespace() {
        // "delete " can never equal a resolved argv word (e.g. from
        // `gh repo delete`, which tokenizes to "delete" with no trailing
        // space) -- the same fail-open dead-rule shape as an exact
        // sugar/required_tokens duplicate, just via padding instead of
        // repetition.
        let toml = r#"
            [[command]]
            id = "bad"
            reason = "padded token"
            command = "gh repo"
            required_tokens = ["delete "]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn required_tokens_allows_internal_whitespace() {
        // A resolved argv word can legitimately contain an internal space
        // when it came from a quoted shell argument (e.g. `mytool "foo
        // bar"` resolves to the single word "foo bar") -- only
        // leading/trailing whitespace is rejected, not internal.
        let toml = r#"
            [[command]]
            id = "ok"
            reason = "quoted positional"
            command = "mytool"
            required_tokens = ["foo bar"]
        "#;
        assert!(Rules::parse(toml).is_ok());
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

    // ==== required_tokens must resolve through effective_command too, or
    // a wrapped/path-qualified command reintroduces exactly the bypass
    // closed for required_flags/targets — matching against raw argv[1..]
    // instead of effective_command's rest_words would offset every
    // positional index by one for any wrapped invocation, making
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

    // ==== multi-word `command` sugar (issue #96) ====

    #[test]
    fn multi_word_command_desugars_to_equivalent_required_tokens_rule() {
        let sugar_toml = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh repo delete"
        "#;
        let manual_toml = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh"
            required_tokens = ["repo", "delete"]
        "#;
        let sugar_rules = Rules::parse(sugar_toml).unwrap();
        let manual_rules = Rules::parse(manual_toml).unwrap();
        assert_eq!(sugar_rules.command_rules[0], manual_rules.command_rules[0]);
    }

    #[test]
    fn multi_word_command_sugar_is_equivalent_regardless_of_split_point() {
        // "gh repo delete" (all sugar), "gh repo" + required_tokens =
        // ["delete"] (partial sugar), and "gh" + required_tokens =
        // ["repo", "delete"] (no sugar) must all desugar to the identical
        // CommandRule.
        let all_sugar = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh repo delete"
        "#;
        let partial_sugar = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh repo"
            required_tokens = ["delete"]
        "#;
        let no_sugar = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh"
            required_tokens = ["repo", "delete"]
        "#;
        let a = Rules::parse(all_sugar).unwrap();
        let b = Rules::parse(partial_sugar).unwrap();
        let c = Rules::parse(no_sugar).unwrap();
        assert_eq!(a.command_rules[0], b.command_rules[0]);
        assert_eq!(b.command_rules[0], c.command_rules[0]);
    }

    #[test]
    fn multi_word_command_rejects_flag_looking_word_at_load_time() {
        let toml = r#"
            [[command]]
            id = "bad"
            reason = "flags belong in required_flags"
            command = "rm -rf"
        "#;
        let err = Rules::parse(toml).unwrap_err();
        let RulesError::InvalidRule { problem, .. } = &err else {
            panic!("expected InvalidRule, got {err:?}");
        };
        // Must name `command`, not `required_tokens` — the rule author
        // wrote a multi-word `command`, not a required_tokens entry.
        assert!(
            problem.contains("command"),
            "error should name `command`, got {problem:?}"
        );
    }

    #[test]
    fn command_prefix_containing_whitespace_is_a_load_time_error() {
        let toml = r#"
            [[command]]
            id = "bad"
            reason = "test"
            command_prefix = "gh repo"
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn command_prefix_containing_tab_or_newline_is_also_a_load_time_error() {
        // The rejection is `char::is_whitespace`-based, not a literal-space
        // check -- confirm a TOML-escaped tab and newline are caught too.
        for toml in [
            r#"
            [[command]]
            id = "bad"
            reason = "test"
            command_prefix = "gh\trepo"
        "#,
            r#"
            [[command]]
            id = "bad"
            reason = "test"
            command_prefix = "gh\nrepo"
        "#,
        ] {
            assert!(matches!(
                Rules::parse(toml),
                Err(RulesError::InvalidRule { .. })
            ));
        }
    }

    #[test]
    fn user_config_rejects_allow_entry_using_multi_word_command_sugar_matching_shell_interpreter() {
        // The sugar's CommandMatch::Exact("bash") must trigger the same
        // dangerous-allow-target rejection a plain `command = "bash"`
        // allow entry would (matches_dangerous_allow_target walks
        // entry.command, populated identically regardless of how the
        // subcommand sequence was spelled).
        let toml = r#"
            [[allow]]
            id = "user-allow-bash-extra"
            reason = "trust me"
            command = "bash extra"
        "#;
        let err = UserConfig::parse(toml).unwrap_err();
        let RulesError::InvalidRule { problem, .. } = &err else {
            panic!("expected InvalidRule, got {err:?}");
        };
        assert!(
            problem.contains("shell interpreter"),
            "error should be the dangerous-allow-target rejection, got {problem:?}"
        );
    }

    // ==== duplicate sugar words in required_tokens (issue #96) ====

    #[test]
    fn multi_word_command_sugar_duplicated_in_required_tokens_is_rejected_at_load_time() {
        let toml = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh repo delete"
            required_tokens = ["repo", "delete"]
        "#;
        let err = Rules::parse(toml).unwrap_err();
        let RulesError::InvalidRule { problem, .. } = &err else {
            panic!("expected InvalidRule, got {err:?}");
        };
        assert!(
            problem.contains("repo") && problem.contains("delete"),
            "error should name the repeated sugar words, got {problem:?}"
        );
    }

    #[test]
    fn multi_word_command_sugar_with_non_overlapping_required_tokens_still_loads() {
        // sugar_tokens = ["repo"], required_tokens = ["delete"] -- no
        // shared prefix, so this is not the duplicate-prefix shape and
        // must not be a false positive.
        let toml = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh repo"
            required_tokens = ["delete"]
        "#;
        assert!(Rules::parse(toml).is_ok());
    }

    #[test]
    fn multi_word_command_sugar_partial_boundary_overlap_is_rejected_at_load_time() {
        // sugar_tokens = ["repo", "delete"], required_tokens = ["delete"]:
        // a k=1 boundary overlap (sugar's last word equals required_tokens'
        // first word) is rejected at load time, not just a k=n full-prefix
        // overlap.
        let toml = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh repo delete"
            required_tokens = ["delete"]
        "#;
        let err = Rules::parse(toml).unwrap_err();
        let RulesError::InvalidRule { problem, .. } = &err else {
            panic!("expected InvalidRule, got {err:?}");
        };
        assert!(
            problem.contains("\"delete\""),
            "error should name the overlapping word, got {problem:?}"
        );
    }

    #[test]
    fn multi_word_command_sugar_overlap_check_reports_the_largest_matching_k() {
        // sugar_tokens = ["a", "b", "b"], required_tokens = ["b", "b", "c"].
        // Both k=1 (sugar's last word "b" vs required_tokens' first word
        // "b") and k=2 (sugar's last two words ["b", "b"] vs
        // required_tokens' first two ["b", "b"]) match; k=3 (the full
        // sugar length) does not (sugar's first word is "a", required_tokens'
        // is "b"). The largest-first search order must report k=2, not the
        // first k it happens to try -- a smallest-first implementation
        // would report "last 1 word(s)" instead and fail this assertion.
        let toml = r#"
            [[command]]
            id = "periodic-tail"
            reason = "test"
            command = "x a b b"
            required_tokens = ["b", "b", "c"]
        "#;
        let err = Rules::parse(toml).unwrap_err();
        let RulesError::InvalidRule { problem, .. } = &err else {
            panic!("expected InvalidRule, got {err:?}");
        };
        assert!(
            problem.contains("last 2 word"),
            "error should report the largest overlap (k=2), got {problem:?}"
        );
    }

    #[test]
    fn whole_repeating_sequence_spelled_as_all_sugar_loads() {
        // The legal respelling of a genuinely-repeating sequence: put the
        // whole thing in `command` and leave required_tokens empty, rather
        // than splitting it across `command` sugar and a hand-written
        // required_tokens that would trigger the overlap check above.
        let toml = r#"
            [[command]]
            id = "npm-run-run"
            reason = "test"
            command = "npm run run"
        "#;
        assert!(Rules::parse(toml).is_ok());
    }

    #[test]
    fn whole_repeating_sequence_spelled_as_hand_written_required_tokens_loads() {
        // The other legal respelling: no sugar at all, every word spelled
        // out by hand in required_tokens. sugar_tokens is empty here, so
        // the overlap check has nothing to compare against and never fires.
        let toml = r#"
            [[command]]
            id = "npm-run-run"
            reason = "test"
            command = "npm"
            required_tokens = ["run", "run"]
        "#;
        assert!(Rules::parse(toml).is_ok());
    }

    // ==== required_tokens + except_targets dead-config check (issue #96) ====

    #[test]
    fn required_tokens_word_never_covered_by_except_targets_is_rejected_at_load_time() {
        // Neither "repo" nor "delete" is ever excepted by a "sandbox/"
        // prefix matcher, so except_targets can never suppress this rule
        // -- provably dead.
        let toml = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh repo delete"
            except_targets = [{ prefix = "sandbox/" }]
        "#;
        let err = Rules::parse(toml).unwrap_err();
        let RulesError::InvalidRule { problem, .. } = &err else {
            panic!("expected InvalidRule, got {err:?}");
        };
        assert!(
            problem.contains("\"repo\""),
            "error should name the unexcepted required_tokens word, got {problem:?}"
        );
    }

    #[test]
    fn required_tokens_word_fully_covered_by_except_targets_loads_successfully() {
        // Every required_tokens word ("repo", "delete") has its own
        // except_targets entry, alongside a genuine target carve-out
        // ("my-org/") -- a legitimate, functional except_targets rule,
        // not the blunt "required_tokens + except_targets = always error"
        // shape this check must not reject.
        let toml = r#"
            [[command]]
            id = "gh-repo-delete"
            reason = "test"
            command = "gh repo delete"
            except_targets = [
                { exact = "repo" }, { exact = "delete" }, { prefix = "my-org/" },
            ]
        "#;
        assert!(Rules::parse(toml).is_ok());
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

    // ==== Issue #149: `Positionals` — the shared positional arithmetic
    // behind `constraints_match` (strict) and
    // `relaxed_required_tokens_match` (Ask floor), replacing each
    // function's own ad hoc index math over resolved/unresolvable words ====

    fn tokens(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    /// An all-`false` `value_flag_consumed` mask of length `n`, for
    /// [`Positionals`] unit tests that aren't exercising `value_flags`.
    fn no_consumed(n: usize) -> Vec<bool> {
        vec![false; n]
    }

    #[test]
    fn positionals_confirms_ignores_a_later_unresolvable_word() {
        // p4 submit $(...) --no-verify — the required prefix is fully
        // resolved and aligned; a later unresolvable word must not
        // un-confirm an already-proven match. Locks against the rejected
        // fix (`confirms` short-circuiting on `!complete`), which would
        // have broken exactly this case.
        let words = vec![
            NormalizedWord::resolved("p4"),
            NormalizedWord::resolved("submit"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion),
            NormalizedWord::resolved("--no-verify"),
        ];
        assert!(
            Positionals::new(&words, &no_consumed(words.len()))
                .confirms(&tokens(&["p4", "submit"]))
        );
    }

    #[test]
    fn positionals_cannot_rule_out_is_false_when_fully_resolved_and_too_short() {
        // No unresolvable word anywhere: a missing slot is a proven
        // absence, not an unknown.
        let words = vec![NormalizedWord::resolved("p4")];
        assert!(
            !Positionals::new(&words, &no_consumed(words.len()))
                .cannot_rule_out(&tokens(&["p4", "submit"]))
        );
    }

    #[test]
    fn positionals_empty_required_tokens_always_confirm_and_never_rule_out() {
        let words = vec![
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion),
            NormalizedWord::resolved("anything"),
        ];
        let positionals = Positionals::new(&words, &no_consumed(words.len()));
        assert!(positionals.confirms(&[]));
        assert!(positionals.cannot_rule_out(&[]));
    }

    #[test]
    fn positionals_cannot_rule_out_when_unresolvable_word_precedes_the_prefix() {
        // The unresolvable word might vanish at runtime, so it must not
        // be assumed to occupy slot 0 and rule "p4" out of ever appearing
        // there.
        let words = vec![
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion),
            NormalizedWord::resolved("p4"),
            NormalizedWord::resolved("submit"),
        ];
        assert!(
            Positionals::new(&words, &no_consumed(words.len()))
                .cannot_rule_out(&tokens(&["p4", "submit"]))
        );
    }

    #[test]
    fn positionals_unresolvable_before_push_is_not_a_mismatch() {
        // The old confirms/resolved_strings mechanism used a drop-based
        // scan that silently skipped past the unresolvable word, so it
        // wrongly counted "push" as slot 0 and returned true here.
        // Positionals::confirms correctly stops alignment at the
        // unresolvable word instead, so "push" never enters `aligned` and
        // confirms is false; cannot_rule_out stays true since alignment
        // stopped early rather than proving "push" absent.
        let words = vec![
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion),
            NormalizedWord::resolved("push"),
            NormalizedWord::resolved("origin"),
        ];
        let positionals = Positionals::new(&words, &no_consumed(words.len()));
        assert!(!positionals.confirms(&tokens(&["push"])));
        assert!(positionals.cannot_rule_out(&tokens(&["push"])));

        // Extend to a two-token required (["push", "origin"]): the actual
        // right-shift-preventing behavior this type exists for. Without
        // stopping alignment at the unresolvable word, "push" would
        // mis-index into slot 0 and falsely prove "origin" absent from
        // slot 1; cannot_rule_out correctly stays true instead, since
        // alignment stopped early before either required token could be
        // checked.
        assert!(positionals.cannot_rule_out(&tokens(&["push", "origin"])));
    }

    #[test]
    fn positionals_confirms_happy_path_fully_resolved() {
        let words = argv(&["push", "origin", "main"]);
        assert!(Positionals::new(&words, &no_consumed(words.len())).confirms(&tokens(&["push"])));
    }

    #[test]
    fn positionals_confirms_false_on_resolved_mismatch_despite_unresolvable_tail() {
        // git commit -m $(echo hi) shape: "commit" in the aligned prefix is
        // a proven miss for required=["push"] — the unresolvable tail
        // can't rescue it.
        let words = vec![
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
        ];
        assert!(!Positionals::new(&words, &no_consumed(words.len())).confirms(&tokens(&["push"])));
    }

    // ---- call-site regressions: the same fix through
    // relaxed_required_tokens_match/constraints_match via the public
    // match_command_except_flags/match_command_except_target/match_command
    // entry points ----

    #[test]
    fn matches_except_flags_floors_when_unresolvable_word_precedes_required_tokens() {
        // git $(echo -C /tmp) p4 submit --no-verify — an unresolvable word
        // between "git" and the required "p4 submit" prefix must not be
        // miscounted as consuming slot 0 and ruling "p4" out; this must
        // still float to the Ask floor via matches_except_flags, not be
        // silently missed.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "git-p4-submit-no-verify"
            reason = "ask before a p4 submit that skips hooks"
            decision = "ask"
            command = "git"
            required_tokens = ["p4", "submit"]
        "#,
        )
        .unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
            NormalizedWord::resolved("p4"),
            NormalizedWord::resolved("submit"),
            NormalizedWord::resolved("--no-verify"),
        ];
        let rule = rules.match_command_except_flags(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-p4-submit-no-verify");
    }

    #[test]
    fn matches_except_target_still_fires_for_a_rule_combining_targets_and_required_tokens() {
        // Synthetic: no shipped rule in rules/blocklist.toml or
        // allowlist.toml combines `targets` and `required_tokens` on the
        // same rule today, but matches_except_target's logic doesn't
        // assume they're mutually exclusive — this pins that a
        // hypothetical/future rule doing so still floors to Ask instead of
        // opening a silent Allow gap when an unresolvable word sits before
        // the required token.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "widget-publish-prod"
            reason = "ask before publishing to prod"
            decision = "ask"
            command = "widget"
            required_tokens = ["publish"]
            targets = [{ exact = "prod" }]
        "#,
        )
        .unwrap();
        let cmd = vec![
            NormalizedWord::resolved("widget"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
            NormalizedWord::resolved("publish"),
            NormalizedWord::resolved("prod"),
        ];
        let rule = rules.match_command_except_target(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "widget-publish-prod");
    }

    #[test]
    fn constraints_match_flags_still_match_with_an_unresolvable_word_in_the_tail() {
        // required_flags is membership-based via resolved_strings, left
        // untouched by this fix — an unresolvable word elsewhere in the
        // tail must not stop an otherwise-satisfied required flag from
        // still matching.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "git-push-force-any-branch"
            reason = "ask before a force push"
            decision = "ask"
            command = "git"
            required_flags = ["--force"]
        "#,
        )
        .unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("push"),
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::CommandSubstitution),
            NormalizedWord::resolved("--force"),
        ];
        let rule = rules.match_command(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-push-force-any-branch");
    }

    #[test]
    fn constraints_match_skips_a_consumed_unresolvable_value_flag_argument() {
        // git -m "$X" commit --no-verify, mirroring the shipped
        // git-commit-no-verify-short rule (required_tokens =
        // ["commit"], value_flags = ["m", "message"]). "$X" (a quoted,
        // single-word command substitution) is -m's declared value, not a
        // positional — Positionals must skip past it rather than stopping
        // alignment there, or "commit" never gets checked and the rule
        // goes silently invisible for this shape.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "git-commit-no-verify-short"
            reason = "git commit -n/--no-verify skips pre-commit and commit-msg hooks"
            decision = "ask"
            command = "git"
            required_tokens = ["commit"]
            required_flags = ["n|--no-verify"]
            value_flags = ["m", "message"]
        "#,
        )
        .unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::unresolvable_single_word(
                crate::normalize::UnresolvableKind::CommandSubstitution,
            ),
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("--no-verify"),
        ];
        let rule = rules.match_command(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn positionals_confirms_true_when_the_only_unresolvable_word_is_consumed() {
        // The Positionals-level mechanism behind the fix above, isolated
        // from rule-matching: a consumed unresolvable word must not break
        // alignment, so "commit" (past it) still enters `aligned`.
        let words = vec![
            NormalizedWord::resolved("-m"),
            NormalizedWord::unresolvable_single_word(
                crate::normalize::UnresolvableKind::CommandSubstitution,
            ),
            NormalizedWord::resolved("commit"),
        ];
        let consumed = vec![false, true, false];
        assert!(Positionals::new(&words, &consumed).confirms(&tokens(&["commit"])));
    }

    #[test]
    fn constraints_match_unaffected_when_value_flag_argument_is_resolved() {
        // Acceptance case from issue #146/#148, left untouched by this
        // fix: git commit -m hello --no-verify, fully resolved, no
        // unresolvable word anywhere. Must still match exactly as before —
        // "hello" is a consumed *Resolved* word, so it goes through the
        // ordinary dash-prefix check unchanged rather than being skipped
        // (the "constraint that matters" for this fix: only a consumed
        // *Unresolvable* word is alignment-transparent).
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "git-commit-no-verify-short"
            reason = "git commit -n/--no-verify skips pre-commit and commit-msg hooks"
            decision = "ask"
            command = "git"
            required_tokens = ["commit"]
            required_flags = ["n|--no-verify"]
            value_flags = ["m", "message"]
        "#,
        )
        .unwrap();
        let cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::resolved("hello"),
            NormalizedWord::resolved("--no-verify"),
        ];
        let rule = rules.match_command(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "git-commit-no-verify-short");

        // Pins the constraint from the other direction: with "-m hello"
        // BEFORE "commit" (a resolved, consumed value-flag argument),
        // "hello" must still occupy its own positional slot rather than
        // being skipped — it is a pre-existing "known gap" (a resolved
        // non-dash token ahead of the subcommand shifts the required
        // token out of alignment), unrelated to and unfixed by this
        // change. Skipping consumed Resolved words too (the forbidden,
        // over-eager implementation) would wrongly make this match.
        let shifted_cmd = vec![
            NormalizedWord::resolved("git"),
            NormalizedWord::resolved("-m"),
            NormalizedWord::resolved("hello"),
            NormalizedWord::resolved("commit"),
            NormalizedWord::resolved("--no-verify"),
        ];
        assert!(rules.match_command(&shifted_cmd).is_none());
    }
}
