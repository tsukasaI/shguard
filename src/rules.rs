//! Stage 3 of the pipeline (plan.md §1.1): mechanical, exact matching of a
//! resolved argv against `rules/blocklist.toml`/`rules/allowlist.toml`.
//!
//! Four rule kinds:
//! - [`CommandRule`] matches one simple command's argv: a command-name
//!   matcher, a set of required flags, a set of required bare tokens
//!   (subcommands/positional arguments), a set of target matchers, and a
//!   set of except-target matchers (issue #30: "matches unless the target
//!   is one of these shapes").
//! - [`PipelineRule`] matches the shape of a whole pipeline (the ported
//!   `curl|wget → sh` installer-pipe pattern, plus issue #268's
//!   `find | xargs rm -f` shape). The more general decode-pipe
//!   gate (rules 5b/5c: a `base64`/`gunzip`/… decode stage piped into an
//!   interpreter) is implemented separately, structurally, in
//!   `crate::gate::evaluate_pipeline_shape` rather than as rule data here.
//! - [`RedirectRule`] matches a redirection target (output/append only)
//!   against a dangerous-path list (block devices, critical system files).
//! - [`TokenRule`] (issue #426) matches a literal, case-sensitive substring
//!   against every assignment name/resolved argv word of a simple command,
//!   independent of the command name.
//!
//! Everything here operates on already-normalised [`NormalizedWord`] values
//! (`crate::normalize`, B2) — no raw strings, no regex over the command
//! line. An [`Resolution::Unresolvable`] word never matches any matcher and
//! never panics (module tests cover this).
//!
//! # Parse, don't validate
//!
//! This module has no serde or TOML dependency: the serde DTOs and the TOML
//! loading live in `crate::config_loader` (`coding-guidelines/principles.md`,
//! "dependencies point inward"), which deserializes a file into its own DTOs
//! and hands this module the plain [`RulesFileSpec`]/[`AllowlistFileSpec`]/
//! [`UserConfigSpec`] values (and the `*RuleSpec`/[`TargetSpec`] types they
//! carry). Loading is a one-step boundary: [`Rules::from_spec`]/
//! [`Allowlist::from_spec`]/[`UserConfig::from_spec`] either return a
//! fully-valid, typed rule set, or an [`RulesError`] — a duplicate id, an
//! empty id/reason, or a matcher with no command identifier is a load-time
//! `Err`, never a silently-skipped rule — security controls default to
//! fail-closed.
//!
//! # File I/O stays out of this module
//!
//! The one place this module needs the filesystem, `resolve_symlinks`
//! (issue #583), goes through the [`CanonicalizeFn`] port it defines; the
//! composition root wires the adapter in ([`Rules::with_path_canonicalizer`]).
//! Nothing here takes a path or TOML text. The composition root reads
//! `rules/blocklist.toml`/an operator-supplied override file and hands the
//! contents to `crate::config_loader`, which builds the specs.
//!
//! `analyze()` (`src/lib.rs`) loads [`Rules::embedded`] and hands it to
//! `src/gate.rs`, which calls [`Rules::match_command`]/
//! [`Rules::match_pipeline`], with the embedded (currently empty)
//! `Allowlist`/no `ask_rules`. `analyze_with_policy()` additionally
//! threads [`Rules::match_ask`], the [allowlist](#allowlist) section, and
//! whatever [`UserConfig`]/[`merge_user_config`] contributed — see
//! `src/gate.rs`'s module docs for the evaluation order, and
//! `src/config.rs` for where a user's config file is found and merged in.

use std::borrow::Cow;
use std::collections::HashSet;

use crate::knowledge::{self, Finding, Known, OptionValue, ParsedArgv, ScriptValue};
use crate::normalize::{NormalizedWord, Resolution};
use crate::verdict::{Decision, DenyMessage, Reason, RuleId, Verdict};

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Everything that can go wrong loading a rule set. Every variant is a
/// load-time failure — this crate never falls back to "skip the bad rule
/// and keep going" (fail-closed).
#[derive(Debug, thiserror::Error)]
pub(crate) enum RulesError {
    /// The input is not valid TOML at all. Carries `toml::de::Error`'s
    /// message as a `String`, not the error type itself — `toml` is a
    /// parsing-driver detail of `crate::config_loader` alone
    /// (`coding-guidelines/principles.md`, "adapters return
    /// domain-meaningful errors, not driver errors"). Only the loader
    /// constructs this variant.
    #[error("invalid TOML: {0}")]
    Syntax(String),
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
///
/// Matching is case-folded (issue #536): callers fold the runtime argv name
/// with [`fold_command_name`] before [`Self::matches`], and the rule-side
/// names below are stored already folded (by `convert_command_rule`), so
/// the comparison itself is a plain byte comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandMatch {
    /// The exact command name, e.g. `"rm"`; stored folded.
    Exact(String),
    /// A command-name prefix, e.g. `"mkfs."` for the `mkfs.*` family; stored
    /// folded. An explicit field, not regex, per issue #11 scope.
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
    /// suffix (GNU long-option convention, e.g. `--in-place=.bak`). For a
    /// git rule or a git `[[pipeline]]` sink, including version-suffixed
    /// spellings such as `git2`, a non-empty prefix of a `--long` token
    /// also matches (issue #582, see [`Self::satisfied`]).
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
    ///
    /// With `long_abbrev` set (deny/ask rules whose command is exactly
    /// `git`, issue #582, and `[[pipeline]]` rules whose resolved sink is
    /// `git` after version-suffix stripping, issues #604 and #652), a
    /// `--`-prefixed [`Self::Token`] is also satisfied by any non-empty
    /// prefix of it (`--mirr`, `--upl=x`): git's option parser accepts any
    /// unambiguous prefix of a long option. No per-subcommand option table
    /// is consulted, so an ambiguous prefix (which git itself rejects) is
    /// over-matched to the rule's own verdict, never allowed.
    fn satisfied(&self, argv: &[&str], long_abbrev: bool) -> bool {
        match self {
            Self::Short(c) => argv
                .iter()
                .any(|token| short_cluster_chars(token).contains(c)),
            Self::Token(token) => argv.iter().any(|arg| {
                *arg == token.as_str()
                    || arg
                        .strip_prefix(token.as_str())
                        .is_some_and(|rest| rest.starts_with('='))
                    || (long_abbrev && is_long_option_abbrev(arg, token))
            }),
            Self::AnyOf(alternatives) => alternatives
                .iter()
                .any(|alt| alt.satisfied(argv, long_abbrev)),
        }
    }
}

/// Whether `arg` (`--x` or `--x=value`) spells a non-empty prefix of the
/// `--`-prefixed long option `token` — see [`FlagMatcher::satisfied`].
fn is_long_option_abbrev(arg: &str, token: &str) -> bool {
    let (Some(arg_rest), Some(full)) = (arg.strip_prefix("--"), token.strip_prefix("--")) else {
        return false;
    };
    let (name, value) = match arg_rest.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (arg_rest, None),
    };
    if name.is_empty() {
        return false;
    }
    match full.split_once('=') {
        Some((full_name, full_value)) => full_name.starts_with(name) && value == Some(full_value),
        None => full.starts_with(name),
    }
}

/// The body after the leading `-` of a short-option cluster token (`-rf` →
/// `"rf"`), or `None` for anything that isn't one: a bare `-`, a
/// `--`-prefixed long option, or a token with no leading `-` at all.
pub(crate) fn short_cluster_letters(token: &str) -> Option<&str> {
    token
        .strip_prefix('-')
        .filter(|rest| !rest.is_empty() && !rest.starts_with('-'))
}

/// The characters of a short-option cluster token (`-rf` → `{'r', 'f'}`,
/// `-r` → `{'r'}`), or an empty set for anything that isn't one — see
/// [`short_cluster_letters`].
fn short_cluster_chars(token: &str) -> HashSet<char> {
    short_cluster_letters(token)
        .map(|rest| rest.chars().collect())
        .unwrap_or_default()
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
pub(crate) const TAR_DASHLESS_CONSUMING: &[char] = &['f', 'C'];
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
    /// A recognized `x`-containing dash-less cluster, already rewritten
    /// into its dashed-token equivalent — the caller should match
    /// flags/targets against this instead of the original tail.
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
/// [`TarDashlessCluster::Recognized`] fires whenever `tail`'s first word is
/// [`Resolution::Resolved`], non-empty, has no leading `-`, is composed
/// entirely of ASCII alphabetic characters all drawn from
/// [`TAR_DASHLESS_CONSUMING`]/[`TAR_DASHLESS_BOOLEAN`], and contains `x` —
/// `C` need not be in the same cluster (issue #344): `tar xf a.tar
/// --directory=/`'s leading `xf` is rewritten into `-x -f` the same as `tar
/// xfC a.tar /`'s `xfC` is, leaving the SEPARATE `--directory=/` for the
/// existing dashed/long-option matching to see on its own, exactly as it
/// already does for `tar -x -f a.tar --directory=/`. Before issue #344,
/// requiring `C` in the SAME cluster left a bare `xf` completely
/// unrewritten (`NotApplicable`), so `-x`/`--extract`/`--get` never reached
/// `required_flags` at all even when a real extraction target followed
/// later in the tail as an ordinary dashed/long token — degrading a rule
/// declaring `required_flags = ["x|--extract|--get"]` to never match a
/// bare-`x` dash-less invocation, no matter what else was present. A
/// value-consuming letter with no positional argument left to consume
/// falls back to [`TarDashlessCluster::NotApplicable`] — post-issue-#344,
/// bare `tar xf` (no trailing archive argument at all) is a real,
/// reachable example of this shape (`tar fC` alone, which also lacks `x`,
/// never reached this case regardless).
///
/// On success, [`TarDashlessCluster::Recognized`] carries the full
/// rewritten tail: one or two synthetic tokens per cluster letter,
/// followed by every argument the cluster didn't consume, unchanged
/// (including any of *those* that are already `-`-prefixed, e.g. a
/// trailing `-P` after the cluster).
pub(crate) fn tar_dashless_cluster(tail: &[NormalizedWord]) -> TarDashlessCluster {
    tar_dashless_cluster_impl(tail, true)
}

/// [`tar_dashless_cluster`] generalized beyond issue #67's original `x`+`C`
/// need (dropping the `contains('x')` gate) — issue #356's `-C` composition
/// need (`tar cCf dir archive.tar file`, no `x` at all: `c` for create, not
/// extract) has to recognize the SAME dash-less bundling convention
/// regardless of which mode letter the cluster happens to carry. Shares
/// [`tar_dashless_cluster_impl`] with the `x`-gated wrapper so the two can
/// never drift apart on what counts as a plausible/modeled/malformed
/// cluster — only the `x` requirement differs.
pub(crate) fn tar_dashless_leading_cluster(tail: &[NormalizedWord]) -> TarDashlessCluster {
    tar_dashless_cluster_impl(tail, false)
}

fn tar_dashless_cluster_impl(tail: &[NormalizedWord], require_x: bool) -> TarDashlessCluster {
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
    if require_x && !cluster.contains('x') {
        return TarDashlessCluster::NotApplicable;
    }
    if !cluster
        .chars()
        .all(|c| TAR_DASHLESS_CONSUMING.contains(&c) || TAR_DASHLESS_BOOLEAN.contains(&c))
    {
        return TarDashlessCluster::Unmodeled;
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

/// GNU tar long options [`tar_long_option_abbrev_rewrite`] recognizes an
/// abbreviation of (issue #128) — GNU tar's own documented "unique
/// abbreviation" feature (`--cre` for `--create`, since no other long
/// option starts with `cre`). Scoped to exactly the option names
/// `rules/blocklist.toml`'s tar rules key off: `directory`
/// (`-C`/`--directory`), the extract-mode aliases `extract`/`get`, and
/// `absolute-names` (`-P`/`--absolute-names`, `tar-absolute-names-ask`).
///
/// Checked against GNU tar's own long-option table (GNU tar manual, "All
/// tar Options") for every other GNU-tar long option starting with `d`
/// (delay-directory-restore, dereference, diff, delete), `e` (exclude,
/// exclude-backups, exclude-caches[-all/-under], exclude-from,
/// exclude-ignore[-recursive], exclude-tag[-all/-under],
/// exclude-vcs[-ignores], extract), `g` (get, group, group-map, gunzip,
/// gzip), or `a` (this crate's own d/e/g enumeration above is not
/// necessarily exhaustive — GNU tar's option surface is large and grows —
/// but that's fine: the argument below holds for ANY sibling option, not
/// just the ones listed): each either isn't a prefix of `directory`/
/// `extract`/`get`/`absolute-names` at all, or — where a SHORT prefix is
/// genuinely ambiguous between multiple real options (the `a`-namespace
/// in particular is the most crowded of the four, so a short `--a`/`--ab`
/// prefix is ambiguous there even among just the options this crate
/// happens to know about) — real GNU tar itself refuses to run with
/// "ambiguous option", so shguard resolving that same short prefix to the
/// dangerous option is harmless over-matching: no real invocation exists
/// where that prefix actually runs AND means something other than what
/// shguard assumes here. This argument doesn't depend on the enumeration
/// being complete — an unlisted sibling option only ever makes MORE
/// prefixes ambiguous in reality, never fewer, which only ever makes
/// over-matching MORE harmless, never less. Matching ANY non-empty prefix
/// (not just a verified-unambiguous one) is therefore safe and
/// deliberately not narrowed further.
///
/// bsdtar (macOS default) is NOT abbreviation-blind the way an earlier
/// version of this comment claimed — measured directly against bsdtar
/// 3.5.3: it DOES support `--directory`/`--extract` as long options, with
/// the same GNU-style unique-abbreviation resolution (`--dir` extracts
/// into the given directory; `--ex` errors as ambiguous, since bsdtar
/// also has `--exclude-vcs`). It has no `--get` alias at all (harmless —
/// this rewrite over-matching a name bsdtar itself rejects is still
/// covered by the general argument above). It spells `-P` differently
/// from GNU tar, though: bsdtar's own long form is `--absolute-paths`
/// (`man tar`, bsdtar 3.5.3, line 515), not `--absolute-names` —
/// [`TAR_BSDTAR_ABSOLUTE_PATHS_ALIAS`] closes that gap explicitly, the
/// same way [`TAR_BSDTAR_DIRECTORY_ALIAS`] closes bsdtar's `--cd` alias
/// for `-C`/`--directory` that GNU tar doesn't have either — neither is a
/// *prefix* of the GNU spelling the general argument above would
/// otherwise cover.
const TAR_LONG_OPTION_DIRECTORY: &str = "directory";
const TAR_LONG_OPTION_EXTRACT_ALIASES: &[&str] = &["extract", "get"];
const TAR_LONG_OPTION_ABSOLUTE_NAMES: &str = "absolute-names";
/// bsdtar-only exact alias for `-C`/`--directory` (issue #128 review
/// finding: `tar -x --cd / -f a.tar` extracts over `/` on bsdtar 3.5.3,
/// same as `-C /`, but wasn't recognized before this). Not a GNU tar
/// option at all (harmless to over-match there too), and not itself
/// treated as further abbreviable (`--c` collides with several other real
/// bsdtar options) — matched by exact name only, unlike the prefix-based
/// names above.
const TAR_BSDTAR_DIRECTORY_ALIAS: &str = "cd";
/// bsdtar's own long spelling of `-P` (`man tar` on bsdtar 3.5.3, line
/// 515: "`-P, --absolute-paths`") — GNU tar's `-P` is `--absolute-names`
/// instead, a *different* string, so it needs its own prefix family
/// rather than falling under [`TAR_LONG_OPTION_ABSOLUTE_NAMES`]'s
/// `starts_with` check (round-2 review finding: `tar -x --absolute-paths
/// -f a.tar` and its abbreviation `--absolute-p` both stayed Allow on
/// bsdtar, degrading `tar-absolute-names-ask`'s Ask). Prefix-matched the
/// same way `TAR_LONG_OPTION_ABSOLUTE_NAMES` is (`--absolute-` is a
/// shared, harmlessly-ambiguous prefix of both spellings — GNU tar has no
/// option starting with `absolute-p` at all, so over-matching there is
/// still covered by the general argument above).
const TAR_BSDTAR_ABSOLUTE_PATHS_ALIAS: &str = "absolute-paths";

/// Rewrites a GNU-tar long-option abbreviation of `--directory` (attached
/// `--dir=/` or separated `--dir /`), the bsdtar `--cd` alias for the
/// same option, `--extract`/`--get`, `--absolute-names`, or the bsdtar
/// `--absolute-paths` alias for `--absolute-names`, to its canonical
/// spelling — see [`TAR_LONG_OPTION_DIRECTORY`]'s own docs for
/// why matching any non-empty prefix is safe. `None` — no rewrite needed
/// — when nothing in `tail` is a recognized abbreviation. An
/// already-canonical spelling is left untouched, not "rewritten to
/// itself". A real, invalid `=value` attached to a value-less option
/// (`--ex=x`, `--absolute-names=x` — GNU tar rejects both) is rewritten
/// through anyway rather than left unrecognized: the resulting canonical
/// token (`--extract=x`) is exactly as invalid to `FlagMatcher`'s own
/// pre-existing lenient `=value` acceptance as the literal
/// `--extract=x` spelling already is, so this keeps abbreviated and
/// canonical spellings deciding identically instead of the abbreviated
/// form being stricter than the spelling it stands in for.
fn tar_long_option_abbrev_rewrite(tail: &[NormalizedWord]) -> Option<Vec<NormalizedWord>> {
    let mut rewritten: Option<Vec<NormalizedWord>> = None;
    for (i, word) in tail.iter().enumerate() {
        let Resolution::Resolved(text) = word.resolution() else {
            continue;
        };
        let Some(rest) = text.strip_prefix("--") else {
            continue;
        };
        let (name, value) = match rest.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (rest, None),
        };
        if name.is_empty() {
            continue;
        }
        let canonical_name = if name == TAR_BSDTAR_DIRECTORY_ALIAS
            || (TAR_LONG_OPTION_DIRECTORY.starts_with(name) && name != TAR_LONG_OPTION_DIRECTORY)
        {
            TAR_LONG_OPTION_DIRECTORY
        } else if (TAR_LONG_OPTION_ABSOLUTE_NAMES.starts_with(name)
            && name != TAR_LONG_OPTION_ABSOLUTE_NAMES)
            || TAR_BSDTAR_ABSOLUTE_PATHS_ALIAS.starts_with(name)
        {
            TAR_LONG_OPTION_ABSOLUTE_NAMES
        } else if TAR_LONG_OPTION_EXTRACT_ALIASES
            .iter()
            .any(|opt| opt.starts_with(name) && name != *opt)
        {
            "extract"
        } else {
            continue;
        };
        let canonical = match value {
            Some(value) => format!("--{canonical_name}={value}"),
            None => format!("--{canonical_name}"),
        };
        rewritten.get_or_insert_with(|| tail.to_vec())[i] = NormalizedWord::resolved(canonical);
    }
    rewritten
}

/// The tail a rule's flag/target checks should actually see for one
/// wrapper-chain hop, extending [`tar_dashless_effective_tail`] with
/// [`tar_long_option_abbrev_rewrite`] (issue #128) — both `tar`-scoped,
/// composed here so [`effective_tail`] only needs one `tar`-guarded call
/// site instead of two.
fn tar_effective_tail<'a>(base: &str, tail: &'a [NormalizedWord]) -> Cow<'a, [NormalizedWord]> {
    let tail = tar_dashless_effective_tail(base, tail);
    if base == "tar" {
        match tar_long_option_abbrev_rewrite(&tail) {
            Some(rewritten) => Cow::Owned(rewritten),
            None => tail,
        }
    } else {
        tail
    }
}

/// `git`'s own global options that consume a *separated* value token and
/// can appear before the subcommand: `-C <path>`, `-c <name>=<value>`,
/// `--git-dir <path>`, `--work-tree <path>`, `--namespace <ns>`,
/// `--config-env <name>=<envvar>`, `--super-prefix <path>` (removed in
/// git 2.41, kept for older gits), `--attr-source <tree-ish>`. Attached
/// spellings (`--git-dir=value`) and value-less globals (`--no-pager`,
/// `--bare`, …) are single self-contained tokens enumerated separately —
/// see [`git_global_single_token_flag`]. `--exec-path` is listed here
/// even though a *separated* value actually makes git print its exec
/// path and exit without running any subcommand — over-consuming that
/// "value" is harmless precisely because nothing executes.
const GIT_GLOBAL_VALUE_FLAGS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--config-env",
    "--super-prefix",
    "--attr-source",
];

/// `git`'s global options that are one self-contained token: the
/// value-less set (per git 2.55's `handle_options`), `--list-cmds=…`
/// (attached-only), and the attached `--opt=value` spelling of every
/// long option in [`GIT_GLOBAL_VALUE_FLAGS`]. `-c`/`-C` have no attached
/// spelling (git compares them with `strcmp`), so they are not
/// prefix-matched here.
const GIT_GLOBAL_VALUELESS_FLAGS: &[&str] = &[
    "-v",
    "--version",
    "-h",
    "--help",
    "--html-path",
    "--man-path",
    "--info-path",
    "-p",
    "--paginate",
    "-P",
    "--no-pager",
    "--no-replace-objects",
    "--no-lazy-fetch",
    "--no-optional-locks",
    "--no-advice",
    "--bare",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
];

/// Whether `token` is a `git` global option that takes its value as a
/// SEPARATE following token (`-C`/`-c`/`--git-dir`/…, per
/// [`GIT_GLOBAL_VALUE_FLAGS`]) — the single source of truth for both
/// [`git_strip_global_flags`] here and `gate.rs`'s
/// `bound_git_global_options`, which used to hardcode only `-C`/`-c` and
/// so missed `--git-dir`/`--work-tree`/etc (issue #400).
pub(crate) fn git_global_takes_separated_value(token: &str) -> bool {
    GIT_GLOBAL_VALUE_FLAGS.contains(&token)
}

/// See [`GIT_GLOBAL_VALUELESS_FLAGS`] — whether `text` is a global git
/// option that consumes no *following* token.
fn git_global_single_token_flag(text: &str) -> bool {
    GIT_GLOBAL_VALUELESS_FLAGS.contains(&text)
        || text.starts_with("--list-cmds=")
        || GIT_GLOBAL_VALUE_FLAGS.iter().any(|flag| {
            flag.starts_with("--")
                && text
                    .strip_prefix(flag)
                    .is_some_and(|rest| rest.starts_with('='))
        })
}

/// The config key half of a `-c`/`--config-env` `key=value` pair (the whole
/// text when there is no `=`). Shared by the `git_config_key_is_*` predicates
/// so key parsing lives in one place.
fn git_config_key(key_value: &str) -> &str {
    key_value.split_once('=').map_or(key_value, |(key, _)| key)
}

/// Whether `key_value` — the text following `-c`/`--config-env`'s `=` or
/// separator, e.g. `"core.hooksPath=/dev/null"` or bare `"core.hooksPath"`
/// — names the `core.hooksPath` config variable. Git config section/key
/// names are matched case-insensitively when (as here) there is no
/// subsection, so `Core.HooksPath`/`CORE.HOOKSPATH` are the same variable.
/// The value half is deliberately ignored: an empty string and `/dev/null`
/// both point every hook at a directory with nothing runnable in it,
/// verified against a real `pre-commit` hook — same effect as
/// `--no-verify` (issue #447), whatever the path spells out. The bare,
/// value-less form (`-c core.hooksPath`) matches too even though real git
/// rejects it ("missing value for 'core.hooksPath'") — Blocking a command
/// that would itself error is a harmless false positive, cheaper than
/// special-casing it out.
fn git_config_key_is_hooks_path(key_value: &str) -> bool {
    let key = git_config_key(key_value);
    key.eq_ignore_ascii_case("core.hookspath")
}

/// Whether `key_value` names the `include.path` config variable (issue
/// #499, follow-up from #447/#498's `core.hooksPath` detection). `-c
/// include.path=<file>`/`--config-env=include.path=<file>` injects an
/// arbitrary config file for the duration of the invocation — that file's
/// own contents could set `core.hooksPath` (or anything else
/// security-relevant) indirectly, but are not statically inspectable
/// here. Consulted by `crate::gate`'s own structural check
/// (`git_config_smuggled_verdict`) rather than folded into
/// [`git_strip_global_flags`]'s `--no-verify`-equivalence rewrite the way
/// [`git_config_key_is_hooks_path`] is: a brand-new `required_flags`-keyed
/// rule keyed on a synthetic marker flag can't be distinguished by
/// `crate::rules::CommandRule`'s except-flags floor from a genuinely
/// unresolvable value that could resolve to the flag it needs — the floor
/// has no way to tell "this is a marker no real command line could ever
/// spell" apart from "this is real user input". A hand-verdict structural
/// check (mirroring `crate::gate::git_checkout_dot`'s own shape) knows
/// which value it's looking at is a `-c`/`--config-env` value specifically,
/// so it can floor an unresolvable one to Ask on its own terms without
/// touching any other rule's unrelated except-flags floor.
/// Deliberately scoped to the exact `include.path` key, not the
/// conditional `includeIf.<condition>.path` family (same file-injection
/// effect, gated on a runtime condition this function doesn't evaluate) —
/// a disclosed residual gap, not covered by the issue this fixes.
pub(crate) fn git_config_key_is_include_path(key_value: &str) -> bool {
    let key = git_config_key(key_value);
    key.eq_ignore_ascii_case("include.path")
}

/// Whether `key_value` names an `alias.<name>` config variable (issue
/// #499). `-c alias.<name>=<value>` defines or overrides a git alias for
/// the duration of the invocation — structurally closer to inline shell
/// execution than to a config toggle: a value beginning with `!` runs as
/// an arbitrary shell command, and even a plain git-subcommand value can
/// redefine what a builtin-looking subcommand does (`alias.co = "!rm -rf
/// /"`-style). The alias's own NAME (`alias.<name>`, a subsection, unlike
/// `core`/`include`'s flat keys) is git-config case-sensitive and not
/// compared against anything here — only the `alias.` section prefix
/// matters, so this fires regardless of what the alias is named. See
/// [`git_config_key_is_include_path`]'s doc for why this is consulted
/// structurally in `crate::gate` rather than via a `required_flags` rule.
pub(crate) fn git_config_key_is_alias(key_value: &str) -> bool {
    let key = git_config_key(key_value);
    key.split_once('.')
        .is_some_and(|(section, name)| section.eq_ignore_ascii_case("alias") && !name.is_empty())
}

/// Whether `key_value` names a config variable whose value git runs as a
/// shell command or execs unconditionally, so a `-c` override is inline
/// command execution: `core.fsmonitor`, `core.sshCommand`, `diff.external`,
/// `gpg.program` (issue #694). Whole-key match, not a prefix: section and
/// key are case-insensitive and these have no subsection.
pub(crate) fn git_config_key_runs_command_block(key_value: &str) -> bool {
    let key = git_config_key(key_value);
    [
        "core.fsmonitor",
        "core.sshcommand",
        "diff.external",
        "gpg.program",
    ]
    .iter()
    .any(|known| key.eq_ignore_ascii_case(known))
}

/// Like [`git_config_key_runs_command_block`] but for keys that also have
/// ordinary non-command values in routine use (`core.pager=less`), so the
/// verdict is Ask rather than Block: `credential.helper`, `core.editor`,
/// `core.pager` (issue #694).
pub(crate) fn git_config_key_runs_command_ask(key_value: &str) -> bool {
    let key = git_config_key(key_value);
    ["credential.helper", "core.editor", "core.pager"]
        .iter()
        .any(|known| key.eq_ignore_ascii_case(known))
}

/// Strips a leading run of `git`'s own global value-taking options (and
/// their separated values) from `tail`. Returns `None` — no rewrite
/// needed — for every non-`git` command, and for a `git` invocation with
/// no leading global flag.
///
/// `git -C <path> push` previously left the non-dash token `<path>` in
/// front of `push`, defeating every git rule's `required_tokens`
/// alignment ([`Positionals`] saw `<path>` as the first positional
/// instead of the real subcommand, so `push`, `reset`, `clean`, … never
/// lined up with slot 0 and no git rule could match at all).
///
/// Once a token resolves to one of [`GIT_GLOBAL_VALUE_FLAGS`]'s bare
/// spellings, the *following* token is skipped unconditionally,
/// regardless of whether it itself resolves — git's own argument parser
/// consumes exactly one token here no matter its content, so there is
/// nothing to gain by waiting to see whether that content is readable.
/// Two exceptions to that rule, both about `-c`/`--config-env` — the one
/// global flag whose *value's content*, not just its presence, is
/// security-relevant:
///
/// 1. If the value IS readable and names `core.hooksPath`
///    (`-c core.hooksPath=...`), a synthetic `--no-verify` token is
///    appended to the returned tail — `git -c core.hooksPath=<any>
///    commit` disables every hook exactly like `--no-verify` does (issue
///    #447), and stripping the pair here (like every other global flag)
///    would otherwise discard that evidence before any `git-*-no-verify`
///    rule ever saw the tail. `--config-env`'s attached spelling
///    (`--config-env=core.hooksPath=ENVVAR`) gets the same treatment in
///    the `git_global_single_token_flag` branch below. (A value hidden
///    behind an expansion that ITSELF folds to a single opaque
///    `Unresolvable` word, e.g. `-c "$X"`, can't be inspected this way
///    even when a literal `core.hooksPath=` prefix sits right next to it
///    in source, e.g. `-c core.hooksPath="$(mktemp -d)"` — normalization
///    collapses the whole value into one word with no literal residue;
///    exception 2 below is what keeps that case from going silently
///    unnoticed.)
/// 2. If the value is UNRESOLVABLE, it is moved rather than dropped: git
///    always consumes it either way, so it is still counted here (the
///    subcommand keeps its positional slot, same as a resolved value),
///    but carried to the END of the returned tail instead of discarded.
///    Appending after the subcommand and its own flags means
///    [`Positionals`] has already aligned everything `required_tokens`
///    cares about before hitting this trailing word, so confirmation for
///    the visible portion is untouched — but the word is still present
///    for `matches_except_flags`'s `has_unresolvable` scan to float an
///    otherwise-clean-looking `git commit -m x` up to `Ask` instead of a
///    silent `Allow`. Residual gap: if the tail's own trailing flag is
///    itself a bare, unresolved value-taking one (`git -c "$X" commit
///    -m`), `value_flags` consumption claims this moved word as -m's
///    value and the floor doesn't fire — real git rejects `commit -m`
///    with no value before running anything, so this isn't reachable in
///    practice.
///
/// A recognized *single-token* global ([`git_global_single_token_flag`]:
/// value-less like `--no-pager`, or attached-value like `--git-dir=/x`)
/// is skipped without a value and the walk continues — breaking on one
/// instead would re-open the bypass one interleaved flag deep
/// (`git --no-pager -C <path> push --force` would keep `<path>` in the
/// positional slot). The walk still BREAKS on any dash token neither
/// table recognizes: real git dies with "unknown option" before running
/// a subcommand there, so under-stripping is benign, while skipping
/// arbitrary dash tokens would strip a rule's own `value_flags` (e.g.
/// `-m`) out of a flag-before-token spelling and break the
/// order-agnostic matching that
/// `constraints_match_skips_a_consumed_unresolvable_value_flag_argument`
/// pins. Residual rot risk: a future git global taking a *separated*
/// value that's missing from [`GIT_GLOBAL_VALUE_FLAGS`] would re-open
/// the positional shift for that one flag — extend the tables when git
/// grows one.
fn git_strip_global_flags(base: &str, tail: &[NormalizedWord]) -> Option<Vec<NormalizedWord>> {
    if base != "git" {
        return None;
    }
    let mut consumed = 0;
    let mut synthesize_no_verify = false;
    let mut deferred_unresolvable_config_values = Vec::new();
    while let Some(Resolution::Resolved(text)) = tail.get(consumed).map(NormalizedWord::resolution)
    {
        if GIT_GLOBAL_VALUE_FLAGS.contains(&text.as_str()) {
            let Some(value_word) = tail.get(consumed + 1) else {
                break;
            };
            if text == "-c" || text == "--config-env" {
                match value_word.resolution() {
                    Resolution::Resolved(value) if git_config_key_is_hooks_path(value) => {
                        synthesize_no_verify = true;
                    }
                    Resolution::Resolved(_) => {}
                    Resolution::Unresolvable(_) => {
                        deferred_unresolvable_config_values.push(value_word.clone());
                    }
                }
            }
            consumed += 2;
        } else if git_global_single_token_flag(text) {
            if let Some(kv) = text.strip_prefix("--config-env=")
                && git_config_key_is_hooks_path(kv)
            {
                synthesize_no_verify = true;
            }
            consumed += 1;
        } else {
            break;
        }
    }
    (consumed > 0).then(|| {
        let mut stripped = tail[consumed..].to_vec();
        if synthesize_no_verify {
            stripped.push(NormalizedWord::resolved("--no-verify"));
        }
        stripped.extend(deferred_unresolvable_config_values);
        stripped
    })
}

/// Composes every per-command calling-convention rewrite this module
/// applies to one wrapper-chain hop's tail before a rule's flag/target
/// checks ever see it: [`tar_effective_tail`] for `tar`'s dash-less
/// cluster (issue #67) and long-option abbreviations (issue #128), then
/// [`git_strip_global_flags`] for `git`'s own leading global options.
/// Shared by [`CommandRule::matching_rest`] and
/// [`CommandRule::matching_rest_by_name`] so the two walkers can't
/// silently diverge on this point — the same discipline issue #86
/// already established for the `tar` rewrite alone.
fn effective_tail<'a>(base: &str, tail: &'a [NormalizedWord]) -> Cow<'a, [NormalizedWord]> {
    let tail = tar_effective_tail(base, tail);
    match git_strip_global_flags(base, &tail) {
        Some(stripped) => Cow::Owned(stripped),
        None => tail,
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
/// docs disclose for `-xhttp://evil.example.com` — a rule author who
/// needs that specific glued short flag's value checked against
/// `except_targets` declares it via `attached_value_flags` (issue #47)
/// instead: unlike this type, which *excludes* a declared flag's value
/// from candidacy, `attached_value_flags` *adds* the glued value as a
/// new candidate, so declaring a flag there can newly suppress a match
/// that would otherwise fire (see [`attached_value_candidate`]'s docs).
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
        /// ASCII case-fold `target`/the token's normalized form before
        /// comparing (issue #449) — see [`TargetSpec::case_insensitive`].
        case_insensitive: bool,
    },
    /// Path-aware prefix match: the token (after an optional `strip`) is
    /// lexically normalized, rendered to its canonical string form via
    /// [`canonical_render`], and compared with `starts_with` against a
    /// pre-rendered `canon` — see [`Self::matches`].
    NormalizedPrefix {
        strip: Option<String>,
        canon: String,
        /// ASCII case-fold `canon`/the rendered token before comparing
        /// (issue #449) — see [`TargetSpec::case_insensitive`].
        case_insensitive: bool,
    },
    /// Path-aware basename match (issue #427): the token (after an
    /// optional `strip`) is lexically normalized, and its TRAILING path
    /// component — the filename, regardless of what directory prefix
    /// leads to it — is compared against `base`. Matches when the
    /// trailing component equals `base` exactly, or starts with `base`
    /// followed by a literal `.` (a dotenv-family suffix variant: `.env`,
    /// `.env.local`, `.env.production`, …) — mirroring the migrated-from
    /// hook's `\.env([.][a-zA-Z0-9_-]+)?` regex, but as a plain
    /// `starts_with` rather than reimplementing its character class (see
    /// [`Self::matches`]'s own docs for why that's the safe direction).
    ///
    /// Unlike [`Self::NormalizedExact`]/[`Self::NormalizedPrefix`], this
    /// variant is immune to every anchor-uncertainty floor
    /// (`ascent_descent_plausible`/`dirstack_plausible`/
    /// `unknown_cwd_plausible`) — it never claims anything about which
    /// directory the token resolves to, only about the LAST component's
    /// name, which is exactly as certain whether the anchor is `/`, `~`,
    /// an unresolved `..` ascent, or an entirely unknown cwd. Every one of
    /// those already-uncertain anchors still carries a certain trailing
    /// filename, so `Self::matches` treats them all as a hard match, not
    /// a floor.
    NormalizedBasename {
        strip: Option<String>,
        base: String,
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

/// Issue #208's three-way classification of a compiled
/// [`TargetMatcher`] for [`CommandRule::mixes_url_host_with_string_except_target`]'s
/// purposes. `UrlHost` and `StringLiteral` are split out because that
/// split *is* the trap the check exists to catch — a rule migrating to
/// `url_host` but leaving the old `exact`/`prefix` entry in place.
/// `Other` covers every remaining variant (`NormalizedExact`/
/// `NormalizedPrefix`, currently rejected from `except_targets` at parse
/// time by `convert_target`'s `is_except_target` branch, so this arm is
/// unreachable there today) — kept as its own arm on an exhaustive match,
/// rather than folded into `StringLiteral` or left off via a wildcard, so
/// a future `TargetMatcher` variant forces a decision at this call site
/// instead of silently going unclassified.
enum ExceptTargetShape {
    UrlHost,
    StringLiteral,
    Other,
}

/// Common home-container directory names (issue #364), consulted only by
/// [`TargetMatcher::ascent_descent_plausible`]'s extra strip-two-components
/// widening — a small, explicitly disclosed list, not a general
/// `/home/<user>`-shaped-path detector (this codebase has no such
/// heuristic anywhere else, deliberately: see that function's own docs).
/// `"home"` covers Linux/BSD; `"Users"` covers macOS. Missing a container
/// name here is a silent miss of that one variant, not a false negative in
/// the sense the rest of this function's design otherwise avoids — same
/// disclosed trade-off the issue itself accepted as a valid resolution.
const HOME_CONTAINER_DIRS: &[&str] = &["home", "Users"];

/// Whether `component` names a [`HOME_CONTAINER_DIRS`] entry, compared
/// case-insensitively: macOS's default APFS/HFS+ volumes are
/// case-INsensitive, so `users`/`USERS`/`Users` all
/// resolve to the exact same real directory at runtime — a bare
/// case-sensitive match would let a one-character respelling of the
/// very name this list exists to catch silently evade it, a materially
/// different (and avoidable) gap from the disclosed "unlisted container
/// name" residual this list already accepts.
fn is_home_container_dir(component: &str) -> bool {
    HOME_CONTAINER_DIRS
        .iter()
        .any(|dir| dir.eq_ignore_ascii_case(component))
}

impl TargetMatcher {
    fn with_canonical_globs(self) -> Self {
        match self {
            Self::NormalizedExact {
                strip,
                target,
                case_insensitive,
            } => Self::NormalizedExact {
                strip,
                target: canonicalize_glob_form(target),
                case_insensitive,
            },
            other => other,
        }
    }

    fn has_strip(&self) -> bool {
        matches!(
            self,
            Self::NormalizedExact { strip: Some(_), .. }
                | Self::NormalizedPrefix { strip: Some(_), .. }
                | Self::NormalizedBasename { strip: Some(_), .. }
        )
    }

    fn except_target_shape(&self) -> ExceptTargetShape {
        match self {
            Self::UrlHost(_) => ExceptTargetShape::UrlHost,
            Self::Exact(_) | Self::Prefix(_) => ExceptTargetShape::StringLiteral,
            Self::NormalizedExact { .. }
            | Self::NormalizedPrefix { .. }
            | Self::NormalizedBasename { .. } => ExceptTargetShape::Other,
        }
    }

    /// Whether a token that is exactly `/dev/fd/<digits>` (what an input
    /// process substitution expands to) could match this target. The digits
    /// are not known, so every number counts. `false` only for a target
    /// that provably cannot equal or contain such a path: a relative, `~`
    /// or URL target, or an absolute path outside `/dev/fd`. Always `true`
    /// for a `strip` target: the strip text may be glued to the path in one
    /// word (`--out=<(x)`), which the parser splits.
    fn admits_dev_fd(&self) -> bool {
        const DEV_FD: &str = "/dev/fd/";
        let fold = |text: &str, case_insensitive: bool| {
            if case_insensitive {
                text.to_ascii_lowercase()
            } else {
                text.to_owned()
            }
        };
        // Whether some `/dev/fd/<digits>` starts with `prefix`.
        let may_start_with = |prefix: &str, case_insensitive: bool| {
            let (prefix, dev_fd) = (fold(prefix, case_insensitive), DEV_FD.to_owned());
            dev_fd.starts_with(&prefix)
                || prefix
                    .strip_prefix(&dev_fd)
                    .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
        };
        match self {
            Self::Exact(text) => text.starts_with(DEV_FD),
            Self::Prefix(prefix) => may_start_with(prefix, false),
            Self::NormalizedExact {
                strip,
                target,
                case_insensitive,
            } => match (strip, target) {
                (Some(_), _) => true,
                (None, PathForm::Abs(comps)) => {
                    comps.iter().any(|c| c.contains(['*', '?', '[']))
                        || matches!(comps.as_slice(), [dev, fd, number]
                            if fold(dev, *case_insensitive) == "dev"
                                && fold(fd, *case_insensitive) == "fd"
                                && number.bytes().all(|b| b.is_ascii_digit()))
                }
                (None, _) => false,
            },
            Self::NormalizedPrefix {
                strip,
                canon,
                case_insensitive,
            } => match strip {
                Some(_) => true,
                None => may_start_with(canon, *case_insensitive),
            },
            Self::NormalizedBasename { strip, base } => match strip {
                Some(_) => true,
                None => base.bytes().all(|b| b.is_ascii_digit()),
            },
            Self::UrlHost(_) => false,
        }
    }

    /// Whether a `-`-leading token (the only kind that can satisfy any
    /// [`FlagMatcher`]) might ALSO satisfy this target, so that one word
    /// could fill both the flag role and the target role (issue #579).
    /// Conservative: `true` for everything except the two shapes proved
    /// unreachable from a `-` token. A `normalized`/`normalized_prefix`
    /// target anchored at `/` or `~` (no `strip`) never equals the form of
    /// a `-`-leading token (`Rel`), except the bare-`/` target, which
    /// `-x/../..` reaches through the pure-ascent widening in
    /// [`Self::matches`].
    fn may_double_as_flag(&self) -> bool {
        match self {
            Self::NormalizedExact {
                strip: None,
                target: PathForm::Abs(comps),
                ..
            } => comps.is_empty(),
            Self::NormalizedExact {
                strip: None,
                target: PathForm::Home(_),
                ..
            } => false,
            Self::NormalizedPrefix {
                strip: None, canon, ..
            } => !(canon.starts_with('/') || canon.starts_with('~')),
            _ => true,
        }
    }

    /// Whether a word that ENDS with the literal path component `last`
    /// (preceded by a literal `/`, see [`literal_tail_component`]) can
    /// provably never satisfy this target, whatever its unresolved part
    /// expands to (issue #579). Fail-closed: `false` unless proven.
    ///
    /// The proof rests on `last` being the final component of the
    /// normalized form of any such word (nothing follows it to cancel it,
    /// and it is neither `.` nor `..`), and on every [`PathForm`] that
    /// carries a component tail keeping it last. A bare-`~` target also
    /// admits the tail-ignoring `EscapesHome` widening of [`Self::matches`],
    /// reachable only by a word that starts with `~`. Expansion results are
    /// never tilde-expanded, so when the word's literal head does not start
    /// with `~` (`head_tilde == false`) no expansion can make it a `~` form
    /// and that target is excluded; otherwise it is kept.
    fn excluded_by_literal_tail(&self, last: &str, head_tilde: bool) -> bool {
        match self {
            Self::NormalizedExact {
                strip,
                target,
                case_insensitive,
            } => {
                if strip.as_deref().is_some_and(|s| s.contains('/')) {
                    return false;
                }
                let differs = |t: &str| {
                    if *case_insensitive {
                        !t.eq_ignore_ascii_case(last)
                    } else {
                        t != last
                    }
                };
                match target {
                    PathForm::Abs(comps) if comps.is_empty() => true,
                    PathForm::Abs(comps) | PathForm::Home(comps) if !comps.is_empty() => {
                        comps.last().is_some_and(|t| differs(t))
                    }
                    PathForm::Home(_) => !head_tilde,
                    _ => false,
                }
            }
            Self::NormalizedBasename { strip, base } => {
                !strip.as_deref().is_some_and(|s| s.contains('/'))
                    && last != base.as_str()
                    && !last.starts_with(&format!("{base}."))
            }
            _ => false,
        }
    }

    fn matches(&self, token: &str) -> bool {
        match self {
            Self::Exact(exact) => token == exact,
            Self::Prefix(prefix) => token.starts_with(prefix.as_str()),
            Self::NormalizedExact {
                strip,
                target,
                case_insensitive,
            } => {
                let Some(remainder) = strip_target(strip.as_deref(), token) else {
                    return false;
                };
                let form = lexical_normalize(remainder);
                let equal = |form: &PathForm| {
                    if *case_insensitive {
                        case_fold_path_form(form) == case_fold_path_form(target)
                    } else {
                        form == target
                    }
                };
                // Both spellings: an allowlist target keeps its literal
                // glob (`TargetGlobs::Literal`), which only the raw form
                // can equal.
                if equal(&form) || equal(&glob_canonical_form(remainder)) {
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
            Self::NormalizedPrefix {
                strip,
                canon,
                case_insensitive,
            } => {
                let Some(remainder) = strip_target(strip.as_deref(), token) else {
                    return false;
                };
                canonical_render(&lexical_normalize(remainder)).is_some_and(|rendered| {
                    if *case_insensitive {
                        rendered
                            .to_ascii_lowercase()
                            .starts_with(&canon.to_ascii_lowercase())
                    } else {
                        rendered.starts_with(canon.as_str())
                    }
                })
            }
            Self::NormalizedBasename { strip, base } => {
                let Some(remainder) = strip_target(strip.as_deref(), token) else {
                    return false;
                };
                path_form_last_component(&lexical_normalize(remainder)).is_some_and(|last| {
                    last == base.as_str() || last.starts_with(&format!("{base}."))
                })
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
    /// Issue #118 (the first-component case fixed here; a deeper variant
    /// is tracked separately as issue #364 — see "Known gaps" below): the
    /// tail's own FIRST component is additionally tried as if it
    /// collapsed back to a bare `~` — i.e. `~/<rest of the tail>` — whenever
    /// a `~`-anchored `canon`/`target` is in play and the tail has at least
    /// one component after that first one. This narrows the gap
    /// `ascent_descent_plausible` used to have with the escaped-past
    /// anchor's own basename reappearing mid-tail: `~alice/../bob/
    /// .config/shguard/x` renders `bob` as `comps[0]`, which the ORIGINAL
    /// (non-re-anchored) candidate keeps in front of `.config`, never
    /// prefix-matching a `~/.config/shguard` canon — but shguard cannot
    /// rule out that `bob` IS the invoking user's own account, in which
    /// case a real shell collapses `bob/.config/shguard/x` right back to
    /// `~/.config/shguard/x`. Trying `~/<comps[1..]>` as one more candidate
    /// catches exactly that case, the same "can't prove it, so widen
    /// rather than silently miss it" posture the rest of this function
    /// already uses. The `comps.len() >= 2` guard is defense-in-depth, not
    /// load-bearing — see the two call sites' own comments for why a
    /// 1-component tail could never match a non-degenerate canon here
    /// regardless.
    ///
    /// Applies uniformly across every source shape above (`Rel`,
    /// `EscapesHome`/`NamedUserHomeEscapes`, `DirStack`), not only the two
    /// tilde-escape shapes the motivating example uses: an unresolved
    /// `Rel` ascent's own landing directory is exactly as unknown as a
    /// named user's home, so a reappearing name mid-tail is exactly as
    /// plausibly the invoker's own `$HOME` there too (`cp e
    /// ../bob/.config/shguard/x` floors the same way `~alice/../bob/
    /// .config/shguard/x` does) — deliberate, not an oversight.
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
    /// - Issue #364 (partially closed): a tail that spells a common home
    ///   CONTAINER directory explicitly before the reappearing name
    ///   (`~alice/../home/bob/.config/shguard/x`) is now also tried by
    ///   stripping `comps[0..2]` (`home`/`bob`) when `comps[0]` is in
    ///   [`HOME_CONTAINER_DIRS`], on top of the plain `comps[0..1]` strip
    ///   above. This is a small, explicitly disclosed list, not a general
    ///   `/home/<user>`-shaped-path heuristic — a container name this
    ///   codebase has no canonical way to detect otherwise. Still misses
    ///   any container name absent from that list.
    fn ascent_descent_plausible(&self, token: &str) -> bool {
        let strip = match self {
            Self::NormalizedPrefix { strip, .. } | Self::NormalizedExact { strip, .. } => strip,
            // Issue #427: no floor needed — `Self::matches`'s
            // `NormalizedBasename` arm already treats an unresolved-ascent
            // token as a HARD match (see that variant's own docs), since
            // its trailing filename is exactly as certain no matter how
            // many directories up the unknown ascent lands.
            Self::Exact(_)
            | Self::Prefix(_)
            | Self::UrlHost(_)
            | Self::NormalizedBasename { .. } => {
                return false;
            }
        };
        let Some(remainder) = strip_target(strip.as_deref(), token) else {
            return false;
        };
        let comps = match lexical_normalize(strip_filter_qualifier(remainder)) {
            PathForm::Rel { ascent, comps } if ascent >= 1 => comps,
            PathForm::EscapesHome(comps)
            | PathForm::NamedUserHomeEscapes(comps)
            // Issue #133: a dirstack anchor (`~+`/`~-`/`~N`) is just as
            // unknown as an unresolved ascent's own starting cwd, so a
            // descended-into tail (`~-/etc/passwd`) is the same "unknown
            // anchor, known descent" shape as the two arms above — see
            // `PathForm::DirStack`'s own docs for the full reasoning,
            // including why a leading `..` doesn't need separate handling
            // here the way `EscapesHome`/`NamedUserHomeEscapes` do. Unlike
            // `dirstack_plausible` just below, this floor does NOT exclude
            // a `strip: Some(..)` target (an attached slot like dd's
            // `of=`) — `dirstack_plausible`'s exclusion rests on `of=~+`
            // not tilde-expanding as a *whole-token* shorthand in the
            // first place (issue #134), but says nothing about whether
            // `of=~-/dev/sda` is a dangerous literal string in its own
            // right; treating it the same as `of=~/../dev/sda` (which
            // already floors via `EscapesHome` above, strip or not) keeps
            // this fail-closed rather than opening a strip-shaped gap the
            // #134 exclusion was never meant to create.
            | PathForm::DirStack(comps) => comps,
            _ => return false,
        };
        if comps.is_empty() {
            return false;
        }
        match self {
            Self::NormalizedPrefix {
                canon,
                case_insensitive,
                ..
            } => {
                let candidate = if canon.starts_with('/') {
                    abs_render(&comps)
                } else if canon.starts_with('~') {
                    format!("~/{}", comps.join("/"))
                } else {
                    return false; // degenerate canon (e.g. "."), never plausible
                };
                // `case_insensitive` (issue #449 review follow-up): reads
                // the SAME flag `TargetMatcher::matches` folds by, so a
                // self-protection rule case-folded for a macOS APFS volume
                // doesn't miss a re-cased ascent-descent tail here that
                // `matches` would have hard-matched had the anchor been
                // certain instead of merely plausible.
                let starts_with_canon = |s: &str| -> bool {
                    if *case_insensitive {
                        s.to_ascii_lowercase()
                            .starts_with(&canon.to_ascii_lowercase())
                    } else {
                        s.starts_with(canon.as_str())
                    }
                };
                if starts_with_canon(&candidate) {
                    return true;
                }
                // Issue #118: the tail's own first component re-anchored as
                // `~`, tried whenever `canon` is itself `~`-anchored and
                // there's a component past it to descend into — see this
                // function's own doc for the full "escaped anchor's
                // basename reappearing mid-tail" rationale. `comps.len() >=
                // 2` is defense-in-depth, not what prevents over-firing on
                // a lone name: with exactly 1 component the widened
                // candidate is `"~/"`, which can't `starts_with` any
                // non-degenerate `~`-anchored canon (the minimum matchable
                // shape is `~/x`), so a bare `~alice/../bob` can never
                // reach a dangerous namespace here regardless of this
                // guard's presence.
                (canon.starts_with('~')
                    && comps.len() >= 2
                    && starts_with_canon(&format!("~/{}", comps[1..].join("/"))))
                    // Issue #364: the same re-anchoring one component
                    // further in, when the tail spells a common home
                    // CONTAINER directory before the reappearing name
                    // (`~alice/../home/bob/.config/shguard/x` strips
                    // `home` too, not just `bob`) -- see this function's
                    // own doc for why this is a small, explicitly
                    // disclosed list rather than a general heuristic.
                    || (canon.starts_with('~')
                        && comps.len() >= 3
                        && is_home_container_dir(&comps[0])
                        && starts_with_canon(&format!("~/{}", comps[2..].join("/"))))
            }
            Self::NormalizedExact {
                target,
                case_insensitive,
                ..
            } => {
                let (PathForm::Abs(target_comps) | PathForm::Home(target_comps)) = target else {
                    return false;
                };
                if target_comps.is_empty() {
                    return false;
                }
                // `case_insensitive`: same rationale as the prefix arm
                // above.
                let eq = |a: &[String], b: &[String]| -> bool {
                    if *case_insensitive {
                        a.len() == b.len()
                            && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
                    } else {
                        a == b
                    }
                };
                // Same canonical spelling `Self::matches` compares.
                let mut comps = comps;
                canonicalize_glob_comps(&mut comps);
                // Issue #506: the `comps[1..]`/`comps[2..]` widening arms
                // below exist to catch a REAPPEARING NAME after an
                // escaped/unresolved ascent (`~alice/../bob` re-descending
                // into the very `bob` this rule cares about), a
                // coincidence specific enough to be worth flooring to Ask.
                // A target made ENTIRELY of glob wildcard components
                // (see `is_glob_only_component`, e.g. `~/*`, `~/.*`) has no such
                // specificity: `comps`'s own trailing component is a
                // wildcard for essentially any benign relative path
                // (`../build/*`, `../build/.*`, ...), so the same
                // widening would flag nearly every sibling-directory
                // glob cleanup, not a real re-anchoring risk.
                // Excluded from the widening arms only — the DIRECT `eq`
                // just below is unaffected, so `rm -r ../*` (an unresolved
                // ascent landing who-knows-where, then globbing
                // everything there) still asks on its own, unwidened
                // merit.
                // Structural, not a spelling list: a list duplicating
                // blocklist.toml's glob targets lets a new glob target
                // silently reintroduce issue #559.
                let widening_target_is_wildcard_only =
                    target_comps.iter().all(|c| is_glob_only_component(c));
                eq(target_comps, &comps)
                    // Issue #118: same re-anchoring as the prefix arm above,
                    // but only against a `~`-anchored target (an `Abs`
                    // target has no anchor a reappearing name could
                    // collapse back into). `comps.len() >= 2` is
                    // defense-in-depth here too — with exactly 1 component,
                    // `comps[1..]` is empty and `target_comps` is guaranteed
                    // non-empty (checked just above), so the equality can
                    // never hold regardless of this guard.
                    || (matches!(target, PathForm::Home(_))
                        && !widening_target_is_wildcard_only
                        && comps.len() >= 2
                        && eq(&comps[1..], target_comps))
                    // Issue #364: same one-component-further widening as
                    // the prefix arm above.
                    || (matches!(target, PathForm::Home(_))
                        && !widening_target_is_wildcard_only
                        && comps.len() >= 3
                        && is_home_container_dir(&comps[0])
                        && eq(&comps[2..], target_comps))
            }
            Self::Exact(_)
            | Self::Prefix(_)
            | Self::UrlHost(_)
            | Self::NormalizedBasename { .. } => {
                unreachable!("filtered out above")
            }
        }
    }

    // Not folded into `Self::matches`: what a glob expands to depends on
    // the filesystem, so this only feeds the Ask-capped
    // `crate::gate::scan_glob_floor`. `*`/`?`/brackets may match a leading
    // `.` (dotglob, zsh): assuming bash's default would be fail-open.
    fn glob_plausible(&self, token: &str) -> bool {
        let (strip, target, case_insensitive, beneath, partial_last) = match self {
            Self::NormalizedExact {
                strip,
                target,
                case_insensitive,
            } => {
                let glob_last = match target {
                    PathForm::Abs(comps) | PathForm::Home(comps) | PathForm::Rel { comps, .. } => {
                        comps.last().is_some_and(|last| is_canonical_glob(last))
                    }
                    _ => false,
                };
                let beneath = if glob_last {
                    GlobBeneath::GlobOnly
                } else {
                    GlobBeneath::Nothing
                };
                (strip, target.clone(), *case_insensitive, beneath, false)
            }
            Self::NormalizedPrefix {
                strip,
                canon,
                case_insensitive,
            } => (
                strip,
                lexical_normalize(canon),
                *case_insensitive,
                GlobBeneath::Anything,
                !canon.ends_with('/'),
            ),
            Self::Exact(_)
            | Self::Prefix(_)
            | Self::UrlHost(_)
            | Self::NormalizedBasename { .. } => return false,
        };
        let Some(remainder) = strip_target(strip.as_deref(), token) else {
            return false;
        };
        let form = superset_glob_form(lexical_normalize(&superset_glob_path(remainder)));
        let (pattern, unknown_anchor) = match (&form, &target) {
            (PathForm::Abs(pattern), PathForm::Abs(_))
            | (PathForm::Home(pattern), PathForm::Home(_)) => (pattern, false),
            (
                PathForm::Rel {
                    ascent: a,
                    comps: pattern,
                },
                PathForm::Rel { ascent: b, .. },
            ) if a == b => (pattern, false),
            (PathForm::Rel { ascent, comps }, PathForm::Abs(_) | PathForm::Home(_))
                if *ascent >= 1 =>
            {
                (comps, true)
            }
            (
                PathForm::EscapesHome(comps)
                | PathForm::NamedUserHomeEscapes(comps)
                | PathForm::DirStack(comps),
                PathForm::Abs(_) | PathForm::Home(_),
            ) => (comps, true),
            _ => return false,
        };
        let (PathForm::Abs(target_comps)
        | PathForm::Home(target_comps)
        | PathForm::Rel {
            comps: target_comps,
            ..
        }) = &target
        else {
            return false;
        };
        if !pattern.iter().any(|c| c.contains(['*', '?', '['])) {
            return false;
        }
        let how = GlobMatch {
            beneath,
            partial_last,
            case_insensitive,
        };
        // At an unknown anchor a leading glob-only component (`../*/dist`,
        // `../*/*`) names every sibling, not a reappearing target name:
        // aligning it with `dev` or with `~/*` would ask on any sibling
        // cleanup. A bare `../*` still asks through the ascent-descent floor.
        let leading_wildcard =
            unknown_anchor && pattern.first().is_some_and(|c| is_glob_only_component(c));
        if !leading_wildcard && comps_glob_plausible(pattern, target_comps, how) {
            return true;
        }
        if !unknown_anchor
            || !matches!(target, PathForm::Home(_))
            || target_comps.iter().all(|c| is_glob_only_component(c))
        {
            return false;
        }
        // The reappearing-name widening of `ascent_descent_plausible`. A
        // glob-only rest (`../build/*`) is skipped for the reason it skips a
        // glob-only target: it would flag every sibling-directory cleanup.
        let widened = |skip: usize| {
            let rest = &pattern[skip..];
            !rest.iter().all(|c| is_glob_only_component(c))
                && comps_glob_plausible(rest, target_comps, how)
        };
        (pattern.len() >= 2 && widened(1))
            || (pattern.len() >= 3 && is_home_container_dir(&pattern[0]) && widened(2))
    }
}

fn is_canonical_glob(comp: &str) -> bool {
    comp == "*" || comp == ".*"
}

// Which pattern components may be left over once the target is consumed.
// `GlobOnly` (an exact glob target such as `~/*`): `~/*/*` empties every
// subdirectory, but `*/node_modules` is not the "every entry" claim `*` is.
#[derive(Clone, Copy)]
enum GlobBeneath {
    Nothing,
    GlobOnly,
    Anything,
}

impl GlobBeneath {
    // Indexed by where the leftover starts in `pattern`.
    fn admits_suffixes(self, pattern: &[String]) -> Vec<bool> {
        let mut admits = vec![true; pattern.len() + 1];
        for p in (0..pattern.len()).rev() {
            admits[p] = match self {
                Self::Nothing => false,
                Self::GlobOnly => admits[p + 1] && is_glob_only_component(&pattern[p]),
                Self::Anything => true,
            };
        }
        admits
    }
}

#[derive(Clone, Copy)]
struct GlobMatch {
    beneath: GlobBeneath,
    // The last target component is a string prefix
    // (`normalized_prefix = "/dev/sd"`).
    partial_last: bool,
    case_insensitive: bool,
}

// Forward reachability over (pattern index, target index), not recursive
// backtracking: a padded run of `**` components backtracks exponentially.
fn comps_glob_plausible(pattern: &[String], target: &[String], how: GlobMatch) -> bool {
    let width = target.len() + 1;
    let admits = how.beneath.admits_suffixes(pattern);
    let mut reached = vec![false; (pattern.len() + 1) * width];
    reached[0] = true;
    for p in 0..=pattern.len() {
        for t in 0..width {
            if !reached[p * width + t] {
                continue;
            }
            let Some(comp) = pattern.get(p) else {
                if t == target.len() {
                    return true;
                }
                continue;
            };
            if comp == "**" {
                reached[(p + 1) * width + t] = true;
            }
            let Some(target_comp) = target.get(t) else {
                if admits[p] {
                    return true;
                }
                continue;
            };
            if comp == "**" {
                reached[p * width + t + 1] = true;
                continue;
            }
            // Against a glob target (`~/*`), only another glob-only component is
            // the same "every entry" claim; a literal `build` in `build/*` is not.
            let component_matches = if is_canonical_glob(target_comp) {
                is_glob_only_component(comp)
            } else {
                glob_component_matches(
                    comp.as_bytes(),
                    target_comp.as_bytes(),
                    how.partial_last && t + 1 == target.len(),
                    how.case_insensitive,
                )
            };
            if component_matches {
                reached[(p + 1) * width + t + 1] = true;
            }
        }
    }
    false
}

// Not lowercasing the pattern: that turns `[!A-Z]` into `[!a-z]` and
// inverts what a negated bracket admits.
fn glob_component_matches(
    pattern: &[u8],
    name: &[u8],
    name_is_prefix: bool,
    case_insensitive: bool,
) -> bool {
    let swapped = |c: u8| {
        if c.is_ascii_lowercase() {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        }
    };
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        let step = match pattern.get(p) {
            Some(b'*') => {
                star = Some((p + 1, n));
                p += 1;
                continue;
            }
            Some(b'?') => Some(p + 1),
            Some(b'[') => match bracket_expr_end(pattern, p) {
                Some(end) => {
                    let expr = &pattern[p..end];
                    (bracket_matches(expr, name[n])
                        || (case_insensitive && bracket_matches(expr, swapped(name[n]))))
                    .then_some(end)
                }
                None => (name[n] == b'[').then_some(p + 1),
            },
            Some(&literal) => (literal == name[n]
                || (case_insensitive && literal.eq_ignore_ascii_case(&name[n])))
            .then_some(p + 1),
            None => None,
        };
        if let Some(next) = step {
            p = next;
            n += 1;
            continue;
        }
        let Some((star_p, star_n)) = star else {
            return false;
        };
        star = Some((star_p, star_n + 1));
        p = star_p;
        n = star_n + 1;
    }
    name_is_prefix || pattern[p..].iter().all(|&b| b == b'*')
}

fn bracket_matches(expr: &[u8], c: u8) -> bool {
    let inner = &expr[1..expr.len() - 1];
    let (negate, mut i) = match inner.first() {
        Some(b'!' | b'^') => (true, 1),
        _ => (false, 0),
    };
    let mut hit = false;
    while i < inner.len() {
        if inner[i] == b'['
            && matches!(inner.get(i + 1), Some(b':' | b'=' | b'.'))
            && let Some(end) = posix_bracket_term_end(inner, i)
        {
            let name = &inner[i + 2..end - 2];
            if inner[i + 1] == b':' {
                // An unknown class may match anything, negated or not.
                let Some(matched) = posix_class_matches(name, c) else {
                    return true;
                };
                hit |= matched;
            } else {
                hit |= name == [c];
            }
            i = end;
        } else if inner.get(i + 1) == Some(&b'-') && i + 2 < inner.len() {
            hit |= (inner[i]..=inner[i + 2]).contains(&c);
            i += 3;
        } else {
            hit |= inner[i] == c;
            i += 1;
        }
    }
    hit != negate
}

fn posix_class_matches(class: &[u8], c: u8) -> Option<bool> {
    Some(match class {
        b"alnum" => c.is_ascii_alphanumeric(),
        b"alpha" => c.is_ascii_alphabetic(),
        b"ascii" => c.is_ascii(),
        b"blank" => c == b' ' || c == b'\t',
        b"cntrl" => c.is_ascii_control(),
        b"digit" => c.is_ascii_digit(),
        b"graph" => c.is_ascii_graphic(),
        b"lower" => c.is_ascii_lowercase(),
        b"print" => c.is_ascii_graphic() || c == b' ',
        b"punct" => c.is_ascii_punctuation(),
        b"space" => c.is_ascii_whitespace() || c == 0x0b,
        b"upper" => c.is_ascii_uppercase(),
        b"word" => c.is_ascii_alphanumeric() || c == b'_',
        b"xdigit" => c.is_ascii_hexdigit(),
        _ => return None,
    })
}

// At least one metacharacter is required: `.` and `..` are path steps, not
// globs.
fn is_glob_only_component(comp: &str) -> bool {
    let body = comp.strip_prefix('.').unwrap_or(comp).as_bytes();
    if body.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < body.len() {
        match body[i] {
            b'*' | b'?' => i += 1,
            // An unclosed `[` is a literal character, so not glob-only.
            b'[' => match bracket_expr_end(body, i) {
                Some(end) => i = end,
                None => return false,
            },
            _ => return false,
        }
    }
    true
}

fn bracket_expr_end(pat: &[u8], open: usize) -> Option<usize> {
    let mut j = open + 1;
    if matches!(pat.get(j), Some(b'!' | b'^')) {
        j += 1;
    }
    if pat.get(j) == Some(&b']') {
        j += 1;
    }
    while j < pat.len() {
        match pat[j] {
            b']' => return Some(j + 1),
            // Not a plain member: the `]` inside `[:alpha:]` does not close
            // the bracket.
            b'[' if matches!(pat.get(j + 1), Some(b':' | b'=' | b'.')) => {
                j = posix_bracket_term_end(pat, j).unwrap_or(j + 1);
            }
            _ => j += 1,
        }
    }
    None
}

fn posix_bracket_term_end(pat: &[u8], open: usize) -> Option<usize> {
    let delim = *pat.get(open + 1)?;
    pat.get(open + 2..)?
        .windows(2)
        .position(|w| w == [delim, b']'])
        .map(|off| open + 2 + off + 2)
}

fn canonical_glob_component(comp: &str) -> Option<&'static str> {
    is_glob_only_component(comp).then(|| if comp.starts_with('.') { ".*" } else { "*" })
}

// No extglob or `^` reading here: this feeds hard matches, and `^foo` is
// a literal name in bash and in zsh without EXTENDED_GLOB.
fn canonicalize_glob_comps(comps: &mut [String]) {
    for comp in comps {
        if let Some(canon) = canonical_glob_component(comp) {
            canon.clone_into(comp);
        }
    }
}

// A trailing group is split off on the whole path, not per component,
// because a qualifier such as `(/)` contains the path separator.
fn trailing_group(path: &str) -> Option<(&str, &str)> {
    let body = path.strip_suffix(')')?;
    let mut depth = 0usize;
    for (open, byte) in body.bytes().enumerate().rev() {
        match byte {
            b')' => depth += 1,
            b'(' if depth > 0 => depth -= 1,
            b'(' => return Some((&path[..open], &body[open + 1..])),
            _ => {}
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
enum QualifierGroup {
    // Only narrows which names the glob yields.
    Filter,
    // Rewrites the yielded paths (`:h`, `P:x:`) or runs code (`e:..:`,
    // `+func`, `oe`, `o+`).
    Expands,
    NotQualifier,
}

// zsh's glob qualifier list (zshexpn "Glob Qualifiers"), parsed rather
// than keyword-matched: a parenthetical such as `(see: x)` is plain text,
// while `(e:'rm x':)` holds spaces inside its delimited argument.
fn classify_qualifier_group(group: &str) -> QualifierGroup {
    let bytes = group.as_bytes();
    let mut expands = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        i += 1;
        let parsed = match c {
            b'%' => Some(i + usize::from(matches!(bytes.get(i), Some(b'b' | b'c')))),
            b'/' | b'.' | b'@' | b'=' | b'p' | b'*' | b'r' | b'w' | b'x' | b'A' | b'I' | b'E'
            | b'R' | b'W' | b'X' | b's' | b'S' | b't' | b'F' | b'^' | b'-' | b'M' | b'T' | b'N'
            | b'D' | b'n' | b'U' | b'G' | b',' => Some(i),
            b'e' | b'P' => {
                expands = true;
                skip_delimited(bytes, i)
            }
            b'+' => {
                expands = true;
                skip_identifier(bytes, i)
            }
            b':' => {
                expands = true;
                bytes
                    .get(i)
                    .is_some_and(|m| b"aAcehlPqQrtuxXsgfFwW&".contains(m))
                    .then_some(bytes.len())
            }
            b'o' | b'O' => match bytes.get(i) {
                Some(b'e') => {
                    expands = true;
                    skip_delimited(bytes, i + 1)
                }
                Some(b'+') => {
                    expands = true;
                    skip_identifier(bytes, i + 1)
                }
                Some(b'n' | b'L' | b'l' | b'a' | b'm' | b'c' | b'd' | b'N') => Some(i + 1),
                _ => None,
            },
            b'f' | b'u' | b'g' => match bytes.get(i) {
                Some(d) if d.is_ascii_digit() => Some(skip_number(bytes, i)),
                _ => skip_delimited(bytes, i),
            },
            b'a' | b'm' | b'c' | b'L' | b'l' | b'd' | b'Y' => {
                let mut j = i;
                if bytes.get(j).is_some_and(u8::is_ascii_alphabetic) {
                    j += 1;
                }
                if matches!(bytes.get(j), Some(b'+' | b'-')) {
                    j += 1;
                }
                bytes
                    .get(j)
                    .is_some_and(u8::is_ascii_digit)
                    .then(|| skip_number(bytes, j))
            }
            b'[' => bytes[i..]
                .iter()
                .position(|&b| b == b']')
                .map(|off| i + off + 1),
            _ => None,
        };
        let Some(next) = parsed else {
            return QualifierGroup::NotQualifier;
        };
        i = next;
    }
    match (bytes.is_empty(), expands) {
        (true, _) => QualifierGroup::NotQualifier,
        (false, true) => QualifierGroup::Expands,
        (false, false) => QualifierGroup::Filter,
    }
}

fn skip_number(bytes: &[u8], from: usize) -> usize {
    from + bytes[from..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count()
}

fn skip_identifier(bytes: &[u8], from: usize) -> Option<usize> {
    if !bytes
        .get(from)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return None;
    }
    let len = bytes[from..]
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count();
    (len > 0).then_some(from + len)
}

// zsh's delimited argument: a bracket opener closes with its pair, any
// other byte closes with itself.
fn skip_delimited(bytes: &[u8], from: usize) -> Option<usize> {
    let open = *bytes.get(from)?;
    let close = match open {
        b'[' => b']',
        b'{' => b'}',
        b'(' => b')',
        b'<' => b'>',
        other => other,
    };
    bytes[from + 1..]
        .iter()
        .position(|&b| b == close)
        .map(|off| from + 1 + off + 1)
}

fn last_component_has_glob(head: &str) -> bool {
    head.rsplit('/')
        .next()
        .is_some_and(|last| last.contains(['*', '?', '[']))
}

// Whether `word` carries a zsh glob qualifier that rewrites the paths a
// glob yields or runs code, so no reading of it as a narrowed glob holds.
// Gated on a glob before the group: an unquoted `name(:h)` is a parse
// error, and a quoted parenthetical (`"bump deps (retest)"`) never globs.
// `(#q...)` is the EXTENDED_GLOB inline spelling.
pub(crate) fn has_expanding_glob_qualifier(word: &str) -> bool {
    let trailing = trailing_group(word).is_some_and(|(head, group)| {
        last_component_has_glob(head) && classify_qualifier_group(group) == QualifierGroup::Expands
    });
    trailing
        || word.match_indices("(#q").any(|(at, _)| {
            let rest = &word[at + 3..];
            rest.find(')')
                .is_none_or(|end| classify_qualifier_group(&rest[..end]) != QualifierGroup::Filter)
        })
}

// The unresolved-word twin of `has_expanding_glob_qualifier`, from the
// literal text before the first and after the last unresolved piece. A
// group opened after a glob in the head and closed in the tail
// (`*(e:$X:)`) holds an unknown piece, so it fails closed. A literal
// piece between two unresolved pieces is not visible here.
pub(crate) fn unresolved_word_may_hide_glob_qualifier(
    head: Option<&str>,
    tail: Option<&str>,
) -> bool {
    let Some(tail) = tail else {
        return false;
    };
    has_expanding_glob_qualifier(tail)
        || (tail.ends_with(')')
            && trailing_group(tail).is_none()
            && head.is_some_and(|head| {
                head.match_indices('(')
                    .any(|(at, _)| last_component_has_glob(&head[..at]))
            }))
}

// Hard-match reading: a filter qualifier after a glob only narrows it, so
// the glob alone stands in for it. `f(x)` stays a literal name, and so
// does `s?(x)`: under bash extglob it matches `s`, which `s?` does not.
fn strip_filter_qualifier(path: &str) -> &str {
    match trailing_group(path) {
        Some((head, group))
            if classify_qualifier_group(group) == QualifierGroup::Filter
                && !head.ends_with(['?', '@', '!', '+'])
                && last_component_has_glob(head) =>
        {
            head
        }
        _ => path,
    }
}

// Ask-floor reading, interim until #666 detects these as shell features:
// a filter qualifier, extglob and zsh `^` each expand to a subset of the
// glob read here. An extglob opener plus its group becomes `*`, not the
// bare opener: `s?(x)` matches `s`, which `s?` would not. An expanding
// qualifier is left alone; `has_expanding_glob_qualifier` floors it.
fn superset_glob_path(path: &str) -> Cow<'_, str> {
    if let Some((head, group)) = trailing_group(path)
        && classify_qualifier_group(group) != QualifierGroup::Expands
        && let Some(stem) = head.strip_suffix(['?', '@', '!', '+', '*'])
    {
        return Cow::Owned(format!("{stem}*"));
    }
    Cow::Borrowed(strip_filter_qualifier(path))
}

fn superset_glob_component(comp: &str) -> Option<&'static str> {
    let extglob = ["@(", "!(", "?(", "+(", "*("]
        .iter()
        .any(|opener| comp.contains(opener));
    if comp.starts_with('^') {
        Some("*")
    } else if extglob {
        Some(if comp.starts_with('.') { ".*" } else { "*" })
    } else {
        None
    }
}

fn superset_glob_comps(comps: &mut [String]) {
    for comp in comps {
        if let Some(glob) = superset_glob_component(comp) {
            glob.clone_into(comp);
        }
    }
}

fn form_comps_mut(form: &mut PathForm) -> Option<&mut Vec<String>> {
    match form {
        PathForm::Abs(comps)
        | PathForm::Home(comps)
        | PathForm::EscapesHome(comps)
        | PathForm::NamedUserHomeSub(comps)
        | PathForm::NamedUserHomeEscapes(comps)
        | PathForm::DirStack(comps)
        | PathForm::Rel { comps, .. } => Some(comps),
        PathForm::NamedUserHome | PathForm::DirStackEscapesEmpty | PathForm::Opaque => None,
    }
}

fn superset_glob_form(mut form: PathForm) -> PathForm {
    if let Some(comps) = form_comps_mut(&mut form) {
        superset_glob_comps(comps);
    }
    form
}

// Partial patterns like `.[a-z]*` also become `.*`: fail-closed for a deny
// target, so only deny/ask/redirect targets get this (see `TargetGlobs`).
fn canonicalize_glob_form(mut form: PathForm) -> PathForm {
    if let Some(comps) = form_comps_mut(&mut form) {
        canonicalize_glob_comps(comps);
    }
    form
}

fn glob_canonical_form(path: &str) -> PathForm {
    canonicalize_glob_form(lexical_normalize(strip_filter_qualifier(path)))
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
            ..
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

    /// Whether `token` starts with `~` and this matcher is anchored at an
    /// absolute path with no `strip` slot, so the tilde might expand to a
    /// home directory under it. `$HOME` is deliberately not consulted: the
    /// home directory is not known when the rule is evaluated, so any tilde
    /// form is treated as possibly landing on any absolute target. Ask-only,
    /// like the other plausibility floors, and used only for rules declaring
    /// `target_flags` ([`CommandRule::matches_named_user_home_floor`]).
    /// A `~user` form is also plausible against a `~`-anchored target: it
    /// never normalizes into the invoker's home.
    fn tilde_may_reach_target(&self, token: &str) -> bool {
        if !token.starts_with('~') {
            return false;
        }
        let (absolute, home_anchored) = match self {
            Self::NormalizedExact {
                strip: None,
                target: PathForm::Abs(_),
                ..
            } => (true, false),
            Self::NormalizedExact {
                strip: None,
                target: PathForm::Home(_),
                ..
            } => (false, true),
            Self::NormalizedPrefix {
                strip: None, canon, ..
            } => (canon.starts_with('/'), canon.starts_with('~')),
            Self::Exact(text) | Self::Prefix(text) => {
                (text.starts_with('/'), text.starts_with('~'))
            }
            _ => (false, false),
        };
        let named_user = token != "~" && !token.starts_with("~/");
        absolute || (home_anchored && named_user)
    }

    /// issue #88's Ask-only floor check: true when this matcher declares
    /// no `strip` prefix and `token` itself normalizes to
    /// [`PathForm::DirStack`] with an empty tail (exactly the anchor,
    /// `~+`) or to [`PathForm::DirStackEscapesEmpty`] (one level *above*
    /// the anchor, `~+/..`) — both reduce to "some real but statically
    /// unknown directory," so both get the same floor eligibility. `~+`/
    /// `~-`/`~N` expand against `$PWD`/`$OLDPWD`/a pushd-stack entry — an
    /// anchor no [`PathForm`] a target can declare represents, so unlike
    /// [`Self::named_user_home_plausible`]/[`Self::ascent_descent_plausible`]
    /// there is no target *value* to compare against (the anchor is
    /// unbounded by construction). The correlation available here is the
    /// *slot* instead: a `strip: Some(..)` target (e.g. `dd`'s `of=`)
    /// expects an ATTACHED token (`of=/dev/sda`), and a bare
    /// `~+`/`~-`/`~N` glued after that same flag (`of=~+`) is a separate
    /// zsh-`magic_equal_subst` question, handled by
    /// [`CommandRule::matches_dirstack_equal_subst_floor`] (issue #134) —
    /// which has its own corroborating-slot gate — so `strip: Some(..)`
    /// targets are excluded here the same way they're excluded from ever
    /// actually matching an unattached dirstack token.
    fn dirstack_plausible(&self, token: &str) -> bool {
        let strip = match self {
            Self::NormalizedExact { strip, .. } | Self::NormalizedPrefix { strip, .. } => strip,
            // Issue #427: no bare-anchor floor applies — `NormalizedBasename`
            // has no "bare `~`-shaped target" concept to widen from in the
            // first place (see `ascent_descent_plausible`'s own comment:
            // `Self::matches` already hard-matches a non-empty dirstack
            // tail, and a bare/empty-tail anchor carries no filename at all
            // for this matcher to compare against).
            Self::Exact(_)
            | Self::Prefix(_)
            | Self::UrlHost(_)
            | Self::NormalizedBasename { .. } => {
                return false;
            }
        };
        if strip.is_some() {
            return false;
        }
        // Bare anchor or escaped-to-empty-anchor only — a non-empty tail
        // is a distinct, more specific shape `ascent_descent_plausible`
        // now floors (issue #133): a rule's bare-`~` target slot is what
        // this probe is checking eligibility for, and `~-/etc/passwd` is
        // not plausibly *that* slot the way bare `~-`/`~-/..` are.
        match lexical_normalize(token) {
            PathForm::DirStack(tail) => tail.is_empty(),
            PathForm::DirStackEscapesEmpty => true,
            _ => false,
        }
    }

    /// Issue #103's poisoned-cwd Ask floor: true when `token` normalizes to
    /// a bare relative shape ([`PathForm::Rel`]) that COULD land inside
    /// this matcher's own dangerous namespace if the (entirely unknown —
    /// `crate::gate::CwdContext::Poisoned`) working directory happened to
    /// be the right ancestor.
    ///
    /// - [`Self::NormalizedExact`]: the token's full component list must be
    ///   a trailing suffix of the target's own components (`is_suffix_of`)
    ///   — e.g. `token = "shguard"` against `target = ~/.config/shguard`
    ///   (`comps = [".config", "shguard"]`) is plausible (an unknown cwd of
    ///   `~/.config` would land exactly there); `token = "etc/shguard"`
    ///   is not (no cwd makes `etc` a stand-in for `.config`).
    /// - [`Self::NormalizedPrefix`]: only the token's components MINUS its
    ///   own last (filename) component need to suffix-match the matcher's
    ///   `canon` — a prefix target's whole point is that anything sits
    ///   below it, so `token = "config.toml"` alone (no leading
    ///   directories at all) is trivially plausible (an empty suffix always
    ///   matches — the unknown cwd could just be the protected directory
    ///   itself), while `token = "foo/config.toml"` is vetoed the same way
    ///   the `NormalizedExact` case is: `foo` can never be a shorter
    ///   spelling of this matcher's own trailing path component.
    ///
    /// Deliberately NOT folded into [`Self::matches`]: shguard has no cwd
    /// (folded or otherwise, under `Poisoned`) to prove the token actually
    /// resolves here, so this must only ever feed a `gate.rs` floor capped
    /// at `Ask` (see `crate::gate::scan_unknown_cwd_floor`), never the
    /// matched rule's own (often stricter) decision — the same posture as
    /// [`Self::ascent_descent_plausible`].
    fn unknown_cwd_plausible(&self, token: &str) -> bool {
        match self {
            Self::NormalizedExact {
                strip,
                target,
                case_insensitive,
            } => {
                let target_comps = match target {
                    PathForm::Abs(comps) | PathForm::Home(comps) => comps,
                    _ => return false,
                };
                let Some(remainder) = strip_target(strip.as_deref(), token) else {
                    return false;
                };
                let mut comps = match lexical_normalize(strip_filter_qualifier(remainder)) {
                    PathForm::Rel { comps, .. } => comps,
                    _ => return false,
                };
                canonicalize_glob_comps(&mut comps);
                !comps.is_empty() && is_suffix_of(&comps, target_comps, *case_insensitive)
            }
            Self::NormalizedPrefix {
                strip,
                canon,
                case_insensitive,
            } => {
                let canon_comps = match lexical_normalize(canon) {
                    PathForm::Abs(comps) | PathForm::Home(comps) => comps,
                    _ => return false,
                };
                let Some(remainder) = strip_target(strip.as_deref(), token) else {
                    return false;
                };
                let comps = match lexical_normalize(remainder) {
                    PathForm::Rel { comps, .. } => comps,
                    _ => return false,
                };
                if comps.is_empty() {
                    return false;
                }
                is_suffix_of(&comps[..comps.len() - 1], &canon_comps, *case_insensitive)
            }
            // Issue #427: no floor needed — `Self::matches`'s
            // `NormalizedBasename` arm already hard-matches a `Rel` token
            // regardless of `CwdContext`, for the same "trailing filename
            // is certain even when the anchor isn't" reason
            // `ascent_descent_plausible`'s own comment gives.
            Self::Exact(_)
            | Self::Prefix(_)
            | Self::UrlHost(_)
            | Self::NormalizedBasename { .. } => false,
        }
    }
}

/// Whether `needle` is a contiguous trailing suffix of `haystack` — the
/// empty slice is always a suffix of anything, matching
/// [`TargetMatcher::unknown_cwd_plausible`]'s "the unknown cwd could just
/// be the protected directory itself" case for a `NormalizedPrefix` target.
/// `case_insensitive` compares each component with `eq_ignore_ascii_case`
/// instead of `==` (issue #449 review follow-up): this floor reads the
/// matcher's own `case_insensitive` flag, so a self-protection rule
/// case-folded for a macOS APFS volume doesn't miss the SAME re-cased
/// spelling here that `TargetMatcher::matches` already tolerates.
fn is_suffix_of(needle: &[String], haystack: &[String], case_insensitive: bool) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let tail = &haystack[haystack.len() - needle.len()..];
    if case_insensitive {
        tail.iter()
            .zip(needle)
            .all(|(h, n)| h.eq_ignore_ascii_case(n))
    } else {
        tail == needle
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
/// canonicalizing against the real filesystem would be wrong here — shguard does static/
/// offline analysis (a target path may not exist yet, e.g. inside an
/// unextracted tar archive) and never knows the invoking shell's cwd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathForm {
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
    /// statically.
    NamedUserHome,
    /// A `~username/subdir`-shaped token whose trailing components do NOT
    /// collapse away (`~username/data`, unlike `NamedUserHome`'s bare
    /// `~username`) and did NOT escape past the account's home either
    /// (unlike `NamedUserHomeEscapes`) — issue #427. Distinct from
    /// `NamedUserHome` because the two anchor-comparing matchers
    /// (`NormalizedExact`/`NormalizedPrefix`) genuinely cannot say anything
    /// about an arbitrary account's real home directory, so this used to
    /// collapse into [`PathForm::Opaque`] (out of scope, symmetric with
    /// `Home`/`EscapesHome` only ever covering `~` itself) — but
    /// [`TargetMatcher::NormalizedBasename`] doesn't compare the anchor at
    /// all, only the TRAILING component, which is exactly as certain here
    /// as it is for every other anchor shape (`~alice/.env` is a `.env`
    /// file regardless of whether `~alice` itself is reachable). Carries
    /// the full component list (not just the last one) so
    /// `path_form_last_component` can extract it uniformly with every
    /// other tail-carrying variant.
    NamedUserHomeSub(Vec<String>),
    /// A `~username/..`-shaped token whose `..` popped past that user's
    /// home — provably outside it, even though the exact resulting path
    /// is unknown (mirrors [`PathForm::EscapesHome`] for a named user
    /// rather than the invoker's own `$HOME`). Carries the post-escape
    /// tail the same way `EscapesHome` does (issue #90).
    NamedUserHomeEscapes(Vec<String>),
    /// A `~+`/`~-`/`~N`/`~+N`/`~-N` directory-stack shorthand (`N` one or
    /// more ASCII digits), carrying the tail of components after it —
    /// empty for exactly that token, or `.`/`.`-padded equivalents
    /// (`~+/.`, `~+//`) that collapse to no remaining components, the same
    /// way `~/.`/`~username/.` collapse to their own bare forms;
    /// non-empty for a real subdirectory tail (`~-/etc/passwd` is
    /// `DirStack(["etc", "passwd"])`, issue #133). A real shell expands
    /// `~+`/`~-` to `$PWD`/`$OLDPWD` and `~N`-shaped forms to a numbered
    /// `pushd`/`popd` directory-stack entry (issue #88) — an arbitrary,
    /// unbounded directory shguard has no cwd or directory stack to
    /// resolve against, so the bare (empty-tail) case only ever feeds a
    /// `gate.rs` floor capped at `Ask`
    /// (`crate::gate::scan_dirstack_tilde_floor`), the same floor a bare,
    /// literal `$PWD`/`$OLDPWD` reference already gets via the
    /// unresolved-`$VAR` floor (rule 4) — never a rule's own (often
    /// `Block`) decision, since unlike a bare `~` every shell expands
    /// identically, whether `~+`/`~-`/`~N` denote a *specific* dangerous
    /// target can't be known statically.
    ///
    /// A non-empty tail is structurally the same "unknown anchor, known
    /// descent" shape [`PathForm::EscapesHome`]/[`PathForm::NamedUserHomeEscapes`]
    /// already are, and floors through the same mechanism
    /// ([`TargetMatcher::ascent_descent_plausible`]) rather than
    /// `dirstack_plausible`'s own bare-anchor-only check: unlike
    /// `NamedUserHome` (whose anchor is a specific, if unresolvable, real
    /// account home directory — genuinely out of scope for an arbitrary
    /// subdirectory the same way an ordinary unresolvable path is),
    /// `~-`/`~N`'s anchor could be ANY absolute directory including `/`,
    /// `/etc`, or a device mount point, making a descended-into tail just
    /// as namespace-relevant as one following a plain unresolved ascent
    /// (`../../etc/passwd`).
    ///
    /// Whether a leading `..` in the source token popped past the
    /// (already-unknown) anchor before real components resumed does NOT
    /// change a NON-EMPTY resulting tail: with no real anchor to cancel
    /// against in the first place, an un-cancelable leading `..` and no
    /// leading `..` at all produce the identical resulting tail (verified:
    /// `~-/etc/passwd` and `~-/../etc/passwd` both normalize to
    /// `DirStack(["etc", "passwd"])`) — exactly mirroring how
    /// [`PathForm::Rel`]'s own `ascent`-then-`comps` shape already feeds
    /// [`TargetMatcher::ascent_descent_plausible`] purely by tail content,
    /// independent of how many leading `..`s produced it, since the real
    /// cwd is equally unknown there too.
    ///
    /// An EMPTY resulting tail is the one place `..`-popping still
    /// matters: `~+` (`escaped == false`, exactly the anchor) and `~+/..`
    /// (`escaped == true`, one level *above* the anchor) are different,
    /// unequal locations that both reduce to an empty `stack` — collapsing
    /// them into the same `DirStack(vec![])` would wrongly make `~+/..`
    /// match a rule's own bare-`~` target the way `~+` itself correctly
    /// does ([`TargetMatcher::dirstack_plausible`]'s `tail.is_empty()`
    /// check). [`lexical_normalize`] routes that one case to
    /// [`PathForm::DirStackEscapesEmpty`] instead.
    DirStack(Vec<String>),
    /// `~+/..`/`~-/..`/`~N/..`: a dirstack anchor whose `..` popped past it
    /// with nothing left over — provably one level *above* an unknown-but-
    /// real anchor ($PWD/$OLDPWD/a pushd-stack entry), the same shape
    /// `PathForm::Rel { ascent: 1, comps: vec![] }` (plain `..`) is for an
    /// unknown cwd. Unlike `Rel`'s pure-ascent case, this does NOT hard-
    /// match `TargetMatcher::matches`'s bare-`/` widening (the anchor
    /// isn't provably real filesystem state the way an actual cwd is) —
    /// it only feeds `TargetMatcher::dirstack_plausible`'s existing
    /// Ask-only floor, alongside the exact-anchor (`~+`) case, since both
    /// share the same "anchor's real identity is unknown, so any strip:
    /// None-slot target through it deserves at least Ask" reasoning
    /// (issue #133 review follow-up).
    DirStackEscapesEmpty,
    /// Matches nothing: only the empty string (a `~username/subdir` token
    /// is [`PathForm::NamedUserHomeSub`] as of issue #427).
    Opaque,
}

/// True for `+`/`-`/`N`/`+N`/`-N` (`N` one or more ASCII digits) — bash/zsh
/// directory-stack shorthand (`~+`/`~-` expand to `$PWD`/`$OLDPWD`,
/// `~N`/`~+N`/`~-N` to a numbered pushd/popd entry), never a real account
/// name. Used by [`lexical_normalize`] to route these tokens to
/// [`PathForm::DirStack`]/[`PathForm::Opaque`] (issue #88) instead of
/// [`PathForm::NamedUserHome`]/[`NamedUserHomeEscapes`].
pub(crate) fn is_dirstack_shape(prefix: &str) -> bool {
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
pub(crate) fn lexical_normalize(token: &str) -> PathForm {
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
        // so `~+/.`/`~+//` still collapse to an empty-tail `DirStack` the
        // same way `~/.`/`~username/.` collapse to their own bare forms.
        // Issue #133: see `PathForm::DirStack`'s own docs for why `escaped`
        // only matters when `stack` ends up empty, not otherwise.
        if dirstack {
            return if escaped && stack.is_empty() {
                PathForm::DirStackEscapesEmpty
            } else {
                PathForm::DirStack(stack)
            };
        }
        return if escaped {
            PathForm::NamedUserHomeEscapes(stack)
        } else if stack.is_empty() {
            PathForm::NamedUserHome
        } else {
            PathForm::NamedUserHomeSub(stack)
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

/// ASCII-lowercases every path component in `form`, preserving its shape
/// (anchor kind, `ascent`) — used only by
/// [`TargetMatcher::NormalizedExact`]'s case-insensitive comparison
/// (issue #449, see [`TargetSpec::case_insensitive`]). Folding only the
/// component TEXT, never the shape, means a target and a token that
/// normalize to different anchors (`Abs` vs `Home`) still correctly
/// don't match just because folding happens to run on both.
fn case_fold_path_form(form: &PathForm) -> PathForm {
    fn fold(comps: &[String]) -> Vec<String> {
        comps.iter().map(|c| c.to_ascii_lowercase()).collect()
    }
    match form {
        PathForm::Abs(comps) => PathForm::Abs(fold(comps)),
        PathForm::Home(comps) => PathForm::Home(fold(comps)),
        PathForm::EscapesHome(comps) => PathForm::EscapesHome(fold(comps)),
        PathForm::Rel { ascent, comps } => PathForm::Rel {
            ascent: *ascent,
            comps: fold(comps),
        },
        PathForm::NamedUserHome => PathForm::NamedUserHome,
        PathForm::NamedUserHomeSub(comps) => PathForm::NamedUserHomeSub(fold(comps)),
        PathForm::NamedUserHomeEscapes(comps) => PathForm::NamedUserHomeEscapes(fold(comps)),
        PathForm::DirStack(comps) => PathForm::DirStack(fold(comps)),
        PathForm::DirStackEscapesEmpty => PathForm::DirStackEscapesEmpty,
        PathForm::Opaque => PathForm::Opaque,
    }
}

/// The trailing path component of `form` — the filename a real shell would
/// actually open, independent of the (possibly entirely unknown) directory
/// prefix leading to it — for [`TargetMatcher::NormalizedBasename`]
/// (issue #427). `None` for a form with no filename component at all:
/// [`PathForm::NamedUserHome`] (a bare `~username`, no tail),
/// [`PathForm::DirStackEscapesEmpty`] (a bare `~+/..`, no tail), and
/// [`PathForm::Opaque`] (only the empty token now that
/// [`PathForm::NamedUserHomeSub`] carries what `~username/subdir` used to
/// collapse into here — see that variant's own docs).
///
/// Every other variant carries a `Vec<String>` tail — `Rel`'s regardless of
/// its `ascent` count, since an unresolved-ascent token still ends in a
/// definite filename no matter how many directories up it lands, and
/// `NamedUserHomeSub`'s for the same reason: an unreachable/nonexistent
/// account doesn't change what the trailing component is spelled.
fn path_form_last_component(form: &PathForm) -> Option<&str> {
    match form {
        PathForm::Abs(comps)
        | PathForm::Home(comps)
        | PathForm::EscapesHome(comps)
        | PathForm::NamedUserHomeSub(comps)
        | PathForm::NamedUserHomeEscapes(comps)
        | PathForm::DirStack(comps)
        | PathForm::Rel { comps, .. } => comps.last().map(String::as_str),
        PathForm::NamedUserHome | PathForm::DirStackEscapesEmpty | PathForm::Opaque => None,
    }
}

/// Renders a [`PathForm`] back into a token string usable as a folded `cd`
/// working-directory anchor (issue #103, `crate::gate::CwdContext::Known`).
///
/// Unlike [`canonical_render`] — which deliberately stays `None` for an
/// unresolved `Rel` ascent/tail, since that function gates a *provable*
/// target match — this covers `Abs`/`Home`/`Rel` in full, including a
/// relative anchor with no leading `..` at all (`"build"`) or with some
/// (`"../x"`). A `cd` target that resolves to one of these three shapes is
/// lexically CERTAIN within the one command line being analyzed: the
/// relative path text itself is fully known, even though the ultimate
/// directory it composes against at runtime is not (that residual
/// uncertainty is what makes an anchor built from `Rel` still just an
/// ordinary relative token to any LATER composition against it, not a
/// resolved absolute path — see `crate::gate`'s module docs).
///
/// `None` for every other [`PathForm`] (`EscapesHome`/`NamedUserHome`/
/// `NamedUserHomeSub`/`NamedUserHomeEscapes`/`DirStack`/
/// `DirStackEscapesEmpty`/`Opaque`) — a `cd` to one of those shapes
/// poisons `crate::gate`'s folded cwd context instead of producing an
/// anchor; callers never render one.
#[must_use]
pub(crate) fn render_cwd_anchor(form: &PathForm) -> Option<String> {
    match form {
        PathForm::Abs(comps) if comps.is_empty() => Some("/".to_string()),
        PathForm::Abs(comps) => Some(format!("/{}", comps.join("/"))),
        PathForm::Home(comps) if comps.is_empty() => Some("~".to_string()),
        PathForm::Home(comps) => Some(format!("~/{}", comps.join("/"))),
        PathForm::Rel { ascent, comps } => {
            let mut parts: Vec<&str> = Vec::with_capacity(*ascent as usize + comps.len());
            parts.extend(std::iter::repeat_n("..", *ascent as usize));
            parts.extend(comps.iter().map(String::as_str));
            Some(if parts.is_empty() {
                ".".to_string()
            } else {
                parts.join("/")
            })
        }
        PathForm::EscapesHome(_)
        | PathForm::NamedUserHome
        | PathForm::NamedUserHomeSub(_)
        | PathForm::NamedUserHomeEscapes(_)
        | PathForm::DirStack(_)
        | PathForm::DirStackEscapesEmpty
        | PathForm::Opaque => None,
    }
}

/// Symlink resolution as a port this module owns (`coding-guidelines/
/// principles.md`: ports are defined next to the code that consumes them):
/// what the filesystem says about an absolute path, or why it cannot say
/// ([`ProbeError`]). The composition root (`src/lib.rs`) wires the
/// filesystem adapter in through [`Rules::with_path_canonicalizer`], the way
/// `gate` receives its parse function; this module never touches the
/// filesystem itself.
pub(crate) type CanonicalizeFn = fn(&str) -> Result<ResolvedPath, ProbeError>;

/// Why a [`CanonicalizeFn`] produced no [`ResolvedPath`]. The variants exist
/// because the callers treat them differently: a path that is not there
/// (yet) leaves the lexical verdict standing, while the rest mean the
/// filesystem form of the path could not be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeError {
    /// ENOENT or ENOTDIR (also a dangling link): nothing to resolve.
    NotFound,
    /// ELOOP: a symlink cycle.
    Loop,
    /// EACCES or EPERM.
    Denied,
    /// Any other I/O error, or a resolved name that is not valid UTF-8.
    Other,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "it does not exist",
            Self::Loop => "it is part of a symlink loop",
            Self::Denied => "permission was denied",
            Self::Other => "the filesystem reported an error",
        })
    }
}

/// A path as the filesystem spells it after symlink resolution, plus the
/// two facts `resolve_symlinks` needs beyond the spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPath {
    /// The canonical spelling, matched against `except_targets`.
    pub(crate) path: String,
    pub(crate) is_dir: bool,
    /// Hard-link count. A non-directory with more than one name can be
    /// reached through a name outside the excepted prefix.
    pub(crate) link_count: u64,
}

/// The injected [`CanonicalizeFn`]. Compares equal to every other value: it
/// is a capability, not rule data, so it never takes part in rule-set
/// equality.
#[derive(Clone, Copy)]
pub(crate) struct PathCanonicalizer(CanonicalizeFn);

impl PathCanonicalizer {
    pub(crate) fn new(canonicalize: CanonicalizeFn) -> Self {
        Self(canonicalize)
    }

    /// The default for a [`Rules`] nobody wired a canonicalizer into:
    /// resolves nothing (every path is [`ProbeError::NotFound`]), so every
    /// `resolve_symlinks` exception stays unapplied (fail-closed) and the
    /// filesystem twin probe never adds a spelling.
    fn unavailable() -> Self {
        Self(|_| Err(ProbeError::NotFound))
    }

    fn canonicalize(self, path: &str) -> Result<ResolvedPath, ProbeError> {
        (self.0)(path)
    }
}

impl std::fmt::Debug for PathCanonicalizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PathCanonicalizer")
    }
}

impl PartialEq for PathCanonicalizer {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for PathCanonicalizer {}

/// What a `resolve_symlinks` rule knows about the cwd and the command line
/// when it resolves an except-target candidate (issues #583, #612).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SymlinkScope<'a> {
    /// The absolute directory a relative candidate is resolved against.
    /// `None` (or a non-absolute value): a relative candidate fails closed.
    base: Option<&'a str>,
    /// Nothing can be trusted to resolve: every candidate fails closed.
    refuse_all: bool,
}

impl<'a> SymlinkScope<'a> {
    pub(crate) fn new(base: Option<&'a str>) -> Self {
        Self {
            base,
            refuse_all: false,
        }
    }

    /// The same scope, except that no `resolve_symlinks` exception applies:
    /// for a command whose real cwd differs from the lexical one the scope
    /// was built from.
    #[must_use]
    pub(crate) fn refusing_all(mut self) -> Self {
        self.refuse_all = true;
        self
    }

    fn base_dir(&self) -> Option<&'a std::path::Path> {
        self.base
            .map(std::path::Path::new)
            .filter(|base| base.is_absolute())
    }
}

/// Whether a candidate token is plausibly a filesystem path rather than a
/// glob, a `key=@file` word or other text the reason hint would mislead on.
fn looks_like_path(token: &str) -> bool {
    !token.is_empty()
        && !token
            .chars()
            .any(|c| c.is_whitespace() || "=@*?[]{}$`\"'".contains(c))
}

/// How one `resolve_symlinks` candidate fared.
enum CandidateResolution {
    /// Resolved to this canonical spelling, ready for `except_targets`.
    Canonical(String),
    /// Deliberately not resolved: no usable cwd, a scope that refuses
    /// everything, a directory, or a hard-linked file.
    Refused,
    /// The filesystem could not resolve this absolute path.
    Unresolved(String),
}

/// Resolves an except-target candidate for a rule with `resolve_symlinks`
/// (issue #583). Fails closed on every doubt: an empty token, a relative
/// token with no absolute `scope.base`, a refusing scope, a path that does
/// not exist or cannot be read, a directory, or a file with more than one
/// hard link.
///
/// A directory is refused rather than walked: the entries inside it are never
/// listed or inspected, so a symlink among them could name anything and the
/// directory's own spelling proves nothing about what the command reaches.
fn resolve_candidate(
    token: &str,
    scope: SymlinkScope<'_>,
    canonicalizer: PathCanonicalizer,
) -> CandidateResolution {
    if scope.refuse_all || token.is_empty() {
        return CandidateResolution::Refused;
    }
    let path = std::path::Path::new(token);
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let Some(base) = scope.base_dir() else {
            return CandidateResolution::Refused;
        };
        base.join(path)
    };
    let Some(full) = full.to_str() else {
        return CandidateResolution::Refused;
    };
    match canonicalizer.canonicalize(full) {
        Err(_) => CandidateResolution::Unresolved(full.to_string()),
        Ok(resolved) if resolved.is_dir || resolved.link_count > 1 => CandidateResolution::Refused,
        Ok(resolved) => CandidateResolution::Canonical(resolved.path),
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
    resolve_symlinks: bool,
    value_flags: Vec<ValueFlag>,
    attached_value_flags: Vec<char>,
    /// Issue #581: when non-empty, the except_targets candidate set is
    /// restricted to the values of these flags (see [`target_flag_values`]).
    /// Issue #622: the `targets` candidate set is restricted the same way
    /// (see [`CommandRule::target_match_candidates`]).
    target_flags: Vec<ValueFlag>,
    deny_message: Option<DenyMessage>,
    /// Whether `required_flags` long options also match their git-style
    /// prefix abbreviations (issue #582). True only for deny/ask rules whose
    /// command is exactly `git`; allowlist entries stay exact so an
    /// abbreviation can never widen an Ask into an Allow.
    long_abbrev: bool,
}

impl CommandRule {
    /// Disables long-option abbreviation matching (see `long_abbrev`); used
    /// for every allowlist entry.
    fn exact_flags_only(mut self) -> Self {
        self.long_abbrev = false;
        self
    }

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

    /// Actionable guidance for the agent (issue #99), distinct from
    /// [`Self::reason`] — `None` unless this rule declared `deny_message`.
    /// Never set for an allowlist entry ([`convert_command_rule`] rejects
    /// `deny_message` on any rule an allow-side caller converts; see
    /// [`UserConfig::parse`]/[`Allowlist::parse`]).
    #[must_use]
    pub(crate) fn deny_message(&self) -> Option<&DenyMessage> {
        self.deny_message.as_ref()
    }

    /// Issue #208: true when `except_targets` contains both an opt-in
    /// [`TargetMatcher::UrlHost`] entry and a string-based
    /// [`TargetMatcher::Exact`]/[`TargetMatcher::Prefix`] entry. Since
    /// `except_targets` alternatives are OR'd ([`Self::matches`]), the
    /// retained string entry still matches whatever the `url_host` entry
    /// was added to reject — a userinfo-spoofed candidate
    /// (`http://localhost:pw@evil.example.com`), for one — so the rule
    /// gains no additional protection from adding `url_host` *alongside*
    /// the old entry rather than in its place. Not itself a config-load
    /// error: array-level "these two entries target the same host" isn't
    /// mechanically decidable without heuristics that could false-positive
    /// on a legitimate config declaring two genuinely different hosts one
    /// as `url_host` and the other as `exact`/`prefix` — flagging any
    /// co-occurrence in one rule's `except_targets`, without trying to
    /// prove same-host intent, is what `shguard --check-config`
    /// (`src/bin/shguard.rs`) surfaces this for instead.
    #[must_use]
    pub(crate) fn mixes_url_host_with_string_except_target(&self) -> bool {
        let has_url_host = self
            .except_targets
            .iter()
            .any(|t| matches!(t.except_target_shape(), ExceptTargetShape::UrlHost));
        let has_string_entry = self
            .except_targets
            .iter()
            .any(|t| matches!(t.except_target_shape(), ExceptTargetShape::StringLiteral));
        has_url_host && has_string_entry
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
    /// `rest_words` has already had `git -C <path>`/`-c <name>=<value>`/
    /// `--git-dir <path>`/etc. stripped by [`effective_tail`] before this
    /// runs (issue's own former "Known gap" here: those global options'
    /// separated values are non-dash tokens that would otherwise occupy
    /// the subcommand's positional slot).
    #[must_use]
    fn constraints_match(&self, rest_words: &[NormalizedWord]) -> bool {
        let rest = resolved_strings(rest_words);
        let long_abbrev = self.long_abbrev;
        if !self
            .required_flags
            .iter()
            .all(|flag| flag.satisfied(&rest, long_abbrev))
        {
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
    /// instead — that function now shares this tar rewrite step via
    /// [`effective_tail`] (issue #86), so the two helpers can't diverge on
    /// this point.
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
    /// through [`tar_effective_tail`] first: [`tar_dashless_rewrite`]
    /// (issue #67) — tar's own calling convention allows a fully
    /// dash-less leading option cluster (`tar xfC a.tar /`), which the
    /// generic flag matching below can't see at all (`short_cluster_chars`
    /// returns an empty set for a dash-less token) — then
    /// [`tar_long_option_abbrev_rewrite`] (issue #128) — GNU tar accepts
    /// an unambiguous abbreviation of a long option (`--dir=` for
    /// `--directory=`), which the generic exact-token matching below
    /// can't see either. Both rewrites are a no-op `Cow::Borrowed` for
    /// every other command, and for any `tar` invocation that isn't the
    /// specific shape each one targets — see their own docs for exactly
    /// when each fires.
    #[must_use]
    fn matching_rest<'a>(&self, argv: &'a [NormalizedWord]) -> Option<Cow<'a, [NormalizedWord]>> {
        let mut rest = argv;
        loop {
            let (first, tail) = rest.split_first()?;
            let Resolution::Resolved(name) = first.resolution() else {
                return None;
            };
            let base = basename(name);
            // Issue #536: folded once and reused for the blocklist match
            // itself, not just wrapper recognition — a re-cased binary
            // name (`RM`, `/bin/Rm`) resolves to the same inode as its
            // lowercase spelling on a case-insensitive filesystem (macOS
            // APFS default), so blocklist matching must not depend on
            // case any more than wrapper recognition already doesn't.
            let folded_base = fold_command_name(base);
            let canonical = canonical_command_name(base);
            if self.command.matches(&folded_base) || self.command.matches(&canonical) {
                let effective = effective_tail(&canonical, tail);
                if self.constraints_match(&effective) {
                    return Some(effective);
                }
            }
            rest = wrapper_hop(base, &canonical, tail, &[])?.next();
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
    /// can't be statically known, it's never assumed to be excepted.
    /// Suppression also never triggers when a candidate's raw text
    /// contains a literal `..` path segment (issue #136): `except_targets`
    /// is deliberately never normalized (`exact`/`prefix` only, matched
    /// against the raw resolved token — see this module's own docs on
    /// why), but `targets` itself IS normalized, so a candidate like
    /// `/dev/shm/../sda` can textually start with an excepted `prefix =
    /// "/dev/shm/"` while lexically resolving to `/dev/sda` — a target the
    /// except was never meant to cover. Scoped to `/`- or `~`-rooted
    /// candidates only, so a `url_host` except (which never deals in `..`
    /// path segments at all) is untouched.
    /// A rule's `value_flags` (issue #48) further narrows the `targets`-
    /// empty candidate set: a declared flag's own value (separated or
    /// `--flag=value` attached) is consumed and never becomes a candidate
    /// at all, so a value-taking flag's output path/format string/pattern
    /// can't wrongly stand in the way of "all candidates excepted" for the
    /// command's actual target. An undeclared flag's value is unaffected —
    /// it keeps counting as a candidate, today's fail-closed default. A
    /// rule's `attached_value_flags` (issue #47) does the opposite: it
    /// *widens* the same candidate set by adding a declared short flag's
    /// glued value (`-xVALUE`, otherwise invisible to
    /// [`target_candidate`]) as a new candidate — this can newly suppress
    /// a match that would otherwise fire, the same opt-in-loosening
    /// posture `except_targets` itself already has, not an accident.
    /// A rule's `target_flags` (issue #581) replaces the candidate set
    /// wholesale: only the values of the named flags are candidates
    /// (positionals and every other flag's value are not), and a named
    /// flag with no value keeps the except from applying (see
    /// [`target_flag_values`]). With a non-empty `targets` (issue #622) it
    /// scopes the `targets` match itself too
    /// ([`Self::target_match_candidates`]), and the except candidates are
    /// the flag values that matched `targets`.
    #[must_use]
    fn matches(&self, argv: &[NormalizedWord]) -> bool {
        self.matches_in(
            argv,
            SymlinkScope::default(),
            PathCanonicalizer::unavailable(),
        )
    }

    /// [`Self::matches`] with the [`SymlinkScope`] a `resolve_symlinks` rule
    /// resolves its candidates in (issues #583, #612).
    ///
    /// With `resolve_symlinks = true` every candidate is canonicalized
    /// (through the injected [`PathCanonicalizer`]) before `except_targets`
    /// matching, and the canonical path must match an alternative for the
    /// exception to apply. Anything short of a clean resolution leaves the
    /// exception unapplied, so the rule fires: a missing file, a permission
    /// error, a relative candidate with no usable base, a refusing scope, a
    /// directory (never walked), a hard-linked file. A
    /// file that does not exist yet fails closed the same way. Canonical
    /// paths are spelled as the OS resolves them (on macOS `/tmp` is
    /// `/private/tmp`), so `except_targets` entries must use that spelling.
    #[must_use]
    fn matches_in(
        &self,
        argv: &[NormalizedWord],
        scope: SymlinkScope<'_>,
        canonicalizer: PathCanonicalizer,
    ) -> bool {
        let Some(rest_words) = self.matching_rest(argv) else {
            return false;
        };
        let rest = resolved_strings(&rest_words);

        let matched = if self.targets.is_empty() {
            true
        } else {
            self.target_match_candidates(&rest_words)
                .iter()
                .any(|token| self.matches_targets(token))
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

        let Some(candidates) = self.except_candidates(&rest) else {
            return true;
        };
        let all_excepted = !candidates.is_empty()
            && !candidates
                .iter()
                .any(|c| candidate_has_unresolved_ascent(c))
            && candidates.iter().all(|token| {
                if self.resolve_symlinks {
                    match resolve_candidate(token, scope, canonicalizer) {
                        CandidateResolution::Canonical(canonical) => {
                            self.except_targets.iter().any(|e| e.matches(&canonical))
                        }
                        CandidateResolution::Refused | CandidateResolution::Unresolved(_) => false,
                    }
                } else {
                    self.except_targets.iter().any(|e| e.matches(token))
                }
            });
        !all_excepted
    }

    /// The tail tokens `except_targets` is checked against, or `None` when
    /// the candidate set cannot be enumerated and the rule must keep firing.
    fn except_candidates<'a>(&self, rest: &[&'a str]) -> Option<Vec<&'a str>> {
        if !self.target_flags.is_empty() {
            // Issue #581: only the declared flags' values are candidates.
            // `None` (a listed flag with no value) fails closed: the rule
            // keeps firing rather than excepting on a partial candidate set.
            let values = target_flag_values(rest, &self.target_flags, &self.value_flags)?;
            // Unlike the other walks ([`candidate_has_unresolved_ascent`],
            // which looks only at `/`- or `~`-rooted candidates), a `..`
            // segment disqualifies a candidate whether or not it is rooted:
            // a flag value like `scratch/../../etc/passwd` can textually
            // start with an excepted prefix yet resolve outside it. Not
            // rooted-only: a `url_host` except candidate whose URL path
            // contains `/../` therefore also asks here. That false Ask is
            // deliberate and fail-closed.
            if values.iter().any(|v| v.split('/').any(|seg| seg == "..")) {
                return None;
            }
            Some(if self.targets.is_empty() {
                values
            } else {
                values
                    .into_iter()
                    .filter(|token| self.matches_targets(token))
                    .collect()
            })
        } else if self.targets.is_empty() {
            Some(value_flag_free_candidates(
                rest,
                &self.value_flags,
                &self.attached_value_flags,
            ))
        } else {
            Some(
                rest.iter()
                    .filter(|token| self.matches_targets(token))
                    .copied()
                    .collect(),
            )
        }
    }

    /// The path of the first candidate of a `resolve_symlinks` rule that
    /// textually lies under an `except_targets` entry but could not be
    /// resolved (missing, dangling, unreadable): the one case where the
    /// fail-closed outcome has a cause the user can fix. `None` for every
    /// other reason an exception did not apply.
    fn unresolved_excepted_path(
        &self,
        argv: &[NormalizedWord],
        scope: SymlinkScope<'_>,
        canonicalizer: PathCanonicalizer,
    ) -> Option<String> {
        if !self.resolve_symlinks || self.except_targets.is_empty() {
            return None;
        }
        let rest_words = self.matching_rest(argv)?;
        if rest_words
            .iter()
            .any(|w| matches!(w.resolution(), Resolution::Unresolvable(_)))
        {
            return None;
        }
        let rest = resolved_strings(&rest_words);
        self.except_candidates(&rest)?
            .into_iter()
            .filter(|token| looks_like_path(token))
            .find_map(
                |token| match resolve_candidate(token, scope, canonicalizer) {
                    CandidateResolution::Unresolved(full)
                        if self.except_targets.iter().any(|e| e.matches(&full)) =>
                    {
                        Some(full)
                    }
                    _ => None,
                },
            )
    }

    #[must_use]
    fn matches_targets(&self, token: &str) -> bool {
        self.targets.iter().any(|t| t.matches(token))
    }

    /// The resolved tail tokens this rule's `targets` are tested against
    /// (issue #622): every resolved tail token without `target_flags`; with
    /// it, only the listed flags' readable values
    /// ([`target_flag_match_values`]), so a subcommand or another flag's
    /// value can never be the target. That matters most once a relative
    /// word is composed against a cwd anchor (`gh issue` under a payload
    /// cwd of `/Users/me` becomes `/Users/me/issue`). A value this walk
    /// cannot read (unresolvable, or missing) is left to the
    /// unresolved-argument floor ([`Self::matches_except_target`]), which
    /// asks rather than matching an unrelated word.
    fn target_match_candidates<'a>(&self, rest_words: &'a [NormalizedWord]) -> Vec<&'a str> {
        if self.target_flags.is_empty() {
            resolved_strings(rest_words)
        } else {
            target_flag_match_values(rest_words, &self.target_flags, &self.value_flags)
        }
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
    /// in the tail is not proof the rule's own danger is absent, but at
    /// least one rule shape — sed, whose first non-option operand is its
    /// edit script, not a target — has resolved content that's part of
    /// neither the flag nor the target and must not by itself defeat this
    /// relaxation. For `sed` specifically this is now handled by the fourth
    /// case below rather than left as a residual gap.
    ///
    /// Blast radius beyond the motivating example (mirrors
    /// [`Self::matches_except_flags`]'s own documented trade-off for
    /// `git-no-verify-any-subcommand` — a `required_flags`-only rule with
    /// no `required_tokens`; no longer an embedded rule since issue #146
    /// split it into per-subcommand rules, but still pinned as a synthetic
    /// rule in
    /// `matches_except_flags_no_required_tokens_rule_fires_regardless_of_subcommand`
    /// below — which would floor EVERY `git` invocation containing an
    /// unresolvable word — no per-command semantics, module
    /// docs): any `sed` invocation whose entire tail is a single
    /// unresolvable word floors to `Ask` via `self-protect-config-sed-tilde`,
    /// regardless of any actual connection to shguard's config path — e.g.
    /// `sed $(cat unrelated-script)`. Narrower than that `git` case (only
    /// an all-opaque tail counts, not "any unresolvable word anywhere") and
    /// Ask-only, never Block, same as every relaxation in this function —
    /// an accepted, intentional trade-off, not an oversight.
    ///
    /// # A fourth case, `sed`-only: exactly one resolved operand survives (issue #117)
    ///
    /// GNU `sed` permutes options after operands (POSIX getopt-style), so a
    /// single resolved token surviving in an otherwise-opaque tail does not
    /// rule out a hidden flag+target elsewhere: `sed 's/a/b/'
    /// $(echo -i ~/.config/shguard/config.toml)` performs the in-place edit
    /// at runtime, but the all-opaque check above stays silent for it (the
    /// tail has one resolved token, `'s/a/b/'`). `sed`'s own calling
    /// convention explains that survivor away: absent `-e`/`-f`, it always
    /// takes exactly one script operand, so this branch tolerates at most
    /// one non-flag-shaped resolved token in the tail — `sed`-scoped only,
    /// via [`sed_tail_has_at_most_one_resolved_operand`] and keyed off
    /// [`CommandMatch::matches`] on this rule's own `command` (so a future
    /// `command_prefix` rule that happens to prefix-match `"sed"` would
    /// silently inherit this too — no such rule exists today). Same
    /// accepted trade-off as the all-opaque case, but with a more common
    /// blast radius: `sed 's/x/y/' "$file"` — an everyday pattern, not just
    /// an edge case like `$(cat unrelated-script)` — now also floors to
    /// `Ask` regardless of `$file`'s actual value, once `$file` itself is
    /// unresolvable. Since issue #579 this probe itself holds only for an
    /// UNQUOTED `$file`: a quoted one is a single argv word that cannot be
    /// both the in-place flag and the target (see
    /// [`Self::one_word_cannot_fill_flag_and_target`]). End to end, `sed`
    /// with a quoted unresolved word still reaches `Ask`, but through the
    /// gate's separate sed-script floor (issue #584), not through this
    /// probe. Likewise the strict branch no longer fires when every
    /// unresolved word is provably not a target
    /// ([`Self::unresolved_word_may_be_target`]).
    ///
    /// Residual gap (not fixed here): a SECOND resolved, non-flag-shaped
    /// operand still defeats this branch, e.g. `sed -f a.sed file $(evil)`
    /// or `sed -e a -e b $(evil)`. This is forced, not an oversight — the
    /// pinned must-not-fire case just below
    /// (`except_target_does_not_fire_when_a_resolved_token_survives_in_the_tail`,
    /// `sed 's/x/y/' /some/normal/file $(compute-suffix)`) is token-shape-
    /// indistinguishable from those two: closing it would need to model
    /// which flags consume how many script/file operands (full `-e`/`-f`
    /// positional semantics), which issue #117 explicitly deferred rather
    /// than fold into this narrower fix.
    #[must_use]
    pub(crate) fn matches_except_target(&self, argv: &[NormalizedWord]) -> bool {
        self.matches_except_target_impl(argv, true, true)
    }

    /// [`Self::matches_except_target`] for an argv composed against a cwd
    /// anchor (`cd`, `env -C`): the anchor can be `~` or a directory whose
    /// children include the home directory, so a bare-`~` target must not
    /// be pruned by a literal tail (`prune_home = false`, issue #579).
    #[must_use]
    pub(crate) fn matches_except_target_composed(&self, argv: &[NormalizedWord]) -> bool {
        self.matches_except_target_impl(argv, true, false)
    }

    /// [`Self::matches_except_target`] without role counting or home
    /// pruning: for a cwd that is entirely unknown, any bare relative
    /// operand might be a target once the unknown directory is accounted
    /// for, so a lone unresolved word must keep the floor (issue #579).
    #[must_use]
    pub(crate) fn matches_except_target_unknown_cwd(&self, argv: &[NormalizedWord]) -> bool {
        self.matches_except_target_impl(argv, false, false)
    }

    fn matches_except_target_impl(
        &self,
        argv: &[NormalizedWord],
        role_counting: bool,
        prune_home: bool,
    ) -> bool {
        if self.targets.is_empty() {
            return false;
        }
        let Some(rest_words) = self.matching_rest_by_name(argv) else {
            return false;
        };
        let rest_words = if rest_words.iter().any(NormalizedWord::is_dev_fd_path)
            && !self.targets.iter().any(TargetMatcher::admits_dev_fd)
        {
            Cow::Owned(
                rest_words
                    .iter()
                    .filter(|word| !word.is_dev_fd_path())
                    .cloned()
                    .collect(),
            )
        } else {
            rest_words
        };
        let has_unresolvable = rest_words
            .iter()
            .any(|w| matches!(w.resolution(), Resolution::Unresolvable(_)));
        if !has_unresolvable || !self.relaxed_required_tokens_match(&rest_words) {
            return false;
        }
        if self.constraints_match(&rest_words) {
            return rest_words
                .iter()
                .any(|w| self.unresolved_word_may_be_target(w, prune_home));
        }
        // Not `target_match_candidates`: a listed flag hidden in an
        // unresolvable word (`gh $X /Users/me/.ssh/id`) leaves its resolved
        // value outside the scoped walk. With `target_flags`, only a
        // resolved word right after an unresolved one can be that value, so
        // a subcommand never stands in for the target.
        let hidden_flag_candidates = if self.target_flags.is_empty() {
            resolved_strings(&rest_words)
        } else {
            resolved_words_after_unresolved(&rest_words)
        };
        if hidden_flag_candidates.iter().any(|token| {
            self.matches_targets(token)
                || (!self.target_flags.is_empty()
                    && self.targets.iter().any(|t| t.tilde_may_reach_target(token)))
        }) {
            return true;
        }
        // Only the plain probe: an attached value hides regardless of the
        // cwd, so the composed and unknown-cwd probes leaving it to the plain
        // one keeps a composed reason about the token composition changed.
        if role_counting
            && prune_home
            && self.unresolved_word_may_hide_attached_target_flag(&rest_words)
        {
            return true;
        }
        if role_counting {
            if self.resolved_token_plausible_target(&rest_words) {
                return true;
            }
            if self.one_word_cannot_fill_flag_and_target(&rest_words) {
                return false;
            }
        }
        if rest_words
            .iter()
            .all(|w| matches!(w.resolution(), Resolution::Unresolvable(_)))
        {
            return true;
        }
        self.command.matches("sed") && sed_tail_has_at_most_one_resolved_operand(&rest_words)
    }

    /// [`Rules::target_flag_glued_value_offset`] for this rule alone.
    fn target_flag_glued_value_offset(&self, token: &str) -> Option<usize> {
        if self.target_flags.is_empty() {
            return None;
        }
        if self
            .target_flags
            .iter()
            .any(|f| f.attached_value_token(token))
        {
            return token.find('=').map(|index| index + 1);
        }
        let shorts: Vec<char> = self
            .target_flags
            .iter()
            .filter_map(|f| match f {
                ValueFlag::Short(c) => Some(*c),
                ValueFlag::Long(_) => None,
            })
            .collect();
        let value = attached_value_candidate(token, &shorts, &self.value_flags)?;
        let start = token.len() - value.len();
        Some(start + usize::from(value.starts_with('=')))
    }

    /// Whether an unresolved word could be a listed `target_flags` flag with
    /// its value attached (`--body-file=$F`, `-F$F`, or a bare `"$X"` that
    /// expands to `--body-file=/etc/passwd`), so one word fills both the flag
    /// and the target role and role counting cannot rule it out (issue #625).
    /// A splittable word always counts (its expansion can add any number of
    /// words, one of them the flag). A single word counts unless the rule's
    /// `value_flags` consume it as a value or its literal head rules out a
    /// listed flag. Without `target_flags` this is always `false`.
    fn unresolved_word_may_hide_attached_target_flag(&self, rest_words: &[NormalizedWord]) -> bool {
        if self.target_flags.is_empty() {
            return false;
        }
        let consumed = value_flag_consumed(rest_words, &self.value_flags);
        rest_words.iter().zip(consumed).any(|(word, consumed)| {
            if !matches!(word.resolution(), Resolution::Unresolvable(_)) {
                return false;
            }
            if !word.is_single_word() {
                return true;
            }
            if consumed {
                return false;
            }
            word.literal_head()
                .is_none_or(|head| self.head_may_begin_target_flag(head))
        })
    }

    /// Whether a single word whose literal text before its first unresolved
    /// piece is `head` could be a listed flag with its value attached. A
    /// long flag needs `--name=` compatibility (a head that is merely a
    /// prefix of the spelling counts). Any single-dash head counts, since
    /// the letter may sit in the unresolved part, unless a `value_flags`
    /// letter comes first in the head and owns the rest of the cluster.
    fn head_may_begin_target_flag(&self, head: &str) -> bool {
        if head.starts_with("--") || head == "-" {
            return head == "-"
                || self.target_flags.iter().any(|flag| match flag {
                    ValueFlag::Long(name) => {
                        let spelling = format!("--{name}=");
                        spelling.starts_with(head) || head.starts_with(&spelling)
                    }
                    ValueFlag::Short(_) => false,
                });
        }
        let Some(cluster) = head.strip_prefix('-') else {
            return false;
        };
        for letter in cluster.chars() {
            if self.target_flags.contains(&ValueFlag::Short(letter)) {
                return true;
            }
            if self.value_flags.contains(&ValueFlag::Short(letter)) {
                return false;
            }
        }
        true
    }

    /// Whether `word` is an unresolvable word that might still be this
    /// rule's target. `false` only when it is one guaranteed word
    /// ([`NormalizedWord::is_single_word`]: an unquoted expansion can split,
    /// and an earlier field is then unconstrained) whose literal tail proves
    /// that no target can match, per
    /// [`TargetMatcher::excluded_by_literal_tail`] (issue #579).
    fn unresolved_word_may_be_target(&self, word: &NormalizedWord, prune_home: bool) -> bool {
        if !matches!(word.resolution(), Resolution::Unresolvable(_)) {
            return false;
        }
        let Some(last) = word
            .is_single_word()
            .then(|| word.literal_tail())
            .flatten()
            .and_then(literal_tail_component)
        else {
            return true;
        };
        !self
            .targets
            .iter()
            .all(|t| t.excluded_by_literal_tail(last, word.literal_head_tilde() || !prune_home))
    }

    /// Whether a resolved token is tied to one of this rule's targets only
    /// by the Ask-only plausibility floors (ascent-descent, `~user`,
    /// dirstack). Those floors consult only a rule whose flags already
    /// match, which is exactly what is missing when an unresolved word may
    /// hide the flag, so the probe keeps the floor (issue #579). The
    /// unknown-cwd floor is not folded in (it would match every bare
    /// filename); the gate runs [`Self::matches_except_target_unknown_cwd`]
    /// instead when the cwd is `Poisoned`.
    fn resolved_token_plausible_target(&self, rest_words: &[NormalizedWord]) -> bool {
        resolved_strings(rest_words).iter().any(|token| {
            self.targets.iter().any(|t| {
                t.ascent_descent_plausible(token)
                    || t.named_user_home_plausible(token)
                    || t.dirstack_plausible(token)
                    || t.glob_plausible(token)
            })
        })
    }

    /// Role counting (issue #579), for the branches where the flag, the
    /// target, or both are hidden in unresolved words: with the strict and
    /// resolved-target branches already failed, the rule can only match if
    /// one unresolved word supplies the missing flag AND another supplies
    /// the target. So a lone unresolved word cannot satisfy it, provided
    /// that word is one guaranteed argv word, the rule needs no
    /// `required_tokens` (positionals are matched elsewhere), and no target
    /// can double as a flag ([`TargetMatcher::may_double_as_flag`]).
    ///
    /// Callers first check [`Self::resolved_token_plausible_target`].
    fn one_word_cannot_fill_flag_and_target(&self, rest_words: &[NormalizedWord]) -> bool {
        let mut unresolved = rest_words
            .iter()
            .filter(|w| matches!(w.resolution(), Resolution::Unresolvable(_)));
        let single_unresolved = match (unresolved.next(), unresolved.next()) {
            (Some(only), None) => only.is_single_word(),
            _ => false,
        };
        single_unresolved
            && self.required_tokens.is_empty()
            && !self.targets.iter().any(TargetMatcher::may_double_as_flag)
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
    /// Applies [`effective_tail`] to the returned tail — the same helper
    /// [`Self::matching_rest`] uses (issue #86), so the two walkers can't
    /// diverge on this point. Without it, a dash-less leading option
    /// cluster (`tar xfC a.tar /`) is invisible to
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
    /// itself a catalogued exec wrapper (e.g. a rule naming `sudo`
    /// as its `command`, reached through `env sudo ...`) — the deeper hop
    /// underneath might still satisfy the rule. This function stops at the
    /// first name match unconditionally, so for such a rule it would
    /// return the wrapper's own tail rather than continuing to unwrap.
    /// Currently unreachable — no rule in `rules/blocklist.toml` names a
    /// catalogued exec wrapper as its `command` — but a future rule
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
            // Issue #536: fold before the blocklist match, same as the
            // sibling walk above.
            let folded_base = fold_command_name(base);
            let canonical = canonical_command_name(base);
            if self.command.matches(&folded_base) || self.command.matches(&canonical) {
                return Some(effective_tail(&canonical, tail));
            }
            rest = wrapper_hop(base, &canonical, tail, &[])?.next();
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
    /// all, a rule like the now-hypothetical `git-no-verify-any-subcommand`
    /// (`required_flags = ["--no-verify"]`, no `required_tokens`; no longer
    /// an embedded rule since issue #146 split it into per-subcommand rules
    /// — see the synthetic rule pinned in
    /// `matches_except_flags_no_required_tokens_rule_fires_regardless_of_subcommand`
    /// below) would floor EVERY `git` invocation containing an unresolvable
    /// word to `Ask`, regardless of
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
        self.matches_resolved_tail_floor(argv, TargetMatcher::ascent_descent_plausible)
    }

    #[must_use]
    pub(crate) fn matches_glob_floor(&self, argv: &[NormalizedWord]) -> bool {
        self.matches_resolved_tail_floor(argv, TargetMatcher::glob_plausible)
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
        // Issue #625: a rule scoped by `target_flags` also floors any
        // `~`-form flag value against its absolute targets (`--body-file
        // ~/.ssh/id` vs `/Users/`), since the tilde never normalizes into
        // an absolute path here.
        let scoped = !self.target_flags.is_empty();
        self.matches_resolved_tail_floor(argv, |target, token| {
            target.named_user_home_plausible(token)
                || (scoped && target.tilde_may_reach_target(token))
        })
    }

    /// issue #88: true when this rule's command+flags match `argv` (via
    /// [`Self::matching_rest`], the same full constraint check
    /// [`Self::matches`] uses) and some resolved tail token is a
    /// directory-stack tilde shorthand (`~+`/`~-`/`~N`/`~+N`/`~-N`,
    /// [`PathForm::DirStack`]) or a `..` step above one
    /// ([`PathForm::DirStackEscapesEmpty`]) that could plausibly occupy one
    /// of this rule's own `targets`' slots
    /// ([`TargetMatcher::dirstack_plausible`]).
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
        self.matches_resolved_tail_floor(argv, TargetMatcher::dirstack_plausible)
    }

    /// Issue #103: true when this rule's command+flags match `argv` (via
    /// [`Self::matching_rest`], the same full constraint check
    /// [`Self::matches`] uses) and some resolved tail token is
    /// [`TargetMatcher::unknown_cwd_plausible`] against one of this rule's
    /// own targets — `crate::gate`'s poisoned-cwd floor
    /// (`crate::gate::scan_unknown_cwd_floor`), fired only when the folded
    /// cwd context for the command line being analyzed is entirely unknown
    /// (`crate::gate::CwdContext::Poisoned`), never when it's merely
    /// `Initial` (no `cd` seen at all — see that type's own docs on why the
    /// two are not the same). Read-only probe, same shape as
    /// [`Self::matches_ascent_descent_floor`] — never itself a match, only
    /// a `gate.rs` floor's input.
    #[must_use]
    pub(crate) fn matches_unknown_cwd_floor(&self, argv: &[NormalizedWord]) -> bool {
        self.matches_resolved_tail_floor(argv, TargetMatcher::unknown_cwd_plausible)
    }

    /// Shared core of the four unattached-token floor probes above
    /// ([`Self::matches_ascent_descent_floor`] issue #78,
    /// [`Self::matches_named_user_home_floor`] issue #80,
    /// [`Self::matches_dirstack_tilde_floor`] issue #88,
    /// [`Self::matches_unknown_cwd_floor`] issue #103): `false` if
    /// `self.targets` is empty, or `argv` doesn't match this rule's
    /// command+flags at all ([`Self::matching_rest`]); otherwise true when
    /// some resolved tail token is `plausible` against one of this rule's
    /// own `targets`. The sibling attached-token pair
    /// ([`Self::matches_directory_equals_tilde_floor`]/
    /// [`Self::matches_dirstack_equal_subst_floor`]) has its own shared
    /// core, [`Self::matches_attach_after_equal_floor`], because it also
    /// needs a corroborating-target check and an `=`-terminated attach
    /// prefix this unattached case has no equivalent of.
    fn matches_resolved_tail_floor(
        &self,
        argv: &[NormalizedWord],
        plausible: impl Fn(&TargetMatcher, &str) -> bool,
    ) -> bool {
        if self.targets.is_empty() {
            return false;
        }
        let Some(rest_words) = self.matching_rest(argv) else {
            return false;
        };
        self.target_match_candidates(&rest_words)
            .iter()
            .any(|token| self.targets.iter().any(|t| plausible(t, token)))
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
        self.matches_attach_after_equal_floor(
            argv,
            |t| {
                matches!(
                    t,
                    TargetMatcher::NormalizedExact {
                        target: PathForm::Home(comps),
                        ..
                    } if comps.is_empty()
                )
            },
            tilde_reachable_via_magic_equal_subst,
        )
    }

    /// Issue #134: true when this rule's command+flags match `argv` (via
    /// [`Self::matching_rest`], the same full constraint check
    /// [`Self::matches`] uses) and some resolved tail token attaches a
    /// directory-stack tilde shorthand (`~+`/`~-`/`~N`/`~+N`/`~-N`) or a
    /// `..` step above one (`~+/..`) directly after an `=`-terminated
    /// `strip` prefix this same rule declares (e.g. `--directory=~+`).
    ///
    /// Same attach-detection shape as
    /// [`Self::matches_directory_equals_tilde_floor`] (issue #115), and
    /// same target-*value*-free reasoning as
    /// [`Self::matches_dirstack_tilde_floor`] (issue #88) for the
    /// unattached case: `~+`/`~-`/`~N` expand against
    /// `$PWD`/`$OLDPWD`/a pushd-stack entry, an anchor no rule target can
    /// declare, so there is nothing about a specific target's own value to
    /// check. But #115's `has_bare_tilde_target` gate is replaced here with
    /// a broader corroborating-slot requirement rather than dropped
    /// outright: this rule must ALSO declare at least one bare, unattached
    /// `NormalizedExact`/`NormalizedPrefix` target (`strip: None`) — the
    /// same "target's slot could even receive a bare path" proxy
    /// [`TargetMatcher::dirstack_plausible`] already uses to gate the
    /// unattached floor (a raw `Exact`/`Prefix` target doesn't count
    /// there either, for the same reason). This is a slot-eligibility
    /// proxy, not an actual directory-vs-file check — nothing here parses
    /// what kind of path a target denotes — but for every rule currently
    /// eligible in the embedded blocklist (the tar rules' bare `/`/`~`;
    /// `mv`/`install`/`cp-write-device`'s bare `/dev`/`/dev/*`), the
    /// `=`-terminated slot itself expects a directory (`--directory=`,
    /// `--target-directory=`) and the rule also declares at least one bare
    /// directory target (`/`, `~`, or the exact `/dev` entry — the bare
    /// `/dev/` *prefix* additionally matches non-directory device nodes,
    /// which is fine: a directory-shaped dirstack token can still land
    /// under `/dev/` too), which is exactly why the proxy works: a rule
    /// whose ONLY targets are
    /// attach-only file/device sinks (`dd`'s `of=/dev/*`, `of=/etc/passwd`)
    /// never gets a false Ask-floor here — `dd of=~-/..` always resolves to
    /// a directory, and `of=<directory>` fails EISDIR regardless of tilde
    /// expansion, so it stays Allow (pinned by
    /// `gate::tests::dd_dirstack_tilde_escape_to_empty_tail_stays_allow`).
    /// A user-config rule that pairs an unrelated bare *file* target with
    /// an `=`-terminated attach target would still float here, an
    /// FP-noise-only edge (Ask, never a bypass) inherent to the proxy.
    /// Read-only probe, never itself a match, only a `gate.rs`
    /// floor's input (see `crate::gate::scan_dirstack_equal_subst_floor`).
    #[must_use]
    pub(crate) fn matches_dirstack_equal_subst_floor(&self, argv: &[NormalizedWord]) -> bool {
        self.matches_attach_after_equal_floor(
            argv,
            |t| {
                matches!(
                    t,
                    TargetMatcher::NormalizedExact { strip: None, .. }
                        | TargetMatcher::NormalizedPrefix { strip: None, .. }
                )
            },
            dirstack_reachable_via_magic_equal_subst,
        )
    }

    /// Shared core of [`Self::matches_directory_equals_tilde_floor`] (issue
    /// #115) and [`Self::matches_dirstack_equal_subst_floor`] (issue #134,
    /// issue #409): both check whether this rule declares some
    /// corroborating "this could be the floor's shape" target
    /// (`has_corroborating_target` — a bare-`~` target for #115, any
    /// unattached bare target for #134; see each caller's own doc for why
    /// its specific predicate is the right proxy), then whether the rule
    /// ALSO declares at least one `=`-terminated `strip` prefix among its
    /// own `targets`, and finally whether some resolved tail token attaches
    /// a shape `reachable` recognizes (zsh's `magic_equal_subst`-gated
    /// tilde/dirstack expansion, respectively) directly after one of those
    /// prefixes. `false` if `self.targets` is empty, or `argv` doesn't
    /// match this rule's command+flags at all
    /// ([`Self::matching_rest`]).
    fn matches_attach_after_equal_floor(
        &self,
        argv: &[NormalizedWord],
        has_corroborating_target: impl Fn(&TargetMatcher) -> bool,
        reachable: fn(&str) -> bool,
    ) -> bool {
        if self.targets.is_empty() {
            return false;
        }
        if !self.targets.iter().any(has_corroborating_target) {
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
        // Unscoped on purpose: `target_flags` values arrive already split
        // from their `--flag=` prefix, which `attach_prefixes` needs intact.
        resolved_strings(&rest_words).iter().any(|token| {
            attach_prefixes
                .iter()
                .any(|prefix| token.strip_prefix(*prefix).is_some_and(reachable))
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
/// Deliberately does NOT recognize [`PathForm::DirStack`]/
/// [`PathForm::DirStackEscapesEmpty`] (issue #88, e.g. `--directory=~+`):
/// unlike `NamedUserHome`/`EscapesHome`, which expand against the SAME
/// anchor (`$HOME`) this function's caller already requires the rule to
/// have a bare-`~` target for, `~+`/`~-`/`~N` expand to `$PWD`/`$OLDPWD`/a
/// dirstack entry — a fundamentally different, unrelated anchor. Folding
/// it in here would produce a floor whose reported reason ("would hit this
/// rule's bare-`~` target") is not actually true for a `$PWD`/`$OLDPWD`-
/// anchored token. That case is instead
/// [`CommandRule::matches_dirstack_equal_subst_floor`]'s own job (issue
/// #134): a separate floor with no bare-`~`-target gate, since a dirstack
/// token has no single anchor to compare against in the first place.
fn tilde_reachable_via_magic_equal_subst(remainder: &str) -> bool {
    match lexical_normalize(remainder) {
        PathForm::Home(comps) => comps.is_empty(),
        PathForm::EscapesHome(_) | PathForm::NamedUserHome | PathForm::NamedUserHomeEscapes(_) => {
            true
        }
        _ => false,
    }
}

/// Whether `remainder` (a token's content after stripping an `=`-
/// terminated flag prefix, e.g. `--directory=`) is a shape that would hit
/// SOME rule target if zsh's `magic_equal_subst` option expanded it (issue
/// #134): a directory-stack tilde shorthand at its bare anchor
/// ([`PathForm::DirStack`] with an empty tail, `~+`) or one `..` step above
/// it ([`PathForm::DirStackEscapesEmpty`], `~+/..`) — the same two shapes
/// [`TargetMatcher::dirstack_plausible`] floors for the unattached case.
/// Unlike [`tilde_reachable_via_magic_equal_subst`], there is no specific
/// target *value* being compared: `~+`/`~-`/`~N` expand to
/// `$PWD`/`$OLDPWD`/a pushd-stack entry, an anchor no [`PathForm`] a target
/// can declare represents, so this only answers "what would it expand to
/// if it did," same as that sibling function's own doc says.
fn dirstack_reachable_via_magic_equal_subst(remainder: &str) -> bool {
    match lexical_normalize(remainder) {
        PathForm::DirStack(tail) => tail.is_empty(),
        PathForm::DirStackEscapesEmpty => true,
        _ => false,
    }
}

/// A rule matching the shape of a whole pipeline: an earlier stage's
/// command name in `sources`, and the final stage's command name in
/// `sinks` (both stored case-folded, compared against the folded runtime
/// name) — the literal ported `curl|wget → sh` installer-pipe pattern
/// (plan.md §1.1 stage 3). The general decode-fed-pipe gate is a later
/// issue (plan.md §4), out of scope here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PipelineRule {
    id: RuleId,
    reason: Reason,
    decision: Decision,
    sources: Vec<String>,
    sinks: Vec<String>,
    /// Constrains the resolved sink's own flags, so a rule can separate
    /// `xargs rm -f` from `xargs rm` without also naming every benign
    /// sink invocation (issue #268). Empty = unconstrained.
    sink_required_flags: Vec<FlagMatcher>,
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
        let Some((sink_name, sink_tail)) = effective_command(sink_stage) else {
            return false;
        };
        // Not the local interpreter: `ssh host sh` and `docker exec -i c sh`
        // run it elsewhere, which the stdin-sink floor already asks about.
        if wrapper_hops(sink_stage)
            .iter()
            .any(|(name, _)| REMOTE_EXEC_WRAPPERS.contains(&name.as_str()))
        {
            return false;
        }
        // Issue #497: a versioned/distro-suffixed sink binary (`dash5`)
        // resolves to the same interpreter `strip_version_suffix` already
        // normalizes it to elsewhere (`is_pipeline_interpreter`,
        // `is_shell_interpreter`) — the sink match must recognize it too.
        // Only the runtime name is normalized; a `sinks` entry is compared
        // literally, so an entry that itself ends in a digit (`python3`)
        // is reachable only through the exact-match arm.
        if !self
            .sinks
            .iter()
            .any(|sink| sink == &sink_name || sink == strip_version_suffix(&sink_name))
        {
            return false;
        }
        // Membership semantics (no `--` end-of-flags awareness, an
        // unresolvable word skipped rather than stopping the scan) are
        // inherited from [`CommandRule::constraints_match`] deliberately:
        // the sink is the same argv shape those rules match on.
        let sink_args = resolved_strings(sink_tail);
        let long_abbrev = strip_version_suffix(&sink_name) == "git";
        if !self
            .sink_required_flags
            .iter()
            .all(|flag| flag.satisfied(&sink_args, long_abbrev))
        {
            return false;
        }
        source_stages.iter().any(|stage| {
            effective_command(stage)
                .is_some_and(|(name, _)| self.sources.iter().any(|src| *src == name))
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

/// [`CommandRule::matches_except_target`]'s `sed`-only fourth relaxation
/// (issue #117): whether `rest_words` has at most one resolved, non-flag-
/// shaped token — GNU `sed` always takes exactly one script operand absent
/// `-e`/`-f`, so tolerating one such survivor (presumed to be that script)
/// still lets a hidden flag+target hide among the rest. A resolved token
/// starting with `-` is excluded from the count: it's a flag candidate, not
/// a script/file operand, and already governed by
/// [`CommandRule::constraints_match`]'s own handling.
fn sed_tail_has_at_most_one_resolved_operand(rest_words: &[NormalizedWord]) -> bool {
    resolved_strings(rest_words)
        .iter()
        .filter(|s| !s.starts_with('-'))
        .count()
        <= 1
}

/// The final path component of `tail` (the literal text ending an
/// unresolvable word, [`NormalizedWord::literal_tail`]) when that component
/// is fully literal: preceded by a `/` inside `tail`, made only of
/// `[A-Za-z0-9._-]`, not `.`/`..`, with no glob or extglob metacharacter
/// anywhere in `tail`. Trailing slashes are skipped
/// (`/p//` yields `p`). `None` when nothing can be proved (`p` alone would
/// glue onto the unresolved part's own last component, `/..` and `/.` can
/// cancel or vanish).
fn literal_tail_component(tail: &str) -> Option<&str> {
    if tail.contains(['*', '?', '[', '(', '\0']) {
        return None;
    }
    let (idx, last) = tail
        .split('/')
        .enumerate()
        .filter(|(_, comp)| !comp.is_empty())
        .last()?;
    let plain = last
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    (idx >= 1 && plain && last != "." && last != "..").then_some(last)
}

/// [`CommandRule::matches`]'s except-suppression fail-closed guard (issue
/// #136): whether `candidate` is a `/`- or `~`-rooted path containing a
/// literal `..` path segment — see that function's doc comment for why
/// such a candidate must never be treated as excepted. Scoped to rooted
/// candidates only: every shipped `except_targets` entry (`exact`/
/// `prefix`) is itself `/`- or `~`-rooted, so only a rooted candidate can
/// ever raw-match one — widening this to unrooted candidates would false-
/// positive a `url_host` except's non-path candidates (e.g. a `..`
/// appearing in a URL path segment) for no matching benefit.
fn candidate_has_unresolved_ascent(candidate: &str) -> bool {
    (candidate.starts_with('/') || candidate.starts_with('~'))
        && candidate.split('/').any(|segment| segment == "..")
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
/// the wrapper walk's documented gap (which can only ever
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
/// function. A rule author can opt a specific short flag into recognition
/// via `attached_value_flags` (issue #47, [`attached_value_candidate`]) —
/// still shape-based (a left-to-right cluster scan as of issue #214; see
/// that function's doc for its known truncation/suppression caveat), but
/// declared per rule rather than guessed.
/// Absent that declaration, gating a command with this attached-value
/// flag idiom should additionally forbid the flag via
/// `required_flags`/a separate `deny` entry rather than relying on
/// `except_targets` alone.
fn target_candidate(token: &str) -> Option<&str> {
    if !token.starts_with('-') {
        return Some(token);
    }
    token
        .strip_prefix("--")?
        .split_once('=')
        .map(|(_, value)| value)
}

/// Whether `token` is one of `attached_value_flags`' declared short flags
/// glued directly onto a value with no `=` separator (`-xVALUE`) — the
/// opt-in *inclusion* counterpart to [`ValueFlag`]'s *exclusion*
/// semantics (issue #47): a declared flag's glued value becomes a NEW
/// except_targets candidate, rather than staying invisible the way
/// [`target_candidate`]'s "Known limitation" section discloses.
///
/// Issue #214: a declared letter is recognised anywhere in the cluster,
/// not just the leading position — a real left-to-right scan matching
/// getopt's own short-cluster parsing (`-sxVALUE` is `-s` plus
/// `-x VALUE`: once a cluster reaches a flag that takes a value,
/// everything after it IS that value, not more flag letters). Every
/// character before the matched letter is just an independent boolean
/// flag in getopt's model and is skipped without being validated as a
/// real, declared flag for the wrapper being called — this function only
/// ever needs to find where the glued value starts, not validate the
/// flags before it.
///
/// Only the exact single-character-then-rest shape is recognised: `-x`
/// alone (nothing follows) is not this shape, so a bare declared flag at
/// the end of a cluster yields no candidate at all, same as an
/// undeclared one — not because an empty candidate could wrongly satisfy
/// an except_targets alternative (`convert_target` rejects an empty
/// `exact`/`prefix` at load, so `""` can never match a loadable
/// alternative either way), but because an un-exceptable `""` candidate
/// would make the rule spuriously fire on a bare cluster, noise this
/// function avoids by not manufacturing it in the first place.
///
/// Widened false-Ask surface: since the scan matches the declared letter
/// anywhere in a dash-prefixed token, not just a genuine flag position,
/// a declared letter appearing incidentally inside an unrelated token's
/// text (e.g. `x` declared, token `-yhttp://evil.example.com` containing
/// "example") yields a junk tail candidate too. Fail-closed only once the
/// candidate set would otherwise already be non-empty (more candidates
/// there means more likely to ask/block, never less) — a rule author
/// declaring `attached_value_flags` should expect a higher false-Ask rate
/// on tokens that happen to contain the letter, not just on the flag
/// shapes they intended to catch. When the candidate set would otherwise
/// be empty, though, this is the same mechanism as the suppression case
/// disclosed below: an incidental junk candidate that happens to match an
/// except is indistinguishable, at this point, from a mis-split one.
///
/// Because the scan has no notion of which earlier characters are
/// themselves value-taking, it can find a declared letter that's really
/// part of an EARLIER flag's own glued value rather than a genuine flag
/// position — e.g. `-oxyz` with `x` declared but `o` actually the
/// value-taking flag would split at `x`, yielding `"yz"` instead of
/// `"xyz"` as `o`'s true value. When `o` is itself declared in this
/// rule's `value_flags`, the scan stops at `o` instead and yields no
/// candidate at all (below), restoring getopt-correct behavior for any
/// flag this rule already knows takes a value. For a flag this rule has
/// no declared knowledge of, shape-based matching genuinely can't tell
/// the two shapes apart from the token's text alone.
///
/// **Known limitation, disclosed rather than silently accepted**: unlike
/// [`target_candidate`]'s gap (a *missing* candidate — the proxy target
/// stays invisible, but the candidate set's existing members are
/// unaffected), a mis-split truncated candidate here CAN newly suppress a
/// rule that used to fire, because the scan only ever adds candidates,
/// never removes them: if the truncated tail happens to match an
/// `except_targets` alternative, it can turn a previously EMPTY candidate
/// set (which fails "all candidates excepted" and so lets the rule fire)
/// into a non-empty, all-excepted one — e.g. rule
/// `except_targets = [{ prefix = "http://localhost" }]`,
/// `attached_value_flags = ["x"]`, argv
/// `curl -yhttp://evil.test -oAxhttp://localhost`: undeclared `-o`'s true
/// value is `Axhttp://localhost`, but the scan finds `x` inside it and
/// manufactures the excepted-looking candidate `http://localhost`,
/// masking the untouched `evil.test` target behind `-y`. This is the
/// accepted opt-in trade-off of declaring `attached_value_flags` for a
/// rule whose other flags aren't all covered by `value_flags` too — not
/// a silent invariant of the mechanism. Regression-tested (disclosed, not
/// silently accepted) by
/// `attached_value_flags_mis_split_can_suppress_an_undeclared_flags_value`.
fn attached_value_candidate<'a>(
    token: &'a str,
    attached_value_flags: &[char],
    value_flags: &[ValueFlag],
) -> Option<&'a str> {
    let rest = token.strip_prefix('-')?;
    if rest.starts_with('-') {
        return None;
    }
    for (index, c) in rest.char_indices() {
        if attached_value_flags.contains(&c) {
            let value = &rest[index + c.len_utf8()..];
            return if value.is_empty() { None } else { Some(value) };
        }
        if value_flags.contains(&ValueFlag::Short(c)) {
            // `c` is a flag this rule already declares takes a value —
            // everything after it in the cluster is THAT flag's value
            // per getopt, not more flag letters to scan through.
            return None;
        }
    }
    None
}

/// The except_targets candidate set drawn from `rest` (already-resolved
/// argv tail) with each declared `value_flags` entry's value consumed and
/// excluded (issue #48), and each declared `attached_value_flags` entry's
/// glued value included (issue #47) — a single left-to-right positional
/// walk, only ever reached once the caller ([`CommandRule::matches`]) has
/// already confirmed no token in the tail is unresolvable, so every token
/// here is a known, concrete string. A token matching a declared flag's
/// bare spelling (`-o`, `--exclude`) consumes the *next* token as that
/// flag's separated value — neither token becomes a candidate. A token
/// matching a declared long flag's `--name=value` attached form is
/// excluded outright — its value never becomes a candidate either. A
/// token matching a declared `attached_value_flags` short flag's glued
/// form (`-xVALUE`) contributes its value as a candidate instead of
/// falling through to [`target_candidate`] (which would see no candidate
/// at all for that shape). Everything else falls through to
/// [`target_candidate`], unchanged from before either field existed. An
/// undeclared flag's value is untouched by any of this and keeps
/// counting as a candidate — the existing fail-closed default.
///
/// A bare `--` token (the POSIX/GNU end-of-options terminator, not itself
/// consumed as a preceding flag's separated value) permanently turns off
/// `value_flags`/`attached_value_flags` matching for every token after
/// it: everything from that point on is an ordinary positional argument
/// by shell convention, so a value carrying the same text as a declared
/// flag name (`rsync ./src/ ./dst/ -- --exclude remote:evil`, where
/// `--exclude`/`remote:evil` are literal filenames, not the `--exclude`
/// flag) must not be mistaken for the flag and consumed — that would
/// silently remove a genuine (non-excepted) target from the candidate
/// set. Regression-tested by
/// `value_flags_does_not_consume_positionals_after_end_of_options_terminator`
/// below.
fn value_flag_free_candidates<'a>(
    rest: &[&'a str],
    value_flags: &[ValueFlag],
    attached_value_flags: &[char],
) -> Vec<&'a str> {
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
            if let Some(candidate) =
                attached_value_candidate(token, attached_value_flags, value_flags)
            {
                candidates.push(candidate);
                continue;
            }
        }
        if let Some(candidate) = target_candidate(token) {
            candidates.push(candidate);
        }
    }
    candidates
}

/// The except_targets candidate set for a rule declaring `target_flags`
/// (issue #581): exactly the values of the listed flags, nothing else. The
/// `targets` match of such a rule uses [`target_flag_match_values`].
/// Recognised shapes: `--flag value`, `--flag=value`, a short flag's
/// separated value (`-f value`), and a short flag's glued value (`-fvalue`,
/// found via [`attached_value_candidate`]'s cluster scan). A bare `--`
/// terminator turns recognition off for everything after it, as in
/// [`value_flag_free_candidates`]. A listed flag that is the last token
/// (no value follows) returns `None`: the caller must fail closed, since a
/// value the command may take from elsewhere cannot be proven excepted.
/// Like [`value_flag_free_candidates`], only reached once the caller has
/// confirmed no tail token is unresolvable. A flag absent from the command
/// yields no candidates, which is never "all excepted".
///
/// # Limits (the rule author's responsibility)
///
/// - Every spelling of the option must be listed: an alias (`--body-file`
///   and `-F`) that is not listed is invisible, so its value is never
///   checked and cannot stop the exception.
/// - No other flag is examined at all: a mode flag that changes what the
///   command does (`--delete-last`, `--attach`) passes through, so pair the
///   rule with a separate `deny` for such flags.
/// - Abbreviated long spellings (`--body-f`, as accepted by `getopt_long`
///   tools) are not recognised; for such a tool pair the rule with a `deny`
///   or do not use `target_flags`. Prefix matching is deliberately not
///   done, since `--body` may be a different real flag.
/// - `-F=value` is not recognised as an attached form: it is read as the
///   glued value `=value`, which matches no loadable except alternative, so
///   the rule fires.
///
/// The rule's `value_flags` stop the short-cluster scan: a declared
/// value-taking letter that precedes a listed letter owns the rest of the
/// cluster, so no candidate is produced from it.
fn target_flag_values<'a>(
    rest: &[&'a str],
    target_flags: &[ValueFlag],
    value_flags: &[ValueFlag],
) -> Option<Vec<&'a str>> {
    let shorts: Vec<char> = target_flags
        .iter()
        .filter_map(|f| match f {
            ValueFlag::Short(c) => Some(*c),
            ValueFlag::Long(_) => None,
        })
        .collect();
    let mut values = Vec::new();
    let mut iter = rest.iter();
    while let Some(token) = iter.next() {
        if *token == "--" {
            break;
        }
        if target_flags.iter().any(|f| f.attached_value_token(token)) {
            if let Some((_, value)) = token.split_once('=') {
                values.push(value);
            }
            continue;
        }
        let separated = target_flags.iter().any(|f| f.is_bare(token))
            || short_cluster_ends_with_declared(token, &shorts, value_flags);
        if separated {
            values.push(iter.next().copied()?);
            continue;
        }
        if let Some(value) = attached_value_candidate(token, &shorts, value_flags) {
            values.push(value);
        }
    }
    Some(values)
}

/// The `targets` candidate set for a rule declaring `target_flags` (issue
/// #622): the readable values of the listed flags, in the shapes
/// [`target_flag_values`] recognises. Built to over-collect, since a value
/// missed here is a missed match rather than a missed exception:
///
/// - A short flag's glued `=value` (`-F=/etc/passwd`, which pflag-based
///   tools such as `gh` read as `/etc/passwd`) yields both `=value` and
///   `value`.
/// - A bare `--` does not stop the walk: not every tool honours it.
/// - An unresolvable word yields nothing, and a listed flag followed by
///   one (or by nothing) consumes it without a value. The word stays in
///   the argv, so the unresolved-argument floor
///   ([`CommandRule::matches_except_target`]) still asks.
///
/// A value passed through an unlisted spelling or an abbreviated long
/// flag is never tested, so the rule does not fire for it: the author must
/// list every spelling.
fn target_flag_match_values<'a>(
    rest_words: &'a [NormalizedWord],
    target_flags: &[ValueFlag],
    value_flags: &[ValueFlag],
) -> Vec<&'a str> {
    let shorts: Vec<char> = target_flags
        .iter()
        .filter_map(|f| match f {
            ValueFlag::Short(c) => Some(*c),
            ValueFlag::Long(_) => None,
        })
        .collect();
    let mut values = Vec::new();
    let mut iter = rest_words.iter().map(|w| match w.resolution() {
        Resolution::Resolved(s) => Some(s.as_str()),
        Resolution::Unresolvable(_) => None,
    });
    while let Some(token) = iter.next() {
        let Some(token) = token else {
            continue;
        };
        if target_flags.iter().any(|f| f.attached_value_token(token)) {
            if let Some((_, value)) = token.split_once('=') {
                values.push(value);
            }
            continue;
        }
        if target_flags.iter().any(|f| f.is_bare(token))
            || short_cluster_ends_with_declared(token, &shorts, value_flags)
        {
            if let Some(Some(value)) = iter.next() {
                values.push(value);
            }
            continue;
        }
        if let Some(value) = attached_value_candidate(token, &shorts, value_flags) {
            values.push(value);
            if let Some(stripped) = value.strip_prefix('=') {
                values.push(stripped);
            }
        }
    }
    values
}

/// The resolved words that directly follow an unresolved word, in order: the
/// only places a flag hidden in that word can take a separated value from.
fn resolved_words_after_unresolved(rest_words: &[NormalizedWord]) -> Vec<&str> {
    rest_words
        .windows(2)
        .filter(|pair| matches!(pair[0].resolution(), Resolution::Unresolvable(_)))
        .filter_map(|pair| match pair[1].resolution() {
            Resolution::Resolved(s) => Some(s.as_str()),
            Resolution::Unresolvable(_) => None,
        })
        .collect()
}

/// Whether `token` is a single-dash short cluster (`-sf`) whose final
/// character is a declared short flag with nothing glued after it, so the
/// NEXT argv token is that flag's separated value per getopt. Only called
/// from [`target_flag_values`], after the `--long` and bare forms.
fn short_cluster_ends_with_declared(
    token: &str,
    shorts: &[char],
    value_flags: &[ValueFlag],
) -> bool {
    let Some(cluster) = token.strip_prefix('-') else {
        return false;
    };
    if cluster.starts_with('-') {
        return false;
    }
    // The first declared letter (left to right) owns the rest of the
    // cluster; it ends the cluster exactly when no value is glued on. A
    // `value_flags` letter met first owns the rest instead.
    cluster
        .char_indices()
        .find(|(_, c)| shorts.contains(c) || value_flags.contains(&ValueFlag::Short(*c)))
        .is_some_and(|(i, c)| shorts.contains(&c) && i + c.len_utf8() == cluster.len())
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

/// Shell interpreters whose `-c '<string>'` argument `crate::gate` recurses
/// into as shell syntax (rule 6a). Lives here, next to the other
/// interpreter lists, so this module's allow-entry validation
/// (`matches_dangerous_allow_target`) can check a config entry against the
/// same list `crate::gate` uses, without `rules` depending on `gate`
/// ("dependencies point inward" — `gate` already depends on `rules`, not
/// the reverse).
pub(crate) const SHELL_INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "fish", "ksh", "tcsh", "csh", "ash", "mksh", "yash", "rbash",
    "osh", "ysh", "oil",
];

/// The `eval` builtin (issue #120): same "interpret this string as a shell
/// command" semantics as [`SHELL_INTERPRETERS`]'s own `-c` flag, but a
/// different calling convention — every one of `eval`'s own arguments, not
/// a single `-c VALUE` pair, is word-joined into the script
/// (`crate::gate`'s `evaluate_eval`), so it gets its own recursion path
/// rather than reusing `evaluate_dash_c`. Kept as its own single-entry list,
/// next to [`SHELL_INTERPRETERS`], for the same reason that one lives here:
/// so [`matches_dangerous_allow_target`] rejects an `allow` entry naming
/// `eval` the same way it already rejects one naming `bash`/`sh`.
pub(crate) const EVAL_BUILTIN: &[&str] = &["eval"];

/// The `trap` builtin (issue #693): its action string is shell code run
/// later in the CURRENT shell (`trap 'rm -rf ~' EXIT`), so it recurses like
/// [`EVAL_BUILTIN`] (`crate::gate`'s `evaluate_trap`). Listed separately
/// because only its first non-option argument is the script, and kept here
/// so [`matches_dangerous_allow_target`] rejects an `allow` entry naming it.
pub(crate) const TRAP_BUILTIN: &[&str] = &["trap"];

/// Non-shell interpreters a pipeline's final stage may additionally be
/// (`crate::gate` rule 5b/5c), beyond every shell already named in
/// [`SHELL_INTERPRETERS`]. Kept as a *separate* small list, rather than a
/// second hand-maintained copy of the shell names, specifically so the two
/// lists cannot drift apart again the way they did for issue #55: that fix
/// added `fish`/`ksh`/`tcsh`/`csh`/`ash` to `SHELL_INTERPRETERS` alone, and
/// this file's own former `PIPELINE_INTERPRETERS` literal silently kept
/// missing them, letting `base64 -d payload | ksh` reach `Allow`. See
/// [`is_pipeline_interpreter`], the single place both lists are consulted
/// together for pipeline-sink classification
/// ([`matches_dangerous_allow_target`] separately chains both lists too,
/// for a different purpose — rejecting a dangerous `allow` config entry).
///
/// `ruby`/`lua`/`php`/`tclsh` (issue #125) share the same "reads and
/// executes a script from stdin when given no file argument" property
/// `python`/`node`/`perl` already have here — the exact sink shape rule
/// 5b/5c exists to catch — so `base64 -d payload | ruby` was Allow the same
/// way `| ksh` was before issue #55. No separate `python2`/`python3`
/// entries: [`strip_version_suffix`] (issue #346) reduces either to
/// `python` before this list is ever consulted, the same normalization
/// that also covers every other versioned spelling (`ruby3.2`, `php8.2`, …)
/// no fixed list could enumerate.
///
/// `osascript`/`irb`/`deno`/`pwsh` (issue #347) share the sink property
/// this list exists to catch. This list is consulted by NAME alone
/// (`is_pipeline_interpreter`) with no awareness of a specific
/// invocation's own flags or arguments — `base64 -d payload | python
/// script.py` already matches despite `script.py` meaning `python` reads
/// its script from that file, not stdin, the same over-approximation
/// every pre-existing entry here already carries. A name only needs to be
/// CAPABLE of the bare-invocation stdin-execute shape in some realistic
/// invocation, not incapable of any other shape, to belong on this list.
///
/// `osascript`'s own man page states it reads and executes AppleScript/JXA
/// from stdin whenever no script-file argument is given. `irb`'s own
/// source (`ruby/irb`'s `init.rb` checks `STDIN.tty?` only to pick a
/// prompt style, never to decide whether to read-and-evaluate) confirms
/// piped, non-TTY input is read and evaluated as Ruby the same as
/// interactive input, just without the prompt decoration — live-confirmed
/// (`printf 'puts 1+2' | irb` prints `3`). `deno` was live-confirmed too,
/// correcting an earlier version of this list that excluded it on a stale
/// 2021 maintainer comment: current stable `deno` (2.9.5) drops a bare
/// invocation into its REPL, which DOES read and evaluate piped stdin
/// (`printf 'console.log(7*6)' | deno` prints `42`) — with every
/// permission granted by default, an even more capable sink than the
/// other entries here. `pwsh` needs an explicit `-Command -`/`-File -` to
/// read stdin as a script (Microsoft's own docs), unlike a truly bare
/// invocation of every other name above — but per this list's own
/// name-only matching (first paragraph), that's exactly the same shape of
/// over-approximation `python script.py` already gets: `pwsh` is added on
/// the strength of its `-Command -`/`-File -` invocations being real and
/// dangerous, not on a claim that literally every `pwsh` invocation reads
/// stdin. `expect`/`julia`/`guile` were considered but judged nichier,
/// unaudited here.
const EXTRA_PIPELINE_INTERPRETERS: &[&str] = &[
    "python",
    "node",
    "perl",
    "ruby",
    "lua",
    "php",
    "tclsh",
    "osascript",
    "irb",
    "deno",
    "pwsh",
    "nu",
    "xonsh",
    "elvish",
    // `pypy3` is version-stripped to this.
    "pypy",
];

/// Tools that run code read from stdin without being a language
/// interpreter (issue #748): a job scheduler (`at`, `batch`), a remote
/// shell (`ssh`), a debugger or REPL (`gdb`, `expect`, `wish`, `jshell`,
/// `R`, `julia`), an editor or calculator with a shell escape (`ed`, `ex`,
/// `vi`, `vim`, `dc`, `m4`) and a database client with one (`sqlite3`,
/// `psql`, `mysql`). A sink by NAME alone, like
/// [`EXTRA_PIPELINE_INTERPRETERS`], but not part of
/// [`matches_dangerous_allow_target`] for their own sake: these are everyday
/// tools, and an `allow` entry naming `psql` must keep loading. `ssh` and
/// `gdb` are also exec wrappers (issue #740), which is what makes an entry
/// naming them rejected.
///
/// Entries are post-[`strip_version_suffix`] and case-folded: `sqlite3` is
/// `sqlite`, `m4` is `m`, `R` is `r`. A stdin-operand-gated sink (`make -f
/// -`, `crontab -`) cannot be a name here; see `crate::gate`.
const STDIN_CODE_TOOLS: &[&str] = &[
    "at", "batch", "ssh", "gdb", "sqlite", "psql", "mysql", "ed", "ex", "vi", "vim", "m", "dc",
    "expect", "wish", "jshell", "r", "julia",
];

/// The `awk` family (`crate::gate` rule 6d, issue #195): every one of these
/// names' script either sits in a bare positional operand (no `-c`-style
/// flag the way `python3`/`perl`/`node` have one) or, for gawk
/// specifically, behind `-e`/`--source`. Lives here, next to
/// [`SHELL_INTERPRETERS`]/[`EVAL_BUILTIN`], for the same cross-module
/// reason those do: so [`matches_dangerous_allow_target`] can reject an
/// `allow` entry naming any of these five awk variants the same way it
/// already rejects one naming `bash`/`eval` (issue #451), without `rules` depending
/// on `gate`. Deliberately NOT added to [`EXTRA_PIPELINE_INTERPRETERS`]/
/// `is_pipeline_interpreter` (rule 5b/5c's decode-pipe-into-interpreter
/// floor): that rule is about an interpreter whose *default, flagless*
/// invocation reads piped stdin bytes as code (`sh`, a bare `python3`) — a
/// flagless `awk` never does that, piped data feeds its *records*, not its
/// script, so it isn't the same risk class. This is narrower than "awk's
/// program never comes from stdin", though: a `-f`/`-E`/`-i` flag's value
/// can itself name stdin (`-`, `/dev/stdin`, `/proc/self/fd/0`), which
/// `crate::gate`'s own awk-script scan floors to Ask on its own, independent
/// of this constant's pipeline-interpreter exclusion.
pub(crate) const AWK_INTERPRETERS: &[&str] = &["awk", "gawk", "mawk", "nawk", "original-awk"];

/// Folds `name` for case-insensitive interpreter-name comparison (issue
/// #493). macOS APFS's default case-insensitive collation is full Unicode
/// case folding, not bare ASCII lowercasing — verified directly on this
/// filesystem: `ſh` (U+017F LATIN SMALL LETTER LONG S), `awk` spelled with
/// a Kelvin sign (U+212A) in place of `k`, and `fish` spelled with a Latin
/// ligature (U+FB00-U+FB06: ﬀ, ﬁ, ﬂ, ﬃ, ﬄ, ﬅ, ﬆ, e.g. `ﬁsh`) or German ß/ẞ,
/// all name the same inode as their plain-ASCII spelling. `str::to_lowercase()`
/// alone closes the Kelvin-sign gap (its Unicode lowercase mapping already
/// reduces U+212A to `k`, and ẞ to ß) but every other fold here changes
/// EITHER which character represents an already-lowercase letter (long s
/// has no lowercase mapping at all, it's already lowercase) OR how many
/// characters represent it (each ligature is one code point standing in
/// for two or three ASCII letters) — neither is something a lowercase
/// mapping alone can express, so each needs its own explicit fold. This is
/// the closed set of Unicode `CaseFolding.txt` C/F entries whose fold
/// consists purely of ASCII letters, applied in the order needed for `ẞ`
/// to still resolve to `ss` after lowercasing produces `ß` first; it is
/// not a general Unicode case-folding implementation (no case-folding
/// crate/table is pulled in for this, and this list is not guaranteed
/// exhaustive against every future Unicode addition).
#[must_use]
pub(crate) fn fold_command_name(name: &str) -> String {
    name.to_lowercase()
        .replace('\u{017F}', "s") // ſ (long s)
        .replace('\u{00DF}', "ss") // ß (sharp s; ẞ already lowercases to this)
        .replace('\u{FB00}', "ff") // ﬀ
        .replace('\u{FB01}', "fi") // ﬁ
        .replace('\u{FB02}', "fl") // ﬂ
        .replace('\u{FB03}', "ffi") // ﬃ
        .replace('\u{FB04}', "ffl") // ﬄ
        .replace(['\u{FB05}', '\u{FB06}'], "st") // ﬅ (long s + t), ﬆ (st)
}

/// Unprefixed names of the GNU tools that Homebrew installs with a `g` prefix
/// (`gdd`, `grm`, `gfind`, `gtar`) so they do not shadow the BSD tools on
/// macOS: coreutils (including its exec wrappers `env`, `nice`, `nohup`,
/// `timeout`, `stdbuf`, `chroot`, `runcon`), findutils, tar, sed and GNU
/// `time` (`gtime`). The wrapper catalog resolves the canonical name.
const GNU_G_PREFIXED_TOOLS: &[&str] = &[
    "find",
    "xargs",
    "env",
    "nice",
    "nohup",
    "timeout",
    "stdbuf",
    "chroot",
    "runcon",
    "time",
    "locate",
    "updatedb",
    "tar",
    "sed",
    "arch",
    "b2sum",
    "base32",
    "base64",
    "basename",
    "basenc",
    "cat",
    "chcon",
    "chgrp",
    "chmod",
    "chown",
    "cksum",
    "comm",
    "cp",
    "csplit",
    "cut",
    "date",
    "dd",
    "df",
    "dir",
    "dircolors",
    "dirname",
    "du",
    "echo",
    "expand",
    "expr",
    "factor",
    "false",
    "fmt",
    "fold",
    "groups",
    "head",
    "hostid",
    "id",
    "install",
    "join",
    "kill",
    "link",
    "ln",
    "logname",
    "ls",
    "md5sum",
    "mkdir",
    "mkfifo",
    "mknod",
    "mktemp",
    "mv",
    "nl",
    "nproc",
    "numfmt",
    "od",
    "paste",
    "pathchk",
    "pinky",
    "pr",
    "printenv",
    "printf",
    "ptx",
    "pwd",
    "readlink",
    "realpath",
    "rm",
    "rmdir",
    "seq",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "shred",
    "shuf",
    "sleep",
    "sort",
    "split",
    "stat",
    "stty",
    "sum",
    "sync",
    "tac",
    "tail",
    "tee",
    "test",
    "touch",
    "tr",
    "true",
    "truncate",
    "tsort",
    "tty",
    "uname",
    "unexpand",
    "uniq",
    "unlink",
    "uptime",
    "users",
    "vdir",
    "wc",
    "who",
    "whoami",
    "yes",
];

/// [`fold_command_name`], then a `g` prefix is dropped when the rest names a
/// [`GNU_G_PREFIXED_TOOLS`] program, so `gdd` is matched exactly like `dd`.
/// Used for the command word of an invocation only: config entries keep
/// their literal [`fold_command_name`] spelling, so an `allow` for `gcp`
/// cannot widen to `cp`.
#[must_use]
pub(crate) fn canonical_command_name(name: &str) -> String {
    let folded = fold_command_name(name);
    match folded.strip_prefix('g') {
        Some(rest) if GNU_G_PREFIXED_TOOLS.contains(&rest) => rest.to_string(),
        _ => folded,
    }
}

/// Strips a trailing distro-style version suffix (`python3.12` -> `python`,
/// `lua5.4` -> `lua`, `php8.2` -> `php`) so interpreter-name matching
/// recognises versioned binaries (issue #346) without a hand-maintained list
/// of every version. Also strips a `-dbg`/`-debug` suffix and any trailing
/// run of the CPython ABI letters (`t` free-threaded, `m` pymalloc, `d` debug,
/// `u` unicode, in any combination or order: `python3.13t`, `python3.7m`,
/// `python3.7dm`, `python3.12-dbg`) that follows the digits; the run is
/// stripped only when a digit precedes it, so a plain name
/// ending in one of those letters (`sed`) is left alone. `trim_end_matches`
/// (byte-index-unsafe alternatives like `rfind` + manual slicing panic on a
/// multibyte name ending just past a non-ASCII character, e.g. `café`) only
/// ever strips ASCII characters, so it never lands mid-character. Returns
/// `name` unchanged if stripping would empty it (a name that is entirely
/// digits/dots, or has no version suffix at all) — never reduced to an empty
/// string.
pub(crate) fn strip_version_suffix(name: &str) -> &str {
    let base = name
        .strip_suffix("-dbg")
        .or_else(|| name.strip_suffix("-debug"))
        .unwrap_or(name);
    let without_abi = base.trim_end_matches(['t', 'm', 'd', 'u']);
    let base = if without_abi.ends_with(|c: char| c.is_ascii_digit()) {
        without_abi
    } else {
        base
    };
    let stripped = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if stripped.is_empty() { name } else { stripped }
}

/// Whether `name` is an interpreter a pipeline's final stage may be
/// (`crate::gate` rule 5b/5c) — every [`SHELL_INTERPRETERS`] entry, plus
/// [`EXTRA_PIPELINE_INTERPRETERS`]'s non-shell interpreters, after
/// [`strip_version_suffix`] normalizes a distro-versioned binary name
/// (`lua5.4`, `php8.2`) down to its base. Always call this rather than
/// consulting either list alone, so a future addition to
/// `SHELL_INTERPRETERS` (a new shell) is automatically also recognised as a
/// pipeline sink, with nothing left to keep in sync by hand. Case-folded
/// before stripping (issue #493): a case-variant spelling (`PYTHON3`)
/// resolves to the same binary as the lowercase name on a case-insensitive
/// filesystem (macOS APFS default), so recognition must not depend on case.
#[must_use]
pub(crate) fn is_pipeline_interpreter(name: &str) -> bool {
    let lower = fold_command_name(name);
    let name = strip_version_suffix(&lower);
    SHELL_INTERPRETERS.contains(&name)
        || EXTRA_PIPELINE_INTERPRETERS.contains(&name)
        || STDIN_CODE_TOOLS.contains(&name)
}

/// Whether `name` is a [`SHELL_INTERPRETERS`] member once
/// [`strip_version_suffix`] normalizes a distro-versioned binary name
/// (`bash5` -> `bash`) — the same normalization [`is_pipeline_interpreter`]
/// applies, kept as its own function for `crate::gate`'s `-c` recursion call
/// sites, which need the plain shell-only list rather than the pipeline-sink
/// union. Case-folded first, see [`is_pipeline_interpreter`]'s doc (issue
/// #493).
#[must_use]
pub(crate) fn is_shell_interpreter(name: &str) -> bool {
    let lower = fold_command_name(name);
    SHELL_INTERPRETERS.contains(&strip_version_suffix(&lower))
}

/// Whether `name` is an [`EXTRA_PIPELINE_INTERPRETERS`] member once
/// [`strip_version_suffix`] normalizes a distro-versioned binary name
/// (`ruby3.2` -> `ruby`). Matches by NAME ALONE, the same
/// over-approximation [`EXTRA_PIPELINE_INTERPRETERS`]'s own docs justify for
/// `is_pipeline_interpreter` (`python3 script.py` matches despite reading
/// `script.py`, not stdin) — a name only needs to be CAPABLE of reading a
/// script from stdin in some realistic invocation, not incapable of any
/// other shape. Mirrors [`is_shell_interpreter`]'s shape, kept as its own
/// function for `crate::gate`'s heredoc-as-stdin floor (issue #424), which
/// needs the non-shell list alone rather than the pipeline-sink union
/// [`is_pipeline_interpreter`] returns. Case-folded first, see
/// [`is_pipeline_interpreter`]'s doc (issue #493).
#[must_use]
pub(crate) fn is_stdin_script_interpreter(name: &str) -> bool {
    let lower = fold_command_name(name);
    let name = strip_version_suffix(&lower);
    EXTRA_PIPELINE_INTERPRETERS.contains(&name) || STDIN_CODE_TOOLS.contains(&name)
}

/// One `find` flag whose payload is itself a command to recurse into
/// directly: no shell is involved at all (issue #72: `find -exec`/
/// `-execdir`/`-ok`/`-okdir` run their payload directly). The span runs from
/// the word after the flag up to the first word resolving to one of
/// `terminators`. The shell-string flags of wrappers (`flock -c`,
/// `su -c`, `script -c`) are roles in the `crate::knowledge` catalog
/// instead, since they belong to a wrapper's spec.
pub(crate) struct RecursableSlot {
    pub(crate) commands: &'static [&'static str],
    pub(crate) flag: &'static str,
    pub(crate) terminators: &'static [&'static str],
}

/// See [`RecursableSlot`]'s docs. `crate::gate::scan_recursable_slots` walks
/// it directly (`find` has no wrapper chain to unwrap).
pub(crate) const RECURSABLE_SLOTS: &[RecursableSlot] = &[
    RecursableSlot {
        commands: &["find"],
        flag: "-exec",
        terminators: &[";", "+"],
    },
    RecursableSlot {
        commands: &["find"],
        flag: "-execdir",
        terminators: &[";", "+"],
    },
    RecursableSlot {
        commands: &["find"],
        flag: "-ok",
        // Issue #360: unlike `-exec`/`-execdir`, POSIX/GNU/BSD `find` never
        // give `-ok`/`-okdir` a `{} +` batching form (they prompt per
        // matched file, which is incompatible with batching) — `;` is the
        // only real terminator. A bare `+` here is an ordinary payload
        // argument, same as anywhere else it doesn't immediately follow a
        // literal `{}`.
        terminators: &[";"],
    },
    RecursableSlot {
        commands: &["find"],
        flag: "-okdir",
        // Issue #360, same rationale as `-ok` above.
        terminators: &[";"],
    },
    // Issue #736: `fd` (`fdfind` on Debian/Ubuntu) runs its payload directly
    // for each match (`-x`) or once with every match (`-X`), exactly like
    // `find -exec`. The payload runs to the end of the command unless a `;`
    // ends it; `+` is never special.
    RecursableSlot {
        commands: FD_COMMANDS,
        flag: "-x",
        terminators: &[";"],
    },
    RecursableSlot {
        commands: FD_COMMANDS,
        flag: "--exec",
        terminators: &[";"],
    },
    RecursableSlot {
        commands: FD_COMMANDS,
        flag: "-X",
        terminators: &[";"],
    },
    RecursableSlot {
        commands: FD_COMMANDS,
        flag: "--exec-batch",
        terminators: &[";"],
    },
];

const FD_COMMANDS: &[&str] = &["fd", "fdfind"];

/// The `-x`/`-X`/`--exec`/`--exec-batch` spelling an `fd` word carries when
/// the payload's first word is attached to the flag (`--exec=rm`, `-xrm`,
/// `-Hx=rm`) or the flag sits in a short-option cluster (`-Hx`), with the
/// attached text (empty for a bare cluster). `None` for any other word.
/// Not a `strip_prefix("-x")` check: `-ex` is `-e x` (extension filter) and
/// `-tx` is `-t x` (type filter), so the scan stops at the first letter of
/// a value-taking flag.
pub(crate) fn fd_attached_exec(command: &str, word: &str) -> Option<(&'static str, String)> {
    if !FD_COMMANDS.contains(&command) {
        return None;
    }
    for (long, flag) in [("--exec=", "--exec"), ("--exec-batch=", "--exec-batch")] {
        if let Some(value) = word.strip_prefix(long) {
            return Some((flag, value.to_string()));
        }
    }
    let cluster = word.strip_prefix('-').filter(|c| !c.starts_with('-'))?;
    for (at, c) in cluster.char_indices() {
        match c {
            'x' | 'X' => {
                let rest = &cluster[at + 1..];
                let value = rest.strip_prefix('=').unwrap_or(rest);
                return Some((if c == 'x' { "-x" } else { "-X" }, value.to_string()));
            }
            'd' | 'E' | 't' | 'e' | 'S' | 'o' | 'c' | 'j' | 'C' => return None,
            _ => {}
        }
    }
    None
}

/// The basename of a command token: `/bin/sh` -> `sh`, `./sh` -> `sh`, a
/// bare `sh` unchanged. A pure string operation on the already-normalised
/// token — never a filesystem lookup or symlink resolution (this crate
/// never touches the filesystem, module docs).
pub(crate) fn basename(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

/// One transparent-wrapper hop of a stage's wrapper chain: the catalogued
/// wrapper, the words after its name and how its own arguments parse.
///
/// An option the catalog does not describe leaves `unmodeled` set. `parsed`
/// then treats that token as a lone flag so the wrapped command stays
/// visible to rule matching; [`first_unmodeled_wrapper_option`] is how the
/// gate raises its floor for it.
struct WrapperHop<'a> {
    base: &'a str,
    wrapper: Known,
    tail: &'a [NormalizedWord],
    parsed: ParsedArgv<'a>,
    unmodeled: Option<Finding>,
}

impl<'a> WrapperHop<'a> {
    /// The words from the wrapped command on.
    fn next(&self) -> &'a [NormalizedWord] {
        &self.tail[self.parsed.command_at()..]
    }
}

/// Reads `tail` as the arguments of the wrapper named `folded`, unless
/// `folded` is not a catalogued exec wrapper or is listed in `excluded`.
fn wrapper_hop<'a>(
    base: &'a str,
    folded: &str,
    tail: &'a [NormalizedWord],
    excluded: &[&str],
) -> Option<WrapperHop<'a>> {
    if excluded.contains(&folded) {
        return None;
    }
    let wrapper = knowledge::lookup(folded).filter(Known::runs_command)?;
    let (parsed, unmodeled) = match wrapper.parse(tail) {
        Ok(parsed) => (parsed, None),
        Err(unmodeled) => {
            let finding = unmodeled.finding();
            (unmodeled.into_best_effort(), Some(finding))
        }
    };
    if !parsed.applies() {
        return None;
    }
    Some(WrapperHop {
        base,
        wrapper,
        tail,
        parsed,
        unmodeled,
    })
}

/// One step of the wrapper-unwrap walk shared by every chain consumer.
enum Step<'a> {
    Wrapper(WrapperHop<'a>),
    /// The first word is not a wrapper (or is an excluded one).
    Command {
        folded: String,
        base: &'a str,
        tail: &'a [NormalizedWord],
    },
    /// The first word is unresolvable.
    Unresolvable,
    Empty,
}

fn step<'a>(rest: &'a [NormalizedWord], excluded: &[&str]) -> Step<'a> {
    let Some((first, tail)) = rest.split_first() else {
        return Step::Empty;
    };
    let Resolution::Resolved(name) = first.resolution() else {
        return Step::Unresolvable;
    };
    let base = basename(name);
    let folded = canonical_command_name(base);
    match wrapper_hop(base, &folded, tail, excluded) {
        Some(hop) => Step::Wrapper(hop),
        None => Step::Command { folded, base, tail },
    }
}

/// Finds the command a pipeline stage actually runs: the basename of
/// `stage`'s command word, looking through any leading chain of catalogued
/// exec wrappers (`nohup nice sh` resolves through both). Returns the
/// effective command name plus the argv words after it, so a caller can
/// still inspect the wrapped command's own flags (`is_decode_stage`'s
/// `base64 -d` check must still see `-d` when reached through `env base64
/// -d`).
///
/// Returns `None` — fail-closed, never a guess — when the stage is empty,
/// the command word (or a wrapper's, mid-chain) is unresolvable, or a
/// wrapper's own arguments consume the rest of the stage with no command
/// left (`env` alone).
#[must_use]
pub(crate) fn effective_command(
    stage: &[NormalizedWord],
) -> Option<(Cow<'_, str>, &[NormalizedWord])> {
    effective_command_excluding(stage, &[])
}

/// Same walk as [`effective_command`], except every wrapper named in
/// `excluded` is treated as though it were not a wrapper at all: the walk
/// stops there and reports the wrapper itself as the effective command,
/// rather than unwrapping through it. Scoped to the callers that need the
/// wrapper's own flags intact (`crate::gate::resolve_static_substitution_output`
/// excludes `xargs`, whose output is not statically determined).
#[must_use]
pub(crate) fn effective_command_excluding<'a>(
    stage: &'a [NormalizedWord],
    excluded: &[&str],
) -> Option<(Cow<'a, str>, &'a [NormalizedWord])> {
    let mut rest = stage;
    loop {
        match step(rest, excluded) {
            Step::Wrapper(hop) => rest = hop.next(),
            Step::Command { folded, base, tail } => {
                // Returned folded (issues #551, #562): callers compare this
                // name against lowercase literals, so a raw re-cased
                // spelling (`ENV`, `TAR`) would silently skip the check.
                let name = if folded == base {
                    Cow::Borrowed(base)
                } else {
                    Cow::Owned(folded)
                };
                return Some((name, tail));
            }
            Step::Unresolvable | Step::Empty => return None,
        }
    }
}

/// The canonical name and the `stage` index range of the own option words
/// (wrapper word excluded) of every wrapper hop along `stage`'s chain,
/// outermost first.
#[must_use]
pub(crate) fn wrapper_option_ranges(
    stage: &[NormalizedWord],
) -> Vec<(String, std::ops::Range<usize>)> {
    let mut ranges = Vec::new();
    let mut at = 0;
    while let Step::Wrapper(hop) = step(&stage[at..], &[]) {
        let end = at + 1 + hop.parsed.command_at();
        ranges.push((canonical_command_name(hop.base), at + 1..end));
        at = end;
    }
    ranges
}

/// The first option along `stage`'s wrapper chain that the catalog does not
/// describe, if any. This is the only way an unmodelled option leaves
/// `rules`; `crate::gate` turns it into a decision.
#[must_use]
pub(crate) fn first_unmodeled_wrapper_option(stage: &[NormalizedWord]) -> Option<Finding> {
    let mut rest = stage;
    while let Step::Wrapper(hop) = step(rest, &[]) {
        if hop.unmodeled.is_some() {
            return hop.unmodeled;
        }
        rest = hop.next();
    }
    None
}

/// Wrappers that run their command on another host or in a container.
const REMOTE_EXEC_WRAPPERS: &[&str] = &["ssh", "docker", "kubectl"];

/// The canonical name and argument tail of every wrapper hop along `stage`'s
/// chain, outermost first. A wrapper that is itself a stdin sink (`ssh`,
/// `docker exec -i`) is only visible here: [`effective_command`] reports the
/// command behind it.
#[must_use]
pub(crate) fn wrapper_hops(stage: &[NormalizedWord]) -> Vec<(String, &[NormalizedWord])> {
    let mut hops = Vec::new();
    let mut rest = stage;
    while let Step::Wrapper(hop) = step(rest, &[]) {
        hops.push((canonical_command_name(hop.base), hop.tail));
        rest = hop.next();
    }
    hops
}

/// The replace-string an `xargs` hop's own options set (`-I R`, `-IR`, `-i[R]`,
/// `--replace[=R]`, BSD `-J R`), the last one winning; `None` when it sets
/// none or the value is unresolvable.
fn xargs_replace_string(hop: &WrapperHop<'_>) -> Option<String> {
    let words = &hop.tail[..hop.parsed.command_at()];
    let text = |i: usize| match words.get(i)?.resolution() {
        Resolution::Resolved(s) => Some(s.as_str()),
        Resolution::Unresolvable(_) => None,
    };
    let mut replace = None;
    let mut i = 0;
    while let Some(word) = text(i) {
        i += 1;
        if word == "--replace" {
            replace = Some("{}".to_string());
        } else if let Some(value) = word.strip_prefix("--replace=") {
            replace = Some(value.to_string());
        } else if let Some(cluster) = word.strip_prefix('-').filter(|c| !c.starts_with('-')) {
            for (at, c) in cluster.char_indices() {
                let attached = &cluster[at + 1..];
                match c {
                    'i' => {
                        replace =
                            Some(if attached.is_empty() { "{}" } else { attached }.to_string());
                        break;
                    }
                    'I' | 'J' => {
                        replace = if attached.is_empty() {
                            let value = text(i).map(str::to_string);
                            i += 1;
                            value
                        } else {
                            Some(attached.to_string())
                        };
                        break;
                    }
                    'E' | 'L' | 'l' | 'n' | 's' | 'P' | 'd' | 'a' | 'e' | 'R' | 'S' => {
                        if attached.is_empty() && !matches!(c, 'l' | 'e') {
                            i += 1;
                        }
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    replace.filter(|r| !r.is_empty())
}

/// Whether some hop of `stage`'s wrapper chain has a command word that
/// contains one of `initial` or an enclosing `xargs`' replace-string. Such a
/// word is substituted before the command runs (`xargs -I{} {} -rf /`,
/// `find -exec env {} rm -rf / \;`), so the command that actually runs
/// comes from data this crate cannot see.
#[must_use]
pub(crate) fn placeholder_in_command_slot(stage: &[NormalizedWord], initial: &[&str]) -> bool {
    let mut active: Vec<String> = initial.iter().map(|p| (*p).to_string()).collect();
    let mut rest = stage;
    loop {
        if let Some(Resolution::Resolved(word)) = rest.first().map(NormalizedWord::resolution)
            && active.iter().any(|p| word.contains(p.as_str()))
        {
            return true;
        }
        match step(rest, &[]) {
            Step::Wrapper(hop) => {
                active.extend(hop_placeholders(&hop));
                rest = hop.next();
            }
            Step::Command { .. } | Step::Unresolvable | Step::Empty => return false,
        }
    }
}

/// The words a wrapper hop itself substitutes into the command it runs.
fn hop_placeholders(hop: &WrapperHop<'_>) -> Vec<String> {
    match canonical_command_name(hop.base).as_str() {
        "xargs" => xargs_replace_string(hop).into_iter().collect(),
        "entr" => vec!["/_".to_string()],
        _ => Vec::new(),
    }
}

/// The shell strings the wrapper chain of `stage` runs once a placeholder is
/// active (`find -exec sh -c '{} -rf /'`, `xargs -I{} sh -c '{} -rf ~'`),
/// with the placeholders active for them. The caller checks each string's
/// own commands with [`placeholder_in_command_slot`].
#[must_use]
pub(crate) fn placeholder_script_strings(
    stage: &[NormalizedWord],
    initial: &[&str],
) -> (Vec<String>, Vec<String>) {
    let mut active: Vec<String> = initial.iter().map(|p| (*p).to_string()).collect();
    let mut scripts = Vec::new();
    let mut rest = stage;
    while let Step::Wrapper(hop) = step(rest, &[]) {
        active.extend(hop_placeholders(&hop));
        if !active.is_empty() {
            for value in hop.wrapper.shell_script_values(hop.tail) {
                if let ScriptValue::Text(script) = value {
                    scripts.push(script.to_string());
                }
            }
        }
        rest = hop.next();
    }
    (scripts, active)
}

/// Whether the command `stage` finally runs is named by a word containing
/// `=`. Bash runs such a word as a command name (`a.b=c`, `1a=b`, `=x` are
/// not assignments), so what executes is unknowable here and `crate::gate`
/// floors it. Checked on the raw word, not [`basename`]: `FOO=/bin/rm` would
/// otherwise read as `rm`.
#[must_use]
pub(crate) fn has_assignment_shaped_command_name(stage: &[NormalizedWord]) -> bool {
    let mut rest = stage;
    loop {
        match step(rest, &[]) {
            Step::Wrapper(hop) => rest = hop.next(),
            Step::Command { .. } => {
                return matches!(
                    rest.first().map(NormalizedWord::resolution),
                    Some(Resolution::Resolved(word)) if word.contains('=')
                );
            }
            Step::Unresolvable | Step::Empty => return false,
        }
    }
}

/// How `stage`'s wrapper-unwrap chain (the same walk as
/// [`effective_command`]) relates to the catalog's privilege-escalating
/// commands — see [`wrapper_chain_escalation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WrapperChainEscalation {
    /// A privilege-escalating command appears at some hop of the chain —
    /// carries which one (the catalog's `'static` name), so `crate::gate`'s
    /// floor reason can name it.
    Contains(&'static str),
    /// The chain passed through at least one transparent wrapper and then
    /// hit an unresolvable word — the wrapped command, possibly an
    /// escalation vector itself (`env $(echo sudo) ls`, `env $SUDO ls`),
    /// cannot be determined statically.
    Unresolved,
    /// The chain resolves and never passes through an escalation vector.
    Absent,
}

/// Classifies `stage`'s wrapper-unwrap chain against the catalog's
/// privilege-escalating commands at *any* hop, not just the terminal
/// resolved command — `env sudo ls` must be caught the same as a bare
/// `sudo ls` (issue #32, generalised to `doas`/`su`/`pkexec`/`run0` by
/// issues #35/#36; `crate::gate` rule 10).
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
        match step(rest, &[]) {
            Step::Wrapper(hop) => {
                if hop.wrapper.escalates_privileges() {
                    return WrapperChainEscalation::Contains(hop.wrapper.name());
                }
                passed_wrapper = true;
                rest = hop.next();
            }
            Step::Unresolvable if passed_wrapper => return WrapperChainEscalation::Unresolved,
            Step::Command { .. } | Step::Unresolvable | Step::Empty => {
                return WrapperChainEscalation::Absent;
            }
        }
    }
}

/// Whether `stage`'s wrapper-unwrap chain passes an option that runs the
/// wrapped command in another directory (`sudo -D`/`--chdir`, `run0 -D`) or
/// root (`-R`/`--chroot`) than the shell's own, or starts a login or `$SHELL`
/// session (`sudo -i`/`-s`, `su -`/`-l`). Relative paths in the wrapped
/// command then name different files than the lexical cwd suggests, and
/// nothing composes them (unlike `env -C`, issue #209). Over-approximates on
/// purpose, see `Known::token_relocates_cwd`.
#[must_use]
pub(crate) fn wrapper_chain_changes_cwd(stage: &[NormalizedWord]) -> bool {
    let mut rest = stage;
    while let Step::Wrapper(hop) = step(rest, &[]) {
        let changes = hop.tail[..hop.parsed.options_end()].iter().any(|word| {
            matches!(word.resolution(), Resolution::Resolved(token) if hop.wrapper.token_relocates_cwd(token))
        });
        if changes {
            return true;
        }
        rest = hop.next();
    }
    false
}

/// [`builtin_loadable_library`]'s outcome for one `builtin` hop found in
/// `stage`'s wrapper-unwrap chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BuiltinLoadableLibrary {
    /// A `-f`-containing flag cluster (bare `-f`, a glued value
    /// `-flib.so`, or clustered with `-d`, e.g. `-df`) appears somewhere in
    /// `builtin`'s own leading run of dash-prefixed tokens — see
    /// [`builtin_loadable_library`]'s docs on why the whole leading run,
    /// not just the first token, must be scanned (`builtin -d -f lib` is
    /// lexically identical to `builtin -df lib` in ksh's own option
    /// parser). Loads a shared object.
    Present,
    /// An unresolvable token appears within `builtin`'s own leading
    /// dash-token run, before either a `-f` cluster or the run's end — fail
    /// closed the same way [`WrapperChainEscalation::Unresolved`] does.
    Uncertain,
    /// No `builtin` hop in the chain, or its leading dash-token run (if
    /// any) contains no `-f` cluster (ordinary dispatch, bare `-d`, or no
    /// arguments at all).
    Absent,
}

/// Whether `stage`'s wrapper-unwrap chain passes through ksh93's `builtin
/// [-d | -f libname] name...` own loadable-library flag (issue #365):
/// `-f` dlopen()s an arbitrary shared object and installs its exported
/// symbols as new shell builtins, the same danger `enable -f` covers
/// (`rules/blocklist.toml`'s `enable-loadable-builtin`). Unlike `enable`,
/// `builtin` is ALSO a catalogued exec wrapper — `builtin name args...`
/// runs shell builtin `name` with the REST of argv as `name`'s own
/// arguments — so a plain `required_flags = ["f"]` blocklist rule
/// false-matches an ordinary dispatch whose wrapped command happens to use
/// `-f`/`-rf` (`builtin $CMD -rf /`).
///
/// `-f`/`-d` are only ever `builtin`'s OWN flags somewhere in its LEADING
/// run of dash-prefixed tokens (ksh's grammar allows no option after the
/// first bare name, which starts the dispatched command's own arguments) —
/// but that run can be more than one token: ksh's option parser treats
/// `-d -f lib` identically to a single clustered `-df lib`. So this scans
/// every leading dash-cluster token (stopping at the first
/// non-dash-cluster token, `--`, or the end of the tail) looking for `f` in
/// ANY of them, rather than [`FlagMatcher`]'s any-position-in-the-WHOLE-argv
/// presence check (which is what let the wrapped command's own `-f`/`-rf`
/// false-match in the reverted attempt).
#[must_use]
pub(crate) fn builtin_loadable_library(stage: &[NormalizedWord]) -> BuiltinLoadableLibrary {
    let mut rest = stage;
    while let Step::Wrapper(hop) = step(rest, &[]) {
        // `builtin` is compared by its raw spelling, not the folded one:
        // folding it would need its own justification this single-keyword
        // check does not have.
        if hop.base == "builtin" {
            return builtin_own_leading_flags(hop.tail);
        }
        rest = hop.next();
    }
    BuiltinLoadableLibrary::Absent
}

/// Scans `tail` (`builtin`'s own argv, unskipped) left-to-right for `f` in
/// any leading dash-cluster token — see [`builtin_loadable_library`]'s docs
/// on why the whole leading run, not just `tail`'s first token, matters.
/// Stops (returning [`BuiltinLoadableLibrary::Absent`]) at the first token
/// that is `--`, is not `-`-prefixed, or is the bare `-` placeholder — any
/// of which ends `builtin`'s own option parsing and starts the dispatched
/// command's own arguments.
fn builtin_own_leading_flags(tail: &[NormalizedWord]) -> BuiltinLoadableLibrary {
    for word in tail {
        match word.resolution() {
            Resolution::Resolved(token) => {
                let chars = short_cluster_chars(token);
                if chars.contains(&'f') {
                    return BuiltinLoadableLibrary::Present;
                }
                if chars.is_empty() {
                    return BuiltinLoadableLibrary::Absent;
                }
            }
            Resolution::Unresolvable(_) => return BuiltinLoadableLibrary::Uncertain,
        }
    }
    BuiltinLoadableLibrary::Absent
}

/// One shell-string slot's value, found while walking a stage's
/// transparent-wrapper chain (issues #64/#66) — see
/// [`chain_script_slots`].
pub(crate) enum ScriptSlot {
    /// The flag's value resolved to a concrete shell-command string, ready
    /// for `crate::gate` to recurse the same way rule 6a recurses `sh
    /// -c`/`bash -c`.
    Resolved(String),
    /// The flag's own position, or its value, could not be statically
    /// resolved — the fail-closed counterpart of [`crate::normalize::FlagScan::Uncertain`]:
    /// an unresolvable word at either position must never read as "no
    /// script to worry about".
    Unresolvable,
}

/// Whether a shell reparse of `s` can stand in for what `env -S` itself
/// would splice into argv (issue #265).
///
/// `-S` is not shell tokenization: it splits on spaces and tabs only, and
/// its own machinery — `\` escapes (including `\_`, which is a SEPARATOR),
/// `'`/`"` quoting, `#` truncating the rest of the string, and `${VAR}`
/// expansion — differs between BSD and GNU in documented corners. Refusing
/// every string carrying that machinery keeps the reconstruction provably
/// equivalent on both flavors, at the cost of an Ask for the rest.
///
/// The characters left in (shell operators, globs, `~`, braces) are ones a
/// shell reparse gives MORE structure to than `env -S` does, so divergence
/// there is over-blocking only.
fn env_split_string_reconstructable(s: &str) -> bool {
    !s.chars()
        .any(|c| matches!(c, '\\' | '\'' | '"' | '#' | '$' | '`') || (c.is_control() && c != '\t'))
}

/// Whether `word` is plain enough to append to a reconstructed `-S`
/// command line without quoting (issue #265).
///
/// Two shapes make an unquoted join actively wrong rather than merely
/// imprecise, so the allowlist is deliberately not a refuse-list:
/// whitespace flattens (`env -S 'sh -c' 'rm -rf /'` would reconstruct to
/// `env sh -c rm -rf /`, whose `-c` script is just `rm`), and a `#` word
/// comments out everything after it, hiding the real arguments.
fn env_split_string_plain_word(word: &str) -> bool {
    !word.is_empty()
        && word.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '_' | '.' | ',' | '/' | ':' | '=' | '+' | '@' | '%' | '^' | '-'
                )
        })
}

/// The split-string values (`env -S`) in one hop, as script slots (issue
/// #265).
///
/// `-S` splits its string into new argv words that `env` then executes —
/// and those words re-enter `env`'s own option processing, which is why
/// each reconstruction is prefixed with `env` rather than recursed bare.
/// The words after the value are appended too, because real `env` splices
/// the split words AHEAD of the remaining argv (`env -S 'rm -rf' /` runs
/// `rm -rf /`). The catalog's grammar only stops the value from being read
/// as the wrapped command; it cannot look inside the string, so this is the
/// `su -c` shell-string recursion applied to a flag whose value is spliced
/// rather than passed on.
fn collect_split_string_slots(
    hop: &WrapperHop<'_>,
    flag: (char, &'static str),
    slots: &mut Vec<ScriptSlot>,
) {
    for option in hop.parsed.options_named(flag) {
        let (script, after) = match option.value {
            OptionValue::Glued(script) => (script.to_string(), &hop.tail[option.token + 1..]),
            OptionValue::Separate(word) => match word.resolution() {
                Resolution::Resolved(script) => (script.clone(), &hop.tail[option.token + 2..]),
                Resolution::Unresolvable(_) => {
                    slots.push(ScriptSlot::Unresolvable);
                    continue;
                }
            },
            // `-S` with nothing after it: real `env` errors out.
            OptionValue::Absent => continue,
        };

        if !env_split_string_reconstructable(&script) {
            slots.push(ScriptSlot::Unresolvable);
            continue;
        }

        let plain_after: Option<Vec<&str>> = after
            .iter()
            .map(|word| match word.resolution() {
                Resolution::Resolved(w) if env_split_string_plain_word(w) => Some(w.as_str()),
                _ => None,
            })
            .collect();
        match plain_after {
            Some(words) => {
                let mut reconstructed = format!("env {script}");
                for word in words {
                    reconstructed.push(' ');
                    reconstructed.push_str(word);
                }
                slots.push(ScriptSlot::Resolved(reconstructed));
            }
            // The tail cannot be represented, so recurse the split string
            // alone AND floor on the part that was dropped.
            None => {
                slots.push(ScriptSlot::Resolved(format!("env {script}")));
                slots.push(ScriptSlot::Unresolvable);
            }
        }
    }
}

/// Finds every shell string a transparent-wrapper chain hands to a shell
/// along `stage`: the catalog's `ShellScript` flags (`flock`/`su`/`runuser`/`script`
/// `-c`/`--command`, `su`/`runuser` `--session-command`, issues #64/#66), `env`'s `-S` splices (issue #265),
/// `watch`'s joined operands and `strace -o '|cmd'`. Mirrors the same
/// wrapper-unwrap walk [`effective_command`]/[`wrapper_chain_escalation`]
/// perform, but — unlike both of those — does not stop at the first hop and
/// does not rely on the hop's option region to find the flag: each hop's
/// *entire* argument tail is scanned for its script flag (see
/// `Known::shell_script_values`), independent of whether that flag sits
/// before or after the wrapper's own positional slot. This is deliberately
/// broader than the option region — a same-hop token that happens to also
/// look like `-c` but belongs to the wrapped command would still be found
/// here; accepted because this function only ever produces a *floor*
/// (never an early-return Allow, per `crate::gate`'s wrapper-layer docs), so
/// a mismatch can only cost an extra recursion or an over-cautious Ask.
#[must_use]
pub(crate) fn chain_script_slots(stage: &[NormalizedWord]) -> Vec<ScriptSlot> {
    let mut slots = Vec::new();
    let mut rest = stage;
    while let Step::Wrapper(hop) = step(rest, &[]) {
        for value in hop.wrapper.shell_script_values(hop.tail) {
            slots.push(match value {
                ScriptValue::Text(script) => ScriptSlot::Resolved(script.to_string()),
                ScriptValue::Unresolvable => ScriptSlot::Unresolvable,
            });
        }
        // Not `ScriptSlot::Unresolvable`: `script` with neither `-c` nor a
        // command starts `$SHELL` on a pty wired to its own stdin.
        if hop.wrapper.name() == "script"
            && hop.next().is_empty()
            && hop.wrapper.shell_script_values(hop.tail).is_empty()
        {
            slots.push(ScriptSlot::Resolved("sh".to_string()));
        }
        if let Some(flag) = hop.wrapper.split_string_option() {
            collect_split_string_slots(&hop, flag, &mut slots);
        }
        if let Some(exec_flag) = hop.wrapper.operands_as_shell_script_exec_flag() {
            collect_operands_shell_slot(&hop, Some(exec_flag), &mut slots);
        } else if hop.wrapper.joins_operands_as_shell_script()
            || hop
                .wrapper
                .operands_as_shell_script_switches()
                .iter()
                .any(|switch| hop.parsed.options_named(*switch).next().is_some())
        {
            collect_operands_shell_slot(&hop, None, &mut slots);
        }
        if let Some(flag) = hop.wrapper.piped_output_option() {
            collect_piped_output_slots(&hop, flag, &mut slots);
        }
        if let Some((letter, keys)) = hop.wrapper.keyed_shell_script() {
            collect_keyed_script_slots(&hop, letter, keys, &mut slots);
        }
        rest = hop.next();
    }
    socat_command_slots(stage, &mut slots);
    slots
}

/// `ssh -o ProxyCommand=CMD` / `-o 'LocalCommand CMD'` hand CMD to a shell.
/// Keys are matched case-folded, as ssh does; an unresolved value might be
/// either key.
fn collect_keyed_script_slots(
    hop: &WrapperHop<'_>,
    letter: char,
    keys: &[&str],
    slots: &mut Vec<ScriptSlot>,
) {
    for option in hop.parsed.options_named((letter, "")) {
        let value = match option.value {
            OptionValue::Glued(text) => text,
            OptionValue::Separate(word) => match word.resolution() {
                Resolution::Resolved(text) => text.as_str(),
                Resolution::Unresolvable(_) => {
                    slots.push(ScriptSlot::Unresolvable);
                    continue;
                }
            },
            OptionValue::Absent => continue,
        };
        let (key, rest) = value
            .split_once(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or((value, ""));
        if keys.contains(&fold_command_name(key).as_str()) {
            let script = rest.trim_start_matches(|c: char| c == '=' || c.is_whitespace());
            if !script.eq_ignore_ascii_case("none") {
                slots.push(ScriptSlot::Resolved(script.to_string()));
            }
        }
    }
}

/// `watch` runs its operands through `sh -c` (words joined by spaces)
/// unless `-x`/`--exec` is given, so `watch 'echo; rm -rf /'` is a shell
/// string, not a command named `echo; rm -rf /`. Any unresolved word in
/// that tail floors to Ask.
fn collect_operands_shell_slot(
    hop: &WrapperHop<'_>,
    exec_flag: Option<(char, &'static str)>,
    slots: &mut Vec<ScriptSlot>,
) {
    let operands = hop.next();
    if exec_flag.is_some_and(|flag| hop.parsed.options_named(flag).next().is_some())
        || operands.is_empty()
    {
        return;
    }
    let mut script = String::new();
    for word in operands {
        let Resolution::Resolved(text) = word.resolution() else {
            slots.push(ScriptSlot::Unresolvable);
            return;
        };
        if !script.is_empty() {
            script.push(' ');
        }
        script.push_str(text);
    }
    slots.push(ScriptSlot::Resolved(script));
}

/// `strace -o '|cmd'` / `-o '!cmd'` pipes the trace to `sh -c cmd`. The
/// remainder is recursed as a shell string; an unresolved `-o` value floors
/// to Ask because it could be such a pipe.
fn collect_piped_output_slots(
    hop: &WrapperHop<'_>,
    flag: (char, &'static str),
    slots: &mut Vec<ScriptSlot>,
) {
    for option in hop.parsed.options_named(flag) {
        match option.value {
            OptionValue::Glued(text) => slots.extend(pipe_remainder(text)),
            OptionValue::Separate(word) => match word.resolution() {
                Resolution::Resolved(text) => slots.extend(pipe_remainder(text)),
                Resolution::Unresolvable(_) => slots.push(ScriptSlot::Unresolvable),
            },
            OptionValue::Absent => {}
        }
    }
}

fn pipe_remainder(value: &str) -> Option<ScriptSlot> {
    value
        .strip_prefix(['|', '!'])
        .map(|script| ScriptSlot::Resolved(script.to_string()))
}

/// What one piece of a `socat` address operand does (issue #737).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SocatAddress {
    /// A keyword on the known non-spawning allowlist, or a bare path.
    Inert,
    /// `EXEC:`/`SYSTEM:`/`SHELL:`: spawns a program whose stdin receives
    /// the other address's bytes.
    Spawns {
        /// The command text up to the first `,` (where socat's options start).
        command: String,
        /// Everything after the keyword's `:` to the end of the whole
        /// operand: socat's own lexer nests and quotes, which this parse
        /// does not model, so the uncut text is kept for fail-closed use.
        raw: String,
    },
    /// A keyword outside the allowlist.
    Unknown,
    /// A keyword written with a quote, backslash or whitespace, which this
    /// parse does not model.
    Unparsable,
    /// The operand could not be resolved statically.
    Unresolvable,
}

impl SocatAddress {
    pub(crate) fn is_sink(&self) -> bool {
        !matches!(self, Self::Inert)
    }
}

/// Whether `name` (an [`effective_command`] name, already case-folded) is
/// `socat`, including a versioned binary such as `socat1`/`socat2`.
pub(crate) fn is_socat(name: &str) -> bool {
    strip_version_suffix(name) == "socat"
}

/// Address keywords that take no further `-` parts.
const SOCAT_INERT_KEYWORDS: &[&str] = &[
    "-",
    "NOP",
    "OPEN",
    "GOPEN",
    "CREATE",
    "FD",
    "STDIO",
    "STDIN",
    "STDOUT",
    "STDERR",
    "PIPE",
    "PTY",
    "INTERFACE",
    "READLINE",
];
/// First `-`-separated part of a connection-style address keyword
/// (`TCP4-LISTEN`, `UNIX-CONNECT`, `OPENSSL-DTLS-CLIENT`).
const SOCAT_INERT_FAMILIES: &[&str] = &[
    "TCP", "TCP4", "TCP6", "UDP", "UDP4", "UDP6", "UDPLITE", "UDPLITE4", "UDPLITE6", "SCTP",
    "SCTP4", "SCTP6", "IP", "IP4", "IP6", "UNIX", "ABSTRACT", "OPENSSL", "SOCKS4", "SOCKS4A",
    "SOCKS5", "SOCKET", "VSOCK", "DCCP", "DCCP4", "DCCP6", "POSIXMQ", "PROXY",
];
/// The `-`-separated parts that may follow a family.
const SOCAT_INERT_SUFFIXES: &[&str] = &[
    "CONNECT", "LISTEN", "L", "SENDTO", "RECV", "RECVFROM", "DATAGRAM", "CLIENT", "SERVER", "DTLS",
];

enum SocatKeyword {
    Spawning,
    Inert,
    Unlisted,
    Unparsable,
}

fn classify_socat_keyword(keyword: &str) -> SocatKeyword {
    if keyword.contains(['\'', '"', '\\']) || keyword.contains(char::is_whitespace) {
        return SocatKeyword::Unparsable;
    }
    let upper = keyword.to_ascii_uppercase();
    if matches!(upper.as_str(), "EXEC" | "SYSTEM" | "SHELL") {
        return SocatKeyword::Spawning;
    }
    let mut parts = upper.split('-');
    let family_ok = parts
        .next()
        .is_some_and(|family| SOCAT_INERT_FAMILIES.contains(&family))
        && parts.all(|part| SOCAT_INERT_SUFFIXES.contains(&part));
    if family_ok || SOCAT_INERT_KEYWORDS.contains(&upper.as_str()) {
        SocatKeyword::Inert
    } else {
        SocatKeyword::Unlisted
    }
}

/// Parses one `socat` operand into its address pieces. socat's dual
/// address `A!!B` writes to `B`, and socat2 chains with `|`, so each piece
/// is judged on its own keyword (the text before the first `:`, `,` or `|`).
/// A colon-less piece is a file path (socat's GOPEN), so it is inert unless
/// it is written with quotes, backslashes or whitespace, or is a bare
/// spawning keyword.
pub(crate) fn socat_address_pieces(word: &NormalizedWord) -> Vec<SocatAddress> {
    let Resolution::Resolved(text) = word.resolution() else {
        return vec![SocatAddress::Unresolvable];
    };
    let mut pieces = Vec::new();
    let mut half_start = 0;
    loop {
        let half_end = text[half_start..]
            .find("!!")
            .map_or(text.len(), |at| half_start + at);
        let mut segment_start = half_start;
        loop {
            let segment = &text[segment_start..half_end];
            let Some(end) = segment.find([':', ',', '|']) else {
                pieces.push(bare_socat_piece(segment));
                break;
            };
            let keyword = &segment[..end];
            if segment.as_bytes()[end] == b':' {
                match classify_socat_keyword(keyword) {
                    SocatKeyword::Spawning => {
                        let raw = &text[segment_start + end + 1..];
                        let command_end = [raw.find(','), raw.find("!!"), raw.find('|')]
                            .into_iter()
                            .flatten()
                            .min()
                            .unwrap_or(raw.len());
                        pieces.push(SocatAddress::Spawns {
                            command: raw[..command_end].to_string(),
                            raw: raw.to_string(),
                        });
                    }
                    SocatKeyword::Inert => pieces.push(SocatAddress::Inert),
                    SocatKeyword::Unlisted => pieces.push(SocatAddress::Unknown),
                    SocatKeyword::Unparsable => pieces.push(SocatAddress::Unparsable),
                }
            } else {
                pieces.push(bare_socat_piece(keyword));
            }
            match segment.find('|') {
                Some(bar) => segment_start += bar + 1,
                None => break,
            }
        }
        if half_end == text.len() {
            return pieces;
        }
        half_start = half_end + 2;
    }
}

fn bare_socat_piece(text: &str) -> SocatAddress {
    if text.contains(['\'', '"', '\\']) || text.contains(char::is_whitespace) {
        return SocatAddress::Unknown;
    }
    if matches!(
        text.to_ascii_uppercase().as_str(),
        "EXEC" | "SYSTEM" | "SHELL"
    ) {
        return SocatAddress::Unknown;
    }
    SocatAddress::Inert
}

/// The shell-string slots of a `socat` stage: the command text of each
/// spawning address, both cut at the first `,` and uncut, and an unresolved
/// operand (it could be `EXEC:...`). A command containing characters socat's
/// own lexer treats specially, or a keyword this parse cannot read, floors to
/// Ask.
fn socat_command_slots(stage: &[NormalizedWord], slots: &mut Vec<ScriptSlot>) {
    let Some((name, args)) = effective_command(stage) else {
        return;
    };
    if !is_socat(&name) {
        return;
    }
    for word in args {
        for piece in socat_address_pieces(word) {
            match piece {
                SocatAddress::Spawns { command, raw } => {
                    if raw.contains(['\'', '"', '\\', '[', ']', '{', '}', '(', ')']) {
                        slots.push(ScriptSlot::Unresolvable);
                    }
                    if raw != command {
                        slots.push(ScriptSlot::Resolved(raw));
                    }
                    slots.push(ScriptSlot::Resolved(command));
                }
                SocatAddress::Unparsable | SocatAddress::Unresolvable => {
                    slots.push(ScriptSlot::Unresolvable);
                }
                SocatAddress::Inert | SocatAddress::Unknown => {}
            }
        }
    }
}

/// Whether `stage`'s wrapper-unwrap chain passes through `su` with a
/// positional "username" slot such that the username *and everything after
/// it*, reinterpreted as their own command line, fully matches one of
/// `rules`' command rules — name, required flags/tokens, and targets alike
/// (issue #54 follow-up — see below for why name-only matching is wrong).
///
/// `su [options] [-] [user [args...]]` is shape-ambiguous: `su rm -rf /`
/// can't be told apart from "su into a user literally named `rm`, with no
/// command" by structure alone, and `crate::gate`'s rule 10 already floors
/// that ambiguity to at least `escalation_floor` (default `Ask`) because
/// `su` escalates privileges. But when the username slot and its trailing
/// arguments, read as a command line, *fully* match a real blocklist rule —
/// not just its command name — the coincidence is worth treating as that
/// rule's own decision (typically `deny`) rather than only the generic
/// floor: `su rm -rf /` reads at least as suspicious as `rm -rf /` itself.
///
/// Matching on name alone (an earlier version of this function) was wrong:
/// `su - git` and `su git -c 'git pull'` — routine administration on any
/// git server, since `git` is a standard system account — matched
/// `git-push-force` by name and denied with a reason describing a
/// force-push that appears nowhere in the command. Reusing
/// [`CommandRule::matches`] (the same constraint/target-checked matcher
/// [`Rules::match_command`] uses everywhere else) instead of a name-only
/// check means the shadow only fires when the reinterpreted command line
/// would itself have tripped the rule.
///
/// Only `su` gets this treatment: `sudo`/`doas`'s user argument is always
/// flag-introduced (`-u root`), so there is no bare positional slot for a
/// command name to land in by coincidence in the first place.
///
/// Walks the same wrapper-unwrap chain as [`effective_command`] so a
/// wrapped `su` (`env su rm -rf /`) is still caught, and starts at the end
/// of `su`'s option region — the token the positional skip would otherwise
/// discard unread.
#[must_use]
pub(crate) fn su_username_matches_blocklisted_command<'a>(
    stage: &[NormalizedWord],
    rules: &'a Rules,
) -> Option<&'a CommandRule> {
    let mut rest = stage;
    while let Step::Wrapper(hop) = step(rest, &[]) {
        if hop.wrapper.name() == "su" {
            let start = hop.parsed.options_end();
            return rules
                .command_rules
                .iter()
                .find(|rule| rule.matches(&hop.tail[start..]));
        }
        rest = hop.next();
    }
    None
}
// ---------------------------------------------------------------------
// Typed rule-file specs (the serde-free input of this module's
// constructors; `crate::config_loader` deserializes TOML into its own
// DTOs and hands these in: parse, don't validate)
// ---------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct RulesFileSpec {
    pub(crate) command: Vec<CommandRuleSpec>,
    pub(crate) pipeline: Vec<PipelineRuleSpec>,
    pub(crate) redirect: Vec<RedirectRuleSpec>,
    pub(crate) token: Vec<TokenRuleSpec>,
}

#[derive(Debug)]
pub(crate) struct AllowlistFileSpec {
    pub(crate) entry: Vec<CommandRuleSpec>,
}

#[derive(Debug)]
pub(crate) struct CommandRuleSpec {
    pub(crate) id: String,
    pub(crate) reason: String,
    pub(crate) decision: Option<String>,
    pub(crate) command: Option<String>,
    pub(crate) command_prefix: Option<String>,
    pub(crate) required_flags: Vec<String>,
    pub(crate) required_tokens: Vec<String>,
    pub(crate) targets: Vec<TargetSpec>,
    pub(crate) except_targets: Vec<TargetSpec>,
    pub(crate) resolve_symlinks: bool,
    pub(crate) value_flags: Vec<String>,
    pub(crate) attached_value_flags: Vec<String>,
    /// `None` when the key is absent; `Some(vec![])` (an explicit empty
    /// list) is rejected at load.
    pub(crate) target_flags: Option<Vec<String>>,
    pub(crate) deny_message: Option<String>,
}

#[derive(Debug)]
pub(crate) struct TargetSpec {
    pub(crate) exact: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) normalized: Option<String>,
    pub(crate) normalized_prefix: Option<String>,
    pub(crate) normalized_basename: Option<String>,
    pub(crate) url_host: Option<String>,
    pub(crate) strip: Option<String>,
    /// Opt-in ASCII case-folded comparison for `normalized`/
    /// `normalized_prefix` (issue #449): used by `crate::config`'s
    /// generated self-protection rules AND `rules/blocklist.toml`'s own
    /// static `~/.config/shguard`-literal self-protection rules, on a
    /// case-insensitive filesystem (macOS APFS by default), where a
    /// re-cased spelling of the config path resolves to the exact same
    /// on-disk file. Not documented as ordinary rule-authoring syntax in
    /// the README — a rule author reaching for this should know their own
    /// target path lives on a case-insensitive volume.
    pub(crate) case_insensitive: bool,
}

#[derive(Debug)]
pub(crate) struct PipelineRuleSpec {
    pub(crate) id: String,
    pub(crate) reason: String,
    pub(crate) decision: Option<String>,
    pub(crate) sources: Vec<String>,
    pub(crate) sinks: Vec<String>,
    pub(crate) sink_required_flags: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct RedirectRuleSpec {
    pub(crate) id: String,
    pub(crate) reason: String,
    pub(crate) decision: Option<String>,
    pub(crate) targets: Vec<TargetSpec>,
}

/// Issue #426: a rule matching a literal substring against every
/// assignment name and resolved argv word of a simple command, independent
/// of which command is being run — `AWS_SECRET_ACCESS_KEY=...` is
/// credential-shaped whether it prefixes `ls` or stands alone.
#[derive(Debug)]
pub(crate) struct TokenRuleSpec {
    pub(crate) id: String,
    pub(crate) reason: String,
    pub(crate) decision: Option<String>,
    pub(crate) patterns: Vec<String>,
    pub(crate) deny_message: Option<String>,
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
        None => Ok(Decision::Ask),
        Some(raw) => parse_ask_or_deny("escalation_floor", "escalation_floor", raw),
    }
}

/// Maps `"ask"` to `Decision::Ask` and `"deny"` to `Decision::Block`; any
/// other value (notably `"allow"`) is a load-time [`RulesError`] under
/// `config_key`, worded as `{field} must be "ask" or "deny"`. The one copy of
/// the rule shared by [`parse_escalation_floor`] and
/// [`parse_ask_outcome_value`], which differ only in the error id and field
/// name.
fn parse_ask_or_deny(config_key: &str, field: &str, raw: &str) -> Result<Decision, RulesError> {
    match raw {
        "ask" => Ok(Decision::Ask),
        "deny" => Ok(Decision::Block),
        other => Err(RulesError::invalid(
            config_key,
            format!("{field} must be \"ask\" or \"deny\", got {other:?}"),
        )),
    }
}

/// A single `"ask"`/`"deny"` slot shared by every `ask_outcome` shape
/// (issues #467/#469): the top-level bare-string form, and each per-mode
/// table key. `"allow"` is rejected the same way [`parse_escalation_floor`]
/// rejects it for `escalation_floor`: there is no config mechanism that
/// turns a genuine `Ask` into a silent `Allow`.
fn parse_ask_outcome_value(key: &str, raw: &str) -> Result<Decision, RulesError> {
    parse_ask_or_deny("ask_outcome", key, raw)
}

/// A per-mode table key: absent keeps the built-in default `Decision::Ask`
/// (issue #469's "any unset table key keeps the built-in default \"ask\""),
/// present goes through [`parse_ask_outcome_value`]. `key` is the table
/// key's own name (e.g. `"ask_outcome.auto"`), threaded through so a
/// rejected value's error names which slot it came from rather than the
/// generic top-level `"ask_outcome"`.
fn parse_ask_outcome_slot(key: &str, raw: Option<&str>) -> Result<Decision, RulesError> {
    match raw {
        None => Ok(Decision::Ask),
        Some(raw) => parse_ask_outcome_value(key, raw),
    }
}

/// The resolved `ask_outcome` user-config key (issues #467/#469): either
/// the bare-string form's single [`Decision`] (`Global`), applied to every
/// terminal `Ask` unconditionally regardless of `permission_mode`/
/// `agent_id` — this is NOT the same as a `PerMode` table with every slot
/// set to the same value, since a `PerMode` table still floors an absent
/// or `Unknown` `permission_mode` to `Ask` (see [`AskOutcomeTable::resolve`]),
/// which would silently narrow #467's existing unconditional-floor
/// behavior for a caller with no `permission_mode` in hand at all (e.g.
/// `shguard check` before issue #469's own `--permission-mode` flag) — or
/// the per-`permission_mode` table (`PerMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AskOutcome {
    Global(Decision),
    PerMode(AskOutcomeTable),
}

impl Default for AskOutcome {
    /// The absent-key default: `Global(Decision::Ask)`, today's unmodified
    /// (pre-#467) behavior.
    fn default() -> Self {
        Self::Global(Decision::Ask)
    }
}

impl AskOutcome {
    /// Resolves the effective [`Decision`] for one hook call. `Global`
    /// ignores `permission_mode`/`agent_id` entirely, by construction (see
    /// this type's own docs); `PerMode` defers to
    /// [`AskOutcomeTable::resolve`].
    #[must_use]
    pub(crate) fn resolve(
        &self,
        permission_mode: Option<&crate::PermissionMode>,
        agent_id: Option<&str>,
    ) -> Decision {
        match self {
            Self::Global(decision) => *decision,
            Self::PerMode(table) => table.resolve(permission_mode, agent_id),
        }
    }
}

/// The `[ask_outcome]` per-mode table (issue #469): one slot per
/// `permission_mode` value the hook stdin documents, plus an optional
/// `subagent` override. Every slot defaults to `Decision::Ask` when the
/// user config's table omits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AskOutcomeTable {
    default: Decision,
    plan: Decision,
    accept_edits: Decision,
    auto: Decision,
    dont_ask: Decision,
    bypass_permissions: Decision,
    /// `None` means "inherit the mode-keyed value" (issue #469: "overrides
    /// the mode value when `agent_id` is present" implies no override at
    /// all when this key is absent) — distinct from the six mode slots
    /// above, whose own absence instead means the built-in default `Ask`.
    subagent: Option<Decision>,
}

impl AskOutcomeTable {
    /// `permission_mode: None` covers both "the hook stdin omitted the
    /// field" and "this caller has no hook stdin at all" (`shguard check`
    /// with no `--permission-mode` flag, or a pre-parse composition-root
    /// fail-closed path that never got far enough to read it) — resolved
    /// the same conservative way `Some(Unknown(_))` is: `Decision::Ask`,
    /// regardless of what the table configures for any named mode, since
    /// this binary has no basis for narrowing an autonomous-session floor
    /// to a mode it cannot identify.
    ///
    /// The `subagent` override is checked FIRST, before the mode lookup —
    /// including before the `None`/`Unknown` fallback above — because
    /// `agent_id`'s presence is itself a fact this binary understands
    /// (issue #468 already reads it off the hook stdin) independent of
    /// whether `permission_mode` also parsed to a recognized value; a
    /// configured `subagent` override is meant to apply to every subagent
    /// call, not only ones whose `permission_mode` also happens to be
    /// recognized.
    #[must_use]
    fn resolve(
        &self,
        permission_mode: Option<&crate::PermissionMode>,
        agent_id: Option<&str>,
    ) -> Decision {
        if agent_id.is_some()
            && let Some(subagent) = self.subagent
        {
            return subagent;
        }
        match permission_mode {
            None => Decision::Ask,
            Some(crate::PermissionMode::Unknown(_)) => Decision::Ask,
            Some(crate::PermissionMode::Default) => self.default,
            Some(crate::PermissionMode::Plan) => self.plan,
            Some(crate::PermissionMode::AcceptEdits) => self.accept_edits,
            Some(crate::PermissionMode::Auto) => self.auto,
            Some(crate::PermissionMode::DontAsk) => self.dont_ask,
            Some(crate::PermissionMode::BypassPermissions) => self.bypass_permissions,
        }
    }
}

/// The `[ask_outcome]` table shape (issue #469's documented keys — exact
/// stdin spellings, e.g. `default`, never `manual`). The loader
/// (`crate::config_loader`) fails config load closed on any other key, the
/// same posture it applies at the top level.
#[derive(Debug)]
pub(crate) struct AskOutcomeTableSpec {
    pub(crate) default: Option<String>,
    pub(crate) plan: Option<String>,
    pub(crate) accept_edits: Option<String>,
    pub(crate) auto: Option<String>,
    pub(crate) dont_ask: Option<String>,
    pub(crate) bypass_permissions: Option<String>,
    pub(crate) subagent: Option<String>,
}

/// The raw `ask_outcome` user-config value, already told apart by kind by
/// the loader (`crate::config_loader`): #467's bare string, #469's per-mode
/// table, or a shape the loader could not accept (a table with an unknown
/// key, or a value that is neither a string nor a table), carried as the
/// problem text so it surfaces at the same point in
/// [`UserConfig::from_spec`]'s validation order as every other
/// `ask_outcome` error.
#[derive(Debug)]
pub(crate) enum AskOutcomeSpec {
    Global(String),
    Table(AskOutcomeTableSpec),
    Invalid(String),
}

/// Parses the optional top-level `ask_outcome` user-config key (issues
/// #467/#469) into an [`AskOutcome`], defaulting to
/// `AskOutcome::Global(Decision::Ask)` — today's unmodified behavior —
/// when absent. Accepts either #467's bare string or #469's per-mode
/// table (see [`AskOutcome`]'s own docs for why these are not
/// interchangeable).
///
/// [`crate::analyze_with_policy`]/[`crate::adapter::respond`] resolve this
/// against the hook call's actual `permission_mode`/`agent_id` (see
/// [`AskOutcome::resolve`]) — most `Ask` verdicts the hook emits in
/// practice are a structural fallback (an unresolved `$VAR`/`$(...)`, an
/// interpreter heredoc/inline script, a parser-unsupported construct) that
/// an autonomous session cannot resolve, though the embedded blocklist
/// also carries 21 `decision = "ask"` rules (e.g.
/// `tar-directory-root-or-home`, the credential-shaped `[[token]]` floor)
/// that this key floors too — none of which are any more actionable to an
/// unattended session than a structural one is, and `Ask` is not even a
/// reliable control under `bypassPermissions`
/// (anthropics/claude-code#37420). Named `ask_outcome`, not `ask_floor`,
/// to avoid colliding with `crate::gate`'s existing `apply_ask_floor` (an
/// Allow-to-Ask floor) and rules 6b/6d's own "Ask floor" terminology —
/// this key floors in the opposite direction (Ask-to-Block), after gate
/// has already run, not during it.
fn parse_ask_outcome(raw: Option<AskOutcomeSpec>) -> Result<AskOutcome, RulesError> {
    match raw {
        None => Ok(AskOutcome::default()),
        Some(AskOutcomeSpec::Global(raw)) => {
            parse_ask_outcome_value("ask_outcome", &raw).map(AskOutcome::Global)
        }
        Some(AskOutcomeSpec::Table(dto)) => {
            let subagent = dto
                .subagent
                .as_deref()
                .map(|raw| parse_ask_outcome_value("ask_outcome.subagent", raw))
                .transpose()?;
            Ok(AskOutcome::PerMode(AskOutcomeTable {
                default: parse_ask_outcome_slot("ask_outcome.default", dto.default.as_deref())?,
                plan: parse_ask_outcome_slot("ask_outcome.plan", dto.plan.as_deref())?,
                accept_edits: parse_ask_outcome_slot(
                    "ask_outcome.acceptEdits",
                    dto.accept_edits.as_deref(),
                )?,
                auto: parse_ask_outcome_slot("ask_outcome.auto", dto.auto.as_deref())?,
                dont_ask: parse_ask_outcome_slot("ask_outcome.dontAsk", dto.dont_ask.as_deref())?,
                bypass_permissions: parse_ask_outcome_slot(
                    "ask_outcome.bypassPermissions",
                    dto.bypass_permissions.as_deref(),
                )?,
                subagent,
            }))
        }
        Some(AskOutcomeSpec::Invalid(problem)) => Err(RulesError::invalid("ask_outcome", problem)),
    }
}

/// Validates the optional top-level `decision_log_path` user-config key
/// (issue #108): absent means "logging disabled" (the required off-by-
/// default posture), and an empty string is rejected rather than silently
/// treated as either "disabled" or a literal empty path — the same
/// "explicit but wrong" distinction [`crate::config::Policy::load`] already
/// draws for `SHGUARD_CONFIG=""`.
fn parse_decision_log_path(raw: Option<&str>) -> Result<Option<String>, RulesError> {
    match raw {
        None => Ok(None),
        Some("") => Err(RulesError::invalid(
            "decision_log_path",
            "decision_log_path must not be empty",
        )),
        Some(path) => Ok(Some(path.to_string())),
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

/// Converts a [`CommandRuleSpec`] into a [`CommandRule`], rejecting every
/// semantically-invalid shape at this one boundary: empty id, empty
/// reason, neither/both of `command`/`command_prefix` set, an empty
/// `command`/`command_prefix` value, a `command_prefix` containing
/// whitespace, a multi-word `command` with a flag-looking word (leading
/// `-`) after the first, a malformed flag spec, an invalid
/// required_tokens entry, a target with neither/both of `exact`/`prefix`
/// set, or a malformed `value_flags` spec. A multi-word `command` (e.g.
/// `"gh repo delete"`) desugars to the first word as the command name plus
/// the remaining words prepended onto `required_tokens`.
fn convert_command_rule(dto: CommandRuleSpec) -> Result<CommandRule, RulesError> {
    convert_command_rule_with(dto, TargetGlobs::Canonical)
}

fn convert_allow_rule(dto: CommandRuleSpec) -> Result<CommandRule, RulesError> {
    convert_command_rule_with(dto, TargetGlobs::Literal)
}

// Not canonical for an allow entry: `.[a-z]*` becoming `.*` would widen
// what the entry allows.
#[derive(Clone, Copy)]
enum TargetGlobs {
    Canonical,
    Literal,
}

fn convert_command_rule_with(
    mut dto: CommandRuleSpec,
    globs: TargetGlobs,
) -> Result<CommandRule, RulesError> {
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
            // Folded after the sugar split: only the command name is
            // case-folded; `required_tokens` (subcommands) stay case-sensitive.
            CommandMatch::Exact(fold_command_name(&name))
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
            CommandMatch::Prefix(fold_command_name(&prefix))
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
        .map(|t| {
            convert_target(&dto.id, t, false).map(|target| match globs {
                TargetGlobs::Canonical => target.with_canonical_globs(),
                TargetGlobs::Literal => target,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let resolve_symlinks = dto.resolve_symlinks;
    if resolve_symlinks
        && (dto.except_targets.is_empty()
            || dto.except_targets.iter().any(|t| t.url_host.is_some()))
    {
        return Err(RulesError::invalid(
            &dto.id,
            "resolve_symlinks has no effect without path-based `except_targets` \
             (`exact`/`prefix`; a `url_host` entry can never match a canonical filesystem path)",
        ));
    }
    if resolve_symlinks
        && dto
            .except_targets
            .iter()
            .filter_map(|t| t.exact.as_deref().or(t.prefix.as_deref()))
            .any(|entry| !entry.starts_with('/'))
    {
        return Err(RulesError::invalid(
            &dto.id,
            "resolve_symlinks matches the canonical (absolute) spelling of each candidate, so \
             every `exact`/`prefix` entry in `except_targets` must start with `/`; a relative \
             or `~` entry could never match",
        ));
    }
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

    let attached_value_flags = dto
        .attached_value_flags
        .iter()
        .map(|spec| {
            parse_attached_value_flag(spec).map_err(|problem| RulesError::invalid(&dto.id, problem))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // A letter declared in both lists is contradictory: value_flags says
    // "this flag's value is a separated/attached-by-'=' argument, exclude
    // it from candidacy", attached_value_flags says "this flag's value is
    // glued with no separator, include it as a candidate" — opposite
    // effects on the same flag can never both be the rule author's intent.
    if let Some(flag) = attached_value_flags
        .iter()
        .find(|&&flag| value_flags.contains(&ValueFlag::Short(flag)))
    {
        return Err(RulesError::invalid(
            &dto.id,
            format!(
                "'{flag}' is declared in both value_flags and attached_value_flags — \
                 these have opposite candidacy effects for the same flag, pick one"
            ),
        ));
    }

    // attached_value_flags only ever feeds value_flag_free_candidates
    // (module docs), which CommandRule::matches only reaches from its
    // `targets`-empty, `except_targets`-non-empty branch — unlike
    // value_flags, it never touches value_flag_consumed's required_tokens
    // floor. So its dead-configuration check is narrower than
    // value_flags's: declaring it is only ever live when `targets` is
    // empty and `except_targets` is non-empty, regardless of
    // required_flags/required_tokens.
    if !attached_value_flags.is_empty() && !targets.is_empty() {
        return Err(RulesError::invalid(
            &dto.id,
            "attached_value_flags has no effect when `targets` is non-empty",
        ));
    }
    if !attached_value_flags.is_empty() && except_targets.is_empty() {
        return Err(RulesError::invalid(
            &dto.id,
            "attached_value_flags has no effect without `except_targets`",
        ));
    }

    // target_flags (issue #581) replaces the candidate walk wholesale: the
    // except_targets candidates and (issue #622) the tokens `targets` is
    // matched against. With neither list it would silently do nothing. It
    // also conflicts with attached_value_flags (whose glued short values it
    // already covers by listing the short flag itself).
    let target_flags = match dto.target_flags.as_deref() {
        None => Vec::new(),
        Some([]) => {
            return Err(RulesError::invalid(
                &dto.id,
                "target_flags must not be an empty list (omit the key to disable it)",
            ));
        }
        Some(specs) => specs
            .iter()
            .map(|spec| {
                parse_target_flag(spec).map_err(|problem| RulesError::invalid(&dto.id, problem))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    if !target_flags.is_empty() {
        if targets.is_empty() && except_targets.is_empty() {
            return Err(RulesError::invalid(
                &dto.id,
                "target_flags has no effect without `targets` or `except_targets`",
            ));
        }
        // A flag value arrives already split from its `--flag=` prefix, so
        // a `strip` target could never see the prefix it strips.
        if targets.iter().any(TargetMatcher::has_strip) {
            return Err(RulesError::invalid(
                &dto.id,
                "target_flags cannot be combined with a `strip` target: the flag values it \
                 selects never carry the prefix",
            ));
        }
        if !attached_value_flags.is_empty() {
            return Err(RulesError::invalid(
                &dto.id,
                "target_flags and attached_value_flags cannot be combined: list the short flag \
                 in target_flags, which already recognises its glued value",
            ));
        }
        // value_flags excludes a flag's value from candidacy while
        // target_flags selects it as the only candidate: opposite effects on
        // the same flag, so a flag in both is dead, contradictory config.
        if let Some(flag) = target_flags.iter().find(|f| value_flags.contains(f)) {
            let spelling = match flag {
                ValueFlag::Short(c) => format!("-{c}"),
                ValueFlag::Long(name) => format!("--{name}"),
            };
            return Err(RulesError::invalid(
                &dto.id,
                format!(
                    "{spelling} is listed in both target_flags and value_flags: target_flags \
                     selects the flag's value as a candidate, value_flags excludes it, pick one"
                ),
            ));
        }
    }

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
        && target_flags.is_empty()
        && let Some(unexcepted) = required_tokens.iter().find(|t| {
            candidate_has_unresolved_ascent(t) || !except_targets.iter().any(|e| e.matches(t))
        })
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

    // deny_message (issue #99): rejected empty the same way `reason` is —
    // an empty string is never a meaningful value here and almost
    // certainly a rule author's mistake. Whether this rule is even
    // allowed to carry a deny_message (deny/ask rules may; an allow-side
    // rule/allowlist entry may not, since it never produces a non-Allow
    // verdict for the message to attach to) is the CALLER's job — this
    // function converts a raw TOML entry for every caller uniformly, and
    // has no way to know which array or file the entry came from.
    let deny_message = match dto.deny_message {
        Some(message) if message.trim().is_empty() => {
            return Err(RulesError::invalid(
                &dto.id,
                "deny_message must not be empty",
            ));
        }
        Some(message) => Some(DenyMessage::new(message)),
        None => None,
    };

    let long_abbrev = matches!(&command, CommandMatch::Exact(name) if name == "git");
    Ok(CommandRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        decision,
        command,
        required_flags,
        required_tokens,
        targets,
        except_targets,
        resolve_symlinks,
        value_flags,
        attached_value_flags,
        target_flags,
        deny_message,
        long_abbrev,
    })
}

/// `resolve_symlinks` (issue #583) fails closed by leaving the exception
/// unapplied, which on an allow-side entry would GRANT the allow instead of
/// withholding it, so it is rejected there.
fn reject_resolve_symlinks_on_allow(entry: &CommandRule) -> Result<(), RulesError> {
    if entry.resolve_symlinks {
        return Err(RulesError::invalid(
            entry.id.as_str(),
            "resolve_symlinks is not supported on an allow-side entry: its fail-closed \
             direction (exception not applied) would grant the allow",
        ));
    }
    Ok(())
}

/// Parses one `target_flags` TOML entry (issue #581): the flag exactly as
/// written on the command line, WITH its leading dashes (unlike
/// `value_flags`), because the key names flags whose values to check, not
/// flags to skip. `-f` (one ASCII letter) is a short flag; `--name`
/// (ASCII alphanumeric/hyphen, longer than one character) is a long flag.
fn parse_target_flag(spec: &str) -> Result<ValueFlag, String> {
    let invalid = || {
        format!(
            "invalid target_flags spec {spec:?}: expected a flag with its leading dashes, \
             either a single-letter short flag (\"-f\") or a long flag (\"--body-file\")"
        )
    };
    if let Some(name) = spec.strip_prefix("--") {
        if name.chars().count() < 2 {
            return Err(invalid());
        }
        return ValueFlag::parse(name).map_err(|_| invalid());
    }
    match spec.strip_prefix('-') {
        Some(letter) if letter.chars().count() == 1 => {
            ValueFlag::parse(letter).map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}

/// Parses one `attached_value_flags` TOML entry: a single ASCII letter
/// naming a short flag known to take a glued attached value with no `=`
/// separator (`"x"` for curl's `-x`). No leading `-`, matching
/// `value_flags`' own spec convention. Long-option names are rejected —
/// GNU long flags already have a recognised `--name=value` attached form
/// via [`ValueFlag::attached_value_token`], so a long entry here would be
/// meaningless.
fn parse_attached_value_flag(spec: &str) -> Result<char, String> {
    let mut chars = spec.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if c.is_ascii_alphabetic() => Ok(c),
        _ => Err(format!(
            "invalid attached_value_flags spec {spec:?}: expected a single ASCII letter (short \
             flag) with no leading '-' — long flags already have a recognised `--name=value` \
             attached form and don't need this field"
        )),
    }
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
    dto: TargetSpec,
    is_except_target: bool,
) -> Result<TargetMatcher, RulesError> {
    let set_count = usize::from(dto.exact.is_some())
        + usize::from(dto.prefix.is_some())
        + usize::from(dto.normalized.is_some())
        + usize::from(dto.normalized_prefix.is_some())
        + usize::from(dto.normalized_basename.is_some())
        + usize::from(dto.url_host.is_some());
    if set_count != 1 {
        return Err(RulesError::invalid(
            rule_id,
            "target requires exactly one of `exact`/`prefix`/`normalized`/`normalized_prefix`/\
             `normalized_basename`/`url_host`",
        ));
    }
    if is_except_target
        && (dto.normalized.is_some()
            || dto.normalized_prefix.is_some()
            || dto.normalized_basename.is_some())
    {
        return Err(RulesError::invalid(
            rule_id,
            "except_targets entries must be `exact`/`prefix` (literal); `normalized`/\
             `normalized_prefix`/`normalized_basename` would silently widen an allow by \
             normalizing the carve-out, which must always be an explicit, deliberate choice",
        ));
    }
    if dto.strip.is_some()
        && dto.normalized.is_none()
        && dto.normalized_prefix.is_none()
        && dto.normalized_basename.is_none()
    {
        return Err(RulesError::invalid(
            rule_id,
            "target's `strip` is only valid alongside `normalized`/`normalized_prefix`/\
             `normalized_basename`",
        ));
    }
    if dto.strip.as_deref().is_some_and(str::is_empty) {
        return Err(RulesError::invalid(
            rule_id,
            "target's `strip` must not be empty",
        ));
    }
    if dto.case_insensitive && dto.normalized.is_none() && dto.normalized_prefix.is_none() {
        return Err(RulesError::invalid(
            rule_id,
            "target's `case_insensitive` is only valid alongside `normalized`/\
             `normalized_prefix`",
        ));
    }

    // `set_count == 1` above guarantees exactly one of these six is
    // `Some` — the wildcard arm is unreachable, not a fallback.
    match (
        dto.exact,
        dto.prefix,
        dto.normalized,
        dto.normalized_prefix,
        dto.normalized_basename,
        dto.url_host,
    ) {
        (Some(exact), None, None, None, None, None) => {
            if exact.trim().is_empty() {
                return Err(RulesError::invalid(
                    rule_id,
                    "target's `exact` must not be empty",
                ));
            }
            Ok(TargetMatcher::Exact(exact))
        }
        (None, Some(prefix), None, None, None, None) => {
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
        (None, None, Some(normalized), None, None, None) => {
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
                case_insensitive: dto.case_insensitive,
            })
        }
        (None, None, None, Some(normalized_prefix), None, None) => {
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
            // `canon` is deliberately left in its original case here — it
            // is read by other consumers besides `Self::matches`
            // (`Self::unknown_cwd_plausible`, `Self::ascent_descent_plausible`)
            // that also honor `case_insensitive` themselves, but do so at
            // THEIR own comparison sites, not by relying on `canon` having
            // been folded ahead of time. Pre-folding `canon` once here
            // instead would apply the fold unconditionally, even to a
            // caller that (today, none do) wanted the untouched
            // author-cased value.
            Ok(TargetMatcher::NormalizedPrefix {
                strip: dto.strip,
                canon,
                case_insensitive: dto.case_insensitive,
            })
        }
        (None, None, None, None, Some(base), None) => {
            if base.trim().is_empty() {
                return Err(RulesError::invalid(
                    rule_id,
                    "target's `normalized_basename` must not be empty",
                ));
            }
            if base.contains('/') {
                return Err(RulesError::invalid(
                    rule_id,
                    format!(
                        "target's `normalized_basename` {base:?} contains '/' — it must be a \
                         bare filename, matched against a token's own trailing path component \
                         regardless of what directory precedes it, not a path of its own"
                    ),
                ));
            }
            if base == "." || base == ".." {
                return Err(RulesError::invalid(
                    rule_id,
                    format!(
                        "target's `normalized_basename` {base:?} is a directory-navigation \
                         component, not a filename — it can never be a real file's trailing \
                         path component"
                    ),
                ));
            }
            Ok(TargetMatcher::NormalizedBasename {
                strip: dto.strip,
                base,
            })
        }
        (None, None, None, None, None, Some(url_host)) => {
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
        | PathForm::NamedUserHomeSub(_)
        | PathForm::NamedUserHomeEscapes(_)
        | PathForm::DirStack(_)
        | PathForm::DirStackEscapesEmpty => true,
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

fn convert_pipeline_rule(dto: PipelineRuleSpec) -> Result<PipelineRule, RulesError> {
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

    let sink_required_flags = dto
        .sink_required_flags
        .iter()
        .map(|spec| {
            FlagMatcher::parse(spec).map_err(|problem| RulesError::invalid(&dto.id, problem))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PipelineRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        decision,
        sources: dto.sources.iter().map(|s| fold_command_name(s)).collect(),
        sinks: dto.sinks.iter().map(|s| fold_command_name(s)).collect(),
        sink_required_flags,
    })
}

fn convert_redirect_rule(dto: RedirectRuleSpec) -> Result<RedirectRule, RulesError> {
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
        .map(|t| convert_target(&dto.id, t, false).map(TargetMatcher::with_canonical_globs))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RedirectRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        decision,
        targets,
    })
}

fn convert_token_rule(dto: TokenRuleSpec) -> Result<TokenRule, RulesError> {
    if dto.id.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "id must not be empty"));
    }
    if dto.reason.trim().is_empty() {
        return Err(RulesError::invalid(&dto.id, "reason must not be empty"));
    }
    if dto.patterns.is_empty() {
        return Err(RulesError::invalid(
            &dto.id,
            "token rule requires at least one pattern",
        ));
    }
    if dto.patterns.iter().any(|p| p.is_empty()) {
        return Err(RulesError::invalid(
            &dto.id,
            "token rule patterns must not be empty",
        ));
    }
    // `crate::gate::word_literal_skeleton` uses a NUL byte as an
    // expansion-boundary sentinel when scanning a word's literal pieces —
    // a pattern containing one could straddle that boundary and either
    // silently never match (harmless) or, if the sentinel encoding ever
    // changes, match across two unrelated pieces. Rejected outright so the
    // sentinel's own value never needs to be a rule author's concern.
    if dto.patterns.iter().any(|p| p.contains('\0')) {
        return Err(RulesError::invalid(
            &dto.id,
            "token rule patterns must not contain a NUL byte",
        ));
    }

    let decision = parse_decision(&dto.id, dto.decision.as_deref())?;

    let deny_message = match dto.deny_message {
        Some(message) if message.trim().is_empty() => {
            return Err(RulesError::invalid(
                &dto.id,
                "deny_message must not be empty",
            ));
        }
        Some(message) => Some(DenyMessage::new(message)),
        None => None,
    };

    Ok(TokenRule {
        id: RuleId::new(dto.id),
        reason: Reason::new(dto.reason),
        decision,
        patterns: dto.patterns,
        deny_message,
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

    fn glob_plausible(&self, target: &str) -> bool {
        self.targets.iter().any(|t| t.glob_plausible(target))
    }

    /// Issue #341: true when `target` (a redirect's resolved target word)
    /// is a directory-stack tilde shorthand (`~+`/`~-`/`~N`/`~+N`/`~-N`,
    /// [`PathForm::DirStack`]) or a `..` step above one
    /// ([`PathForm::DirStackEscapesEmpty`]) that could plausibly occupy one
    /// of this rule's own targets ([`TargetMatcher::dirstack_plausible`]) —
    /// the same gap [`CommandRule::matches_dirstack_tilde_floor`] closes for
    /// argv-based targets (`rm -rf ~+`), but for shell redirect syntax
    /// (`> ...`, `>> ...`). Read-only probe, never itself a match (see
    /// `crate::gate::scan_redirect_dirstack_tilde_floor`).
    #[must_use]
    fn dirstack_tilde_plausible(&self, target: &str) -> bool {
        self.targets.iter().any(|t| t.dirstack_plausible(target))
    }
}

/// Issue #426: a rule matching a literal, case-sensitive substring against
/// every assignment name (`NAME=`) and resolved argv word of a simple
/// command — command-agnostic, unlike [`CommandRule`], since a
/// credential-shaped token (`AWS_SECRET_ACCESS_KEY=`) is exactly as
/// sensitive whether it prefixes `ls`, `curl`, or nothing at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenRule {
    id: RuleId,
    reason: Reason,
    decision: Decision,
    patterns: Vec<String>,
    deny_message: Option<DenyMessage>,
}

impl TokenRule {
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
    pub(crate) fn deny_message(&self) -> Option<&DenyMessage> {
        self.deny_message.as_ref()
    }

    /// True when any of this rule's patterns is a substring of any
    /// `candidates` entry — deliberately plain [`str::contains`], not a
    /// regex engine: the codebase has no `regex` dependency and every
    /// existing matcher (`TargetMatcher`, `CommandMatch`, `FlagMatcher`) is
    /// literal-exact/literal-prefix already.
    #[must_use]
    fn matches(&self, candidates: &[String]) -> bool {
        self.patterns
            .iter()
            .any(|pattern| candidates.iter().any(|c| c.contains(pattern.as_str())))
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

/// A loaded, validated rule set: [`CommandRule`]s, [`PipelineRule`]s,
/// [`RedirectRule`]s, and [`TokenRule`]s (issue #426), every id unique
/// within the set.
///
/// `ask_rules` is always empty for a [`Self::parse`]d/[`Self::embedded`]
/// set — `RulesFileSpec`/`rules/blocklist.toml` have no `[[ask]]` array of
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
    token_rules: Vec<TokenRule>,
    ask_rules: Vec<CommandRule>,
    escalation_floor: Decision,
    path_canonicalizer: PathCanonicalizer,
    home: Option<HomeContext>,
}

/// The parsed `$HOME` kept on [`Rules`] for the filesystem twin probe, plus
/// its canonical spelling, resolved at most once and only when a probe
/// actually runs (not at load: a command no fs-sensitive rule applies to
/// never pays for it).
#[derive(Debug, Clone, PartialEq, Eq)]
struct HomeContext {
    dir: HomeDir,
    canonical: std::sync::OnceLock<Result<HomeDir, ProbeError>>,
}

/// Shared scan behind every worst-decision-wins `match_*` method on
/// [`Rules`]: a Block anywhere in `rules` outranks an Ask regardless of
/// declaration order (issue #261, extended by #399/#465/#426 to
/// command/pipeline/token rules), because rules appended later by
/// `merge_user_config` (e.g. a user `[[deny]]`) must not be shadowed by an
/// earlier-declared embedded Ask rule for the same shape. Ties keep the
/// first-declared rule.
fn worst_wins<R>(
    rules: &[R],
    decision: impl Fn(&R) -> Decision,
    matches: impl Fn(&R) -> bool,
) -> Option<&R> {
    let mut ask = None;
    for rule in rules {
        if !matches(rule) {
            continue;
        }
        match decision(rule) {
            Decision::Block => return Some(rule),
            _ if ask.is_none() => ask = Some(rule),
            _ => {}
        }
    }
    ask
}

/// The invoking process's `$HOME`, parsed once at policy load into the
/// lexically normalized absolute path a `~`-anchored rule target's
/// absolute spelling would take (issue #585). Parse, don't validate: the
/// only way to get one is [`HomeDir::parse`], which rejects every shape
/// that would make the derived twin targets over-broad or meaningless
/// (empty, relative, `~`-anchored, or the filesystem root).
///
/// The root is rejected deliberately: a `/`-anchored twin of `~` would be
/// `/` itself, and every `~/x` twin would become `/x`, so a container with
/// `HOME=/` would silently turn each home-scoped rule into a root-scoped one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HomeDir {
    comps: Vec<String>,
}

/// Why [`HomeDir::parse`] refused a `$HOME` value. Rendered into the
/// stderr warning `crate::config::Policy::load` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HomeDirRejection {
    Empty,
    NotAbsolute,
    Root,
}

impl std::fmt::Display for HomeDirRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "it is empty",
            Self::NotAbsolute => "it is not an absolute path",
            Self::Root => "it resolves to the filesystem root",
        })
    }
}

impl HomeDir {
    /// Parses a raw `$HOME` value.
    ///
    /// # Errors
    ///
    /// Returns [`HomeDirRejection`] for an empty or whitespace-only value, a
    /// relative or `~`-anchored one, or one that normalizes to `/`.
    pub(crate) fn parse(raw: &str) -> Result<Self, HomeDirRejection> {
        if raw.trim().is_empty() {
            return Err(HomeDirRejection::Empty);
        }
        match lexical_normalize(raw) {
            PathForm::Abs(comps) if comps.is_empty() => Err(HomeDirRejection::Root),
            PathForm::Abs(comps) => Ok(Self { comps }),
            _ => Err(HomeDirRejection::NotAbsolute),
        }
    }

    /// The absolute twins of a `~`-anchored target (none for any other
    /// target shape).
    fn twins_of(&self, target: &TargetMatcher, fold_case: bool) -> Vec<TargetMatcher> {
        match target {
            TargetMatcher::NormalizedExact {
                strip,
                target: PathForm::Home(tail),
                case_insensitive,
            } => {
                let comps = self.comps.iter().chain(tail).cloned().collect();
                vec![TargetMatcher::NormalizedExact {
                    strip: strip.clone(),
                    target: PathForm::Abs(comps),
                    case_insensitive: *case_insensitive || fold_case,
                }]
            }
            TargetMatcher::NormalizedPrefix {
                strip,
                canon,
                case_insensitive,
            } => {
                // `canon` is `~` or `~/...` here (`canonical_render` only
                // yields the anchor followed by a `/`-led tail).
                let Some(rest) = canon.strip_prefix('~') else {
                    return Vec::new();
                };
                let home = format!("/{}", self.comps.join("/"));
                let case_insensitive = *case_insensitive || fold_case;
                if rest.is_empty() {
                    // A bare `~` prefix matches `~` and everything under
                    // it. A plain string prefix of the absolute home would
                    // also match a sibling (`/Users/mebob`), so split it
                    // into the exact home plus a `/`-bounded prefix.
                    vec![
                        TargetMatcher::NormalizedExact {
                            strip: strip.clone(),
                            target: PathForm::Abs(self.comps.clone()),
                            case_insensitive,
                        },
                        TargetMatcher::NormalizedPrefix {
                            strip: strip.clone(),
                            canon: format!("{home}/"),
                            case_insensitive,
                        },
                    ]
                } else {
                    vec![TargetMatcher::NormalizedPrefix {
                        strip: strip.clone(),
                        canon: format!("{home}{rest}"),
                        case_insensitive,
                    }]
                }
            }
            _ => Vec::new(),
        }
    }
}

/// Appends each `~`-anchored target's `$HOME`-absolute twin to `targets`
/// (skipping any twin already present).
fn push_home_twins(targets: &mut Vec<TargetMatcher>, home: &HomeDir, fold_case: bool) {
    let mut twins: Vec<TargetMatcher> = targets
        .iter()
        .flat_map(|target| home.twins_of(target, fold_case))
        .collect();
    // A bare `~` target carries no `strip` form for an attached
    // `-C~`/`--directory=~` (that spelling is left to the tilde floors,
    // because `~` after `=` may not expand). The absolute home has no such
    // ambiguity, so it inherits whichever `strip` forms the same rule
    // already declares for the root target `/`.
    let has_bare_home = targets.iter().any(|target| {
        matches!(
            target,
            TargetMatcher::NormalizedExact {
                strip: None,
                target: PathForm::Home(tail),
                ..
            } if tail.is_empty()
        )
    });
    if has_bare_home {
        for target in targets.iter() {
            if let TargetMatcher::NormalizedExact {
                strip: Some(strip),
                target: PathForm::Abs(root),
                case_insensitive,
            } = target
                && root.is_empty()
            {
                twins.push(TargetMatcher::NormalizedExact {
                    strip: Some(strip.clone()),
                    target: PathForm::Abs(home.comps.clone()),
                    case_insensitive: *case_insensitive || fold_case,
                });
            }
        }
    }
    for twin in twins {
        if !targets.contains(&twin) {
            targets.push(twin);
        }
    }
}

impl Rules {
    /// Issue #585: for every deny/ask command rule and redirect rule, adds
    /// the `$HOME`-absolute spelling of each `~`-anchored `normalized`/
    /// `normalized_prefix` target next to it, so `rm -rf /Users/me` matches
    /// whatever `rm -rf ~` does. Only ever ADDS matches to a rule that
    /// already denies or asks, so it can raise a verdict but never lower
    /// one. Deliberately never touches `except_targets` (a twin there would
    /// widen a carve-out) and has no counterpart on [`Allowlist`] (a twin
    /// there would widen an allow).
    ///
    /// The asymmetry is visible to a rule author: a `~/scratch` entry in
    /// `except_targets` excepts the `~` spelling only, so the same
    /// directory spelled `/Users/me/scratch` is still matched by the
    /// rule's (twinned) `targets` and not excepted. That fails closed;
    /// spell the absolute path in `except_targets` to carve it out too.
    ///
    /// `fold_case` ORs into each twin's own `case_insensitive` flag, for
    /// platforms whose default volume treats `/Users/Me` and `/users/me`
    /// as one directory.
    ///
    /// Also remembers `home`, so the filesystem twin probe
    /// ([`Self::fs_twin_probe`]) can expand a `~` operand and match the
    /// canonical spelling of a symlinked `$HOME`.
    #[must_use]
    pub(crate) fn with_home_twins(mut self, home: &HomeDir, fold_case: bool) -> Self {
        for rule in self.command_rules.iter_mut().chain(&mut self.ask_rules) {
            push_home_twins(&mut rule.targets, home, fold_case);
        }
        for rule in &mut self.redirect_rules {
            push_home_twins(&mut rule.targets, home, fold_case);
        }
        self.home = Some(HomeContext {
            dir: home.clone(),
            canonical: std::sync::OnceLock::new(),
        });
        self
    }

    /// One warning per `resolve_symlinks` `except_targets` entry (issue
    /// #612) whose canonical spelling differs from how it is written (on
    /// macOS `/tmp` is `/private/tmp`): candidates are matched in canonical
    /// form, so such an entry silently never applies. Entries that do not
    /// resolve (not created yet) produce no warning.
    #[must_use]
    pub(crate) fn resolve_symlinks_spelling_warnings(&self) -> Vec<String> {
        let canonicalizer = self.path_canonicalizer;
        let mut warnings = Vec::new();
        for rule in self
            .command_rules
            .iter()
            .chain(&self.ask_rules)
            .filter(|rule| rule.resolve_symlinks)
        {
            for target in &rule.except_targets {
                let (TargetMatcher::Exact(entry) | TargetMatcher::Prefix(entry)) = target else {
                    continue;
                };
                let written = match entry.trim_end_matches('/') {
                    "" => "/",
                    trimmed => trimmed,
                };
                if let Ok(resolved) = canonicalizer.canonicalize(written)
                    && resolved.path != written
                {
                    warnings.push(format!(
                        "rule {:?}: resolve_symlinks matches canonical paths, but except_targets \
                         entry {entry:?} resolves to {:?}; write that spelling or the exception \
                         will never apply",
                        rule.id.as_str(),
                        resolved.path
                    ));
                }
            }
        }
        warnings
    }

    /// Wires the symlink-resolution adapter (see [`CanonicalizeFn`]) that
    /// `resolve_symlinks` rules canonicalize their candidates through. Called
    /// once, from the composition root.
    #[must_use]
    pub(crate) fn with_path_canonicalizer(mut self, canonicalizer: PathCanonicalizer) -> Self {
        self.path_canonicalizer = canonicalizer;
        self
    }
}

/// Most distinct paths one simple command (operands, their ancestors and
/// redirect targets together) may have looked up on the filesystem; a command
/// needing more asks instead of probing a prefix of them (a skipped operand
/// would be an unchecked one).
const MAX_FS_PROBES: usize = 32;

/// Id prefix of the rules `crate::config` generates to protect shguard's own
/// config directory and decision log.
const SELF_PROTECTION_ID_PREFIX: &str = "shguard-self-protect-";

/// Whether the filesystem can change which rule a target spelling hits: a
/// `~`-anchored target (its `$HOME` may be a symlink, and so may anything
/// that points into it) or a rule that protects shguard's own files.
fn fs_sensitive(id: &RuleId, targets: &[TargetMatcher]) -> bool {
    id.as_str().starts_with(SELF_PROTECTION_ID_PREFIX)
        || targets.iter().any(|target| match target {
            TargetMatcher::NormalizedExact {
                target: PathForm::Home(_),
                ..
            } => true,
            TargetMatcher::NormalizedPrefix { canon, .. } => canon.starts_with('~'),
            _ => false,
        })
}

/// An operand split into the literal text glued before its path (`-C`,
/// `--directory=`, `of=`) and the path itself; `("", "")` for an operand
/// that carries no path.
fn split_operand(token: &str) -> (&str, &str) {
    if token.starts_with("--") {
        return token
            .split_once('=')
            .map_or(("", ""), |(flag, value)| (&token[..flag.len() + 1], value));
    }
    if token.starts_with('-') {
        let value = token.get(2..).unwrap_or("");
        return if value.starts_with(['/', '~']) {
            (&token[..2], value)
        } else {
            ("", "")
        };
    }
    if !token.starts_with(['/', '~'])
        && let Some((name, value)) = token.split_once('=')
        && value.starts_with('/')
        && name.chars().all(|c| c.is_ascii_alphabetic())
    {
        return (&token[..name.len() + 1], value);
    }
    ("", token)
}

/// One extra spelling of a command line for the filesystem twin probe: the
/// operand at one position replaced by a spelling the filesystem gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FsTwin {
    pub(crate) argv: Vec<NormalizedWord>,
    /// The operand as written.
    pub(crate) operand: String,
    /// The spelling it was replaced by.
    pub(crate) spelling: String,
    /// The spelling is the lexical `$HOME` form of the resolved path, not
    /// what the filesystem itself calls it.
    pub(crate) via_home: bool,
}

/// A spelling [`Rules::fs_twin_spellings`] found, and which kind it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FsSpelling {
    pub(crate) path: String,
    pub(crate) via_home: bool,
}

/// A path the filesystem twin probe could not check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FsProbeFailure {
    pub(crate) subject: String,
    pub(crate) why: String,
}

/// The filesystem lookups one simple command has made so far, shared by its
/// path operands and redirect targets so [`MAX_FS_PROBES`] bounds them
/// together.
#[derive(Debug, Default)]
pub(crate) struct FsProbeBudget {
    lookups: std::collections::HashMap<String, Result<ResolvedPath, ProbeError>>,
}

/// What [`Rules::fs_twin_probe`] found: spellings to match in addition to the
/// lexical one, and the paths it could not check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FsTwinProbe {
    pub(crate) twins: Vec<FsTwin>,
    pub(crate) failures: Vec<FsProbeFailure>,
}

impl HomeDir {
    fn path(&self) -> String {
        format!("/{}", self.comps.join("/"))
    }

    /// `path` moved from under `from` to under `self`, or `None` when it is
    /// not under `from`.
    fn rebase_from(&self, from: &Self, path: &str) -> Option<String> {
        let PathForm::Abs(comps) = lexical_normalize(path) else {
            return None;
        };
        let tail = comps.strip_prefix(from.comps.as_slice())?;
        Some(format!(
            "/{}",
            self.comps
                .iter()
                .map(String::as_str)
                .chain(tail.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join("/")
        ))
    }
}

impl Rules {
    /// Issue #602: the filesystem half of home and config self-protection.
    /// Rule matching is lexical, so `rm -rf link` (a symlink to `$HOME`), a
    /// payload `cwd` that is such a link, or a `$HOME` that is itself a link
    /// slip past the `~` rules. For each path operand of a command that an
    /// fs-sensitive rule applies to, this asks the filesystem port for the
    /// canonical spelling and returns the command line with that operand
    /// replaced by it (and, when `$HOME` is a symlink, by the lexical-home
    /// form of it), so the caller can match the extra spellings with the
    /// ordinary rules. It only adds spellings: the lexical one is never
    /// removed. Run it after the lexical match and skip it once that
    /// blocked.
    ///
    /// `base` is the absolute directory relative operands resolve against,
    /// when it is trustworthy. The longest existing ancestor of an operand
    /// that is a glob or does not exist yet stands in for it; with none, the
    /// lexical result stands. A loop, a permission error or any other failure
    /// is reported in [`FsTwinProbe::failures`] for the caller to Ask on. Only
    /// the operands and their ancestors are looked up, never a directory's
    /// contents.
    #[must_use]
    pub(crate) fn fs_twin_probe(
        &self,
        argv: &[NormalizedWord],
        base: Option<&str>,
        budget: &mut FsProbeBudget,
    ) -> FsTwinProbe {
        let mut probe = FsTwinProbe::default();
        let applies = self
            .command_rules
            .iter()
            .chain(&self.ask_rules)
            .any(|rule| {
                fs_sensitive(&rule.id, &rule.targets) && rule.matching_rest(argv).is_some()
            });
        if !applies {
            return probe;
        }
        let Some((_, rest)) = effective_command(argv) else {
            return probe;
        };
        let start = argv.len() - rest.len();
        for (index, word) in argv.iter().enumerate().skip(start) {
            let Resolution::Resolved(token) = word.resolution() else {
                continue;
            };
            let (prefix, value) = split_operand(token);
            let Some(full) = self.probe_path(value, base) else {
                continue;
            };
            match self.fs_twin_spellings(&full, budget) {
                Ok(found) => {
                    for found in found {
                        let mut twin = argv.to_vec();
                        twin[index] = NormalizedWord::resolved(format!("{prefix}{}", found.path));
                        probe.twins.push(FsTwin {
                            argv: twin,
                            operand: token.clone(),
                            spelling: found.path,
                            via_home: found.via_home,
                        });
                    }
                }
                Err(failure) => {
                    if !probe.failures.contains(&failure) {
                        probe.failures.push(failure);
                    }
                }
            }
        }
        probe
    }

    /// [`Self::fs_twin_probe`] for a redirect target: the extra spellings to
    /// match against the redirect rules. Draws on the same `budget` as the
    /// command's operands.
    ///
    /// # Errors
    ///
    /// Returns the [`FsProbeFailure`] when the target (or `$HOME`) could not
    /// be resolved for a reason other than not existing, or the budget ran
    /// out.
    pub(crate) fn fs_twin_redirect_spellings(
        &self,
        target: &str,
        base: Option<&str>,
        budget: &mut FsProbeBudget,
    ) -> Result<Vec<FsSpelling>, FsProbeFailure> {
        if !self
            .redirect_rules
            .iter()
            .any(|rule| fs_sensitive(&rule.id, &rule.targets))
        {
            return Ok(Vec::new());
        }
        match self.probe_path(target, base) {
            Some(full) => self.fs_twin_spellings(&full, budget),
            None => Ok(Vec::new()),
        }
    }

    /// The absolute path an operand value names, when it can be located:
    /// absolute, `~`-led under a known `$HOME`, or relative under `base`.
    /// It may carry glob characters or name a file that does not exist yet;
    /// [`Self::fs_twin_spellings`] resolves the part that does.
    fn probe_path(&self, value: &str, base: Option<&str>) -> Option<String> {
        if value.is_empty() {
            return None;
        }
        if value.starts_with('/') {
            return Some(value.to_string());
        }
        if value == "~" || value.starts_with("~/") {
            let home = self.home.as_ref()?;
            return Some(format!("{}{}", home.dir.path(), &value[1..]));
        }
        if value.starts_with('~') || value == "-" {
            return None;
        }
        base.filter(|base| base.starts_with('/'))
            .map(|base| format!("{base}/{value}"))
    }

    /// One filesystem lookup, answered from `budget` when this command
    /// already made it; a new one past [`MAX_FS_PROBES`] is refused.
    fn probe_lookup(
        &self,
        path: &str,
        budget: &mut FsProbeBudget,
    ) -> Result<Result<ResolvedPath, ProbeError>, FsProbeFailure> {
        if let Some(known) = budget.lookups.get(path) {
            return Ok(known.clone());
        }
        if budget.lookups.len() >= MAX_FS_PROBES {
            return Err(FsProbeFailure {
                subject: "the command".to_string(),
                why: format!("it has more than {MAX_FS_PROBES} path operands to resolve"),
            });
        }
        let found = self.path_canonicalizer.canonicalize(path);
        budget.lookups.insert(path.to_string(), found.clone());
        Ok(found)
    }

    /// The spellings the filesystem gives `full`: its longest glob-free
    /// ancestor that exists, resolved, with the rest of the operand (a glob,
    /// or a name not created yet) reattached. Walks up the operand's own
    /// components, one lookup per prefix, never listing a directory.
    fn fs_twin_spellings(
        &self,
        full: &str,
        budget: &mut FsProbeBudget,
    ) -> Result<Vec<FsSpelling>, FsProbeFailure> {
        let comps: Vec<&str> = full.split('/').filter(|comp| !comp.is_empty()).collect();
        let mut keep = comps
            .iter()
            .position(|comp| comp.contains(['*', '?', '[', '{']))
            .unwrap_or(comps.len());
        let resolved = loop {
            if keep == 0 {
                return Ok(Vec::new());
            }
            let head = format!("/{}", comps[..keep].join("/"));
            match self.probe_lookup(&head, budget)? {
                Ok(resolved) => break resolved,
                Err(ProbeError::NotFound) => keep -= 1,
                Err(error) => {
                    return Err(FsProbeFailure {
                        subject: head,
                        why: error.to_string(),
                    });
                }
            }
        };
        let tail = comps[keep..].join("/");
        let resolved_full = if tail.is_empty() {
            resolved.path.clone()
        } else {
            format!("{}/{tail}", resolved.path.trim_end_matches('/'))
        };
        let mut spellings = Vec::new();
        if resolved_full != full {
            spellings.push(FsSpelling {
                path: resolved_full.clone(),
                via_home: false,
            });
        }
        if let Some(home) = &self.home {
            let canonical = home.canonical.get_or_init(|| {
                let resolved = self.path_canonicalizer.canonicalize(&home.dir.path())?;
                HomeDir::parse(&resolved.path).map_err(|_| ProbeError::NotFound)
            });
            match canonical {
                Ok(canonical) => {
                    if let Some(rebased) = home.dir.rebase_from(canonical, &resolved_full)
                        && rebased != full
                        && spellings.iter().all(|known| known.path != rebased)
                    {
                        spellings.push(FsSpelling {
                            path: rebased,
                            via_home: true,
                        });
                    }
                }
                Err(ProbeError::NotFound) => {}
                Err(error) => {
                    return Err(FsProbeFailure {
                        subject: "$HOME".to_string(),
                        why: error.to_string(),
                    });
                }
            }
        }
        Ok(spellings)
    }
}

impl Rules {
    /// Builds a validated [`Rules`] set from an already-deserialized
    /// [`RulesFileSpec`] (`Rules::parse` in `crate::config_loader` is the
    /// TOML-text entry point).
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] for a semantically invalid rule (empty
    /// id/reason, an empty/contradictory matcher, a malformed flag spec),
    /// or a duplicate rule id — fail-closed, never a silently-skipped rule.
    pub(crate) fn from_spec(dto: RulesFileSpec) -> Result<Self, RulesError> {
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
        let token_rules = dto
            .token
            .into_iter()
            .map(convert_token_rule)
            .collect::<Result<Vec<_>, _>>()?;

        reject_duplicate_ids(
            command_rules
                .iter()
                .map(|r| r.id.as_str())
                .chain(pipeline_rules.iter().map(|r| r.id.as_str()))
                .chain(redirect_rules.iter().map(|r| r.id.as_str()))
                .chain(token_rules.iter().map(|r| r.id.as_str())),
        )?;

        Ok(Self {
            command_rules,
            pipeline_rules,
            redirect_rules,
            token_rules,
            ask_rules: Vec::new(),
            escalation_floor: Decision::Ask,
            path_canonicalizer: PathCanonicalizer::unavailable(),
            home: None,
        })
    }

    /// `PathCanonicalizer` never takes part in equality, so the legacy_units
    /// recorder asks this to tell a wired-up filesystem double apart.
    #[cfg(test)]
    #[allow(clippy::fn_to_numeric_cast)]
    pub(crate) fn legacy_has_default_canonicalizer(&self) -> bool {
        self.path_canonicalizer.0 as usize == PathCanonicalizer::unavailable().0 as usize
    }

    /// The embedded/user-config [`CommandRule`] declared with id `id`, if
    /// any — issue #452: lets a `src/gate.rs` structural check (one that
    /// detects the same *intent* as an existing TOML rule through a shape
    /// `required_flags`/`targets` can't express, e.g. `git push`'s `+`
    /// refspec spelling of a force push) reuse that rule's own
    /// reason/deny_message/id rather than duplicating that text as a
    /// second source of truth.
    #[must_use]
    pub(crate) fn command_rule_by_id(&self, id: &str) -> Option<&CommandRule> {
        self.command_rules
            .iter()
            .find(|rule| rule.id.as_str() == id)
    }

    /// The worst-decision [`CommandRule`] that matches `argv`, if any —
    /// Block outranks Ask regardless of declaration order (issue #399,
    /// mirroring [`Self::match_redirect_target`]'s issue #261 fix); ties
    /// keep the first-declared rule.
    #[must_use]
    pub(crate) fn match_command(&self, argv: &[NormalizedWord]) -> Option<&CommandRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.match_command_in(argv, SymlinkScope::default())
    }

    /// [`Self::match_command`] with the [`SymlinkScope`] `resolve_symlinks`
    /// rules resolve their candidates in (issues #583, #612); see
    /// [`CommandRule::matches_in`].
    #[must_use]
    pub(crate) fn match_command_in(
        &self,
        argv: &[NormalizedWord],
        scope: SymlinkScope<'_>,
    ) -> Option<&CommandRule> {
        worst_wins(&self.command_rules, CommandRule::decision, |rule| {
            rule.matches_in(argv, scope, self.path_canonicalizer)
        })
    }

    /// The worst-decision [`PipelineRule`] that matches `stages` (one
    /// normalised argv per pipeline stage, in order), if any — Block
    /// outranks Ask regardless of declaration order (issue #465, aligning
    /// with [`Self::match_command`]/[`Self::match_redirect_target`]/
    /// [`Self::match_token`]); ties keep the first-declared rule.
    #[must_use]
    pub(crate) fn match_pipeline(&self, stages: &[Vec<NormalizedWord>]) -> Option<&PipelineRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_pipeline",
            &crate::legacy_units::Call::Stages(stages),
        );
        worst_wins(&self.pipeline_rules, PipelineRule::decision, |rule| {
            rule.matches(stages)
        })
    }

    /// The worst-decision [`RedirectRule`] whose target list matches
    /// `target`, if any — Block outranks Ask regardless of declaration
    /// order (issue #261); ties keep the first-declared rule.
    #[must_use]
    pub(crate) fn match_redirect_target(&self, target: &str) -> Option<&RedirectRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_redirect_target",
            &crate::legacy_units::Call::Target(target),
        );
        worst_wins(&self.redirect_rules, RedirectRule::decision, |rule| {
            rule.matches(target)
        })
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
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_redirect_target_ascent_descent",
            &crate::legacy_units::Call::Target(target),
        );
        self.redirect_rules
            .iter()
            .find(|rule| rule.ascent_descent_plausible(target))
    }

    #[must_use]
    pub(crate) fn match_redirect_target_glob(&self, target: &str) -> Option<&RedirectRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_redirect_target_glob",
            &crate::legacy_units::Call::Target(target),
        );
        self.redirect_rules
            .iter()
            .find(|rule| rule.glob_plausible(target))
    }

    /// The first [`RedirectRule`] for which
    /// [`RedirectRule::dirstack_tilde_plausible`] holds against `target`, if
    /// any — issue #341's floor, extending #88/#133's argv-side
    /// directory-stack tilde floor to shell redirect syntax. Read-only
    /// probe, same shape as [`Self::match_redirect_target_ascent_descent`].
    #[must_use]
    pub(crate) fn match_redirect_target_dirstack_tilde(
        &self,
        target: &str,
    ) -> Option<&RedirectRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_redirect_target_dirstack_tilde",
            &crate::legacy_units::Call::Target(target),
        );
        self.redirect_rules
            .iter()
            .find(|rule| rule.dirstack_tilde_plausible(target))
    }

    /// The hint to append to `rule`'s reason when its `resolve_symlinks`
    /// exception could not be applied because a candidate under an excepted
    /// prefix did not resolve (issue #612). `None` for every other cause.
    #[must_use]
    pub(crate) fn unresolved_exception_hint(
        &self,
        rule: &CommandRule,
        argv: &[NormalizedWord],
        scope: SymlinkScope<'_>,
    ) -> Option<String> {
        rule.unresolved_excepted_path(argv, scope, self.path_canonicalizer)
            .map(|path| {
                format!(
                    "; except_targets could not be applied because {path} could not be \
                     resolved (does it exist?)"
                )
            })
    }

    /// [`Self::match_ask_in`] without a `resolve_symlinks` scope.
    #[must_use]
    pub(crate) fn match_ask(&self, argv: &[NormalizedWord]) -> Option<&CommandRule> {
        self.match_ask_in(argv, SymlinkScope::default())
    }

    /// The first user-configured `ask` [`CommandRule`] that matches `argv`,
    /// if any, resolving `resolve_symlinks` candidates in `scope` as
    /// [`Self::match_command_in`] does. Always `None` for an embedded-only
    /// [`Rules`] (see the struct docs) — only [`merge_user_config`]
    /// populates `ask_rules`.
    #[must_use]
    pub(crate) fn match_ask_in(
        &self,
        argv: &[NormalizedWord],
        scope: SymlinkScope<'_>,
    ) -> Option<&CommandRule> {
        self.ask_rules
            .iter()
            .find(|rule| rule.matches_in(argv, scope, self.path_canonicalizer))
    }

    /// The worst-decision [`TokenRule`] whose patterns match any of
    /// `candidates` (issue #426: every assignment name plus every resolved
    /// argv word), if any — Block outranks Ask regardless of declaration
    /// order, same convention as [`Self::match_command`]/
    /// [`Self::match_redirect_target`]; ties keep the first-declared rule.
    #[must_use]
    pub(crate) fn match_token(&self, candidates: &[String]) -> Option<&TokenRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_token",
            &crate::legacy_units::Call::Tokens(candidates),
        );
        worst_wins(&self.token_rules, TokenRule::decision, |rule| {
            rule.matches(candidates)
        })
    }

    /// Shared scan behind every `match_command_*` floor probe below: a
    /// user-config `[[ask]]` rule (`ask_rules`) with a matching
    /// target/flags shape is just as eligible for any of these floors as
    /// an embedded blocklist rule (`command_rules`) — both are
    /// `CommandRule`s. Scanning only `command_rules` would leave that
    /// floor's own literal-vs-obfuscated-spelling asymmetry alive for user
    /// config: the literal spelling correctly Asks via the user's rule
    /// itself, but an obfuscated respelling of the same target/flag
    /// silently Allows. Centralizing this scan, rather than each probe
    /// repeating `command_rules.iter().chain(ask_rules.iter())` inline,
    /// means a future 9th floor probe can't independently drift out of
    /// sync with the rest. Read-only: never mutates rule state, never
    /// itself constitutes a match.
    fn find_command_or_ask_rule(
        &self,
        predicate: impl Fn(&CommandRule) -> bool,
    ) -> Option<&CommandRule> {
        self.command_rules
            .iter()
            .chain(self.ask_rules.iter())
            .find(|rule| predicate(rule))
    }

    /// Byte offset in `token` where the value starts, when `token` is a
    /// listed `target_flags` flag of a rule whose command matches some hop of
    /// `scope_argv`'s wrapper chain (the walk rule matching itself uses) with
    /// its value glued on
    /// (`--body-file=v`, `-Fv`, `-F=v`; the `=` of the last form stays in the
    /// flag part). The value of such a token is a path the rule tests, so
    /// the cwd composition must reach it (issue #625). Rules of other
    /// commands are skipped: their `-F` is not this command's flag.
    #[must_use]
    pub(crate) fn target_flag_glued_value_offset(
        &self,
        scope_argv: &[NormalizedWord],
        token: &str,
    ) -> Option<usize> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "target_flag_glued_value_offset",
            &crate::legacy_units::Call::ArgvToken(scope_argv, token),
        );
        self.command_rules
            .iter()
            .chain(self.ask_rules.iter())
            .filter(|rule| rule.matching_rest_by_name(scope_argv).is_some())
            .find_map(|rule| rule.target_flag_glued_value_offset(token))
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
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command_except_target",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.find_command_or_ask_rule(|rule| rule.matches_except_target(argv))
    }

    /// [`Self::match_command_except_target`] for an argv composed against a
    /// cwd anchor ([`CommandRule::matches_except_target_composed`]).
    #[must_use]
    pub(crate) fn match_command_except_target_composed(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        self.find_command_or_ask_rule(|rule| rule.matches_except_target_composed(argv))
    }

    /// [`Self::match_command_except_target`] for a `Poisoned` cwd, without
    /// role counting or home pruning
    /// ([`CommandRule::matches_except_target_unknown_cwd`]).
    #[must_use]
    pub(crate) fn match_command_except_target_unknown_cwd(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        self.find_command_or_ask_rule(|rule| rule.matches_except_target_unknown_cwd(argv))
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
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command_except_flags",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.find_command_or_ask_rule(|rule| rule.matches_except_flags(argv))
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
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command_ascent_descent",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.find_command_or_ask_rule(|rule| rule.matches_ascent_descent_floor(argv))
    }

    #[must_use]
    pub(crate) fn match_command_glob(&self, argv: &[NormalizedWord]) -> Option<&CommandRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command_glob",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.find_command_or_ask_rule(|rule| rule.matches_glob_floor(argv))
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
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command_named_user_home",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.find_command_or_ask_rule(|rule| rule.matches_named_user_home_floor(argv))
    }

    /// The first [`CommandRule`] for which
    /// [`CommandRule::matches_dirstack_tilde_floor`] holds, if any — issue
    /// #88's directory-stack tilde floor (`src/gate.rs`). Like
    /// [`Self::match_command_named_user_home`], a read-only probe: never
    /// mutates rule state, never itself constitutes a match.
    #[must_use]
    pub(crate) fn match_command_dirstack_tilde(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command_dirstack_tilde",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.find_command_or_ask_rule(|rule| rule.matches_dirstack_tilde_floor(argv))
    }

    /// The first [`CommandRule`] for which
    /// [`CommandRule::matches_unknown_cwd_floor`] holds, if any — issue
    /// #103's poisoned-cwd floor (`src/gate.rs`). Like
    /// [`Self::match_command_dirstack_tilde`], a read-only probe: never
    /// mutates rule state, never itself constitutes a match.
    #[must_use]
    pub(crate) fn match_command_unknown_cwd(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command_unknown_cwd",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.find_command_or_ask_rule(|rule| rule.matches_unknown_cwd_floor(argv))
    }

    /// The first [`CommandRule`] for which
    /// [`CommandRule::matches_directory_equals_tilde_floor`] holds, if any
    /// — issue #115's zsh `magic_equal_subst` floor (`src/gate.rs`). Like
    /// [`Self::match_command_named_user_home`], a read-only probe: never
    /// mutates rule state, never itself constitutes a match.
    #[must_use]
    pub(crate) fn match_command_directory_equals_tilde(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command_directory_equals_tilde",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.find_command_or_ask_rule(|rule| rule.matches_directory_equals_tilde_floor(argv))
    }

    /// The first [`CommandRule`] for which
    /// [`CommandRule::matches_dirstack_equal_subst_floor`] holds, if any —
    /// issue #134's attached-dirstack-tilde `magic_equal_subst` floor
    /// (`src/gate.rs`). Like [`Self::match_command_directory_equals_tilde`],
    /// a read-only probe: never mutates rule state, never itself
    /// constitutes a match.
    #[must_use]
    pub(crate) fn match_command_dirstack_equal_subst(
        &self,
        argv: &[NormalizedWord],
    ) -> Option<&CommandRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Rules(self),
            "match_command_dirstack_equal_subst",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.find_command_or_ask_rule(|rule| rule.matches_dirstack_equal_subst_floor(argv))
    }

    /// The configured escalation floor (issues #35/#36, `crate::gate` rule
    /// 10): `Decision::Ask` unless a user config set `escalation_floor =
    /// "deny"` (see the struct docs and [`merge_user_config`]). Never
    /// `Decision::Allow` — rejected at user-config load time.
    #[must_use]
    pub(crate) fn escalation_floor(&self) -> Decision {
        self.escalation_floor
    }

    /// Issue #208: ids of every `command_rules`/`ask_rules` entry whose
    /// `except_targets` mixes a `url_host` entry with an `exact`/`prefix`
    /// entry — see [`CommandRule::mixes_url_host_with_string_except_target`]
    /// for why this is a warning-worthy trap, not a config-load error.
    #[must_use]
    pub(crate) fn ids_with_mixed_except_targets(&self) -> Vec<RuleId> {
        self.command_rules
            .iter()
            .chain(self.ask_rules.iter())
            .filter(|rule| rule.mixes_url_host_with_string_except_target())
            .map(|rule| rule.id().clone())
            .collect()
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
    /// Builds a validated [`Allowlist`] from an already-deserialized
    /// [`AllowlistFileSpec`] (`Allowlist::parse` in `crate::config_loader`
    /// is the TOML-text entry point).
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] under the same conditions as
    /// [`Rules::from_spec`] (a semantically invalid entry, or a duplicate
    /// id).
    pub(crate) fn from_spec(dto: AllowlistFileSpec) -> Result<Self, RulesError> {
        let entries = dto
            .entry
            .into_iter()
            .map(convert_allow_rule)
            .map(|rule| rule.map(CommandRule::exact_flags_only))
            .collect::<Result<Vec<_>, _>>()?;
        reject_duplicate_ids(entries.iter().map(|r| r.id.as_str()))?;

        // deny_message (issue #99) has nothing to attach to on an allowlist
        // entry: it never produces a non-Allow verdict, so a declared
        // deny_message would load successfully but silently do nothing —
        // the same "catch dead configuration at load time" posture
        // value_flags' own dead-config checks already take.
        for entry in &entries {
            if entry.deny_message.is_some() {
                return Err(RulesError::invalid(
                    entry.id.as_str(),
                    "deny_message has no effect on an allowlist entry — it never produces a \
                     non-Allow verdict for the message to attach to",
                ));
            }
            reject_resolve_symlinks_on_allow(entry)?;
        }

        Ok(Self { entries })
    }

    /// The first allowlist entry that matches `argv`, if any.
    pub(crate) fn first_match(&self, argv: &[NormalizedWord]) -> Option<&CommandRule> {
        #[cfg(test)]
        let _legacy = crate::legacy_units::rules_call(
            crate::legacy_units::Receiver::Allowlist(self),
            "allowlist_first_match",
            &crate::legacy_units::Call::Argv(argv),
        );
        self.entries.iter().find(|entry| entry.matches(argv))
    }

    /// Issue #208: ids of every allowlist entry whose `except_targets`
    /// mixes a `url_host` entry with an `exact`/`prefix` entry — an
    /// allowlist entry shares [`CommandRule::matches`], `except_targets`
    /// included ([`Self::first_match`]), so the same trap
    /// [`Rules::ids_with_mixed_except_targets`] flags for deny/ask rules
    /// applies here too.
    #[must_use]
    pub(crate) fn ids_with_mixed_except_targets(&self) -> Vec<RuleId> {
        self.entries
            .iter()
            .filter(|entry| entry.mixes_url_host_with_string_except_target())
            .map(|entry| entry.id().clone())
            .collect()
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
// User config (deny/ask/allow/pipeline) — plan.md §6 item 8
// ---------------------------------------------------------------------

/// Whether `entry`'s matcher would match any known shell interpreter,
/// `eval`/`trap`, awk variant, or transparent wrapper name (`SHELL_INTERPRETERS`/
/// `EVAL_BUILTIN`/`TRAP_BUILTIN`/`EXTRA_PIPELINE_INTERPRETERS`/`AWK_INTERPRETERS`/
/// the catalog's exec wrappers) —
/// used to reject `allow` config entries that would suppress every
/// recursion-derived `Ask` involving one of those names (`bash -c`
/// recursion, `eval`'s own recursion (issue #120), a decode-fed pipeline
/// sink, the substitution-depth-cap DoS guard's own fail-closed `Ask`), not
/// just an entry that names one exactly: `entry.command`'s own `matches` is
/// reused against every candidate name, so a `command_prefix = "b"` entry is
/// caught the same way an exact `command = "bash"` entry would be — a
/// `Prefix` matcher this permissive is exactly as dangerous as an exact
/// one.
///
/// An `Exact` entry additionally counts as dangerous if [`strip_version_suffix`]
/// reduces it to one of the same candidate names (issue #346 follow-up): the
/// gate now treats a versioned binary (`command = "bash5"`) as the
/// interpreter it normalizes to, so an allow entry naming it exactly must be
/// rejected the same way `command = "bash"` already is. Skipped for `Prefix`
/// entries — a prefix is already checked against every candidate's
/// unversioned spelling above, and stripping a version suffix from a
/// user-supplied *prefix* (which may not even end at a version boundary)
/// has no well-defined meaning.
///
/// Both comparisons case-fold `entry.command` (issue #493, folded via
/// [`fold_command_name`] rather than ASCII-only lowercasing): an allow
/// entry naming `AWK` or `BASH` is exactly as dangerous as one naming the
/// lowercase spelling once interpreter recognition itself is
/// case-insensitive, so this rejection must not be case-sensitive either —
/// otherwise `[[allow]] command = "AWK"` would sail through this check
/// while `crate::gate`'s own recognition treats it as the real interpreter.
fn matches_dangerous_allow_target(entry: &CommandRule) -> bool {
    let candidates = || {
        SHELL_INTERPRETERS
            .iter()
            .chain(EVAL_BUILTIN.iter())
            .chain(TRAP_BUILTIN.iter())
            .chain(EXTRA_PIPELINE_INTERPRETERS.iter())
            .chain(AWK_INTERPRETERS.iter())
            .copied()
            .chain(knowledge::always_wrapping_names())
    };
    let matches_ci = |name: &str| match &entry.command {
        CommandMatch::Exact(exact) => {
            let name = fold_command_name(name);
            fold_command_name(exact) == name || canonical_command_name(exact) == name
        }
        CommandMatch::Prefix(prefix) => {
            fold_command_name(name).starts_with(&fold_command_name(prefix))
        }
    };
    if candidates().any(matches_ci) {
        return true;
    }
    match &entry.command {
        CommandMatch::Exact(exact) => {
            let lower = canonical_command_name(exact);
            candidates().any(|name| strip_version_suffix(&lower) == name)
        }
        CommandMatch::Prefix(_) => false,
    }
}

#[derive(Debug)]
pub(crate) struct UserConfigSpec {
    pub(crate) deny: Vec<CommandRuleSpec>,
    pub(crate) ask: Vec<CommandRuleSpec>,
    pub(crate) allow: Vec<CommandRuleSpec>,
    pub(crate) redirect: Vec<RedirectRuleSpec>,
    pub(crate) pipeline: Vec<PipelineRuleSpec>,
    pub(crate) escalation_floor: Option<String>,
    pub(crate) decision_log_path: Option<String>,
    pub(crate) ask_outcome: Option<AskOutcomeSpec>,
}

/// A user-supplied policy config, parsed and validated but not yet merged
/// with the embedded blocklist/allowlist — see [`merge_user_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserConfig {
    deny: Vec<CommandRule>,
    ask: Vec<CommandRule>,
    allow: Vec<CommandRule>,
    redirect: Vec<RedirectRule>,
    pipeline: Vec<PipelineRule>,
    escalation_floor: Decision,
    decision_log_path: Option<String>,
    ask_outcome: AskOutcome,
}

impl UserConfig {
    /// Builds a validated [`UserConfig`] from an already-deserialized
    /// [`UserConfigSpec`] (`UserConfig::parse` in `crate::config_loader` is
    /// the TOML-text entry point; this module never sees a path or TOML).
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] for a semantically invalid entry (same
    /// checks as [`Rules::from_spec`]/[`Allowlist::from_spec`]),
    /// a duplicate id — checked across all five of `deny`/`ask`/`allow`/
    /// `redirect`/`pipeline` together, one shared id-space, so an id can't
    /// dodge the check by moving arrays — an `allow` entry matching a shell
    /// interpreter or transparent wrapper name (see
    /// [`matches_dangerous_allow_target`]) — or an invalid
    /// `escalation_floor` value (see [`parse_escalation_floor`]; only
    /// `"ask"`/`"deny"` are accepted, `"allow"` is rejected here the same
    /// as it already is for `[[allow]]` entries naming an escalation
    /// vector). A `[[redirect]]` entry's `decision` is further restricted
    /// to `"block"` only (not `"ask"`, unlike an embedded-blocklist
    /// redirect entry) — see the rejection loop below for why: the
    /// redirect check runs first-match, before any other check, so an
    /// `Ask`-decision user rule could otherwise downgrade a stricter
    /// embedded rule matched on a different redirect target of the same
    /// command. A `[[pipeline]]` entry's `decision` is restricted to
    /// `"block"`/`"ask"` by [`convert_pipeline_rule`]/[`parse_decision`]
    /// the same way an embedded-blocklist pipeline entry's is — there is
    /// no `"allow"` value to reject here, unlike the command-rule arrays.
    pub(crate) fn from_spec(dto: UserConfigSpec) -> Result<Self, RulesError> {
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
            .map(convert_allow_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let redirect = dto
            .redirect
            .into_iter()
            .map(convert_redirect_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let pipeline = dto
            .pipeline
            .into_iter()
            .map(convert_pipeline_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let escalation_floor = parse_escalation_floor(dto.escalation_floor.as_deref())?;
        let decision_log_path = parse_decision_log_path(dto.decision_log_path.as_deref())?;
        let ask_outcome = parse_ask_outcome(dto.ask_outcome)?;

        reject_duplicate_ids(
            deny.iter()
                .map(|r| r.id.as_str())
                .chain(ask.iter().map(|r| r.id.as_str()))
                .chain(allow.iter().map(|r| r.id.as_str()))
                .chain(redirect.iter().map(|r| r.id.as_str()))
                .chain(pipeline.iter().map(|r| r.id.as_str())),
        )?;

        for entry in &allow {
            if matches_dangerous_allow_target(entry) {
                return Err(RulesError::invalid(
                    entry.id.as_str(),
                    "an `allow` entry must not match a shell interpreter, `eval`, \
                     interpreter pipeline sink, awk variant, or transparent wrapper name \
                     (bash, sh, eval, python, ruby, awk, env, xargs, ...) — this would \
                     suppress every recursion-derived Ask involving that name, including \
                     the substitution-depth-cap fail-closed guard's own Ask",
                ));
            }
            // deny_message (issue #99) has nothing to attach to on an
            // `allow` entry — same reasoning as Allowlist::parse's own
            // rejection.
            if entry.deny_message.is_some() {
                return Err(RulesError::invalid(
                    entry.id.as_str(),
                    "deny_message has no effect on an `allow` entry — it never produces a \
                     non-Allow verdict for the message to attach to",
                ));
            }
            reject_resolve_symlinks_on_allow(entry)?;
        }

        // A user-config `[[redirect]]` entry must be `decision = "block"`
        // (the default) — `"ask"` is rejected here, even though
        // `convert_redirect_rule`/`parse_decision` themselves allow it for
        // the embedded blocklist, which now ships one Ask-level rule
        // (`shell-init-redirect`, pinned by
        // `embedded_redirect_rule_decision_levels` below). The downgrade
        // race that originally motivated this rejection is closed: issue
        // #261 made `Rules::match_redirect_target` and
        // `check_redirect_targets` (`src/gate.rs`) fold worst-wins across
        // rules, targets and both resolution channels, and left only a
        // Block short-circuiting the other checks. The restriction stays
        // as a conservative posture pending issue #100's own review of
        // what a user-declared Ask redirect rule should mean.
        for entry in &redirect {
            if entry.decision == Decision::Ask {
                return Err(RulesError::invalid(
                    entry.id.as_str(),
                    "a `[[redirect]]` entry must use `decision = \"block\"` (the default) — \
                     user-declared redirect rules stay Block-only pending issue #100's own \
                     review, even though the downgrade race that first motivated this \
                     rejection is closed (issue #261 made the redirect check fold worst-wins \
                     across rules, targets and resolution channels, and left only a Block \
                     short-circuiting the other checks)",
                ));
            }
        }

        Ok(Self {
            deny,
            ask,
            allow,
            redirect,
            pipeline,
            escalation_floor,
            decision_log_path,
            ask_outcome,
        })
    }

    /// The optional top-level `decision_log_path` user-config key (issue
    /// #108) — `None` unless the user's own config set it (never set by
    /// the internally-generated self-protection TOML this same parser
    /// also processes, since that text never contains this key), so
    /// [`crate::config::Policy::load`] only needs to read this off the
    /// real config-file parse, not fold it across every self-protection
    /// merge the way `escalation_floor` folds via `max`.
    #[must_use]
    pub(crate) fn decision_log_path(&self) -> Option<&str> {
        self.decision_log_path.as_deref()
    }

    /// The top-level `ask_outcome` user-config key (issues #467/#469),
    /// defaulting to [`AskOutcome::default`] when absent — see
    /// [`parse_ask_outcome`]. Read off the real config-file parse alone by
    /// [`crate::config::Policy::load`], the same way
    /// [`Self::decision_log_path`] is: the self-protection synthetic TOMLs
    /// this parser also processes never carry this key, so there is
    /// nothing to fold across multiple merges the way `escalation_floor`
    /// needs `.max()` for.
    #[must_use]
    pub(crate) fn ask_outcome(&self) -> AskOutcome {
        self.ask_outcome
    }
}

/// Merges a user config's `deny`/`ask`/`allow`/`redirect`/`pipeline` onto
/// the embedded blocklist plus allowlist, additively only, never
/// replace-by-id (unlike the deleted `Rules::with_override`/`layer`).
///
/// Every id the user config introduces, across all five arrays, must be
/// new versus `blocklist`'s command rule ids, `blocklist`'s pipeline rule
/// ids, `blocklist`'s redirect rule ids, and `allowlist`'s entry ids — one
/// shared id-space. A collision is a load-time [`RulesError::DuplicateId`],
/// fail-closed, never a silent replace.
///
/// `deny` entries land in the returned `Rules`' `command_rules`, the
/// existing Block-matching path, so `evaluate_simple_command` needs no
/// change to pick them up. `ask` entries land in `ask_rules` (see
/// [`Rules::match_ask`]). `allow` entries land in the returned
/// `Allowlist`'s entries; the only path from a config `allow` entry to a
/// permissive decision is [`apply_allowlist`], which is structurally
/// Block-immune before it even consults its entries. `redirect` entries
/// (issue #100) are appended AFTER the embedded blocklist's own
/// `redirect_rules`, never prepended, so a user-declared redirect rule
/// reports second when two rules match the same target at the same
/// decision level. Ordering no longer decides the DECISION itself:
/// [`Rules::match_redirect_target`] folds worst-wins across rules, and
/// `check_redirect_targets` (`src/gate.rs`) folds across targets and both
/// resolution channels (issue #261). `UserConfig::parse` nonetheless still
/// rejects `decision = "ask"` on a user redirect entry — a conservative
/// posture pending issue #100's own review, not the downgrade race that
/// first motivated it. `pipeline` entries
/// (issue #97) are appended AFTER the embedded blocklist's own
/// `pipeline_rules`, never prepended: [`Rules::match_pipeline`] folds
/// worst-wins across declaration order (issue #465) and keeps the
/// first-declared rule on a tie, same convention as
/// [`Rules::match_redirect_target`] above, so appending is what makes a
/// user pipeline rule report second rather than shadowing a built-in one
/// it ties with on the same sources/sinks shape. `escalation_floor` folds via `max` rather than overwriting —
/// see the inline comment at that line for why an overwrite would be
/// wrong given how `src/config.rs`'s `Policy::load` calls this function
/// more than once.
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
        .chain(
            blocklist
                .token_rules
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
        .chain(user_config.redirect.iter().map(|r| r.id.as_str()))
        .chain(user_config.pipeline.iter().map(|r| r.id.as_str()))
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
    entries.extend(
        user_config
            .allow
            .into_iter()
            .map(CommandRule::exact_flags_only),
    );

    // Append, never prepend: `match_redirect_target` folds worst-wins and
    // keeps the first-declared rule on a tie (issue #261), so appending is
    // what makes a user rule report second rather than shadowing the
    // built-in one it ties with. Combined with the Block-only restriction
    // above, a user redirect entry can only ever add protected targets.
    let mut redirect_rules = blocklist.redirect_rules;
    redirect_rules.extend(user_config.redirect);

    // Append, never prepend: `Rules::match_pipeline` folds worst-wins and
    // keeps the first-declared rule on a tie (issue #465), so appending is
    // what makes a user pipeline rule report second rather than shadowing
    // a built-in one it ties with on the same sources/sinks shape.
    let mut pipeline_rules = blocklist.pipeline_rules;
    pipeline_rules.extend(user_config.pipeline);

    Ok((
        Rules {
            command_rules,
            pipeline_rules,
            redirect_rules,
            // Issue #426: no user-config equivalent exists yet
            // (`UserConfigSpec` has no `token` field) — carried through
            // unchanged from the embedded blocklist.
            token_rules: blocklist.token_rules,
            ask_rules,
            escalation_floor,
            path_canonicalizer: blocklist.path_canonicalizer,
            home: blocklist.home,
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

    // ==== Issue #346: strip_version_suffix edge cases ====

    #[test]
    fn strip_version_suffix_strips_trailing_digits_and_dots() {
        assert_eq!(strip_version_suffix("python3.12"), "python");
        assert_eq!(strip_version_suffix("lua5.4"), "lua");
        assert_eq!(strip_version_suffix("bash5"), "bash");
    }

    #[test]
    fn strip_version_suffix_strips_abi_letters_and_debug_suffix() {
        assert_eq!(strip_version_suffix("python3.13t"), "python");
        assert_eq!(strip_version_suffix("python3.12t"), "python");
        assert_eq!(strip_version_suffix("python3.7m"), "python");
        assert_eq!(strip_version_suffix("python3.12-dbg"), "python");
        assert_eq!(strip_version_suffix("python3-dbg"), "python");
        assert_eq!(strip_version_suffix("python3.13td"), "python");
        assert_eq!(strip_version_suffix("python-debug"), "python");
        assert_eq!(strip_version_suffix("python3.12-debug"), "python");
    }

    #[test]
    fn strip_version_suffix_keeps_abi_letter_without_preceding_digit() {
        assert_eq!(strip_version_suffix("sed"), "sed");
        assert_eq!(strip_version_suffix("mkfifo"), "mkfifo");
        assert_eq!(strip_version_suffix("3d"), "3d");
        assert_eq!(strip_version_suffix("-dbg"), "-dbg");
    }

    #[test]
    fn strip_version_suffix_leaves_unversioned_name_unchanged() {
        assert_eq!(strip_version_suffix("bash"), "bash");
    }

    #[test]
    fn strip_version_suffix_never_empties_a_digit_only_name() {
        assert_eq!(strip_version_suffix("123"), "123");
    }

    #[test]
    fn strip_version_suffix_never_empties_a_dot_only_name() {
        assert_eq!(strip_version_suffix("..."), "...");
    }

    #[test]
    fn strip_version_suffix_is_char_boundary_safe_on_multibyte_names() {
        // Regression: an earlier `rfind` + byte-index-slice implementation
        // panicked here ("byte index 4 is not a char boundary").
        assert_eq!(strip_version_suffix("café"), "café");
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

    // logic-bugfixer finding: `/*`'s target entry used to be `{ exact =
    // "/*" }`, a byte-exact matcher, unlike every sibling entry in the
    // same rule — `//*`/`/./*`/`/tmp/../*`/`/*/` all lexically collapse
    // to the same `Abs(["*"])` value `/*` does and must match too,
    // exactly like `/dev/sda`'s own `//dev/sda`/`/./dev/sda`/
    // `/tmp/../dev/sda` spellings already do via `normalized_prefix`.
    #[test]
    fn rm_rf_glob_root_respelled_via_lexical_ascent_still_matches() {
        let rules = Rules::embedded().unwrap();
        for target in ["//*", "/./*", "/tmp/../*", "/*/"] {
            assert!(
                rules.match_command(&argv(&["rm", "-rf", target])).is_some(),
                "expected {target:?} to match rm-recursive-force-dangerous-target"
            );
        }
    }

    // False-positive pin: a glob under an ordinary directory must stay
    // unmatched — only a glob whose parent lexically collapses to the
    // filesystem root is in scope.
    #[test]
    fn rm_rf_glob_under_an_ordinary_directory_does_not_match() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["rm", "-rf", "/tmp/*"]))
                .is_none()
        );
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
    fn rm_recursive_without_force_root_matches() {
        // issue #453: `rm -r` (no `-f`) against `/` still deletes every
        // writable file there non-interactively, via the sibling
        // `rm-recursive-dangerous-target` rule.
        let rules = Rules::embedded().unwrap();
        assert_eq!(
            rules
                .match_command(&argv(&["rm", "--recursive", "/"]))
                .map(|rule| rule.id().as_str()),
            Some("rm-recursive-dangerous-target")
        );
    }

    // ---- FlagMatcher::Token also accepts a GNU "=value" suffix ----
    #[test]
    fn flag_matcher_token_matches_bare_flag() {
        let flag = FlagMatcher::parse("--in-place").unwrap();
        assert!(flag.satisfied(&["--in-place"], false));
    }

    #[test]
    fn flag_matcher_token_matches_equals_suffix() {
        let flag = FlagMatcher::parse("--in-place").unwrap();
        assert!(flag.satisfied(&["--in-place=.bak"], false));
    }

    #[test]
    fn flag_matcher_token_does_not_match_unrelated_suffix_without_equals() {
        let flag = FlagMatcher::parse("--in-place").unwrap();
        assert!(!flag.satisfied(&["--in-placefoo"], false));
    }

    #[test]
    fn flag_matcher_token_long_abbrev_is_opt_in_prefix_match() {
        let flag = FlagMatcher::parse("--mirror").unwrap();
        assert!(!flag.satisfied(&["--mirr"], false));
        assert!(flag.satisfied(&["--mirr"], true));
        assert!(flag.satisfied(&["--m=x"], true));
        assert!(flag.satisfied(&["--mirror"], true));
        assert!(!flag.satisfied(&["--"], true));
        assert!(!flag.satisfied(&["--=x"], true));
        assert!(!flag.satisfied(&["--mirrors"], true));
        assert!(!flag.satisfied(&["-m"], true));
        let alt = FlagMatcher::parse("f|--force").unwrap();
        assert!(alt.satisfied(&["--forc"], true));
        assert!(!alt.satisfied(&["--force-with-lease"], true));
        let valued = FlagMatcher::parse("--push-option=ci.skip").unwrap();
        assert!(valued.satisfied(&["--push-o=ci.skip"], true));
        assert!(!valued.satisfied(&["--push-o=other"], true));
        assert!(!valued.satisfied(&["--push-o"], true));
    }

    // ---- regression: --force-with-lease must not satisfy a --force token ----
    #[test]
    fn flag_matcher_token_force_with_lease_does_not_satisfy_force() {
        let flag = FlagMatcher::parse("--force").unwrap();
        assert!(!flag.satisfied(&["--force-with-lease"], false));
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
    fn glob_only_component_is_structural() {
        for glob in [
            "*",
            "**",
            "?",
            ".*",
            ".**",
            ".*?",
            ".?*",
            ".??*",
            ".[!.]*",
            ".[!.]**",
            ".[^.]*",
            "[]a]*",
            "[a-z]",
            ".[[:alnum:]]*",
            "[[:alpha:]]",
            ".[![:space:]]?",
            "[[=a=]]",
            "[[.a.]]*",
            "[[:]",
        ] {
            assert!(is_glob_only_component(glob), "{glob:?}");
        }
        for literal in [
            "",
            ".",
            "..",
            "build",
            ".config",
            "foo*",
            ".*bak",
            "[",
            ".[!.",
            "*[a",
            "[]",
            "[[:alpha:]",
            ".[[:alnum:]x",
            "[[:alpha:]]x",
        ] {
            assert!(!is_glob_only_component(literal), "{literal:?}");
        }
    }

    #[test]
    fn glob_only_deny_target_matches_every_glob_only_spelling() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "user-deny-dotglob"
            reason = "test"
            command = "rm"
            targets = [{ normalized = "~/.[!.]*" }, { normalized = "build/**" }]
        "#,
        )
        .unwrap();
        for token in ["~/.*", "~/.??*", "~/.[a-z]*", "build/*", "./build/?*"] {
            assert!(
                rules.match_command(&argv(&["rm", token])).is_some(),
                "{token:?}"
            );
        }
        for token in ["~/.config", "~/.c*", "build/x", "build/*.o"] {
            assert!(
                rules.match_command(&argv(&["rm", token])).is_none(),
                "{token:?}"
            );
        }
    }

    #[test]
    fn glob_component_matching_is_fnmatch_with_dotglob() {
        for (pattern, name) in [
            ("*", ".config"),
            ("?config", ".config"),
            (".c*", ".config"),
            ("*guard", "shguard"),
            ("[!.]hguard", "shguard"),
            ("[[:alpha:]]hguard", "shguard"),
            ("[a-z]h*", "shguard"),
            ("[]s]hguard", "shguard"),
            ("s[[:bogus:]]guard", "shguard"),
        ] {
            assert!(
                glob_component_matches(pattern.as_bytes(), name.as_bytes(), false, false),
                "{pattern:?} vs {name:?}"
            );
        }
        for (pattern, name) in [
            ("s*x", "shguard"),
            ("[!s]hguard", "shguard"),
            ("[[:digit:]]hguard", "shguard"),
            ("?", "shguard"),
            ("[a", "shguard"),
        ] {
            assert!(
                !glob_component_matches(pattern.as_bytes(), name.as_bytes(), false, false),
                "{pattern:?} vs {name:?}"
            );
        }
        assert!(glob_component_matches(b"s?a1", b"sd", true, false));
        assert!(!glob_component_matches(b"x?", b"sd", true, false));
    }

    #[test]
    fn qualifier_and_extglob_read_as_the_glob_they_narrow() {
        for (path, read_as) in [
            ("~/.config/*(/)", "~/.config/*"),
            ("~/.config/s*(N)", "~/.config/s*"),
            ("~/.config/s[a-z](/)", "~/.config/s[a-z]"),
            ("~/.config/s?(/)", "~/.config/s*"),
            ("~/.config/!(nvim)", "~/.config/*"),
            ("~/.config/x*(a)(/)", "~/.config/x*(a)"),
            ("notes(1).txt", "notes(1).txt"),
            ("f(x)", "f(x)"),
            ("(x)", "(x)"),
            ("%(refname)", "%(refname)"),
            ("~/.config/nvim/*(:h:h)", "~/.config/nvim/*(:h:h)"),
            ("*(e:rm -rf ~:)", "*(e:rm -rf ~:)"),
        ] {
            assert_eq!(superset_glob_path(path), read_as, "{path:?}");
        }
        for (path, hard) in [
            ("~/*(/)", "~/*"),
            ("~/.config/!(nvim)", "~/.config/!(nvim)"),
            ("~/.config/s?(x)", "~/.config/s?(x)"),
            ("/tmp/*(:h:h)", "/tmp/*(:h:h)"),
        ] {
            assert_eq!(strip_filter_qualifier(path), hard, "{path:?}");
        }
    }

    #[test]
    fn qualifier_groups_are_parsed_not_keyword_matched() {
        for group in [
            "/", "N", ".", "^/", "-/", "om[1]", "Lk+10", "m-1", "f:gu+w:", "u0", "%b",
        ] {
            assert_eq!(
                classify_qualifier_group(group),
                QualifierGroup::Filter,
                "{group:?}"
            );
        }
        for group in [
            ":h:h",
            ":s/nvim/shguard/",
            ":a:h:h",
            "e:rm -rf ~:",
            "e{x}",
            "+myfunc",
            ".oe:x:",
            "o+f",
            "P:-rf:",
        ] {
            assert_eq!(
                classify_qualifier_group(group),
                QualifierGroup::Expands,
                "{group:?}"
            );
        }
        for group in ["see: x", "refname", "#595", "e.g. foo", "+1", "", "x y"] {
            assert_eq!(
                classify_qualifier_group(group),
                QualifierGroup::NotQualifier,
                "{group:?}"
            );
        }
        assert!(has_expanding_glob_qualifier(
            "~/.config/n*(:s/nvim/shguard/)"
        ));
        assert!(has_expanding_glob_qualifier("x(#qe:y:)z"));
        assert!(!has_expanding_glob_qualifier("~/.config/*(/)"));
        assert!(!has_expanding_glob_qualifier("fix(rules): x (see: y)"));
        assert!(!has_expanding_glob_qualifier("x(:h)"));
        assert!(unresolved_word_may_hide_glob_qualifier(
            None,
            Some("/*(:h)")
        ));
        assert!(unresolved_word_may_hide_glob_qualifier(
            Some("*(e:"),
            Some(":)")
        ));
        assert!(!unresolved_word_may_hide_glob_qualifier(
            Some("("),
            Some(")")
        ));
        assert!(!unresolved_word_may_hide_glob_qualifier(
            None,
            Some(" (see: y)")
        ));
        assert!(!unresolved_word_may_hide_glob_qualifier(Some("*(e:"), None));
        for (comp, read_as) in [
            ("^nvim", Some("*")),
            ("@(shguard)", Some("*")),
            (".c@(onfig)", Some(".*")),
            ("x*(a)", Some("*")),
            ("f(x)", None),
            ("shguard", None),
        ] {
            assert_eq!(superset_glob_component(comp), read_as, "{comp:?}");
        }
    }

    #[test]
    fn padded_globstar_run_is_matched_without_backtracking() {
        let how = GlobMatch {
            beneath: GlobBeneath::Nothing,
            partial_last: false,
            case_insensitive: false,
        };
        let target: Vec<String> = ["a", "b", "c", "d"].map(String::from).to_vec();
        let mut stars = vec!["**".to_string(); 2000];
        stars.push("zzz".to_string());
        assert!(!comps_glob_plausible(&stars, &target, how));
        let mut alternating: Vec<String> = ["**", "*"]
            .repeat(1000)
            .into_iter()
            .map(String::from)
            .collect();
        alternating.push("zzz".to_string());
        assert!(!comps_glob_plausible(&alternating, &target, how));
        let mut reaching = vec!["**".to_string(); 2000];
        reaching.push("d".to_string());
        assert!(comps_glob_plausible(&reaching, &target, how));
    }

    #[test]
    fn case_insensitive_glob_matching_never_inverts_a_bracket() {
        for (pattern, name) in [
            ("[!A-Z]hguard", "shguard"),
            ("[!a-z]hguard", "shguard"),
            ("[A-Z]hguard", "shguard"),
            ("[[:upper:]]hguard", "shguard"),
            ("SH*", "shguard"),
            ("s*", "SHGUARD"),
        ] {
            assert!(
                glob_component_matches(pattern.as_bytes(), name.as_bytes(), false, true),
                "{pattern:?} vs {name:?}"
            );
        }
        assert!(!glob_component_matches(
            b"[0-9]hguard",
            b"shguard",
            false,
            true
        ));
        assert!(!glob_component_matches(
            b"[A-Z]hguard",
            b"shguard",
            false,
            false
        ));
    }

    #[test]
    fn glob_plausible_lines_components_up_with_the_target() {
        let exact = |target: &str| TargetMatcher::NormalizedExact {
            strip: None,
            target: canonicalize_glob_form(lexical_normalize(target)),
            case_insensitive: false,
        };
        let prefix = |canon: &str| TargetMatcher::NormalizedPrefix {
            strip: None,
            canon: canon.to_string(),
            case_insensitive: false,
        };
        let shguard = exact("~/.config/shguard");
        let home_glob = exact("~/*");
        let rel_glob = exact("*");
        let config_dir = prefix("~/.config/shguard/");
        let dev = prefix("/dev/sd");
        for (matcher, token) in [
            (&shguard, "~/.*/shguard"),
            (&shguard, "~/.c*/s*"),
            (&shguard, "~/**/shguard"),
            (&home_glob, "~/*/*"),
            (&home_glob, "~/**/*"),
            (&rel_glob, "*/*"),
            (&config_dir, "~/.config/*/config.toml"),
            (&config_dir, "~/.config/sh*"),
            (&dev, "/dev/s?a1"),
            (&shguard, "../.config/s*"),
            (&shguard, "~+/.c*/shguard"),
            (&shguard, "../x/.config/s*"),
            (&shguard, "~alice/../home/bob/.config/s*"),
            (&dev, "../dev/s*"),
        ] {
            assert!(matcher.glob_plausible(token), "{token:?}");
        }
        for (matcher, token) in [
            (&shguard, "~/.config/shguard"),
            (&shguard, "~/.config/x*"),
            (&shguard, "/Users/*/.config/shguard"),
            (&shguard, "../build/.c*"),
            (&config_dir, "../build/*"),
            (&home_glob, "../x/*"),
            (&dev, "../*/sda"),
            (&home_glob, "../*/*"),
            (&home_glob, "~/proj/*"),
            (&rel_glob, "build/*"),
            (&rel_glob, "*/node_modules"),
            (&home_glob, "~/*/node_modules"),
            (&rel_glob, "*.o"),
            (&config_dir, "~/.conf*"),
            (&dev, "/dev/x*"),
        ] {
            assert!(!matcher.glob_plausible(token), "{token:?}");
        }
    }

    #[test]
    fn glob_only_allow_target_stays_literal() {
        let allowlist = Allowlist::parse(
            r#"
            [[entry]]
            id = "allow-letter-dotfiles"
            reason = "test"
            command = "rm"
            targets = [{ normalized = "~/.[a-z]*" }]
        "#,
        )
        .unwrap();
        assert!(allowlist.first_match(&argv(&["rm", "~/.[a-z]*"])).is_some());
        for token in ["~/.*", "~/.??*", "~/.[!.]*"] {
            assert!(
                allowlist.first_match(&argv(&["rm", token])).is_none(),
                "{token:?}"
            );
        }
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
    fn ascent_descent_redirect_dirstack_tilde_descent_floors() {
        // Issue #133: RedirectRule::ascent_descent_plausible delegates to
        // the same TargetMatcher::ascent_descent_plausible the CommandRule
        // channel above does, so a dirstack-anchored descent floors via
        // shell redirect syntax too — not just argv (`dd of=...`).
        let rules = Rules::embedded().unwrap();
        let rule = rules
            .match_redirect_target_ascent_descent("~-/dev/sda")
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

    // ==== Issue #118: the escaped-past anchor's own basename reappearing
    // mid-tail (`~alice/../bob/...`, where `bob` could be the invoking
    // user's own account) is now also tried re-anchored as `~` — narrowing
    // the residual gap issue #90 documented but didn't fix (a further,
    // deeper-nested variant is partially closed by issue #364, below). ====

    #[test]
    fn ascent_descent_escaped_anchor_basename_reanchors_into_self_protect_prefix() {
        // The issue's own repro shape: `bob` sits in front of `.config` in
        // the raw tail, but shguard can't rule out `bob` IS the invoker's
        // own account, in which case a real shell collapses this right
        // back to `~/.config/shguard/config.toml`.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&[
            "cp",
            "evil.toml",
            "~alice/../bob/.config/shguard/config.toml",
        ]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-cp-tilde");
    }

    #[test]
    fn ascent_descent_escaped_anchor_basename_reanchors_into_self_protect_exact() {
        // Same re-anchoring, but against a `normalized` (exact) target
        // rather than a `normalized_prefix` one.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~alice/../bob/.config/shguard"]);
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-rm-tilde");
    }

    #[test]
    fn ascent_descent_escaped_anchor_bare_basename_with_nothing_after_does_not_floor() {
        // A lone reappearing name with nothing past it to descend into
        // can't reach a specific dangerous sub-path either way — must not
        // over-fire into a useless blanket floor on every two-component
        // ascent-then-descent tail.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["cp", "evil.toml", "~alice/../bob"]);
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
    }

    #[test]
    fn ascent_descent_escaped_anchor_basename_reanchoring_into_an_ordinary_path_does_not_floor() {
        // Parity with the pre-#118 noise guards: re-anchoring into a path
        // that isn't inside any rule's dangerous namespace must stay Allow.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["cp", "x", "~alice/../bob/shared/file"]);
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
    }

    #[test]
    fn ascent_descent_reanchoring_applies_to_a_plain_relative_ascent_too() {
        // Issue #118's widening is deliberately not restricted to the
        // named-user-escape source shapes — an unresolved `Rel` ascent's
        // own landing directory is exactly as unknown as a named user's
        // home, so `bob` reappearing mid-tail is exactly as plausibly the
        // invoker's own `$HOME` here too.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["cp", "evil.toml", "../bob/.config/shguard/config.toml"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-cp-tilde");
    }

    #[test]
    fn ascent_descent_reanchoring_applies_to_a_dirstack_anchor_too() {
        // Same widening for issue #133's dirstack-anchor shape (`~-/...`) —
        // an unknown dirstack entry's landing directory is just as unknown
        // as a plain relative ascent's or a named user's home.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["cp", "evil.toml", "~-/bob/.config/shguard/config.toml"]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-cp-tilde");
    }

    // ==== Issue #364: the same re-anchoring one component further in, when
    // the tail spells a common home CONTAINER directory (`home`, `Users`)
    // explicitly before the reappearing name. ====

    #[test]
    fn ascent_descent_home_container_basename_reanchors_into_self_protect_prefix() {
        // The issue's own repro: `home` sits in front of `bob`, so the
        // plain issue-#118 strip only removes `home`, leaving `~/bob/
        // .config/shguard/config.toml`, which matches nothing. Stripping
        // both `home` and `bob` catches it.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&[
            "cp",
            "evil.toml",
            "~alice/../home/bob/.config/shguard/config.toml",
        ]);
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-cp-tilde");
    }

    #[test]
    fn ascent_descent_home_container_basename_reanchors_into_self_protect_exact() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~alice/../home/bob/.config/shguard"]);
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-rm-tilde");
    }

    #[test]
    fn ascent_descent_home_container_basename_reanchors_for_macos_users_dir_too() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&[
            "cp",
            "evil.toml",
            "~alice/../Users/bob/.config/shguard/config.toml",
        ]);
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-cp-tilde");
    }

    #[test]
    fn ascent_descent_unlisted_container_name_still_does_not_floor() {
        // Disclosed residual: a home-container name not on the small
        // explicit list (issue #364's own accepted trade-off) still
        // isn't recognized -- must not regress to a false floor either.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&[
            "cp",
            "evil.toml",
            "~alice/../export/home/bob/.config/shguard/config.toml",
        ]);
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
    }

    #[test]
    fn ascent_descent_home_container_match_is_case_insensitive() {
        // macOS's default APFS/HFS+ volumes are case-insensitive, so
        // `users` and `Users` resolve to the exact same real directory at
        // runtime -- a case-sensitive list lookup would let this
        // respelling silently evade the widening.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&[
            "cp",
            "evil.toml",
            "~alice/../users/bob/.config/shguard/config.toml",
        ]);
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-cp-tilde");
    }

    #[test]
    fn ascent_descent_home_container_widening_applies_to_a_plain_relative_ascent_too() {
        // Same widening as issue #118's own uniformity guarantee -- not
        // restricted to the named-user-escape source shape.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["cp", "evil.toml", "../home/bob/.config/shguard/config.toml"]);
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-cp-tilde");
    }

    #[test]
    fn ascent_descent_home_container_widening_applies_to_a_dirstack_anchor_too() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["cp", "evil.toml", "~-/home/bob/.config/shguard/config.toml"]);
        let rule = rules.match_command_ascent_descent(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-cp-tilde");
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
    fn dirstack_tilde_subdir_tail_does_not_reach_the_bare_anchor_floor() {
        // A real subdirectory tail (`~-/etc/passwd`) is not the bare
        // anchor `TargetMatcher::dirstack_plausible`/`match_command_dirstack_tilde`
        // check for — it's a distinct, more specific shape that floors via
        // `ascent_descent_plausible`/`match_command_ascent_descent`
        // instead (issue #133; see the `ascent_descent_*` tests below).
        // `~+/foo` isn't matched by either mechanism: `dd`'s own targets
        // don't include a bare-relative `foo` in the first place, matching
        // how plain `../../foo` (no dirstack at all) is equally unmatched
        // by `ascent_descent_plausible` when `foo` isn't a declared
        // target — this pins the *bare-anchor* floor's own boundary, not
        // a residual #133 gap.
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
    fn dirstack_tilde_escape_to_empty_tail_floors_via_dirstack_not_ascent_descent() {
        // `~+/..` ascends one level *above* the (unknown) anchor — a
        // different, unequal location from `~+` itself, but
        // equally unknown, so it now shares `~+`'s own
        // `dirstack_plausible` floor eligibility via
        // `PathForm::DirStackEscapesEmpty` rather than falling through to
        // plain `Opaque` unmatched. It still does NOT reach
        // `ascent_descent_plausible`: that mechanism only ever sees a
        // non-empty descended-into tail (`PathForm::DirStack`'s own
        // `comps`), which an escaped-to-empty token has none of.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~+/.."]);
        assert!(rules.match_command_dirstack_tilde(&cmd).is_some());
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
    }

    // ==== Issue #133: a dirstack anchor + a real descended-into tail
    // (`~-/dev/sda`) is the same "unknown anchor, known descent" shape
    // plain ascent (`../../dev/sda`) already floors via
    // `ascent_descent_plausible` — these pin that `PathForm::DirStack`'s
    // tail now reaches that mechanism too, not just plain `Rel`/
    // `EscapesHome`/`NamedUserHomeEscapes`. ====

    #[test]
    fn dirstack_tilde_subdir_tail_matching_a_rule_target_floors_via_ascent_descent() {
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["dd", "of=~-/dev/sda"]),
            argv(&["dd", "of=~2/dev/sda"]),
            // A leading `..` that fails to cancel (nothing in `stack` yet)
            // must reach the identical tail as no leading `..` at all —
            // see `PathForm::DirStack`'s own docs for why that's sound
            // when the anchor is unknown either way.
            argv(&["dd", "of=~-/../dev/sda"]),
        ] {
            assert!(
                rules.match_command_ascent_descent(&cmd).is_some(),
                "{cmd:?}"
            );
            // Never the rule's own (Block) decision — always capped at
            // Ask via the floor, same posture as every other #78-family
            // ascent-descent case.
            assert!(rules.match_command(&cmd).is_none(), "{cmd:?}");
        }
    }

    #[test]
    fn dirstack_tilde_subdir_tail_not_matching_any_target_stays_unmatched() {
        // `/etc/passwd` isn't one of `rm-recursive-force-dangerous-target`'s
        // own targets (see `rules/blocklist.toml`) — exact parity with
        // plain ascent (`../../etc/passwd`, also unmatched for the same
        // reason): #133 closes the *mechanism* gap, not a target-coverage
        // gap the sibling plain-ascent floor doesn't already have either.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "~-/etc/passwd"]);
        assert!(rules.match_command_ascent_descent(&cmd).is_none());
        let plain = argv(&["rm", "-rf", "../../etc/passwd"]);
        assert!(rules.match_command_ascent_descent(&plain).is_none());
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

    // ==== Issue #134: a directory-stack tilde shorthand attached directly
    // after an `=`-terminated flag (`--directory=~+`, `--directory=~-`,
    // `--directory=~N`) or one `..` step above it (`--directory=~+/..`)
    // floors to Ask via Rules::match_command_dirstack_equal_subst — the
    // attached-token counterpart to issue #88/#133's unattached dirstack
    // floor, gated on magic_equal_subst the same way issue #115's bare-`~`
    // attach floor is. ====

    #[test]
    fn dirstack_equal_subst_bare_anchor_floors_but_does_not_hard_match() {
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["tar", "-x", "--directory=~+", "-f", "a.tar"]),
            argv(&["tar", "-x", "--directory=~-", "-f", "a.tar"]),
            argv(&["tar", "-x", "--directory=~5", "-f", "a.tar"]),
            argv(&["tar", "-x", "--directory=~+3", "-f", "a.tar"]),
            argv(&["tar", "-x", "--directory=~-3", "-f", "a.tar"]),
        ] {
            assert!(rules.match_command(&cmd).is_none(), "{cmd:?}");
            let rule = rules
                .match_command_dirstack_equal_subst(&cmd)
                .unwrap_or_else(|| {
                    panic!("expected {cmd:?} to floor via match_command_dirstack_equal_subst")
                });
            assert_eq!(rule.id().as_str(), "tar-extract-over-root-or-home");
        }
    }

    #[test]
    fn dirstack_equal_subst_escape_to_empty_floors() {
        // `--directory=~+/..` collapses to one level above the (unknown)
        // anchor — issue #133's PathForm::DirStackEscapesEmpty, same shape
        // as the unattached ~+/.. case, now recognized attached too.
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["tar", "-x", "--directory=~+/..", "-f", "a.tar"]),
            argv(&["tar", "-x", "--directory=~-/..", "-f", "a.tar"]),
        ] {
            assert!(
                rules.match_command_dirstack_equal_subst(&cmd).is_some(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn dirstack_equal_subst_subdir_does_not_floor() {
        // `--directory=~+/subdir` is a non-escaping descent under an
        // unknown anchor — not the bare-anchor or escape-to-empty shape
        // this floor covers; the separated-word equivalent is already
        // Allow (issue #133), so the attached form must not become
        // stricter than the form it's no more dangerous than.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "--directory=~+/subdir", "-f", "a.tar"]);
        assert!(rules.match_command_dirstack_equal_subst(&cmd).is_none());
    }

    #[test]
    fn dirstack_equal_subst_ordinary_path_does_not_floor() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "--directory=/some/path", "-f", "a.tar"]);
        assert!(rules.match_command_dirstack_equal_subst(&cmd).is_none());
    }

    #[test]
    fn dirstack_equal_subst_dash_c_short_flag_does_not_floor() {
        // magic_equal_subst only ever matches an `=`-shaped word; `-C~+`
        // has no `=`, so it's unaffected and stays out of scope.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "-C~+", "-f", "a.tar"]);
        assert!(rules.match_command(&cmd).is_none());
        assert!(rules.match_command_dirstack_equal_subst(&cmd).is_none());
    }

    #[test]
    fn dirstack_equal_subst_requires_a_corroborating_unattached_target_on_the_rule() {
        // `dd-write-device`'s ONLY targets are attach-only file/device
        // sinks (`of=/dev/*`, `of=/etc/passwd`, `of=/etc/shadow`) — no
        // bare, unattached target at all. A bare-anchor/escape-to-empty
        // dirstack token always denotes a directory, and `of=<directory>`
        // always fails EISDIR regardless of tilde expansion, so this must
        // NOT floor — same posture as the pinned
        // `gate::tests::dd_dirstack_tilde_escape_to_empty_tail_stays_allow`.
        let rules = Rules::embedded().unwrap();
        for cmd in [argv(&["dd", "of=~+"]), argv(&["dd", "of=~-/.."])] {
            assert!(
                rules.match_command_dirstack_equal_subst(&cmd).is_none(),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn dirstack_equal_subst_separated_form_floors_via_the_unattached_mechanism_instead() {
        // The space-separated equivalent (`tar -x --directory ~+ ...`) is
        // issue #88/#133's territory (match_command_dirstack_tilde), not
        // this attached-only floor — each mechanism owns its own shape,
        // with no double-floor and no gap between them.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "--directory", "~+", "-f", "a.tar"]);
        assert!(rules.match_command_dirstack_equal_subst(&cmd).is_none());
        assert!(rules.match_command_dirstack_tilde(&cmd).is_some());
    }

    #[test]
    fn dirstack_equal_subst_floor_reachable_through_env_wrapper() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["env", "tar", "-x", "--directory=~+", "-f", "a.tar"]);
        assert!(rules.match_command_dirstack_equal_subst(&cmd).is_some());
    }

    #[test]
    fn dirstack_equal_subst_requires_an_equals_terminated_strip_on_the_rule() {
        // `rm-recursive-force-dangerous-target` has no `=`-terminated
        // `strip` entry anywhere in its own targets — magic_equal_subst's
        // mechanism has nothing to do with rm's flags at all, so a rule
        // shaped like this must never floor on an arbitrary
        // `--flag=~+token`, no matter what the flag is called.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["rm", "-rf", "--totally-unrelated-flag=~+"]);
        assert!(rules.match_command_dirstack_equal_subst(&cmd).is_none());
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

    // ==== Issue #54: timeout/ionice/flock became exec wrappers,
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
        // `su` permutes its options, so `su root -c sh` has the username
        // `root`, the option `-c sh`, and no command operand left. The
        // script itself is found by `chain_script_slots`.
        let words = argv(&["su", "root", "-c", "sh"]);
        assert!(effective_command(&words).is_none());
        let words = argv(&["su", "-c", "sh", "root", "ls"]);
        let (name, rest) = effective_command(&words).unwrap();
        assert_eq!(name, "ls");
        assert!(rest.is_empty());
    }

    // ---- RFC #658 stage 2: unmodelled wrapper options ----

    #[test]
    fn unmodeled_option_keeps_the_wrapped_command_visible() {
        let words = argv(&["sudo", "--bogus", "rm", "-rf", "/"]);
        let (name, rest) = effective_command(&words).unwrap();
        assert_eq!(name, "rm");
        assert_eq!(resolved_strings(rest), vec!["-rf", "/"]);
    }

    #[test]
    fn first_unmodeled_wrapper_option_names_the_offending_hop() {
        assert!(first_unmodeled_wrapper_option(&argv(&["nice", "-n", "5", "ls"])).is_none());
        assert!(first_unmodeled_wrapper_option(&argv(&["ls", "--bogus"])).is_none());
        let finding =
            first_unmodeled_wrapper_option(&argv(&["env", "nice", "--bogus", "ls"])).unwrap();
        assert_eq!(finding.command(), "nice");
        // A non-wrapper command's own flags are never the catalog's concern.
        assert!(first_unmodeled_wrapper_option(&argv(&["make", "-Z"])).is_none());
    }

    #[test]
    fn unresolvable_word_before_the_command_stops_the_walk() {
        let mut words = argv(&["nice", "-n"]);
        words.push(NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::ParameterExpansion,
        ));
        words.extend(argv(&["ls"]));
        assert!(effective_command(&words).is_none());
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

    // ==== Issue #114: busybox became an exec wrapper ====

    #[test]
    fn mkswap_matches_through_busybox_wrapper() {
        // The issue's own reproduction: `busybox mkswap /dev/sda1` behaves
        // identically to a bare `mkswap /dev/sda1` and must match the same
        // rule.
        let rules = Rules::embedded().unwrap();
        for wrapper in ["busybox", "toybox"] {
            assert!(
                rules
                    .match_command(&argv(&[wrapper, "mkswap", "/dev/sda1"]))
                    .is_some(),
                "{wrapper}"
            );
        }
    }

    #[test]
    fn rm_rf_root_matches_through_busybox_wrapper() {
        let rules = Rules::embedded().unwrap();
        for wrapper in ["busybox", "toybox", "coreutils"] {
            assert!(
                rules
                    .match_command(&argv(&[wrapper, "rm", "-rf", "/"]))
                    .is_some(),
                "{wrapper}"
            );
        }
    }

    #[test]
    fn wrapper_chain_escalation_finds_every_vector_through_busybox() {
        // Mirrors wrapper_chain_escalation_finds_each_escalation_vector's
        // "through env" case, but through busybox — every escalation vector
        // must still floor when reached via busybox's empty option
        // grammar, not just su. (A "vector before busybox", e.g.
        // `sudo busybox rm -rf /`, would be vacuous coverage here: the
        // per-hop escalation check fires on `sudo` before
        // `busybox` is ever inspected, so that ordering can't exercise
        // busybox's exec-wrapper membership at all — this loop
        // only tests the direction that actually depends on it.)
        for wrapper in ["busybox", "toybox", "coreutils"] {
            for vector in crate::knowledge::escalation_vectors() {
                assert_eq!(
                    wrapper_chain_escalation(&argv(&[wrapper, vector, "whoami"])),
                    WrapperChainEscalation::Contains(vector),
                    "vector {vector:?} through {wrapper}"
                );
            }
        }
    }

    #[test]
    fn wrapper_chain_escalation_is_absent_for_busybox_alone() {
        // Guards against a future regression that adds busybox to
        // the escalation vectors, contradicting its catalog entry
        // ("busybox is a dispatcher, not a privilege-escalation
        // mechanism") with no test failing to catch it.
        for wrapper in ["busybox", "toybox", "coreutils"] {
            assert_eq!(
                wrapper_chain_escalation(&argv(&[wrapper, "rm", "-rf", "/"])),
                WrapperChainEscalation::Absent,
                "{wrapper}"
            );
        }
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
        // Regression: the grammar originally listed only the short
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
        // Regression: flock had no value-flag grammar at all, so
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
        for vector in crate::knowledge::escalation_vectors() {
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

    #[test]
    fn pipeline_rule_sink_required_flags_invalid_spec_is_err() {
        let toml = r#"
            [[pipeline]]
            id = "x"
            reason = "some reason"
            sources = ["find"]
            sinks = ["rm"]
            sink_required_flags = ["f|"]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn pipeline_rule_sink_required_flags_matches_cluster_and_long_spellings() {
        let rules = Rules::embedded().unwrap();
        let find = argv(&["find", "."]);
        for sink in [
            argv(&["xargs", "rm", "-f"]),
            argv(&["xargs", "-n", "1", "rm", "-rf"]),
            argv(&["xargs", "rm", "--force"]),
        ] {
            assert!(
                rules
                    .match_pipeline(&[find.clone(), sink.clone()])
                    .is_some_and(|rule| rule.id().as_str() == "find-pipe-rm-force"),
                "sink {sink:?} should satisfy the rule's sink_required_flags"
            );
        }
        assert!(
            rules
                .match_pipeline(&[find, argv(&["xargs", "rm"])])
                .is_none(),
            "a flagless rm sink must not satisfy the rule"
        );
    }

    fn git_sink_flag_rule(flag: &str) -> Rules {
        Rules::parse(&format!(
            r#"
            [[pipeline]]
            id = "pipe-git-flag"
            reason = "some reason"
            sources = ["curl"]
            sinks = ["git", "other"]
            sink_required_flags = ["{flag}"]
            "#
        ))
        .unwrap()
    }

    fn pipeline_hit(rules: &Rules, sink: &[&str]) -> bool {
        rules
            .match_pipeline(&[argv(&["curl", "x"]), argv(sink)])
            .is_some()
    }

    #[test]
    fn pipeline_rule_sink_required_flags_git_sink_matches_long_abbrev() {
        let rules = git_sink_flag_rule("--no-verify");
        assert!(pipeline_hit(&rules, &["git", "commit", "--no-verify"]));
        assert!(pipeline_hit(
            &rules,
            &["git", "commit", "--no-ver", "-F", "-"]
        ));
        assert!(pipeline_hit(&rules, &["git", "commit", "--no-v"]));
        assert!(pipeline_hit(
            &rules,
            &["/usr/bin/git", "commit", "--no-ver"]
        ));
        assert!(pipeline_hit(&rules, &["env", "git", "commit", "--no-ver"]));
        assert!(!pipeline_hit(&rules, &["git", "commit"]));
    }

    #[test]
    fn pipeline_rule_sink_long_abbrev_through_wrapper_and_global_opts() {
        let rules = git_sink_flag_rule("--no-verify");
        assert!(pipeline_hit(
            &rules,
            &["command", "git", "commit", "--no-ver"]
        ));
        assert!(pipeline_hit(
            &rules,
            &["git", "-C", "/r", "commit", "--no-ver"]
        ));
    }

    #[test]
    fn pipeline_rule_sink_long_abbrev_versioned_git() {
        let rules = git_sink_flag_rule("--no-verify");
        assert!(pipeline_hit(&rules, &["git2", "commit", "--no-ver"]));
        assert!(pipeline_hit(&rules, &["git2.40", "commit", "--no-v"]));
        assert!(!pipeline_hit(&rules, &["git2", "commit"]));
    }

    #[test]
    fn pipeline_rule_sink_required_flags_git_sink_abbrev_edge_prefixes() {
        let rules = git_sink_flag_rule("--no-verify");
        // Same policy as the deny path: any non-empty prefix of the full
        // name counts; a bare `--`, an empty name, or a longer word does not.
        assert!(pipeline_hit(&rules, &["git", "commit", "--n"]));
        assert!(!pipeline_hit(&rules, &["git", "commit", "--"]));
        assert!(!pipeline_hit(&rules, &["git", "commit", "--=x"]));
        assert!(!pipeline_hit(&rules, &["git", "commit", "--no-verifyx"]));
        assert!(!pipeline_hit(&rules, &["git", "commit", "-n"]));
    }

    #[test]
    fn pipeline_rule_sink_required_flags_non_git_sink_stays_exact_only() {
        let rules = git_sink_flag_rule("--no-verify");
        assert!(pipeline_hit(&rules, &["other", "--no-verify"]));
        assert!(!pipeline_hit(&rules, &["other", "--no-ver"]));
        assert!(!pipeline_hit(&rules, &["other", "--no-v"]));
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

    // ==== Embedded blocklist parses (malformed shipped file fails `cargo test`, not
    // runtime) ====

    #[test]
    fn embedded_blocklist_parses() {
        // rules/blocklist.toml must parse and validate
        Rules::embedded().unwrap();
    }

    // Issue #452: `crate::gate::git_push_plus_refspec`'s structural Block
    // reuses this rule's id/reason/deny_message via
    // `Rules::command_rule_by_id("git-push-force")` rather than declaring
    // a second rule — a rename or removal of this id would silently fail
    // that lookup open (`+`-refspec force pushes falling through to
    // Allow) with nothing else to catch it. Pinned here instead.
    #[test]
    fn embedded_git_push_force_rule_id_exists_for_gate_reuse() {
        assert!(
            Rules::embedded()
                .unwrap()
                .command_rule_by_id("git-push-force")
                .is_some()
        );
    }

    // Every embedded `[[redirect]]` rule's decision level, as an exact
    // map: adding one is a deliberate choice between Block (a target with
    // no legitimate write path) and Ask (issue #261's shell-init family,
    // which every other write mechanism also Asks about), not something
    // that should happen by copying a neighbouring entry.
    #[test]
    fn embedded_redirect_rule_decision_levels() {
        let rules = Rules::embedded().unwrap();
        for rule in &rules.redirect_rules {
            let expected = if rule.id.as_str() == "shell-init-redirect" {
                Decision::Ask
            } else {
                Decision::Block
            };
            assert_eq!(
                rule.decision,
                expected,
                "embedded redirect rule {:?} carries an unexpected decision",
                rule.id.as_str()
            );
        }
        assert!(
            rules
                .redirect_rules
                .iter()
                .any(|rule| rule.id.as_str() == "shell-init-redirect"),
            "the shell-init redirect rule must exist for the Ask arm above to mean anything"
        );
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

    // Issue #344: a bare `xf` dash-less cluster (no `C` in the SAME
    // cluster) now also gets its `x` rewritten into `-x`, so a SEPARATE
    // dashed `-C /` reaches the same Block `tar-extract-over-root-or-home`
    // rule a fully-dashed `tar -x -f evil.tar -C /` already does — before
    // issue #344's fix, `tar_dashless_rewrite` only fired when a single
    // dash-less cluster carried *both* `x` and `C` together, leaving a bare
    // `xf` completely unrewritten and `required_flags = ["x|--extract|--get"]`
    // permanently unsatisfied for this shape, degrading to the weaker Ask
    // `tar-directory-root-or-home` rule instead.
    #[test]
    fn tar_dashless_x_only_cluster_with_separate_dashed_c_now_blocks() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "xf", "evil.tar", "-C", "/"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    // Same gap, but for the long/GNU-style `--directory=`/`--dir=`
    // spelling (issue #344's own reported repro) rather than a separately
    // dashed `-C`.
    #[test]
    fn tar_dashless_x_only_cluster_with_separate_long_directory_now_blocks() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "xf", "a.tar", "--directory=/"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    // Same gap, but for issue #128's own `--dir=` abbreviation — confirms
    // the dashless rewrite (this fix) composes correctly with the
    // abbreviation rewrite, which runs on the ALREADY-rewritten tail
    // (`tar_dashless_effective_tail`).
    #[test]
    fn tar_dashless_x_only_cluster_with_dir_abbreviation_now_blocks() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "xf", "a.tar", "--dir=/"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    // A no-`C`, three-letter cluster (`z` unmodeled-but-boolean, `v`
    // boolean, `f` consuming) with a SEPARATE dashed `-C` — guards the
    // generic per-letter rewrite loop's claim for a cluster shape beyond
    // the two-letter `xf` this fix's other tests all use.
    #[test]
    fn tar_dashless_multi_letter_cluster_without_c_now_blocks() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "xzvf", "a.tar", "-C", "/"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    // Undeclared-but-real behavior change this fix also causes:
    // dash-less `x`+`P` (absolute-names) with no
    // `C` in the same cluster now also reaches `tar-absolute-names-ask`,
    // matching `TAR_DASHLESS_BOOLEAN`'s own doc comment's promise that `-P`
    // reaches that rule — pinned so this isn't a silent, undocumented
    // side effect.
    #[test]
    fn tar_dashless_x_and_p_cluster_without_c_now_asks() {
        let rules = Rules::embedded().unwrap();
        let matched = rules.match_command(&argv(&["tar", "xP", "a.tar"])).unwrap();
        assert_eq!(matched.decision(), Decision::Ask);
        assert_eq!(matched.id().as_str(), "tar-absolute-names-ask");
    }

    // Regression guard: a bare `xf` cluster with no directory-changing
    // target at all must stay exactly as unaffected by this rewrite as
    // before — the rewrite only ever changes which LATER tokens `-x`'s
    // presence lets a rule's own `required_flags` see, never introduces a
    // target match that wasn't otherwise there.
    #[test]
    fn tar_dashless_x_only_cluster_without_directory_target_still_allows() {
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["tar", "xf", "a.tar"]))
                .is_none()
        );
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

    // ==== issue #128: GNU tar long-option abbreviations (`--dir=` for
    // `--directory=`, `--ex`/`--extrac` for `--extract`, `--g` for `--get`)
    // must not slip past the rules that key off the canonical spellings.
    // tar_long_option_abbrev_rewrite canonicalizes these before any
    // FlagMatcher/TargetMatcher check ever runs. ====

    #[test]
    fn tar_directory_abbreviation_attached_matches_block() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "-x", "--dir=/", "-f", "a.tar"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    #[test]
    fn tar_directory_abbreviation_separated_matches_block() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "-x", "--dir", "/", "-f", "a.tar"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    #[test]
    fn tar_extract_abbreviations_restore_the_strict_block_rule() {
        // Before this fix, an abbreviated extract-mode flag left
        // required_flags "x|--extract|--get" unsatisfied, so only the
        // weaker tar-directory-root-or-home (Ask, no extract-mode
        // requirement) rule fired — silently degrading Block to Ask.
        let rules = Rules::embedded().unwrap();
        for cluster in ["--extrac", "--ex", "--g"] {
            let matched = rules
                .match_command(&argv(&["tar", cluster, "-f", "a.tar", "-C", "/"]))
                .unwrap_or_else(|| panic!("expected {cluster:?} to match a rule"));
            assert_eq!(matched.decision(), Decision::Block, "{cluster:?}");
            assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
        }
    }

    #[test]
    fn tar_directory_abbreviation_negative_exclude_does_not_match() {
        // "exclude" shares no prefix with "directory" at all.
        let rules = Rules::embedded().unwrap();
        let matched = rules.match_command(&argv(&["tar", "-x", "--exclude=/", "-f", "a.tar"]));
        assert!(matched.is_none());
    }

    #[test]
    fn tar_directory_abbreviation_negative_longer_token_does_not_match() {
        // "directoryx" is not a PREFIX of "directory" — it's longer.
        let rules = Rules::embedded().unwrap();
        let matched = rules.match_command(&argv(&["tar", "-x", "--directoryx=/", "-f", "a.tar"]));
        assert!(matched.is_none());
    }

    #[test]
    fn tar_bare_double_dash_does_not_panic_or_match() {
        let rules = Rules::embedded().unwrap();
        let matched = rules.match_command(&argv(&["tar", "-x", "--", "-f", "a.tar"]));
        assert!(matched.is_none());
    }

    #[test]
    fn tar_directory_already_canonical_spelling_unaffected() {
        // Regression guard: the rewrite must be a no-op for the spelling
        // that was already correct, not double-process it.
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "-x", "--directory=/", "-f", "a.tar"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    #[test]
    fn mv_target_dir_abbreviation_out_of_scope_stays_unmatched() {
        // Scope boundary: this rewrite is tar-only. mv's own
        // --target-directory= abbreviation gap is issue #214's territory,
        // untouched here.
        let rules = Rules::embedded().unwrap();
        let matched = rules.match_command(&argv(&["mv", "--target-dir=/dev/sda", "x"]));
        assert!(matched.is_none());
    }

    #[test]
    fn tar_directory_abbreviation_reaches_the_directory_equals_tilde_floor() {
        // Issue #115's floor keys off the rule's own literal "--directory="
        // strip string; the abbreviation rewrite runs first, so the floor
        // sees the canonicalized token exactly like the unabbreviated form.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "--dir=~", "-f", "a.tar"]);
        assert!(rules.match_command(&cmd).is_none());
        assert!(rules.match_command_directory_equals_tilde(&cmd).is_some());
    }

    #[test]
    fn tar_directory_abbreviation_reaches_the_dirstack_equal_subst_floor() {
        // Same as above, for issue #134's dirstack-tilde attach floor.
        let rules = Rules::embedded().unwrap();
        let cmd = argv(&["tar", "-x", "--dir=~+", "-f", "a.tar"]);
        assert!(rules.match_command(&cmd).is_none());
        assert!(rules.match_command_dirstack_equal_subst(&cmd).is_some());
    }

    // bsdtar 3.5.3 (macOS default) has a
    // `--cd` alias for `-C`/`--directory` that GNU tar doesn't — not a
    // prefix of "directory", so it needs its own exact-name recognition.
    #[test]
    fn tar_bsdtar_cd_alias_attached_matches_block() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "-x", "--cd=/", "-f", "a.tar"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    #[test]
    fn tar_bsdtar_cd_alias_separated_matches_block() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "-x", "--cd", "/", "-f", "a.tar"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Block);
        assert_eq!(matched.id().as_str(), "tar-extract-over-root-or-home");
    }

    // tar-absolute-names-ask keys on the
    // long option `--absolute-names`, which needs the same abbreviation
    // treatment as `--directory`/`--extract`.
    #[test]
    fn tar_absolute_names_abbreviation_matches_ask() {
        let rules = Rules::embedded().unwrap();
        for cluster in ["--abs", "--a"] {
            let matched = rules
                .match_command(&argv(&["tar", "-x", cluster, "-f", "a.tar"]))
                .unwrap_or_else(|| panic!("expected {cluster:?} to match a rule"));
            assert_eq!(matched.decision(), Decision::Ask, "{cluster:?}");
            assert_eq!(matched.id().as_str(), "tar-absolute-names-ask");
        }
    }

    #[test]
    fn tar_absolute_names_already_canonical_spelling_unaffected() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "-x", "--absolute-names", "-f", "a.tar"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Ask);
        assert_eq!(matched.id().as_str(), "tar-absolute-names-ask");
    }

    // bsdtar 3.5.3 (macOS default) spells
    // `-P` as `--absolute-paths`, not GNU tar's `--absolute-names` — a
    // different string this crate's own prefix family doesn't cover
    // without its own exact/prefix alias, unlike --cd's relationship to
    // --directory.
    #[test]
    fn tar_bsdtar_absolute_paths_alias_matches_ask() {
        let rules = Rules::embedded().unwrap();
        for cluster in ["--absolute-paths", "--absolute-p"] {
            let matched = rules
                .match_command(&argv(&["tar", "-x", cluster, "-f", "a.tar"]))
                .unwrap_or_else(|| panic!("expected {cluster:?} to match a rule"));
            assert_eq!(matched.decision(), Decision::Ask, "{cluster:?}");
            assert_eq!(matched.id().as_str(), "tar-absolute-names-ask");
        }
    }

    #[test]
    fn tar_bsdtar_absolute_paths_alias_with_attached_value_matches_like_absolute_names() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["tar", "-x", "--absolute-paths=x", "-f", "a.tar"]))
            .unwrap();
        assert_eq!(matched.decision(), Decision::Ask);
        assert_eq!(matched.id().as_str(), "tar-absolute-names-ask");
    }

    // An abbreviated extract-mode flag with
    // an attached (real-tar-invalid) `=value` must decide identically to
    // the canonical spelling with the same invalid `=value`, not more
    // leniently.
    #[test]
    fn tar_extract_abbreviation_with_attached_value_matches_like_the_canonical_spelling() {
        let rules = Rules::embedded().unwrap();
        let abbreviated = rules
            .match_command(&argv(&["tar", "--ex=x", "-f", "a.tar", "-C", "/"]))
            .unwrap();
        let canonical = rules
            .match_command(&argv(&["tar", "--extract=x", "-f", "a.tar", "-C", "/"]))
            .unwrap();
        assert_eq!(abbreviated.decision(), Decision::Block);
        assert_eq!(abbreviated.id(), canonical.id());
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

    // ==== logic-bugfixer finding: `git -C <path>`/`-c <name>=<value>`
    // shifts the subcommand out of positional slot 0. Before the fix,
    // `git -C /tmp push --force` left `/tmp` occupying the slot
    // `required_tokens = ["push"]` expected `push` in, so no git rule
    // could match at all. ====

    #[test]
    fn git_valueless_global_flag_between_globals_still_matches_push_force() {
        // `--no-pager` (value-less global) interleaved before `-C` must
        // not stop the strip — breaking there re-opened the original
        // bypass one flag deep.
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&[
                "git",
                "--no-pager",
                "-C",
                "/tmp",
                "push",
                "--force",
            ]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-push-force");
    }

    #[test]
    fn git_attached_form_global_before_dash_capital_c_still_matches_push_force() {
        // `--git-dir=/x` (attached-value global) interleaved before `-C`
        // must not stop the strip either.
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&[
                "git",
                "--git-dir=/x",
                "-C",
                "/tmp",
                "push",
                "--force",
            ]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-push-force");
    }

    #[test]
    fn git_attr_source_separated_value_before_subcommand_still_matches_push_force() {
        // `--attr-source <tree-ish>` consumes a separated value in
        // current git; leaving it out of GIT_GLOBAL_VALUE_FLAGS left
        // `<tree-ish>` occupying the subcommand's positional slot.
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["git", "--attr-source", "HEAD", "push", "--force"]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-push-force");
    }

    #[test]
    fn git_unknown_leading_dash_token_stops_the_strip() {
        // `-m` is NOT a git global; the walk must break there, leaving the
        // tail intact so a rule's own value_flags still see it (pinned by
        // constraints_match_skips_a_consumed_unresolvable_value_flag_argument).
        assert_eq!(
            git_strip_global_flags("git", &argv(&["-m", "msg", "commit"])),
            None
        );
    }

    #[test]
    fn git_dash_capital_c_before_subcommand_still_matches_push_force() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["git", "-C", "/tmp", "push", "--force"]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-push-force");
    }

    #[test]
    fn git_lowercase_c_before_subcommand_still_matches_push_force() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["git", "-c", "a=b", "push", "--force"]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-push-force");
    }

    #[test]
    fn git_git_dir_separated_value_before_subcommand_still_matches_push_force() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["git", "--git-dir", "/x", "push", "--force"]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-push-force");
    }

    #[test]
    fn git_multiple_global_flags_before_subcommand_still_matches_push_force() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&[
                "git", "-C", "/tmp", "-c", "a=b", "push", "--force",
            ]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-push-force");
    }

    #[test]
    fn git_dash_capital_c_before_a_benign_subcommand_stays_unmatched() {
        // False-positive pin: `-C <path>` stripping must not turn `status`
        // into anything it shouldn't match.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["git", "-C", "/tmp", "status"]))
                .is_none()
        );
    }

    #[test]
    fn git_dash_capital_c_with_no_value_does_not_strip_anything() {
        // A trailing `-C` with nothing after it: git_strip_global_flags
        // must not consume past the end of the tail.
        assert_eq!(git_strip_global_flags("git", &argv(&["-C"])), None);
    }

    // ==== issue #447: `-c core.hooksPath=...` is `--no-verify` in disguise ====

    #[test]
    fn git_dash_c_hooks_path_synthesizes_no_verify_for_commit() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&[
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-m",
                "x",
            ]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn git_dash_c_hooks_path_synthesizes_no_verify_for_push() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["git", "-c", "core.hooksPath=/dev/null", "push"]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-push-no-verify");
    }

    #[test]
    fn git_dash_c_hooks_path_synthesizes_no_verify_for_merge() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&[
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "merge",
                "other",
            ]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-merge-no-verify");
    }

    #[test]
    fn git_dash_c_hooks_path_key_match_is_case_insensitive() {
        // Git config section/key names are case-insensitive.
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&[
                "git",
                "-c",
                "Core.HooksPath=/dev/null",
                "commit",
                "-m",
                "x",
            ]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn git_config_env_separated_hooks_path_synthesizes_no_verify() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&[
                "git",
                "--config-env",
                "core.hooksPath=ENVVAR",
                "commit",
                "-m",
                "x",
            ]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn git_config_env_attached_hooks_path_synthesizes_no_verify() {
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&[
                "git",
                "--config-env=core.hooksPath=ENVVAR",
                "commit",
                "-m",
                "x",
            ]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn git_dash_c_unrelated_key_does_not_synthesize_no_verify() {
        // False-positive pin: an ordinary `-c` config override must not
        // trigger the no-verify family.
        let rules = Rules::embedded().unwrap();
        assert!(
            rules
                .match_command(&argv(&["git", "-c", "user.name=x", "commit", "-m", "x"]))
                .is_none()
        );
    }

    #[test]
    fn git_dash_c_hooks_path_empty_value_synthesizes_no_verify() {
        // issue #447's own headline spelling: an empty hooksPath (not just
        // /dev/null) disables hooks too.
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&[
                "git",
                "-c",
                "core.hooksPath=",
                "commit",
                "-m",
                "x",
            ]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-commit-no-verify-short");
    }

    #[test]
    fn git_dash_c_bare_hooks_path_synthesizes_no_verify() {
        // The value-less `-c core.hooksPath` form: real git rejects it
        // ("missing value for 'core.hooksPath'"), so Blocking is a
        // harmless false positive rather than a live gap.
        let rules = Rules::embedded().unwrap();
        let matched = rules
            .match_command(&argv(&["git", "-c", "core.hooksPath", "commit", "-m", "x"]))
            .unwrap();
        assert_eq!(matched.id().as_str(), "git-commit-no-verify-short");
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

    // Regression pin (PR #205): the ancestor rm rule's
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
        assert_eq!(
            rule.id().as_str(),
            "self-protect-config-ancestor-rsync-tilde"
        );
        assert_eq!(rule.decision(), Decision::Ask);
    }

    // Issue #450's recursive-copy/extract half of the ancestor family --
    // asserting `rule.id()`, not just `Decision::Ask`, so a future
    // unrelated Ask rule on the same command can't silently make this
    // pass for the wrong reason (unlike the plain decision-only checks
    // above, added before that failure mode was on file).
    #[test]
    fn self_protect_ancestor_rsync_copy_literal_tilde_asks() {
        let rules = Rules::embedded().unwrap();
        let rule = rules
            .match_command(&argv(&["rsync", "-a", "payload/", "~/.config/"]))
            .unwrap();
        assert_eq!(
            rule.id().as_str(),
            "self-protect-config-ancestor-rsync-copy-tilde"
        );
        assert_eq!(rule.decision(), Decision::Ask);
    }

    #[test]
    fn self_protect_ancestor_cp_recursive_literal_tilde_asks() {
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["cp", "-r", "payload/.", "~/.config/"]),
            argv(&["cp", "--archive", "payload/.", "~/.config/"]),
            argv(&["cp", "-r", "payload", "--target-directory=~/.config"]),
            argv(&["cp", "-r", "payload", "-t~/.config"]),
        ] {
            let rule = rules.match_command(&cmd).unwrap();
            assert_eq!(rule.id().as_str(), "self-protect-config-ancestor-cp-tilde");
            assert_eq!(rule.decision(), Decision::Ask);
        }
        // Flagless cp is additive at the destination, same as flagless
        // rsync above -- not covered by this rule.
        assert!(
            rules
                .match_command(&argv(&["cp", "payload", "~/.config/"]))
                .is_none()
        );
    }

    #[test]
    fn self_protect_ancestor_tar_extract_literal_tilde_asks() {
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["tar", "-xf", "p.tar", "-C", "~/.config"]),
            argv(&["tar", "-xf", "p.tar", "-C~/.config"]),
            argv(&["tar", "-xf", "p.tar", "--directory=~/.config"]),
        ] {
            let rule = rules.match_command(&cmd).unwrap();
            assert_eq!(
                rule.id().as_str(),
                "self-protect-config-ancestor-tar-extract-tilde"
            );
            assert_eq!(rule.decision(), Decision::Ask);
        }
    }

    #[test]
    fn self_protect_ancestor_unzip_literal_tilde_asks() {
        let rules = Rules::embedded().unwrap();
        for cmd in [
            argv(&["unzip", "p.zip", "-d", "~/.config"]),
            argv(&["unzip", "p.zip", "-d~/.config"]),
        ] {
            let rule = rules.match_command(&cmd).unwrap();
            assert_eq!(
                rule.id().as_str(),
                "self-protect-config-ancestor-unzip-tilde"
            );
            assert_eq!(rule.decision(), Decision::Ask);
        }
    }

    // Issue #450 added a flagless `rsync` ancestor rule
    // (`self-protect-config-ancestor-rsync-copy-tilde`, tested above), so
    // a flagless rsync no longer stays universally unmatched near the
    // config directory the way this test's name once implied -- what it
    // actually pins is narrower: `~/.config/other/` is a SIBLING/child of
    // the ancestor, not the ancestor itself, so no ancestor rule (delete
    // or copy) fires on it either way.
    #[test]
    fn self_protect_ancestor_rsync_non_ancestor_subdir_does_not_match() {
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

    // Issue #497: a versioned/distro-suffixed sink name (`dash5`) must be
    // recognized the same way the unversioned spelling already is.
    #[test]
    fn curl_pipe_versioned_dash_sink_matches() {
        let rules = Rules::embedded().unwrap();
        let stages = vec![argv(&["curl", "http://x/install.sh"]), argv(&["dash5"])];
        assert!(rules.match_pipeline(&stages).is_some());
    }

    #[test]
    fn cat_pipe_bash_does_not_match() {
        let rules = Rules::embedded().unwrap();
        let stages = vec![argv(&["cat", "script.sh"]), argv(&["bash"])];
        assert!(rules.match_pipeline(&stages).is_none());
    }

    #[test]
    fn match_pipeline_prefers_block_over_an_earlier_ask() {
        // issue #465: declaration order must not decide the decision,
        // mirroring match_command/match_redirect_target/match_token's own
        // worst-wins regression tests. A hypothetical embedded Ask rule
        // declared before a Block rule for the same pipeline shape must
        // not shadow the Block.
        let toml = r#"
            [[pipeline]]
            id = "ask-first"
            decision = "ask"
            reason = "declared first"
            sources = ["curl"]
            sinks = ["sh"]

            [[pipeline]]
            id = "block-second"
            reason = "declared second"
            sources = ["curl"]
            sinks = ["sh"]
        "#;
        let rules = Rules::parse(toml).unwrap();
        let stages = vec![argv(&["curl", "http://x/install.sh"]), argv(&["sh"])];
        let rule = rules.match_pipeline(&stages).unwrap();
        assert_eq!(rule.id().as_str(), "block-second");
        assert_eq!(rule.decision(), Decision::Block);
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
    fn except_target_skips_a_dev_fd_word_only_when_no_target_admits_dev_fd() {
        let dev_fd = || NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::DevFdPath);
        let unresolved =
            || NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion);
        let fires = |targets: &str, word: NormalizedWord| {
            let rules = Rules::parse(&format!(
                "[[command]]\nid = \"t\"\nreason = \"test\"\ncommand = \"rm\"\ntargets = [{targets}]\n"
            ))
            .unwrap();
            let mut cmd = argv(&["rm"]);
            cmd.push(word);
            rules.match_command_except_target(&cmd).is_some()
        };
        for targets in [
            r#"{ exact = "/etc/passwd" }"#,
            r#"{ prefix = "/etc/" }"#,
            r#"{ normalized = "/etc/passwd" }"#,
            r#"{ normalized = "/dev/fd" }"#,
            r#"{ normalized_prefix = "/etc/" }"#,
            r#"{ normalized_basename = ".env" }"#,
            r#"{ normalized = "~/.ssh" }"#,
            r#"{ normalized = "secret" }"#,
        ] {
            assert!(!fires(targets, dev_fd()), "{targets}");
            assert!(fires(targets, unresolved()), "{targets}");
        }
        for targets in [
            r#"{ exact = "/dev/fd/3" }"#,
            r#"{ prefix = "/dev/" }"#,
            r#"{ prefix = "/" }"#,
            r#"{ normalized = "/dev/fd/3" }"#,
            r#"{ normalized = "/dev/fd/*" }"#,
            r#"{ normalized_prefix = "/dev/" }"#,
            r#"{ normalized_prefix = "/" }"#,
            r#"{ normalized_prefix = "/dev/fd/" }"#,
            r#"{ normalized_basename = "63" }"#,
            r#"{ exact = "/etc/passwd" }, { prefix = "/dev/" }"#,
        ] {
            assert!(fires(targets, dev_fd()), "{targets}");
        }
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
        // still return the r-only `rm-recursive-dangerous-target` rule
        // instead (the same fail-safe "unresolvable target could be
        // anything" refinement issue #22 extends to `rm`, already present
        // for `cp`/`tee`/`mv`/`install`/`dd`) — what must not happen is the
        // *force*-gated rule firing on an incomplete flag set.
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
    // the same argv still floors via a different, r-only rule (issue #453's
    // `rm-recursive-dangerous-target`), since its lack of an `f` requirement
    // means the missing `-f` never disqualifies it the way it disqualifies
    // `rm-recursive-force-dangerous-target`.
    #[test]
    fn except_target_still_fires_via_a_different_rule_when_force_is_missing() {
        let rules = Rules::embedded().unwrap();
        let cmd = argv_with_unresolvable_tail(&["rm", "-r"]);
        let matched = rules.match_command_except_target(&cmd);
        assert_eq!(
            matched.map(|rule| rule.id().as_str()),
            Some("rm-recursive-dangerous-target")
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

    // ==== Issue #117: matches_except_target's fourth relaxation — sed's
    // decoy script token no longer defeats the flag+target-hidden check ====

    #[test]
    fn except_target_fires_for_sed_with_one_resolved_script_and_an_opaque_tail() {
        // sed 's/a/b/' $(echo -i ~/.config/shguard/config.toml) — GNU sed
        // permutes options after operands, so the hidden substitution still
        // performs the in-place edit at runtime even though the tail has
        // one resolved token (the script).
        let rules = Rules::embedded().unwrap();
        let mut cmd = argv(&["sed", "s/a/b/"]);
        cmd.push(NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::CommandSubstitution,
        ));
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_except_target(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-sed-tilde");
    }

    #[test]
    fn except_target_fires_for_sed_with_a_resolved_flag_plus_script_and_an_opaque_tail() {
        // sed -n 's/a/b/' $(echo -i ~/.config/shguard/config.toml) — the
        // resolved "-n" must not count toward the one-operand allowance
        // (it's a flag candidate, not a script/file operand), so this must
        // still fire.
        let rules = Rules::embedded().unwrap();
        let mut cmd = argv(&["sed", "-n", "s/a/b/"]);
        cmd.push(NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::CommandSubstitution,
        ));
        assert!(rules.match_command(&cmd).is_none());
        let rule = rules.match_command_except_target(&cmd).unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-sed-tilde");
    }

    // The two-resolved-operand must-not-fire case (sed's own residual gap
    // under the new relaxation, same shape as the pinned #85 case) is
    // already covered above by
    // `except_target_does_not_fire_when_a_resolved_token_survives_in_the_tail`
    // — no separate test needed here.

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

    // ==== target_flags (issue #581): candidates restricted to named flags'
    // values ====

    fn target_flags_rules(flags: &str) -> Rules {
        Rules::parse(&format!(
            r#"
            [[command]]
            id = "gh-comment-body-file"
            reason = "ask unless the body file is under the scratchpad"
            decision = "ask"
            command = "gh issue comment"
            target_flags = {flags}
            except_targets = [{{ prefix = "/private/tmp/claude-501/" }}]
        "#
        ))
        .unwrap()
    }

    fn fires(rules: &Rules, words: &[&str]) -> bool {
        rules.match_command(&argv(words)).is_some()
    }

    #[test]
    fn target_flags_ignores_positionals_and_other_flag_values() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        // The issue number and `--repo` value are not candidates, so only
        // the --body-file value decides.
        assert!(!fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "123",
                "--repo",
                "o/r",
                "--body-file",
                "/private/tmp/claude-501/x.md"
            ]
        ));
        assert!(!fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "123",
                "--body-file=/private/tmp/claude-501/x.md"
            ]
        ));
    }

    #[test]
    fn target_flags_fires_when_flag_value_is_not_excepted() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        assert!(fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "123",
                "--body-file",
                "/etc/passwd"
            ]
        ));
        assert!(fires(
            &rules,
            &["gh", "issue", "comment", "123", "--body-file=/etc/passwd"]
        ));
        // One excepted and one unexcepted listed-flag value: ALL must be excepted.
        assert!(fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "--body-file=/private/tmp/claude-501/a",
                "--body-file",
                "/etc/passwd"
            ]
        ));
    }

    #[test]
    fn target_flags_absent_flag_fails_closed() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        // No listed flag at all: no candidates, never "all excepted".
        assert!(fires(
            &rules,
            &["gh", "issue", "comment", "123", "--body", "hi"]
        ));
        assert!(fires(
            &rules,
            &["gh", "issue", "comment", "/private/tmp/claude-501/x"]
        ));
    }

    #[test]
    fn target_flags_flag_without_value_fails_closed() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        assert!(fires(
            &rules,
            &["gh", "issue", "comment", "123", "--body-file"]
        ));
        // A terminator before the flag turns recognition off entirely.
        assert!(fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "--",
                "--body-file=/private/tmp/claude-501/x"
            ]
        ));
    }

    #[test]
    fn target_flags_unresolved_value_fails_closed() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        let mut words = argv(&["gh", "issue", "comment", "123", "--body-file"]);
        words.push(NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::ParameterExpansion,
        ));
        assert!(rules.match_command(&words).is_some());
    }

    #[test]
    fn target_flags_dotdot_candidate_is_never_excepted() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        assert!(fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "--body-file",
                "/private/tmp/claude-501/../../etc/passwd"
            ]
        ));
    }

    #[test]
    fn target_flags_short_flag_forms() {
        let rules = target_flags_rules(r#"["-F"]"#);
        let ok = "/private/tmp/claude-501/x";
        assert!(!fires(&rules, &["gh", "issue", "comment", "1", "-F", ok]));
        assert!(!fires(
            &rules,
            &["gh", "issue", "comment", "1", "-F/private/tmp/claude-501/x"]
        ));
        assert!(!fires(&rules, &["gh", "issue", "comment", "1", "-sF", ok]));
        assert!(fires(
            &rules,
            &["gh", "issue", "comment", "1", "-F", "/etc/passwd"]
        ));
        assert!(fires(
            &rules,
            &["gh", "issue", "comment", "1", "-F/etc/passwd"]
        ));
        assert!(fires(&rules, &["gh", "issue", "comment", "1", "-F"]));
        assert!(fires(&rules, &["gh", "issue", "comment", "1", "-sF"]));
    }

    fn target_flags_rules_with(flags: &str, value_flags: &str, prefix: &str) -> Rules {
        Rules::parse(&format!(
            r#"
            [[command]]
            id = "gh-comment-body-file"
            reason = "ask unless the body file is under the scratchpad"
            decision = "ask"
            command = "gh issue comment"
            target_flags = {flags}
            value_flags = {value_flags}
            except_targets = [{{ prefix = "{prefix}" }}]
        "#
        ))
        .unwrap()
    }

    const SCRATCH_FILE: &str = "/private/tmp/claude-501/x.md";

    // Disclosed limit, not a guarantee: an alias that is not listed is
    // invisible, so its value never stops the exception.
    #[test]
    fn target_flags_unlisted_alias_value_is_invisible_and_can_suppress() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        assert!(!fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "--body-file",
                SCRATCH_FILE,
                "-F",
                "/etc/passwd"
            ]
        ));
        assert!(!fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "-F",
                "/etc/passwd",
                "--body-file",
                SCRATCH_FILE
            ]
        ));
        let listed = target_flags_rules(r#"["--body-file", "-F"]"#);
        assert!(fires(
            &listed,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "--body-file",
                SCRATCH_FILE,
                "-F",
                "/etc/passwd"
            ]
        ));
        assert!(fires(
            &listed,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "-F",
                "/etc/passwd",
                "--body-file",
                SCRATCH_FILE
            ]
        ));
    }

    // Disclosed limit: no other flag is examined, so a mode flag passes
    // through; a separate deny rule is the author's job.
    #[test]
    fn target_flags_mode_flag_passes_through() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        assert!(!fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "--delete-last",
                "--body-file",
                SCRATCH_FILE
            ]
        ));
    }

    #[test]
    fn target_flags_empty_attached_value_fails_closed() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        assert!(fires(
            &rules,
            &["gh", "issue", "comment", "1", "--body-file="]
        ));
    }

    #[test]
    fn target_flags_flag_followed_by_another_flag_takes_it_as_the_value() {
        let rules = target_flags_rules(r#"["--body-file"]"#);
        assert!(fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "--body-file",
                "--delete-last"
            ]
        ));
    }

    #[test]
    fn target_flags_short_equals_form_is_not_recognised_and_fires() {
        let rules = target_flags_rules(r#"["-F"]"#);
        assert!(fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "-F=/private/tmp/claude-501/x.md"
            ]
        ));
    }

    #[test]
    fn target_flags_value_flags_stop_the_cluster_scan() {
        let words = [
            "gh",
            "issue",
            "comment",
            "123",
            "-Ro/rF/private/tmp/claude-501/x.md",
        ];
        let with = target_flags_rules_with(r#"["--body-file", "-F"]"#, r#"["R"]"#, "/private/tmp/");
        assert!(fires(&with, &words));
        // Without the declaration the scan mis-splits inside `-R`'s glued
        // value and manufactures an excepted-looking candidate (disclosed).
        let without = target_flags_rules(r#"["--body-file", "-F"]"#);
        assert!(!fires(&without, &words));
    }

    #[test]
    fn target_flags_unrooted_dotdot_candidate_is_never_excepted() {
        let rules = target_flags_rules_with(r#"["--body-file"]"#, "[]", "scratch/");
        assert!(!fires(
            &rules,
            &["gh", "issue", "comment", "1", "--body-file", "scratch/a.md"]
        ));
        assert!(fires(
            &rules,
            &[
                "gh",
                "issue",
                "comment",
                "1",
                "--body-file",
                "scratch/../../etc/passwd"
            ]
        ));
    }

    #[test]
    fn target_flags_load_validation() {
        let reject = |body: &str, needle: &str| {
            let toml = format!(
                r#"
                [[command]]
                id = "x"
                reason = "r"
                decision = "ask"
                command = "gh"
                {body}
            "#
            );
            let err = Rules::parse(&toml).unwrap_err().to_string();
            assert!(err.contains(needle), "{body}: {err}");
        };
        let ex = r#"except_targets = [{ prefix = "/p/" }]"#;
        reject(&format!("target_flags = []\n{ex}"), "empty list");
        reject(
            &format!("target_flags = [\"body-file\"]\n{ex}"),
            "target_flags",
        );
        reject(&format!("target_flags = [\"\"]\n{ex}"), "target_flags");
        reject(&format!("target_flags = [\"-\"]\n{ex}"), "target_flags");
        reject(&format!("target_flags = [\"--\"]\n{ex}"), "target_flags");
        reject(&format!("target_flags = [\"--f\"]\n{ex}"), "target_flags");
        reject(&format!("target_flags = [\"-ab\"]\n{ex}"), "target_flags");
        reject(&format!("target_flags = [\"--a=b\"]\n{ex}"), "target_flags");
        reject(
            "target_flags = [\"--body-file\"]",
            "without `targets` or `except_targets`",
        );
        reject(
            &format!("target_flags = [\"-x\"]\nattached_value_flags = [\"x\"]\n{ex}"),
            "cannot be combined",
        );
    }

    #[test]
    fn a_letter_in_both_target_flags_and_value_flags_fails_to_load() {
        let reject = |target_flags: &str, value_flags: &str, needle: &str| {
            let toml = format!(
                r#"
                [[command]]
                id = "x"
                reason = "r"
                decision = "ask"
                command = "gh"
                target_flags = {target_flags}
                value_flags = {value_flags}
                except_targets = [{{ prefix = "/p/" }}]
            "#
            );
            let err = Rules::parse(&toml).unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
        };
        reject(r#"["-F"]"#, r#"["F"]"#, "-F is listed in both");
        reject(
            r#"["--body-file"]"#,
            r#"["body-file"]"#,
            "--body-file is listed in both",
        );
        // Different letters stay legal.
        assert!(
            Rules::parse(
                r#"
                [[command]]
                id = "x"
                reason = "r"
                decision = "ask"
                command = "gh"
                target_flags = ["-F"]
                value_flags = ["R"]
                except_targets = [{ prefix = "/p/" }]
            "#
            )
            .is_ok()
        );
    }

    // ==== target_flags on a `targets` rule (issue #622) ====

    fn target_flags_deny_rules(except: &str) -> Rules {
        Rules::parse(&format!(
            r#"
            [[command]]
            id = "gh-body-file-escape"
            reason = "gh --body-file outside the scratchpad"
            decision = "block"
            command = "gh"
            target_flags = ["--body-file", "-F"]
            targets = [{{ normalized_prefix = "/Users/" }}, {{ normalized_prefix = "/etc/" }}]
            {except}
        "#
        ))
        .unwrap()
    }

    #[test]
    fn target_flags_scope_targets_to_the_flag_values() {
        let rules = target_flags_deny_rules("");
        // Positionals and other flags' values are not candidates, even when
        // they would match a target on their own.
        assert!(!fires(
            &rules,
            &[
                "gh",
                "/Users/me/issue",
                "create",
                "--title",
                "/etc/x",
                "--body-file",
                "/private/tmp/claude-501/x.md"
            ]
        ));
        for words in [
            &["gh", "issue", "create", "--body-file", "/Users/me/.ssh/id"][..],
            &["gh", "issue", "create", "--body-file=/etc/passwd"],
            &["gh", "issue", "create", "-F", "/etc/passwd"],
            &["gh", "issue", "create", "-F/etc/passwd"],
            &["gh", "issue", "create", "--body-file", "/tmp/../etc/passwd"],
        ] {
            assert!(fires(&rules, words), "{words:?}");
        }
        // No listed flag at all: nothing is a target, so the rule is silent.
        assert!(!fires(&rules, &["gh", "/Users/me/issue", "list"]));
    }

    #[test]
    fn target_flag_glued_value_offset_is_scoped_to_the_matching_command() {
        let rules = target_flags_deny_rules("");
        let scope = |words: &[&str]| -> Vec<NormalizedWord> {
            words.iter().map(|w| NormalizedWord::resolved(*w)).collect()
        };
        assert_eq!(
            rules.target_flag_glued_value_offset(&scope(&["gh", "issue"]), "-Fnotes.md"),
            Some(2)
        );
        assert_eq!(
            rules.target_flag_glued_value_offset(&scope(&["sudo", "gh"]), "--body-file=notes.md"),
            Some(12)
        );
        // Another command's `-F` is not a listed flag of this rule.
        assert_eq!(
            rules.target_flag_glued_value_offset(&scope(&["awk"]), "-Fnotes.md"),
            None
        );
        assert_eq!(
            rules.target_flag_glued_value_offset(&[], "-Fnotes.md"),
            None
        );
    }

    #[test]
    fn target_flags_on_targets_stay_scoped_when_a_value_is_unreadable() {
        let rules = target_flags_deny_rules("");
        // A listed flag with no value: nothing to match, and the other
        // words still don't count.
        assert!(!fires(&rules, &["gh", "/etc/x", "--body-file"]));
        // An unresolvable flag value is consumed, never replaced by the
        // next word; the unresolved-argument floor asks instead.
        let unresolvable =
            || NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion);
        let mut words = argv(&["gh", "/etc/x", "--body-file"]);
        words.push(unresolvable());
        words.push(NormalizedWord::resolved("/private/tmp/x".to_string()));
        assert!(rules.match_command(&words).is_none());
        assert!(rules.match_command_except_target(&words).is_some());
        // A listed flag hidden in an unresolvable word: the resolved word
        // after it may be its value, so the floor still asks.
        let mut words = argv(&["gh", "issue", "create"]);
        words.push(unresolvable());
        words.push(NormalizedWord::resolved("/Users/me/.ssh/id".to_string()));
        assert!(rules.match_command(&words).is_none());
        assert!(rules.match_command_except_target(&words).is_some());
        // An unresolvable title leaves a readable value fully decidable.
        let mut words = argv(&["gh", "pr", "create", "--title"]);
        words.push(unresolvable());
        words.extend(argv(&["--body-file", "/etc/passwd"]));
        assert!(rules.match_command(&words).is_some());
    }

    #[test]
    fn target_flags_on_targets_read_past_a_terminator_and_strip_short_equals() {
        let rules = target_flags_deny_rules("");
        assert!(fires(
            &rules,
            &["gh", "issue", "create", "--", "--body-file", "/etc/passwd"]
        ));
        assert!(fires(&rules, &["gh", "issue", "create", "-F=/etc/passwd"]));
        assert!(!fires(
            &rules,
            &["gh", "issue", "create", "-F=/private/tmp/x"]
        ));
    }

    #[test]
    fn target_flags_rejects_strip_targets() {
        let err = Rules::parse(
            r#"
            [[command]]
            id = "x"
            reason = "r"
            decision = "block"
            command = "gh"
            target_flags = ["--body-file"]
            targets = [{ normalized_prefix = "/Users/", strip = "--body-file=" }]
        "#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("`strip` target"), "{err}");
    }

    #[test]
    fn target_flags_on_targets_with_except_targets_excepts_only_flag_values() {
        let rules =
            target_flags_deny_rules(r#"except_targets = [{ prefix = "/Users/me/scratch/" }]"#);
        assert!(!fires(
            &rules,
            &["gh", "/etc/x", "--body-file", "/Users/me/scratch/body.md"]
        ));
        assert!(fires(
            &rules,
            &[
                "gh",
                "issue",
                "--body-file",
                "/Users/me/scratch/a.md",
                "-F",
                "/Users/me/.ssh/id"
            ]
        ));
    }

    // ==== attached_value_flags (issue #47): opt-in closure of the gap
    // documented immediately above ====

    #[test]
    fn attached_value_flags_recognises_a_declared_short_flags_glued_value_as_a_candidate() {
        // Same command as the known-gap test above, but with `x` declared
        // via attached_value_flags: the glued proxy target now becomes a
        // candidate, so it's checked against except_targets and correctly
        // fails to match (all-excepted no longer holds over the widened
        // candidate set) — the rule fires instead of being wrongly
        // suppressed.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
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
                .is_some(),
            "declared attached_value_flags entry should surface the glued proxy target as a \
             candidate, defeating the wrongful all-excepted suppression"
        );
    }

    // Documented-but-untested
    // behavior: declaring attached_value_flags is a per-rule trust
    // decision (README's own wording) that can flip a genuine localhost
    // target from excepted to unexcepted -- widening the candidate set
    // widens what except_targets checks, which can loosen as well as
    // tighten depending on the target's actual value. Pinned here so this
    // direction is asserted, not just the tightening direction the other
    // tests above cover.
    #[test]
    fn attached_value_flags_still_excepts_a_declared_flags_genuine_localhost_value() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "-xhttp://localhost:8080"]))
                .is_none(),
            "a declared attached_value_flags entry's glued value is checked against \
             except_targets like any other candidate -- a genuine localhost value is still \
             correctly excepted, not just a genuine evil one still correctly caught"
        );
    }

    // Documented-but-untested
    // behavior: an ordinary combined short-flag cluster containing no
    // declared attached_value_flags letter at all must not have any
    // candidate extracted from it, the same way it wouldn't with the
    // field entirely unset.
    #[test]
    fn attached_value_flags_does_not_false_positive_on_an_unrelated_cluster() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "-sSL", "http://localhost"]))
                .is_none(),
            "an ordinary combined short-flag cluster containing none of the declared \
             attached_value_flags letters must not spuriously yield a candidate"
        );
    }

    #[test]
    fn attached_value_flags_bare_declared_flag_yields_no_candidate() {
        // A bare `-x` (nothing glued after it) must not become an empty
        // candidate. Not because `""` could wrongly satisfy an
        // except_targets alternative (convert_target rejects an empty
        // exact/prefix at load, so it never would) — an un-exceptable
        // `""` candidate would instead make the rule spuriously fire on
        // `-x` alone.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://localhost", "-x"]))
                .is_none(),
            "a bare declared flag with nothing glued after it must not become a candidate"
        );
    }

    // Issue #214: a declared flag glued into a non-leading cluster
    // position (`-sxVALUE`, `s` then `x`) is now recognised via a
    // left-to-right scan of the cluster, matching real getopt short-flag
    // parsing (once a cluster reaches a value-taking flag, everything
    // after it is that flag's value). This used to be a disclosed known
    // gap (see the removed `attached_value_flags_cluster_position_is_not
    // _recognized` test this replaces).
    #[test]
    fn attached_value_flags_recognises_a_non_leading_cluster_position() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "http://localhost",
                    "-sxhttp://evil.example.com"
                ]))
                .is_some(),
            "a declared flag glued into a non-leading cluster position is now recognised, \
             surfacing the glued value as a candidate that fails except_targets"
        );
    }

    // The leading-position case (already covered by
    // `attached_value_flags_recognises_a_declared_short_flags_glued_value_as_a_candidate`
    // above) must keep working unchanged after the #214 cluster-scan
    // widening — a single-character cluster of just the declared flag is
    // the degenerate case of the same code path.
    #[test]
    fn attached_value_flags_leading_position_still_recognised_after_cluster_scan() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
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
                .is_some(),
            "the leading-position shape must still be recognised exactly as before"
        );
    }

    // Every character before the matched declared letter is treated as an
    // independent boolean flag and skipped without validation — the scan
    // only looks for WHERE the declared letter is, not whether the
    // characters before it are themselves meaningful flags for the
    // wrapper in question.
    #[test]
    fn attached_value_flags_skips_unrelated_leading_characters_in_cluster() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "http://localhost",
                    "-SLxhttp://evil.example.com"
                ]))
                .is_some(),
            "multiple unrelated leading characters before the declared letter must not prevent \
             recognition of its glued value"
        );
    }

    // A declared letter that never appears anywhere in the cluster still
    // yields no candidate at all — the scan doesn't manufacture a
    // candidate out of thin air just because SOME character in the
    // cluster happens to be dash-prefixed.
    #[test]
    fn attached_value_flags_no_candidate_when_declared_letter_absent_from_cluster() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "http://localhost",
                    "-sLhttp://evil.invalid"
                ]))
                .is_none(),
            "a cluster containing none of the declared attached_value_flags letters must not \
             spuriously yield a candidate, even with trailing dash-shaped text"
        );
    }

    // A bare cluster ending in the declared letter with nothing glued
    // after it (`-sx`) must not become an empty candidate, the same as
    // the already-tested leading-position bare case.
    #[test]
    fn attached_value_flags_bare_declared_flag_at_end_of_cluster_yields_no_candidate() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "http://localhost", "-sx"]))
                .is_none(),
            "a declared flag at the end of a cluster with nothing glued after it must not \
             become a candidate"
        );
    }

    // A declared flag glued after a long-option-shaped token (`--x...`)
    // must not be treated as a short cluster — that shape belongs to
    // ValueFlag::attached_value_token's `--name=value` handling instead.
    #[test]
    fn attached_value_flags_does_not_treat_long_option_as_a_cluster() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "http://localhost",
                    "--xhttp://evil.example.com"
                ]))
                .is_none(),
            "a `--`-prefixed token must never be scanned as a short-flag cluster"
        );
    }

    // PR #350 (issue #214): the cluster scan's
    // left-to-right search has no notion of which earlier characters are
    // themselves value-taking, so it can split inside an EARLIER flag's
    // own glued value rather than a genuine flag position. Declaring that
    // earlier flag in this rule's `value_flags` closes the gap: the scan
    // stops at the first `value_flags`-declared letter it meets, the same
    // way getopt would treat everything after it as that flag's value.
    #[test]
    fn attached_value_flags_stops_at_a_declared_value_flags_letter_earlier_in_the_cluster() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
            value_flags = ["o"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "http://localhost",
                    "-oxhttp://evil.example.com"
                ]))
                .is_none(),
            "when the earlier flag is declared in value_flags, the scan must stop at it \
             instead of mis-splitting at a later attached_value_flags letter inside its value"
        );
    }

    // PR #350: disclosed limitation, not a silent
    // invariant — the cluster scan CAN newly suppress a rule that used to
    // fire, when a mis-split truncated candidate (from an UNDECLARED
    // earlier flag's glued value) happens to match an except_targets
    // alternative. `-o`'s true value is `Axhttp://localhost`, but the
    // scan finds `x` inside it and manufactures the excepted-looking
    // candidate `http://localhost`, masking the untouched evil target
    // behind `-y`. This is the accepted opt-in trade-off of declaring
    // attached_value_flags for a rule whose other flags aren't all
    // covered by value_flags too.
    #[test]
    fn attached_value_flags_mis_split_can_suppress_an_undeclared_flags_value() {
        let argv_words = argv(&["curl", "-yhttp://evil.test", "-oAxhttp://localhost"]);

        let baseline = Rules::parse(
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
            baseline.match_command(&argv_words).is_some(),
            "baseline (no attached_value_flags declared): the rule correctly fires since \
             http://evil.test is not excepted"
        );

        let with_attached_value_flags = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            with_attached_value_flags
                .match_command(&argv_words)
                .is_none(),
            "disclosed limitation: an undeclared earlier flag's glued value can be mis-split at \
             a later attached_value_flags letter, manufacturing a candidate that matches \
             except_targets and wrongly suppressing the rule despite the untouched evil target"
        );
    }

    // The cluster-position analog of
    // `attached_value_flags_still_excepts_a_declared_flags_genuine_localhost_value`:
    // a genuine localhost value glued into a non-leading cluster position
    // is still correctly excepted, not just a genuine evil one still
    // correctly caught there.
    #[test]
    fn attached_value_flags_cluster_position_still_excepts_a_genuine_localhost_value() {
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&["curl", "-sxhttp://localhost"]))
                .is_none(),
            "a declared flag's genuine value glued into a non-leading cluster position is \
             still correctly excepted, matching the leading-position case"
        );
    }

    #[test]
    fn attached_value_flags_does_not_consume_a_separated_value() {
        // `-x http://evil` (separated, no glue) is a different shape from
        // `-xhttp://evil` (glued) — attached_value_flags only recognises
        // the glued form, so the bare `-x` token itself yields no
        // candidate (same as an undeclared flag) and the following token
        // is untouched: it stays an ordinary positional candidate, caught
        // by the pre-existing target_candidate path exactly as it already
        // was before this field existed.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "http://localhost",
                    "-x",
                    "http://evil.example.com"
                ]))
                .is_some(),
            "a separated flag value must not be consumed by attached_value_flags — it stays a \
             candidate and correctly fails the except_targets check"
        );
    }

    #[test]
    fn attached_value_flags_matches_shape_only_including_a_literal_equals_sign() {
        // attached_value_candidate is shape-based only: it doesn't special
        // -case '=' the way ValueFlag::attached_value_token does for long
        // flags. `-x=http://evil` yields the verbatim candidate
        // `=http://evil...` (leading '=' included), which fails every
        // http://-prefixed except_targets alternative and so correctly
        // fails closed (asks) rather than silently passing through.
        let rules = Rules::parse(
            r#"
            [[command]]
            id = "curl-non-localhost"
            reason = "ask unless curl targets localhost"
            decision = "ask"
            command = "curl"
            except_targets = [{ prefix = "http://localhost" }]
            attached_value_flags = ["x"]
        "#,
        )
        .unwrap();
        assert!(
            rules
                .match_command(&argv(&[
                    "curl",
                    "http://localhost",
                    "-x=http://evil.example.com"
                ]))
                .is_some(),
            "a '-x=value' token's candidate is the verbatim '=value' text, which fails closed \
             against a http://-prefixed except_targets alternative"
        );

        // Discriminates verbatim-candidate handling from an (incorrect)
        // '='-stripping implementation: if the leading '=' were stripped,
        // this token's candidate would become the bare `http://localhost`
        // text, matching the except alternative and wrongly suppressing
        // the rule (a block-to-allow regression). The verbatim candidate
        // `=http://localhost` matches no `http://`-prefixed alternative,
        // so the rule correctly still fires here.
        assert!(
            rules
                .match_command(&argv(&["curl", "-x=http://localhost"]))
                .is_some(),
            "the '=' must not be stripped from the candidate — an implementation that stripped \
             it would wrongly suppress this rule via the except_targets prefix match"
        );
    }

    #[test]
    fn attached_value_flags_with_non_empty_targets_is_rejected_at_rule_load() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            attached_value_flags = ["x"]
            targets = [{ prefix = "http://" }]
            except_targets = [{ prefix = "http://localhost" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // ==== except_targets resolve_symlinks (issue #583) ====

    mod resolve_symlinks {
        use super::*;

        fn resolved(path: &str, is_dir: bool, link_count: u64) -> Result<ResolvedPath, ProbeError> {
            Ok(ResolvedPath {
                path: path.to_string(),
                is_dir,
                link_count,
            })
        }

        /// In-memory stand-in for the filesystem adapter: `/scratch/ok.md`
        /// is a regular file, `/scratch/link.md` a symlink out of the
        /// scratch directory, `/scratch/hard.md` a file with a second hard
        /// link, `/scratch/flat` a directory with a link count of one,
        /// `/tmp/scratch` a directory behind a symlinked `/tmp`, and
        /// everything else (dangling links, files not created yet) fails to
        /// resolve.
        fn fake_canonicalize(path: &str) -> Result<ResolvedPath, ProbeError> {
            match path {
                "/scratch/ok.md" => resolved("/scratch/ok.md", false, 1),
                "/scratch/link.md" => resolved("/outside/secret", false, 1),
                "/scratch/hard.md" => resolved("/scratch/hard.md", false, 2),
                "/scratch/sub" => resolved("/scratch/sub", true, 3),
                "/scratch/flat" => resolved("/scratch/flat", true, 1),
                "/tmp/scratch" => resolved("/private/tmp/scratch", true, 2),
                _ => Err(ProbeError::NotFound),
            }
        }

        fn rules_excepting(dir: &str) -> Rules {
            Rules::parse(&format!(
                r#"
                [[command]]
                id = "upload"
                reason = "ask unless uploading from the scratch dir"
                decision = "ask"
                command = "upload-tool"
                except_targets = [{{ prefix = "{dir}/" }}]
                resolve_symlinks = true
            "#
            ))
            .unwrap()
            .with_path_canonicalizer(PathCanonicalizer::new(fake_canonicalize))
        }

        #[test]
        fn regular_file_under_the_prefix_is_excepted_and_a_symlink_out_is_not() {
            let rules = rules_excepting("/scratch");
            let hit = |path: &str| rules.match_command(&argv(&["upload-tool", path])).is_some();
            assert!(!hit("/scratch/ok.md"));
            assert!(hit("/scratch/link.md"));
            assert!(hit("/scratch/dangling.md"));
            assert!(hit("/scratch/missing.md"));
        }

        #[test]
        fn relative_candidate_resolves_against_base_and_fails_closed_without_one() {
            let rules = rules_excepting("/scratch");
            let words = argv(&["upload-tool", "ok.md"]);
            let scope = |base| SymlinkScope::new(base);
            assert!(
                rules
                    .match_command_in(&words, scope(Some("/scratch")))
                    .is_none()
            );
            assert!(rules.match_command_in(&words, scope(None)).is_some());
            assert!(
                rules
                    .match_command_in(&words, scope(Some("relative")))
                    .is_some()
            );
        }

        #[test]
        fn hard_linked_files_and_directories_fail_closed() {
            let rules = rules_excepting("/scratch");
            let hit = |path: &str| rules.match_command(&argv(&["upload-tool", path])).is_some();
            assert!(hit("/scratch/hard.md"));
            assert!(hit("/scratch/sub"));
            // Refused as a directory even with no extra hard link.
            assert!(hit("/scratch/flat"));
        }

        #[test]
        fn login_and_chdir_wrappers_relocate_the_cwd() {
            for words in [
                &["sudo", "-i", "rm", "-rf", "x"][..],
                &["sudo", "--shell", "rm", "x"],
                &["su", "-", "root", "-c", "rm x"],
                &["su", "-l", "root", "-c", "rm x"],
                &["run0", "-D", "/w", "rm", "x"],
                &["env", "sudo", "-i", "rm", "x"],
            ] {
                assert!(wrapper_chain_changes_cwd(&argv(words)), "{words:?}");
            }
            for words in [
                &["sudo", "rm", "-i", "x"][..],
                &["sudo", "-u", "root", "rm", "x"],
                &["su", "root", "-c", "rm x"],
                &["rm", "-rf", "x"],
            ] {
                assert!(!wrapper_chain_changes_cwd(&argv(words)), "{words:?}");
            }
        }

        #[test]
        fn a_refusing_scope_excepts_nothing() {
            let rules = rules_excepting("/scratch");
            let words = argv(&["upload-tool", "/scratch/ok.md"]);
            let scope = SymlinkScope::new(Some("/scratch")).refusing_all();
            assert!(rules.match_command_in(&words, scope).is_some());
        }

        #[test]
        fn relative_except_entries_are_rejected_at_load() {
            for entry in [
                "{ prefix = \"scratch/\" }",
                "{ exact = \"scratch/ok.md\" }",
                "{ prefix = \"~/scratch/\" }",
                "{ prefix = \"/scratch/\" }, { exact = \"./ok.md\" }",
            ] {
                let toml = format!(
                    "[[command]]\nid = \"x\"\nreason = \"r\"\ncommand = \"c\"\n\
                     except_targets = [{entry}]\nresolve_symlinks = true\n"
                );
                assert!(matches!(
                    Rules::parse(&toml),
                    Err(RulesError::InvalidRule { .. })
                ));
            }
            let relative_without_the_key = "[[command]]\nid = \"x\"\nreason = \"r\"\ncommand = \"c\"\n\
                 except_targets = [{ prefix = \"scratch/\" }]\n";
            assert!(Rules::parse(relative_without_the_key).is_ok());
        }

        #[test]
        fn unresolved_candidate_under_an_excepted_prefix_gets_a_hint() {
            let rules = rules_excepting("/scratch");
            let hint = |path: &str| {
                let words = argv(&["upload-tool", path]);
                let rule = rules.match_command(&words)?;
                rules.unresolved_exception_hint(rule, &words, SymlinkScope::default())
            };
            assert_eq!(
                hint("/scratch/missing.md").as_deref(),
                Some(
                    "; except_targets could not be applied because /scratch/missing.md could not \
                     be resolved (does it exist?)"
                )
            );
            assert_eq!(hint("/scratch/link.md"), None);
            assert_eq!(hint("/scratch/hard.md"), None);
            assert_eq!(hint("/elsewhere/missing.md"), None);
        }

        #[test]
        fn except_entry_that_canonicalizes_to_another_spelling_is_warned_about() {
            let warnings = rules_excepting("/tmp/scratch").resolve_symlinks_spelling_warnings();
            assert_eq!(warnings.len(), 1);
            assert!(warnings[0].contains("\"/tmp/scratch/\""));
            assert!(warnings[0].contains("\"/private/tmp/scratch\""));
            assert!(
                rules_excepting("/scratch/sub")
                    .resolve_symlinks_spelling_warnings()
                    .is_empty()
            );
            assert!(
                rules_excepting("/not/created/yet")
                    .resolve_symlinks_spelling_warnings()
                    .is_empty()
            );
        }

        #[test]
        fn dotdot_candidate_still_fires_alongside_resolution() {
            let rules = rules_excepting("/scratch");
            assert!(
                rules
                    .match_command(&argv(&["upload-tool", "/scratch/../scratch/ok.md"]))
                    .is_some()
            );
        }

        #[test]
        fn without_the_key_matching_stays_lexical() {
            let rules = Rules::parse(
                r#"
                [[command]]
                id = "upload"
                reason = "r"
                decision = "ask"
                command = "upload-tool"
                except_targets = [{ prefix = "/scratch/" }]
            "#,
            )
            .unwrap();
            assert!(
                rules
                    .match_command(&argv(&["upload-tool", "/scratch/missing"]))
                    .is_none()
            );
        }

        #[test]
        fn an_unwired_canonicalizer_fails_closed() {
            let wired = rules_excepting("/scratch");
            let unwired = wired.with_path_canonicalizer(PathCanonicalizer::unavailable());
            assert!(
                unwired
                    .match_command(&argv(&["upload-tool", "/scratch/ok.md"]))
                    .is_some()
            );
        }

        #[test]
        fn rejected_without_path_except_targets_or_on_allow_side_entries() {
            for toml in [
                "[[command]]\nid = \"x\"\nreason = \"r\"\ncommand = \"c\"\nresolve_symlinks = true\n",
                "[[command]]\nid = \"x\"\nreason = \"r\"\ncommand = \"c\"\n\
                 except_targets = [{ url_host = \"localhost\" }]\nresolve_symlinks = true\n",
            ] {
                assert!(matches!(
                    Rules::parse(toml),
                    Err(RulesError::InvalidRule { .. })
                ));
            }
            let allow_entry = "[[entry]]\nid = \"x\"\nreason = \"r\"\ncommand = \"c\"\n\
                 except_targets = [{ prefix = \"/a/\" }]\nresolve_symlinks = true\n";
            assert!(matches!(
                Allowlist::parse(allow_entry),
                Err(RulesError::InvalidRule { .. })
            ));
            let user_allow = "[[allow]]\nid = \"x\"\nreason = \"r\"\ncommand = \"c\"\n\
                 except_targets = [{ prefix = \"/a/\" }]\nresolve_symlinks = true\n";
            assert!(matches!(
                UserConfig::parse(user_allow),
                Err(RulesError::InvalidRule { .. })
            ));
        }
    }

    #[test]
    fn attached_value_flags_without_except_targets_is_rejected_at_rule_load() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            attached_value_flags = ["x"]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn attached_value_flags_conflicting_with_value_flags_is_rejected_at_rule_load() {
        // 'o' declared as both a separated/attached-by-'=' value to
        // exclude (value_flags) and a glued value to include
        // (attached_value_flags) is a contradiction, not a valid
        // combination of two independent narrowings.
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            value_flags = ["o"]
            attached_value_flags = ["o"]
            except_targets = [{ prefix = "http://localhost" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn attached_value_flags_invalid_spec_is_rejected_at_rule_load() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "curl"
            attached_value_flags = ["exclude"]
            except_targets = [{ prefix = "http://localhost" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
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

    // ==== issue #100: user-config `[[redirect]]` entries ====

    #[test]
    fn user_config_parses_redirect() {
        let toml = r#"
            [[redirect]]
            id = "user-redirect-protected-dir"
            reason = "forbid redirecting into this directory"
            targets = [{ prefix = "/protected/" }]
        "#;
        let config = UserConfig::parse(toml).unwrap();
        assert_eq!(config.redirect.len(), 1);
    }

    #[test]
    fn user_config_redirect_requires_at_least_one_target() {
        let toml = r#"
            [[redirect]]
            id = "user-redirect-empty"
            reason = "invalid"
            targets = []
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn match_redirect_target_prefers_block_over_an_earlier_ask() {
        // issue #261: declaration order must not decide the decision.
        let toml = r#"
            [[redirect]]
            id = "ask-first"
            decision = "ask"
            reason = "declared first"
            targets = [{ exact = "/tmp/x" }]

            [[redirect]]
            id = "block-second"
            reason = "declared second"
            targets = [{ exact = "/tmp/x" }]
        "#;
        let rules = Rules::parse(toml).unwrap();
        let rule = rules.match_redirect_target("/tmp/x").unwrap();
        assert_eq!(rule.id().as_str(), "block-second");
    }

    // The downgrade race found in #204 is closed (issue
    // #261 made the redirect path fold worst-wins), but user redirect
    // entries stay Block-only as a conservative posture pending issue
    // #100's own review.
    #[test]
    fn user_config_rejects_ask_decision_redirect_entry() {
        let toml = r#"
            [[redirect]]
            id = "user-redirect-ask"
            reason = "should be rejected"
            decision = "ask"
            targets = [{ prefix = "/tmp/" }]
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn merge_user_config_redirect_entry_matches_a_new_target() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[redirect]]
            id = "user-forbid-redirect-to-secrets"
            reason = "forbid redirecting into ~/secrets"
            targets = [{ normalized_prefix = "~/secrets/" }]
        "#,
        )
        .unwrap();
        let (merged, _) = merge_user_config(blocklist, allowlist, config).unwrap();

        assert!(
            merged
                .match_redirect_target("~/secrets/api-key.txt")
                .is_some()
        );
        assert!(merged.match_redirect_target("~/not-secrets/x").is_none());
    }

    #[test]
    fn merge_user_config_redirect_entry_never_shadows_a_builtin_redirect_rule() {
        // A user rule sharing the embedded config-directory redirect
        // rule's exact target must never win the match ahead of the
        // embedded one: Rules::match_redirect_target is worst-decision-wins
        // with ties keeping the first-declared rule, so merge_user_config
        // appending (not prepending) user redirect rules after the
        // embedded ones is load-bearing here — the
        // reported rule id proves which one actually fired, not just that
        // *a* Block resulted (decision alone can't distinguish them, since
        // `decision = "ask"` on a user redirect entry is rejected at load
        // time — see `user_config_rejects_ask_decision_redirect_entry`).
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[redirect]]
            id = "user-config-redirect-same-target"
            reason = "shadow attempt"
            targets = [{ normalized_prefix = "~/.config/shguard/" }]
        "#,
        )
        .unwrap();
        let (merged, _) = merge_user_config(blocklist, allowlist, config).unwrap();

        let rule = merged
            .match_redirect_target("~/.config/shguard/config.toml")
            .unwrap();
        assert_eq!(rule.id().as_str(), "self-protect-config-redirect-tilde");
        assert_eq!(rule.decision(), Decision::Block);
    }

    #[test]
    fn merge_user_config_rejects_redirect_id_colliding_with_embedded_redirect_id() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[redirect]]
            id = "self-protect-config-redirect-tilde"
            reason = "totally different rule"
            targets = [{ prefix = "/totally-different/" }]
        "#,
        )
        .unwrap();
        assert!(matches!(
            merge_user_config(blocklist, allowlist, config),
            Err(RulesError::DuplicateId(id)) if id == "self-protect-config-redirect-tilde"
        ));
    }

    #[test]
    fn merge_user_config_rejects_deny_id_colliding_with_embedded_token_id() {
        // fable review of #430 (finding #2): `merge_user_config`'s
        // `existing_ids` set was extended with every other embedded rule
        // kind but not `token_rules` -- a user config could silently reuse
        // the shipped token rule's id.
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[deny]]
            id = "token-credential-shaped-assignment"
            reason = "totally different rule"
            command = "totally-different-command"
        "#,
        )
        .unwrap();
        assert!(matches!(
            merge_user_config(blocklist, allowlist, config),
            Err(RulesError::DuplicateId(id)) if id == "token-credential-shaped-assignment"
        ));
    }

    // ==== issue #99: deny_message ====

    #[test]
    fn user_config_deny_entry_parses_deny_message() {
        let toml = r#"
            [[deny]]
            id = "user-deny-force-push"
            reason = "git push --force overwrites remote history"
            command = "git push"
            required_flags = ["f|--force"]
            deny_message = "use --force-with-lease instead"
        "#;
        let config = UserConfig::parse(toml).unwrap();
        assert_eq!(
            config.deny[0].deny_message().unwrap().as_str(),
            "use --force-with-lease instead"
        );
    }

    #[test]
    fn user_config_ask_entry_parses_deny_message() {
        let toml = r#"
            [[ask]]
            id = "user-ask-gh"
            reason = "confirm every gh invocation"
            command = "gh"
            deny_message = "prefer a read-only gh subcommand"
        "#;
        let config = UserConfig::parse(toml).unwrap();
        assert_eq!(
            config.ask[0].deny_message().unwrap().as_str(),
            "prefer a read-only gh subcommand"
        );
    }

    #[test]
    fn user_config_entry_without_deny_message_is_unaffected() {
        let toml = r#"
            [[deny]]
            id = "user-deny-scary"
            reason = "never run this"
            command = "scary-tool"
        "#;
        let config = UserConfig::parse(toml).unwrap();
        assert!(config.deny[0].deny_message().is_none());
    }

    #[test]
    fn user_config_rejects_empty_deny_message() {
        let toml = r#"
            [[deny]]
            id = "user-deny-scary"
            reason = "never run this"
            command = "scary-tool"
            deny_message = ""
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn user_config_rejects_deny_message_on_allow_entry() {
        let toml = r#"
            [[allow]]
            id = "user-allow-ls"
            reason = "read-only, always safe"
            command = "ls"
            deny_message = "no effect here"
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn allowlist_rejects_deny_message_on_entry() {
        let toml = r#"
            [[entry]]
            id = "allow-ls"
            reason = "read-only, always safe"
            command = "ls"
            deny_message = "no effect here"
        "#;
        assert!(matches!(
            Allowlist::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn matched_command_rule_surfaces_deny_message_in_the_verdict() {
        let toml = r#"
            [[command]]
            id = "deny-force-push"
            reason = "force push overwrites remote history"
            command = "git push"
            required_flags = ["f|--force"]
            deny_message = "use --force-with-lease instead"
        "#;
        let rules = Rules::parse(toml).unwrap();
        let rule = rules
            .match_command(&argv(&["git", "push", "--force", "origin", "main"]))
            .unwrap();
        assert_eq!(
            rule.deny_message().unwrap().as_str(),
            "use --force-with-lease instead"
        );
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

    // Issue #346: a versioned interpreter spelling must be rejected the
    // same way its unversioned form already is — the gate now treats it as
    // the same interpreter via `strip_version_suffix`, so an allow entry
    // naming it exactly would otherwise suppress the same recursion-derived
    // `Ask`s an exact `command = "bash"` entry is already rejected for.
    #[test]
    fn user_config_rejects_allow_entry_matching_versioned_interpreter_exactly() {
        for versioned in ["bash5", "python3.12", "ksh93", "ruby3.2"] {
            let toml = format!(
                r#"
                [[allow]]
                id = "user-allow-versioned"
                reason = "trust me"
                command = "{versioned}"
                "#
            );
            assert!(
                matches!(
                    UserConfig::parse(&toml),
                    Err(RulesError::InvalidRule { .. })
                ),
                "expected {versioned:?} to be rejected as a dangerous allow target"
            );
        }
    }

    // A command name that merely happens to end in digits, with no real
    // interpreter base once stripped, must still be accepted — the same
    // false-positive-avoidance guarantee `strip_version_suffix` gives the
    // gate's own matching.
    #[test]
    fn user_config_accepts_allow_entry_for_command_ending_in_digits() {
        let toml = r#"
            [[allow]]
            id = "user-allow-b2"
            reason = "trust me"
            command = "b2"
        "#;
        assert!(UserConfig::parse(toml).is_ok());
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

    // Issue #120: `eval` joined `EVAL_BUILTIN`, its own recursion-derived Ask
    // must be just as unsuppressable as `bash -c`'s.
    #[test]
    fn user_config_rejects_allow_entry_matching_eval_exactly() {
        let toml = r#"
            [[allow]]
            id = "user-allow-eval"
            reason = "trust me"
            command = "eval"
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // Issue #451: AWK_INTERPRETERS joined the candidate list, so an awk
    // family member's own recursion-derived Ask (rule 6d, un-introspectable
    // script) must be just as unsuppressable as `eval`'s.
    #[test]
    fn user_config_rejects_allow_entry_matching_awk_family_exactly() {
        for awk in AWK_INTERPRETERS {
            let toml = format!(
                r#"
                [[allow]]
                id = "user-allow-awk"
                reason = "trust me"
                command = "{awk}"
                "#
            );
            assert!(
                matches!(
                    UserConfig::parse(&toml),
                    Err(RulesError::InvalidRule { .. })
                ),
                "expected {awk:?} to be rejected as a dangerous allow target"
            );
        }
    }

    // Issue #493: a case-variant allow entry (`AWK`, `BASH`) must be
    // rejected exactly like the lowercase spelling, since a case-insensitive
    // filesystem resolves both to the same binary.
    #[test]
    fn user_config_rejects_allow_entry_matching_awk_family_case_variant() {
        let toml = r#"
            [[allow]]
            id = "user-allow-awk-upper"
            reason = "trust me"
            command = "AWK"
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn user_config_rejects_allow_entry_matching_bash_case_variant() {
        let toml = r#"
            [[allow]]
            id = "user-allow-bash-upper"
            reason = "trust me"
            command = "BASH"
        "#;
        assert!(matches!(
            UserConfig::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // Issue #493: a case-variant interpreter name resolves to the same
    // binary as the lowercase spelling on a case-insensitive filesystem
    // (macOS APFS default), so recognition must not depend on case.
    #[test]
    fn is_shell_interpreter_is_case_insensitive() {
        assert!(is_shell_interpreter("bash"));
        assert!(is_shell_interpreter("BASH"));
        assert!(is_shell_interpreter("Bash"));
    }

    #[test]
    fn is_pipeline_interpreter_is_case_insensitive() {
        assert!(is_pipeline_interpreter("python3"));
        assert!(is_pipeline_interpreter("PYTHON3"));
    }

    #[test]
    fn is_stdin_script_interpreter_is_case_insensitive() {
        assert!(is_stdin_script_interpreter("python3"));
        assert!(is_stdin_script_interpreter("PYTHON3"));
    }

    // Issue #493 follow-up: a fable code-reviewer pass proved macOS APFS's
    // case-insensitive collation is full Unicode case folding, not ASCII
    // lowercasing alone -- these fold to the same inode as their plain
    // spelling on that filesystem. Written as `\u{...}` escapes, not
    // literal glyphs: an editor or terminal NFC-normalizing the source
    // would silently turn the Kelvin-sign/ligature cases into ASCII ones
    // and defeat the point of the test.
    #[test]
    fn fold_command_name_covers_known_apfs_case_folds() {
        assert_eq!(fold_command_name("\u{017F}h"), "sh"); // ſh -> sh (long s)
        assert_eq!(fold_command_name("aw\u{212A}"), "awk"); // awK (Kelvin) -> awk
        assert_eq!(fold_command_name("\u{FB01}sh"), "fish"); // ﬁsh -> fish
        assert_eq!(fold_command_name("\u{FB02}ock"), "flock"); // ﬂock -> flock
        assert_eq!(fold_command_name("ba\u{00DF}"), "bass"); // baß -> bass
        assert_eq!(fold_command_name("be\u{FB06}"), "best"); // beﬆ -> best
        // ẞ (U+1E9E, uppercase sharp s) lowercases to ß first, then folds
        // to "ss" -- pins the doc's own ordering claim, not just ß itself.
        assert_eq!(fold_command_name("ba\u{1E9E}"), "bass"); // baẞ -> bass
        assert_eq!(fold_command_name("a\u{FB03}x"), "affix"); // aﬃx -> affix
    }

    #[test]
    fn is_shell_interpreter_covers_ligature_fold() {
        assert!(is_shell_interpreter("\u{FB01}sh")); // ﬁsh
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

    // Issue #493: a case-variant prefix must be rejected exactly like the
    // lowercase spelling, exercising `matches_dangerous_allow_target`'s
    // `Prefix` branch specifically (`Exact` alone was covered above).
    #[test]
    fn user_config_rejects_allow_entry_whose_uppercase_prefix_captures_a_shell_interpreter() {
        let toml = r#"
            [[allow]]
            id = "user-allow-ba-prefix-upper"
            reason = "trust me"
            command_prefix = "BA"
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
    fn user_config_rejects_allow_entry_matching_busybox_toybox_and_coreutils() {
        // Issue #114: busybox became an exec wrapper, so an
        // `[[allow]] command = "busybox"` entry must be rejected the same
        // way `env`'s is above — otherwise it would launder every
        // busybox-wrapped Ask/Block floor to Allow.
        for wrapper in ["busybox", "toybox", "coreutils"] {
            let toml = format!(
                r#"
                [[allow]]
                id = "user-allow-{wrapper}"
                reason = "trust me"
                command = "{wrapper}"
                "#
            );
            assert!(
                matches!(
                    UserConfig::parse(&toml),
                    Err(RulesError::InvalidRule { .. })
                ),
                "{wrapper}"
            );
        }
    }

    #[test]
    fn user_config_allow_entry_for_subcommand_gated_wrapper_loads_but_pure_wrapper_is_rejected() {
        // Issue #740: `npm`, `docker` and the like wrap a command only for
        // one subcommand, so their allow entries keep loading; `npx`, `ssh`
        // and `gtimeout` wrap every call.
        for (name, loads) in [
            ("npm", true),
            ("docker", true),
            ("tmux", true),
            ("npx", false),
            ("ssh", false),
            ("sshpass", false),
            ("gtimeout", false),
        ] {
            let toml = format!(
                r#"
                [[allow]]
                id = "user-allow-{name}"
                reason = "trust me"
                command = "{name}"
                "#
            );
            assert_eq!(UserConfig::parse(&toml).is_ok(), loads, "{name}");
        }
    }

    #[test]
    fn user_config_rejects_allow_entry_matching_builtin() {
        // Issue #245: builtin became an exec wrapper, so an
        // `[[allow]] command = "builtin"` entry must be rejected the same
        // way busybox's/env's is above — otherwise it would launder every
        // builtin-wrapped Ask/Block floor to Allow.
        let toml = r#"
            [[allow]]
            id = "user-allow-builtin"
            reason = "trust me"
            command = "builtin"
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

    // ==== issue #449: `case_insensitive` target matcher flag ====

    // `case_insensitive` only makes sense alongside `normalized`/
    // `normalized_prefix` — a byte-literal `exact`/`prefix` target has no
    // normalization step to fold case within.
    #[test]
    fn case_insensitive_without_normalized_target_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "tar"
            targets = [{ exact = "/tmp", case_insensitive = true }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    // Setup B of issue #449's reproduction table: a `normalized_prefix`
    // self-protection-style rule with `case_insensitive = true` must still
    // match a token that only differs from the protected directory by
    // ASCII case (macOS APFS's default case-insensitive-but-preserving
    // volumes resolve both spellings to the same on-disk file).
    #[test]
    fn normalized_prefix_case_insensitive_matches_recased_token() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[deny]]
            id = "user-deny-recased-prefix"
            reason = "test"
            command = "tee"
            targets = [{ normalized_prefix = "/Users/h/.config/shguard/", case_insensitive = true }]
        "#,
        )
        .unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, config).unwrap();

        let matches = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules.match_command(&words).is_some()
        };

        assert!(matches(&["tee", "/Users/h/.config/shguard/config.toml"]));
        assert!(matches(&["tee", "/USERS/H/.CONFIG/SHGUARD/config.toml"]));
        assert!(!matches(&["tee", "/Users/h/.config/other/config.toml"]));
    }

    // The default (`case_insensitive` unset, i.e. `false`) must stay
    // byte-exact — a re-cased spelling of the same `normalized_prefix`
    // target must NOT match, the pre-issue-#449 behavior every ordinary
    // (non-macOS-self-protection) rule keeps.
    #[test]
    fn normalized_prefix_without_case_insensitive_stays_byte_exact() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[deny]]
            id = "user-deny-case-sensitive-prefix"
            reason = "test"
            command = "tee"
            targets = [{ normalized_prefix = "/Users/h/.config/shguard/" }]
        "#,
        )
        .unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, config).unwrap();

        let words: Vec<NormalizedWord> = ["tee", "/USERS/H/.CONFIG/SHGUARD/config.toml"]
            .iter()
            .map(|w| NormalizedWord::resolved(*w))
            .collect();
        assert!(rules.match_command(&words).is_none());
    }

    // Regression for the #542 review: runtime argv names are folded before
    // matching, so a user rule's own `command`/`command_prefix` must be
    // stored folded too, or an uppercase rule name never matches anything.
    #[test]
    fn user_deny_with_uppercase_command_matches_any_casing() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[deny]]
            id = "user-deny-rscript"
            reason = "test"
            command = "Rscript"

            [[deny]]
            id = "user-deny-prefix"
            reason = "test"
            command_prefix = "Mk"
            required_tokens = ["Sub"]
        "#,
        )
        .unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, config).unwrap();

        let matches = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules.match_command(&words).is_some()
        };

        for name in ["Rscript", "rscript", "RSCRIPT", "/usr/bin/Rscript"] {
            assert!(matches(&[name, "-e", "1"]), "{name}");
        }
        for name in ["Mkfoo", "mkfoo", "MKFOO"] {
            assert!(matches(&[name, "Sub"]), "{name}");
        }
        // Required tokens (subcommands) stay case-sensitive.
        assert!(!matches(&["mkfoo", "sub"]));
    }

    // Same case-folded comparison for `normalized` (`NormalizedExact`) —
    // covers the ancestor-directory self-protection rules
    // (`crate::config::ancestor_rules_toml`), which use `normalized`
    // rather than `normalized_prefix`.
    #[test]
    fn normalized_case_insensitive_matches_recased_token() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[deny]]
            id = "user-deny-recased-exact"
            reason = "test"
            command = "rm"
            targets = [{ normalized = "/Users/h/.config", case_insensitive = true }]
        "#,
        )
        .unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, config).unwrap();

        let matches = |argv: &[&str]| {
            let words: Vec<NormalizedWord> =
                argv.iter().map(|w| NormalizedWord::resolved(*w)).collect();
            rules.match_command(&words).is_some()
        };

        assert!(matches(&["rm", "/Users/h/.config"]));
        assert!(matches(&["rm", "/USERS/H/.CONFIG"]));
        assert!(!matches(&["rm", "/Users/h/.config-other"]));
    }

    // `case_insensitive` is a parse-time TOML flag, not gated on the host
    // OS running this test — so `rules/blocklist.toml`'s own static
    // `~`-literal self-protection rules (which now carry it, issue #449
    // review follow-up) can be exercised on any platform, including
    // Linux CI, even though the flag only ever gets SET on macOS by
    // `crate::config`'s generated rules.
    #[test]
    fn embedded_tilde_self_protection_matches_recased_path() {
        let blocklist = Rules::embedded().unwrap();
        let words: Vec<NormalizedWord> = ["tee", "~/.CONFIG/SHGUARD/config.toml"]
            .iter()
            .map(|w| NormalizedWord::resolved(*w))
            .collect();
        assert!(blocklist.match_command(&words).is_some());
    }

    #[test]
    fn embedded_tilde_ancestor_self_protection_matches_recased_path() {
        let blocklist = Rules::embedded().unwrap();
        let words: Vec<NormalizedWord> = ["rm", "-r", "~/.CONFIG"]
            .iter()
            .map(|w| NormalizedWord::resolved(*w))
            .collect();
        assert_eq!(
            blocklist.match_command(&words).map(CommandRule::decision),
            Some(Decision::Ask)
        );
    }

    // `case_insensitive` must also be honored by the Ask-only floors
    // (`unknown_cwd_plausible`/`ascent_descent_plausible`), not just
    // `Self::matches`'s certain-match path — otherwise a case-folded
    // self-protection rule would still miss a re-cased token under a
    // poisoned/unknown cwd (issue #449 review follow-up).
    #[test]
    fn ascent_descent_floor_honors_case_insensitive() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[deny]]
            id = "user-deny-recased-ascent-descent"
            reason = "test"
            command = "tee"
            targets = [{ normalized = "~/mystuff", case_insensitive = true }]
        "#,
        )
        .unwrap();
        let (rules, _) = merge_user_config(blocklist, allowlist, config).unwrap();

        let words: Vec<NormalizedWord> = ["tee", "../MYSTUFF"]
            .iter()
            .map(|w| NormalizedWord::resolved(*w))
            .collect();
        let rule = rules.match_command_ascent_descent(&words).unwrap();
        assert_eq!(rule.id().as_str(), "user-deny-recased-ascent-descent");
    }

    // ==== issue #427: `normalized_basename` target matcher ====

    fn dotenv_family_rule() -> &'static str {
        r#"
            [[command]]
            id = "cat-dotenv-family"
            reason = "test"
            command = "cat"
            targets = [{ normalized_basename = ".env" }]
        "#
    }

    #[test]
    fn normalized_basename_matches_the_bare_filename() {
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(rules.match_command(&argv(&["cat", ".env"])).is_some());
    }

    #[test]
    fn normalized_basename_matches_under_a_relative_directory_prefix() {
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["cat", "foo/.env.local"]))
                .is_some()
        );
    }

    #[test]
    fn normalized_basename_matches_under_a_home_anchored_prefix() {
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["cat", "~/p/.env.production"]))
                .is_some()
        );
    }

    #[test]
    fn normalized_basename_matches_under_an_absolute_prefix() {
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(rules.match_command(&argv(&["cat", "/abs/.env"])).is_some());
    }

    #[test]
    fn normalized_basename_matches_through_an_unresolved_ascent() {
        // Issue #427: unlike `normalized`/`normalized_prefix`, this needs
        // no separate Ask-only ascent-descent floor -- the trailing
        // filename is already a hard match regardless of the unknown
        // ascent depth.
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(rules.match_command(&argv(&["cat", "../.env"])).is_some());
    }

    #[test]
    fn normalized_basename_matches_through_an_escaped_home() {
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(rules.match_command(&argv(&["cat", "~/../.env"])).is_some());
    }

    #[test]
    fn normalized_basename_matches_through_an_unresolved_dirstack_anchor() {
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(rules.match_command(&argv(&["cat", "~+/.env"])).is_some());
    }

    // `PathForm::NamedUserHomeSub` (issue #427): unlike the
    // anchor-comparing matchers, an unreachable/nonexistent account still
    // spells a definite trailing filename.

    #[test]
    fn normalized_basename_matches_a_named_user_home_subdirectory() {
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["cat", "~alice/.env"]))
                .is_some()
        );
        assert!(
            rules
                .match_command(&argv(&["cat", "~alice/foo/.env"]))
                .is_some()
        );
    }

    #[test]
    fn normalized_basename_does_not_match_a_bare_named_user_home() {
        // No tail at all -- nothing to compare a filename against.
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(rules.match_command(&argv(&["cat", "~alice"])).is_none());
        assert!(rules.match_command(&argv(&["cat", "~alice/"])).is_none());
    }

    #[test]
    fn normalized_basename_matches_with_an_attached_strip_prefix() {
        let toml = r#"
            [[command]]
            id = "cat-dotenv-family-attached"
            reason = "test"
            command = "cat"
            targets = [{ strip = "--file=", normalized_basename = ".env" }]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["cat", "--file=foo/.env.local"]))
                .is_some()
        );
    }

    #[test]
    fn normalized_basename_works_in_a_redirect_rule_too() {
        let toml = r#"
            [[redirect]]
            id = "user-forbid-redirect-to-dotenv-family"
            reason = "test"
            targets = [{ normalized_basename = ".env" }]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(rules.match_redirect_target("foo/.env.local").is_some());
        assert!(rules.match_redirect_target("foo/config.toml").is_none());
    }

    #[test]
    fn normalized_basename_does_not_match_an_unrelated_dotted_name() {
        let rules = Rules::parse(dotenv_family_rule()).unwrap();
        assert!(
            rules
                .match_command(&argv(&["cat", "foo/.environment"]))
                .is_none()
        );
        assert!(rules.match_command(&argv(&["cat", ".envrc"])).is_none());
        assert!(rules.match_command(&argv(&["cat", "env"])).is_none());
    }

    #[test]
    fn normalized_basename_dotted_suffix_widening_is_documented_behavior() {
        // The trap: a dotted-suffix widening this broad also matches
        // `id_rsa.pub` for a `normalized_basename = "id_rsa"` rule --
        // pinned as intentional, not a bug, per the variant's own docs.
        let toml = r#"
            [[command]]
            id = "cat-id-rsa"
            reason = "test"
            command = "cat"
            targets = [{ normalized_basename = "id_rsa" }]
        "#;
        let rules = Rules::parse(toml).unwrap();
        assert!(
            rules
                .match_command(&argv(&["cat", "~/.ssh/id_rsa.pub"]))
                .is_some()
        );
    }

    #[test]
    fn normalized_basename_rejects_empty_value_at_load_time() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "test"
            command = "cat"
            targets = [{ normalized_basename = "" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn normalized_basename_rejects_a_value_containing_a_slash() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "test"
            command = "cat"
            targets = [{ normalized_basename = "a/b" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
    }

    #[test]
    fn normalized_basename_rejects_dot_and_dotdot() {
        for base in [".", ".."] {
            let toml = format!(
                r#"
                [[command]]
                id = "x"
                reason = "test"
                command = "cat"
                targets = [{{ normalized_basename = "{base}" }}]
            "#
            );
            assert!(matches!(
                Rules::parse(&toml),
                Err(RulesError::InvalidRule { .. })
            ));
        }
    }

    #[test]
    fn except_targets_normalized_basename_is_rejected() {
        let toml = r#"
            [[command]]
            id = "x"
            reason = "some reason"
            command = "tar"
            targets = [{ normalized = "/" }]
            except_targets = [{ normalized_basename = ".env" }]
        "#;
        assert!(matches!(
            Rules::parse(toml),
            Err(RulesError::InvalidRule { .. })
        ));
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

    // ==== issue #97: user-config `[[pipeline]]` entries ====

    #[test]
    fn merge_user_config_pipeline_entry_matches_a_new_shape() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[pipeline]]
            id = "user-forbid-curl-python"
            reason = "forbid piping a downloaded script into python3"
            decision = "block"
            sources = ["curl"]
            sinks = ["python3"]
        "#,
        )
        .unwrap();
        let (merged, _) = merge_user_config(blocklist, allowlist, config).unwrap();

        let stages = vec![argv(&["curl", "http://x/install.py"]), argv(&["python3"])];
        let rule = merged.match_pipeline(&stages).unwrap();
        assert_eq!(rule.id().as_str(), "user-forbid-curl-python");
        assert_eq!(rule.decision(), Decision::Block);
    }

    #[test]
    fn merge_user_config_pipeline_entry_never_shadows_a_builtin_pipeline_rule() {
        // A user rule sharing the embedded curl-wget-pipe-to-shell rule's
        // exact sources/sinks shape, but with a weaker `ask` decision, must
        // never win the match: Rules::match_pipeline folds worst-wins
        // (issue #465), so the embedded Block outranks the user Ask
        // regardless of declaration order.
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[pipeline]]
            id = "user-weaker-curl-sh"
            reason = "shadow attempt"
            decision = "ask"
            sources = ["curl"]
            sinks = ["sh"]
        "#,
        )
        .unwrap();
        let (merged, _) = merge_user_config(blocklist, allowlist, config).unwrap();

        let stages = vec![argv(&["curl", "http://x/install.sh"]), argv(&["sh"])];
        let rule = merged.match_pipeline(&stages).unwrap();
        assert_eq!(rule.id().as_str(), "curl-wget-pipe-to-shell");
        assert_eq!(rule.decision(), Decision::Block);
    }

    #[test]
    fn merge_user_config_rejects_pipeline_id_colliding_with_embedded_pipeline_id() {
        let blocklist = Rules::embedded().unwrap();
        let allowlist = Allowlist::embedded().unwrap();
        let config = UserConfig::parse(
            r#"
            [[pipeline]]
            id = "curl-wget-pipe-to-shell"
            reason = "totally different rule"
            decision = "block"
            sources = ["totally-different"]
            sinks = ["also-different"]
        "#,
        )
        .unwrap();
        assert!(matches!(
            merge_user_config(blocklist, allowlist, config),
            Err(RulesError::DuplicateId(id)) if id == "curl-wget-pipe-to-shell"
        ));
    }

    #[test]
    fn user_config_pipeline_entry_with_allow_decision_is_rejected() {
        assert!(matches!(
            UserConfig::parse(
                r#"
                [[pipeline]]
                id = "user-pipeline-allow"
                reason = "invalid"
                decision = "allow"
                sources = ["curl"]
                sinks = ["python3"]
            "#,
            ),
            Err(RulesError::InvalidRule { .. })
        ));
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
        let scope = SymlinkScope::default();
        assert!(
            merged
                .match_ask_in(&argv(&["gh", "pr", "view"]), scope)
                .is_some()
        );
        assert!(merged.match_ask_in(&argv(&["ls"]), scope).is_none());
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

    // ==== Issue #579: role counting and literal-tail pruning ====

    fn quoted_unresolved() -> NormalizedWord {
        NormalizedWord::unresolvable_single_word(
            crate::normalize::UnresolvableKind::ParameterExpansion,
        )
    }

    fn quoted_with_tail(tail: &str) -> NormalizedWord {
        quoted_unresolved().with_literal_tail(tail)
    }

    fn synthetic(flags: &str, target: &str) -> Rules {
        Rules::parse(&format!(
            r#"
            [[command]]
            id = "widget-rule"
            reason = "synthetic"
            decision = "ask"
            command = "widget"
            {flags}
            targets = [{target}]
        "#
        ))
        .unwrap()
    }

    fn except_target_fires(rules: &Rules, words: &[NormalizedWord]) -> bool {
        let mut cmd = vec![NormalizedWord::resolved("widget")];
        cmd.extend_from_slice(words);
        rules
            .command_rules
            .iter()
            .chain(rules.ask_rules.iter())
            .any(|r| r.matches_except_target(&cmd))
    }

    #[test]
    fn literal_tail_component_needs_a_slash_before_a_plain_last_component() {
        assert_eq!(literal_tail_component("/p"), Some("p"));
        assert_eq!(literal_tail_component("a/b/p//"), Some("p"));
        assert_eq!(literal_tail_component("/p/"), Some("p"));
        for unprovable in [
            "", "p", "/", "//", "/p/.", "/p/..", "/..", "/.", "/p*", "/p?", "/[p]", "x/p\0",
        ] {
            assert_eq!(literal_tail_component(unprovable), None, "{unprovable:?}");
        }
    }

    #[test]
    fn sed_lone_quoted_word_cannot_fill_two_roles() {
        let rules = Rules::embedded().unwrap();
        for tail in [&["-n", "1,5p"][..], &["s/x/y/"][..], &[][..]] {
            let mut cmd = argv(&["sed"]);
            cmd.extend(argv(tail));
            cmd.push(quoted_unresolved());
            assert!(
                rules.match_command_except_target(&cmd).is_none(),
                "{tail:?}"
            );
        }
    }

    #[test]
    fn sed_floor_keeps_firing_for_unquoted_two_word_and_resolved_role_shapes() {
        let rules = Rules::embedded().unwrap();
        let unquoted =
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion);
        let id = |cmd: &[NormalizedWord]| {
            rules
                .match_command_except_target(cmd)
                .map(|r| r.id().as_str().to_string())
        };
        let sed = "self-protect-config-sed-tilde";
        // unquoted twins
        let mut cmd = argv(&["sed", "-n", "1,5p"]);
        cmd.push(unquoted.clone());
        assert_eq!(id(&cmd).as_deref(), Some(sed));
        let mut cmd = argv(&["sed"]);
        cmd.push(unquoted);
        assert_eq!(id(&cmd).as_deref(), Some(sed));
        // two quoted words: one flag, one target
        let mut cmd = argv(&["sed", "-n", "1,5p"]);
        cmd.extend([quoted_unresolved(), quoted_unresolved()]);
        assert_eq!(id(&cmd).as_deref(), Some(sed));
        // attached-value flag spellings, target hidden
        for flag in ["-i", "-i.bak", "--in-place=.bak"] {
            let mut cmd = argv(&["sed", flag, "1p"]);
            cmd.push(quoted_unresolved());
            assert_eq!(id(&cmd).as_deref(), Some(sed), "{flag}");
        }
        // target resolved, flag hidden
        let mut cmd = argv(&["sed"]);
        cmd.push(quoted_unresolved());
        cmd.push(NormalizedWord::resolved("~/.config/shguard/config.toml"));
        assert_eq!(id(&cmd).as_deref(), Some(sed));
        // quoted arithmetic is not single_word by construction
        let mut cmd = argv(&["sed", "-n", "1,5p"]);
        cmd.push(NormalizedWord::unresolvable(
            crate::normalize::UnresolvableKind::ArithmeticExpansion,
        ));
        assert_eq!(id(&cmd).as_deref(), Some(sed));
    }

    #[test]
    fn role_counting_is_skipped_when_a_target_can_double_as_a_flag() {
        // relative `.` target, bare `/` target (`-x/../..`), a strip target
        // (`-C/`) and a basename target (`-x/.env`) can all be reached by
        // a `-`-leading token, so one word may fill both roles.
        for target in [
            r#"{ normalized = "." }"#,
            r#"{ normalized = "/" }"#,
            r#"{ strip = "-C", normalized = "/" }"#,
            r#"{ normalized_basename = ".env" }"#,
        ] {
            let rules = synthetic(r#"required_flags = ["x"]"#, target);
            assert!(
                except_target_fires(&rules, &[quoted_unresolved()]),
                "{target}"
            );
        }
        // an anchored target without strip cannot
        let rules = synthetic(r#"required_flags = ["x"]"#, r#"{ normalized = "/etc" }"#);
        assert!(!except_target_fires(&rules, &[quoted_unresolved()]));
        let rules = synthetic(
            r#"required_flags = ["x"]"#,
            r#"{ normalized_prefix = "/etc/" }"#,
        );
        assert!(!except_target_fires(&rules, &[quoted_unresolved()]));
        // required_tokens disable it
        let rules = synthetic(
            r#"required_tokens = ["go"]
            required_flags = ["x"]"#,
            r#"{ normalized = "/etc" }"#,
        );
        assert!(except_target_fires(&rules, &[quoted_unresolved()]));
    }

    #[test]
    fn literal_tail_prunes_only_when_no_target_can_match() {
        let rules = synthetic(
            r#"required_flags = ["C"]"#,
            r#"{ strip = "-C", normalized = "/" }, { normalized = "~" }, { normalized = "/etc/shadow" }"#,
        );
        let c = NormalizedWord::resolved("-C");
        // provably not `/`, `~` or `/etc/shadow`
        assert!(!except_target_fires(
            &rules,
            &[c.clone(), quoted_with_tail("/p")]
        ));
        assert!(!except_target_fires(
            &rules,
            &[c.clone(), quoted_with_tail("/a/b/p//")]
        ));
        // the final component equals a target's own last component
        assert!(except_target_fires(
            &rules,
            &[c.clone(), quoted_with_tail("/shadow")]
        ));
        // a literal `~` head can still be the tilde-anchored `~/../p` form
        let tilde_head = quoted_with_tail("/p").with_literal_head_tilde(true);
        assert!(except_target_fires(&rules, &[c.clone(), tilde_head]));
        // no slash before the component, `.`/`..`, glob and extglob
        // characters, a non-plain component, no tail
        for tail in [
            "p", "/p/.", "/p/..", "/..", "/p*", "/", "/@(p)", "/+(p)", "/!(p)", "/p~", "/pé",
        ] {
            assert!(
                except_target_fires(&rules, &[c.clone(), quoted_with_tail(tail)]),
                "{tail}"
            );
        }
        assert!(except_target_fires(
            &rules,
            &[c.clone(), quoted_unresolved()]
        ));
        // unquoted: an earlier split field is unconstrained
        let unquoted =
            NormalizedWord::unresolvable(crate::normalize::UnresolvableKind::ParameterExpansion)
                .with_literal_tail("/p");
        assert!(except_target_fires(&rules, &[c.clone(), unquoted]));
        // a second unresolved word with no tail keeps the floor
        assert!(except_target_fires(
            &rules,
            &[c.clone(), quoted_with_tail("/p"), quoted_unresolved()]
        ));
    }

    #[test]
    fn role_counting_keeps_the_floor_for_a_plausibility_floor_target() {
        let rules = synthetic(
            r#"required_flags = ["x"]"#,
            r#"{ normalized = "~/.config/x" }"#,
        );
        for operand in ["~/../alice/.config/x", "~+/.config/x", "../alice/.config/x"] {
            assert!(
                except_target_fires(
                    &rules,
                    &[quoted_unresolved(), NormalizedWord::resolved(operand)]
                ),
                "{operand}"
            );
        }
        assert!(!except_target_fires(
            &rules,
            &[quoted_unresolved(), NormalizedWord::resolved("notes.txt")]
        ));
    }

    #[test]
    fn composed_and_unknown_cwd_probes_never_prune_the_home_target() {
        let rules = synthetic(r#"required_flags = ["C"]"#, r#"{ normalized = "~" }"#);
        let mut cmd = vec![NormalizedWord::resolved("widget")];
        cmd.push(NormalizedWord::resolved("-C"));
        cmd.push(quoted_with_tail("/p"));
        let rule = rules
            .command_rules
            .iter()
            .chain(rules.ask_rules.iter())
            .next()
            .unwrap();
        assert!(!rule.matches_except_target(&cmd));
        assert!(rule.matches_except_target_composed(&cmd));
        assert!(rule.matches_except_target_unknown_cwd(&cmd));
    }

    #[test]
    fn literal_tail_never_prunes_a_prefix_target() {
        let rules = synthetic(
            r#"required_flags = ["x"]"#,
            r#"{ normalized_prefix = "/etc/" }"#,
        );
        let x = NormalizedWord::resolved("-x");
        assert!(except_target_fires(&rules, &[x, quoted_with_tail("/p")]));
    }

    #[test]
    fn literal_tail_basename_target_prunes_a_different_final_component() {
        let rules = synthetic(
            r#"required_flags = ["x"]"#,
            r#"{ normalized_basename = ".env" }"#,
        );
        let x = NormalizedWord::resolved("-x");
        assert!(!except_target_fires(
            &rules,
            &[x.clone(), quoted_with_tail("/notes")]
        ));
        assert!(except_target_fires(
            &rules,
            &[x.clone(), quoted_with_tail("/.env")]
        ));
        assert!(except_target_fires(
            &rules,
            &[x, quoted_with_tail("/.env.local")]
        ));
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

    // ==== Issue #426: [[token]] rule loading ====

    #[test]
    fn token_rule_with_empty_patterns_is_rejected_at_load_time() {
        let toml = r#"
            [[token]]
            id = "test-token"
            reason = "test"
            patterns = []
        "#;
        let err = Rules::parse(toml).unwrap_err();
        let RulesError::InvalidRule { problem, .. } = &err else {
            panic!("expected InvalidRule, got {err:?}");
        };
        assert!(problem.contains("pattern"), "got {problem:?}");
    }

    #[test]
    fn token_rule_with_an_empty_pattern_string_is_rejected_at_load_time() {
        let toml = r#"
            [[token]]
            id = "test-token"
            reason = "test"
            patterns = [""]
        "#;
        assert!(Rules::parse(toml).is_err());
    }

    #[test]
    fn token_rule_with_a_nul_in_a_pattern_is_rejected_at_load_time() {
        // fable review round 2 of #430 (finding F6): the NUL-pattern
        // rejection landed with no dedicated test.
        let toml =
            "[[token]]\nid = \"test-token\"\nreason = \"test\"\npatterns = [\"a\\u0000b\"]\n";
        let err = Rules::parse(toml).unwrap_err();
        let RulesError::InvalidRule { problem, .. } = &err else {
            panic!("expected InvalidRule, got {err:?}");
        };
        assert!(problem.contains("NUL"), "got {problem:?}");
    }

    #[test]
    fn token_rule_loads_and_matches_a_credential_shaped_assignment_name() {
        let toml = r#"
            [[token]]
            id = "test-token"
            reason = "test"
            decision = "ask"
            patterns = ["_SECRET="]
        "#;
        let rules = Rules::parse(toml).unwrap();
        let rule = rules.match_token(&["MY_SECRET=".to_string()]).unwrap();
        assert_eq!(rule.id().as_str(), "test-token");
        assert_eq!(rule.decision(), Decision::Ask);
    }

    /// `match_token` is worst-decision-wins: a Block rule declared AFTER an
    /// Ask rule sharing a pattern must still win. Pins the shared
    /// `worst_wins` loop against a regression to first-match-wins (the
    /// embedded blocklist has only one `[[token]]`, so nothing else
    /// exercises two token rules at once).
    #[test]
    fn match_token_block_outranks_an_earlier_declared_ask() {
        let toml = r#"
            [[token]]
            id = "ask-first"
            reason = "test"
            decision = "ask"
            patterns = ["_SECRET="]

            [[token]]
            id = "block-second"
            reason = "test"
            decision = "block"
            patterns = ["_SECRET="]
        "#;
        let rules = Rules::parse(toml).unwrap();
        let rule = rules.match_token(&["MY_SECRET=".to_string()]).unwrap();
        assert_eq!(rule.id().as_str(), "block-second");
        assert_eq!(rule.decision(), Decision::Block);
    }
}
