//! The loader's error type.

use thiserror::Error;

/// A problem found while loading catalog files. Every variant names the file
/// and where in it: a row (its key joined with spaces) or a rule (its id).
#[derive(Debug, Error)]
pub enum LoadError {
    /// The file is not valid TOML, or does not match the schema (unknown
    /// field, bad enum string, missing required field).
    #[error("{file:?}: {error}")]
    Toml {
        /// Name of the file, as passed to the loader.
        file: String,
        // not `source`: thiserror would also return it from `Error::source()`,
        // and a chain-walking reporter would print it twice
        /// The parser's error; its `Display` gives the line and column when toml knows the span.
        error: toml::de::Error,
    },
    /// A row has no `source`, or an empty one.
    #[error("{file:?}: row {row:?}: missing or empty `source`")]
    MissingSource {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
    },
    /// A row key is empty or has an empty segment.
    #[error("{file:?}: row {row:?}: empty key or key segment")]
    BadRowKey {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
    },
    /// An option name is not a valid short or long name.
    #[error("{file:?}: row {row:?}: bad option name {name:?}")]
    BadOptName {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
        /// The rejected option name, as written in the file.
        name: String,
    },
    /// An option has neither `short` nor `long`.
    #[error("{file:?}: row {row:?}: option with neither `short` nor `long`")]
    OptWithoutName {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
    },
    /// Two rows (possibly in different files) have the same key.
    #[error("{file:?}: row {row:?}: duplicate key, first defined in {first_file:?}")]
    DuplicateRow {
        /// Name of the file holding the later, duplicate row.
        file: String,
        /// Key shared by both rows, segments joined with spaces.
        row: String,
        /// Name of the file holding the first row with this key.
        first_file: String,
    },
    /// Two options of one grammar share a short or a long name.
    #[error("{file:?}: row {row:?}: duplicate option name {name:?}")]
    DuplicateOpt {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
        /// The option name that occurs twice, spelled as on argv (`-x` or `--name`).
        name: String,
    },
    /// A row with a longer key has no row for the key minus its last
    /// segment.
    #[error("{file:?}: row {row:?}: no parent row")]
    OrphanRow {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
    },
    /// A row sets both `changes_cwd` and `cwd_sensitive`.
    #[error("{file:?}: row {row:?}: sets both `changes_cwd` and `cwd_sensitive`")]
    ConflictingCwd {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
    },
    /// A row under a `cwd_sensitive` parent row does not set `cwd_sensitive`.
    #[error("{file:?}: row {row:?}: the parent row is `cwd_sensitive`, so this row must be too")]
    CwdSensitiveParent {
        /// Name of the file holding the child row.
        file: String,
        /// Key of the child row that lacks `cwd_sensitive`, segments joined
        /// with spaces.
        row: String,
    },
    /// A row whose head the grammar cannot express (#1039) does not run code.
    #[error("{file:?}: row {row:?}: head is not expressible, so the row must set `runs_code`")]
    DenylistedHead {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
    },
    /// A row head holds a `/` (`/bin/bash`, `/opt/homebrew/bin/fd`). The
    /// kernel matches heads byte for byte, so a path head would skip the
    /// head checks that a bare name gets.
    #[error("{file:?}: row {row:?}: head is a path; name the command without `/`")]
    PathHead {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
    },
    /// A row head holds a non-ASCII byte (`baſh`). The head checks compare in
    /// ASCII case only, and a filesystem that folds Unicode could reach an
    /// interpreter through a non-ASCII spelling, so the loader fails closed.
    #[error(
        "{file:?}: row \"{row}\": head \"{head}\" has a non-ASCII byte; name the command in ASCII"
    )]
    NonAsciiHead {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces, with every non-ASCII
        /// character escaped like `head`.
        row: String,
        /// The head with every non-ASCII character escaped (`ba\u{17f}h`), so
        /// the head prints in ASCII.
        head: String,
    },
    /// A row key segment after the head holds a non-ASCII byte
    /// (`["git", "clipſ"]`). Subcommand matching is ASCII-only too, and a
    /// Unicode-folding filesystem could spell a different name, so the loader
    /// fails closed; one error is reported per offending segment.
    #[error(
        "{file:?}: row \"{row}\": key segment \"{segment}\" has a non-ASCII byte; spell the key in ASCII"
    )]
    NonAsciiSegment {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces, with every non-ASCII
        /// character escaped like `segment`.
        row: String,
        /// The segment with every non-ASCII character escaped (`Clipp\u{17f}`),
        /// so it prints in ASCII.
        segment: String,
    },
    /// A row for a head that runs code through known options (`fd -x`)
    /// lists one of them, or an abbreviation of one, without a
    /// `takes = "code"` value (#1111).
    #[error(
        "{file:?}: row {row:?}: option {opt:?} runs code, so leave it out or give it `value = {{ takes = \"code\" }}`"
    )]
    CodeOptionNotCode {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the row, segments joined with spaces.
        row: String,
        /// The known code-running option the listed one spells in full or
        /// abbreviates, such as `-x`.
        opt: String,
    },
    /// A parent option spells a `runs_code` child's last key segment but
    /// does not take a `Code` value (#1070).
    #[error("{file:?}: row {row:?}: option {opt:?} is the child key but its value is not `code`")]
    ParentOptNotCode {
        /// Name of the file holding the parent row.
        file: String,
        /// Key of the parent row, segments joined with spaces.
        row: String,
        /// The child's last key segment, which the parent's option spells.
        opt: String,
    },
    /// A row or rule key segment starts with `-` or `+`, and the key is not
    /// that of a `runs_code` row.
    #[error("{file:?}: {item}: key segment starts with `-` or `+`")]
    OptionLikeKey {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Already labelled for display, as `row "<key>"` or `rule "<id>"`.
        item: String,
    },
    /// The config is in the shguard 0.9 format (`[[deny]]`, `[[ask]]`,
    /// `[[allow]]`, `decision_log_path`, ...), which this version cannot
    /// read. The text names no config content.
    #[error(
        "{file:?}: this is a shguard 0.9 config, which this version cannot read; \
         move it aside, run `shguard init`, and re-add your rules as [[rule]] entries (see the README)"
    )]
    LegacyConfig {
        /// Name of the config file, as passed to the loader.
        file: String,
    },
    /// `decision_log` is not an absolute path.
    #[error("{file:?}: `decision_log` must be an absolute path")]
    DecisionLogNotAbsolute {
        /// Name of the config file, as passed to the loader.
        file: String,
    },
    /// A file could not be read.
    #[error("{file:?}: {error}")]
    Read {
        /// Name of the file that could not be read.
        file: String,
        // not `source`: same reason as `Toml`'s `error` field (#1135)
        /// The I/O error, or why the path was refused before reading.
        error: std::io::Error,
    },
    /// A rule `id` is empty or only whitespace.
    #[error("{file:?}: a rule has an empty `id`")]
    EmptyRuleId {
        /// Name of the file, as passed to the loader.
        file: String,
    },
    /// A rule `id` has a character outside `A-Z a-z 0-9 . _ -`. The id goes
    /// into the hook reason the agent reads.
    #[error("{file:?}: rule {rule:?}: an id may only use `A-Z a-z 0-9 . _ -`")]
    BadRuleId {
        /// Name of the file, as passed to the loader.
        file: String,
        /// The rejected rule `id`, as written in the file.
        rule: String,
    },
    /// Two rules share an id.
    #[error("{file:?}: rule {rule:?}: duplicate id")]
    DuplicateRuleId {
        /// Name of the file holding the later rule with this id.
        file: String,
        /// The `id` that occurs twice.
        rule: String,
    },
    /// A rule key is empty or has an empty segment.
    #[error("{file:?}: rule {rule:?}: empty key or key segment")]
    BadRuleKey {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
    },
    /// No row key is a prefix of the rule key or extends it.
    #[error("{file:?}: rule {rule:?}: no row can match its key")]
    DeadRule {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
    },
    /// A rule option is not spelled `-x` or `--name`.
    #[error("{file:?}: rule {rule:?}: malformed option {name:?}")]
    BadRuleOpt {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
        /// The rejected option spelling, as written in the file.
        name: String,
    },
    /// A rule option appears in no matching row's grammar.
    #[error("{file:?}: rule {rule:?}: option {name:?} is in no matching row's grammar")]
    UnknownRuleOpt {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
        /// The option spelling, as written in the file.
        name: String,
    },
    /// A rule has an empty option alias set.
    #[error("{file:?}: rule {rule:?}: empty option alias set")]
    EmptyAlts {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
    },
    /// A rule target is empty.
    #[error("{file:?}: rule {rule:?}: empty target")]
    EmptyTarget {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
    },
    /// A rule target contains `$`.
    #[error("{file:?}: rule {rule:?}: target contains `$`")]
    TargetHasDollar {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
    },
    /// A target starts with `~` followed by something other than `/`
    /// (`~user`), which no command word can match.
    #[error("{file:?}: rule {rule:?}: target {pat:?}: `~` must be followed by `/` or nothing")]
    TildeUserTarget {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
        /// The rejected target pattern, as written in the file.
        pat: String,
    },
    /// A `component` or `component_prefix` target starts with `~` or `/`.
    #[error(
        "{file:?}: rule {rule:?}: component target {pat:?} starts with `~` or `/`; name the segments only (`.ssh`), or use `prefix`/`under`"
    )]
    AnchoredComponentTarget {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
        /// The rejected target pattern, as written in the file.
        pat: String,
    },
    /// A `component` or `component_prefix` target has a `..` segment.
    #[error(
        "{file:?}: rule {rule:?}: component target {pat:?} has a `..` segment; words keep `..` unresolved, so no credential name is ever `..`; name the segments only (`.ssh`)"
    )]
    DotDotTarget {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
        /// The rejected target pattern, as written in the file.
        pat: String,
    },
    /// The target `.` has a kind other than `exact`.
    #[error(
        "{file:?}: rule {rule:?}: target `.` must be `exact`; relative words are compared in normal form (`./x` is `x`), so name the paths instead (`.git` as `under`)"
    )]
    DotTarget {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
    },
    /// A `prefix` target ends in `/` and is not `/` itself.
    #[error(
        "{file:?}: rule {rule:?}: prefix target {pat:?} ends in `/`; use `under` without the `/`"
    )]
    PrefixEndsInSlash {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
        /// The rejected target pattern, as written in the file.
        pat: String,
    },
    /// A target's bytes after a leading `~` are not in the normal form
    /// `normalize_path` gives (`./x`, `a//b`, `x/`).
    #[error("{file:?}: rule {rule:?}: target {pat:?} is not in normal form; write {normal:?}")]
    TargetNotNormal {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of the rule.
        rule: String,
        /// The rejected target pattern, as written in the file.
        pat: String,
        /// The whole target in normal form, which the message tells the user
        /// to write instead.
        normal: String,
    },
    /// A rule `reason` or a hint `text` is empty, longer than 300 bytes
    /// (`TEXT_CAP`), or holds a control, line separator, invisible or format
    /// character.
    #[error("{file:?}: {item}: {why}")]
    BadText {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Already labelled for display, as `rule "<id>"` or `hint "<key>"`.
        item: String,
        /// Which of the limits above the text broke, in words.
        why: &'static str,
    },
    /// A hint key is empty, has an empty segment, a segment that starts with
    /// `-` or `+`, or a segment with whitespace or an invisible character.
    #[error(
        "{file:?}: hint {hint:?}: empty key segment, one that starts with `-` or `+`, or one with whitespace or an invisible character"
    )]
    BadHintKey {
        /// Name of the file, as passed to the loader.
        file: String,
        /// Key of the hint, segments joined with spaces.
        hint: String,
    },
    /// Two hints share a key.
    #[error("{file:?}: hint {hint:?}: duplicate key")]
    DuplicateHint {
        /// Name of the file holding the later hint with this key.
        file: String,
        /// Key shared by both hints, segments joined with spaces.
        hint: String,
    },
    /// More rules than a rule id can number.
    #[error("{file:?}: rule {rule:?}: too many rules")]
    TooManyRules {
        /// Name of the file, as passed to the loader.
        file: String,
        /// `id` of a rule past the limit; each one gets its own error.
        rule: String,
    },
}
