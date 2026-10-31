//! The loader's error type.
#![expect(
    missing_docs,
    reason = "every field is the file name or the row, rule or option it names; the variant docs say the rest"
)]

use thiserror::Error;

/// A problem found while loading catalog files. Every variant names the file
/// and where in it: a row (its key joined with spaces) or a rule (its id).
#[derive(Debug, Error)]
pub enum LoadError {
    /// The file is not valid TOML, or does not match the schema (unknown
    /// field, bad enum string, missing required field).
    #[error("{file}: {source}")]
    Toml {
        file: String,
        source: toml::de::Error,
    },
    /// A row has no `source`, or an empty one.
    #[error("{file}: row `{row}`: missing or empty `source`")]
    MissingSource { file: String, row: String },
    /// A row key is empty or has an empty segment.
    #[error("{file}: row `{row}`: empty key or key segment")]
    BadRowKey { file: String, row: String },
    /// An option name is not a valid short or long name.
    #[error("{file}: row `{row}`: bad option name `{name}`")]
    BadOptName {
        file: String,
        row: String,
        name: String,
    },
    /// An option has neither `short` nor `long`.
    #[error("{file}: row `{row}`: option with neither `short` nor `long`")]
    OptWithoutName { file: String, row: String },
    /// Two rows (possibly in different files) have the same key.
    #[error("{file}: row `{row}`: duplicate key, first defined in {first_file}")]
    DuplicateRow {
        file: String,
        row: String,
        first_file: String,
    },
    /// Two options of one grammar share a short or a long name.
    #[error("{file}: row `{row}`: duplicate option name `{name}`")]
    DuplicateOpt {
        file: String,
        row: String,
        name: String,
    },
    /// A row with a longer key has no row for the key minus its last
    /// segment.
    #[error("{file}: row `{row}`: no parent row")]
    OrphanRow { file: String, row: String },
    /// A row sets both `changes_cwd` and `cwd_sensitive`.
    #[error("{file}: row `{row}`: sets both `changes_cwd` and `cwd_sensitive`")]
    ConflictingCwd { file: String, row: String },
    /// A row under a `cwd_sensitive` parent row does not set `cwd_sensitive`.
    #[error("{file}: row `{row}`: the parent row is `cwd_sensitive`, so this row must be too")]
    CwdSensitiveParent { file: String, row: String },
    /// A row whose head the grammar cannot express (#1039) does not run code.
    #[error("{file}: row `{row}`: head is not expressible, so the row must set `runs_code`")]
    DenylistedHead { file: String, row: String },
    /// A parent option spells a `runs_code` child's last key segment but
    /// does not take a `Code` value (#1070).
    #[error("{file}: row `{row}`: option `{opt}` is the child key but its value is not `code`")]
    ParentOptNotCode {
        file: String,
        row: String,
        opt: String,
    },
    /// A row or rule key segment starts with `-` or `+`, and the key is not
    /// that of a `runs_code` row. `item` is "row `key`" or "rule `id`".
    #[error("{file}: {item}: key segment starts with `-` or `+`")]
    OptionLikeKey { file: String, item: String },
    /// The config is in the shguard 0.9 format (`[[deny]]`, `[[ask]]`,
    /// `[[allow]]`, `decision_log_path`, ...), which this version cannot
    /// read. The text names no config content.
    #[error(
        "{file}: this is a shguard 0.9 config, which this version cannot read; \
         move it aside, run `shguard init`, and re-add your rules as [[rule]] entries (see the README)"
    )]
    LegacyConfig { file: String },
    /// `decision_log` is not an absolute path.
    #[error("{file}: `decision_log` must be an absolute path")]
    DecisionLogNotAbsolute { file: String },
    /// A file could not be read.
    #[error("{file}: {source}")]
    Read {
        file: String,
        source: std::io::Error,
    },
    /// A rule `id` is empty or only whitespace.
    #[error("{file}: a rule has an empty `id`")]
    EmptyRuleId { file: String },
    /// Two rules share an id.
    #[error("{file}: rule `{rule}`: duplicate id")]
    DuplicateRuleId { file: String, rule: String },
    /// A rule key is empty or has an empty segment.
    #[error("{file}: rule `{rule}`: empty key or key segment")]
    BadRuleKey { file: String, rule: String },
    /// No row key is a prefix of the rule key or extends it.
    #[error("{file}: rule `{rule}`: no row can match its key")]
    DeadRule { file: String, rule: String },
    /// A rule option is not spelled `-x` or `--name`.
    #[error("{file}: rule `{rule}`: malformed option `{name}`")]
    BadRuleOpt {
        file: String,
        rule: String,
        name: String,
    },
    /// A rule option appears in no matching row's grammar.
    #[error("{file}: rule `{rule}`: option `{name}` is in no matching row's grammar")]
    UnknownRuleOpt {
        file: String,
        rule: String,
        name: String,
    },
    /// A rule has an empty option alias set.
    #[error("{file}: rule `{rule}`: empty option alias set")]
    EmptyAlts { file: String, rule: String },
    /// A rule target is empty.
    #[error("{file}: rule `{rule}`: empty target")]
    EmptyTarget { file: String, rule: String },
    /// A rule target contains `$`.
    #[error("{file}: rule `{rule}`: target contains `$`")]
    TargetHasDollar { file: String, rule: String },
    /// A target starts with `~` followed by something other than `/`
    /// (`~user`), which no command word can match.
    #[error("{file}: rule `{rule}`: target `{pat}`: `~` must be followed by `/` or nothing")]
    TildeUserTarget {
        file: String,
        rule: String,
        pat: String,
    },
    /// The target `.` has kind `prefix` or `under`.
    #[error(
        "{file}: rule `{rule}`: target `.` must be `exact`; relative words are compared in normal form (`./x` is `x`), so name the paths instead (`.git` as `under`)"
    )]
    DotTarget { file: String, rule: String },
    /// A `prefix` target ends in `/` and is not `/` itself.
    #[error(
        "{file}: rule `{rule}`: prefix target `{pat}` ends in `/`; use `under` without the `/`"
    )]
    PrefixEndsInSlash {
        file: String,
        rule: String,
        pat: String,
    },
    /// A target's bytes after a leading `~` are not in the normal form
    /// `normalize_path` gives (`./x`, `a//b`, `x/`).
    #[error("{file}: rule `{rule}`: target `{pat}` is not in normal form; write `{normal}`")]
    TargetNotNormal {
        file: String,
        rule: String,
        pat: String,
        normal: String,
    },
    /// More rules than a rule id can number.
    #[error("{file}: rule `{rule}`: too many rules")]
    TooManyRules { file: String, rule: String },
}
