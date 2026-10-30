//! The serde shapes of the catalog TOML. They only describe the file; the
//! loader turns them into kernel values.

use serde::Deserialize;

/// One catalog file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileDto {
    #[serde(default)]
    pub(super) row: Vec<RowDto>,
    #[serde(default)]
    pub(super) rule: Vec<RuleDto>,
}

/// The user config: `ask_outcome` plus rows and rules in the catalog schema.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfigDto {
    #[serde(default)]
    pub(super) ask_outcome: AskOutcome,
    #[serde(default)]
    pub(super) row: Vec<RowDto>,
    #[serde(default)]
    pub(super) rule: Vec<RuleDto>,
}

/// What an Ask becomes when the hook answers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AskOutcome {
    /// Refuse it. The default, since an autonomous session cannot answer.
    #[default]
    Deny,
    /// Let Claude Code ask the user.
    Ask,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RoleDto {
    Inert,
    Path,
    Code,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OrderDto {
    Permute,
    Strict,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DashDashDto {
    Ends,
    Literal,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PlusWordsDto {
    #[default]
    Reject,
    Operand,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ValueDto {
    #[default]
    Flag,
    Takes(RoleDto),
    Optional(RoleDto),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OptDto {
    pub(super) short: Option<String>,
    pub(super) long: Option<String>,
    #[serde(default)]
    pub(super) value: ValueDto,
}

/// A row. `source` is optional here so that a missing one is its own
/// load error rather than a serde error.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RowDto {
    pub(super) key: Vec<String>,
    pub(super) source: Option<String>,
    pub(super) order: OrderDto,
    pub(super) dashdash: DashDashDto,
    #[serde(default)]
    pub(super) plus_words: PlusWordsDto,
    #[serde(default)]
    pub(super) positionals: Vec<RoleDto>,
    pub(super) rest: Option<RoleDto>,
    #[serde(default)]
    pub(super) runs_code: bool,
    #[serde(default)]
    pub(super) changes_cwd: bool,
    #[serde(default)]
    pub(super) opt: Vec<OptDto>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ScopeDto {
    #[default]
    Simple,
    PipeInto,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OutcomeDto {
    Ask,
    Block,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PatKindDto {
    Exact,
    Prefix,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetDto {
    pub(super) pat: String,
    pub(super) kind: PatKindDto,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuleDto {
    pub(super) id: String,
    #[serde(default)]
    pub(super) scope: ScopeDto,
    pub(super) key: Vec<String>,
    #[serde(default)]
    pub(super) opts: Vec<Vec<String>>,
    #[serde(default)]
    pub(super) targets: Vec<TargetDto>,
    pub(super) outcome: OutcomeDto,
}
