//! TOML loading for the rule sets (plan.md §1.4): the serde DTOs
//! `rules/blocklist.toml`, `rules/allowlist.toml` and a user config file
//! deserialize into, and the conversion of those DTOs into the serde-free
//! specs `crate::rules` validates (`Rules::from_spec` and friends).
//!
//! `crate::rules` stays free of serde and TOML
//! (`coding-guidelines/principles.md`, "dependencies point inward"): this
//! module is the one place that sees a serde attribute or a TOML type, and
//! the `parse`/`embedded` entry points below are inherent methods of the
//! `crate::rules` types only so that call sites keep reading
//! `Rules::parse(text)`/`Rules::embedded()`.
//!
//! Every entry point takes TOML text (`&str`), never a path: file I/O stays
//! in `crate::config` and the composition root.

use serde::Deserialize;

use crate::rules::{
    Allowlist, AllowlistFileSpec, AskOutcomeSpec, AskOutcomeTableSpec, CommandRuleSpec,
    PipelineRuleSpec, RedirectRuleSpec, Rules, RulesError, RulesFileSpec, TargetSpec,
    TokenRuleSpec, UserConfig, UserConfigSpec,
};

// ---------------------------------------------------------------------
// Embedded defaults
// ---------------------------------------------------------------------

/// The default blocklist, embedded in the binary so the hook works with
/// zero setup (plan.md §1.1 stage 3, issue #11 scope).
pub(crate) const EMBEDDED_BLOCKLIST: &str = include_str!("../rules/blocklist.toml");

/// The default allowlist, embedded the same way. Ships empty (no entries)
/// per issue #11 scope — a commented example lives in the file itself.
const EMBEDDED_ALLOWLIST: &str = include_str!("../rules/allowlist.toml");

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
    #[serde(default)]
    token: Vec<TokenRuleDto>,
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
    #[serde(default)]
    attached_value_flags: Vec<String>,
    /// `None` when the key is absent; `Some(vec![])` (an explicit empty
    /// list) is rejected at load.
    #[serde(default)]
    target_flags: Option<Vec<String>>,
    #[serde(default)]
    deny_message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetDto {
    exact: Option<String>,
    prefix: Option<String>,
    normalized: Option<String>,
    normalized_prefix: Option<String>,
    normalized_basename: Option<String>,
    url_host: Option<String>,
    strip: Option<String>,
    /// Opt-in ASCII case-folded comparison for `normalized`/
    /// `normalized_prefix` (issue #449): used by `crate::config`'s
    /// generated self-protection rules AND `rules/blocklist.toml`'s own
    /// static `~/.config/shguard`-literal self-protection rules, on a
    /// case-insensitive filesystem (macOS APFS by default), where a
    /// re-cased spelling of the config path resolves to the exact same
    /// on-disk file. Not documented as ordinary rule-authoring syntax in
    /// the README — a rule author reaching for this should know their own
    /// target path lives on a case-insensitive volume.
    #[serde(default)]
    case_insensitive: bool,
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
    /// `deny_unknown_fields` means a config using this field fails to load
    /// on an shguard built before issue #268 — fail-closed, so a rule
    /// author cannot get a silently unconstrained sink out of a version
    /// mismatch.
    #[serde(default)]
    sink_required_flags: Vec<String>,
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

/// Issue #426: a rule matching a literal substring against every
/// assignment name and resolved argv word of a simple command, independent
/// of which command is being run — `AWS_SECRET_ACCESS_KEY=...` is
/// credential-shaped whether it prefixes `ls` or stands alone.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRuleDto {
    id: String,
    reason: String,
    #[serde(default)]
    decision: Option<String>,
    patterns: Vec<String>,
    #[serde(default)]
    deny_message: Option<String>,
}

/// The `[ask_outcome]` table shape (issue #469's documented keys — exact
/// stdin spellings, e.g. `default`, never `manual`). `deny_unknown_fields`
/// fails config load closed on any other key, the same posture
/// [`UserConfigFileDto`] already applies at the top level.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AskOutcomeTableDto {
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    plan: Option<String>,
    #[serde(default, rename = "acceptEdits")]
    accept_edits: Option<String>,
    #[serde(default)]
    auto: Option<String>,
    #[serde(default, rename = "dontAsk")]
    dont_ask: Option<String>,
    #[serde(default, rename = "bypassPermissions")]
    bypass_permissions: Option<String>,
    #[serde(default)]
    subagent: Option<String>,
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
    redirect: Vec<RedirectRuleDto>,
    #[serde(default)]
    pipeline: Vec<PipelineRuleDto>,
    #[serde(default)]
    escalation_floor: Option<String>,
    #[serde(default)]
    decision_log_path: Option<String>,
    #[serde(default)]
    ask_outcome: Option<toml::Value>,
}

// ---------------------------------------------------------------------
// DTO -> spec
// ---------------------------------------------------------------------

impl From<TargetDto> for TargetSpec {
    fn from(dto: TargetDto) -> Self {
        Self {
            exact: dto.exact,
            prefix: dto.prefix,
            normalized: dto.normalized,
            normalized_prefix: dto.normalized_prefix,
            normalized_basename: dto.normalized_basename,
            url_host: dto.url_host,
            strip: dto.strip,
            case_insensitive: dto.case_insensitive,
        }
    }
}

impl From<CommandRuleDto> for CommandRuleSpec {
    fn from(dto: CommandRuleDto) -> Self {
        Self {
            id: dto.id,
            reason: dto.reason,
            decision: dto.decision,
            command: dto.command,
            command_prefix: dto.command_prefix,
            required_flags: dto.required_flags,
            required_tokens: dto.required_tokens,
            targets: dto.targets.into_iter().map(Into::into).collect(),
            except_targets: dto.except_targets.into_iter().map(Into::into).collect(),
            value_flags: dto.value_flags,
            attached_value_flags: dto.attached_value_flags,
            target_flags: dto.target_flags,
            deny_message: dto.deny_message,
        }
    }
}

impl From<PipelineRuleDto> for PipelineRuleSpec {
    fn from(dto: PipelineRuleDto) -> Self {
        Self {
            id: dto.id,
            reason: dto.reason,
            decision: dto.decision,
            sources: dto.sources,
            sinks: dto.sinks,
            sink_required_flags: dto.sink_required_flags,
        }
    }
}

impl From<RedirectRuleDto> for RedirectRuleSpec {
    fn from(dto: RedirectRuleDto) -> Self {
        Self {
            id: dto.id,
            reason: dto.reason,
            decision: dto.decision,
            targets: dto.targets.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<TokenRuleDto> for TokenRuleSpec {
    fn from(dto: TokenRuleDto) -> Self {
        Self {
            id: dto.id,
            reason: dto.reason,
            decision: dto.decision,
            patterns: dto.patterns,
            deny_message: dto.deny_message,
        }
    }
}

impl From<RulesFileDto> for RulesFileSpec {
    fn from(dto: RulesFileDto) -> Self {
        Self {
            command: dto.command.into_iter().map(Into::into).collect(),
            pipeline: dto.pipeline.into_iter().map(Into::into).collect(),
            redirect: dto.redirect.into_iter().map(Into::into).collect(),
            token: dto.token.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<AllowlistFileDto> for AllowlistFileSpec {
    fn from(dto: AllowlistFileDto) -> Self {
        Self {
            entry: dto.entry.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<AskOutcomeTableDto> for AskOutcomeTableSpec {
    fn from(dto: AskOutcomeTableDto) -> Self {
        Self {
            default: dto.default,
            plan: dto.plan,
            accept_edits: dto.accept_edits,
            auto: dto.auto,
            dont_ask: dto.dont_ask,
            bypass_permissions: dto.bypass_permissions,
            subagent: dto.subagent,
        }
    }
}

/// Dispatches the raw `ask_outcome` value on its own [`toml::Value`] kind
/// rather than a `#[serde(untagged)]` enum, since an untagged enum's
/// deserialize failure collapses every candidate variant's error into one
/// generic "data did not match any variant" message, losing exactly the
/// `unknown field \"foo\"` detail `deny_unknown_fields` exists to report
/// for a mistyped table key. A rejected shape is carried as
/// [`AskOutcomeSpec::Invalid`] (not returned as an `Err` here) so it is
/// reported at the same point of `UserConfig::from_spec`'s validation order
/// it always was.
fn ask_outcome_spec(raw: Option<toml::Value>) -> Option<AskOutcomeSpec> {
    Some(match raw? {
        toml::Value::String(raw) => AskOutcomeSpec::Global(raw),
        table @ toml::Value::Table(_) => match table.try_into::<AskOutcomeTableDto>() {
            Ok(dto) => AskOutcomeSpec::Table(dto.into()),
            Err(err) => AskOutcomeSpec::Invalid(err.to_string()),
        },
        other => AskOutcomeSpec::Invalid(format!(
            "ask_outcome must be a string or a table, got {}",
            other.type_str()
        )),
    })
}

impl From<UserConfigFileDto> for UserConfigSpec {
    fn from(dto: UserConfigFileDto) -> Self {
        Self {
            deny: dto.deny.into_iter().map(Into::into).collect(),
            ask: dto.ask.into_iter().map(Into::into).collect(),
            allow: dto.allow.into_iter().map(Into::into).collect(),
            redirect: dto.redirect.into_iter().map(Into::into).collect(),
            pipeline: dto.pipeline.into_iter().map(Into::into).collect(),
            escalation_floor: dto.escalation_floor,
            decision_log_path: dto.decision_log_path,
            ask_outcome: ask_outcome_spec(dto.ask_outcome),
        }
    }
}

// ---------------------------------------------------------------------
// TOML-text entry points
// ---------------------------------------------------------------------

/// Deserializes `toml` into `T`, mapping a TOML/serde failure to
/// [`RulesError::Syntax`] (the message text only, never the driver's error
/// type).
fn deserialize<T: serde::de::DeserializeOwned>(toml: &str) -> Result<T, RulesError> {
    toml::from_str(toml).map_err(|e| RulesError::Syntax(e.to_string()))
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
        let dto: RulesFileDto = deserialize(toml)?;
        Self::from_spec(dto.into())
    }

    /// Parses the embedded default blocklist (`rules/blocklist.toml`,
    /// baked in via `include_str!` so the hook works with zero setup).
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] if the embedded file itself is malformed —
    /// a unit test asserts this never happens, so this is a startup
    /// error only if a future edit to `rules/blocklist.toml` breaks it.
    pub(crate) fn embedded() -> Result<Self, RulesError> {
        Self::parse(EMBEDDED_BLOCKLIST)
    }
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
        let dto: AllowlistFileDto = deserialize(toml)?;
        Self::from_spec(dto.into())
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
}

impl UserConfig {
    /// Parses `toml` (never a path) into a validated [`UserConfig`]; see
    /// [`UserConfig::from_spec`] for every semantic check and the full
    /// error list.
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] for invalid TOML syntax, or any error
    /// [`UserConfig::from_spec`] reports.
    pub(crate) fn parse(toml: &str) -> Result<Self, RulesError> {
        let dto: UserConfigFileDto = deserialize(toml)?;
        Self::from_spec(dto.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::rules::SHELL_INTERPRETERS;

    // The shell-init/persistence path list is duplicated across nine
    // `[[command]]` rules and one `[[redirect]]` rule (issue #261's own
    // tenth copy). Nothing in the schema ties them together, so this test
    // is what keeps a path added to one mechanism from silently missing
    // from the others.
    #[test]
    fn shell_init_target_lists_are_in_sync() {
        let doc: toml::Value = toml::from_str(EMBEDDED_BLOCKLIST).unwrap();
        let targets_of = |table: &toml::Value| -> Vec<(String, String)> {
            table["targets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    let table = entry.as_table().unwrap();
                    // `strip` is per-mechanism (`shell-init-dd` carries
                    // `of=`), so only the matcher kind and value are
                    // compared.
                    let (kind, value) = table
                        .iter()
                        .find(|(key, _)| key.as_str() != "strip")
                        .unwrap();
                    (kind.clone(), value.as_str().unwrap().to_string())
                })
                .collect()
        };

        let expected = doc["command"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["id"].as_str() == Some("shell-init-tee"))
            .map(targets_of)
            .unwrap();

        let mut checked = 0;
        for rule in doc["command"].as_array().unwrap() {
            let id = rule["id"].as_str().unwrap();
            if !id.starts_with("shell-init-") {
                continue;
            }
            assert_eq!(targets_of(rule), expected, "rule {id:?} drifted");
            checked += 1;
        }
        for rule in doc["redirect"].as_array().unwrap() {
            let id = rule["id"].as_str().unwrap();
            if !id.starts_with("shell-init-") {
                continue;
            }
            assert_eq!(targets_of(rule), expected, "rule {id:?} drifted");
            checked += 1;
        }
        assert_eq!(
            checked, 11,
            "expected eleven shell-init rules, found {checked}"
        );
    }

    // Issue #446: `curl-wget-pipe-to-shell`'s `sinks` drifted from
    // `SHELL_INTERPRETERS` twice (issue #55's fish/ksh/tcsh/csh/ash, then
    // `dash`), each time silently downgrading `curl ... | <shell>` from
    // Block to Ask. Enforces the comment's promise mechanically instead of
    // relying on it being kept by hand, the same pattern
    // `shell_init_target_lists_are_in_sync` already uses for a different
    // duplicated list. `source`/`.` are checked separately: they are not
    // `SHELL_INTERPRETERS` members (they need a stdin-alias operand, not
    // just a bare name, to actually act as a sink — see
    // `crate::gate`'s `is_interpreter_sink`), but belong in this rule's
    // `sinks` the same way `pwsh` belongs in `EXTRA_PIPELINE_INTERPRETERS`.
    #[test]
    fn curl_wget_pipe_to_shell_sinks_cover_shell_interpreters() {
        let doc: toml::Value = toml::from_str(EMBEDDED_BLOCKLIST).unwrap();
        let rule = doc["pipeline"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["id"].as_str() == Some("curl-wget-pipe-to-shell"))
            .unwrap();
        let sinks: Vec<&str> = rule["sinks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for shell in SHELL_INTERPRETERS {
            assert!(
                sinks.contains(shell),
                "curl-wget-pipe-to-shell's sinks is missing {shell:?} from SHELL_INTERPRETERS"
            );
        }
        for extra in ["source", "."] {
            assert!(
                sinks.contains(&extra),
                "curl-wget-pipe-to-shell's sinks is missing {extra:?}"
            );
        }
    }
}
