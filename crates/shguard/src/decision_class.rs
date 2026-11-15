//! The stable class name of a decision, written to the decision log as
//! `class` and counted by `shguard report`.
//!
//! The names are a contract: a log keeps its meaning across versions, so a
//! name is never reused for another case. A class comes from the type of the
//! reason, never from reason text. It says which path produced the answer; it
//! does not say a command is safe.

use shguard_kernel::verdict::UnknownKind;
use shguard_syntax::UnsupportedKind;

/// Why a decision came out as it did, as a stable class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionClass {
    /// An Allow that the embedded catalog covers.
    Allow,
    /// An Allow that needs a user `[[row]]`.
    AllowUserRow,
    /// An Allow that needs a user `[[row]]` that does not set `runs_code` for
    /// a head that runs other code or has option syntax the grammar cannot
    /// express (a row that loads with a warning).
    AllowUserCodeRow,
    /// A rule hit (an Ask or a Block).
    RuleHit,
    /// A command the catalog does not cover, by the kernel's kind.
    Unknown(UnknownKind),
    /// A command outside the parsed subset, by the parser's kind.
    ParseRefusal(UnsupportedKind),
    /// An empty command.
    EmptyCommand,
    /// Hook input that is not the hook contract.
    MalformedInput,
    /// The config or catalog failed to load.
    LoadError,
}

impl DecisionClass {
    /// The class name as it appears in the log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowUserRow => "allow_user_row",
            Self::AllowUserCodeRow => "allow_user_code_row",
            Self::RuleHit => "rule_hit",
            Self::Unknown(kind) => unknown(kind),
            Self::ParseRefusal(kind) => parse_refusal(kind),
            Self::EmptyCommand => "empty_command",
            Self::MalformedInput => "malformed_input",
            Self::LoadError => "load_error",
        }
    }
}

fn unknown(kind: UnknownKind) -> &'static str {
    match kind {
        UnknownKind::NoRow => "unknown:no_row",
        UnknownKind::OpaqueCommandName => "unknown:opaque_command_name",
        UnknownKind::UnknownOption => "unknown:unknown_option",
        UnknownKind::OpaqueOption => "unknown:opaque_option",
        UnknownKind::MissingValue => "unknown:missing_value",
        UnknownKind::FlagGivenValue => "unknown:flag_given_value",
        UnknownKind::DashDashNotAllowed => "unknown:dash_dash_not_allowed",
        UnknownKind::ExtraOperand => "unknown:extra_operand",
        UnknownKind::OptionAfterOperand => "unknown:option_after_operand",
        UnknownKind::PlusWord => "unknown:plus_word",
        UnknownKind::CodeRole => "unknown:code_role",
        UnknownKind::RunsCode => "unknown:runs_code",
        UnknownKind::UnknownSubcommand => "unknown:unknown_subcommand",
        UnknownKind::PathOpaque => "unknown:path_opaque",
        UnknownKind::PathDotDot => "unknown:path_dot_dot",
        UnknownKind::PathNonAscii => "unknown:path_non_ascii",
        UnknownKind::PathAfterCd => "unknown:path_after_cd",
        UnknownKind::SensitiveAfterCd => "unknown:sensitive_after_cd",
    }
}

fn parse_refusal(kind: UnsupportedKind) -> &'static str {
    match kind {
        UnsupportedKind::InputTooLarge => "parse_refusal:input_too_large",
        UnsupportedKind::ControlByte => "parse_refusal:control_byte",
        UnsupportedKind::UnterminatedSingleQuote => "parse_refusal:unterminated_single_quote",
        UnsupportedKind::UnterminatedDoubleQuote => "parse_refusal:unterminated_double_quote",
        UnsupportedKind::BackgroundAmpersand => "parse_refusal:background_ampersand",
        UnsupportedKind::PipeAmpersand => "parse_refusal:pipe_ampersand",
        UnsupportedKind::DoubleSemicolon => "parse_refusal:double_semicolon",
        UnsupportedKind::SemicolonAmpersand => "parse_refusal:semicolon_ampersand",
        UnsupportedKind::Parenthesis => "parse_refusal:parenthesis",
        UnsupportedKind::InputRedirect => "parse_refusal:input_redirect",
        UnsupportedKind::AppendRedirect => "parse_refusal:append_redirect",
        UnsupportedKind::ClobberRedirect => "parse_refusal:clobber_redirect",
        UnsupportedKind::AmpersandRedirect => "parse_refusal:ampersand_redirect",
        UnsupportedKind::ProcessSubstitution => "parse_refusal:process_substitution",
        UnsupportedKind::Brace => "parse_refusal:brace",
        UnsupportedKind::Glob => "parse_refusal:glob",
        UnsupportedKind::Comment => "parse_refusal:comment",
        UnsupportedKind::UnquotedDollar => "parse_refusal:unquoted_dollar",
        UnsupportedKind::Backquote => "parse_refusal:backquote",
        UnsupportedKind::DollarParen => "parse_refusal:dollar_paren",
        UnsupportedKind::BracedParameter => "parse_refusal:braced_parameter",
        UnsupportedKind::SpecialParameter => "parse_refusal:special_parameter",
        UnsupportedKind::NameBeforeNonAscii => "parse_refusal:name_before_non_ascii",
        UnsupportedKind::BackslashAfterNonAscii => "parse_refusal:backslash_after_non_ascii",
        UnsupportedKind::BareDollar => "parse_refusal:bare_dollar",
        UnsupportedKind::LineContinuation => "parse_refusal:line_continuation",
        UnsupportedKind::BackslashAtEnd => "parse_refusal:backslash_at_end",
        UnsupportedKind::TildeForm => "parse_refusal:tilde_form",
        UnsupportedKind::TildeAssignment => "parse_refusal:tilde_assignment",
        UnsupportedKind::MultiDigitFd => "parse_refusal:multi_digit_fd",
        UnsupportedKind::DupOperand => "parse_refusal:dup_operand",
        UnsupportedKind::RedirectDescriptor => "parse_refusal:redirect_descriptor",
        UnsupportedKind::RedirectTarget => "parse_refusal:redirect_target",
        UnsupportedKind::LeadingSeparator => "parse_refusal:leading_separator",
        UnsupportedKind::MissingCommand => "parse_refusal:missing_command",
        UnsupportedKind::RedirectOnly => "parse_refusal:redirect_only",
        UnsupportedKind::Assignment => "parse_refusal:assignment",
        UnsupportedKind::ReservedWord => "parse_refusal:reserved_word",
        UnsupportedKind::TooManyWords => "parse_refusal:too_many_words",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every class: the fixed variants, then each kind of the two payload
    /// variants. `listed` has no `_` arm, so a new variant fails to compile
    /// here until it is handled.
    pub(crate) fn every_class() -> Vec<DecisionClass> {
        use UnknownKind as U;
        use UnsupportedKind as S;
        let unknown = [
            U::NoRow,
            U::OpaqueCommandName,
            U::UnknownOption,
            U::OpaqueOption,
            U::MissingValue,
            U::FlagGivenValue,
            U::DashDashNotAllowed,
            U::ExtraOperand,
            U::OptionAfterOperand,
            U::PlusWord,
            U::CodeRole,
            U::RunsCode,
            U::UnknownSubcommand,
            U::PathOpaque,
            U::PathDotDot,
            U::PathNonAscii,
            U::PathAfterCd,
            U::SensitiveAfterCd,
        ];
        let refusals = [
            S::InputTooLarge,
            S::ControlByte,
            S::UnterminatedSingleQuote,
            S::UnterminatedDoubleQuote,
            S::BackgroundAmpersand,
            S::PipeAmpersand,
            S::DoubleSemicolon,
            S::SemicolonAmpersand,
            S::Parenthesis,
            S::InputRedirect,
            S::AppendRedirect,
            S::ClobberRedirect,
            S::AmpersandRedirect,
            S::ProcessSubstitution,
            S::Brace,
            S::Glob,
            S::Comment,
            S::UnquotedDollar,
            S::Backquote,
            S::DollarParen,
            S::BracedParameter,
            S::SpecialParameter,
            S::NameBeforeNonAscii,
            S::BackslashAfterNonAscii,
            S::BareDollar,
            S::LineContinuation,
            S::BackslashAtEnd,
            S::TildeForm,
            S::TildeAssignment,
            S::MultiDigitFd,
            S::DupOperand,
            S::RedirectDescriptor,
            S::RedirectTarget,
            S::LeadingSeparator,
            S::MissingCommand,
            S::RedirectOnly,
            S::Assignment,
            S::ReservedWord,
            S::TooManyWords,
        ];
        let mut all = vec![
            DecisionClass::Allow,
            DecisionClass::AllowUserRow,
            DecisionClass::AllowUserCodeRow,
            DecisionClass::RuleHit,
            DecisionClass::EmptyCommand,
            DecisionClass::MalformedInput,
            DecisionClass::LoadError,
        ];
        all.extend(unknown.map(DecisionClass::Unknown));
        all.extend(refusals.map(DecisionClass::ParseRefusal));
        for class in &all {
            assert!(listed(*class), "{class:?}");
        }
        all
    }

    fn listed(class: DecisionClass) -> bool {
        match class {
            DecisionClass::Allow
            | DecisionClass::AllowUserRow
            | DecisionClass::AllowUserCodeRow
            | DecisionClass::RuleHit
            | DecisionClass::Unknown(_)
            | DecisionClass::ParseRefusal(_)
            | DecisionClass::EmptyCommand
            | DecisionClass::MalformedInput
            | DecisionClass::LoadError => true,
        }
    }

    #[test]
    fn every_class_name_is_distinct() {
        let all = every_class();
        let mut seen = std::collections::HashSet::new();
        for class in &all {
            assert!(
                seen.insert(class.as_str()),
                "the name of {class:?} is used twice"
            );
        }
        assert_eq!(seen.len(), all.len());
    }

    #[test]
    fn a_kind_name_never_equals_another_class_name() {
        for class in every_class() {
            let name = class.as_str();
            match class {
                DecisionClass::Unknown(_) => assert!(name.starts_with("unknown:"), "{name}"),
                DecisionClass::ParseRefusal(_) => {
                    assert!(name.starts_with("parse_refusal:"), "{name}");
                }
                DecisionClass::Allow
                | DecisionClass::AllowUserRow
                | DecisionClass::AllowUserCodeRow
                | DecisionClass::RuleHit
                | DecisionClass::EmptyCommand
                | DecisionClass::MalformedInput
                | DecisionClass::LoadError => {
                    assert!(!name.contains(':'), "{name}");
                }
            }
        }
    }
}
