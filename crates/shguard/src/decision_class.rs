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
            Self::RuleHit => "rule_hit",
            Self::Unknown(kind) => unknown(kind),
            Self::ParseRefusal(kind) => parse_refusal(kind),
            Self::EmptyCommand => "parse_refusal:empty_command",
            Self::MalformedInput => "parse_refusal:malformed_input",
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
