//! Turns catalog TOML into kernel values and checks the whole set.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use shguard_kernel::ast::{Opaque, Part};
use shguard_kernel::bytes::normalize_path;
use shguard_kernel::catalog::{
    Catalog, Cwd, DashDash, Grammar, LongName, Opt, OptName, OptValue, Order, PlusWords, Role, Row,
    RunsCode, ShortName, key_ok,
};
use shguard_kernel::rule::{OptAlts, Outcome, Pat, PatKind, Rule, RuleId, Scope};

use super::LoadError;
use super::dto::{
    AskOutcome, ConfigDto, DashDashDto, FileDto, HintDto, OptDto, OrderDto, OutcomeDto, PatKindDto,
    PlusWordsDto, RoleDto, RowDto, RuleDto, ScopeDto, TargetDto, ValueDto,
};

/// Command heads that get no coverable row, whatever the user config says.
/// A row for one of them must set `runs_code`, so it can never cover a
/// command: such a command is an Ask by Unknown. Each head is here for one
/// of these reasons:
///
/// - its option syntax is outside the grammar: dash-less bundles (`tar xf`)
///   or single-dash long options (`find -exec`, `ps -ef`, #1039);
/// - it runs the program or script it is given, or evaluates its argument
///   (wrappers, shell builtins that run text, interpreters);
/// - it opens a connection or a session to another system or a multiplexer
///   (`ssh`, `docker`, `kubectl`, `tmux`, `socat`);
/// - it changes what later commands do or schedules code (`trap`, `crontab`).
///
/// The `g`-prefixed names are the Homebrew GNU builds of the same tools.
const INEXPRESSIBLE_HEADS: &[&[u8]] = &[
    // Option syntax outside the grammar (#1039).
    b"tar",
    b"ps",
    b"ar",
    b"find",
    b"gtar",
    b"gfind",
    // Shell builtins that run text or replace the shell.
    b"eval",
    b"source",
    b".",
    b"exec",
    b"command",
    b"builtin",
    b"trap",
    // Wrappers that run another command.
    b"xargs",
    b"gxargs",
    b"env",
    b"nohup",
    b"timeout",
    b"nice",
    b"sudo",
    b"doas",
    b"watch",
    b"script",
    b"parallel",
    b"flock",
    b"strace",
    // Remote, container and multiplexer sessions.
    b"ssh",
    b"docker",
    b"kubectl",
    b"socat",
    b"tmux",
    // Schedules code to run later.
    b"crontab",
    // Interpreters: their argument is a program.
    b"sed",
    b"gsed",
    b"awk",
    b"gawk",
    b"perl",
    b"node",
    b"python",
    b"python3",
    b"ruby",
    b"bash",
    b"sh",
    b"zsh",
    // More shells and interpreters, and the GNU builds of the wrappers.
    b"su",
    b"dash",
    b"ksh",
    b"fish",
    b"csh",
    b"tcsh",
    b"deno",
    b"bun",
    b"php",
    b"lua",
    b"pypy",
    b"pypy3",
    b"ipython",
    b"luajit",
    b"tclsh",
    b"expect",
    b"pwsh",
    b"osascript",
    b"python2",
    b"gtimeout",
    b"genv",
    b"gnohup",
    b"gnice",
    // Runtimes, REPLs and template or script engines that run their argument.
    b"jruby",
    b"truffleruby",
    b"irb",
    b"erb",
    b"wish",
    b"elixir",
    b"iex",
    b"groovy",
    b"julia",
    b"rscript",
];

/// Interpreters whose binaries carry a version suffix (`ruby3.1`, `python-3.10`).
const VERSIONED_INTERPRETERS: &[&[u8]] = &[
    b"python", b"perl", b"ruby", b"php", b"lua", b"luajit", b"pwsh", b"pypy", b"ipython", b"tclsh",
];

/// Whether `head` is an [`INEXPRESSIBLE_HEADS`] entry, compared in ASCII
/// lower case, or an interpreter name from [`VERSIONED_INTERPRETERS`]
/// followed by a digit, or by `-` and a digit (`python3.10`, `perl5.30`,
/// `python-3.10`, `luajit-2.1.0-beta3`), or `python`
/// followed by the framework GUI build's `w` (`pythonw`, `pythonw3.12`).
///
/// Not an exact byte match: the default macOS filesystem is case-insensitive,
/// so `ENV` and `Python3` reach the same binary, and the version suffix is
/// open-ended (`python3.13t`, `python3.13-intel64`). Because only `head` is
/// lowercased, every list entry must already be lowercase.
fn is_inexpressible(head: &[u8]) -> bool {
    let lower = head.to_ascii_lowercase();
    let versioned = VERSIONED_INTERPRETERS.iter().any(|name| {
        lower
            .strip_prefix(*name)
            .is_some_and(|suffix| matches!(suffix, [b'0'..=b'9', ..] | [b'-', b'0'..=b'9', ..]))
    });
    let versioned_pythonw = lower
        .strip_prefix(b"pythonw")
        .is_some_and(|suffix| matches!(suffix, [] | [b'0'..=b'9', ..]));
    versioned || versioned_pythonw || INEXPRESSIBLE_HEADS.contains(&lower.as_slice())
}

/// Command heads that run code only through a known set of options (#1111).
/// A row for one of them, or for a key under it, may cover commands, but
/// only if it lists none of these options, or lists each with a
/// `takes = "code"` value: an option the row does not list makes the
/// command Unknown, and a `code` value it takes makes it an Ask. An
/// `optional` value is read only inline (`--exec=x`), so `fd --exec rm`
/// would read `rm` as an operand; it is refused. A flag that runs a program
/// (`fd -l` runs `ls`) can only be left out, or listed as taking code.
/// `abbrev`: the tool accepts a unique prefix of a long name (GNU
/// `getopt_long`), so a listed long name that is a prefix of a code
/// option's is refused too. Spellings are `-x` or `--name`.
struct CodeOptions {
    head: &'static [u8],
    opts: &'static [&'static str],
    abbrev: bool,
}

const FD_CODE: &[&str] = &["-x", "--exec", "-X", "--exec-batch", "-l", "--list-details"];

const CODE_OPTION_HEADS: &[CodeOptions] = &[
    // fd runs a command per result (`-x`), per batch (`-X`), and `ls` for
    // `-l`. clap in fd does not infer abbreviated long options. Debian and
    // Ubuntu install it as `fdfind`.
    CodeOptions {
        head: b"fd",
        opts: FD_CODE,
        abbrev: false,
    },
    CodeOptions {
        head: b"fdfind",
        opts: FD_CODE,
        abbrev: false,
    },
    // `split --filter` runs a shell command per chunk.
    CodeOptions {
        head: b"split",
        opts: &["--filter"],
        abbrev: true,
    },
    CodeOptions {
        head: b"gsplit",
        opts: &["--filter"],
        abbrev: true,
    },
];

/// The code-running options of the head `head`, if it is in
/// [`CODE_OPTION_HEADS`], compared ASCII case-insensitively for the reason
/// given on [`is_inexpressible`].
fn code_options(head: &[u8]) -> Option<&'static CodeOptions> {
    CODE_OPTION_HEADS
        .iter()
        .find(|c| c.head.eq_ignore_ascii_case(head))
}

/// The code option of `c` that the row option `name` can be written as, if
/// any.
fn code_option_hit(c: &CodeOptions, name: &OptName) -> Option<&'static str> {
    let (_, long) = names_of(name);
    c.opts.iter().copied().find(|s| {
        let exact = spelling(s.as_bytes()).is_some_and(|code| overlaps(name, &code));
        let abbrev = c.abbrev
            && long.is_some_and(|l| {
                s.strip_prefix("--")
                    .is_some_and(|code| code.as_bytes().starts_with(l.bytes()))
            });
        exact || abbrev
    })
}

/// Where a catalog file comes from. A user hint replaces an embedded hint
/// with the same key; the file name says nothing about the origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Compiled into the binary.
    Embedded,
    /// The user's config or a file given to `shguard check`.
    User,
}

/// One catalog file's name, origin and text.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    /// The name used in error messages; display only.
    pub name: &'a str,
    /// Where the file comes from.
    pub origin: Origin,
    /// The TOML text.
    pub text: &'a str,
}

/// A loaded catalog: the kernel catalog, the rules, each rule's name
/// (`rule_ids[i]` names the rule with `RuleId(i)`) and reason, and the
/// hints.
#[derive(Debug)]
pub struct Loaded {
    /// The catalog rows.
    pub catalog: Catalog,
    /// The rules, in load order.
    pub rules: Vec<Rule>,
    /// The TOML id of each rule, indexed by its `RuleId`.
    pub rule_ids: Vec<String>,
    /// The `reason` text of each rule, if it has one, indexed by its
    /// `RuleId`.
    pub rule_reasons: Vec<Option<GuidanceText>>,
    /// Text for the reason of an Unknown command, by command key.
    pub hints: Vec<Hint>,
}

/// Text added to the reason when a command under `key` is Unknown. It
/// changes no decision and comes only from catalog files, never from the
/// command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    /// The command words the hint applies to (`["find"]`, `["git", "log"]`).
    pub key: Vec<Vec<u8>>,
    /// The text.
    pub text: GuidanceText,
}

/// A rule `reason` or a hint `text` that passed [`text_problem`]: not empty,
/// at most [`TEXT_CAP`] bytes, no line break, invisible or format character.
/// Only [`GuidanceText::new`] builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidanceText(String);

impl GuidanceText {
    /// Checks `text` and wraps it.
    ///
    /// # Errors
    ///
    /// The reason `text` cannot be guidance text.
    pub fn new(text: String) -> Result<Self, &'static str> {
        match text_problem(&text) {
            Some(why) => Err(why),
            None => Ok(Self(text)),
        }
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The most bytes a rule `reason` or a hint `text` may have.
pub const TEXT_CAP: usize = 300;

/// Why `text` cannot be a reason or hint text, if it cannot. The text goes
/// into the hook answer that the agent reads, so a line break (control
/// characters, U+2028, U+2029) or an invisible or format character (zero
/// width, bidirectional, joiner, variation selector, tag, fillers, soft
/// hyphen and the other `Cf` characters, which can make the text read
/// differently from its bytes or carry hidden text) is refused. The "300"
/// in the message is tied to `TEXT_CAP` by a loader test.
fn text_problem(text: &str) -> Option<&'static str> {
    if text.trim().is_empty() {
        Some("empty text")
    } else if text.len() > TEXT_CAP {
        Some("text longer than 300 bytes")
    } else if text.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '\u{00AD}'
                    | '\u{034F}'
                    | '\u{0600}'..='\u{0605}'
                    | '\u{061C}'
                    | '\u{06DD}'
                    | '\u{070F}'
                    | '\u{08E2}'
                    | '\u{115F}'..='\u{1160}'
                    | '\u{17B4}'..='\u{17B5}'
                    | '\u{180B}'..='\u{180F}'
                    | '\u{200B}'..='\u{200F}'
                    | '\u{2028}'..='\u{202E}'
                    | '\u{2060}'..='\u{206F}'
                    | '\u{3164}'
                    | '\u{FE00}'..='\u{FE0F}'
                    | '\u{FEFF}'
                    | '\u{FFA0}'
                    | '\u{FFF0}'..='\u{FFFB}'
                    | '\u{110BD}'
                    | '\u{110CD}'
                    | '\u{13430}'..='\u{1343F}'
                    | '\u{1BCA0}'..='\u{1BCA3}'
                    | '\u{1D173}'..='\u{1D17A}'
                    | '\u{E0000}'..='\u{E0FFF}'
            )
    }) {
        Some("text with a control, line separator, invisible or format character")
    } else {
        None
    }
}

/// Checks a rule `reason` or hint `text`; a bad one is recorded in `errs`.
fn guidance(
    file: &str,
    item: impl FnOnce() -> String,
    text: String,
    errs: &mut Vec<LoadError>,
) -> Option<GuidanceText> {
    match GuidanceText::new(text) {
        Ok(t) => Some(t),
        Err(why) => {
            errs.push(LoadError::BadText {
                file: file.to_owned(),
                item: item(),
                why,
            });
            None
        }
    }
}

/// A row as seen by the cross-row checks. `row` is `None` when the row
/// itself failed to build; its key still counts when it is well formed, so
/// one bad row does not cascade into orphan and dead-rule errors.
struct Entry {
    file: String,
    label: String,
    key: Vec<Vec<u8>>,
    row: Option<Row>,
}

/// Loads and checks catalog files.
///
/// A TOML or schema error stops that file only; the rows and rules of the
/// other files are still merged and checked, and every error is returned.
///
/// # Errors
///
/// Every [`LoadError`] found, if there is at least one.
pub fn load(sources: &[Source<'_>]) -> Result<Loaded, Vec<LoadError>> {
    let mut errs = Vec::new();
    let files = parse_sources(sources, &mut errs);
    load_files(files, errs)
}

/// Parses every source; the ones that fail add their error to `errs`.
pub(crate) fn parse_sources(
    sources: &[Source<'_>],
    errs: &mut Vec<LoadError>,
) -> Vec<(String, Origin, ParsedFile)> {
    let mut files = Vec::new();
    for src in sources {
        match parse_file(src.name, src.text) {
            Ok(file) => files.push((src.name.to_owned(), src.origin, file)),
            Err(e) => errs.push(e),
        }
    }
    files
}

/// A catalog file that parsed and matches the schema, but is not yet checked
/// against the other files.
#[derive(Debug)]
pub struct ParsedFile(FileDto);

/// Parses one catalog file.
///
/// # Errors
///
/// [`LoadError::Toml`] if the text is not valid TOML or does not match the
/// schema.
fn parse_file(name: &str, text: &str) -> Result<ParsedFile, LoadError> {
    toml::from_str::<FileDto>(text)
        .map(ParsedFile)
        .map_err(|error| LoadError::Toml {
            file: name.to_owned(),
            error,
        })
}

/// The settings of the user config other than its rows and rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigHead {
    /// What an Ask becomes.
    pub ask_outcome: AskOutcome,
    /// Where to append one JSON line per decision, if anywhere.
    pub decision_log: Option<PathBuf>,
}

/// Top-level keys of the shguard 0.9 user config that this schema lacks.
const LEGACY_KEYS: &[&str] = &[
    "deny",
    "ask",
    "allow",
    "redirect",
    "pipeline",
    "escalation_floor",
    "decision_log_path",
];

/// Parses the user config: `ask_outcome` and `decision_log` plus rows and
/// rules in the catalog schema. The rows and rules come back as a catalog
/// file to be merged with the others.
///
/// # Errors
///
/// [`LoadError::LegacyConfig`] if the text is a shguard 0.9 config,
/// [`LoadError::Toml`] if it is otherwise not valid TOML or does not match
/// the schema, and [`LoadError::DecisionLogNotAbsolute`].
pub fn parse_config(name: &str, text: &str) -> Result<(ConfigHead, ParsedFile), LoadError> {
    let c = match toml::from_str::<ConfigDto>(text) {
        Ok(c) => c,
        Err(source) if is_legacy(text) => {
            drop(source);
            return Err(LoadError::LegacyConfig {
                file: name.to_owned(),
            });
        }
        Err(error) => {
            return Err(LoadError::Toml {
                file: name.to_owned(),
                error,
            });
        }
    };
    let decision_log = match c.decision_log.map(PathBuf::from) {
        Some(p) if !p.is_absolute() => {
            return Err(LoadError::DecisionLogNotAbsolute {
                file: name.to_owned(),
            });
        }
        other => other,
    };
    Ok((
        ConfigHead {
            ask_outcome: c.ask_outcome,
            decision_log,
        },
        ParsedFile(FileDto {
            row: c.row,
            rule: c.rule,
            hint: c.hint,
        }),
    ))
}

/// The text is TOML whose top level has a 0.9-only key, or an
/// `ask_outcome` table (0.9 also took a table there).
fn is_legacy(text: &str) -> bool {
    let Ok(table) = toml::from_str::<toml::Table>(text) else {
        return false;
    };
    LEGACY_KEYS.iter().any(|k| table.contains_key(*k))
        || table.get("ask_outcome").is_some_and(toml::Value::is_table)
}

/// Merges and checks parsed files. `errs` are the errors found while
/// parsing the other files; they are returned with the ones found here.
///
/// # Errors
///
/// Every [`LoadError`] found, if there is at least one.
pub(crate) fn load_files(
    files: Vec<(String, Origin, ParsedFile)>,
    mut errs: Vec<LoadError>,
) -> Result<Loaded, Vec<LoadError>> {
    let mut entries = Vec::new();
    let mut rule_dtos: Vec<(String, RuleDto)> = Vec::new();
    let mut hints: Vec<(Hint, Origin)> = Vec::new();
    for (name, origin, ParsedFile(file)) in files {
        for row in file.row {
            entries.push(build_row(&name, row, &mut errs));
        }
        rule_dtos.extend(file.rule.into_iter().map(|r| (name.clone(), r)));
        // A user hint replaces an embedded hint with the same key; two
        // hints of one origin with the same key stay an error.
        for h in file.hint {
            let pool: Vec<&Hint> = hints
                .iter()
                .filter(|(_, o)| origin == Origin::Embedded || *o == Origin::User)
                .map(|(h, _)| h)
                .collect();
            if let Some(hint) = build_hint(&name, h, &pool, &mut errs) {
                hints.retain(|(x, _)| x.key != hint.key);
                hints.push((hint, origin));
            }
        }
    }
    check_rows(&entries, &mut errs);
    let mut rules = Vec::new();
    let mut rule_ids = Vec::new();
    let mut rule_reasons = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (index, (file_name, dto)) in rule_dtos.into_iter().enumerate() {
        let file = file_name.as_str();
        // The id is the only locator in rule errors and in the hook reason.
        if dto.id.trim().is_empty() {
            errs.push(LoadError::EmptyRuleId {
                file: file.to_owned(),
            });
        } else if !dto
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            errs.push(LoadError::BadRuleId {
                file: file.to_owned(),
                rule: dto.id.clone(),
            });
        } else if !seen.insert(dto.id.clone()) {
            errs.push(LoadError::DuplicateRuleId {
                file: file.to_owned(),
                rule: dto.id.clone(),
            });
        }
        let id = match u32::try_from(index) {
            Ok(n) => RuleId(n),
            Err(_) => {
                errs.push(LoadError::TooManyRules {
                    file: file.to_owned(),
                    rule: dto.id.clone(),
                });
                continue;
            }
        };
        let name = dto.id.clone();
        let reason = dto
            .reason
            .clone()
            .and_then(|t| guidance(file, || format!("rule {name:?}"), t, &mut errs));
        if let Some(rule) = build_rule(file, id, dto, &entries, &mut errs) {
            rules.push(rule);
        }
        rule_ids.push(name);
        rule_reasons.push(reason);
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    let rows = entries.into_iter().filter_map(|e| e.row).collect();
    Ok(Loaded {
        catalog: Catalog::new(rows, Vec::new()),
        rules,
        rule_ids,
        rule_reasons,
        hints: hints.into_iter().map(|(h, _)| h).collect(),
    })
}

/// Checks one hint against the hints before it. A hint key needs no row:
/// a hint is most useful for a command that has none (`find`).
fn build_hint(
    file: &str,
    dto: HintDto,
    before: &[&Hint],
    errs: &mut Vec<LoadError>,
) -> Option<Hint> {
    let label = dto.key.join(" ");
    let key = seg_bytes(&dto.key);
    let mut ok = true;
    if !key_ok(&key)
        || option_like(&dto.key)
        || dto
            .key
            .iter()
            .any(|s| text_problem(s).is_some() || s.chars().any(char::is_whitespace))
    {
        errs.push(LoadError::BadHintKey {
            file: file.to_owned(),
            hint: label.clone(),
        });
        ok = false;
    } else if before.iter().any(|h| h.key == key) {
        errs.push(LoadError::DuplicateHint {
            file: file.to_owned(),
            hint: label.clone(),
        });
        ok = false;
    }
    let text = guidance(file, || format!("hint {label:?}"), dto.text, errs);
    text.filter(|_| ok).map(|text| Hint { key, text })
}

fn role(r: RoleDto) -> Role {
    match r {
        RoleDto::Inert => Role::Inert,
        RoleDto::Path => Role::Path,
        RoleDto::Code => Role::Code,
    }
}

fn value(v: ValueDto) -> OptValue {
    match v {
        ValueDto::Flag => OptValue::Flag,
        ValueDto::Takes(r) => OptValue::Takes(role(r)),
        ValueDto::Optional(r) => OptValue::Optional(role(r)),
    }
}

/// Whether a key segment starts with `-` or `+`. Such a segment would be
/// selected ahead of a shorter row and swallow the option (`["rm", "-rf"]`
/// over `["rm"]`). Only a `runs_code` row may have one, and only as its last
/// segment spelling a single option (`["python", "-c"]`, #1070): it can never
/// cover a command, so it cannot widen Allow.
fn option_like(key: &[String]) -> bool {
    key.iter().any(|s| s.starts_with(['-', '+']))
}

/// Whether the key's only option-like segment is the last one and reads as
/// `-x` or `--name`.
fn is_option_child(key: &[String]) -> bool {
    match key.split_last() {
        Some((last, init)) => !option_like(init) && spelling(last.as_bytes()).is_some(),
        None => false,
    }
}

fn seg_bytes(key: &[String]) -> Vec<Vec<u8>> {
    key.iter().map(|s| s.as_bytes().to_vec()).collect()
}

/// Builds an option name from its `short` and `long` fields.
fn opt_name(file: &str, row: &str, dto: &OptDto, errs: &mut Vec<LoadError>) -> Option<OptName> {
    let bad = |name: &str| LoadError::BadOptName {
        file: file.to_owned(),
        row: row.to_owned(),
        name: name.to_owned(),
    };
    let short = match dto.short.as_deref().map(str::as_bytes) {
        None => None,
        Some(&[b]) => {
            let s = ShortName::new(b);
            if s.is_none() {
                errs.push(bad(dto.short.as_deref().unwrap_or_default()));
            }
            s
        }
        Some(_) => {
            errs.push(bad(dto.short.as_deref().unwrap_or_default()));
            None
        }
    };
    let long = dto.long.as_deref().and_then(|l| {
        let n = LongName::new(l.as_bytes().to_vec());
        if n.is_none() {
            errs.push(bad(l));
        }
        n
    });
    match (&dto.short, &dto.long, short, long) {
        (None, None, _, _) => {
            errs.push(LoadError::OptWithoutName {
                file: file.to_owned(),
                row: row.to_owned(),
            });
            None
        }
        (_, _, Some(s), Some(l)) => Some(OptName::Both(s, l)),
        (_, None, Some(s), None) => Some(OptName::Short(s)),
        (None, _, None, Some(l)) => Some(OptName::Long(l)),
        // A name was given but rejected; the error is already recorded.
        (_, _, _, _) => None,
    }
}

fn build_row(file: &str, dto: RowDto, errs: &mut Vec<LoadError>) -> Entry {
    let label = dto.key.join(" ");
    let key = seg_bytes(&dto.key);
    let before = errs.len();
    let key_valid = key_ok(&key);
    if !key_valid {
        errs.push(LoadError::BadRowKey {
            file: file.to_owned(),
            row: label.clone(),
        });
    }
    if option_like(&dto.key) && !(dto.runs_code && is_option_child(&dto.key)) {
        errs.push(LoadError::OptionLikeKey {
            file: file.to_owned(),
            item: format!("row {label:?}"),
        });
    }
    if dto.source.as_deref().is_none_or(|s| s.trim().is_empty()) {
        errs.push(LoadError::MissingSource {
            file: file.to_owned(),
            row: label.clone(),
        });
    }
    if key_valid && !dto.runs_code && key.first().is_some_and(|h| is_inexpressible(h)) {
        errs.push(LoadError::DenylistedHead {
            file: file.to_owned(),
            row: label.clone(),
        });
    }
    if key.first().is_some_and(|h| h.contains(&b'/')) {
        errs.push(LoadError::PathHead {
            file: file.to_owned(),
            row: label.clone(),
        });
    }
    if let Some(h) = dto.key.first().filter(|h| !h.is_ascii()) {
        errs.push(LoadError::NonAsciiHead {
            file: file.to_owned(),
            row: label.escape_default().to_string(),
            head: h.escape_default().to_string(),
        });
    }
    if dto.changes_cwd && dto.cwd_sensitive {
        errs.push(LoadError::ConflictingCwd {
            file: file.to_owned(),
            row: label.clone(),
        });
    }
    let code_opts = if key_valid && !dto.runs_code {
        key.first().and_then(|h| code_options(h))
    } else {
        None
    };
    let mut opts = Vec::new();
    let mut shorts: Vec<u8> = Vec::new();
    let mut longs: Vec<Vec<u8>> = Vec::new();
    for o in &dto.opt {
        let Some(name) = opt_name(file, &label, o, errs) else {
            continue;
        };
        if let Some(c) = code_opts
            && !matches!(o.value, ValueDto::Takes(RoleDto::Code))
            && let Some(hit) = code_option_hit(c, &name)
        {
            errs.push(LoadError::CodeOptionNotCode {
                file: file.to_owned(),
                row: label.clone(),
                opt: hit.to_owned(),
            });
        }
        let (s, l) = names_of(&name);
        if let Some(s) = s {
            if shorts.contains(&s.byte()) {
                errs.push(LoadError::DuplicateOpt {
                    file: file.to_owned(),
                    row: label.clone(),
                    name: format!("-{}", char::from(s.byte())),
                });
            }
            shorts.push(s.byte());
        }
        if let Some(l) = l {
            if longs.iter().any(|x| x.as_slice() == l.bytes()) {
                errs.push(LoadError::DuplicateOpt {
                    file: file.to_owned(),
                    row: label.clone(),
                    name: format!("--{}", String::from_utf8_lossy(l.bytes())),
                });
            }
            longs.push(l.bytes().to_vec());
        }
        opts.push(Opt::new(name, value(o.value)));
    }
    let row = if errs.len() == before {
        let grammar = Grammar::new(
            opts,
            dto.positionals.iter().copied().map(role).collect(),
            dto.rest.map(role),
            match dto.order {
                OrderDto::Permute => Order::Permute,
                OrderDto::Strict => Order::Strict,
            },
            match dto.dashdash {
                DashDashDto::Ends => DashDash::Ends,
                DashDashDto::Literal => DashDash::Literal,
            },
            match dto.plus_words {
                PlusWordsDto::Reject => PlusWords::Reject,
                PlusWordsDto::Operand => PlusWords::Operand,
            },
        );
        Row::new(
            key.clone(),
            grammar,
            if dto.runs_code {
                RunsCode::Yes
            } else {
                RunsCode::No
            },
            if dto.changes_cwd {
                Cwd::Changes
            } else if dto.cwd_sensitive {
                Cwd::Sensitive
            } else {
                Cwd::Keeps
            },
        )
    } else {
        None
    };
    Entry {
        file: file.to_owned(),
        label,
        // An ill-formed key matches nothing, so it is kept out of the
        // key-based checks.
        key: if key_valid { key } else { Vec::new() },
        row,
    }
}

fn names_of(n: &OptName) -> (Option<ShortName>, Option<&LongName>) {
    match n {
        OptName::Short(s) => (Some(*s), None),
        OptName::Long(l) => (None, Some(l)),
        OptName::Both(s, l) => (Some(*s), Some(l)),
    }
}

/// Whether an option named `have` can be written as `want`.
fn overlaps(have: &OptName, want: &OptName) -> bool {
    let (hs, hl) = names_of(have);
    let (ws, wl) = names_of(want);
    let short = matches!((hs, ws), (Some(a), Some(b)) if a.byte() == b.byte());
    let long = matches!((hl, wl), (Some(a), Some(b)) if a.bytes() == b.bytes());
    short || long
}

/// Reads `-x` or `--name` as written on argv.
fn spelling(s: &[u8]) -> Option<OptName> {
    if let Some(rest) = s.strip_prefix(b"--") {
        LongName::new(rest.to_vec()).map(OptName::Long)
    } else if let &[b'-', b] = s {
        ShortName::new(b).map(OptName::Short)
    } else {
        None
    }
}

fn check_rows(entries: &[Entry], errs: &mut Vec<LoadError>) {
    // Keys compare ASCII case-insensitively, so `FD` cannot shadow `fd` (#1168).
    let mut first: HashMap<Vec<Vec<u8>>, &str> = HashMap::new();
    for e in entries.iter().filter(|e| !e.key.is_empty()) {
        let folded: Vec<Vec<u8>> = e.key.iter().map(|w| w.to_ascii_lowercase()).collect();
        if let Some(&first_file) = first.get(&folded) {
            errs.push(LoadError::DuplicateRow {
                file: e.file.clone(),
                row: e.label.clone(),
                first_file: first_file.to_owned(),
            });
        } else {
            first.insert(folded, e.file.as_str());
            check_code_child(e, entries, errs);
            check_cwd_child(e, entries, errs);
        }
        if let Some((_, parent)) = e.key.split_last()
            && !parent.is_empty()
            && !has_key(entries, parent)
        {
            errs.push(LoadError::OrphanRow {
                file: e.file.clone(),
                row: e.label.clone(),
            });
        }
    }
}

fn has_key(entries: &[Entry], key: &[Vec<u8>]) -> bool {
    entries.iter().any(|e| e.key == key)
}

/// #1070 A: a parent option that spells a `runs_code` child's last key
/// segment must take a `Code` value.
fn check_code_child(child: &Entry, entries: &[Entry], errs: &mut Vec<LoadError>) {
    let Some(row) = &child.row else { return };
    if row.runs_code() == RunsCode::No {
        return;
    }
    let Some((last, parent_key)) = child.key.split_last() else {
        return;
    };
    if parent_key.is_empty() {
        return;
    }
    let Some(want) = spelling(last) else { return };
    for parent in entries.iter().filter(|e| e.key == parent_key) {
        let Some(prow) = &parent.row else { continue };
        for opt in prow.grammar().opts() {
            if overlaps(opt.name(), &want) && !matches!(opt.value(), OptValue::Takes(Role::Code)) {
                errs.push(LoadError::ParentOptNotCode {
                    file: parent.file.clone(),
                    row: parent.label.clone(),
                    opt: String::from_utf8_lossy(last).into_owned(),
                });
            }
        }
    }
}

/// The kernel reads `cwd_sensitive` from the selected row only, and the
/// longest key wins, so a child of a `cwd_sensitive` row (`git status` under
/// `git`) must say it again; otherwise `cd /x && git status` would not be
/// asked.
fn check_cwd_child(child: &Entry, entries: &[Entry], errs: &mut Vec<LoadError>) {
    let Some(row) = &child.row else { return };
    if row.cwd() == Cwd::Sensitive {
        return;
    }
    let Some((_, parent_key)) = child.key.split_last() else {
        return;
    };
    if parent_key.is_empty() {
        return;
    }
    let parent_sensitive = entries
        .iter()
        .any(|p| p.key == parent_key && p.row.as_ref().is_some_and(|r| r.cwd() == Cwd::Sensitive));
    if parent_sensitive {
        errs.push(LoadError::CwdSensitiveParent {
            file: child.file.clone(),
            row: child.label.clone(),
        });
    }
}

fn target_parts(s: &str) -> Vec<Part> {
    if let Some(rest) = s.strip_prefix('~') {
        let mut parts = vec![Part::Opaque(Opaque::Tilde)];
        if !rest.is_empty() {
            parts.push(Part::Lit(rest.as_bytes().to_vec()));
        }
        parts
    } else if s.is_empty() {
        Vec::new()
    } else {
        vec![Part::Lit(s.as_bytes().to_vec())]
    }
}

fn build_target(file: &str, rule: &str, t: &TargetDto, errs: &mut Vec<LoadError>) -> Option<Pat> {
    if t.pat.contains('$') {
        errs.push(LoadError::TargetHasDollar {
            file: file.to_owned(),
            rule: rule.to_owned(),
        });
        return None;
    }
    // The lexer accepts `~` only before `/` or at the end of a word, so a
    // `~user` target could never match.
    if t.pat
        .strip_prefix('~')
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
    {
        errs.push(LoadError::TildeUserTarget {
            file: file.to_owned(),
            rule: rule.to_owned(),
            pat: t.pat.clone(),
        });
        return None;
    }
    let kind = match t.kind {
        PatKindDto::Exact => PatKind::Exact,
        PatKindDto::Prefix => PatKind::Prefix,
        PatKindDto::Under => PatKind::Under,
        PatKindDto::Component => PatKind::Component,
        PatKindDto::ComponentPrefix => PatKind::ComponentPrefix,
    };
    // A component pattern is matched against the segments of the word's
    // key, which has no `~` and whose segments never start with `/`, so a
    // `~` or `/` lead could only ever match at the key's start, which is
    // what `prefix` and `under` already say.
    if matches!(kind, PatKind::Component | PatKind::ComponentPrefix)
        && t.pat.starts_with(['~', '/'])
    {
        errs.push(LoadError::AnchoredComponentTarget {
            file: file.to_owned(),
            rule: rule.to_owned(),
            pat: t.pat.clone(),
        });
        return None;
    }
    // Words keep `..` unresolved (`a/../.ssh` is not `.ssh`), so a component
    // that is `..` would match a traversal, not a name. `exact`, `prefix`
    // and `under` compare whole normalized forms on both sides and stay
    // coherent with `..`, so only the component kinds refuse it.
    if matches!(kind, PatKind::Component | PatKind::ComponentPrefix)
        && t.pat.split('/').any(|seg| seg == "..")
    {
        errs.push(LoadError::DotDotTarget {
            file: file.to_owned(),
            rule: rule.to_owned(),
            pat: t.pat.clone(),
        });
        return None;
    }
    let (head, body) = match t.pat.strip_prefix('~') {
        Some(rest) => ("~", rest),
        None => ("", t.pat.as_str()),
    };
    let normal = normalize_path(body.as_bytes());
    let full = format!("{head}{}", String::from_utf8_lossy(&normal));
    // A `prefix` that ends in `/` is a component match spelled as a byte
    // prefix, and the kernel's normalized key drops that `/` (`.git/` would
    // cover `.github`); `under` says it without the `/`. A target whose
    // normal form ends in `/` (`~/.` is `~/`) gets this error directly, not
    // a "write `~/`" that this check would then reject.
    if matches!(kind, PatKind::Prefix)
        && full != "/"
        && (t.pat.ends_with('/') || full.ends_with('/'))
    {
        errs.push(LoadError::PrefixEndsInSlash {
            file: file.to_owned(),
            rule: rule.to_owned(),
            pat: t.pat.clone(),
        });
        return None;
    }
    // The kernel compares normalized words with normalized targets, so a
    // target out of normal form (`./x`, `a//b`, `x/`) means at best the same
    // as its normal form; require that form. This check has no proof.
    if normal != body.as_bytes() {
        errs.push(LoadError::TargetNotNormal {
            file: file.to_owned(),
            rule: rule.to_owned(),
            pat: t.pat.clone(),
            normal: full,
        });
        return None;
    }
    // Words are compared in normal form, where `./x` is `x`, so `.` as a
    // `prefix` or `under` target reads as "anything relative" but covers only
    // `.` (under) or dot names such as `.git` (prefix). As a component it
    // would cover only the word `.` (component) or every dot name
    // (component_prefix).
    if t.pat == "." && !matches!(kind, PatKind::Exact) {
        errs.push(LoadError::DotTarget {
            file: file.to_owned(),
            rule: rule.to_owned(),
        });
        return None;
    }
    let pat = Pat::new(target_parts(&t.pat), kind);
    if pat.is_none() {
        errs.push(LoadError::EmptyTarget {
            file: file.to_owned(),
            rule: rule.to_owned(),
        });
    }
    pat
}

fn is_prefix(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    b.starts_with(a)
}

fn build_rule(
    file: &str,
    id: RuleId,
    dto: RuleDto,
    entries: &[Entry],
    errs: &mut Vec<LoadError>,
) -> Option<Rule> {
    let before = errs.len();
    let key = seg_bytes(&dto.key);
    let key_valid = key_ok(&key);
    if !key_valid {
        errs.push(LoadError::BadRuleKey {
            file: file.to_owned(),
            rule: dto.id.clone(),
        });
    }
    let names_code_row = entries.iter().any(|e| {
        e.key == key
            && e.row
                .as_ref()
                .is_some_and(|r| r.runs_code() == RunsCode::Yes)
    });
    if option_like(&dto.key) && !names_code_row {
        errs.push(LoadError::OptionLikeKey {
            file: file.to_owned(),
            item: format!("rule {:?}", dto.id),
        });
    }
    // Rows whose key is a prefix of the rule's, or extends it.
    let related: Vec<&Entry> = entries
        .iter()
        .filter(|e| !e.key.is_empty() && (is_prefix(&e.key, &key) || is_prefix(&key, &e.key)))
        .collect();
    if key_valid && related.is_empty() {
        errs.push(LoadError::DeadRule {
            file: file.to_owned(),
            rule: dto.id.clone(),
        });
    }
    let grammars: Vec<&Grammar> = related
        .iter()
        .filter_map(|e| e.row.as_ref().map(Row::grammar))
        .collect();
    let mut opts = Vec::new();
    for alias_set in &dto.opts {
        let mut names = Vec::new();
        let mut set_ok = true;
        for spelt in alias_set {
            let Some(name) = spelling(spelt.as_bytes()) else {
                set_ok = false;
                errs.push(LoadError::BadRuleOpt {
                    file: file.to_owned(),
                    rule: dto.id.clone(),
                    name: spelt.clone(),
                });
                continue;
            };
            if !grammars.is_empty()
                && !grammars
                    .iter()
                    .any(|g| g.opts().iter().any(|o| overlaps(o.name(), &name)))
            {
                errs.push(LoadError::UnknownRuleOpt {
                    file: file.to_owned(),
                    rule: dto.id.clone(),
                    name: spelt.clone(),
                });
            }
            names.push(name);
        }
        if set_ok {
            match OptAlts::new(names) {
                Some(a) => opts.push(a),
                None => errs.push(LoadError::EmptyAlts {
                    file: file.to_owned(),
                    rule: dto.id.clone(),
                }),
            }
        }
    }
    let targets: Vec<Pat> = dto
        .targets
        .iter()
        .filter_map(|t| build_target(file, &dto.id, t, errs))
        .collect();
    if errs.len() != before {
        return None;
    }
    Rule::new(
        id,
        match dto.scope {
            ScopeDto::Simple => Scope::Simple,
            ScopeDto::PipeInto => Scope::PipeInto,
        },
        key,
        opts,
        targets,
        match dto.outcome {
            OutcomeDto::Ask => Outcome::Ask,
            OutcomeDto::Block => Outcome::Block,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denylist_entries_are_ascii_lowercase() {
        for h in INEXPRESSIBLE_HEADS.iter().chain(VERSIONED_INTERPRETERS) {
            assert!(
                h.is_ascii() && h.to_ascii_lowercase() == *h,
                "{}",
                String::from_utf8_lossy(h)
            );
        }
    }
}
