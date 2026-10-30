//! Turns catalog TOML into kernel values and checks the whole set.

use std::collections::{HashMap, HashSet};

use shguard_kernel::ast::{Opaque, Part};
use shguard_kernel::catalog::{
    Catalog, Cwd, DashDash, Grammar, LongName, Opt, OptName, OptValue, Order, PlusWords, Role, Row,
    RunsCode, ShortName, key_ok,
};
use shguard_kernel::rule::{OptAlts, Outcome, Pat, PatKind, Rule, RuleId, Scope};

use super::LoadError;
use super::dto::{
    AskOutcome, ConfigDto, DashDashDto, FileDto, OptDto, OrderDto, OutcomeDto, PatKindDto,
    PlusWordsDto, RoleDto, RowDto, RuleDto, ScopeDto, TargetDto, ValueDto,
};

/// Command heads whose tools have dash-less option bundles (`tar xf`) or
/// single-dash long options (`find -exec`, `ps -ef`) that the option grammar
/// cannot express (#1039). A row for one of them must set `runs_code`, so it
/// can never cover a command. Extended in M14.
const INEXPRESSIBLE_HEADS: [&[u8]; 4] = [b"tar", b"ps", b"ar", b"find"];

/// One catalog file's name and text.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    /// The name used in error messages.
    pub name: &'a str,
    /// The TOML text.
    pub text: &'a str,
}

/// A loaded catalog: the kernel catalog, the rules, and each rule's name
/// (`rule_ids[i]` names the rule with `RuleId(i)`).
#[derive(Debug)]
pub struct Loaded {
    /// The catalog rows.
    pub catalog: Catalog,
    /// The rules, in load order.
    pub rules: Vec<Rule>,
    /// The TOML id of each rule, indexed by its `RuleId`.
    pub rule_ids: Vec<String>,
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
    let mut files = Vec::new();
    for src in sources {
        match parse_file(src.name, src.text) {
            Ok(file) => files.push((src.name.to_owned(), file)),
            Err(e) => errs.push(e),
        }
    }
    load_files(files, errs)
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
pub fn parse_file(name: &str, text: &str) -> Result<ParsedFile, LoadError> {
    toml::from_str::<FileDto>(text)
        .map(ParsedFile)
        .map_err(|source| LoadError::Toml {
            file: name.to_owned(),
            source,
        })
}

/// Parses the user config: `ask_outcome` plus rows and rules in the catalog
/// schema. The rows and rules come back as a catalog file to be merged with
/// the others.
///
/// # Errors
///
/// [`LoadError::Toml`] if the text is not valid TOML or does not match the
/// schema.
pub fn parse_config(name: &str, text: &str) -> Result<(AskOutcome, ParsedFile), LoadError> {
    toml::from_str::<ConfigDto>(text)
        .map(|c| {
            (
                c.ask_outcome,
                ParsedFile(FileDto {
                    row: c.row,
                    rule: c.rule,
                }),
            )
        })
        .map_err(|source| LoadError::Toml {
            file: name.to_owned(),
            source,
        })
}

/// Merges and checks parsed files. `errs` are the errors found while
/// parsing the other files; they are returned with the ones found here.
///
/// # Errors
///
/// Every [`LoadError`] found, if there is at least one.
pub fn load_files(
    files: Vec<(String, ParsedFile)>,
    mut errs: Vec<LoadError>,
) -> Result<Loaded, Vec<LoadError>> {
    let mut entries = Vec::new();
    let mut rule_dtos: Vec<(String, RuleDto)> = Vec::new();
    for (name, ParsedFile(file)) in files {
        for row in file.row {
            entries.push(build_row(&name, row, &mut errs));
        }
        rule_dtos.extend(file.rule.into_iter().map(|r| (name.clone(), r)));
    }
    check_rows(&entries, &mut errs);
    let mut rules = Vec::new();
    let mut rule_ids = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (index, (file_name, dto)) in rule_dtos.into_iter().enumerate() {
        let file = file_name.as_str();
        if !seen.insert(dto.id.clone()) {
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
        if let Some(rule) = build_rule(file, id, dto, &entries, &mut errs) {
            rules.push(rule);
        }
        rule_ids.push(name);
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    let rows = entries.into_iter().filter_map(|e| e.row).collect();
    Ok(Loaded {
        catalog: Catalog::new(rows, Vec::new()),
        rules,
        rule_ids,
    })
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
/// over `["rm"]`). Only a `runs_code` row may have one (`["python", "-c"]`,
/// #1070): it can never cover a command, so it cannot widen Allow.
fn option_like(key: &[String]) -> bool {
    key.iter().any(|s| s.starts_with(['-', '+']))
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
    if !dto.runs_code && option_like(&dto.key) {
        errs.push(LoadError::OptionLikeKey {
            file: file.to_owned(),
            item: format!("row `{label}`"),
        });
    }
    if dto.source.as_deref().is_none_or(|s| s.trim().is_empty()) {
        errs.push(LoadError::MissingSource {
            file: file.to_owned(),
            row: label.clone(),
        });
    }
    if key_valid
        && !dto.runs_code
        && key
            .first()
            .is_some_and(|h| INEXPRESSIBLE_HEADS.contains(&h.as_slice()))
    {
        errs.push(LoadError::DenylistedHead {
            file: file.to_owned(),
            row: label.clone(),
        });
    }
    let mut opts = Vec::new();
    let mut shorts: Vec<u8> = Vec::new();
    let mut longs: Vec<Vec<u8>> = Vec::new();
    for o in &dto.opt {
        let Some(name) = opt_name(file, &label, o, errs) else {
            continue;
        };
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
    let mut first: HashMap<&[Vec<u8>], &str> = HashMap::new();
    for e in entries.iter().filter(|e| !e.key.is_empty()) {
        if let Some(&first_file) = first.get(e.key.as_slice()) {
            errs.push(LoadError::DuplicateRow {
                file: e.file.clone(),
                row: e.label.clone(),
                first_file: first_file.to_owned(),
            });
        } else {
            first.insert(e.key.as_slice(), e.file.as_str());
            check_code_child(e, entries, errs);
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
            if overlaps(opt.name(), &want)
                && !matches!(
                    opt.value(),
                    OptValue::Takes(Role::Code) | OptValue::Optional(Role::Code)
                )
            {
                errs.push(LoadError::ParentOptNotCode {
                    file: parent.file.clone(),
                    row: parent.label.clone(),
                    opt: String::from_utf8_lossy(last).into_owned(),
                });
            }
        }
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
    let kind = match t.kind {
        PatKindDto::Exact => PatKind::Exact,
        PatKindDto::Prefix => PatKind::Prefix,
    };
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
            item: format!("rule `{}`", dto.id),
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
