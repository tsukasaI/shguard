//! Loads `rules/catalog.toml` into [`CommandSpec`]s. The serde DTOs live
//! here so that `spec` stays free of serde.
//!
//! The loaded data is leaked once into `&'static` slices: the catalog lives
//! for the whole process, and every reader keeps its `&'static` signature.

use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;

use super::spec::{ArgOrder, CommandSpec, CwdEffect, OptionGrammar, Slot, SubcommandSet};

pub(super) const EMBEDDED_CATALOG: &str = include_str!("../../rules/catalog.toml");

#[derive(Debug, thiserror::Error)]
pub(crate) enum CatalogError {
    #[error("{0}")]
    Toml(#[from] toml::de::Error),
    #[error("the command {command:?} names the unknown grammar {grammar:?}")]
    UnknownGrammar { command: String, grammar: String },
    #[error("{0:?} is named by two commands")]
    DuplicateName(String),
    #[error("the command {command:?} is open but gives no justification")]
    OpenWithoutJustification { command: String },
    #[error("the command {command:?} gives a justification but is closed")]
    JustificationOnClosed { command: String },
    #[error("the catalog has no commands")]
    Empty,
    #[error("a command row has no names")]
    EmptyNames,
    #[error("the command {command:?} has an empty entry in {field}")]
    EmptyEntry {
        command: String,
        field: &'static str,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogDto {
    #[serde(default)]
    grammar: BTreeMap<String, GrammarDto>,
    command: Vec<CommandDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandDto {
    names: Vec<String>,
    grammar: Option<String>,
    #[serde(default)]
    options: GrammarDto,
    #[serde(default)]
    slots: Vec<SlotDto>,
    #[serde(default)]
    code_options: Vec<String>,
    #[serde(default)]
    code_subcommands: Vec<Vec<String>>,
    #[serde(default)]
    env_code: Vec<String>,
    #[serde(default)]
    reads_files: Vec<String>,
    #[serde(default)]
    persists: Vec<String>,
    cwd_effect: Option<CwdEffectDto>,
    #[serde(default)]
    subcommands: SubcommandSetDto,
    justification: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SubcommandSetDto {
    #[default]
    Closed,
    Open,
}

/// Every field is optional so that a row can set fields on top of a named
/// grammar; an absent field keeps the base's value.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrammarDto {
    short_flags: Option<String>,
    short_values: Option<String>,
    short_glued: Option<String>,
    short_values_unless_dash: Option<String>,
    long_flags: Option<Vec<String>>,
    long_values: Option<Vec<String>>,
    long_glued: Option<Vec<String>>,
    dash_words: Option<Vec<String>>,
    dash_word_values: Option<Vec<String>>,
    any_long_attached: Option<bool>,
    bare_dash_option: Option<bool>,
    dash_command_unmodeled: Option<bool>,
    numeric_option: Option<bool>,
    assignments: Option<bool>,
    leading_operand: Option<bool>,
    order: Option<ArgOrderDto>,
    long_pairs: Option<Vec<String>>,
    single_dash_long: Option<bool>,
    command_after: Option<Vec<String>>,
    skip_first_operand: Option<Vec<String>>,
    plus_operand: Option<bool>,
    floor_options: Option<Vec<String>>,
    floor_values: Option<Vec<FloorValueDto>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FloorValueDto {
    short: char,
    values: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ArgOrderDto {
    FirstOperand,
    PermuteUntilCommand,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CwdEffectDto {
    Composed,
    Relocates,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwitchDto {
    short: char,
    long: String,
}

// Unit variants are empty struct variants: serde does not reject an
// unknown key next to the tag of an internally tagged unit variant.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SlotDto {
    Exec {},
    Operands {
        count: usize,
    },
    ShellScript {
        short: Option<char>,
        long: Option<String>,
    },
    ShellPassthrough {},
    SplitString {
        short: char,
        long: String,
    },
    PipedOutput {
        short: char,
        long: String,
    },
    OperandsAsShellScript {
        exec_short: char,
        exec_long: String,
    },
    OperandsJoinedShellScript {},
    OperandsAsShellScriptWith {
        switches: Vec<SwitchDto>,
    },
    Subcommands {
        alternatives: Vec<Vec<String>>,
    },
    UnmodeledSubcommands {
        alternatives: Vec<Vec<String>>,
    },
    KeyedShellScript {
        short: char,
        keys: Vec<String>,
    },
    Cwd {
        short: char,
        long: String,
        effect: CwdEffectDto,
    },
    CwdSwitch {
        short: char,
        long: String,
        effect: CwdEffectDto,
    },
    CwdBareDash {
        effect: CwdEffectDto,
    },
    Privilege {},
}

/// Parses catalog TOML, resolving every `grammar = "<name>"` reference.
///
/// # Errors
///
/// [`CatalogError`] when the TOML does not match the schema (an unknown
/// field, a character field that is not exactly one character), a row names
/// an unknown grammar, two rows claim the same name, there are no rows, a row
/// has no names, an open row lacks a justification, or a row's list holds an
/// empty entry.
pub(super) fn parse(text: &str) -> Result<&'static [CommandSpec], CatalogError> {
    let dto: CatalogDto = toml::from_str(text)?;
    if dto.command.is_empty() {
        return Err(CatalogError::Empty);
    }
    let grammars: BTreeMap<String, OptionGrammar> = dto
        .grammar
        .into_iter()
        .map(|(name, grammar)| (name, grammar.over(OptionGrammar::EMPTY)))
        .collect();
    let mut seen = HashSet::new();
    let mut specs = Vec::with_capacity(dto.command.len());
    for row in dto.command {
        if row.names.is_empty() {
            return Err(CatalogError::EmptyNames);
        }
        let base = match row.grammar {
            None => OptionGrammar::EMPTY,
            Some(name) => *grammars
                .get(&name)
                .ok_or_else(|| CatalogError::UnknownGrammar {
                    command: row.names.first().cloned().unwrap_or_default(),
                    grammar: name.clone(),
                })?,
        };
        for name in &row.names {
            if !seen.insert(name.clone()) {
                return Err(CatalogError::DuplicateName(name.clone()));
            }
        }
        let command = || row.names.first().cloned().unwrap_or_default();
        let blank = |text: &String| text.trim().is_empty();
        for (field, empty) in [
            ("code_options", row.code_options.iter().any(blank)),
            (
                "code_subcommands",
                row.code_subcommands
                    .iter()
                    .any(|path| path.is_empty() || path.iter().any(blank)),
            ),
            ("env_code", row.env_code.iter().any(blank)),
            ("reads_files", row.reads_files.iter().any(blank)),
            ("persists", row.persists.iter().any(blank)),
        ] {
            if empty {
                return Err(CatalogError::EmptyEntry {
                    command: command(),
                    field,
                });
            }
        }
        let subcommands = match (row.subcommands, row.justification.as_deref().map(str::trim)) {
            (SubcommandSetDto::Closed, None) => SubcommandSet::Closed,
            (SubcommandSetDto::Closed, Some(_)) => {
                return Err(CatalogError::JustificationOnClosed { command: command() });
            }
            (SubcommandSetDto::Open, Some(text)) if !text.is_empty() => SubcommandSet::Open {
                justification: leak_str(text.to_owned()),
            },
            (SubcommandSetDto::Open, _) => {
                return Err(CatalogError::OpenWithoutJustification { command: command() });
            }
        };
        specs.push(CommandSpec {
            options: row.options.over(base),
            slots: leak_slice(row.slots.into_iter().map(SlotDto::into_slot)),
            code_options: leak_strs(row.code_options),
            code_subcommands: leak_slice(row.code_subcommands.into_iter().map(leak_strs)),
            env_code: leak_strs(row.env_code),
            reads_files: leak_strs(row.reads_files),
            persists: leak_strs(row.persists),
            cwd_effect: row.cwd_effect.map(CwdEffectDto::into_effect),
            subcommands,
            names: leak_strs(row.names),
        });
    }
    Ok(leak_slice(specs))
}

impl GrammarDto {
    fn over(self, base: OptionGrammar) -> OptionGrammar {
        let str_or = |value: Option<String>, base| value.map_or(base, leak_str);
        let strs_or = |value: Option<Vec<String>>, base| value.map_or(base, leak_strs);
        OptionGrammar {
            short_flags: str_or(self.short_flags, base.short_flags),
            short_values: str_or(self.short_values, base.short_values),
            short_glued: str_or(self.short_glued, base.short_glued),
            short_values_unless_dash: str_or(
                self.short_values_unless_dash,
                base.short_values_unless_dash,
            ),
            long_flags: strs_or(self.long_flags, base.long_flags),
            long_values: strs_or(self.long_values, base.long_values),
            long_glued: strs_or(self.long_glued, base.long_glued),
            dash_words: strs_or(self.dash_words, base.dash_words),
            dash_word_values: strs_or(self.dash_word_values, base.dash_word_values),
            any_long_attached: self.any_long_attached.unwrap_or(base.any_long_attached),
            bare_dash_option: self.bare_dash_option.unwrap_or(base.bare_dash_option),
            dash_command_unmodeled: self
                .dash_command_unmodeled
                .unwrap_or(base.dash_command_unmodeled),
            numeric_option: self.numeric_option.unwrap_or(base.numeric_option),
            assignments: self.assignments.unwrap_or(base.assignments),
            leading_operand: self.leading_operand.unwrap_or(base.leading_operand),
            order: self.order.map_or(base.order, ArgOrderDto::into_order),
            long_pairs: strs_or(self.long_pairs, base.long_pairs),
            single_dash_long: self.single_dash_long.unwrap_or(base.single_dash_long),
            command_after: strs_or(self.command_after, base.command_after),
            skip_first_operand: strs_or(self.skip_first_operand, base.skip_first_operand),
            plus_operand: self.plus_operand.unwrap_or(base.plus_operand),
            floor_options: strs_or(self.floor_options, base.floor_options),
            floor_values: self.floor_values.map_or(base.floor_values, |values| {
                leak_slice(
                    values
                        .into_iter()
                        .map(|value| (value.short, leak_strs(value.values))),
                )
            }),
        }
    }
}

impl ArgOrderDto {
    fn into_order(self) -> ArgOrder {
        match self {
            Self::FirstOperand => ArgOrder::FirstOperand,
            Self::PermuteUntilCommand => ArgOrder::PermuteUntilCommand,
        }
    }
}

impl CwdEffectDto {
    fn into_effect(self) -> CwdEffect {
        match self {
            Self::Composed => CwdEffect::Composed,
            Self::Relocates => CwdEffect::Relocates,
        }
    }
}

impl SlotDto {
    fn into_slot(self) -> Slot {
        let alternatives =
            |alternatives: Vec<Vec<String>>| leak_slice(alternatives.into_iter().map(leak_strs));
        match self {
            Self::Exec {} => Slot::Exec,
            Self::Operands { count } => Slot::Operands(count),
            Self::ShellScript { short, long } => Slot::ShellScript {
                short,
                long: long.map(leak_str),
            },
            Self::ShellPassthrough {} => Slot::ShellPassthrough,
            Self::SplitString { short, long } => Slot::SplitString {
                short,
                long: leak_str(long),
            },
            Self::PipedOutput { short, long } => Slot::PipedOutput {
                short,
                long: leak_str(long),
            },
            Self::OperandsAsShellScript {
                exec_short,
                exec_long,
            } => Slot::OperandsAsShellScript {
                exec_short,
                exec_long: leak_str(exec_long),
            },
            Self::OperandsJoinedShellScript {} => Slot::OperandsJoinedShellScript,
            Self::OperandsAsShellScriptWith { switches } => {
                Slot::OperandsAsShellScriptWith(leak_slice(
                    switches
                        .into_iter()
                        .map(|switch| (switch.short, leak_str(switch.long))),
                ))
            }
            Self::Subcommands { alternatives: alts } => Slot::Subcommands(alternatives(alts)),
            Self::UnmodeledSubcommands { alternatives: alts } => {
                Slot::UnmodeledSubcommands(alternatives(alts))
            }
            Self::KeyedShellScript { short, keys } => Slot::KeyedShellScript {
                short,
                keys: leak_strs(keys),
            },
            Self::Cwd {
                short,
                long,
                effect,
            } => Slot::Cwd {
                short,
                long: leak_str(long),
                effect: effect.into_effect(),
            },
            Self::CwdSwitch {
                short,
                long,
                effect,
            } => Slot::CwdSwitch {
                short,
                long: leak_str(long),
                effect: effect.into_effect(),
            },
            Self::CwdBareDash { effect } => Slot::CwdBareDash {
                effect: effect.into_effect(),
            },
            Self::Privilege {} => Slot::Privilege,
        }
    }
}

fn leak_str(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn leak_strs(texts: Vec<String>) -> &'static [&'static str] {
    leak_slice(texts.into_iter().map(leak_str))
}

fn leak_slice<T>(items: impl IntoIterator<Item = T>) -> &'static [T] {
    Box::leak(items.into_iter().collect::<Box<[T]>>())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn error(text: &str) -> CatalogError {
        parse(text).expect_err("rejected")
    }

    #[test]
    fn a_named_grammar_is_the_base_a_row_overrides() {
        let specs = parse(
            r#"
            [grammar.shared]
            short_flags = "ab"
            long_flags = ["all"]

            [[command]]
            names = ["x"]
            grammar = "shared"
            slots = [{ kind = "exec" }]

            [command.options]
            short_flags = "c"
            "#,
        )
        .expect("loads");
        assert_eq!(specs[0].options.short_flags, "c");
        assert_eq!(specs[0].options.long_flags, ["all"]);
        assert_eq!(specs[0].slots, [Slot::Exec]);
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        for text in [
            "bogus = 1",
            "[[command]]\nnames = [\"x\"]\nbogus = 1",
            "[[command]]\nnames = [\"x\"]\n[command.options]\nbogus = 1",
            "[grammar.g]\nbogus = 1",
            "[[command]]\nnames = [\"x\"]\ncode_option = [\"eval\"]",
            "[[command]]\nnames = [\"x\"]\nslots = [{ kind = \"exec\", bogus = 1 }]",
            "[[command]]\nnames = [\"x\"]\nslots = [{ kind = \"operands\", count = 1, bogus = 1 }]",
            "[[command]]\nnames = [\"x\"]\nslots = [{ kind = \"bogus\" }]",
        ] {
            assert!(
                matches!(error(text), CatalogError::Toml(_)),
                "{text:?} should be rejected"
            );
        }
    }

    #[test]
    fn an_unresolved_grammar_reference_is_rejected() {
        let err = error("[[command]]\nnames = [\"x\"]\ngrammar = \"missing\"");
        assert!(
            matches!(&err, CatalogError::UnknownGrammar { command, grammar }
                if command == "x" && grammar == "missing"),
            "{err:?}"
        );
    }

    #[test]
    fn a_char_field_must_be_exactly_one_char() {
        for short in ["", "ab"] {
            let text = format!(
                "[[command]]\nnames = [\"x\"]\nslots = [{{ kind = \"split_string\", short = {short:?}, long = \"s\" }}]"
            );
            assert!(matches!(error(&text), CatalogError::Toml(_)), "{short:?}");
        }
        let text = "[[command]]\nnames = [\"x\"]\n[command.options]\nfloor_values = [{ short = \"XY\", values = [] }]";
        assert!(matches!(error(text), CatalogError::Toml(_)));
    }

    #[test]
    fn a_name_claimed_twice_is_rejected() {
        for text in [
            "[[command]]\nnames = [\"x\"]\n[[command]]\nnames = [\"y\", \"x\"]",
            "[[command]]\nnames = [\"x\", \"x\"]",
        ] {
            assert!(
                matches!(error(text), CatalogError::DuplicateName(name) if name == "x"),
                "{text:?}"
            );
        }
    }

    #[test]
    fn an_empty_catalog_or_nameless_row_is_rejected() {
        for text in ["", "[grammar.g]\nshort_flags = \"a\"", "command = []"] {
            assert!(parse(text).is_err(), "{text:?} should be rejected");
        }
        assert!(matches!(error("command = []"), CatalogError::Empty));
        assert!(matches!(
            error("[[command]]\nnames = []"),
            CatalogError::EmptyNames
        ));
    }

    #[test]
    fn an_empty_entry_in_a_row_list_is_rejected() {
        for (field, value) in [
            ("code_options", "[\"\"]"),
            ("code_subcommands", "[[]]"),
            ("code_subcommands", "[[\"run\", \" \"]]"),
            ("env_code", "[\"  \"]"),
            ("reads_files", "[\"\"]"),
            ("persists", "[\" \"]"),
        ] {
            let text = format!("[[command]]\nnames = [\"x\"]\n{field} = {value}");
            assert!(
                matches!(error(&text), CatalogError::EmptyEntry { field: got, .. } if got == field),
                "{text:?}"
            );
        }
    }

    #[test]
    fn an_open_row_must_justify_itself() {
        for text in [
            "[[command]]\nnames = [\"x\"]\nsubcommands = \"open\"",
            "[[command]]\nnames = [\"x\"]\nsubcommands = \"open\"\njustification = \"  \"",
        ] {
            assert!(
                matches!(error(text), CatalogError::OpenWithoutJustification { command } if command == "x"),
                "{text:?}"
            );
        }
        let text = "[[command]]\nnames = [\"x\"]\njustification = \"why\"";
        assert!(matches!(
            error(text),
            CatalogError::JustificationOnClosed { .. }
        ));
        let specs =
            parse("[[command]]\nnames = [\"x\"]\nsubcommands = \"open\"\njustification = \"why\"")
                .expect("loads");
        assert_eq!(
            specs[0].subcommands,
            SubcommandSet::Open {
                justification: "why"
            }
        );
    }

    #[test]
    fn the_rfc_row_fields_parse() {
        let specs = parse(
            r#"
            [[command]]
            names = ["x", "y"]
            code_options = ["eval"]
            code_subcommands = [["run", "script"], ["exec"]]
            env_code = ["NODE_OPTIONS"]
            reads_files = ["~/.xrc"]
            persists = ["cron entry"]
            cwd_effect = "relocates"
            subcommands = "open"
            justification = "every subcommand is read-only"
            "#,
        )
        .expect("loads");
        let spec = &specs[0];
        assert_eq!(spec.code_options, ["eval"]);
        assert_eq!(
            spec.code_subcommands,
            [&["run", "script"][..], &["exec"][..]]
        );
        assert_eq!(spec.env_code, ["NODE_OPTIONS"]);
        assert_eq!(spec.reads_files, ["~/.xrc"]);
        assert_eq!(spec.persists, ["cron entry"]);
        assert_eq!(spec.cwd_effect, Some(CwdEffect::Relocates));
        assert_eq!(
            spec.subcommands,
            SubcommandSet::Open {
                justification: "every subcommand is read-only"
            }
        );
    }

    #[test]
    fn the_rfc_row_fields_default_to_empty_and_closed() {
        let specs = parse("[[command]]\nnames = [\"x\"]").expect("loads");
        let spec = &specs[0];
        assert!(spec.code_options.is_empty() && spec.code_subcommands.is_empty());
        assert!(spec.env_code.is_empty() && spec.reads_files.is_empty());
        assert!(spec.persists.is_empty());
        assert_eq!(spec.cwd_effect, None);
        assert_eq!(spec.subcommands, SubcommandSet::Closed);
    }

    #[test]
    fn leaf_rows_share_no_name_with_exec_rows_and_open_rows_justify() {
        let specs = parse(EMBEDDED_CATALOG).expect("rules/catalog.toml loads");
        let mut owner = BTreeMap::new();
        for (index, spec) in specs.iter().enumerate() {
            for name in spec.names {
                assert_eq!(
                    owner.insert(*name, index),
                    None,
                    "{name:?} is named by more than one row"
                );
            }
        }
        let (exec, leaf): (Vec<_>, Vec<_>) = specs.iter().partition(|spec| spec.runs_command());
        let exec_names: HashSet<_> = exec.iter().flat_map(|spec| spec.names).collect();
        for name in leaf.iter().flat_map(|spec| spec.names) {
            assert!(
                !exec_names.contains(name),
                "leaf row name {name:?} is also an exec row"
            );
        }
        for spec in specs {
            if let SubcommandSet::Open { justification } = spec.subcommands {
                assert!(
                    !justification.trim().is_empty(),
                    "{:?} is open without a justification",
                    spec.names
                );
            }
        }
    }
}
