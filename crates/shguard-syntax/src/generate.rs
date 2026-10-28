//! The script generator shared by the parser round trip and the differential
//! tests: it renders a random script and builds the AST the parser must give
//! back for it.

use proptest::prelude::*;
use shguard_kernel::ast::{
    AndOr, Connector, Link, Opaque, Part, Pipeline, Redir, Script, Simple, Word,
};

pub(crate) fn lit(s: &str) -> Part {
    Part::Lit(s.as_bytes().to_vec())
}

pub(crate) fn w(parts: Vec<Part>) -> Word {
    Word::new(parts).unwrap()
}

#[derive(Debug, Clone)]
pub(crate) enum GWord {
    Bare(String),
    Single(String),
    Mixed(String, String),
    DqVar(String),
    /// Double-quoted text without expansions; may be empty.
    Dq(String),
    /// Every byte backslash-escaped.
    Esc(String),
    Tilde,
}

impl GWord {
    pub(crate) fn render(&self) -> String {
        match self {
            GWord::Bare(s) => s.clone(),
            GWord::Single(s) => format!("'{s}'"),
            GWord::Mixed(a, b) => format!("{a}'{b}'"),
            GWord::DqVar(n) => format!("\"${n}\""),
            GWord::Dq(s) => format!("\"{s}\""),
            GWord::Esc(s) => s.chars().map(|c| format!("\\{c}")).collect(),
            GWord::Tilde => "~".to_string(),
        }
    }

    fn word(&self) -> Word {
        match self {
            GWord::Bare(s) | GWord::Single(s) | GWord::Dq(s) | GWord::Esc(s) => w(vec![lit(s)]),
            GWord::Mixed(a, b) => w(vec![lit(a), lit(b)]),
            GWord::DqVar(n) => w(vec![Part::Opaque(Opaque::Var(n.as_bytes().to_vec()))]),
            GWord::Tilde => w(vec![Part::Opaque(Opaque::Tilde)]),
        }
    }
}

fn gword() -> impl Strategy<Value = GWord> {
    let bare_s = "[a-z0-9./-]{1,6}";
    let quoted = "[a-z ;|&$<>()]{0,6}";
    prop_oneof![
        4 => bare_s.prop_map(GWord::Bare),
        2 => quoted.prop_map(GWord::Single),
        1 => (bare_s, quoted).prop_map(|(a, b)| GWord::Mixed(a, b)),
        1 => "[A-Za-z_][A-Za-z0-9_]{0,4}".prop_map(GWord::DqVar),
        1 => "[a-z ;|&<>()]{0,6}".prop_map(GWord::Dq),
        1 => "[a-z;|&<>()$ ]{1,4}".prop_map(GWord::Esc),
        1 => Just(GWord::Tilde),
    ]
}

/// A command name that is neither reserved nor assignment-shaped.
fn gname() -> impl Strategy<Value = GWord> {
    prop_oneof![
        3 => "x[a-z0-9./-]{0,5}".prop_map(GWord::Bare),
        1 => "[a-z ;|&$<>()]{0,6}".prop_map(GWord::Single),
        1 => Just(GWord::Tilde),
    ]
}

#[derive(Debug, Clone)]
pub(crate) struct GSimple {
    name: GWord,
    args: Vec<GWord>,
    redirs: Vec<Redir>,
    placement: Placement,
}

/// Where the redirects of a generated command are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Before the command name.
    Before,
    /// After the last word.
    After,
    /// One after each word, between the words; leftovers go last.
    Between,
}

fn gredir() -> impl Strategy<Value = Redir> {
    prop_oneof![
        (0u8..10, 0u8..10).prop_map(|(from, to)| Redir::Dup { from, to }),
        (0u8..10).prop_map(|fd| Redir::DevNull { fd }),
    ]
}

fn render_redir(r: Redir) -> String {
    match r {
        Redir::Dup { from, to } => format!("{from}>&{to}"),
        Redir::DevNull { fd } => format!("{fd}>/dev/null"),
    }
}

fn gsimple() -> impl Strategy<Value = GSimple> {
    (
        gname(),
        prop::collection::vec(gword(), 0..4),
        prop::collection::vec(gredir(), 0..3),
        prop_oneof![
            Just(Placement::Before),
            Just(Placement::After),
            Just(Placement::Between),
        ],
    )
        .prop_map(|(name, args, redirs, placement)| GSimple {
            name,
            args,
            redirs,
            placement,
        })
}

impl GSimple {
    /// Renders with `name` standing in for the command name when given.
    pub(crate) fn render(&self, name: Option<&str>) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut redirs = self.redirs.iter().copied().map(render_redir);
        if self.placement == Placement::Before {
            parts.extend(redirs.by_ref());
        }
        parts.push(name.map_or_else(|| self.name.render(), str::to_string));
        for arg in &self.args {
            if self.placement == Placement::Between {
                parts.extend(redirs.next());
            }
            parts.push(arg.render());
        }
        parts.extend(redirs);
        parts.join(" ")
    }

    fn simple(&self) -> Simple {
        Simple::new(
            std::iter::once(&self.name)
                .chain(&self.args)
                .map(GWord::word)
                .collect(),
            self.redirs.clone(),
        )
        .unwrap()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GAndOr {
    first: Vec<GSimple>,
    rest: Vec<(bool, bool, Vec<GSimple>)>, // (is_and, newline_after, pipeline)
    pipe_newlines: Vec<bool>,
}

fn gpipeline() -> impl Strategy<Value = Vec<GSimple>> {
    prop::collection::vec(gsimple(), 1..4)
}

fn gand_or() -> impl Strategy<Value = GAndOr> {
    (
        gpipeline(),
        prop::collection::vec((any::<bool>(), any::<bool>(), gpipeline()), 0..3),
        prop::collection::vec(any::<bool>(), 8),
    )
        .prop_map(|(first, rest, pipe_newlines)| GAndOr {
            first,
            rest,
            pipe_newlines,
        })
}

#[derive(Debug, Clone)]
pub(crate) struct GScript {
    items: Vec<GAndOr>,
    seps: Vec<&'static str>,
    trailing: &'static str,
}

pub(crate) fn gscript() -> impl Strategy<Value = GScript> {
    let sep = prop::sample::select(vec![";", "; ", " ;", "\n", "\n\n", ";\n", " ; \n "]);
    let trailing = prop::sample::select(vec!["", ";", "\n", " ; ", "\n\n"]);
    (
        prop::collection::vec(gand_or(), 1..4),
        prop::collection::vec(sep, 4),
        trailing,
    )
        .prop_map(|(items, seps, trailing)| GScript {
            items,
            seps,
            trailing,
        })
}

fn render_pipeline(
    p: &[GSimple],
    newlines: &[bool],
    bad: &mut Option<(usize, &str)>,
    n: &mut usize,
) -> String {
    let mut out = String::new();
    for (i, s) in p.iter().enumerate() {
        if i > 0 {
            let nl = newlines.get(i - 1).copied().unwrap_or(false);
            out.push_str(if nl { " |\n " } else { " | " });
        }
        let name = match bad {
            Some((at, name)) if *at == *n => Some(*name),
            Some(_) | None => None,
        };
        if name.is_some() {
            *bad = None;
        }
        *n += 1;
        out.push_str(&s.render(name));
    }
    out
}

impl GScript {
    pub(crate) fn simple_count(&self) -> usize {
        self.items
            .iter()
            .map(|a| a.first.len() + a.rest.iter().map(|r| r.2.len()).sum::<usize>())
            .sum()
    }

    pub(crate) fn render(&self, mut bad: Option<(usize, &str)>) -> String {
        let mut out = String::new();
        let mut n = 0;
        for (i, item) in self.items.iter().enumerate() {
            if i > 0 {
                out.push_str(self.seps.get(i - 1).copied().unwrap_or(";"));
            }
            out.push_str(&render_pipeline(
                &item.first,
                &item.pipe_newlines,
                &mut bad,
                &mut n,
            ));
            for (is_and, nl, p) in &item.rest {
                out.push_str(match (is_and, nl) {
                    (true, false) => " && ",
                    (true, true) => " &&\n ",
                    (false, false) => " || ",
                    (false, true) => " ||\n ",
                });
                out.push_str(&render_pipeline(p, &item.pipe_newlines, &mut bad, &mut n));
            }
        }
        out.push_str(self.trailing);
        out
    }

    pub(crate) fn script(&self) -> Script {
        Script::new(
            self.items
                .iter()
                .map(|item| {
                    AndOr::new(
                        pipe_of(&item.first),
                        item.rest
                            .iter()
                            .map(|(is_and, _, p)| {
                                Link::new(
                                    if *is_and {
                                        Connector::And
                                    } else {
                                        Connector::Or
                                    },
                                    pipe_of(p),
                                )
                            })
                            .collect(),
                    )
                })
                .collect(),
        )
    }
}

fn pipe_of(p: &[GSimple]) -> Pipeline {
    Pipeline::new(p.iter().map(GSimple::simple).collect()).unwrap()
}
