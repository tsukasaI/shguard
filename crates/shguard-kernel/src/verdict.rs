//! Addresses into a script and the reasons a verdict carries.
//!
//! `Verdict` and `Witness` arrive in M6.

#[cfg(creusot)]
use crate::ast::Pipeline;
use crate::ast::{Script, Simple};
use crate::rule::RuleId;
#[cfg(creusot)]
use creusot_std::prelude::{Clone, PartialEq, *};

/// Where a command or word sits in a script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub struct Addr {
    /// Index into the script's and-or lists.
    pub item: usize,
    /// `0` is the and-or list's `first` pipeline; `k` is `rest[k - 1]`.
    pub link: usize,
    /// Index of the simple command in its pipeline.
    pub cmd: usize,
    /// Index of a word in the simple command; `None` means the whole command.
    pub word: Option<usize>,
}

/// Why a command is Unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum UnknownKind {
    /// No catalog row matches the command.
    NoRow,
    /// The command name is not a literal.
    OpaqueCommandName,
    /// An option the row's grammar does not list.
    UnknownOption,
    /// An option position holds a word that is not a literal.
    OpaqueOption,
    /// An option that takes a value has none.
    MissingValue,
    /// An operand beyond what the grammar allows.
    ExtraOperand,
    /// A position whose role is code.
    CodeRole,
    /// The row marks the command as running other code.
    RunsCode,
    /// A redirect the model cannot reason about.
    Redirect,
}

/// Why a verdict is not Allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Reason {
    /// The command is not covered by the catalog.
    Unknown(UnknownKind, Addr),
    /// A rule hit.
    Rule(RuleId, Addr),
}

/// The pipeline that `a.item` and `a.link` select, whatever `a.cmd` is.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn pipeline_at_l(s: Script, a: Addr) -> Pipeline {
    pearlite! {
        if a.link@ == 0 {
            s.items@[a.item@].first
        } else {
            s.items@[a.item@].rest@[a.link@ - 1].rhs
        }
    }
}

/// `a` names a command of `s`, and its word index (if any) is in range.
#[cfg(creusot)]
#[logic(open(crate))]
pub fn valid_addr(s: Script, a: Addr) -> bool {
    pearlite! {
        a.item@ < s.items@.len()
            && a.link@ <= s.items@[a.item@].rest@.len()
            && a.cmd@ < pipeline_at_l(s, a).cmds@.len()
            && match a.word {
                None => true,
                Some(w) => w@ < pipeline_at_l(s, a).cmds@[a.cmd@].words@.len(),
            }
    }
}

/// The simple command at `a`.
#[cfg(creusot)]
#[logic(open(crate))]
#[requires(valid_addr(s, a))]
pub fn simple_at_l(s: Script, a: Addr) -> Simple {
    pearlite! { pipeline_at_l(s, a).cmds@[a.cmd@] }
}

/// The simple command at `a`, or `None` when `a` is out of range.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(match result {
    Some(x) => valid_addr(*s, a) && *x == simple_at_l(*s, a),
    None => !valid_addr(*s, a),
}))]
#[must_use]
pub fn simple_at(s: &Script, a: Addr) -> Option<&Simple> {
    if a.item >= s.items.len() {
        return None;
    }
    let ao = &s.items[a.item];
    let pipeline = if a.link == 0 {
        &ao.first
    } else if a.link > ao.rest.len() {
        return None;
    } else {
        &ao.rest[a.link - 1].rhs
    };
    if a.cmd >= pipeline.cmds.len() {
        return None;
    }
    let cmd = &pipeline.cmds[a.cmd];
    if let Some(w) = a.word
        && w >= cmd.words.len()
    {
        return None;
    }
    Some(cmd)
}

#[cfg(test)]
mod tests {
    use super::{Addr, simple_at};
    use crate::ast::{AndOr, Connector, Link, Part, Pipeline, Script, Simple, Word};

    fn cmd(name: &str, args: &[&str]) -> Simple {
        let mut words = Vec::new();
        for w in std::iter::once(&name).chain(args) {
            let parts = vec![Part::Lit(w.as_bytes().to_vec())];
            words.push(Word::new(parts).expect("non-empty"));
        }
        Simple::new(words, Vec::new()).expect("non-empty")
    }

    fn pipeline(cmds: Vec<Simple>) -> Pipeline {
        Pipeline::new(cmds).expect("non-empty")
    }

    /// `a | b && c ; d || e`
    fn script() -> Script {
        let first = AndOr::new(
            pipeline(vec![cmd("a", &[]), cmd("b", &["x"])]),
            vec![Link::new(Connector::And, pipeline(vec![cmd("c", &[])]))],
        );
        let second = AndOr::new(
            pipeline(vec![cmd("d", &[])]),
            vec![Link::new(Connector::Or, pipeline(vec![cmd("e", &[])]))],
        );
        Script::new(vec![first, second])
    }

    fn at(item: usize, link: usize, cmd: usize, word: Option<usize>) -> Addr {
        Addr {
            item,
            link,
            cmd,
            word,
        }
    }

    #[test]
    fn valid_addresses() {
        let s = script();
        assert_eq!(simple_at(&s, at(0, 0, 0, None)), Some(&cmd("a", &[])));
        assert_eq!(simple_at(&s, at(0, 0, 1, Some(1))), Some(&cmd("b", &["x"])));
        assert_eq!(simple_at(&s, at(0, 1, 0, Some(0))), Some(&cmd("c", &[])));
        assert_eq!(simple_at(&s, at(1, 0, 0, None)), Some(&cmd("d", &[])));
        assert_eq!(simple_at(&s, at(1, 1, 0, None)), Some(&cmd("e", &[])));
    }

    #[test]
    fn out_of_bounds_addresses() {
        let s = script();
        assert_eq!(simple_at(&s, at(2, 0, 0, None)), None, "item");
        assert_eq!(simple_at(&s, at(0, 2, 0, None)), None, "link");
        assert_eq!(simple_at(&s, at(0, 0, 2, None)), None, "cmd");
        assert_eq!(simple_at(&s, at(0, 1, 1, None)), None, "cmd in a link");
        assert_eq!(simple_at(&s, at(0, 0, 1, Some(2))), None, "word");
        assert_eq!(
            simple_at(&s, at(0, 0, 0, Some(1))),
            None,
            "word, one-word cmd"
        );
        assert_eq!(
            simple_at(&Script::new(Vec::new()), at(0, 0, 0, None)),
            None,
            "empty"
        );
    }
}
