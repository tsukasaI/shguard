//! The command AST (v1 is non-recursive).
//!
//! Values are well-formed by construction: fields are `pub(crate)`, and other
//! crates build the types that carry an invariant only through the checked
//! constructors, which return `None` for an ill-formed input. Each such type
//! has an `Invariant` impl that states its well-formedness, so Creusot hands
//! the fact to every function that receives one.

#[cfg(creusot)]
use creusot_std::prelude::{Clone, PartialEq, *};

/// A word part that the kernel never expands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Opaque {
    /// A variable reference; holds the variable name.
    Var(Vec<u8>),
    /// A leading `~` (home directory).
    Tilde,
}

/// One piece of a word.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Part {
    /// Literal bytes. May be empty, since `''` is a word.
    Lit(Vec<u8>),
    /// Something the shell expands at run time.
    Opaque(Opaque),
}

/// A shell word: one or more parts.
///
/// A `Word` is exactly one argv word after expansion (#1036). The kernel
/// relies on this without checking it; it is an obligation on the parser
/// that builds the AST:
/// - `Lit` bytes reach the program verbatim;
/// - unquoted expansions, globs and brace expansion are rejected, never
///   built, so no word splits, vanishes or multiplies;
/// - `Opaque(Var)` only ever comes from a quoted `"$X"`.
///
/// `crates/shguard-syntax` meets it: its lexer rejects unquoted `$`, glob
/// bytes and braces, and its differential tests (`src/differential/`, M10)
/// check that brush-parser, shfmt and bash read every accepted input as the
/// same words.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Word {
    pub(crate) parts: Vec<Part>,
}

/// A word has at least one part.
#[cfg(creusot)]
#[logic(open)]
pub fn word_wf(parts: Seq<Part>) -> bool {
    parts.len() > 0
}

#[cfg(creusot)]
impl Invariant for Word {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { word_wf(self.parts@) }
    }
}

impl Word {
    /// Builds a word, or `None` when `parts` is empty.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(w) => w.parts@ == parts@,
        None => !word_wf(parts@),
    }))]
    #[must_use]
    pub fn new(parts: Vec<Part>) -> Option<Word> {
        if <[_]>::is_empty(&parts) {
            None
        } else {
            Some(Word { parts })
        }
    }

    /// Builds a word from its first part and the rest; infallible, since the
    /// first part is present by construction.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.parts@ == Seq::singleton(first).concat(rest@)))]
    #[must_use]
    pub fn with_first(first: Part, rest: Vec<Part>) -> Word {
        let mut parts = rest;
        parts.insert(0, first);
        Word { parts }
    }

    /// The parts of the word.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.parts@))]
    #[must_use]
    pub fn parts(&self) -> &[Part] {
        &self.parts
    }
}

/// A redirection the subset parser accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Redir {
    /// `N>&M`: `2>&1` is `from: 2, to: 1`; `>&2` is `from: 1, to: 2`.
    Dup {
        /// The redirected descriptor.
        from: u8,
        /// The descriptor it now refers to.
        to: u8,
    },
    /// `N>/dev/null`: `>/dev/null` is `fd: 1`.
    DevNull {
        /// The redirected descriptor.
        fd: u8,
    },
}

/// A simple command: words (the first is the command name) and redirects.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Simple {
    pub(crate) words: Vec<Word>,
    pub(crate) redirs: Vec<Redir>,
}

/// A simple command has at least one word.
#[cfg(creusot)]
#[logic(open)]
pub fn simple_wf(words: Seq<Word>) -> bool {
    words.len() > 0
}

#[cfg(creusot)]
impl Invariant for Simple {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { simple_wf(self.words@) }
    }
}

impl Simple {
    /// Builds a simple command, or `None` when `words` is empty.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(c) => c.words@ == words@ && c.redirs@ == redirs@,
        None => !simple_wf(words@),
    }))]
    #[must_use]
    pub fn new(words: Vec<Word>, redirs: Vec<Redir>) -> Option<Simple> {
        if <[_]>::is_empty(&words) {
            None
        } else {
            Some(Simple { words, redirs })
        }
    }

    /// Builds a simple command from its first word, the other words and the
    /// redirects; infallible, since the first word is present by construction.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(
        result.words@ == Seq::singleton(first).concat(rest@) && result.redirs@ == redirs@
    ))]
    #[must_use]
    pub fn with_first(first: Word, rest: Vec<Word>, redirs: Vec<Redir>) -> Simple {
        let mut words = rest;
        words.insert(0, first);
        Simple { words, redirs }
    }

    /// The words; the first is the command name.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.words@))]
    #[must_use]
    pub fn words(&self) -> &[Word] {
        &self.words
    }

    /// The redirects.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.redirs@))]
    #[must_use]
    pub fn redirs(&self) -> &[Redir] {
        &self.redirs
    }
}

/// Simple commands joined by `|`.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Pipeline {
    pub(crate) cmds: Vec<Simple>,
}

/// A pipeline has at least one command.
#[cfg(creusot)]
#[logic(open)]
pub fn pipeline_wf(cmds: Seq<Simple>) -> bool {
    cmds.len() > 0
}

#[cfg(creusot)]
impl Invariant for Pipeline {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { pipeline_wf(self.cmds@) }
    }
}

impl Pipeline {
    /// Builds a pipeline, or `None` when `cmds` is empty.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(p) => p.cmds@ == cmds@,
        None => !pipeline_wf(cmds@),
    }))]
    #[must_use]
    pub fn new(cmds: Vec<Simple>) -> Option<Pipeline> {
        if <[_]>::is_empty(&cmds) {
            None
        } else {
            Some(Pipeline { cmds })
        }
    }

    /// Builds a pipeline from its first command and the rest; infallible,
    /// since the first command is present by construction.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.cmds@ == Seq::singleton(first).concat(rest@)))]
    #[must_use]
    pub fn with_first(first: Simple, rest: Vec<Simple>) -> Pipeline {
        let mut cmds = rest;
        cmds.insert(0, first);
        Pipeline { cmds }
    }

    /// The commands.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.cmds@))]
    #[must_use]
    pub fn cmds(&self) -> &[Simple] {
        &self.cmds
    }
}

/// The operator between two pipelines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Connector {
    /// `&&`
    And,
    /// `||`
    Or,
}

/// An operator and the pipeline on its right.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Link {
    pub(crate) op: Connector,
    pub(crate) rhs: Pipeline,
}

impl Link {
    /// Builds a link.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.op == op && result.rhs == rhs))]
    #[must_use]
    pub fn new(op: Connector, rhs: Pipeline) -> Link {
        Link { op, rhs }
    }

    /// The operator.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.op))]
    #[must_use]
    pub fn op(&self) -> Connector {
        self.op
    }

    /// The pipeline on the right of the operator.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.rhs))]
    #[must_use]
    pub fn rhs(&self) -> &Pipeline {
        &self.rhs
    }
}

/// `first (&& | ||) pipeline ...`
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct AndOr {
    pub(crate) first: Pipeline,
    pub(crate) rest: Vec<Link>,
}

impl AndOr {
    /// Builds an and-or list.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.first == first && result.rest@ == rest@))]
    #[must_use]
    pub fn new(first: Pipeline, rest: Vec<Link>) -> AndOr {
        AndOr { first, rest }
    }

    /// The leading pipeline.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.first))]
    #[must_use]
    pub fn first(&self) -> &Pipeline {
        &self.first
    }

    /// The links after the first pipeline.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.rest@))]
    #[must_use]
    pub fn rest(&self) -> &[Link] {
        &self.rest
    }
}

/// A whole command line: and-or lists separated by `;` or newlines. May be
/// empty.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Script {
    pub(crate) items: Vec<AndOr>,
}

impl Script {
    /// Builds a script.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.items@ == items@))]
    #[must_use]
    pub fn new(items: Vec<AndOr>) -> Script {
        Script { items }
    }

    /// The and-or lists.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.items@))]
    #[must_use]
    pub fn items(&self) -> &[AndOr] {
        &self.items
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(s: &str) -> Part {
        Part::Lit(s.as_bytes().to_vec())
    }

    fn word(s: &str) -> Word {
        Word::with_first(lit(s), Vec::new())
    }

    fn cmd(s: &str) -> Simple {
        Simple::with_first(word(s), Vec::new(), Vec::new())
    }

    #[test]
    fn word_with_first_puts_first_in_front() {
        let w = Word::with_first(lit("a"), vec![lit("b"), Part::Opaque(Opaque::Tilde)]);
        assert_eq!(w.parts(), [lit("a"), lit("b"), Part::Opaque(Opaque::Tilde)]);
        assert_eq!(Word::new(vec![lit("a")]), Some(word("a")));
    }

    #[test]
    fn simple_with_first_puts_first_in_front() {
        let redir = Redir::DevNull { fd: 1 };
        let c = Simple::with_first(word("a"), vec![word("b")], vec![redir]);
        assert_eq!(c.words(), [word("a"), word("b")]);
        assert_eq!(c.redirs(), [redir]);
        assert_eq!(Simple::new(vec![word("a")], Vec::new()), Some(cmd("a")));
    }

    #[test]
    fn pipeline_with_first_puts_first_in_front() {
        let p = Pipeline::with_first(cmd("a"), vec![cmd("b")]);
        assert_eq!(p.cmds(), [cmd("a"), cmd("b")]);
        assert_eq!(
            Pipeline::new(vec![cmd("a")]),
            Some(Pipeline::with_first(cmd("a"), Vec::new()))
        );
    }
}
