//! The closed command catalog: per-command grammars that say how to read a
//! command's argv.
//!
//! Like the AST, values are well-formed by construction: fields are
//! `pub(crate)` and the types with an invariant are built through checked
//! constructors. Key uniqueness is not enforced here; the catalog loader
//! rejects duplicates.
//!
//! Two refinements over the plan's sketch:
//! - `Grammar::rest` is an `Option<Role>` (`None` means no operands beyond
//!   `positionals`), not a bare `Role`.
//! - An option is `Opt { name: OptName, value: OptValue }`, not
//!   `{ short, long, takes_value, value_role }`, so it always has a name and a
//!   flag cannot carry a value role.

#[cfg(creusot)]
use creusot_std::prelude::{Clone, PartialEq, *};

/// What an argument position does with its word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum Role {
    /// The word is plain data.
    Inert,
    /// The word names a file system path.
    Path,
    /// The word is run as code.
    Code,
}

/// A long option name, without the leading `--`. Never empty.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct LongName {
    pub(crate) bytes: Vec<u8>,
}

/// A long name has at least one byte.
#[cfg(creusot)]
#[logic(open)]
pub fn long_name_wf(bytes: Seq<u8>) -> bool {
    bytes.len() > 0
}

#[cfg(creusot)]
impl Invariant for LongName {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { long_name_wf(self.bytes@) }
    }
}

impl LongName {
    /// Builds a long name, or `None` when `bytes` is empty.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(n) => n.bytes@ == bytes@,
        None => !long_name_wf(bytes@),
    }))]
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Option<LongName> {
        if <[_]>::is_empty(&bytes) {
            None
        } else {
            Some(LongName { bytes })
        }
    }

    /// The name's bytes.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.bytes@))]
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The name of an option; an option always has at least one name.
///
/// The long name lives in a [`LongName`], whose invariant (non-empty) the
/// enum inherits. A bare `Vec<u8>` payload would stay mutable through a
/// `&mut` pattern even with `#[non_exhaustive]` variants.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub enum OptName {
    /// Only a short name: `-v` is `Short(b'v')`.
    Short(u8),
    /// Only a long name: `--verbose` is `Long(..)`.
    Long(LongName),
    /// Both spellings: `-v` and `--verbose`.
    Both(u8, LongName),
}

/// Whether an option takes a value, and what the value does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(creusot, derive(DeepModel))]
pub enum OptValue {
    /// A flag: no value.
    Flag,
    /// The option consumes a value with this role.
    Takes(Role),
}

/// One option of a grammar.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Opt {
    pub(crate) name: OptName,
    pub(crate) value: OptValue,
}

impl Opt {
    /// Builds an option.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.name == name && result.value == value))]
    #[must_use]
    pub fn new(name: OptName, value: OptValue) -> Opt {
        Opt { name, value }
    }

    /// The option's name.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.name))]
    #[must_use]
    pub fn name(&self) -> &OptName {
        &self.name
    }

    /// Whether the option takes a value.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.value))]
    #[must_use]
    pub fn value(&self) -> OptValue {
        self.value
    }
}

/// How to read the argv of a command.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Grammar {
    pub(crate) opts: Vec<Opt>,
    pub(crate) positionals: Vec<Role>,
    pub(crate) rest: Option<Role>,
    pub(crate) permute: bool,
    pub(crate) dashdash: bool,
}

impl Grammar {
    /// Builds a grammar.
    ///
    /// - `positionals`: roles of the leading operands, in order.
    /// - `rest`: the role of every operand after them; `None` means there are
    ///   none.
    /// - `permute`: options may follow operands (GNU style).
    /// - `dashdash`: `--` ends option parsing.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.opts@ == opts@ && result.positionals@ == positionals@
        && result.rest == rest && result.permute == permute && result.dashdash == dashdash))]
    #[must_use]
    pub fn new(
        opts: Vec<Opt>,
        positionals: Vec<Role>,
        rest: Option<Role>,
        permute: bool,
        dashdash: bool,
    ) -> Grammar {
        Grammar {
            opts,
            positionals,
            rest,
            permute,
            dashdash,
        }
    }

    /// The options.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.opts@))]
    #[must_use]
    pub fn opts(&self) -> &[Opt] {
        &self.opts
    }

    /// The roles of the leading operands.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.positionals@))]
    #[must_use]
    pub fn positionals(&self) -> &[Role] {
        &self.positionals
    }

    /// The role of the operands after the leading ones, if any are allowed.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.rest))]
    #[must_use]
    pub fn rest(&self) -> Option<Role> {
        self.rest
    }

    /// Whether options may follow operands.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.permute))]
    #[must_use]
    pub fn permute(&self) -> bool {
        self.permute
    }

    /// Whether `--` ends option parsing.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.dashdash))]
    #[must_use]
    pub fn dashdash(&self) -> bool {
        self.dashdash
    }
}

/// A command key is non-empty and every segment is non-empty.
#[cfg(creusot)]
#[logic(open)]
pub fn key_wf(key: Seq<Vec<u8>>) -> bool {
    pearlite! { key.len() > 0 && forall<i> 0 <= i && i < key.len() ==> key[i]@.len() > 0 }
}

/// Runtime check of [`key_wf`].
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == key_wf(key@)))]
#[must_use]
pub fn key_ok(key: &[Vec<u8>]) -> bool {
    if <[_]>::is_empty(key) {
        return false;
    }
    let mut i: usize = 0;
    #[cfg_attr(creusot, variant(key@.len() - i@))]
    #[cfg_attr(creusot, invariant(i@ <= key@.len()))]
    #[cfg_attr(creusot, invariant(forall<k> 0 <= k && k < i@ ==> key@[k]@.len() > 0))]
    while i < key.len() {
        if <[_]>::is_empty(&key[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// A catalog row: the grammar of one command (or subcommand) and its flags.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Row {
    pub(crate) key: Vec<Vec<u8>>,
    pub(crate) grammar: Grammar,
    pub(crate) runs_code: bool,
    pub(crate) changes_cwd: bool,
}

#[cfg(creusot)]
impl Invariant for Row {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { key_wf(self.key@) }
    }
}

impl Row {
    /// Builds a row, or `None` when `key` is empty or has an empty segment.
    ///
    /// Subcommands are flattened into the key (`["git", "status"]`).
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(r) => r.key@ == key@ && r.grammar == grammar
            && r.runs_code == runs_code && r.changes_cwd == changes_cwd,
        None => !key_wf(key@),
    }))]
    #[must_use]
    pub fn new(
        key: Vec<Vec<u8>>,
        grammar: Grammar,
        runs_code: bool,
        changes_cwd: bool,
    ) -> Option<Row> {
        if key_ok(&key) {
            Some(Row {
                key,
                grammar,
                runs_code,
                changes_cwd,
            })
        } else {
            None
        }
    }

    /// The key segments.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.key@))]
    #[must_use]
    pub fn key(&self) -> &[Vec<u8>] {
        &self.key
    }

    /// The grammar of the command's own argv.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.grammar))]
    #[must_use]
    pub fn grammar(&self) -> &Grammar {
        &self.grammar
    }

    /// Whether the command runs other code.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.runs_code))]
    #[must_use]
    pub fn runs_code(&self) -> bool {
        self.runs_code
    }

    /// Whether the command changes the working directory.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result == self.changes_cwd))]
    #[must_use]
    pub fn changes_cwd(&self) -> bool {
        self.changes_cwd
    }
}

/// The grammar of the words between key segments, such as `-C x` in
/// `git -C x status`.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Global {
    pub(crate) head: Vec<u8>,
    pub(crate) grammar: Grammar,
}

/// A global's head (the command it belongs to) is non-empty.
#[cfg(creusot)]
#[logic(open)]
pub fn head_wf(head: Seq<u8>) -> bool {
    head.len() > 0
}

#[cfg(creusot)]
impl Invariant for Global {
    #[logic(open(crate))]
    fn invariant(self) -> bool {
        pearlite! { head_wf(self.head@) }
    }
}

impl Global {
    /// Builds a global grammar, or `None` when `head` is empty.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(match result {
        Some(g) => g.head@ == head@ && g.grammar == grammar,
        None => !head_wf(head@),
    }))]
    #[must_use]
    pub fn new(head: Vec<u8>, grammar: Grammar) -> Option<Global> {
        if <[_]>::is_empty(&head) {
            None
        } else {
            Some(Global { head, grammar })
        }
    }

    /// The command name this grammar belongs to.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.head@))]
    #[must_use]
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    /// The grammar of the words between key segments.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(*result == self.grammar))]
    #[must_use]
    pub fn grammar(&self) -> &Grammar {
        &self.grammar
    }
}

/// The rows and global grammars.
#[derive(Clone, Debug)]
#[cfg_attr(not(creusot), derive(PartialEq, Eq))]
pub struct Catalog {
    pub(crate) rows: Vec<Row>,
    pub(crate) globals: Vec<Global>,
}

impl Catalog {
    /// Builds a catalog. Key uniqueness is the loader's job, not the
    /// kernel's.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result.rows@ == rows@ && result.globals@ == globals@))]
    #[must_use]
    pub fn new(rows: Vec<Row>, globals: Vec<Global>) -> Catalog {
        Catalog { rows, globals }
    }

    /// The rows.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.rows@))]
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The global grammars.
    #[cfg_attr(creusot, check(terminates))]
    #[cfg_attr(creusot, ensures(result@ == self.globals@))]
    #[must_use]
    pub fn globals(&self) -> &[Global] {
        &self.globals
    }
}

#[cfg(test)]
mod tests {
    use super::{Catalog, Global, Grammar, LongName, Opt, OptName, OptValue, Role, Row, key_ok};

    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    fn grammar() -> Grammar {
        Grammar::new(Vec::new(), Vec::new(), None, false, true)
    }

    #[test]
    fn long_name_constructor() {
        let name = LongName::new(bytes("verbose")).expect("non-empty");
        assert_eq!(name.bytes(), b"verbose");
        assert!(LongName::new(Vec::new()).is_none());

        let both = OptName::Both(b'v', name.clone());
        assert_ne!(both, OptName::Long(name));
    }

    #[test]
    fn key_ok_cases() {
        assert!(key_ok(&[bytes("git")]));
        assert!(key_ok(&[bytes("git"), bytes("status")]));
        assert!(!key_ok(&[]));
        assert!(!key_ok(&[Vec::new()]));
        assert!(!key_ok(&[bytes("git"), Vec::new()]));
        assert!(!key_ok(&[Vec::new(), bytes("status")]));
    }

    #[test]
    fn row_constructor() {
        let row = Row::new(vec![bytes("git"), bytes("status")], grammar(), false, true)
            .expect("valid key");
        assert_eq!(row.key(), [bytes("git"), bytes("status")]);
        assert_eq!(*row.grammar(), grammar());
        assert!(!row.runs_code());
        assert!(row.changes_cwd());

        assert!(Row::new(Vec::new(), grammar(), false, false).is_none());
        assert!(Row::new(vec![Vec::new()], grammar(), false, false).is_none());
        assert!(Row::new(vec![bytes("git"), Vec::new()], grammar(), false, false).is_none());
    }

    #[test]
    fn global_constructor() {
        let global = Global::new(bytes("git"), grammar()).expect("valid head");
        assert_eq!(global.head(), b"git");
        assert_eq!(*global.grammar(), grammar());
        assert!(Global::new(Vec::new(), grammar()).is_none());
    }

    #[test]
    fn grammar_and_catalog_accessors() {
        let opt = Opt::new(OptName::Short(b'C'), OptValue::Takes(Role::Path));
        assert_eq!(*opt.name(), OptName::Short(b'C'));
        assert_eq!(opt.value(), OptValue::Takes(Role::Path));

        let g = Grammar::new(
            vec![opt.clone()],
            vec![Role::Inert],
            Some(Role::Path),
            true,
            false,
        );
        assert_eq!(g.opts(), [opt]);
        assert_eq!(g.positionals(), [Role::Inert]);
        assert_eq!(g.rest(), Some(Role::Path));
        assert!(g.permute());
        assert!(!g.dashdash());

        let row = Row::new(vec![bytes("ls")], g, false, false).expect("valid key");
        let global = Global::new(bytes("git"), grammar()).expect("valid head");
        let cat = Catalog::new(vec![row.clone()], vec![global.clone()]);
        assert_eq!(cat.rows(), [row]);
        assert_eq!(cat.globals(), [global]);
    }
}
