//! Stage 3 of the RFC #658 architecture: the abstract domains the gate
//! interprets a command line over, and the scoping that decides which
//! assignments reach a use.
//!
//! # Domains and their joins
//!
//! Each domain is a lattice whose join is the least upper bound of two
//! states reaching the same program point. Every join errs toward the less
//! informative state, so a join can only move a decision toward Ask.
//!
//! | Domain | Element | Join |
//! |---|---|---|
//! | value ([`value`]) | a set of known strings, or `Top`, per variable | union of the known sets; `Top` as soon as either side is `Top` (absorbing) |
//! | path ([`path`]) | a normalised path form, a shape class (ascent, named home, dirstack tilde, glob), or `Top` | equal forms stay; any other pair is `Top`. Not yet implemented: [`path`] only documents the seed |
//! | cwd ([`cwd`]) | `Initial`, `Known(anchor)` or `Poisoned`, with a `pushd` stack | equal contexts stay, every other pair is `Poisoned`; equal stacks stay, any other pair is one `Poisoned` frame |
//!
//! # Scoping
//!
//! [`env::Env`] holds the value facts of one command line. Which assignment
//! reaches a use depends on where the assigning command runs, so each call
//! carries an [`env::ExecScope`]:
//!
//! - `Parent`: certainly runs in the parent shell. Its assignment is a
//!   strong write, replacing the value, only when the command also has no
//!   words (`X=v cmd` is scoped to `cmd`) and the name is not possibly
//!   readonly.
//! - `Conditional`: may be skipped (`&&`/`||` right-hand side, a redirected
//!   brace group). Writes are weak: the earlier value stays reachable.
//! - `Forked`: a backgrounded chain or a pipeline stage. Writes are weak.
//!
//! A strong write of an unresolvable value truncates the candidate history
//! and sets `overwritten_by_unknown`; the next strong resolved write that is
//! not an append truncates once more. Once an unknown overwrite has happened,
//! only values written after the latest certain overwrite stay candidates;
//! before one, every resolved write stays a candidate (#463).
//!
//! A brace group shares its parent's `Env`. A loop or `if` body starts from
//! [`env::Env::child_of`] and a subshell from [`env::Env::subshell_of`]: no
//! values, but the functions, attributes and poison of the parent. A
//! function body is [`env::Env::opaque`], and a recursed payload binds
//! nothing. A body that writes into the parent shell is folded back by
//! [`env::Env::absorb_body`] as writes of unknown values; joining the body's
//! values is future work (#653).
//!
//! # Exact values
//!
//! The value domain also answers whether `$NAME` is certainly one literal
//! string ([`env::Env::exact`]), which is the only source of an Allow from a
//! binding. A variable starts as `Top` (the inherited environment may hold
//! anything); only a literal `for` list word binds it. Anything that may rewrite it unseen drops the
//! binding: a builtin that writes the names it is given, code that may write
//! anything (`eval`, a call to a function defined on the line, a trap), and
//! attributes that change what an assignment stores. Special variables
//! (`IFS`, `HOME`, `PATH`, `BASH_*`, ...) are never bound.
//!
//! # Floor functions by domain
//!
//! The floor functions in `gate.rs` are the current encoding of these
//! domains; they are deleted only after the domain they map to replaces
//! them.
//!
//! | Domain | Floor functions |
//! |---|---|
//! | path | `scan_ascent_descent_floor`, `scan_glob_floor`, `scan_named_user_home_floor`, `scan_dirstack_tilde_floor`, `scan_directory_equals_tilde_floor`, `scan_redirect_ascent_descent_floor`, `scan_redirect_glob_floor`, `scan_redirect_dirstack_tilde_floor`, `scan_redirect_substituted_target_floor`, `scan_redirect_named_user_home_floor` |
//! | cwd | `scan_unknown_cwd_floor`, `scan_dirstack_equal_subst_floor` |
//! | value | `apply_opaque_kind_floor`, `is_opaque_unresolvable`, `ExceptFloors`, `raise_expansion_floor`, `scan_redirect_home_env_floor` |

pub(crate) mod cwd;
pub(crate) mod env;
mod path;
pub(crate) mod value;
