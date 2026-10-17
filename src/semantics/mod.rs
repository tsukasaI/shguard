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
//! not an append truncates once more, so only values written after the last
//! certain overwrite stay candidates (issues #516, #534, #607).
//!
//! A subshell, loop or `if` body, a function body and a recursed payload each
//! start from [`env::Env::isolated`]; only a brace group shares its parent's
//! `Env`. Child environments that join back are future work (#653).
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
