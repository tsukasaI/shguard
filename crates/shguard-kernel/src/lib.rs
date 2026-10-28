//! The verified decision kernel: the command AST, the catalog and rule
//! model, and the `classify`/`decide` functions whose contracts Creusot
//! proves.
#![expect(clippy::indexing_slicing, reason = "bounds proved by Creusot")]

pub mod ast;
pub mod bytes;
pub mod catalog;
pub mod decision;
pub mod rule;
pub mod verdict;
