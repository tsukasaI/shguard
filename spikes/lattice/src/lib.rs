//! M1 Creusot proof spike: each module de-risks one proof shape the v1
//! kernel needs. See `spikes/README.md` for the ADR.

pub mod arena;
pub mod consumer;
pub mod decision;
pub mod tree;
pub mod witness;
pub mod words;

// Negative controls; must FAIL to prove. Off by default, see spikes/README.md.
#[cfg(all(creusot, shguard_mutants))]
pub mod mutants;
