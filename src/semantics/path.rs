//! The path domain.
//!
//! The seed is `crate::rules::PathForm`, a lexically normalised rendering of
//! a path-shaped token: anchored at `/`, anchored at `~`, relative, or a
//! `~`-anchored token that escaped `$HOME`. It stays in `rules.rs` because
//! the knowledge layer's `TargetMatcher` depends on it, and knowledge must
//! not import semantics.
//!
//! The planned domain widens it with the shape classes the path floors
//! detect today (ascent, named home, dirstack tilde, glob) and a `Top`; its
//! join, written in the parent module's table, is: equal forms stay, any
//! other pair is `Top`. No code lives here until a floor function is
//! replaced by it.
