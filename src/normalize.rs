//! Normalised word representation.
//!
//! This module currently defines only the output *type* of stage 2
//! (plan.md §1.1) — the folding logic that produces values of this type
//! (quote removal, ANSI-C decoding, `$IFS` splitting, tilde/brace
//! expansion) is a later issue. [`Verdict`](crate::verdict::Verdict)'s
//! `normalized_argv` is expressed in terms of [`NormalizedWord`] now so the
//! contract is fixed ahead of the implementation.

/// Why a word's final value could not be statically resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnresolvableKind {
    /// The word contains a command substitution (`$(...)` or `` `...` ``)
    /// whose runtime output cannot be known statically.
    CommandSubstitution,
    /// The word contains a parameter expansion (`$NAME`/`${NAME}`) whose
    /// runtime value cannot be known statically.
    ParameterExpansion,
}

/// The two states a normalised word can be in: its value was folded to a
/// concrete string, or it could not be — and if not, why.
///
/// A sum type rather than `Option<String>` plus a side channel: a word is
/// never simultaneously resolved and unresolvable, and the type makes that
/// state unrepresentable instead of relying on callers to keep two fields in
/// sync (principles.md "make invalid states unrepresentable").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The word's final value, folded statically.
    Resolved(String),
    /// The word's value could not be folded statically.
    Unresolvable(UnresolvableKind),
}

/// A normalised word: its [`Resolution`] plus provenance.
///
/// The provenance flag exists because "resolved" and "trustworthy" are not
/// the same claim: plan.md §1.1/§4 folds `$IFS`-containing words using the
/// *default* IFS, but a same-line `IFS=` assignment can make that fold
/// wrong. Such a word is legitimately both `Resolved` *and* untrusted — the
/// structural gate (a later issue) needs to tell it apart from an ordinarily
/// resolved word (e.g. to still check it against the blocklist but never let
/// a miss fall through to `Allow`). Wrapping `Resolution` in a struct with
/// an `ifs_derived` flag makes that combined state representable instead of
/// forcing a third `Resolution` variant that would duplicate the resolved
/// string case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedWord {
    resolution: Resolution,
    ifs_derived: bool,
}

impl NormalizedWord {
    /// A word resolved to a concrete value by ordinary static folding
    /// (quote removal, ANSI-C decoding, tilde/brace expansion — not `$IFS`
    /// folding).
    #[must_use]
    pub fn resolved(value: impl Into<String>) -> Self {
        Self {
            resolution: Resolution::Resolved(value.into()),
            ifs_derived: false,
        }
    }

    /// A word resolved to a concrete value via `$IFS` folding against the
    /// default IFS — "resolved but untrusted" per plan.md §4: a same-line
    /// `IFS=` assignment can make this value wrong, so it stays subject to
    /// blocklist checks but must never fall through to `Allow` on a miss.
    #[must_use]
    pub fn resolved_ifs_derived(value: impl Into<String>) -> Self {
        Self {
            resolution: Resolution::Resolved(value.into()),
            ifs_derived: true,
        }
    }

    /// A word whose value could not be resolved statically.
    #[must_use]
    pub fn unresolvable(kind: UnresolvableKind) -> Self {
        Self {
            resolution: Resolution::Unresolvable(kind),
            ifs_derived: false,
        }
    }

    /// The word's resolution state.
    #[must_use]
    pub fn resolution(&self) -> &Resolution {
        &self.resolution
    }

    /// Whether this word's resolved value came from folding a `$IFS`
    /// expansion, and is therefore untrusted in the presence of a same-line
    /// `IFS=` reassignment (plan.md §4).
    #[must_use]
    pub fn is_ifs_derived(&self) -> bool {
        self.ifs_derived
    }
}
