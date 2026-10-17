//! The value domain: what a shell variable may hold at one program point.

use std::collections::BTreeSet;

/// A finite set of strings a variable is known to have held.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KnownSet(BTreeSet<String>);

impl KnownSet {
    fn singleton(value: &str) -> Self {
        Self(BTreeSet::from([value.to_string()]))
    }

    fn union(&self, other: &Self) -> Self {
        Self(self.0.union(&other.0).cloned().collect())
    }

    fn only(&self) -> Option<&str> {
        let mut values = self.0.iter();
        match (values.next(), values.next()) {
            (Some(value), None) => Some(value.as_str()),
            _ => None,
        }
    }
}

/// One assignment as the value domain sees it: a statically resolved string,
/// or a value that could be anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Write {
    Exact(String),
    Top,
}

/// What a variable may hold: a set of known strings, or `Top` (`open`).
///
/// The default is bottom: nothing known, not open. The join is the least
/// upper bound of the lattice `bottom < Known(set) < Top`: the union of the
/// known sets, and `Top` as soon as either side is open. `Top` absorbs, so
/// an open value never carries a known set (`open` implies an empty
/// `known`), which keeps the join associative and `Top` a true top element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AbsValue {
    known: KnownSet,
    open: bool,
}

impl AbsValue {
    fn of(write: &Write) -> Self {
        match write {
            Write::Exact(value) => Self {
                known: KnownSet::singleton(value),
                open: false,
            },
            Write::Top => Self {
                known: KnownSet::default(),
                open: true,
            },
        }
    }

    /// The value of a variable nothing is known about.
    pub(crate) fn top() -> Self {
        Self::of(&Write::Top)
    }

    /// The one string this value certainly is: `Some` only when the known
    /// set has a single element and the value is not open.
    pub(crate) fn exact(&self) -> Option<&str> {
        if self.open {
            return None;
        }
        self.known.only()
    }

    pub(crate) fn join(&self, other: &Self) -> Self {
        if self.open || other.open {
            return Self::of(&Write::Top);
        }
        Self {
            known: self.known.union(&other.known),
            open: false,
        }
    }

    /// A write that may not have happened (a short-circuited, forked or
    /// possibly-readonly assignment): the old value stays a possibility.
    pub(crate) fn weak_write(&self, write: &Write) -> Self {
        self.join(&Self::of(write))
    }

    /// A write that certainly replaced the value.
    pub(crate) fn strong_write(write: &Write) -> Self {
        Self::of(write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(value: &str) -> AbsValue {
        AbsValue::strong_write(&Write::Exact(value.to_string()))
    }

    fn top() -> AbsValue {
        AbsValue::strong_write(&Write::Top)
    }

    fn samples() -> Vec<AbsValue> {
        let ab = exact("a").join(&exact("b"));
        vec![AbsValue::default(), exact("a"), exact("b"), ab, top()]
    }

    #[test]
    fn join_is_commutative() {
        for x in samples() {
            for y in samples() {
                assert_eq!(x.join(&y), y.join(&x), "{x:?} {y:?}");
            }
        }
    }

    #[test]
    fn join_is_associative() {
        for x in samples() {
            for y in samples() {
                for z in samples() {
                    assert_eq!(
                        x.join(&y).join(&z),
                        x.join(&y.join(&z)),
                        "{x:?} {y:?} {z:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn join_is_idempotent() {
        for x in samples() {
            assert_eq!(x.join(&x), x);
        }
    }

    #[test]
    fn bottom_is_the_join_identity() {
        for x in samples() {
            assert_eq!(x.join(&AbsValue::default()), x);
        }
    }

    #[test]
    fn top_absorbs() {
        for x in samples() {
            assert_eq!(x.join(&top()), top(), "{x:?}");
            assert_eq!(top().join(&x), top(), "{x:?}");
        }
    }

    #[test]
    fn exact_is_some_only_for_a_single_known_string() {
        assert_eq!(exact("a").exact(), Some("a"));
        assert_eq!(exact("a").join(&exact("a")).exact(), Some("a"));
        assert_eq!(exact("a").join(&exact("b")).exact(), None);
        assert_eq!(AbsValue::default().exact(), None);
        assert_eq!(top().exact(), None);
        assert_eq!(AbsValue::top(), top());
        assert_eq!(exact("a").weak_write(&Write::Top).exact(), None);
    }

    #[test]
    fn weak_write_keeps_the_old_possibility_and_strong_write_drops_it() {
        let both = exact("a").weak_write(&Write::Exact("b".to_string()));
        assert_eq!(both, exact("a").join(&exact("b")));
        assert_eq!(
            AbsValue::strong_write(&Write::Exact("b".to_string())),
            exact("b")
        );
        assert_eq!(exact("a").weak_write(&Write::Top), top());
        assert_eq!(top().weak_write(&Write::Exact("b".to_string())), top());
        assert_eq!(AbsValue::strong_write(&Write::Top), top());
    }
}
