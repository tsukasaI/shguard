//! Byte-string helpers: equality, prefix test and lexical path
//! normalization.
//!
//! `normalize_path` is specified against `norm_l`, a logic definition
//! written as split / filter / join over `/`-separated segments.

#[cfg(creusot)]
use creusot_std::prelude::*;

// Public because Creusot refuses to unfold an open logic function that
// mentions a less visible item.
/// The path separator.
pub const SLASH: u8 = b'/';
/// The current-directory segment.
pub const DOT: u8 = b'.';

/// Byte-wise equality.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == (a@ == b@)))]
#[must_use]
#[expect(
    clippy::module_name_repetitions,
    reason = "`eq` alone would read as `PartialEq::eq` at call sites"
)]
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    #[cfg_attr(creusot, variant(a@.len() - i@))]
    #[cfg_attr(creusot, invariant(i@ <= a@.len()))]
    #[cfg_attr(creusot, invariant(forall<k> 0 <= k && k < i@ ==> a@[k] == b@[k]))]
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    #[cfg(creusot)]
    proof_assert!(a@.ext_eq(b@));
    true
}

/// `prefix` is a prefix of `s`.
///
/// This is a byte prefix, not a path-component prefix: `/etc` matches
/// `/etcfoo`. That is safe only for rules that can raise a decision; any rule
/// that scopes an Allow needs a component-boundary check as well.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result == (prefix@.len() <= s@.len()
    && s@.subsequence(0, prefix@.len()) == prefix@)))]
#[must_use]
pub fn starts_with(s: &[u8], prefix: &[u8]) -> bool {
    if prefix.len() > s.len() {
        return false;
    }
    let mut i: usize = 0;
    #[cfg_attr(creusot, variant(prefix@.len() - i@))]
    #[cfg_attr(creusot, invariant(i@ <= prefix@.len()))]
    #[cfg_attr(creusot, invariant(forall<k> 0 <= k && k < i@ ==> s@[k] == prefix@[k]))]
    while i < prefix.len() {
        if s[i] != prefix[i] {
            #[cfg(creusot)]
            proof_assert!(s@.subsequence(0, prefix@.len())[i@] != prefix@[i@]);
            return false;
        }
        i += 1;
    }
    #[cfg(creusot)]
    proof_assert!(s@.subsequence(0, prefix@.len()).ext_eq(prefix@));
    true
}

/// All `/`-separated segments of `p`, empty ones included, so `"/a//"`
/// gives `["", "a", "", ""]`. Defined by recursion on the last byte.
#[cfg(creusot)]
#[logic(open)]
#[variant(p.len())]
pub fn split_segs(p: Seq<u8>) -> Seq<Seq<u8>> {
    if p.len() == 0 {
        Seq::singleton(Seq::empty())
    } else {
        let r = split_segs(p.pop_back());
        let c = p[p.len() - 1];
        if r.len() == 0 {
            // Unreachable (`lemma_split_nonempty`); keeps the definition total.
            Seq::empty()
        } else if c == SLASH {
            r.push_back(Seq::empty())
        } else {
            r.pop_back().push_back(r[r.len() - 1].push_back(c))
        }
    }
}

/// A segment survives normalization unless it is empty or `.`.
#[cfg(creusot)]
#[logic(open)]
pub fn keep_seg(s: Seq<u8>) -> bool {
    s.len() > 0 && !(s.len() == 1 && s[0] == DOT)
}

/// The segments of `ss` that `keep_seg` accepts, in order.
#[cfg(creusot)]
#[logic(open)]
#[variant(ss.len())]
pub fn filter_segs(ss: Seq<Seq<u8>>) -> Seq<Seq<u8>> {
    if ss.len() == 0 {
        Seq::empty()
    } else {
        let r = filter_segs(ss.pop_back());
        let last = ss[ss.len() - 1];
        if keep_seg(last) { r.push_back(last) } else { r }
    }
}

/// The segments of `ss` joined with single `/` separators.
#[cfg(creusot)]
#[logic(open)]
#[variant(ss.len())]
pub fn join_segs(ss: Seq<Seq<u8>>) -> Seq<u8> {
    if ss.len() == 0 {
        Seq::empty()
    } else if ss.len() == 1 {
        ss[0]
    } else {
        join_segs(ss.pop_back())
            .push_back(SLASH)
            .concat(ss[ss.len() - 1])
    }
}

/// The lexical normal form of `p`: drop empty and `.` segments, keep `..`,
/// rejoin with `/`, and keep a leading `/`. With nothing left, an absolute
/// path is `/` and a relative one `.`; the empty path stays empty.
#[cfg(creusot)]
#[logic(open)]
pub fn norm_l(p: Seq<u8>) -> Seq<u8> {
    let kept = filter_segs(split_segs(p));
    if p.len() == 0 {
        Seq::empty()
    } else if p[0] == SLASH {
        Seq::singleton(SLASH).concat(join_segs(kept))
    } else if kept.len() == 0 {
        Seq::singleton(DOT)
    } else {
        join_segs(kept)
    }
}

/// `split_segs` always yields at least one segment.
#[cfg(creusot)]
#[logic]
#[variant(p.len())]
#[ensures(split_segs(p).len() >= 1)]
pub fn lemma_split_nonempty(p: Seq<u8>) {
    if p.len() > 0 {
        lemma_split_nonempty(p.pop_back())
    }
}

/// Pushing then popping is the identity.
#[cfg(creusot)]
#[logic]
#[ensures(s.push_back(x).pop_back() == s)]
#[ensures(s.push_back(x)[s.len()] == x)]
pub fn lemma_snoc_pop<T>(s: Seq<T>, x: T) {
    proof_assert! { s.push_back(x).pop_back().ext_eq(s) }
}

/// Extending a slice of `p` by the next byte.
#[cfg(creusot)]
#[logic]
#[requires(0 <= s && s <= i && i < p.len())]
#[ensures(p.subsequence(s, i).push_back(p[i]) == p.subsequence(s, i + 1))]
#[ensures(p.subsequence(0, i + 1).pop_back() == p.subsequence(0, i))]
#[ensures(p.subsequence(0, i + 1)[i] == p[i])]
pub fn lemma_sub_snoc(p: Seq<u8>, s: Int, i: Int) {
    proof_assert! { p.subsequence(s, i).push_back(p[i]).ext_eq(p.subsequence(s, i + 1)) };
    proof_assert! { p.subsequence(0, i + 1).pop_back().ext_eq(p.subsequence(0, i)) }
}

/// Appending to a concatenation, and the empty-sequence units.
#[cfg(creusot)]
#[logic]
#[ensures(a.concat(b).push_back(x) == a.concat(b.push_back(x)))]
#[ensures(a.concat(b).concat(c) == a.concat(b.concat(c)))]
#[ensures(a.concat(Seq::empty()) == a)]
#[ensures(Seq::empty().concat(a) == a)]
pub fn lemma_concat_laws(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>, x: u8) {
    proof_assert! { a.concat(b).push_back(x).ext_eq(a.concat(b.push_back(x))) };
    proof_assert! { a.concat(b).concat(c).ext_eq(a.concat(b.concat(c))) };
    proof_assert! { a.concat(Seq::empty()).ext_eq(a) };
    proof_assert! { Seq::empty().concat(a).ext_eq(a) }
}

/// Re-associates the two shapes `emit_seg` produces on `a ++ j`.
#[cfg(creusot)]
#[logic]
#[ensures(j.len() == 0 ==> a.concat(j).concat(x) == a.concat(x))]
#[ensures(a.concat(j).push_back(SLASH).concat(x) == a.concat(j.push_back(SLASH).concat(x)))]
pub fn lemma_emit_assoc(a: Seq<u8>, j: Seq<u8>, x: Seq<u8>) {
    proof_assert! { j.len() == 0 ==> a.concat(j).concat(x).ext_eq(a.concat(x)) };
    proof_assert! {
        a.concat(j).push_back(SLASH).concat(x).ext_eq(a.concat(j.push_back(SLASH).concat(x)))
    }
}

/// The segments completed before position `s` (a segment start): none when
/// `s` is 0, else every segment of `p[..s - 1]`.
#[cfg(creusot)]
#[logic(open)]
fn done_segs(p: Seq<u8>, s: Int) -> Seq<Seq<u8>> {
    if s <= 0 {
        Seq::empty()
    } else {
        split_segs(p.subsequence(0, s - 1))
    }
}

/// The leading `/` of an absolute path, or nothing.
#[cfg(creusot)]
#[logic(open)]
fn lead(p: Seq<u8>) -> Seq<u8> {
    if p.len() > 0 && p[0] == SLASH {
        Seq::singleton(SLASH)
    } else {
        Seq::empty()
    }
}

/// While scanning a segment that starts at `s`, the segments of `p[..i]`
/// are the completed ones followed by the partial `p[s..i]`.
#[cfg(creusot)]
#[logic]
#[variant(i - s)]
#[requires(0 <= s && s <= i && i <= p.len())]
#[requires(s == 0 || p[s - 1] == SLASH)]
#[requires(forall<k> s <= k && k < i ==> p[k] != SLASH)]
#[ensures(split_segs(p.subsequence(0, i)) == done_segs(p, s).push_back(p.subsequence(s, i)))]
pub fn lemma_split_prefix(p: Seq<u8>, s: Int, i: Int) {
    if i > s {
        lemma_split_prefix(p, s, i - 1);
        lemma_sub_snoc(p, s, i - 1);
        lemma_snoc_pop(done_segs(p, s), p.subsequence(s, i - 1));
        lemma_snoc_pop(done_segs(p, s), p.subsequence(s, i))
    } else if s > 0 {
        lemma_sub_snoc(p, s - 1, s - 1);
        lemma_split_nonempty(p.subsequence(0, s - 1));
        proof_assert! { p.subsequence(s, s).ext_eq(Seq::empty()) }
    } else {
        proof_assert! { p.subsequence(0, 0).ext_eq(Seq::empty()) };
        proof_assert! {
            Seq::<Seq<u8>>::empty().push_back(Seq::empty()).ext_eq(Seq::singleton(Seq::empty()))
        }
    }
}

/// Filtering distributes over appending one segment.
#[cfg(creusot)]
#[logic]
#[ensures(filter_segs(ss.push_back(x))
    == if keep_seg(x) { filter_segs(ss).push_back(x) } else { filter_segs(ss) })]
pub fn lemma_filter_snoc(ss: Seq<Seq<u8>>, x: Seq<u8>) {
    lemma_snoc_pop(ss, x)
}

/// Joining after appending one segment adds a separator unless it is the
/// first.
#[cfg(creusot)]
#[logic]
#[ensures(join_segs(ss.push_back(x))
    == if ss.len() == 0 { x } else { join_segs(ss).push_back(SLASH).concat(x) })]
pub fn lemma_join_snoc(ss: Seq<Seq<u8>>, x: Seq<u8>) {
    lemma_snoc_pop(ss, x)
}

/// Appends the segment `p[s..e]` to `out` if `keep_seg` accepts it, after a
/// `/` unless `first`. Returns whether `out` still holds no segment.
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, requires(s@ <= e@ && e@ <= p@.len()))]
#[cfg_attr(creusot, ensures(if keep_seg(p@.subsequence(s@, e@)) {
    !result && (^out)@ == (if first { out@ } else { out@.push_back(SLASH) })
        .concat(p@.subsequence(s@, e@))
} else {
    result == first && (^out)@ == out@
}))]
fn emit_seg(out: &mut Vec<u8>, p: &[u8], s: usize, e: usize, first: bool) -> bool {
    if e == s || (e - s == 1 && p[s] == DOT) {
        return first;
    }
    if !first {
        out.push(SLASH);
    }
    #[cfg(creusot)]
    let base = snapshot!(out@);
    #[cfg(creusot)]
    proof_assert! { lemma_concat_laws(*base, Seq::empty(), Seq::empty(), 0u8);
    p@.subsequence(s@, s@).ext_eq(Seq::empty()) };
    let mut j = s;
    #[cfg_attr(creusot, variant(e@ - j@))]
    #[cfg_attr(creusot, invariant(s@ <= j@ && j@ <= e@))]
    #[cfg_attr(creusot, invariant(out@ == (*base).concat(p@.subsequence(s@, j@))))]
    while j < e {
        #[cfg(creusot)]
        proof_assert! { lemma_sub_snoc(p@, s@, j@);
        lemma_concat_laws(*base, p@.subsequence(s@, j@), Seq::empty(), p@[j@]); true };
        out.push(p[j]);
        j += 1;
    }
    false
}

/// Lexical path normalization: collapse `/` runs, drop `.` segments and a
/// trailing `/`, keep `..` segments unresolved and keep a leading `/`.
///
/// With nothing left, an absolute path gives `/` and a relative one `.`.
/// The empty path gives the empty path.
///
/// Use it only to compare path operands with rule targets. Never apply it to
/// a command name or use it to decide whether a word is an option: dropping
/// `./` changes how the shell looks the word up (`./ls` runs a file, `ls`
/// searches `PATH`).
#[cfg_attr(creusot, check(terminates))]
#[cfg_attr(creusot, ensures(result@ == norm_l(p@)))]
#[must_use]
pub fn normalize_path(p: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let n = p.len();
    if n == 0 {
        #[cfg(creusot)]
        proof_assert!(out@.ext_eq(Seq::empty()));
        return out;
    }
    let abs = p[0] == SLASH;
    if abs {
        out.push(SLASH);
    }
    #[cfg(creusot)]
    proof_assert! { lemma_concat_laws(out@, Seq::empty(), Seq::empty(), 0u8);
    out@.ext_eq(lead(p@)) };
    let mut first = true;
    let mut s: usize = 0;
    let mut i: usize = 0;
    #[cfg_attr(creusot, variant(n@ - i@))]
    #[cfg_attr(creusot, invariant(s@ <= i@ && i@ <= n@))]
    #[cfg_attr(creusot, invariant(s@ == 0 || p@[s@ - 1] == SLASH))]
    #[cfg_attr(creusot, invariant(forall<k> s@ <= k && k < i@ ==> p@[k] != SLASH))]
    #[cfg_attr(creusot, invariant(
        out@ == lead(p@).concat(join_segs(filter_segs(done_segs(p@, s@))))))]
    #[cfg_attr(creusot, invariant(first == (filter_segs(done_segs(p@, s@)).len() == 0)))]
    while i < n {
        if p[i] == SLASH {
            #[cfg(creusot)]
            proof_assert! {
                lemma_split_prefix(p@, s@, i@);
                lemma_filter_snoc(done_segs(p@, s@), p@.subsequence(s@, i@));
                lemma_join_snoc(filter_segs(done_segs(p@, s@)), p@.subsequence(s@, i@));
                lemma_emit_assoc(lead(p@), join_segs(filter_segs(done_segs(p@, s@))),
                    p@.subsequence(s@, i@));
                done_segs(p@, i@ + 1) == split_segs(p@.subsequence(0, i@))
            };
            first = emit_seg(&mut out, p, s, i, first);
            s = i + 1;
        }
        i += 1;
    }
    #[cfg(creusot)]
    proof_assert! {
        lemma_split_prefix(p@, s@, n@);
        lemma_filter_snoc(done_segs(p@, s@), p@.subsequence(s@, n@));
        lemma_join_snoc(filter_segs(done_segs(p@, s@)), p@.subsequence(s@, n@));
        lemma_emit_assoc(lead(p@), join_segs(filter_segs(done_segs(p@, s@))),
            p@.subsequence(s@, n@));
        p@.subsequence(0, n@).ext_eq(p@)
    };
    first = emit_seg(&mut out, p, s, n, first);
    #[cfg(creusot)]
    proof_assert! {
        lemma_concat_laws(join_segs(filter_segs(split_segs(p@))), Seq::empty(), Seq::empty(), 0u8);
        out@ == lead(p@).concat(join_segs(filter_segs(split_segs(p@))))
    };
    if first && !abs {
        #[cfg(creusot)]
        proof_assert!(out@.push_back(DOT).ext_eq(Seq::singleton(DOT)));
        out.push(DOT);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{bytes_eq, normalize_path, starts_with};

    #[test]
    fn bytes_eq_cases() {
        assert!(bytes_eq(b"", b""));
        assert!(bytes_eq(b"abc", b"abc"));
        assert!(!bytes_eq(b"abc", b"abd"));
        assert!(!bytes_eq(b"abc", b"ab"));
        assert!(!bytes_eq(b"", b"a"));
    }

    #[test]
    fn starts_with_cases() {
        assert!(starts_with(b"", b""));
        assert!(starts_with(b"abc", b""));
        assert!(starts_with(b"abc", b"abc"));
        assert!(starts_with(b"abc", b"ab"));
        assert!(!starts_with(b"abc", b"abd"));
        assert!(!starts_with(b"ab", b"abc"));
        assert!(!starts_with(b"", b"a"));
    }

    #[test]
    fn normalize_examples() {
        let cases: [(&[u8], &[u8]); 9] = [
            (b"//usr///bin/", b"/usr/bin"),
            (b"/./etc/.", b"/etc"),
            (b"a/./b//", b"a/b"),
            (b"./", b"."),
            (b"/", b"/"),
            (b"////", b"/"),
            (b"../x/", b"../x"),
            (b"a/../b", b"a/../b"),
            (b"", b""),
        ];
        for (input, want) in cases {
            assert_eq!(
                normalize_path(input),
                want,
                "normalize_path({:?})",
                String::from_utf8_lossy(input)
            );
        }
    }
}
