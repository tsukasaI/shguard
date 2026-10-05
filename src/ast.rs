//! shguard's own AST for a parsed bash command line.
//!
//! These types are shguard's, not any parser crate's: `src/parser.rs`
//! translates the selected parser crate's output (docs/adr/0001-parser-crate.md)
//! into this shape so the rest of the pipeline never imports a type from
//! that crate (plan.md §1.1 stage 1). The shape here is sized to the
//! fixture corpus the ADR validated the selected crate against: lists joined by
//! `;`/`&&`/`||`, pipelines, simple commands (assignments + words +
//! redirections), and word pieces covering quoting, ANSI-C quoting,
//! parameter/command/backquote substitution, tilde, brace alternation, and
//! escape sequences.
//!
//! Constructed by `src/parser.rs` (the stage 1 adapter, B1). Consumed by the
//! normalise stage (`src/normalize.rs`, B2) and, for the raw substitution
//! text and command-position shape that normalisation deliberately does not
//! retain, by the structural gate (`src/gate.rs`, B4) directly.

/// Shared nesting-depth cap for brace-alternation (`{`/`}`) and
/// command-substitution (`(`/`)`) recursion, enforced independently by
/// `src/parser.rs`'s raw pre-scan and AST-level depth cap and by
/// `src/normalize.rs`'s `expand_braces` recursion (issue #52).
///
/// Placed here rather than in either consuming module because both
/// `parser` and `normalize` already depend on `ast`, and sharing one
/// constant across the two layers avoids a new `parser` -> `normalize`
/// dependency that keeping it in either module would create.
///
/// # Why 64
///
/// Real brace nesting rarely exceeds 2-3 levels; one nesting level costs
/// roughly 3KB of raw input (measured: `{a,`x3000 is the crash threshold on
/// an 8MiB main-thread stack, so ~1 level per ~3KB), so 64 levels is a ~10x
/// safety margin over the ~600-level budget `cargo test`'s 2MiB test-thread
/// stack allows — comfortably clear of both the tested-safe range and any
/// realistic legitimate nesting. This measurement is tied to `brush-parser
/// =0.4.0`'s specific recursion cost and the OS-default 8MiB main-thread
/// stack (not a Rust guarantee — `ulimit -s` or a musl target can shrink
/// it): re-measure the crash threshold before raising this cap on any
/// `brush-parser` version bump. It intentionally matches
/// `normalize::MAX_BRACE_ALTERNATIVES` (also 64) rather than
/// `gate::MAX_SUBSTITUTION_DEPTH` (8): the latter is an *analysis* recursion
/// depth (each level re-evaluates a whole pipeline through the gate), while
/// this is cheap *structural* recursion (descending into an AST/text shape).
/// A cap as tight as 8 risks a false Ask when the raw scanner over-counts
/// (e.g. `{`/`(` occurring inside a quoted string it does not parse
/// quoting out of); 64 tolerates that over-count while still capping actual
/// unbounded recursion. With [`MAX_RAW_BRACE_NESTING_DEPTH`]/
/// [`MAX_RAW_PAREN_NESTING_DEPTH`] in place, this tolerance argument no
/// longer applies to either half of the raw scan — see their own docs for
/// why each needs a much tighter, PEG-cost-driven cap instead.
///
/// # Known trade-off
///
/// The raw pre-scan in `src/parser.rs::parse` counts every `{`/`}`/`(`/`)`
/// byte in the input, including ones inside quotes (e.g. a deeply nested
/// JSON literal passed as a shell argument). Such input can hit this cap
/// (or, more likely given how much tighter they are,
/// [`MAX_RAW_BRACE_NESTING_DEPTH`]/[`MAX_RAW_PAREN_NESTING_DEPTH`]) and
/// fail closed to `Ask` even though it is not itself a nesting attack —
/// an accepted false-positive cost of a scan that is deliberately linear
/// and non-recursive (the only correctness property that matters for a
/// stack-overflow defense).
pub(crate) const MAX_BRACE_NESTING_DEPTH: usize = 64;

/// Cap on `{`/`}` nesting depth specifically for `src/parser.rs`'s raw
/// pre-scan (`reject_excessive_raw_nesting`) — separate from
/// [`MAX_BRACE_NESTING_DEPTH`], which every AST-level brace-depth cap
/// (`src/parser.rs`'s `convert_brace_segment`/`convert_brace_members`,
/// `src/normalize.rs`'s `expand_braces`) keeps using unchanged.
///
/// # Why a separate, much smaller cap
///
/// A *comma-less* nested brace group (`{{{x}}}`, no `,` inside any level)
/// makes brush-parser's PEG grammar backtrack catastrophically — no
/// memoization, ~6.5x cost growth per two nesting levels (~2.5x per level;
/// crash-fuzzer measurement, release build):
///
/// | depth | time |
/// |---|---|
/// | 12 | 0.026s |
/// | 14 | 0.158s |
/// | 16 | 1.064s |
/// | 18 | 7.278s |
///
/// `MAX_BRACE_NESTING_DEPTH`'s own 64-level cap is far above the usable
/// limit here: depth 24 already extrapolates to over half an hour and
/// depth 26 to hours, so a raw brace count sitting *below* 64 sails
/// through unrejected while still taking unbounded wall-clock time. A
/// *closed* brace expansion containing at least one `,` at every level
/// (`{a,{a,{a,x}}}`) does not backtrack this way — confirmed flat at
/// ~0.004s regardless of depth. An *unclosed* comma-ful run
/// (`{a,{a,{a,`, no `}`) does, because the failed alternation is retried
/// at every level (release build, `shguard check` end to end, best of 2):
///
/// | unclosed units | `{a,` | `{a,b,` | `{a,b,c,` |
/// |---|---|---|---|
/// | 9 | 0.022s | 0.023s | 0.037s |
/// | 10 | 0.037s | 0.068s | 0.134s |
/// | 11 | 0.078s | 0.735s | 0.991s |
/// | 12 | 0.763s | 2.013s (watchdog trip) | 1.02s |
/// | 13 | 2.028s (watchdog trip) | 2.018s (watchdog trip) | 2.014s (watchdog trip) |
///
/// The cap rejects *any* raw `{` depth past 10, comma or not: a comma-ful
/// alternation nested deeper than 10, and quoted/heredoc text whose braces
/// the scan over-counts (a >10-deep JSON literal, an awk body), fail closed
/// to `Ask` where 64 tolerated them.
///
/// # Why a depth cap alone is not enough
///
/// The depth counter decrements on every `}`, quoted or not, so each of
/// several words can stay at depth <= 10 (`{a,b,c,`x10 + `'}'`x10, repeated)
/// while their per-word costs add up. [`MAX_RAW_BRACE_OPEN_COUNT`], a total
/// that closers can never reset, bounds the sum: at most three full-depth
/// words fit under it (3 words of depth 10 measured 0.27s, 4 words 0.50s).
///
/// 10 is the deepest level where the worst measured unclosed shape
/// (`{a,b,c,`, 0.134s) still leaves a >=3x margin below the 2s watchdog
/// budget even summed over the words the open-count cap admits (about
/// 0.4s, ~5x). Re-measure the same curves before raising this on any
/// `brush-parser` version bump — unlike stack-depth caps, this one is not
/// just "still safe", it can silently become "usable again" or "unusably
/// slow one level earlier" depending on whether a new grammar version added
/// memoization.
pub(crate) const MAX_RAW_BRACE_NESTING_DEPTH: usize = 10;

/// Cap on `(`/`)` nesting depth specifically for `src/parser.rs`'s raw
/// pre-scan (`reject_excessive_raw_nesting`) — issue #404's tightening of
/// the same PEG-catastrophic-backtracking class [`MAX_RAW_BRACE_NESTING_DEPTH`]
/// already closed for `{`/`}`. Separate from [`MAX_BRACE_NESTING_DEPTH`],
/// which every AST-level paren-adjacent depth cap (`collect_extended_test_words`)
/// keeps using unchanged.
///
/// # Why a separate, much smaller cap
///
/// A leading run of unbalanced `(` (no matching `)` anywhere) triggers
/// brush-parser's subshell-vs-arithmetic-expansion PEG ambiguity into the
/// same catastrophic backtracking `{{{`-nesting does — no memoization
/// (crash-fuzzer measurement, release build, `shguard check` end to end):
///
/// | depth | time |
/// |---|---|
/// | 16 | 0.007s (at CLI-startup baseline; no measurable parse cost) |
/// | 18 | 0.013s |
/// | 20 | 0.036s |
/// | 22 | 0.129s |
/// | 24 | 0.498s |
/// | 26 | 2.000s (watchdog trip) |
///
/// `MAX_BRACE_NESTING_DEPTH`'s own 64-level cap is far above the usable
/// limit here — a raw paren depth sitting below 64 sailed through
/// unrejected while spending arbitrary CPU. Via the CLI/hook path this
/// only stalls for the watchdog's timeout before failing closed to `Ask`;
/// via the public library API (`shguard::analyze`), the detached watchdog
/// worker thread keeps burning CPU indefinitely after the caller already
/// received its `Ask` verdict — a real CPU DoS against any long-lived
/// process embedding `shguard` as a library, independent of the CLI's own
/// watchdog protection.
///
/// 16 sits at the last depth measured indistinguishable from CLI-startup
/// baseline (no detectable parse cost at all), with a wide margin below
/// where growth becomes exponential (18+). Re-measure the same
/// leading-unbalanced-paren timing curve before raising this on any
/// `brush-parser` version bump, for the same reason
/// [`MAX_RAW_BRACE_NESTING_DEPTH`]'s docs give.
pub(crate) const MAX_RAW_PAREN_NESTING_DEPTH: usize = 16;

/// Cap on the total count of raw `{` bytes [`crate::parser::reject_excessive_raw_nesting`]
/// tolerates in one command, counted once per `{` byte and never decremented
/// on a `}` — unlike [`MAX_RAW_BRACE_NESTING_DEPTH`]'s balanced depth
/// counter, this one cannot be driven back down.
///
/// # Why a second, non-decrementing counter is needed at all
///
/// A quoted, backslash-escaped, heredoc-body, or `#`-comment `}` is not a
/// real brace-group closer to `brush-parser` — bash never treats it as one
/// either — but [`MAX_RAW_BRACE_NESTING_DEPTH`]'s depth counter decrements
/// on every raw `}` byte regardless, with no quote/escape/heredoc/comment
/// awareness. So real nesting can grow unboundedly while the depth counter
/// this raw pre-scan relies on stays pinned at 0-1, sailing straight past
/// the depth cap (crash-fuzzer bisection, release build, real hook binary):
/// `rm -rf / ` + `{\}`x2925 + `x` + `}`x2925 (backslash-escaped closer) and
/// `rm -rf / ` + `{'}'`x2925 + `x` + `}`x2925 (quoted closer) both abort
/// with an uncatchable stack overflow and empty stdout — a fail-open bypass
/// of the whole hook. Heredoc-body and `#`-comment closers abort the same
/// way. Counting only openers, never decrementing, has no closer for an
/// attacker to inject against, the same reasoning [`MAX_KEYWORD_NESTING_COUNT`]'s
/// docs give for keyword closers: the count can only ever overestimate true
/// nesting depth (safe direction).
///
/// # Why 32
///
/// Two independent bounds, both against the lowest measured floor:
///
/// - Stack depth. A bare brace *group* with a quoted closer
///   (`{ '}'; `, one per command position) recurses through the program
///   grammar and aborts at 115 openers (debug build, `cargo test`'s 2MiB
///   thread stack, the tighter of the two budgets this crate ships against)
///   / 403 (release): 32 is only ~3.6x below the debug figure. (A brace
///   *word* `{'}'` aborts much later, 580 / 2922 with the 2s time budget
///   tripping first, and is not the binding shape.) Parameter expansions
///   recurse much deeper per `{` and are bounded by the tighter
///   [`MAX_RAW_PARAM_EXPANSION_COUNT`] instead. Because grammar-level
///   recursions of different kinds share one stack, the cap that actually
///   guarantees the composed margin is [`MAX_RAW_STACK_BUDGET`].
/// - CPU time: this total is what bounds the number of full-depth unclosed
///   comma-ful words that [`MAX_RAW_BRACE_NESTING_DEPTH`]'s per-word depth
///   cap lets through, because a quoted `}` resets that depth counter
///   (`{a,b,c,`x10 + `'}'`x10, repeated). 32 admits at most three depth-10
///   words, ~0.4s against the 2s budget (~5x). The check counts every `{`,
///   comma-ful or not, since a closer-proof comma-ful count would need the
///   very quote awareness this scan lacks.
///
/// # Known trade-off
///
/// Like [`MAX_BRACE_NESTING_DEPTH`], this counts every raw `{` byte
/// including ones inside quotes, heredoc bodies, and comments. Legitimate
/// input with more than 32 `{` bytes anywhere in one command — a large
/// inline JSON literal, an awk or jq body, a long run of `${...}`
/// expansions — fails closed to `Ask`. That over-Ask is accepted: a count
/// that quoting cannot reset is the only guard that does not depend on
/// matching brush's quoting rules.
pub(crate) const MAX_RAW_BRACE_OPEN_COUNT: usize = 32;

/// Cap on the total count of `${` openers (a `{` immediately preceded by
/// `$`) in one command, enforced by [`crate::parser::reject_excessive_raw_nesting`]
/// on top of [`MAX_RAW_BRACE_OPEN_COUNT`]. Never decremented, so a quoted or
/// escaped `}` (`${x:-'}'`, `${a/b/'}'`, `${x:-\}`) cannot reset it.
///
/// # Why 16
///
/// brush-parser recurses once per `${` however its closer is hidden.
/// Smallest aborting count with the cap lifted, `echo ` + the unit repeated
/// N times (+ `x` and N closing `}` for the "closed" column), debug build /
/// release build:
///
/// | unit | unclosed | closed |
/// |---|---|---|
/// | `${a/b/'}'` (lowest floor; `/`, `//`, `^^`, `,,` forms 73) | 168 / 2530 | 72 / 1643 |
/// | `${a:1:2'}'` | 168 / 2530 | 76 / 2434 |
/// | `${a:-'}'` (`:+`, `#`, `%`, `:-\}` forms alike) | 168 / 2530 | 120 / 1643 |
/// | `${!a'}'`, `${a@'}'` | 168 / 2530 | 168 / 2530 |
///
/// 16 is 4.5x below the lowest debug floor (72) and ~100x below the release
/// one. Re-bisect every parameter-expansion operator form before raising
/// this on any `brush-parser` version bump.
///
/// # Known trade-off
///
/// More than 16 `${...}` expansions in one command (a long generated
/// script, a heredoc body that mentions many `${VAR}`) fail closed to `Ask`.
pub(crate) const MAX_RAW_PARAM_EXPANSION_COUNT: usize = 16;

/// Cap on the total count of raw `(` bytes [`crate::parser::reject_excessive_raw_nesting`]
/// tolerates in one command, counted once per `(` byte and never decremented
/// on a `)` — the `(`/`)` counterpart of [`MAX_RAW_BRACE_OPEN_COUNT`], for
/// the identical reason: a quoted, backslash-escaped, or `$(...)`-nested `)`
/// is not a real closer to `brush-parser`, so [`MAX_RAW_PAREN_NESTING_DEPTH`]'s
/// decrementing depth counter can be driven back down by injecting one
/// while real nesting keeps growing (crash-fuzzer bisection: `rm -rf / ` +
/// `$(echo ")"`x3000 + `x` + `)`x3000 aborts with an uncatchable stack
/// overflow and empty stdout, sailing straight past the depth cap).
///
/// # Why 32
///
/// This is the general bound on every `(`; the openers that recurse
/// deepest per byte have their own, tighter caps
/// ([`MAX_RAW_COMMAND_SUBST_COUNT`], [`MAX_RAW_PROCESS_SUBST_COUNT`]). What
/// remains is a bare `(` (subshell, `$((` second paren, array literal),
/// whose nesting needs real unquoted closers that
/// [`MAX_RAW_PAREN_NESTING_DEPTH`] already bounds (a flat run of `( ')' `
/// units is a syntax error at the first unit, so no hidden-closer shape
/// reaches deep recursion through a bare `(`). Re-check this on a
/// `brush-parser` bump.
///
/// # Known trade-off
///
/// Like [`MAX_RAW_BRACE_OPEN_COUNT`], this counts every raw `(` byte
/// including ones inside quotes and nested substitutions. Legitimate input
/// with more than 32 `(` bytes in one command (a long `case` pattern list,
/// many subshells) fails closed to `Ask`.
pub(crate) const MAX_RAW_PAREN_OPEN_COUNT: usize = 32;

/// Cap on the total count of `$(` openers (command substitution, including
/// the first two bytes of `$((`) in one command, enforced by
/// [`crate::parser::reject_excessive_raw_nesting`] on top of
/// [`MAX_RAW_PAREN_OPEN_COUNT`]. Never decremented, so a quoted or escaped
/// `)` (`$( ')' `, `$( \) `) cannot reset it: brush recurses once per `$(`
/// however its closer is hidden.
///
/// # Why 16
///
/// Smallest aborting count with the cap lifted, `echo ` + `$( ')' ` (or
/// `$( \) `) repeated N times: 151 (debug build, 2MiB worker stack, the
/// tighter of the two budgets this crate ships against) / 1709 (release).
/// 16 is ~9x below the debug floor.
///
/// Per-opener caps alone do not compose: every grammar-level recursion
/// shares one stack and their depths add, which [`MAX_RAW_STACK_BUDGET`]
/// bounds.
///
/// # Known trade-off
///
/// More than 16 command substitutions in one command (a generated script)
/// fail closed to `Ask`.
pub(crate) const MAX_RAW_COMMAND_SUBST_COUNT: usize = 16;

/// Cap on the total count of `<(` and `>(` openers (process substitution,
/// both directions together) in one command, enforced by
/// [`crate::parser::reject_excessive_raw_nesting`] on top of
/// [`MAX_RAW_PAREN_OPEN_COUNT`]. Never decremented, so a quoted or escaped
/// `)` cannot reset it. Process substitution recurses through the program
/// grammar and aborts at the lowest count of the paren openers.
///
/// # Why 8
///
/// Smallest aborting count with the cap lifted, `cat ` + `<( ')' ` (or
/// `tee ` + `>( ')' `) repeated N times: 122 (debug) / 485 (release). 8 is
/// ~15x below the debug floor (the program-grammar `cat <( ')'; ` shape
/// aborts at the same 122 / 485) and ~60x below the release one. A command
/// with more than 8 process substitutions is rare. The composed margin is
/// [`MAX_RAW_STACK_BUDGET`]'s job.
pub(crate) const MAX_RAW_PROCESS_SUBST_COUNT: usize = 8;

/// Cap on the total count of `$[` openers (legacy arithmetic expansion) in
/// one command, enforced by [`crate::parser::reject_excessive_raw_nesting`]
/// on top of [`MAX_RAW_BRACKET_OPENER_COUNT`]. Never decremented, so a quoted
/// or escaped `]` cannot reset it.
///
/// # Why 8
///
/// Smallest aborting count with the cap lifted, `echo ` + `$[` repeated N
/// times (closed or unclosed): 151 (debug) / 1709 (release); 8 is ~19x below
/// the debug floor. A `$[` already resolves to `Ask` (arithmetic expansion
/// cannot be analyzed statically), so the cap adds no false-positive cost.
pub(crate) const MAX_RAW_LEGACY_ARITH_COUNT: usize = 8;

/// Cap on the total count of `[` bytes in one command, enforced by
/// `src/parser.rs`'s raw pre-scan (`reject_excessive_raw_nesting`).
/// brush-parser 0.4.0's array-subscript and legacy `$[ ... ]` arithmetic
/// grammars recurse once per `[` opener (`word.rs`'s
/// `expansion_parser::__parse_array_element_name` /
/// `__parse_arithmetic_word_piece::<__parse_array_index>`), with no depth
/// limit of its own.
///
/// # Why an opener count, not a net `[`/`]` depth
///
/// brush hides a closing `]` inside quotes, backticks, `$(`, `$((`, `${`
/// and `$[`, so a repeated `a["]"` or `a[$(])` keeps any `]`-decrementing
/// depth at 1 while brush recurses once per `a[`. The recursion depth is
/// bounded by the opener count however the closers are hidden, so every
/// `[` counts and `]` never decrements.
///
/// # Why 64
///
/// Smallest aborting N with the cap lifted, `echo ` plus a unit repeated N
/// times, debug build (2 MiB worker stack) / release build: `a[` 1284 /
/// 3749. The deeper-per-opener `$[` shape is bounded by its own, much
/// tighter [`MAX_RAW_LEGACY_ARITH_COUNT`] (151 / 1709), so what this
/// general cap governs is the `a[` array-subscript shape: 64 is ~20x below
/// the debug floor, and also tolerates ordinary commands (`[ -f x ]`,
/// `[[ ... ]]`, globs). Every `[` is counted rather than only `[` after an
/// identifier byte, since the shapes that recurse deepest have no
/// identifier prefix. Re-measure before raising this on any `brush-parser`
/// version bump, for the same reason [`MAX_RAW_BRACE_NESTING_DEPTH`]'s docs
/// give.
///
/// # Known trade-off
///
/// A count cap trips on volume, not nesting: a heredoc body or quoted
/// literal with more than 64 `[` (a README with 65 markdown links, many
/// `[[:alpha:]]` classes) fails closed to `Ask`. That is the safe direction
/// and accepted.
pub(crate) const MAX_RAW_BRACKET_OPENER_COUNT: usize = 64;

/// Cap on the total count of reserved-word compound-command openers (`if`,
/// `while`, `until`, `for`, `case`) `src/parser.rs`'s raw pre-scan tolerates
/// in one command, enforced by [`crate::parser::reject_excessive_raw_nesting`]
/// (issue #52 follow-up: brush-parser's recursive-descent grammar recurses
/// once per nested compound command exactly as unboundedly as it does per
/// nested brace/paren, and none of these five keywords involve a `{`/`(`
/// character the existing [`MAX_BRACE_NESTING_DEPTH`] scan would catch).
///
/// Live-probed thresholds against `brush-parser =0.4.0`, on an 8MiB
/// main-thread stack: `case` aborts first at 401 levels, `for` at 420,
/// `until` at 446, `if` at 448 (`while` confirmed aborting by 2000). But
/// per-level cost here is far higher than brace/paren nesting's ~3KB
/// ([`MAX_BRACE_NESTING_DEPTH`]'s docs) — re-bisected under a 2MiB stack
/// (`ulimit -s 2048`, matching `cargo test`'s per-test thread budget, the
/// same target [`MAX_BRACE_NESTING_DEPTH`] is sized against): `case` aborts
/// there at 99 levels, `if` at 110. This value must clear the 2MiB budget,
/// not just the main-thread one. 10 sits a
/// ~10x margin below the lowest 2MiB threshold found (`case`'s 99, 101 in
/// the grammar-shaped `case x in x) ` probe); this is
/// a *count*, not a *depth*, so 10 is also generous headroom over any
/// realistic legitimate use of these keywords. Re-measure both the 8MiB and
/// 2MiB thresholds before raising this on any `brush-parser` version bump,
/// same as [`MAX_BRACE_NESTING_DEPTH`].
///
/// # Why 10 (CPU time, not stack)
///
/// Nested `case x in x) ` backtracks exponentially, and trailing grammar
/// constructs multiply the cost (`case x in x) `xN, then more groups).
/// Measured `shguard` end to end, release build / debug build: 12 levels
/// 0.011s / 0.077s; 14 levels 0.046s / 0.29s; 16 levels 0.099s / 1.06s,
/// and 16 levels followed by 8 `{ '}'; ` and 8 `( ')'; ` 1.35s / the 2s
/// watchdog trip (via the library API the detached worker keeps burning CPU
/// after the verdict). Filling the rest of [`MAX_RAW_STACK_BUDGET`] after
/// 12 levels costs at most 0.11s / 1.1s, after 10 levels at most
/// 0.034s / 0.30s. 10 keeps the worst composed shape >=6x under the 2s
/// budget in both builds, which 12 does not in debug.
///
/// # Why not 8 (issue #75)
///
/// `for`/`while`/`until` are now modeled as real [`Command::Compound`]
/// variants (issue #75) — a single occurrence of one of them no longer
/// automatically resolves to `Unsupported`/`Ask` regardless of this cap the
/// way it used to when this cap was first sized at 8. That earlier sizing's
/// "no false-positive cost to weigh" premise was already only true for
/// *syntactic* keyword use, though: [`crate::parser::reject_excessive_raw_nesting`]
/// counts raw bytes with no quote awareness, so a command whose *text*
/// happens to contain the words `for`/`if`/`while`/`case`/`until` several
/// times — a `git commit -m "..."` message being the clearest real example —
/// was always able to trip this cap even though nothing is actually nested.
/// Modeling `for`/`while`/`until` doesn't create that false-positive class,
/// but it does raise the stakes of it: a real, legitimate one-liner chaining
/// a couple of loops plus an `if` (still unmodeled, still hard-Asks on its
/// own first use) can now sit closer to this budget than "always Ask
/// anyway" made it matter before. The cap was 16 here for that reason (now 10, see above)
/// under the probed 2MiB-stack abort floor (`case`'s 99) while giving that
/// realistic multi-loop one-liner — and the quoted-text false-count above —
/// more headroom than 8 did.
///
/// `select` was probed too and excluded: brush-parser rejects it with an
/// immediate syntax error rather than recursing on it, so it is not a
/// stack-overflow vector at all. `[[ … ]]` was probed at the same time and
/// excluded then too, but for a shguard-side reason, not a brush-parser
/// one: `src/parser.rs` mapped it straight to `ParseError::Unsupported`
/// without ever recursing into it (brush-parser itself always parsed it
/// fine). That has since changed: `[[ … ]]` is modeled as
/// [`Command::ExtendedTest`] (issue #191) and *is* a real stack-overflow
/// vector of its own, bounded separately by [`MAX_RAW_EXTENDED_TEST_COUNT`]
/// (`crate::parser::reject_excessive_raw_nesting`, issue #401) rather than
/// by this keyword-nesting counter. `function` is also excluded
/// deliberately: its body is a brace group, so its recursion is already
/// bounded by [`MAX_BRACE_NESTING_DEPTH`] and counting the keyword itself
/// would only add false positives with no additional safety.
///
/// # `if` is now modeled too (issue #191)
///
/// `if`/`elif` clauses are [`Command::Compound`] variants as of issue #191,
/// the same way `for`/`while`/`until` became one under issue #75 — a single
/// `if` no longer automatically resolves to `Unsupported`/`Ask` regardless
/// of this cap either. This does not change the cap's own sizing rationale
/// above (still measured against `case`'s 99-level 2MiB-stack abort floor,
/// still a 6x margin): `case` — the tightest keyword — remains entirely
/// unmodeled (zero measured occurrences per issue #75/#191's traffic
/// samples), so it alone still keeps this cap's "no false-positive cost"
/// premise from ever mattering for that specific keyword, and 16 was
/// already sized with `if`/`while`/`until`/`for` all being real, evaluated
/// constructs in mind.
///
/// # Why a total count, not a balanced depth like [`MAX_BRACE_NESTING_DEPTH`]
///
/// A `{`/`}`/`(`/`)` depth counter that decrements on the closing character
/// is NOT safe: a quoted, backslash-escaped, heredoc-body, or `#`-comment
/// closer (e.g. `echo "}"`, `echo \}`, a `}` inside a `<<EOF` body, or one
/// after a `#`) is not a real brace/paren closer to `brush-parser`, but the
/// decrementing counter treats it as one regardless, letting real nesting
/// grow unboundedly while the counter stays pinned at 0-1 (crash-fuzzer,
/// live-confirmed — see [`MAX_RAW_BRACE_OPEN_COUNT`]'s and
/// [`MAX_RAW_PAREN_OPEN_COUNT`]'s docs for the exact aborting repros). Those
/// two non-decrementing counters close that gap; [`MAX_RAW_BRACE_NESTING_DEPTH`]/
/// [`MAX_RAW_PAREN_NESTING_DEPTH`]'s decrementing counters remain useful only
/// for bounding PEG-backtracking cost on well-formed nesting, not as a
/// stack-overflow defense on their own. The same closer-injection problem is
/// not new: keyword closers have always had it. `echo fi` and `echo done`
/// are ordinary, valid arguments (live-confirmed to resolve normally), so a
/// decrementing counter keyed on the words `fi`/`done`/`esac`
/// could be driven back down by injecting those words as arguments inside
/// genuinely-nested input that still recurses past the crash threshold —
/// live-confirmed: `("if true; then echo fi; " x 2000) + "echo done" + ("
/// fi" x 2000)` still aborts even though a naive decrementing counter reads
/// its `fi` count as balanced against its `if` count throughout. Counting
/// only openers, and never decrementing, has no closer for an attacker to
/// inject against: the count can only ever overestimate true nesting depth
/// (safe direction — an inflated count fails closed to `Ask` earlier, never
/// later). Without a `\`+newline-split keyword (`i\<newline>f`) being
/// rejoined before counting, it would go unrecognized as `if` and
/// undercount, while brush-parser's own tokenizer rejoined and recursed on
/// it regardless — so the raw text is counted twice (issue #443), once
/// through `crate::parser::strip_raw_line_continuations` and once through
/// `crate::parser::strip_raw_line_continuations_blind`, rejecting if either
/// scan's count exceeds this cap: each rejoins the continuations the other
/// can miss (see the two functions' docs). Both stripped copies are
/// scan-only inputs to this counter — brush-parser itself always parses the
/// untouched original text — see `strip_raw_line_continuations`'s docs on
/// why.
pub(crate) const MAX_KEYWORD_NESTING_COUNT: usize = 10;

/// Cap on the total count of `!`/`&&`/`||` operators `src/parser.rs`'s raw
/// pre-scan tolerates inside one `[[ ... ]]` extended-test region, enforced
/// by [`crate::parser::reject_excessive_raw_nesting`] (issue #401: none of
/// `{`/`}`/`(`/`)`/[`NESTING_KEYWORDS`](crate::parser) appear in a long
/// `[[ ! ! ! ... a ]]`/`[[ a && a && ... ]]` chain, so it sailed through this
/// scan untouched and reached brush-parser's recursive-descent grammar (or,
/// for the `&&` shape, the recursive `Drop` of the already-parsed tree)
/// uncapped — an uncatchable stack-overflow abort with empty stdout, a fail-
/// open bypass of the whole hook (see the module docs on
/// [`crate::parser::reject_excessive_raw_nesting`]).
///
/// Smallest aborting count with the cap lifted, debug build (2 MiB worker
/// stack) / release build: a `!` chain (`[[ ! ! ! ... x ]]`) 209 / 2052
/// (parse time); an `&&` chain 18770 / 65821 (drop time, parsing itself
/// succeeds). 64 is ~3.3x below the tighter debug `!` threshold and ~32x
/// below the release one. It composes with the other grammar-level
/// recursions through [`MAX_RAW_STACK_BUDGET`].
///
/// # Why the count is never reset
///
/// The count covers the whole command, not one `[[ ... ]]` region: it is
/// never reset by a `[[` token and tracking is never turned off by a `]]`
/// token. The scan is quote-blind, so a quoted `' [[ '` inside a real,
/// still-open region is indistinguishable from a genuinely new block, and
/// resetting on it would let quoting drive the count back down while brush
/// still builds one boolean-expression tree (and symmetrically for a quoted
/// `]]` turning tracking off). Never-reset is the only rule that holds
/// without quote awareness.
///
/// # Known trade-off
///
/// Independent `[[ ]]` blocks chained at the top level parse and drop
/// separately, so summing their operators bounds nothing real there; the
/// sum is accepted anyway. A command with more than 64 `!`/`&&`/`||`
/// occurrences after its first `[[` (including ones outside any
/// `[[ ]]`) fails closed to `Ask`.
pub(crate) const MAX_RAW_EXTENDED_TEST_COUNT: usize = 64;

/// Combined, never-decremented budget over every raw opener whose
/// recursion shares brush-parser's one parse stack, enforced by
/// [`crate::parser::reject_excessive_raw_nesting`] in addition to the
/// per-opener caps. Each opener adds its `STACK_COST_*` weight; the command
/// is rejected once the running total exceeds this budget.
///
/// # Why a combined budget
///
/// Per-opener caps bound each recursion alone, but a bare subshell
/// (`( ')'; `), a bare brace group (`{ '}'; `), `if`/`case`, process
/// substitution and a `[[ ! ! ... ]]` chain all recurse through the same
/// grammar, so their depths add: every cap filled at once (`{ '}'; `x32,
/// `( ')'; `x24, `cat <( ')'; `x8, `if true; then `x16, `[[ ` + `! `x64)
/// aborts a debug build.
///
/// # Weights and budget
///
/// A weight is the opener's share of the debug worker stack in permille,
/// rounded up, from the smallest aborting count with the caps lifted
/// (debug build, 2MiB stack / release build): bare `{` group 115 / 403 ->
/// 9; bare `(` subshell 115 / 403 -> 9 (`$(` 151 and `<(` 122 are covered
/// by it); `if` 113 / 412 -> 10, `case` 101 / 411 -> 10; `[[ !` 208 / 2051
/// -> 5; `[` (`a[`) 1284 -> 1. `${` (72 closed form) and `$[` (151) recurse
/// deeper than the `{`/`[` they contain, so they add an extra 5 and 6.
/// Measured on the grammar shapes, the costs are additive: filling the old
/// per-opener caps at once summed to 1.00 of the debug stack and aborted
/// at exactly 1x, and the same payload in a release build aborts at 4.5x.
/// A budget of 333 permille therefore targets 3x on the debug 2MiB thread.
/// Measured with every cap lifted, scaling budget-filling payloads (`{ '}'; `
/// x37, `( ')'; ` x37, `case x in x) ` x33, `[[ ! `x66, and a mix of
/// `{ '}'; `x10 + `( ')'; `x8 + `cat <( ')'; `x4 + `if true; then `x8 +
/// `[[ ! `x10) up: the debug build aborts at 3.25x the budget for every one
/// of them, the release build at 11x or more (`[[ !`: no abort up to 16x).
/// The per-opener caps alone left the reviewed composed payload at 1.0x
/// (a debug abort).
///
/// # Known trade-off
///
/// The budget is a total over the whole command, quoted text included, so
/// e.g. about 37 `(` bytes, or a mix summing past 333, fail closed to `Ask`
/// even when nothing is nested. Re-measure the weights (including the
/// composed payload, not just each shape) on any `brush-parser` bump.
///
/// # Time, not just stack
///
/// Staying inside the budget does not bound CPU time by itself: nested
/// `case` backtracks exponentially and trailing constructs multiply it, so
/// [`MAX_KEYWORD_NESTING_COUNT`] is 10 (see its docs for the curves); the
/// worst budget-filling shape after 10 `case` levels measured 0.034s
/// release / 0.30s debug against the 2s watchdog.
pub(crate) const MAX_RAW_STACK_BUDGET: usize = 333;

/// Stack-cost weights for [`MAX_RAW_STACK_BUDGET`], one per raw opener.
pub(crate) const STACK_COST_BRACE: usize = 9;
/// Extra weight a `${` adds on top of [`STACK_COST_BRACE`].
pub(crate) const STACK_COST_PARAM_EXPANSION_EXTRA: usize = 5;
/// Weight of a raw `(` (subshell, `$(`, `<(`).
pub(crate) const STACK_COST_PAREN: usize = 9;
/// Weight of a raw `[`.
pub(crate) const STACK_COST_BRACKET: usize = 1;
/// Extra weight a `$[` adds on top of [`STACK_COST_BRACKET`].
pub(crate) const STACK_COST_LEGACY_ARITH_EXTRA: usize = 6;
/// Weight of a nesting keyword (`if`, `while`, `until`, `for`, `case`).
pub(crate) const STACK_COST_KEYWORD: usize = 10;
/// Weight of a `!`/`&&`/`||` counted inside an extended test.
pub(crate) const STACK_COST_EXTENDED_TEST_OP: usize = 5;

/// A separator joining two [`Pipeline`]s in a [`CommandLine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Separator {
    /// `;`
    Sequence,
    /// `&&`
    And,
    /// `||`
    Or,
    /// `&` (issue #191): backgrounds the whole `&&`/`||` chain to its left
    /// (per bash grammar, `&` terminates an `and_or` list, not just the one
    /// pipeline immediately before it), but that chain still runs —
    /// `crate::gate::evaluate_command_line` folds the resulting DANGER
    /// verdict identically to every other separator (worst-wins across the
    /// whole line, regardless of `;`/`&&`/`||`). Its working-directory
    /// effect is a different story (issue #383): a backgrounded chain runs
    /// in its own subshell in real bash, so a `cd`/`pushd`/`popd` anywhere
    /// inside it never persists past the `&` — `evaluate_command_line`
    /// evaluates every pipeline in the chain this separator terminates
    /// against one shared isolated `cwd` clone, specifically because of
    /// this variant, not the plain worst-wins fold every other separator
    /// gets.
    Async,
}

/// A full command line: one pipeline, optionally followed by more pipelines
/// joined by separators.
///
/// Modelled as `first` + `rest` (a non-empty list), not two parallel `Vec`s,
/// so "zero pipelines" and "one fewer separator than pipeline" are not
/// representable — the plain-`Vec` encoding would allow both.
///
/// `trailing_async` (issue #383): whether the `&&`/`||` chain ending at the
/// LAST pipeline on this line (`rest.last()`, or `first` when `rest` is
/// empty) is terminated by a bare `&` with nothing after it — real bash
/// backgrounds that whole chain into its own subshell, so
/// `crate::gate::evaluate_command_line` must not let any `cd`/`pushd`/`popd`
/// effect from within it reach whatever runs after this `CommandLine`, the
/// same isolation every other backgrounded chain gets when observed via
/// `Separator::Async`. A `CommandLine` that is itself a `BraceGroup`'s body
/// (`{ pushd /tmp & }`) is the case that actually matters in practice: the
/// group runs in the CURRENT shell (unlike a `Subshell`), so its body's own
/// trailing `&` is the only place this distinction is otherwise invisible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandLine {
    pub(crate) first: Pipeline,
    pub(crate) rest: Vec<(Separator, Pipeline)>,
    pub(crate) trailing_async: bool,
}

/// A pipeline: one or more [`Command`]s connected by `|`.
///
/// Modelled as `first` + `rest` for the same non-empty-list reason as
/// [`CommandLine`]: a pipeline can never have zero commands.
///
/// `bang` (issue #353): whether this pipeline was written with a leading
/// `!` (negates the pipeline's own exit status, changing no argv and no
/// executed command — every OTHER consumer of this AST still ignores it
/// for exactly that reason). `crate::gate::evaluate_command_line`'s
/// pushd-stack collapse is the one place `bang` does matter: `! pushd X`
/// reports SUCCESS to `&&` even when the real `pushd` failed, so a
/// negated pipeline must be treated the same as a non-`&&` separator for
/// deciding whether the FOLLOWING pipeline runs in a reachable
/// failure-world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pipeline {
    pub(crate) first: Command,
    pub(crate) rest: Vec<Command>,
    pub(crate) bang: bool,
}

/// One command in a [`Pipeline`]: an ordinary simple command, a compound
/// command (issue #75: `for`/`while`/`until`/subshell/brace group;
/// issue #191 added `if`), a function definition (issue #75), or an
/// extended test command (issue #191: `[[ ... ]]`).
///
/// A sum type rather than folding compound commands and function
/// definitions into `SimpleCommand` itself: the four have almost nothing in
/// common structurally (a compound command has a nested [`CommandLine`]
/// body instead of `words`; a function definition has a name and a body but
/// no argv at all; an extended test has test operands that are not argv at
/// all — see [`ExtendedTest`]'s own docs), so a single struct with optional
/// fields for all four shapes would make invalid combinations (a
/// `SimpleCommand` with a `body`, a `ForClause` with `words: Vec<Word>` in
/// the argv sense) representable when they should not be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Simple(SimpleCommand),
    Compound(CompoundCommand),
    FunctionDefinition(FunctionDefinition),
    ExtendedTest(ExtendedTest),
}

/// `[[ ... ]]` (issue #191): an extended test expression. shguard does not
/// model the expression's own boolean structure (`&&`/`||`/`!`/parens
/// inside the brackets, or which unary/binary predicate each operand pairs
/// with) — none of that changes what actually executes. It only keeps every
/// operand as a [`Word`] for `crate::gate`'s expansion-position scan
/// (`scan_word_expansions`), exactly the treatment a `for` clause's `in`
/// word list or an array assignment's elements already get (issue #75).
///
/// This is a deliberate choice, not an approximation of a fuller model:
/// `[[ ]]`'s operands are never command words — bash performs no
/// word-splitting or globbing on them (unlike a `SimpleCommand`'s `words`)
/// — so treating them as an argv the way `SimpleCommand` does would be a
/// false-positive risk with no safety benefit (`[[ -d /tmp/x ]]` is not the
/// command `-d /tmp/x`, and matching it against blocklist rules that expect
/// a real command name in position 0 would be nonsensical). But an operand
/// CAN still hide a command substitution (`[[ -n $(rm -rf /) ]]`), which is
/// exactly what the expansion scan catches; treating the whole construct as
/// opaque (skip it entirely, the pre-#191 behavior) would silently miss
/// that. brush-parser already hands operands over as structural [`Word`]s
/// (`bast::ExtendedTestExpr::UnaryTest`/`BinaryTest`), not raw strings, so
/// nothing is lost by extracting them this way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtendedTest {
    pub(crate) words: Vec<Word>,
    pub(crate) redirections: Vec<Redirection>,
}

/// A compound command (issue #75): `for`/`while`/`until`, a subshell, or a
/// brace group, each carrying its own nested [`CommandLine`] body (and, for
/// `while`/`until`, a condition `CommandLine` evaluated before each
/// iteration) plus any redirections attached to the compound command as a
/// whole (`for i in 1; do echo x; done > /dev/null` attaches the redirect to
/// the loop, not to `echo`).
///
/// `BraceGroup` and `Subshell` get identical treatment everywhere shguard's
/// gate evaluates them, with one exception (issue #103): a `BraceGroup`'s
/// folded-cwd context (`crate::gate::CwdContext`) is threaded through by
/// mutable reference, so a `cd` inside one persists into the enclosing
/// scope, while a `Subshell`'s is a throwaway clone whose mutations never
/// escape — this is the one place the difference between "runs in a
/// subshell" and "runs in the current shell" IS meaningful, since a real
/// `cd`'s effect on the working directory is exactly that distinction.
/// Otherwise the difference isn't meaningful to a static, non-executing
/// analyzer that already gives every recursed body its own fresh
/// environment (see `crate::gate`'s module docs). `BraceGroup` exists as its
/// own variant (rather than being folded into `Subshell`) only because
/// [`FunctionDefinition`]'s body is a brace group in virtually every real
/// function, and keeping the two syntactically distinct mirrors
/// brush-parser's own `CompoundCommand` shape.
///
/// Deliberately excludes `case` clauses, C-style arithmetic `for`, bare
/// `((...))` arithmetic commands, and coprocesses — none of these were
/// measured in issue #75's or #191's traffic samples, so they stay exactly
/// as unsupported (translate-error, `Ask`) as before this change. `if`
/// clauses (with `elif`/`else`) were added by issue #191, following the
/// same "measured in real traffic" bar #75 set.
///
/// `body`/`condition` are `Box<CommandLine>`, not a bare `CommandLine`:
/// `CommandLine` -> `Pipeline` -> `Command` -> `CompoundCommand` ->
/// `CommandLine` is a recursive type with no fixed size without some
/// indirection breaking the cycle, and this is the one point in it that
/// needs boxing (`Command::Compound`/`Pipeline::first` stay unboxed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompoundCommand {
    BraceGroup {
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    Subshell {
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    ForClause {
        variable: String,
        /// The `in ...` word list. `None` when the `for` clause omits the
        /// `in` entirely (bash then iterates `"$@"`) — kept distinct from
        /// `Some(vec![])` (an explicit, empty `in` list, which iterates zero
        /// times) rather than collapsing both to one representation.
        words: Option<Vec<Word>>,
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    WhileClause {
        condition: Box<CommandLine>,
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    UntilClause {
        condition: Box<CommandLine>,
        body: Box<CommandLine>,
        redirections: Vec<Redirection>,
    },
    /// `if COND; then BODY [elif COND; then BODY]... [else BODY] fi` (issue
    /// #191). `elifs`/`else_body` split brush-parser's own
    /// `Option<Vec<ElseClause>>` shape (each entry either an `elif` with a
    /// condition or a trailing plain `else` with none — see
    /// `src/parser.rs::convert_if_clause`'s docs) into the two forms
    /// shguard's own grammar actually has: zero or more conditional `elif`
    /// arms, followed by at most one unconditional `else`.
    ///
    /// shguard cannot know statically which branch runs, so
    /// `crate::gate::evaluate_compound_command` evaluates `condition`,
    /// `then_body`, every `elifs` condition/body, and `else_body` (when
    /// present) and folds all of them worst-wins — the same
    /// evaluate-every-branch stance already used for `WhileClause`/
    /// `UntilClause`'s condition-plus-body pair.
    IfClause {
        condition: Box<CommandLine>,
        then_body: Box<CommandLine>,
        elifs: Vec<ElifClause>,
        else_body: Option<Box<CommandLine>>,
        redirections: Vec<Redirection>,
    },
}

/// One `elif COND; then BODY` arm of an [`CompoundCommand::IfClause`] (issue
/// #191).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ElifClause {
    pub(crate) condition: Box<CommandLine>,
    pub(crate) body: Box<CommandLine>,
}

/// A function definition (issue #75): `name() { ...; }` (or the `function`
/// keyword form). shguard evaluates the body eagerly at the definition site
/// and folds its verdict worst-wins into the definition's own — it does
/// **not** track the function name and inline it at call sites. Ignoring
/// the body entirely (parse the definition, evaluate nothing) would turn
/// `f() { rm -rf /; }; f` from an `Unsupported`/`Ask` line into a clean
/// `Allow` (an unknown, no-rule-match command defaults to `Allow` —
/// `crate::gate::fold_floors`), which is a deny-rule bypass, not a
/// documented gap. Eager body evaluation closes that without needing any
/// name-tracking or call-site resolution; the residual gap (a body that
/// only becomes dangerous once called with a specific argument, e.g.
/// `f() { rm -rf "$1"; }; f /`) already fails closed to `Ask` today via the
/// ordinary unresolved-argument floor, not `Allow`.
///
/// Has no `redirections` field of its own: `bast::FunctionBody`'s optional
/// redirect list (`f() { ...; } > log`) is exactly the same shape as
/// `bast::Command::Compound`'s own attached-redirect list, so
/// `src/parser.rs` folds it straight into `body`'s own `CompoundCommand`
/// variant (its `redirections` field) rather than duplicating it here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FunctionDefinition {
    pub(crate) name: Word,
    pub(crate) body: Box<CompoundCommand>,
}

/// A single simple command: leading assignments, words (the command name and
/// its arguments), and redirections. Unlike `CommandLine`/`Pipeline`, all
/// three lists may legitimately be empty on their own (e.g. `> file` is a
/// valid simple command with zero words and zero assignments), so this stays
/// a plain struct of `Vec`s rather than a non-empty-list encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SimpleCommand {
    pub(crate) assignments: Vec<Assignment>,
    pub(crate) words: Vec<Word>,
    pub(crate) redirections: Vec<Redirection>,
}

/// A `NAME=value` assignment preceding (or standing in place of) a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Assignment {
    pub(crate) name: String,
    pub(crate) value: AssignmentValue,
    /// `NAME+=value` (append to the name's current value) rather than plain
    /// `NAME=value` (replace it) — issue #139: dropping this bit made
    /// `IFS+=,` indistinguishable from `IFS=,`, silently discarding the
    /// preexisting `IFS` value the append form actually preserves.
    pub(crate) append: bool,
}

/// The right-hand side of an [`Assignment`]: an ordinary scalar value, or
/// (issue #75) an array literal (`arr=(a b c)`). Kept as its own sum type
/// rather than always a `Vec<Word>` (a scalar is not "an array of one
/// element" — `NAME=` and `NAME=()` are observably different assignments in
/// bash) so the two remain distinguishable through normalisation and the
/// gate's expansion-position scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AssignmentValue {
    Scalar(Word),
    Array(Vec<Word>),
}

/// A redirection attached to a simple command (`>`, `<`, `>>`, a heredoc, …).
///
/// A sum type rather than one struct with optional fields: a file
/// redirection has a target word and no body; a heredoc has a body and no
/// filename target. Optional fields on a single struct would make all four
/// combinations representable when only two are ever valid — the ADR's
/// heredoc fixtures (docs/adr/0001-parser-crate.md rows 7-9) specifically
/// need the body to survive into the AST, so `Redirection` must not be able
/// to hold a `HereDoc` variant with no body, the way an `Option<String>`
/// field would allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Redirection {
    /// `<`, `>`, or `>>` with a target word (a filename, itself subject to
    /// the same word-piece expansions as any other word).
    File {
        kind: FileRedirectionKind,
        target: Word,
    },
    /// `<<` (or `<<-` when `strip_leading_tabs` is set).
    ///
    /// The delimiter itself (`EOF` in `<<EOF`) has no analytical value once
    /// parsing is done — it only serves to find the terminating line — so
    /// it is dropped rather than carried in this type; only what it implies
    /// (`expand_body`) is kept.
    HereDoc {
        strip_leading_tabs: bool,
        /// `false` when the delimiter was quoted (`<<'EOF'`): bash performs
        /// no parameter/command-substitution expansion on the body in that
        /// case, so ADR row 9's `$(rm -rf /)` inside a quoted-delimiter
        /// heredoc must stay inert literal text rather than being
        /// interpreted as a substitution. `true` for an unquoted delimiter
        /// (`<<EOF`), where the body is subject to expansion.
        expand_body: bool,
        /// The heredoc body, raw and un-decoded.
        ///
        /// `String`, not `Word`: when `expand_body` is `false` the body is
        /// definitionally literal text (bash performs no expansion on it
        /// at all), so `Word`'s piece structure would model nothing that
        /// isn't already a single `Literal`. When `expand_body` is `true`
        /// the body is still multi-line raw text that gets parsed and
        /// word-split per line in the normalise stage, not as one `Word`
        /// value — the parser adapter (a later issue) re-examines this raw
        /// string then, rather than this type pre-committing to a `Word`
        /// shape that doesn't fit a multi-line body.
        body: String,
    },
}

/// The kind of a plain file redirection, per the ADR's redirection fixture
/// (row 18: `echo x > /dev/null`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileRedirectionKind {
    /// `<`. Ordinarily a no-op for the dangerous-target check — reading an
    /// ordinary file is harmless. Issue #455's exception:
    /// `crate::gate::is_redirect_write_applicable` still treats `target`
    /// as connection-applicable when it's a network pseudo-device (see
    /// `crate::gate::is_network_pseudo_device`'s docs for why).
    Input,
    /// `>`
    Output,
    /// `>>`
    Append,
    /// `<&` (issue #75). `target` is still a plain [`Word`] — brush-parser
    /// does not structurally distinguish a numeric fd/`-` target from a
    /// filename one here (`bast::IoFileRedirectTarget::Duplicate`'s own docs:
    /// "could be a filename, a file descriptor, or a file descriptor and a
    /// '-'"), so that distinction is made in `crate::gate` once the target
    /// has been resolved, not here.
    DuplicateInput,
    /// `>&` (issue #75). See [`FileRedirectionKind::DuplicateInput`]'s docs —
    /// same target ambiguity applies (`2>&1` vs. `>&/dev/sda`, which is a
    /// genuine file write bash treats identically to `> /dev/sda`).
    DuplicateOutput,
    /// `<>` (issue #425). Opens `target` for both reading and writing —
    /// bash's own documented mechanism for `exec 3<>/dev/tcp/host/port`
    /// reverse-shell/data-exfil primitives, since opening `/dev/tcp/...`
    /// at all is what establishes the TCP connection, independent of
    /// which direction ends up used. `crate::gate` treats it as a genuine
    /// write for the same dangerous-target check `>`/`>>` already get
    /// (`is_redirect_write_applicable`), rather than as the no-op `<`'s
    /// read-only `Input` is for a non-network target (issue #455, see
    /// `Input`'s own docs).
    ReadAndWrite,
}

/// A shell word: a sequence of [`WordPiece`]s. Kept as a sequence rather than
/// a single string so quote/expansion boundaries survive into the normalise
/// stage — the whole point of the parser-crate selection (ADR 0001):
/// `r''m` must stay `[Literal("r"), SingleQuoted(""), Literal("m")]`, never
/// pre-joined into `"rm"` before shguard's own fold decides that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Word(pub(crate) Vec<WordPiece>);

/// One piece of a [`Word`], mirroring the granularity the selected parser
/// crate exposes (docs/adr/0001-parser-crate.md's evidence excerpts) —
/// expressed as shguard's own type, not that crate's `WordPiece`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WordPiece {
    /// Unquoted literal text.
    Literal(String),
    /// Single-quoted text, quotes already stripped, contents un-decoded.
    SingleQuoted(String),
    /// ANSI-C-quoted text (`$'...'`), raw un-decoded contents — hex/octal/
    /// control-escape decoding happens in the normalise stage.
    AnsiCQuoted(String),
    /// A double-quoted sequence: the pieces that appear between `"` `"`,
    /// e.g. literal text mixed with parameter expansions.
    DoubleQuoted(Vec<WordPiece>),
    /// `$NAME` / `${NAME}` — the parameter name only.
    ParameterExpansion(String),
    /// `$(...)` — the raw, unparsed inner command string.
    CommandSubstitution(String),
    /// `` `...` `` — the raw, unparsed inner command string.
    BackquotedSubstitution(String),
    /// `~` or `~user`, the raw text after `~` (empty for the current user).
    Tilde(String),
    /// `{a,b,c}` — each alternative as its own [`Word`].
    BraceAlternation(Vec<Word>),
    /// A backslash-escaped character, e.g. `\ ` inside an otherwise
    /// unquoted word.
    EscapeSequence(char),
    /// `$((...))` (issue #75) — the raw, unparsed inner arithmetic text
    /// (`bword::ParameterExpr`'s `UnexpandedArithmeticExpr.value`). Raw, not
    /// a `Word`, for the same reason as [`WordPiece::CommandSubstitution`]:
    /// bash performs command substitution *inside* an arithmetic expression
    /// before evaluating it (`$(( $(rm -rf /) ))` really does run the `rm`),
    /// so `crate::gate` must re-scan this raw text for embedded `$(...)`/
    /// backtick substitutions the same way it already does for heredoc
    /// bodies, rather than treating the whole expression as inert.
    ArithmeticExpansion(String),
    /// `<(...)`/`>(...)` (issue #75) — process substitution. Unlike
    /// [`WordPiece::CommandSubstitution`], the inner command is **not** raw
    /// text: brush-parser already parses it into a structural command list
    /// (`bast::SubshellCommand`), so `body` is shguard's own already-parsed
    /// [`CommandLine`], not a string to re-parse. `Box`ed because
    /// `WordPiece` -> `CommandLine` -> ... -> `Word` -> `WordPiece` is
    /// otherwise a recursive type with no fixed size. Occupies exactly one
    /// [`Word`] position (bash expands `<(cmd)` to a single pathname-like
    /// token), so — like [`WordPiece::CommandSubstitution`] — it never needs
    /// a dedicated `SimpleCommand` field of its own: a bare process
    /// substitution argument becomes a single-piece `Word`, and one used as
    /// a redirect target becomes an ordinary [`Redirection::File`] target.
    ProcessSubstitution {
        direction: ProcessSubstitutionDirection,
        body: Box<CommandLine>,
    },
}

/// Whether a [`WordPiece::ProcessSubstitution`] reads from (`<(...)`) or
/// writes to (`>(...)`) the substituted command. Kept for fidelity/debug
/// output and future rule authoring even though it is not currently
/// security-relevant to shguard's own analysis (both directions recurse
/// through the same worst-wins evaluation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessSubstitutionDirection {
    /// `<(...)`
    Read,
    /// `>(...)`
    Write,
}
