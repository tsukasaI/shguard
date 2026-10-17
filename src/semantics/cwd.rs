//! The cwd domain: the folded working directory, its `pushd`/`popd` stack
//! and the flags that qualify how far a `resolve_symlinks` exception may
//! trust them. The `cd`-effect functions that drive it stay in `gate.rs`.

use crate::rules::SymlinkScope;

/// The folded working-directory context for the command line currently
/// being analyzed (issue #103) — a `cd`/`pushd`/etc. *within one command
/// line* is statically resolvable the same way tilde/brace expansion
/// already are, so `cd X && cmd rel/path` is made to resolve to the same
/// decision `cmd X/rel` would, without shguard gaining any notion of a real
/// runtime cwd or any state that survives past one `analyze()` call
/// (plan.md's cross-invocation scope boundary is unchanged — see the
/// README's Limitations section).
///
/// - `Initial`: no `cd`-family command has been seen yet on this line. The
///   ordinary, pre-#103 axiom holds unconditionally: a bare relative token
///   (`rm config.toml` with no `cd` anywhere) is never itself dangerous, so
///   nothing here composes or floors anything. **Never conflate this with
///   `Poisoned`** — they read the same to a naive "do we know the cwd?"
///   question, but only `Poisoned` means the cwd became attacker-steerable
///   within the analyzed string itself; `Initial` means it never came up.
///   A hook payload carrying an absolute `cwd` (issue #549) seeds the top
///   level as `Known(cwd)` instead, so `Initial` there means "no usable
///   payload `cwd`".
/// - `Known(anchor)`: some earlier `cd`/`pushd` target on this line, or
///   the hook payload's absolute `cwd` (issue #549), resolved to a
///   lexically-certain string — `anchor.path` is that string, already
///   normalized and either absolute (the hook payload's `cwd`) or
///   `~`-anchored (`"/tmp"`, `"~/.config/shguard"`, `"build"`,
///   `"../x"`; see [`render_cwd_anchor`](crate::rules::render_cwd_anchor)). Composing a later `Rel`-shaped
///   token against it (`anchor + "/" + token`, then ordinary rule matching
///   re-normalizes the join from scratch) is lexical CERTAINTY, the same
///   class as tilde expansion — so a composed match inherits the matched
///   rule's own full decision, uncapped (`crate::gate::evaluate_composed_cwd`).
/// - `Poisoned`: a `cd`-family command ran whose destination is statically
///   unknowable (`cd $(sub)`, `cd -`, `source file`, an unresolvable
///   `argv[0]` that could itself be `cd`, …) — see `apply_cwd_effect`/
///   `cd_directive`'s docs for the full catalogue. This is genuine
///   uncertainty, not certainty: a later relative token only ever floors to
///   `Ask` (`scan_unknown_cwd_floor`), never inherits a matched rule's own
///   stricter decision.
///
/// # Recursion (substitutions, `bash -c`, subshells, loops, functions)
///
/// Every recursion boundary in `gate.rs` seeds its own independent
/// [`CwdContext`] from a CLONE of whatever was live at the recursion site —
/// see `analyze_at_depth`'s own docs for why this is never
/// [`CwdContext::Initial`] except at the two true top-level entry points.
/// Whether that clone's own mutations are later allowed to write back
/// (`evaluate_command_line`'s pipelines, a `BraceGroup`'s body) or are
/// strictly discarded (a `$(...)`/backtick payload, a `Subshell`'s body, a
/// loop's body/condition, a function definition's body, a non-single-stage
/// pipeline's stages) is a per-construct decision documented at each call
/// site — see `evaluate_pipeline`/`evaluate_compound_command`'s own
/// docs for the full shell-semantics table this issue's design specified.
///
/// Additive-only, worst-wins by construction: every consumer of this type
/// either composes a rewritten path and folds the result via ordinary
/// [`fold_worst`](crate::policy::combine::fold_worst) (never lowering a decision the uncomposed evaluation
/// already reached), or floors to `Ask` on top of whatever a matching
/// deny/ask rule already produced. A bug in this tracking logic can only
/// ever push a decision toward over-asking, never toward a silent bypass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CwdContext {
    Initial,
    Known(CwdAnchor),
    Poisoned,
}

impl CwdContext {
    /// The least upper bound of two contexts reaching the same program point:
    /// equal contexts stay, every other pair (`Initial` with `Known`, two
    /// different anchors, anything with `Poisoned`) becomes `Poisoned`.
    ///
    /// The lattice is flat with no bottom: `Initial` is not an identity
    /// (`Initial ⊔ Known = Poisoned`). Anchors that differ only in `origin`
    /// or `physical` are unequal and so also join to `Poisoned`, which is
    /// sound but over-conservative.
    pub(crate) fn join(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            Self::Poisoned
        }
    }

    /// `Known` for an anchor a `cd`/`pushd` on the analyzed line produced.
    pub(crate) fn on_line(path: String) -> Self {
        Self::Known(CwdAnchor {
            path,
            origin: AnchorOrigin::Line,
            physical: false,
        })
    }

    /// The [`SymlinkScope`] a `resolve_symlinks` rule (issues #583, #612)
    /// resolves this command's relative candidates in. The base is only a
    /// `Known` anchor that is absolute and whose lexical spelling still names
    /// the real cwd: a `~`-anchored, relative or physical-mode anchor,
    /// `Initial` and `Poisoned` all yield no base, and so do commands whose
    /// wrapper moved the real cwd (`sudo -D`) — those relative candidates
    /// fail closed. `refuse` drops every exception (see
    /// [`CwdState::earlier_writer`]).
    pub(crate) fn symlink_scope<'a>(
        &'a self,
        wrapper_moves_cwd: bool,
        refuse: bool,
    ) -> SymlinkScope<'a> {
        let scope = SymlinkScope::new(self.trusted_base(wrapper_moves_cwd));
        if refuse { scope.refusing_all() } else { scope }
    }

    /// [`Self::trusted_base`] for the filesystem twin probe, which resolves
    /// through `realpath` and so follows physical semantics itself: a
    /// physical-mode anchor is as usable there as a logical one.
    pub(crate) fn fs_probe_base(&self, wrapper_moves_cwd: bool) -> Option<&str> {
        match self {
            Self::Known(anchor) if anchor.path.starts_with('/') && !wrapper_moves_cwd => {
                Some(anchor.path.as_str())
            }
            _ => None,
        }
    }

    /// The absolute directory relative paths of a command run now resolve
    /// against, when this module's lexical cwd can be trusted to name it.
    pub(crate) fn trusted_base(&self, wrapper_moves_cwd: bool) -> Option<&str> {
        match self {
            Self::Known(anchor)
                if anchor.path.starts_with('/') && !anchor.physical && !wrapper_moves_cwd =>
            {
                Some(anchor.path.as_str())
            }
            _ => None,
        }
    }
}

/// A [`CwdContext::Known`] directory and where it came from. The origin
/// only shapes reason strings (issue #622): a composed match under the
/// payload `cwd` must not be blamed on a `cd` the command line never ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CwdAnchor {
    pub(crate) path: String,
    pub(crate) origin: AnchorOrigin,
    /// Set after a physical `cd -P` or under `set -P`: `path` is then the
    /// lexical spelling, which can name a different directory than the real
    /// cwd once a symlinked component is followed by `..`.
    pub(crate) physical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnchorOrigin {
    /// The hook payload's absolute `cwd`, untouched by the analyzed line.
    Payload,
    /// A `cd`/`pushd` on the analyzed line (possibly relative to the
    /// payload `cwd`): the visible cause once one has run.
    Line,
}

impl CwdAnchor {
    /// What composed a relative target against this anchor, for a reason.
    pub(crate) fn describe(&self) -> String {
        match self.origin {
            AnchorOrigin::Payload => format!("the hook payload cwd {:?}", self.path),
            AnchorOrigin::Line => format!("a same-line folded `cd` to {:?}", self.path),
        }
    }

    /// The [`SymlinkScope`] for the composed pass, whose relative tokens were
    /// already joined onto this anchor: no `resolve_symlinks` exception
    /// applies when the anchor's lexical spelling cannot be trusted to name
    /// the real cwd (see [`CwdAnchor::physical`]) or a wrapper moved it.
    pub(crate) fn composed_symlink_scope<'a>(
        &'a self,
        wrapper_moves_cwd: bool,
        refuse: bool,
    ) -> SymlinkScope<'a> {
        let scope = SymlinkScope::new(Some(self.path.as_str()));
        if self.physical || wrapper_moves_cwd || refuse {
            scope.refusing_all()
        } else {
            scope
        }
    }
}

/// Cap on how many frames issue #210's directory-stack tracking
/// ([`CwdState::stack`]) may hold before `gate.rs` gives up modeling it
/// precisely and poisons instead — the same fail-closed-on-overflow stance
/// `MAX_SUBSTITUTION_DEPTH` takes, guarding against an adversarial
/// `pushd d && pushd d && ...` chain growing the tracked stack unboundedly
/// within one command line.
pub(crate) const MAX_CWD_STACK_DEPTH: usize = 64;

/// Issue #210: [`CwdContext`]'s current-directory tracking, paired with a
/// linear stack of earlier frames pushed by `pushd`/popped by `popd` —
/// modeling bash's own directory stack precisely enough to resolve
/// `pushd ~/.config/shguard && pushd /tmp && popd && rm config.toml` back to
/// the real, dangerous `~/.config/shguard` anchor instead of flooring
/// straight to `Ask` the way collapsing every stack operation to
/// [`CwdContext::Poisoned`] (this mechanism's pre-#210 behavior, and still
/// its fallback for any shape it doesn't model — see `apply_pushd`/
/// `apply_popd`'s own docs) would.
///
/// The ACTUAL stack contents are never threaded across a recursion
/// boundary — every recursion starts its own local [`CwdState`], seeded
/// via [`CwdState::seed`] or [`CwdState::seed_unknown_stack`] depending on
/// what kind of boundary it is (a substitution recursion's own cwd
/// mutations are independently read-or-discarded per [`CwdContext`]'s
/// "Recursion" section above and never write back to the caller's stack
/// either way, regardless of which seed is used). The two seeds differ in
/// whether the STACK ITSELF is honestly modeled as possibly non-empty:
/// - [`CwdState::seed`] (empty stack): correct only for a boundary that
///   spawns a genuinely fresh interpreter process with its own empty
///   `DIRSTACK` — `bash -c`/`sh -c`/`zsh -c`/`dash -c`/`fish -c`/
///   `flock -c`/`su -c`/`env -S`, and the top-level entry points when the
///   hook payload carries no usable `cwd`.
/// - [`CwdState::seed_unknown_stack`] (one [`CwdContext::Poisoned`]
///   sentinel frame): required for a hook payload with a `Known` `cwd` (the
///   persistent shell behind it has a directory stack this line did not
///   build), a `$()`/backtick payload, a process
///   substitution, a heredoc body substitution, or `eval`'s joined
///   script — every one of these forks or evaluates in the CURRENT shell
///   and really does inherit the parent's live stack via fork, so an
///   inner `popd`/bare-`pushd` reaching past what the recursed scope
///   itself pushed must poison forward rather than silently no-op past a
///   frame that, in the real shell, actually exists. Using [`Self::seed`]
///   at one of these boundaries was a confirmed Ask/Block→Allow bypass
///   found in the initial #210 landing: `pushd
///   ~/.config/shguard && pushd /tmp && cat $(popd && cp evil.toml
///   config.toml)` composed the inner `cp` against `/tmp` instead of the
///   real, inherited `~/.config/shguard`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CwdState {
    pub(crate) current: CwdContext,
    pub(crate) stack: Vec<CwdContext>,
    /// `set -P`/`set -o physical` or a `cd -P` has run on this line, so
    /// every anchor a later `cd` produces is marked [`CwdAnchor::physical`].
    pub(crate) physical_mode: bool,
    /// Set once an earlier simple command on this line is anything but a
    /// cwd move or a no-write builtin (issue #612), so it may have written,
    /// replaced or re-linked any path: every later `resolve_symlinks`
    /// exception on the line is refused. Shared by every clone of this state
    /// so a subshell, a backgrounded chain or a loop body that runs earlier
    /// counts for a later command. A fresh recursion (`bash -c`, `$(...)`,
    /// `eval`) starts its own flag and is refused outright instead
    /// (`resolve_symlinks` at `depth > 0`).
    pub(crate) earlier_writer: std::rc::Rc<std::cell::Cell<bool>>,
    /// Set on the clone a function body or loop is evaluated with: the body
    /// can run before or repeatedly around the commands that precede it
    /// textually, so no `resolve_symlinks` exception applies inside it.
    pub(crate) symlink_untrusted: bool,
}

impl CwdState {
    /// The clone a backgrounded chain runs with: it is not ordered against
    /// the rest of the line, so no `resolve_symlinks` exception applies in it.
    pub(crate) fn clone_untrusted(&self) -> Self {
        Self {
            symlink_untrusted: true,
            ..self.clone()
        }
    }

    /// Marks the current anchor physical once physical mode is on, called
    /// after every `cd`-family command.
    pub(crate) fn apply_physical_mode(&mut self, requested: bool) {
        self.physical_mode |= requested;
        if self.physical_mode
            && let CwdContext::Known(anchor) = &mut self.current
        {
            anchor.physical = true;
        }
    }

    /// Seeds a fresh state from a recursion site's [`CwdContext`] (issue
    /// #103's cwd-seeding mechanism) with a genuinely EMPTY stack — only
    /// correct for a
    /// boundary that spawns a real, fresh interpreter process with its own
    /// empty `DIRSTACK` (`bash -c`/`sh -c`/`zsh -c`/`dash -c`/`fish -c`/
    /// `flock -c`/`su -c`/`env -S`, and the two true top-level entry
    /// points). See [`Self::seed_unknown_stack`] for the same-process
    /// (`$()`/backtick/process-substitution/`eval`) counterpart, and
    /// [`CwdState`]'s own docs for why the two are NOT interchangeable.
    pub(crate) fn seed(current: CwdContext) -> Self {
        Self {
            current,
            stack: Vec::new(),
            physical_mode: false,
            earlier_writer: Default::default(),
            symlink_untrusted: false,
        }
    }

    /// Seeds a fresh state for a SAME-process recursion boundary — a
    /// `$()`/backtick payload, a process substitution, a heredoc body's own
    /// substitution, or `eval`'s joined script — every one of which forks
    /// or evaluates in the CURRENT shell and therefore really does inherit
    /// the live directory stack, unlike [`Self::seed`]'s fresh-process
    /// case. Seeding with a genuinely empty `stack` there would make an
    /// inner `popd`/bare-`pushd` a silent, precise no-op (per
    /// `apply_popd`/`apply_pushd_swap`'s own "empty stack is a safe
    /// no-op" reasoning) even though a real, unmodeled frame is actually
    /// there to pop back to — a confirmed Ask/Block→Allow regression in
    /// the initial #210 landing. Seeding with one
    /// [`CwdContext::Poisoned`] sentinel frame instead keeps every
    /// operation this recursed scope can itself statically account for
    /// (a balanced `pushd X ... popd` pair fully inside the recursion)
    /// exactly as precise as [`Self::seed`] would, while any `popd`/bare-
    /// `pushd` that reaches PAST what this scope itself pushed correctly
    /// pops the sentinel and poisons forward — honest about "one or more
    /// real frames exist here, contents unknown" instead of silently
    /// claiming there are none.
    pub(crate) fn seed_unknown_stack(current: CwdContext) -> Self {
        Self {
            current,
            stack: vec![CwdContext::Poisoned],
            physical_mode: false,
            earlier_writer: Default::default(),
            symlink_untrusted: false,
        }
    }

    /// Poisons the current directory AND discards the tracked stack, where
    /// [`Self::join`] alone would only collapse a differing stack to one
    /// `Poisoned` frame —
    /// issue #210's stack is only ever meaningful alongside a `current` we
    /// can still compose against; once `current` itself becomes unknown,
    /// nothing later could safely pop back to a stack frame recorded before
    /// the point uncertainty began, so keeping them would be false
    /// precision, not caution.
    pub(crate) fn poison(&mut self) {
        let poisoned = Self {
            current: CwdContext::Poisoned,
            ..self.clone()
        };
        *self = self.join(&poisoned);
        self.stack.clear();
    }

    /// The least upper bound of two states reaching the same program point:
    /// `current` joins per [`CwdContext::join`]; equal stacks stay, any other
    /// pair collapses to a single [`CwdContext::Poisoned`] sentinel (the shape
    /// [`Self::collapse_stack_on_uncertain_crossing`] uses); `physical_mode`
    /// and `symlink_untrusted` are OR-ed so a join never regains trust; and
    /// `earlier_writer` is OR-ed into `self`'s shared cell, which the result
    /// keeps sharing.
    ///
    /// Not symmetric in side effects: the OR lands in `self`'s cell and the
    /// result shares `self`'s `earlier_writer`, never `other`'s.
    pub(crate) fn join(&self, other: &Self) -> Self {
        self.earlier_writer
            .set(self.earlier_writer.get() || other.earlier_writer.get());
        Self {
            current: self.current.join(&other.current),
            stack: if self.stack == other.stack {
                self.stack.clone()
            } else {
                vec![CwdContext::Poisoned]
            },
            physical_mode: self.physical_mode || other.physical_mode,
            earlier_writer: std::rc::Rc::clone(&self.earlier_writer),
            symlink_untrusted: self.symlink_untrusted || other.symlink_untrusted,
        }
    }

    /// Issue #353's mitigation: collapses a non-empty stack down to a
    /// single [`CwdContext::Poisoned`] sentinel — the same "one or more
    /// real frames exist here, contents unknown" shape [`Self::seed_unknown_stack`]
    /// seeds with — leaving `current` untouched. Called at every
    /// [`crate::ast::Separator`] in a [`crate::ast::CommandLine`] that
    /// does NOT guarantee the preceding pipeline succeeded (every
    /// separator except `&&`, OR `&&` following a pipeline whose reported
    /// success is untrustworthy per
    /// `crate::gate::pipeline_reported_success_is_untrustworthy` — a
    /// `!`-negated pipeline reports SUCCESS to `&&` even when the real
    /// command inside failed, since negation flips the reported exit
    /// status, not whether the command itself ran; a single-stage brace
    /// group whose own last inner pipeline is so negated inherits the
    /// same untrustworthiness, since the group's reported status IS that
    /// last pipeline's) whenever the stack is non-empty.
    ///
    /// `apply_pushd`'s own known limitation (assume-success: a `pushd X`
    /// this module resolves is always assumed to actually `cd` there) means
    /// the tracked stack can desync from reality the instant a resolved
    /// push's target doesn't really exist — a real `pushd` to a
    /// nonexistent target fails outright (no push, no `cd`), so this
    /// module's stack ends up one frame deeper than reality from that
    /// point on. Under `&&`-only continuation this is harmless: if the
    /// real `pushd` fails, `&&` never runs what follows, so any verdict
    /// about it is vacuous. Once a `;`/`||`/`&` separator makes that
    /// failure-world reachable, though, a later `popd` recovers whichever
    /// of TWO adjacent real-world outcomes shguard can no longer
    /// distinguish — exactly the shape [`CwdContext::Poisoned`] already
    /// exists to represent. Collapsing at the crossing rather than at
    /// every individual resolved `pushd` (which would degenerate into
    /// treating any `pushd` as unverifiable, discarding issue #210's value
    /// for the extremely common `pushd X && ... && popd` shape entirely)
    /// confines the cost to command lines that are ACTUALLY two-world —
    /// still a real precision loss for a benign `pushd /tmp; make; popd`,
    /// but strictly better than pre-#210's poison-on-any-`pushd` baseline,
    /// and never worse than the already-accepted plain-`cd` gap (issue
    /// #103) `current` alone still carries after the collapse.
    pub(crate) fn collapse_stack_on_uncertain_crossing(&mut self) {
        if !self.stack.is_empty() {
            self.stack = vec![CwdContext::Poisoned];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contexts() -> Vec<CwdContext> {
        vec![
            CwdContext::Initial,
            CwdContext::on_line("/a".to_string()),
            CwdContext::on_line("/b".to_string()),
            CwdContext::Poisoned,
        ]
    }

    #[test]
    fn context_join_keeps_equal_and_poisons_every_other_pair() {
        for x in contexts() {
            for y in contexts() {
                let expected = if x == y {
                    x.clone()
                } else {
                    CwdContext::Poisoned
                };
                assert_eq!(x.join(&y), expected);
                assert_eq!(y.join(&x), expected);
            }
        }
    }

    #[test]
    fn state_join_collapses_unequal_stacks_and_ors_the_flags() {
        let mut a = CwdState::seed(CwdContext::on_line("/a".to_string()));
        a.stack.push(CwdContext::on_line("/x".to_string()));
        let same = a.join(&a.clone());
        assert_eq!(same.stack, a.stack);
        assert_eq!(same.current, a.current);

        let mut b = CwdState::seed(CwdContext::on_line("/a".to_string()));
        b.physical_mode = true;
        b.symlink_untrusted = true;
        b.earlier_writer.set(true);
        let joined = a.join(&b);
        assert_eq!(joined.current, a.current);
        assert_eq!(joined.stack, vec![CwdContext::Poisoned]);
        assert!(joined.physical_mode && joined.symlink_untrusted);
        assert!(a.earlier_writer.get() && joined.earlier_writer.get());
    }

    #[test]
    fn poison_poisons_current_discards_the_stack_and_keeps_the_shared_flag() {
        let mut state = CwdState::seed(CwdContext::on_line("/a".to_string()));
        state.stack.push(CwdContext::on_line("/x".to_string()));
        let clone = state.clone();
        state.poison();
        assert_eq!(state.current, CwdContext::Poisoned);
        assert!(state.stack.is_empty());
        state.earlier_writer.set(true);
        assert!(clone.earlier_writer.get());
    }
}
