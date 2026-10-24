# Distribution

## crates.io

```bash
cargo install shguard
```

Published via `cargo publish` after tagging a release. The `Cargo.toml` metadata
(description, repository, license) is already set.

### Keeping current
Run `cargo publish` after each tagged release, once the GitHub Release workflow
completes.

## Release procedure

1. Open a `chore/release-vX.Y.Z` PR (the branch name must start with
   `chore/release-`). CI does not run the `nix-build` matrix on it. Instead,
   the lefthook pre-push hook runs `nix build` on the exact pushed commit
   (`scripts/release-nix-build.sh`, for pushes to `refs/heads/chore/release-*`).
   That covers aarch64-darwin only, on the maintainer's Mac, and needs nix with
   the sandbox enabled (`sandbox = true`, `sandbox-fallback = false` in the
   daemon's system config: `/etc/nix/nix.conf`, or nix-darwin's
   `nix.settings`; for an untrusted user a user-level nix.conf does not reach
   the daemon, so the script requires both the system config and your
   effective user config to set them) and refuses the push otherwise.
   The nix build's checkPhase runs the test suite in release mode, where
   `SHGUARD_TEST_EVAL_TIMEOUT_MS` is compiled out, so hook-path tests run
   against the production 2s bound; flakes from a loaded builder there are
   out of scope (accepted).
   The script does not pin where the `nix build` runs: it checks neither the
   store or remote daemon (`NIX_REMOTE` / `--store`, e.g. `ssh-ng://`), nor the
   daemon's `builders` (or `/etc/nix/machines`), which could send the derivation
   to a machine whose sandbox settings it never saw, nor a system-level
   `extra-sandbox-paths` that exposes `/Users` and defeats the #779 check. These
   are out of scope (accepted): `builders` is empty and the store is the local
   `daemon`, and an untrusted user can only clear `builders`, not add them.
   x86_64-linux and aarch64-darwin are first built in CI by `main-check.yaml`'s
   `nix-build` job (ubuntu-latest and macos-latest) on the push to `main` when
   the release PR merges. x86_64-darwin is not gated: there is no hosted Intel
   macOS runner.
   Do not add commits to a release PR through the GitHub UI (web edits,
   "Commit suggestion", "Update branch"); push them locally instead, because
   only a local push runs the pre-push nix build. The push-to-`main` nix-build
   and `release.yaml`'s tag-time gate would still catch such a commit later.
   If a UI commit already landed, pulling it and running `git push` gives the
   hook no refs to check, so the nix build does not run; make a new local
   commit (e.g. `git commit --amend --no-edit`) and push with
   `--force-with-lease` so the hook checks it.
2. After merge, wait for `main-check.yaml`'s `nix-build` on the merge commit to
   pass, then tag the merge commit `vX.Y.Z` and push the tag.
3. `release.yaml` re-runs `nix build` on x86_64-linux and aarch64-darwin for the
   tagged commit, and its `build` and `release` jobs `needs` it, so a failed or
   skipped Darwin nix build cannot produce a GitHub release.
4. Once the workflow completes, `cargo publish` as described above.

## Homebrew

**Not yet available.** A `tsukasaI/homebrew-shguard` tap is planned for a
future release; this section will be updated with `brew tap` / `brew
install` instructions once the formula exists. Until then, install via
crates.io or Nix (below).

## Nix

```bash
nix run github:tsukasaI/shguard
```

### Keeping current
The flake input points to the repository; `nix flake update` picks up new
commits and tags automatically.

`flake.lock`'s inputs (nixpkgs, flake-utils) have no automated renewal
(Dependabot does not cover flakes): renew with `nix flake update`, then
verify with `gh workflow run main-check.yaml --ref <branch>` (its sandboxed
nix-build matrix).
