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
   the sandbox enabled (`sandbox = true`, `sandbox-fallback = false` in
   nix.conf). x86_64-linux is first built by `release.yaml` at tag time (step 3).
   x86_64-darwin is not gated: there is no hosted Intel macOS runner.
2. After merge, tag the merge commit `vX.Y.Z` and push the tag.
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
