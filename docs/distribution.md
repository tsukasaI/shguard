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
   `chore/release-`). The `nix-build` matrix in `main-check.yaml` (x86_64-linux
   on ubuntu-latest and aarch64-darwin on macos-latest, sandboxed) runs on it
   and must pass before merging. x86_64-darwin is not gated: there is no hosted
   Intel macOS runner.
2. After merge, tag the merge commit `vX.Y.Z` and push the tag.
3. `release.yaml` re-runs `nix build` on x86_64-linux and aarch64-darwin for
   the tagged commit,
   and its `build` and `release` jobs `needs` it, so a failed or skipped Darwin
   nix build cannot produce a GitHub release.
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
