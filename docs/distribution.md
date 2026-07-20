# Distribution

## crates.io

```bash
cargo install shguard
```

Published via `cargo publish` after tagging a release. The `Cargo.toml` metadata
(description, repository, license) is already set.

### Keeping current
Run `cargo publish` after each tagged release, once the GitHub Release workflow
completes and CI is green.

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
