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

```bash
brew tap tsukasaI/shguard
brew install shguard
```

Formula lives in the [homebrew-shguard](https://github.com/tsukasaI/homebrew-shguard) tap.

### Keeping current
After each release, update the formula's `url` and `sha256` to point to the
new release binary and regenerated checksum. This can be automated with
`brew bump-formula-pr` or a CI step in the release workflow.

## Nix

```bash
nix run github:tsukasaI/shguard
```

### Keeping current
The flake input points to the repository; `nix flake update` picks up new
commits and tags automatically.
