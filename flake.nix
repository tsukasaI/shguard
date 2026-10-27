{
  description = "shguard: PreToolUse hook gating shell commands through a Creusot-verified kernel";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Pinned to the release the proofs were built against. Its pinned nightly
    # rustc, why3 and solvers come with it; flake.lock freezes them and the
    # committed verif/**/proof.json replay catches drift.
    creusot.url = "github:creusot-rs/creusot/v0.14.0";
  };

  outputs = { self, nixpkgs, creusot }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in {
      # No `packages.default` yet: `shguard` is a lib until the hook binary
      # lands (M13), so there is nothing to install. Add a
      # `rustPlatform.buildRustPackage` over ./Cargo.lock with that milestone.
      devShells = forAllSystems (system: pkgs: {
        default = pkgs.mkShell {
          packages = [
            # Stable toolchain for production code, fmt and clippy.
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.cargo-deny
            pkgs.lefthook
            pkgs.gitleaks
            pkgs.shfmt
            pkgs.bash # bash 5, for the differential tests
            # `free` has the freely redistributable alt-ergo 2.4.3; `default`
            # pulls the non-commercial alt-ergo 2.6, which is unfree.
            # This package also ships its own nightly `cargo`/`rustc`/`cc`;
            # it must stay AFTER the stable toolchain above so a plain
            # `cargo` resolves to stable. `cargo creusot` sets CARGO itself.
            creusot.packages.${system}.free
            # TODO(M9): add Kani (`cargo kani -p shguard-syntax`); not wired
            # here because it needs its own CBMC bundle and is not verified.
          ];
        };
      });
    };
}
