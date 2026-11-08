{
  description = "shguard: PreToolUse hook gating shell commands through a Creusot-verified kernel";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Pinned to the release the proofs were built against. Its pinned nightly
    # rustc, why3 and solvers come with it; flake.lock freezes the solver
    # versions and every gate re-proves from source (#1005).
    creusot.url = "github:creusot-rs/creusot/v0.14.0";
  };

  outputs = { self, nixpkgs, creusot }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in {
      # The hook binary, built like the release job builds it
      # (`cargo build --locked --release -p shguard`), with nixpkgs' stable
      # rustc. Tests are not run here: the differential tests need bash,
      # brush and shfmt, and the release job runs `cargo test` before it
      # publishes.
      packages = forAllSystems (system: pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "shguard";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "shguard" ];
          doCheck = false;
          meta = {
            description = "PreToolUse hook gating shell commands through a Creusot-verified kernel";
            license = with pkgs.lib.licenses; [ mit asl20 ];
            mainProgram = "shguard";
          };
        };
      });

      devShells = forAllSystems (system: pkgs: {
        default = pkgs.mkShell {
          # Not PATH order: stdenv adds its own cc after every entry in
          # `packages`, so the Creusot bundle's gcc-wrapper (`cc`/`gcc`) is found
          # first. The linker var covers rustc linking; CC_<target> covers
          # `cc`-crate build scripts. Not plain `CC`: cc-wrapper's setup hook
          # overwrites it.
          env."CARGO_TARGET_${pkgs.stdenv.hostPlatform.rust.cargoEnvVarTarget}_LINKER" = "${pkgs.stdenv.cc}/bin/cc";
          env."CC_${builtins.replaceStrings [ "-" ] [ "_" ] pkgs.stdenv.hostPlatform.rust.rustcTarget}" = "${pkgs.stdenv.cc}/bin/cc";
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
            # This package also ships its own nightly `cargo`/`rustc` and a
            # gcc-wrapper `cc`; it must stay AFTER the stable toolchain above
            # so a plain `cargo` resolves to stable. `cargo creusot` sets CARGO
            # itself.
            creusot.packages.${system}.free
            # Kani is not in nixpkgs; `.github/workflows/kani.yaml` installs it.
          ];
        };
      });
    };
}
