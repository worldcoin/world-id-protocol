{
  description = "World ID Protocol dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # Noir is not packaged in nixpkgs, so we repackage the official
        # prebuilt release binaries. The version must match what provekit
        # expects (see .github/workflows/noir-ci.yml and CONTRIBUTING.md).
        noirVersion = "1.0.0-beta.11";
        nargoArtifacts = {
          aarch64-darwin = {
            target = "aarch64-apple-darwin";
            hash = "sha256-XAYTKQvnKPyzFKSAV4pg4KEc0ZLSSdCN7US+58XuoUI=";
          };
          x86_64-darwin = {
            target = "x86_64-apple-darwin";
            hash = "sha256-q/qd+hpYsQoQBt0uq/2xnrpWl99com4XB+qhsK36j/c=";
          };
          x86_64-linux = {
            target = "x86_64-unknown-linux-gnu";
            hash = "sha256-iaAU/TBYoFnRv6+ZzZiR65SKCT7DExSpzwRzSI9Ud5U=";
          };
          aarch64-linux = {
            target = "aarch64-unknown-linux-gnu";
            hash = "sha256-v25Eqc0dqMnERdIcaYtAZ4o9bveda3txjCSdZp0HCWY=";
          };
        };

        nargo = pkgs.stdenv.mkDerivation rec {
          pname = "nargo";
          version = noirVersion;

          src = pkgs.fetchurl {
            url = "https://github.com/noir-lang/noir/releases/download/v${version}/nargo-${nargoArtifacts.${system}.target}.tar.gz";
            hash = nargoArtifacts.${system}.hash;
          };

          sourceRoot = ".";

          nativeBuildInputs =
            pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.autoPatchelfHook ];
          buildInputs =
            pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.stdenv.cc.cc.lib ];

          installPhase = ''
            runHook preInstall
            install -Dm755 nargo $out/bin/nargo
            runHook postInstall
          '';

          meta = {
            description = "Noir compiler and package manager";
            homepage = "https://noir-lang.org";
            mainProgram = "nargo";
          };
        };

        rustToolchain =
          pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in {
        packages = {
          inherit nargo;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            nargo
            pkgs.foundry # forge / cast / anvil
            pkgs.circom
            pkgs.just
            pkgs.pkg-config
            pkgs.openssl
          ];
        };
      });
}
