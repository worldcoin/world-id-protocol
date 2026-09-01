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

        nargo = pkgs.callPackage ./nix/nargo.nix { };

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
            pkgs.mdbook
            pkgs.mdbook-mermaid
            pkgs.pkg-config
            pkgs.python3
            pkgs.openssl
          ];
        };
      });
}
