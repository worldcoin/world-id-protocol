# Noir is not packaged in nixpkgs, so we repackage the official prebuilt
# release binaries. The version must match what provekit expects
# (see .github/workflows/noir-ci.yml and CONTRIBUTING.md).
{ stdenv, lib, fetchurl, autoPatchelfHook }:

let
  artifacts = {
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
  artifact = artifacts.${stdenv.hostPlatform.system};
in stdenv.mkDerivation rec {
  pname = "nargo";
  version = "1.0.0-beta.11";

  src = fetchurl {
    url = "https://github.com/noir-lang/noir/releases/download/v${version}/nargo-${artifact.target}.tar.gz";
    hash = artifact.hash;
  };

  sourceRoot = ".";

  nativeBuildInputs = lib.optionals stdenv.isLinux [ autoPatchelfHook ];
  buildInputs = lib.optionals stdenv.isLinux [ stdenv.cc.cc.lib ];

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
}
