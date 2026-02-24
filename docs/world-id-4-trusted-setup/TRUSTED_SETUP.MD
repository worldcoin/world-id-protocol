# World ID 4.0 Trusted Setup Verification (snarkjs)

This document describes how to independently verify the Phase 2 Groth16 artifacts for the World ID 4.0 trusted setup ceremony.

> [!NOTE]
> You are on the [`trusted-setup`](https://github.com/worldcoin/world-id-protocol/tree/trusted-setup) orphan branch which contains all ceremony artifacts. For the main protocol codebase, see the [`main`](https://github.com/worldcoin/world-id-protocol) branch.

It follows the same core pattern as the SMTB guide's verification phase, adapted for this OPRF setup:

1. Rebuild the exact `r1cs` from upstream circuit source.
2. Verify each final `zkey` against `(r1cs, ptau)` with `snarkjs zkey verify`.
3. Check the committed transcript logs (`contribution #...`, circuit hash, beacon, `ZKey Ok!`).
4. Index and validate contributor attestation gist links.

**Important: Git LFS Required.**
Make sure you have checked out this branch and pulled LFS files before proceeding — see the [Git LFS instructions](../../README.md#git-lfs) in the repository README. Without this step, verification tools will encounter LFS pointer stubs instead of valid binary data.

Reference methodology:

- <https://github.com/worldcoin/smtb-ceremony/blob/main/GUIDE.md#verify-contributions-happened-correctly>

Source circuits used for this ceremony:

- <https://github.com/TaceoLabs/oprf-service/tree/02c6442349cc6a2baf35ec8d94ae5b4ac4f49a71/circom/main>

Repository audit artifacts are committed under:

- [`docs/world-id-4-trusted-setup/artifacts/`](./artifacts/)

## 1. Prerequisites

- `git`
- `git-lfs`
- `node` + `snarkjs`
- `circom` (`2.2.x`; ceremony toolchain target is `2.2.3`)

Quick check:

```bash
git --version
git lfs version
circom --version
snarkjs --help | head -n 1
```

Install `snarkjs` if needed:

```bash
npm i -g snarkjs@0.7.6
```

Hydrate LFS-tracked setup artifacts on this branch before running verification:

```bash
git lfs install --local
git lfs pull --include="circom/artifacts/**/*.r1cs,circom/artifacts/**/*.zkey,circom/artifacts/**/*.wasm"
```

If these files are not hydrated, they remain 3-line Git LFS pointer files and
`snarkjs zkey verify ... circom/artifacts/..._final.zkey` will fail before cryptographic checks.

Recommended verification invocation (version-pinned):

```bash
npx -y snarkjs@0.7.6 --help
```

Notes:

- The upstream circuits declare `pragma circom 2.2.0`, so use a `2.2.x` compiler.
- The upstream build flow is `circom` + `snarkjs` (not `gnark`) for Groth16 setup.
- Older `snarkjs` versions can fail verification even when artifacts are correct; prefer `0.7.6` for parity with the ceremony toolchain.

## 2. Fetch Exact Source Commit

```bash
git clone https://github.com/TaceoLabs/oprf-service /tmp/oprf-service
cd /tmp/oprf-service
git checkout 02c6442349cc6a2baf35ec8d94ae5b4ac4f49a71
```

Circuits of interest:

- `circom/main/OPRFKeyGenProof13.circom`
- `circom/main/OPRFKeyGenProof25.circom`
- `circom/main/OPRFKeyGenProof37.circom`
- `circom/main/OPRFNullifierProof.circom`
- `circom/main/OPRFQueryProof.circom`

## 3. Rebuild R1CS Deterministically

```bash
mkdir -p /tmp/oprf-r1cs
cd /tmp/oprf-service/circom

circom --r1cs main/OPRFKeyGenProof13.circom -l . --O2 --output /tmp/oprf-r1cs
circom --r1cs main/OPRFKeyGenProof25.circom -l . --O2 --output /tmp/oprf-r1cs
circom --r1cs main/OPRFKeyGenProof37.circom -l . --O2 --output /tmp/oprf-r1cs
circom --r1cs main/OPRFNullifierProof.circom -l . --O2 --output /tmp/oprf-r1cs
circom --r1cs main/OPRFQueryProof.circom -l . --O2 --output /tmp/oprf-r1cs
```

Compare rebuilt `r1cs` hashes to this repo's committed files:

```bash
cd <world-id-protocol-repo>

shasum -a 256 \
  /tmp/oprf-r1cs/OPRFKeyGenProof13.r1cs \
  /tmp/oprf-r1cs/OPRFKeyGenProof25.r1cs \
  /tmp/oprf-r1cs/OPRFKeyGenProof37.r1cs \
  /tmp/oprf-r1cs/OPRFNullifierProof.r1cs \
  /tmp/oprf-r1cs/OPRFQueryProof.r1cs
```

Expected SHA-256:

- `OPRFKeyGenProof13.r1cs`: `6ed2ada50791bfd2a3eba15f727a5228e1efdc7545d07664b4671b02518813b8`
- `OPRFKeyGenProof25.r1cs`: `445876d7505d1aea9d8fdd2defd41e392e70deadafea28302a983b5920d66e33`
- `OPRFKeyGenProof37.r1cs`: `397b041e8fb32ad619f02e1f7d0eca5a59df96b1d6684f6232874466949fea8e`
- `OPRFNullifierProof.r1cs`: `6e590ca8afb21f81460b7208f0cd830fad0da7b99f6368cc41dc8cb838e58bec`
- `OPRFQueryProof.r1cs`: `04431dc408ff158d072ff0932c9bf7dfe7a669a7164228f4093e1f170e4ba521`

Check constraints (used to choose PTAU power):

```bash
npx -y snarkjs@0.7.6 r1cs info /tmp/oprf-r1cs/OPRFKeyGenProof13.r1cs
npx -y snarkjs@0.7.6 r1cs info /tmp/oprf-r1cs/OPRFKeyGenProof25.r1cs
npx -y snarkjs@0.7.6 r1cs info /tmp/oprf-r1cs/OPRFKeyGenProof37.r1cs
npx -y snarkjs@0.7.6 r1cs info /tmp/oprf-r1cs/OPRFNullifierProof.r1cs
npx -y snarkjs@0.7.6 r1cs info /tmp/oprf-r1cs/OPRFQueryProof.r1cs
```

Expected constraint counts:

- `OPRFKeyGenProof13`: `16528` -> needs `pot15` (`2^15 = 32768`)
- `OPRFKeyGenProof25`: `32820` -> needs `pot16` (`2^16 = 65536`)
- `OPRFKeyGenProof37`: `55252` -> needs `pot16`
- `OPRFNullifierProof`: `44285` -> needs `pot16`
- `OPRFQueryProof`: `17836` -> needs `pot15`

## 4. Verify Final ZKeys Against R1CS + PTAU

Use only the PTAU files required by the above circuit sizes (`pot15` and `pot16`):

```bash
curl -L https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_15.ptau -o /tmp/powersOfTau28_hez_final_15.ptau
curl -L https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_16.ptau -o /tmp/powersOfTau28_hez_final_16.ptau
```

PTAU mapping for this ceremony:

- `OPRFKeyGenProof13`: `powersOfTau28_hez_final_15.ptau`
- `OPRFQueryProof`: `powersOfTau28_hez_final_15.ptau`
- `OPRFKeyGenProof25`: `powersOfTau28_hez_final_16.ptau`
- `OPRFKeyGenProof37`: `powersOfTau28_hez_final_16.ptau`
- `OPRFNullifierProof`: `powersOfTau28_hez_final_16.ptau`

Run `snarkjs zkey verify` with the correct PTAU per circuit:

```bash
cd <world-id-protocol-repo>

npx -y snarkjs@0.7.6 zkey verify \
  /tmp/oprf-r1cs/OPRFKeyGenProof13.r1cs \
  /tmp/powersOfTau28_hez_final_15.ptau \
  circom/artifacts/OPRFKeyGenProof13/oprfkeygenproof13_final.zkey

npx -y snarkjs@0.7.6 zkey verify \
  /tmp/oprf-r1cs/OPRFKeyGenProof25.r1cs \
  /tmp/powersOfTau28_hez_final_16.ptau \
  circom/artifacts/OPRFKeyGenProof25/oprfkeygenproof25_final.zkey

npx -y snarkjs@0.7.6 zkey verify \
  /tmp/oprf-r1cs/OPRFKeyGenProof37.r1cs \
  /tmp/powersOfTau28_hez_final_16.ptau \
  circom/artifacts/OPRFKeyGenProof37/oprfkeygenproof37_final.zkey

npx -y snarkjs@0.7.6 zkey verify \
  /tmp/oprf-r1cs/OPRFNullifierProof.r1cs \
  /tmp/powersOfTau28_hez_final_16.ptau \
  circom/artifacts/OPRFNullifierProof/oprfnullifierproof_final.zkey

npx -y snarkjs@0.7.6 zkey verify \
  /tmp/oprf-r1cs/OPRFQueryProof.r1cs \
  /tmp/powersOfTau28_hez_final_15.ptau \
  circom/artifacts/OPRFQueryProof/oprfqueryproof_final.zkey
```

Each command must end with:

```text
ZKey Ok!
```

Expected final `zkey` SHA-256:

- `oprfkeygenproof13_final.zkey`: `6046b8900027cb7c10ac2371eaf63ef8398a53ebbd1725762dc04dfe91b46313`
- `oprfkeygenproof25_final.zkey`: `56d72ca97c415d52427a47a94a1bc657dab5e3406f252a2125690eb051926c47`
- `oprfkeygenproof37_final.zkey`: `66e9c470c5dd1a8faffe858de8cd47adda57ab149fecd46b36a653962d16ad57`
- `oprfnullifierproof_final.zkey`: `cef08ef106d7fdef3640a2bbb2d5e65fc2bef0c613ba65b900b65d4321a24139`
- `oprfqueryproof_final.zkey`: `03899a095915800757ecb9c79e1f350e95aa23b080bda83d36d4c3d6281559e0`

## 5. Validate Transcript Logs

Transcript files:

- `circom/artifacts/OPRFKeyGenProof13/oprfkeygenproof13_dcbuild3r-19372745_final_verification_transcript.log`
- `circom/artifacts/OPRFKeyGenProof25/oprfkeygenproof25_dcbuild3r-19372745_final_verification_transcript.log`
- `circom/artifacts/OPRFKeyGenProof37/oprfkeygenproof37_dcbuild3r-19372745_final_verification_transcript.log`
- `circom/artifacts/OPRFNullifierProof/oprfnullifierproof_dcbuild3r-19372745_final_verification_transcript.log`
- `circom/artifacts/OPRFQueryProof/oprfqueryproof_dcbuild3r-19372745_final_verification_transcript.log`

Check summary fields (contribution count, beacon, and `ZKey Ok!`):

```bash
cd <world-id-protocol-repo>

for f in circom/artifacts/OPRF*Proof*/oprf*_final_verification_transcript.log; do
  echo "===== $f"
  rg '^contribution #' "$f" | wc -l
  rg '^Beacon generator:' "$f"
  rg '^Beacon iterations Exp:' "$f"
  tail -n 1 "$f"
done
```

Expected contribution counts:

- `OPRFKeyGenProof13`: `114`
- `OPRFKeyGenProof25`: `112`
- `OPRFKeyGenProof37`: `106`
- `OPRFNullifierProof`: `105`
- `OPRFQueryProof`: `105`

Expected beacon in all five logs:

- generator: `39de5b1d29d0a4b1d817bf61d75afbafd1e390b4bbd18168fdc33b2c61da4d6c`
- iterations exp: `10`

## 6. Contributor Attestation Gists (Indexing)

Attestation links are expected to be provided as GitHub Gists by contributors.
To make auditing easy, keep a canonical mapping file with one row per contributor:

- `username`
- `gist_url`

The committed canonical mapping is:

- [`docs/world-id-4-trusted-setup/artifacts/contributions.tsv`](./artifacts/contributions.tsv)

This mapping is restricted to gists containing the file title:

- `world-id-protocol_attestation.log`

### 6.1 File Format Note (`.tsv`)

- `TSV` = Tab-Separated Values (fields separated by a tab character).

Example:

```bash
awk -F'\t' 'NR==1 {print $0}' docs/world-id-4-trusted-setup/artifacts/contributions.tsv
```

### 6.2 Committed Artifact Set

These files are committed in [`docs/world-id-4-trusted-setup/artifacts/`](./artifacts/):

- `contributions.tsv`: canonical contributor -> gist mapping for attestation gists that include `world-id-protocol_attestation.log`.
  - columns: `username,gist_url`

Quick check:

```bash
cd <world-id-protocol-repo>

wc -l docs/world-id-4-trusted-setup/artifacts/contributions.tsv
```

## 7. Deriving Runtime Artifacts (`.arks.zkey`, `.bin`, `.sol`)

This section documents how the currently committed runtime artifacts in
[`circom/artifacts/`](../../circom/artifacts/) are derived from final ceremony `*.zkey` files.

### 7.1 Generate `.arks.zkey` from final `.zkey` (TACEO `convert-zkey-to-ark`)

Tool:

- `convert-zkey-to-ark` from [TaceoLabs/circom-helpers](https://github.com/TaceoLabs/circom-helpers)

Install (example):

```bash
cargo install --git https://github.com/TaceoLabs/circom-helpers --locked \
  taceo-circom-types --features bin --bin convert-zkey-to-ark
```

Generate uncompressed Arkworks-compatible zkeys:

```bash
cd <world-id-protocol-repo>

convert-zkey-to-ark \
  --zkey-path circom/artifacts/OPRFQueryProof/oprfqueryproof_final.zkey \
  --arks-zkey-path circom/artifacts/OPRFQueryProof/oprfqueryproof_final.arks.zkey \
  --uncompressed

convert-zkey-to-ark \
  --zkey-path circom/artifacts/OPRFNullifierProof/oprfnullifierproof_final.zkey \
  --arks-zkey-path circom/artifacts/OPRFNullifierProof/oprfnullifierproof_final.arks.zkey \
  --uncompressed

convert-zkey-to-ark \
  --zkey-path circom/artifacts/OPRFKeyGenProof13/oprfkeygenproof13_final.zkey \
  --arks-zkey-path circom/artifacts/OPRFKeyGenProof13/oprfkeygenproof13_final.arks.zkey \
  --uncompressed

convert-zkey-to-ark \
  --zkey-path circom/artifacts/OPRFKeyGenProof25/oprfkeygenproof25_final.zkey \
  --arks-zkey-path circom/artifacts/OPRFKeyGenProof25/oprfkeygenproof25_final.arks.zkey \
  --uncompressed

convert-zkey-to-ark \
  --zkey-path circom/artifacts/OPRFKeyGenProof37/oprfkeygenproof37_final.zkey \
  --arks-zkey-path circom/artifacts/OPRFKeyGenProof37/oprfkeygenproof37_final.arks.zkey \
  --uncompressed
```

### 7.2 What `.arks.zkey` contains

The output type is
[`ArkZkey<P>`](https://github.com/TaceoLabs/circom-helpers/blob/393a5b6910432f81a34a51e47d1fe6dc75c00b4c/circom-types/src/groth16/zkey_to_ark.rs#L13-L17),
which serializes:

1. `matrices`: Arkworks [`ConstraintMatrices`](https://docs.rs/ark-relations/latest/ark_relations/r1cs/struct.ConstraintMatrices.html)
   (R1CS sparse matrices and metadata such as variable/constraint counts).
2. `pk`: Arkworks [`ProvingKey`](https://docs.rs/ark-groth16/latest/ark_groth16/data_structures/struct.ProvingKey.html)
   (Groth16 proving material including verification key elements and query vectors).

Conversion from Circom `zkey` to Arkworks format maps Circom Groth16 sections to
these Arkworks structures, then canonical-serializes them using `ark-serialize`.
With `--uncompressed`, group elements are written in uncompressed canonical form.

### 7.3 Generate `.bin` witness graphs (philsippl `circom-witness-rs`)

Tool:

- [circom-witness-rs](https://github.com/philsippl/circom-witness-rs)

Conceptually, `circom-witness-rs` does this:

1. Builds against Circom-generated C++ witness code.
2. Hooks field operations and executes symbolically to recover an execution graph.
3. Builds a DAG of nodes (`Input`, `Constant`, arithmetic/logical `Op`, optional `BBF`).
4. Optimizes the graph (tree-shaking, constant propagation, value numbering, Montgomery normalization).
5. Serializes `(nodes, outputs, input_map)` to `graph.bin`.

At runtime, the graph is deserialized and interpreted to compute witnesses without WASM.

The graphs in this repo were regenerated from:

- circuit sources: `https://github.com/TaceoLabs/oprf-service/tree/02c6442349cc6a2baf35ec8d94ae5b4ac4f49a71/circom/main`
- crate: `circom-witness-rs = 0.2.3`

Runner pattern (equivalent to what was used):

```bash
# helper crate:
# [dependencies]
# circom-witness-rs = { version = "0.2.3", features = ["build-witness"] }
#
# main():
#   circom_witness_rs::generate::build_witness().unwrap();

cd /tmp/circom-witgen-runner

WITNESS_CPP=/tmp/oprf-service/circom/main/OPRFQueryProof.circom \
CIRCOM_LIBRARY_PATH=/tmp/oprf-service/circom \
CARGO_TARGET_DIR=/tmp/circom-witgen-target-OPRFQueryProof \
cargo run --release

# move graph.bin to:
# <world-id-protocol-repo>/circom/artifacts/OPRFQueryProof/OPRFQueryProofGraph.bin
```

Repeat per circuit (`OPRFNullifierProof`, `OPRFKeyGenProof13`, `OPRFKeyGenProof25`, `OPRFKeyGenProof37`).

### 7.4 Generate Solidity verifiers (`.sol`) from vkeys (TACEO `groth16-sol-utils`)

Tool:

- `groth16-sol-utils extract-verifier` from [TaceoLabs/circom-helpers](https://github.com/TaceoLabs/circom-helpers)

Install from a pinned checkout (example):

```bash
git clone https://github.com/TaceoLabs/circom-helpers /tmp/circom-helpers
git -C /tmp/circom-helpers checkout 393a5b6910432f81a34a51e47d1fe6dc75c00b4c
cargo install --path /tmp/circom-helpers/groth16-sol --locked --features bin --bin groth16-sol-utils
```

Generate verifiers from each `*_vkey.json` (use pragma `^0.8.28` to reproduce committed files exactly):

```bash
cd <world-id-protocol-repo>

groth16-sol-utils extract-verifier \
  --vk circom/artifacts/OPRFQueryProof/oprfqueryproof_vkey.json \
  --output circom/artifacts/OPRFQueryProof/oprfqueryproof_verifier.sol \
  --pragma-version '^0.8.28'

groth16-sol-utils extract-verifier \
  --vk circom/artifacts/OPRFNullifierProof/oprfnullifierproof_vkey.json \
  --output circom/artifacts/OPRFNullifierProof/oprfnullifierproof_verifier.sol \
  --pragma-version '^0.8.28'

groth16-sol-utils extract-verifier \
  --vk circom/artifacts/OPRFKeyGenProof13/oprfkeygenproof13_vkey.json \
  --output circom/artifacts/OPRFKeyGenProof13/oprfkeygenproof13_verifier.sol \
  --pragma-version '^0.8.28'

groth16-sol-utils extract-verifier \
  --vk circom/artifacts/OPRFKeyGenProof25/oprfkeygenproof25_vkey.json \
  --output circom/artifacts/OPRFKeyGenProof25/oprfkeygenproof25_verifier.sol \
  --pragma-version '^0.8.28'

groth16-sol-utils extract-verifier \
  --vk circom/artifacts/OPRFKeyGenProof37/oprfkeygenproof37_vkey.json \
  --output circom/artifacts/OPRFKeyGenProof37/oprfkeygenproof37_verifier.sol \
  --pragma-version '^0.8.28'
```

## 8. Toolchain Provenance (Releases / Commits)

The following identifiers are the versions/commits used to generate or derive trusted
setup artifacts for this repository.

| Component | Role | Release / commit |
| --- | --- | --- |
| `TaceoLabs/oprf-service` | Source circuits for rebuild/verification | `02c6442349cc6a2baf35ec8d94ae5b4ac4f49a71` |
| `@worldcoin/world-id-trusted-setup-cli` | Ceremony client (Worldcoin p0tion fork) | `1.2.18`, gitHead `632e0c6e05cf89f649674a36b8607fcb5d09cf24` |
| `worldcoin/p0tion` | Repository for the CLI above | `632e0c6e05cf89f649674a36b8607fcb5d09cf24` |
| `snarkjs` (ceremony CLI dependency) | Phase-2 contribution/verification in p0tion flow | `0.7.6` |
| `circom` (toolchain target) | Compile Circom sources to `r1cs` | `2.2.x` (`2.2.3` target family) |
| `iden3/circom` (local binary provenance) | Local binary used during reproduction | tag `v2.2.2`, commit `e410b0d5cd2948a15931df0bc50d79ce56fa8c32` |
| `circom-witness-rs` | Generate optimized witness graph `.bin` files | `0.2.3` |
| `TaceoLabs/circom-helpers` | Zkey conversion + Solidity verifier tooling | `393a5b6910432f81a34a51e47d1fe6dc75c00b4c` |
| `taceo-circom-types` | `convert-zkey-to-ark` binary | `0.2.2` |
| `taceo-groth16-sol` | `groth16-sol-utils` binary | `0.2.2` |
| `ark-groth16` | `ProvingKey` format used inside `.arks.zkey` | `0.5.0` |
| `ark-relations` | `ConstraintMatrices` format used inside `.arks.zkey` | `0.5.1` |

Reference links:

- `@worldcoin/world-id-trusted-setup-cli`: <https://www.npmjs.com/package/@worldcoin/world-id-trusted-setup-cli>
- `worldcoin/p0tion`: <https://github.com/worldcoin/p0tion>
- `circom-witness-rs`: <https://github.com/philsippl/circom-witness-rs>
- `circom-helpers`: <https://github.com/TaceoLabs/circom-helpers>
- `ConstraintMatrices`: <https://docs.rs/ark-relations/latest/ark_relations/r1cs/struct.ConstraintMatrices.html>
- `ProvingKey`: <https://docs.rs/ark-groth16/latest/ark_groth16/data_structures/struct.ProvingKey.html>

## 9. Final Acceptance Criteria

Trusted setup is accepted when all are true:

1. Recompiled `r1cs` from upstream commit matches expected hashes.
2. Every `snarkjs zkey verify r1cs ptau final.zkey` returns `ZKey Ok!`.
3. Transcript logs end with `ZKey Ok!`, use the expected beacon, and have expected contribution counts.
4. Final `zkey` SHA-256 hashes match expected values in this guide.
5. Regenerated runtime artifacts match committed files bit-for-bit:
   - `.arks.zkey`
   - `.bin` witness graphs
   - `.sol` verifiers (with `--pragma-version '^0.8.28'`)
6. Canonical contributor attestation mapping is present in [`docs/world-id-4-trusted-setup/artifacts/contributions.tsv`](./artifacts/contributions.tsv), restricted to gists containing `world-id-protocol_attestation.log`.
