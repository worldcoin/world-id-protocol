# World ID 4.0 Trusted Setup Verification (snarkjs)

This document describes how to independently verify the Phase 2 Groth16 artifacts committed in this repository.

It follows the same core pattern as the SMTB guide's verification phase, but simplified for this OPRF setup:

1. Rebuild the exact `r1cs` from upstream circuit source.
2. Verify each final `zkey` against `(r1cs, ptau)` with `snarkjs zkey verify`.
3. Check the committed transcript logs (`contribution #...`, circuit hash, beacon, `ZKey Ok!`).
4. Index and validate contributor attestation gist links.

Reference methodology:

- https://github.com/worldcoin/smtb-ceremony/blob/main/GUIDE.md#verify-contributions-happened-correctly

Source circuits used for this ceremony:

- https://github.com/TaceoLabs/oprf-service/tree/02c6442349cc6a2baf35ec8d94ae5b4ac4f49a71/circom/main

Repository audit artifacts generated from transcript parsing and GitHub gist matching are committed under:

- `docs/world-id-4-trusted-setup/artifacts/`

## 1. Prerequisites

- `git`
- `node` + `snarkjs`
- `circom` (use `2.2.x`; ceremony toolchain target is `2.2.3`)

Quick check:

```bash
snarkjs --version
circom --version
```

Install `snarkjs` if needed:

```bash
npm i -g snarkjs@0.7.6
```

Notes:

- The upstream circuits declare `pragma circom 2.2.0`, so use a `2.2.x` compiler.
- The upstream build flow itself is `circom` + `snarkjs` (not `gnark`) for Groth16 setup.

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
cd /Users/dcbuilder/Code/world/world-id-protocol

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
snarkjs r1cs info /tmp/oprf-r1cs/OPRFKeyGenProof13.r1cs
snarkjs r1cs info /tmp/oprf-r1cs/OPRFKeyGenProof25.r1cs
snarkjs r1cs info /tmp/oprf-r1cs/OPRFKeyGenProof37.r1cs
snarkjs r1cs info /tmp/oprf-r1cs/OPRFNullifierProof.r1cs
snarkjs r1cs info /tmp/oprf-r1cs/OPRFQueryProof.r1cs
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
cd /Users/dcbuilder/Code/world/world-id-protocol

snarkjs zkey verify \
  /tmp/oprf-r1cs/OPRFKeyGenProof13.r1cs \
  /tmp/powersOfTau28_hez_final_15.ptau \
  circom/artifacts/OPRFKeyGenProof13/oprfkeygenproof13_final.zkey

snarkjs zkey verify \
  /tmp/oprf-r1cs/OPRFKeyGenProof25.r1cs \
  /tmp/powersOfTau28_hez_final_16.ptau \
  circom/artifacts/OPRFKeyGenProof25/oprfkeygenproof25_final.zkey

snarkjs zkey verify \
  /tmp/oprf-r1cs/OPRFKeyGenProof37.r1cs \
  /tmp/powersOfTau28_hez_final_16.ptau \
  circom/artifacts/OPRFKeyGenProof37/oprfkeygenproof37_final.zkey

snarkjs zkey verify \
  /tmp/oprf-r1cs/OPRFNullifierProof.r1cs \
  /tmp/powersOfTau28_hez_final_16.ptau \
  circom/artifacts/OPRFNullifierProof/oprfnullifierproof_final.zkey

snarkjs zkey verify \
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
cd /Users/dcbuilder/Code/world/world-id-protocol

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
To make auditing easy, maintain an index file with one row per contribution:

- `circuit`
- `contribution_number`
- `contributor_tag` (from transcript, e.g. `dcbuild3r-19372745`)
- `contribution_hash`
- `attestation_gist_url`

Generate a starter CSV directly from transcript logs:

```bash
cd /Users/dcbuilder/Code/world/world-id-protocol

echo "circuit,contribution_number,contributor_tag,contribution_hash,attestation_gist_url" > /tmp/oprf_attestations.csv

for log in circom/artifacts/OPRF*Proof*/oprf*_final_verification_transcript.log; do
  circuit=$(basename "$(dirname "$log")")
  awk -v circuit="$circuit" '
    /^contribution #[0-9]+ /{
      contribution=$2
      gsub("#","",contribution)
      contributor=$3
      gsub(":$","",contributor)
      getline h1; getline h2; getline h3; getline h4
      gsub(/[[:space:]]/,"",h1)
      gsub(/[[:space:]]/,"",h2)
      gsub(/[[:space:]]/,"",h3)
      gsub(/[[:space:]]/,"",h4)
      hash=h1 h2 h3 h4
      printf "%s,%s,%s,%s,\n", circuit, contribution, contributor, hash
    }
  ' "$log" >> /tmp/oprf_attestations.csv
done

wc -l /tmp/oprf_attestations.csv
```

After filling the `attestation_gist_url` column, verify all URLs are reachable:

```bash
awk -F, 'NR>1 && $5 != "" {print $5}' /tmp/oprf_attestations.csv | while read -r url; do
  curl -fsSI "$url" >/dev/null || echo "invalid: $url"
done
```

### 6.1 File Format Note (`.csv` vs `.tsv`)

- `CSV` = Comma-Separated Values.
- `TSV` = Tab-Separated Values (fields are separated by a tab character, not a comma).
- Both are plain-text table formats; you can open them in spreadsheets or parse them in shell tools.

Examples:

```bash
# CSV: split on comma
awk -F, 'NR==1 {print $0}' docs/world-id-4-trusted-setup/artifacts/contributions.csv

# TSV: split on tab
awk -F'\t' 'NR==1 {print $0}' docs/world-id-4-trusted-setup/artifacts/contributor_gist_check.tsv
```

### 6.2 Committed Artifact Set

These files are committed in `docs/world-id-4-trusted-setup/artifacts/`:

- `contributions.csv`: all contribution rows extracted from transcripts.
  - columns: `circuit,contribution_number,contributor_tag,username,github_numeric_id,contribution_hash`
- `contributor_usernames.txt`: unique contributor GitHub usernames (one per line).
- `contributor_gist_check.tsv`: concise reviewer table with one primary hash-match gist URL per user.
  - columns: `username,gist_count,metadata_matches,hash_matches,primary_hash_gist`
- `hash_gists_primary.tsv`: one hash-match gist URL per user.
  - columns: `username,gist_url`
- `gist_matches_fast.tsv`: full raw match rows (metadata and hash matches).
  - columns: `username,gist_id,gist_url,updated_at,match_type,match_value,description,files`

Quick check:

```bash
cd /Users/dcbuilder/Code/world/world-id-protocol

wc -l docs/world-id-4-trusted-setup/artifacts/contributions.csv
wc -l docs/world-id-4-trusted-setup/artifacts/contributor_gist_check.tsv
wc -l docs/world-id-4-trusted-setup/artifacts/gist_matches_fast.tsv
```

## 7. Final Acceptance Criteria

Trusted setup is accepted when all are true:

1. Recompiled `r1cs` from upstream commit matches expected hashes.
2. Every `snarkjs zkey verify r1cs ptau final.zkey` returns `ZKey Ok!`.
3. Transcript logs end with `ZKey Ok!`, use the expected beacon, and have expected contribution counts.
4. Contribution-to-attestation mapping is indexed in `docs/world-id-4-trusted-setup/artifacts/contributions.csv`.
5. Contributor gist evidence is indexed and reviewable in `docs/world-id-4-trusted-setup/artifacts/contributor_gist_check.tsv`, with canonical gist links in `docs/world-id-4-trusted-setup/artifacts/hash_gists_primary.tsv` and raw match rows in `docs/world-id-4-trusted-setup/artifacts/gist_matches_fast.tsv`.
