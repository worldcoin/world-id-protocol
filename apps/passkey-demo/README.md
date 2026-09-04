# World ID passkey-signature demo

A local website that replaces a PRF-derived World ID secret with direct control of an ES256
passkey signing key.

- **Create World ID** registers the passkey as a WIP-104 proving authenticator in a fresh
  `WorldIDRegistryV2` account on loopback Anvil.
- **Generate proof with passkey** signs a domain-separated request bound to the registry root and
  RP ID, builds the Noir witness, generates and verifies a ProveKit WASM proof in the browser, and
  confirms that a bit-flipped proof is rejected.

The account leaf is displayed as the local World ID identifier. The proof establishes passkey
control and registry inclusion only; it is not a personhood, uniqueness, credential, query, or
nullifier proof. The separate PRF output proposed for credential-vault encryption is unaffected.

Private inputs, witnesses, and proof bytes stay in browser memory. The bridge handles only local
contract deployment, registration, and Merkle reads. Its verification endpoint intentionally
returns HTTP 501.

## Run locally

Build the Foundry artifacts once from the repository root:

```sh
cd contracts && forge build
```

Then use three terminals:

```sh
anvil --host 127.0.0.1 --port 8545
```

```sh
cd apps/passkey-demo
bun install --frozen-lockfile
bun run bridge
```

```sh
cd apps/passkey-demo
bun run dev
```

Open `http://localhost:5178`, select **Create World ID**, then **Generate proof with passkey**.
Plain HTTP on `localhost` is a WebAuthn secure context; an IP address is not a valid relying-party
ID, so always use the `localhost` URL.

The bridge refuses non-loopback RPC URLs and chains other than Anvil's chain ID `31337`. It uses
Anvil's first standard development account by default; override it only for another local Anvil
instance:

```sh
PASSKEY_DEMO_ANVIL_RPC_URL=http://127.0.0.1:8545 \
PASSKEY_DEMO_ANVIL_PRIVATE_KEY=0x... \
bun run bridge
```

## Checks

```sh
bun run test
bun run build
```

### Deterministic browser fixture

The fixture drives the same bridge, witness construction, and ProveKit prove/verify lifecycle
with a synthetic ES256 key, so it runs without a platform passkey prompt. With Anvil and the
bridge running:

```sh
bun run fixture
```

Open `http://localhost:5179/e2e-fixture.html`. It uses threaded proving when cross-origin
isolation is available and reports valid-proof acceptance, tampered-proof rejection, and
constraint rejection after mutating the challenge, RP-ID hash, nonce, signature, public key,
registry root, or Merkle path. Append `?threads=false` to force single-threaded proving. Real
WebAuthn acceptance still needs the main website, because synthetic keys cannot exercise the
platform passkey prompt.

## Circuit and artifacts

The circuit lives in `crates/proof/noir/passkey-ownership-proof`. It enforces the P-256 signature,
signed-challenge occurrence, RP-ID hash, the fixed action-domain + RP-ID-hash + registry-root +
nonce challenge derivation, the passkey slot commitment, and the registry Merkle path. The browser
additionally enforces WebAuthn's `type`, exact challenge, exact origin, `crossOrigin: false`,
credential ID, and UP/UV flags before any witness is built; those policy checks are not duplicated
inside the circuit.

P-256 verification comes from ProveKit's
[`p256_bigcurve`](https://github.com/worldfnd/provekit/tree/v1/noir-examples/p256_bigcurve)
example with Noir `1.0.0-beta.11`, `noir-bignum` `v0.8.0`, and `noir_bigcurve` `v0.11.0`. The
circuit triggers Noir's BigCurve manual-constraint diagnostic, which artifact preparation
acknowledges with `--skip-brillig-constraints-check`.

Two artifact pairs are checked in because the native and browser stacks consume incompatible
formats:

| Target  | Location                                                | Noir    | Format          |
| ------- | ------------------------------------------------------- | ------- | --------------- |
| native  | `crates/proof/noir/passkey-ownership-proof/artifacts`   | beta.11 | PKP 1.1 / PKV 1.2 |
| browser | `apps/passkey-demo/artifacts`                           | beta.20 | PKP 2.0 / PKV 2.1 |

Native artifacts match the ProveKit `v1` revision pinned in the workspace:

```sh
cd crates/proof/noir/passkey-ownership-proof
provekit-cli prepare --skip-brillig-constraints-check --force \
  -p artifacts/passkey_ownership_proof.pkp \
  -v artifacts/passkey_ownership_proof.pkv \
  .
```

Browser artifacts target the published `@worldcoin/provekit@0.1.0` SDK. `prepare-browser-artifacts.sh`
is the reproducible recipe: it copies the native circuit, applies only the documented beta.20
dependency and API substitutions, runs the circuit tests, and invokes a `provekit-cli` built from
commit `4b61b5d68e633a044eb41de4a6934d52ffdcbedc`.

These artifacts are suitable for integration testing. They are not a production or audited
security claim.
