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

The passkey is a **proving authenticator**. The bridge creates a random Ethereum management
authenticator to authorize its insertion; the passkey does not manage or recover the account.
This management key and the browser's credential selection are ephemeral demo state. Reloading
the page or restarting the bridge does not implement a recovery or existing-account login flow.

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
constraint rejection after mutating the challenge, RP-ID hash, origin hash, nonce, signature,
public key, registry root, or Merkle path. It also re-signs assertions with disallowed type,
origin, cross-origin status and UP/UV flags, and checks challenge-field and unsigned-padding
attacks. These policy failures therefore cannot pass merely because an invalid signature was
rejected. Append `?threads=false` to force single-threaded proving. Real
WebAuthn acceptance still needs the main website, because synthetic keys cannot exercise the
platform passkey prompt.

## Circuit and artifacts

The circuit lives in `crates/proof/noir/passkey-ownership-proof`. It enforces the P-256 signature,
exact JSON challenge field, `type: webauthn.get`, RP-ID hash, UP/UV flags, and an origin whose
SHA-256 equals the public `origin_hash`. It also enforces the fixed action-domain + RP-ID-hash +
registry-root + nonce challenge derivation, passkey slot commitment, and registry Merkle path.
The circuit inspects only bytes covered by the signature; unsigned bounded-vector padding cannot
provide a challenge. The browser validates the same policy before proving and explicitly compares
the returned credential ID with the registered ID.

The demo deliberately accepts a restricted client-data serialization: compact JSON fields in
the order `type`, `challenge`, `origin`, optionally followed by `crossOrigin: false`. Origins must
be unescaped printable ASCII. Unknown/duplicate fields, other ordering, escapes, and trailing
bytes are rejected. This is a supported browser profile, not a general-purpose WebAuthn JSON parser.

The public statement is `(root, challenge, rp_id_hash, origin_hash, nonce)`. Origin is bound by the
signed JSON and public hash; the v1 challenge formula itself is unchanged. An external verifier
must compare these public inputs with its expected root, RP, exact origin (including port), and
issued nonce, and track nonce consumption for replay protection. The self-verifying local demo
does not provide a remote verifier or nonce-consumption service.

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

Both recipes require a clean ProveKit checkout at the specified commit, verify the Nargo
compiler revision, and build `provekit-cli` with its locked dependencies. Run from the repository
root with absolute paths to those checkouts and Nargo binaries:

```sh
PROVEKIT_NATIVE_BUILDER=/path/to/provekit-at-9b2a6f37 \
NARGO_NATIVE_BIN=/path/to/beta11/nargo \
  bash scripts/passkey-artifacts.sh prepare-native

PROVEKIT_BROWSER_BUILDER=/path/to/provekit-at-4b61b5d6 \
NARGO_BIN=/path/to/beta20/nargo \
  bash scripts/passkey-artifacts.sh prepare-browser

bash scripts/passkey-artifacts.sh write-manifest
bash scripts/passkey-artifacts.sh verify
```

Browser artifacts target the published `@worldcoin/provekit@0.1.1` SDK, which fixes the older
release's WebKit initialization failure and provides a scalar fallback when its threaded build
cannot run. `prepare-browser-artifacts.sh`
copies the native circuit, applies only the documented beta.20
dependency and API substitutions, runs the circuit tests, and invokes a `provekit-cli` built from
commit `4b61b5d68e633a044eb41de4a6934d52ffdcbedc`.

The native builder is pinned to `9b2a6f37c67691eab4b0cec6c35e35c520e93285`, matching the
workspace dependencies. `artifacts/passkey-artifacts.sha256` records both pairs, their circuit
source, and the generation scripts. Demo CI checks that manifest before testing and building the
website. Update it only after regenerating both pairs and running native/browser proof acceptance;
checksums detect drift but do not by themselves establish that an artifact implements its source.

These artifacts are suitable for integration testing. They are not a production or audited
security claim.
