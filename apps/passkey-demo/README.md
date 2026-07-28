# World ID passkey demo

This local demo registers an ES256 passkey as a WIP-104 proving authenticator in a fresh
`WorldIDRegistryV2` on loopback Anvil. Registration returns the real registry root and direct
30-level Merkle proof. The browser then builds the Noir witness, generates a ProveKit WASM proof,
verifies it locally, and confirms that a bit-flipped proof is rejected. Private inputs, witnesses,
and proof bytes stay in browser memory. The bridge verification API intentionally remains HTTP 501.

## Run locally

Build the Foundry artifacts once from the repository root:

```sh
cd contracts
forge build
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

Open `https://localhost:5178` and accept Vite's local development certificate. Use `localhost`—an
IP address is not a valid WebAuthn relying-party ID. The bridge refuses
non-loopback RPC URLs and chains other than Anvil's chain ID `31337`. It uses Anvil's first standard
development account by default; override it only for another local Anvil instance:

```sh
PASSKEY_DEMO_ANVIL_RPC_URL=http://127.0.0.1:8545 \
PASSKEY_DEMO_ANVIL_PRIVATE_KEY=0x... \
bun run bridge
```

## Checks

```sh
bun test
bun run build
```

The passkey circuit uses the P-256 verifier from ProveKit's
[`p256_bigcurve`](https://github.com/worldfnd/provekit/tree/main/noir-examples/p256_bigcurve)
example with Noir `1.0.0-beta.20`, `noir-bignum` `v0.10.0`, and `noir_bigcurve` `v0.14.0`.
The checked-in PKP/PKV were prepared with ProveKit commit
`4b61b5d68e633a044eb41de4a6934d52ffdcbedc`:

```sh
cd crates/proof/noir/passkey-ownership-proof
provekit-cli prepare --skip-brillig-constraints-check --force \
  -p artifacts/passkey_ownership_proof.pkp \
  -v artifacts/passkey_ownership_proof.pkv \
  .
```

The browser demo consumes these artifacts directly through `@worldcoin/provekit@0.1.0`.
They are intentionally not exposed through `world-id-proof`'s older native Rust ProveKit API:
the current native SDK and ProveKit-main artifact formats are not compatible.

For the deterministic browser acceptance fixture, run Anvil and the bridge as above, then:

```sh
bun run fixture
```

Open `http://localhost:5179/e2e-fixture.html`. The fixture uses threaded proving when
cross-origin isolation is available and reports valid-proof acceptance plus tampered-proof
rejection. The circuit currently triggers Noir's BigCurve manual-constraint diagnostic, so
artifact preparation explicitly acknowledges that diagnostic. These artifacts are suitable for
integration testing, but are not a production or audited security claim.
