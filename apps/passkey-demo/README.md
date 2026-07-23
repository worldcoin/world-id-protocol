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

The checked-in circuit currently triggers Noir's BigCurve manual-constraint diagnostic. The demo
artifacts are suitable for integration testing, but are not a production/audited security claim.
