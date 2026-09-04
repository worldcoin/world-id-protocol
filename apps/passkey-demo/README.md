# World ID passkey-signature demo

This local website demonstrates replacing a PRF-derived World ID secret with direct control of an
ES256 passkey signing key. **Create World ID** registers the passkey as a WIP-104 proving
authenticator in a fresh `WorldIDRegistryV2` account on loopback Anvil. **Generate proof with
passkey** signs a domain-separated request bound to the registry root and RP ID, builds the Noir
witness, generates and verifies a ProveKit WASM proof, and confirms that a bit-flipped proof is
rejected.

The account leaf is displayed as the local World ID identifier. The proof establishes passkey
control and registry inclusion; it is not a personhood, uniqueness, credential, query, or nullifier
proof. The separate PRF output proposed for credential-vault encryption is unaffected by this
experiment.

Private inputs, witnesses, and proof bytes stay in browser memory. The bridge handles only local
contract deployment, registration, and Merkle reads. Its verification API intentionally remains
HTTP 501.

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

Open `http://localhost:5178`, select **Create World ID**, then **Generate proof with passkey**.
Loopback HTTP is a WebAuthn secure context. Use `localhost`—an IP address is not a valid WebAuthn
relying-party ID. The bridge refuses
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
[`p256_bigcurve`](https://github.com/worldfnd/provekit/tree/v1/noir-examples/p256_bigcurve)
example with Noir `1.0.0-beta.11`, `noir-bignum` `v0.8.0`, and `noir_bigcurve` `v0.11.0`.
The native PKP/PKV under `crates/proof` match the ProveKit `v1` revision pinned in the workspace:

```sh
cd crates/proof/noir/passkey-ownership-proof
provekit-cli prepare --skip-brillig-constraints-check --force \
  -p artifacts/passkey_ownership_proof.pkp \
  -v artifacts/passkey_ownership_proof.pkv \
  .
```

The published `@worldcoin/provekit@0.1.0` browser SDK uses the later PKP 2.0/PKV 2.1 format and
Noir beta.20. Its checked-in artifacts live under `apps/passkey-demo/artifacts`. The reproducible
recipe is `prepare-browser-artifacts.sh`: it copies the checked-in native circuit, applies only the
documented beta.20 dependency/API substitutions, runs all circuit tests, and invokes a
`provekit-cli` built from commit `4b61b5d68e633a044eb41de4a6934d52ffdcbedc`. Keeping the two
artifact pairs explicit prevents browser and native runtimes from consuming incompatible formats.

The circuit enforces the P-256 signature, signed challenge occurrence, RP-ID hash, fixed
action-domain + RP-ID-hash + registry-root + nonce challenge derivation,
passkey slot commitment, and registry Merkle path. The browser additionally enforces WebAuthn's
`type`, exact challenge value, exact origin, `crossOrigin: false`, credential ID, UP/UV flags, and
platform API semantics before any witness is built. Those browser policy checks are not duplicated
inside the circuit.

For the deterministic browser acceptance fixture, run Anvil and the bridge as above, then:

```sh
bun run fixture
```

Open `http://localhost:5179/e2e-fixture.html`. The deterministic fixture uses threaded proving when
cross-origin isolation is available and reports valid-proof acceptance, tampered-proof rejection,
and constraint rejection after mutating the challenge, RP-ID hash, nonce, signature, public key,
registry root, or Merkle path. Real WebAuthn acceptance must still use the main website because synthetic keys
cannot exercise the platform passkey prompt. The circuit currently triggers Noir's BigCurve
manual-constraint diagnostic, so
artifact preparation explicitly acknowledges that diagnostic. These artifacts are suitable for
integration testing, but are not a production or audited security claim.
