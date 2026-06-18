# World ID Solana Satellite

Minimal Anchor-based Solana satellite program for the World ID bridge.

## Local E2E

The relay integration test uses LiteSVM as an in-process local Solana network.
Build the SBF artifact first:

```sh
cargo build-sbf --manifest-path crates/solana-satellite/Cargo.toml --sbf-out-dir target/deploy
```

Then run the focused relay E2E:

```sh
cargo test -p world-id-relay --test it e2e_solana_permissioned_replays_commitment_on_local_svm -- --nocapture
```

The LiteSVM test funds local accounts itself. The funded test account is also
the permissioned gateway signer, matching the Anvil-style local testing model.
