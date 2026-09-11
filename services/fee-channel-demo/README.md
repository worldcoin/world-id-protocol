# world-id-fee-channel-demo

Runs a whole YABS fee channel locally: deploy to anvil, register an RP, open a funded channel,
do paid work, settle on-chain, close and refund. Three roles run in one process.

- **Nonce manager** — the spec's public nonce service. Leases a lane, returns the previous
  signed request so the RP can check the service is not inventing nonces, records the new one.
- **Collector** — a mock work host. Admits a request only if the channel can still cover the
  fee, priced off the on-chain `IFeeSchedule`, then batches settlements to the escrow.
- **RP** — concurrent workers that lease a nonce, sign a `ProofRequestV2`, and ask for work.

Pricing comes from `RationalDecayFeeSchedule(price, threshold)`: a flat `price` per verification
up to `threshold`, then a marginal price decaying as roughly `price·threshold²/n²`, with the
total capped just under `maxFee() = 2·price·threshold`. Fund a channel to `maxFee` and it can
never be priced out, which is what the default run shows.

The lease is this demo's answer to the spec's open problem: YABS leaves concurrent allocation of
the same nonce unsolved, so a lane here is held by one caller until it records or releases it.

```bash
cargo run -p world-id-fee-channel-demo            # watch it, RUST_LOG=debug for more
cargo nextest run -p world-id-fee-channel-demo    # the same flow, asserted
```

Needs `forge build` artifacts under `contracts/out/` at compile time and `anvil` on PATH.
