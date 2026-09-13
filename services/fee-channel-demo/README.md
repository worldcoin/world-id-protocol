# world-id-fee-channel-demo

Runs a whole fixed-rate fee channel locally: deploy to anvil, register an RP, open a channel,
fund an epoch, spend the capacity, fund more, settle, then close. Two roles run in one process.

- **Collector** — issues nonces over `POST /channels/{id}/nonces`, takes early signatures over
  `PUT /channels/{id}/nonces/{lane}/{counter}`, admits payments at `POST /admit`, and settles
  the epoch on chain. It reads capacity from a snapshot of `epochState` bounded by a staleness
  limit, and refuses rather than serves when that read is stale or unavailable.
- **RP** — holds no nonce state. For each unit it reserves a counter, checks the collector's
  proposal against its own signature on the counter below it, signs a `Payment`, and hands it
  on.

A `Payment` is consumed by its first admission, so returning the signature early and presenting
it for work are alternatives rather than a sequence; `--early-return` picks the first.

A refusal at capacity carries the highest payment per lane. The RP verifies those signatures and
sums the counters, so the proof costs one signature per lane rather than one per unit. Nothing is
ever refunded: whatever an epoch was funded for reaches the collector, by settlement during the
epoch or by the closing settlement after it.

```bash
cargo run -p world-id-fee-channel-demo -- demo          # watch it, RUST_LOG=debug for more
cargo nextest run -p world-id-fee-channel-demo          # the same flow, asserted
```

Needs `forge build` artifacts under `contracts/out/` and `anvil` on PATH at run time.

## Local end-to-end with the flamingo host

The same channel, driven against the real collector: the flamingo verifier host. Two terminals,
in this order.

```bash
# Terminal 1: deploys everything, writes the env block, then waits for the host.
cargo run -p world-id-fee-channel-demo -- local-e2e

# Terminal 2: once terminal 1 has printed the env block.
cd ~/work/flamingo
cargo build -p flamingo-verifier-host --features mock-enclave
set -a; source ~/work/world-id-protocol/target/local-e2e.env; set +a
cargo run -p flamingo-verifier-host --features mock-enclave
```

Terminal 1 starts anvil on a fixed mnemonic, deploys the registry, the token, and the escrow
behind its proxy, registers an RP, opens a channel, funds epoch 0, and writes
`target/local-e2e.env`. It then polls the host's `/ready` until it answers, drives the funded
units through `POST /v1/matches`, checks that the next one is refused as `capacity_exhausted`,
verifies every signature in `error.details.authorizations` against the RP's own spend key, funds
more, drives one more unit, and prints a summary.

`ENCLAVE_MODE=mock` answers matches from a hash, so the ciphertext is a placeholder and nothing
is attested. The host does not settle on chain in this version, so no lane mark is ever raised:
the harness closes the epoch itself with an empty `settle`, which pays the collector the whole
funded amount.
