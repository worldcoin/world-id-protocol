# world-id-fee-escrow

POC of the YABS spec: a World ID `ProofRequest` extended with a payment authorisation against a
`WorldIDFeeEscrow` channel, plus the RP-side nonce allocator and the collector's solvency ledger.

- `typed_data` — EIP-712 `OpenChannel` / `PaymentAuthorization` payloads and `channel_id`.
- `nonce` — `LaneNonce` (`lane << 64 | counter`, serialised as a hex `uint96`) and `NonceAllocator`.
- `request` — `ProofRequestV2`: `ProofRequest` plus flattened `channel_id` / `channel_nonce`.
- `collector` — `Ledger::admit`, which verifies the request then checks the channel can pay.

POC decisions: `verify` never falls back to V1 EIP-191 recovery; the ledger and the allocator are
in-memory and single-process, so production needs durable, serialised state on both sides; the
ledger charges on Σ lane high-water marks, matching the escrow.

```bash
cargo test -p world-id-fee-escrow                 # unit tests, no contracts needed
forge build --root contracts                      # required once for the e2e bindings
cargo test -p world-id-fee-escrow --features e2e  # anvil end-to-end, needs `anvil` on PATH
```
