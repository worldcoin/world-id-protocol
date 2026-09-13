# world-id-fee-escrow

Fixed-rate epoch payment channels: the standalone `Payment` object, the RP's stateless
predecessor check, and the collector's nonce and admission ledger.

- `typed_data` — the EIP-712 domain, `ChannelSettings` (whose digest is the `channelId`), and
  `PaymentAuthorization(bytes32 channelId,uint64 epoch,uint96 channelNonce)`, with
  canonical-signature recovery and the epoch arithmetic.
- `nonce` — `LaneNonce`, `lane << 64 | counter`, packed into the escrow's `uint96` and
  serialised as a hex string, never a JSON number.
- `payment` — `Payment::sign`, `Payment::verify`, and `verify_predecessor`.
- `collector` — `Ledger`: `reserve`, `record`, `admit`, `refusal_proof`, `settlement_batch`.

A `Payment` names no request, so `ProofRequest` and every party that verifies it are untouched.
It is a bearer authorisation for one unit: whoever presents it first consumes it, and a repeat
is refused as `already_admitted`. Binding a payment to one request is deferred to a later
version, which would add the request digest to the signed struct.

Capacity is read through the `ChainView` trait, which must fail rather than guess, so a stale or
unavailable chain read refuses work instead of serving it. `Ledger` is in-memory and
single-process; production needs durable state serialised per `(channel, epoch)`.

```bash
cargo test -p world-id-fee-escrow                 # unit tests and the cross-language vectors
forge build --root contracts                      # required once for the e2e artifacts
cargo test -p world-id-fee-escrow --features e2e  # anvil end to end, needs `anvil` on PATH
```
