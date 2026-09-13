# world-id-fee-escrow

The protocol side of fixed-rate epoch payment channels: the EIP-712 types the escrow verifies,
the `Payment` a relying party signs, and the stateless checks an RP makes before signing one.

- `typed_data` — the EIP-712 domain, `ChannelSettings` (whose digest is the `channelId`),
  `PaymentAuthorization(bytes32 channelId,uint64 epoch,uint96 channelNonce)`,
  `NonceReservation(bytes32 channelId,uint64 epoch,uint64 issuedAt)`, canonical-signature
  recovery, and the epoch arithmetic.
- `nonce` — `LaneNonce`, `lane << 64 | counter`, packed into the escrow's `uint96` and
  serialised as a hex string, never a JSON number.
- `payment` — `Payment::sign` and `verify`, plus `verify_predecessor` and `verify_reservation`.

This crate is the protocol, not a collector. It signs, verifies, and hashes; deciding what to
serve, holding lanes, and settling are a collector's business.

A `Payment` names no request, so `ProofRequest` and every party that verifies it are untouched.
It is a bearer authorisation for one unit: whoever presents it first consumes it. Binding a
payment to one request is deferred to a later version, which would add the request digest to the
signed struct.

```bash
cargo test -p world-id-fee-escrow                 # unit tests and the cross-language vectors
forge build --root contracts                      # required once for the e2e artifacts
cargo test -p world-id-fee-escrow --features e2e  # anvil end to end, needs `anvil` on PATH
```
