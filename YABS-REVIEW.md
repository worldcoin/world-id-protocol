# YABS review

Critique of `YABS.md` and the decisions the POC took. Ranked. B = blocking, M = major, m = minor.

## Blocking

**B1. The settlement math does not exist.** `closeChannel(channelId, bytes[] encodedProofRequests)` gives the escrow a bag of opaque bytes. Encoded how? On-chain JSON parsing is not an option. And `cumulativeFee(uint64 nonce)` takes one nonce while there are `laneCount` of them. Sum of lane maxima, max of them, or the count of submitted requests all price differently under any non-linear schedule. This is the function that moves money.
*POC:* on-chain unit is `PaymentAuthorization{uint96 channelNonce, bytes32 rpRequestDigest, bytes signature}`. Fee is `cumulativeFee(Σ lane high-water)`. Only the highest auth per lane is submitted. `settle` is incremental and permissionless; `close` is separate.

**B2. Nonce is not count, and the spec bills by nonce.** Requests get lost, retried, and signed by racing servers. If the RP signs 1..50 and the collector sees only 50, either the RP pays for 49 units nobody did, or the collector must submit every request and the escrow must keep a nonce set. The spec never chooses.
*POC:* pay by high-water. The RP bears gap risk because it controls its own nonce discipline.

**B3. The payer has no exit.** `ChannelSettings` has `periodStart` and nothing else about time or amount. The prose mentions a "collection deadline" the struct lacks. `closeChannel` has no stated caller. No top-up. A collector that vanishes locks funds forever.
*POC:* `collectionDeadline` in the signed settings. Settlement accepted until it, payer reclaims after it, collector may close and refund any time. `fund()` for top-ups. Deposit is a call argument so top-ups do not change the channel id.

**B4. One signature couples nullifier derivation to a payments contract.** OPRF nodes today verify EIP-191 over 49..81 bytes and know no contract. Under V2 the same signature is EIP-712 with `verifyingContract = escrow`, so every OPRF node must be configured with the escrow's chain id and address. Every escrow redeploy becomes an OPRF-node change.
*Alternative:* keep the V1 signature for the OPRF path and add a second payment signature. 65 bytes buys clean layering. The POC implements the single-signature design as written so the cost is visible.

## Major

**M1. A leaked spendKey drains the escrow until the deadline.** Settlement deliberately ignores registry rotation, so rotating the RpRegistry signer after a compromise does nothing for open channels. Needs a payer/manager freeze or a rotation cutoff. Not in the POC.

**M2. `periodStart` cannot be both RP-signed and contract-set.** The RP cannot know `block.timestamp` in advance; if the caller supplies it, it is untrusted. Identical settings also collide on `channelId`.
*POC:* drop `periodStart` from the signed struct, record `openedAt` in state, add `salt`.

**M3. Opening is underspecified four ways.** Which key signs consent (cold `manager` or hot `signer`)? Under what typehash and domain? Who is `msg.sender`? Where does the deposit amount come from?
*POC:* `spendKey` signs EIP-712 `OpenChannel(settings)`; `msg.sender == payer` and supplies `deposit`; the contract checks `spendKey` against the registry at open.

**M4. A `pure` function of count cannot price a month.** `cumulativeFee(uint64) pure` and a promised monthly seat schedule contradict each other. The external call can also revert forever if the schedule is buggy, which with B3 means locked funds.
The schedule is an external `view` call made on every settle and on close. A schedule backed by storage, an oracle, or a timestamp can price correctly for weeks and then start reverting; without protection that locks the deposit forever.
*POC:* `cumulativeFee(uint256) view`, must be monotonic. A "month" is a channel with a `collectionDeadline`. `closeChannel` wraps the schedule call in `try/catch` and refunds the payer in full if it fails (emits `FeeScheduleFailed`); `settle` stays strict.

**M5. A V2 request without payment has no signing rule.** The spec allows both channel fields to be absent and also forbids falling back to V1 after V2 verification fails. Both cannot hold unless V2 always means EIP-712, in which case a payment-free V2 request has no defined struct to sign. The natural reading, a dual path keyed on field presence, is the downgrade the spec warns against.
*POC:* `signing_hash` and `verify` return `NoPayment` for a V2 request with no channel fields. Decide before shipping.

**M6. Delivery order matters, not just allocation order.** The escrow and any collector require counters to arrive strictly increasing per lane. Two RP servers on one lane that sign 5 and 6 and deliver 6 first have spent 5 for nothing: signed, billed under high-water, never settleable. Building the demo forced this out.
*POC:* the nonce manager's lane lease spans allocation through delivery; the RP records the signed request only after the collector has answered.

**M7. The nonce management service is admitted to be broken.** It can equivocate, and two servers told "n" both sign n+1. Lanes already solve multi-server signing. Delete the section; a row per lane is an RP implementation detail.

## Minor

**m1. Types drift.** `channelNonce` is `u128` in Rust, `uint96` in the typehash, "< 2^96" in prose. camelCase JSON fields in a snake_case protocol. 96 bits do not fit a JSON number. `ProofRequestV2 { inner }` without `#[serde(flatten)]` nests the request and breaks the "unknown fields are ignored" compatibility the struct doc relies on.
*POC:* flattened `channel_id`, hex `channel_nonce`, `version: 2`, `uint96` on-chain, validated `LaneNonce` off-chain.

**m2. Names collide and versions invent history.** The typehash is called `ProofRequest(...)`. The domain is version "2" for a contract with no version 1; repo convention is "1.0".
*POC:* `PaymentAuthorization`, `WorldIDFeeEscrow/1.0`.

**m3. No events, no views.** Collectors need balance, paid, and per-lane high-water; indexers need events.
*POC:* `getChannel`, `laneHighWater`, `quote`, five events.

**m4. "Host solvency verification is out of scope."** It is the only thing the collector does and where every nonce ambiguity lands. Minimum: `cumulativeFee(settled + pending + 1) − paid ≤ balance`, with freshness checked against on-chain ∪ pending high-water.
*POC:* `collector::Ledger`.

**m5. `rpRequestDigest` is a weak commitment.** It covers nonce, timestamps and action only. Not `rp_id`, `proof_type`, `session_id`, `oprf_key_id`, or the requested credentials. `rpId` is added separately in the typed struct, so payment binds to an RP, but two materially different requests share a digest. Not exploitable on-chain today because the escrow never stores digests; it does mean the digest proves nothing about what work was paid for.

**m6. Loose ends.** `rpId` in the payment typehash is redundant with `channelId` (fine, but say why). Two dead Notion links. Design Tradeoffs is one sentence with a typo. No threat model, so the good property that a collector cannot inflate charges without RP signatures goes unstated.

## Keep

- Unidirectional channel is the right primitive.
- The collector cannot inflate charges; every billed unit needs an RP signature. State it as an invariant.
- Immutable per-channel schedule is a real commitment device.
- Permissionless collectors keep the market open.

## POC

- `contracts/src/core/interfaces/IWorldIDFeeEscrow.sol`, `IFeeSchedule.sol` — binding interface
- `contracts/src/core/WorldIDFeeEscrow.sol`, `FixedFeeSchedule.sol`, `TieredFeeSchedule.sol`
- `contracts/test/core/WorldIDFeeEscrow.t.sol`
- `crates/fee-escrow/` — `world-id-fee-escrow`: typed data, lane nonce, `ProofRequestV2` sign/verify, collector ledger, anvil e2e
- `crates/primitives/src/request/mod.rs` — `RequestVersion::V2` only
- `services/fee-channel-demo/` — `world-id-fee-channel-demo`: nonce manager, mock collector, RP service, one `flow::run` shared by the binary and `tests/flow.rs`

```
cd contracts && forge test --match-path 'test/core/WorldIDFeeEscrow.t.sol' -vvv   # 53 passed
cargo nextest run -p world-id-fee-escrow                                          # 32 passed
cargo nextest run -p world-id-fee-escrow --features e2e                           # 34 passed, incl. anvil e2e
cargo nextest run -p world-id-fee-channel-demo                                    # 7 passed, two full flows on anvil
cargo run -p world-id-fee-channel-demo                                            # watch the flow with tracing
```

The demo registers the RP, opens a 14 WLD channel with three lanes, runs three RP workers × six requests through the nonce manager and the mock collector, settles every five admissions, and closes after the deadline. Observed: 14 admitted, 4 refused 402 insolvent, 4 settlements, collector holds 14 WLD, nonce manager counters [6, 6, 6].

The e2e deploys RpRegistry, ERC20, FixedFeeSchedule and the escrow on anvil, checks `computeChannelId` and `openChannelHash` parity between Rust and Solidity, opens a 12e18 channel, signs 11 V2 requests over 2 lanes, admits 10 and rejects the 11th as insolvent, settles 10e18 with only the two highest auths, rejects a replay, then closes after the deadline for a 2e18 refund.
