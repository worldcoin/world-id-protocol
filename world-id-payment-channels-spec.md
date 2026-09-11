#1937260 World ID payment channels

Design draft · 9 September 2026 · Proposed specification, not an implementation.

## 1. Scope

This specification defines monthly escrow, signed `ProofRequest` payment authorization, cumulative settlement, and refunds. Host behavior and solvency verification are out of scope.

An RP or its approved payer deposits the quoted cap `B` for one channel. Each payment authorizes a cumulative count in one lane of that channel. Anyone may submit it before the collection deadline; the contract pays only that channel's fixed collector. Afterward, anyone may trigger a refund to its payer.

A lane is an independent monotonic counter, identified by `laneId`. The two-dimensional payment nonce is `(laneId, count)`, scoped to the channel. The channel fixes its lane count at opening.

## 2. Existing request authorization

The existing [`ProofRequest`](crates/primitives/src/request/mod.rs) has an RP ID, random identity nonce, timestamps, optional action, and one signature. Its current signing digest is SHA-256 over [`compute_rp_signature_msg`](crates/primitives/src/rp.rs):

`0x01 || nonce[32] || created_at[8] || expires_at[8] || action[32, if present]`

Integers use big-endian encoding. This commits to those authorization fields, not the whole request. Section 6 uses it as an inner digest under a new shared identity-and-payment signature. The `0x01` prefix remains part of that inner encoding; the upgraded request version is V2.

## 3. Pricing

A pricing authority quotes a positive cap `B` for a channel identified by `(rpId, periodStart)`. `B` is that channel's total fee cap and initial deposit, in the escrow token's smallest units. The escrow fixes positive `T`, the cumulative count at which a channel reaches half its cap before rounding. Each count increment authorizes one billing unit.

The authority uses proposed seats and expected usage to set `B`. It is the total channel cap, not a per-seat price or per-lane allowance. Channels in one escrow share `T` and token but may have different caps. `T` does not scale with seats: every channel reaches half its own cap at the same count. Seat enforcement and estimation are out of scope. The RP manager approves the quote before funding.

All notation below is scoped to one channel. For its lane `i`, `P_i` is the highest settled count. Let `N = Σ P_i` over that channel's lanes. Its cumulative fee is:

`A(0) = 0`

`A(N) = ceil(B × N / (T + N))`

At `N = T`, the unrounded fee is `B/2`; at `9T`, it is `0.9B`. Settlement pays only the increase in `A(N)`. Use full-precision multiplication and division, checked addition, and bounded counts. Round the cumulative fee, not individual requests. Batch size and settlement order must not change the final bill.

Every lane in a channel shares its `B`; increasing the selected lane count does not multiply the cap. Some count increases add no fee after rounding; signed requests are still required. The curve reaches `B` when `N > (B−1) × T`, if count bounds permit it. No per-request minimum applies.

## 4. Channel settings

Shared settings are immutable at escrow deployment:

```solidity
struct EscrowSettings {
    address pricingSigner;
    address token;
    address collector;
    uint256 halfCapAttempts;
    uint64 collectionPeriod;
    uint32 maxLaneCount;
}
```

Opening fixes only the channel-specific settings:

```solidity
struct ChannelSettings {
    uint64 rpId;
    uint64 periodStart;
    address payer;
    address spendKey;
    uint256 cap;
    uint32 laneCount;
}
```

`ChannelSettings.cap` is the quoted `B`, without multiplying by seats or lanes. `EscrowSettings.halfCapAttempts` is `T`. Derive deadlines from `periodStart` and the fixed collection period. Opening verifies the quote; no on-chain quote registration is required.

`rpId` matches the registry's `uint64`. `periodStart` is the Unix timestamp at 00:00:00 UTC on the first day of the billing month; reject other timestamps. `payer = msg.sender` at opening; it supplies the deposit and receives refunds. `spendKey` is the fixed nonzero secp256k1 key appointed by RP-manager consent to authorize channel spending. Require `0 < laneCount <= maxLaneCount`; valid lane IDs are `0..laneCount−1`.

`channelId = keccak256(abi.encode(chainId, contractAddress, rpId, periodStart))`

Allow one channel per RP and month in the approved escrow deployment. A refund does not free the ID. Quotes bind the deployment through their signature domain. Only one deployment may be approved for a given RP and month; that deployment-selection rule is external to each escrow. New versions start in a later month.

Derive `acceptUntil` as the next UTC calendar month's start, not a fixed number of seconds after `periodStart`. Derive `claimUntil = acceptUntil + collectionPeriod` with checked arithmetic. Opening is allowed for the current or next month before `acceptUntil`. Settlement is allowed from `periodStart` until `claimUntil`; refunds start at `claimUntil`. Request expiry remains part of World ID authorization and does not revoke a signed payment.

The full channel cap is funded at opening. There are no topups, early withdrawals, added lanes, or changes to the channel's `spendKey`. The contract stores `N`, refund status, and settled counts `P_i` per channel, defaulting to zero. It derives payment as `A(N)`; no lane initialization loop is needed.

## 5. Opening, settlement, and refunds

### Contract interface

`SettlementClaim` carries the signed fields from `ProofRequest` and its existing signature, using the hash defined in §6. `msg.sender` is the payer at opening; smart-contract wallets call through their own execution method. Before opening, the payer approves the escrow to transfer `B` of the pricing rules' token. None of these functions accepts native currency.

```solidity
struct FeeQuote {
    uint64 rpId;
    uint64 periodStart;
    uint256 cap;
}

struct RpConsent {
    /// Unix timestamp after which setup consent is invalid.
    uint64 expiry;
    /// Current RP registry nonce at opening.
    uint256 registryNonce;
    /// Manager's EIP-712 signature; supports ERC-1271 managers.
    bytes signature;
}

struct SettlementClaim {
    bytes32 channelId;
    uint64 rpId;
    uint96 paymentNonce;
    bytes32 rpRequestDigest;
    bytes signature;
}

interface IWorldIDFeeChannel {
    /// @notice Opens and fully funds one RP's monthly channel.
    /// @param quote Pricing terms for an active RP and the current or next month.
    /// @param pricingSignature Pricing authority's EIP-712 signature over the quote.
    /// @param spendKey Nonzero current registry signer; must have no deployed code.
    /// @param laneCount Fixed number of lane slots, for independent counters; bounded by pricing rules.
    /// @param rpConsent Manager signature, expiry, and current registry nonce for this setup.
    function openChannel(
        FeeQuote calldata quote,
        bytes calldata pricingSignature,
        address spendKey,
        uint32 laneCount,
        RpConsent calldata rpConsent
    ) external;

    /// @notice Records higher lane counts and pays the collector; callable by anyone.
    /// @param channelId Unrefunded channel whose collection window is open.
    /// @param claims Signed request projections using the original signature; at most one per lane.
    function settle(
        bytes32 channelId,
        SettlementClaim[] calldata claims
    ) external;

    /// @notice Returns unused funds to the recorded payer once; callable by anyone.
    /// @param channelId Existing, unrefunded channel at or after claimUntil.
    function refund(bytes32 channelId) external;
}
```

`quote.rpId` and `quote.periodStart` identify the channel; `quote.cap` sets its `B`. The pricing signer signs `FeeQuote(uint64 rpId,uint64 periodStart,uint256 cap)` in the EIP-712 domain from §6. The domain binds the immutable escrow settings. Verify against `pricingSigner` and require `cap > 0`. The quote has no separate expiry: opening closes at `acceptUntil`.

At deployment, require nonzero signer, token, and collector, and positive `T`, collection period, and maximum lane count. Use a supported exact-transfer token. At opening, validate the month boundary, selected lane count, and derived deadline bounds.

At deployment, let `N_max = uint256(maxLaneCount) × type(uint64).max` and require `T <= type(uint256).max − N_max`, so every valid channel fits `T + N`. Use full-precision rounded-up multiplication/division for `B × N / (T + N)`; do not compute `B × N` in a single `uint256` first.

The manager signs `OpenChannel(bytes32 quoteDigest,address payer,address spendKey,uint32 laneCount,uint64 expiry,uint256 registryNonce)` in that same domain. `quoteDigest` is the quote's full EIP-712 digest, `payer` is `msg.sender`, and expiry and nonce come from `rpConsent`. Require `t <= rpConsent.expiry` and `rpConsent.registryNonce == nonceOf(quote.rpId)`. This binds consent to the exact quote and prevents substitution of the payer, key, or lane count.

`settle` accepts a nonempty batch within the batch limit. Every `claim.channelId` must equal `channelId` and `claim.rpId` must equal the channel's RP. Decode `laneId` and `count` from `paymentNonce` as specified in §6; require `laneId < laneCount`. Invalid entries revert the entire batch. These functions have no return values; `refund` transfers the amount defined below.

### Open and fund

`openChannel(quote, pricingSignature, spendKey, laneCount, rpConsent)` verifies the pricing quote and RP consent, then transfers funds from the caller.

Require an active RP and verify consent from `getRp(quote.rpId).manager` using the registry's checks for [ordinary and smart-contract wallets](contracts/src/core/RpRegistry.sol), including ERC-1271. Before recording the channel or transferring funds, require `spendKey != address(0)`, `spendKey == getRp(quote.rpId).signer`, and `spendKey.code.length == 0`. Reject mismatched keys and all code-bearing request signers. The [request signing key](contracts/src/core/interfaces/IRpRegistry.sol) alone cannot authorize opening.

This gate deliberately excludes WIP-101 contract request signers, including contracts that also support ERC-1271. The registry has no separate authorization-mode field; the gate rejects all deployed signer code instead of assuming that manager consent establishes ECDSA compatibility. Contract managers and funding wallets remain supported. The code check is made at opening; later registry or account-code changes may interrupt identity requests but cannot invalidate previously signed settlement claims.

Accept only the current or next month and require `t < acceptUntil`. Reject an existing channel. A deposit without RP consent cannot reserve another RP's monthly channel. Registry changes invalidate unused setup consent but preserve payment authorizations in an already opened channel.

The pricing signer has no withdrawal or channel-update authority. A quote remains usable until its month's end; issuing a newer quote does not revoke an older one for that month. One channel per RP and month prevents repeated opening. Changing shared settings requires a new approved escrow deployment for a later month. Existing channels retain their terms. The quote signature is setup-only; each request still has one signature.

Transfer exactly `quote.cap` of the escrow's token from the caller for this channel; all its counts initially read as zero. Its unused balance is refundable only to the recorded payer.

Support only approved tokens that transfer the exact requested amount. Reject unsupported behavior, including transfer fees or automatic balance changes. Prevent token callbacks from re-entering the contract during a transfer. Check and save the required account changes before transferring funds. Track each channel's balance separately; an unsolicited token transfer does not increase its cap.

### Settle

Anyone may call `settle(channelId, claims)` to submit signed payment authorizations. It pays only the recorded billing recipient. Limit the number of entries and reject repeated lane IDs. Let `N_old` be the channel's stored work total before this batch:

1. Verify every request signature's domain, fixed spending key, channel ID, RP ID, and decoded lane range. Require `periodStart ≤ t < claimUntil` and an unrefunded channel.
2. Require each `count > P_i` within the count bound. Compute `N_new = N_old + Σ(count − P_i)` with checked arithmetic.
3. Set each `P_i = count` and `N = N_new` before transfer.
4. Pay `delta = A(N_new) − A(N_old)` to the fixed billing recipient. When `delta = 0`, update counts without a token transfer. Transfer failure reverts the transaction.

A batch either succeeds in full or changes nothing. An old count rejects; callers refresh settled counts before rebuilding the batch. The contract applies the quoted curve to this channel's total across its lanes. Claims may arrive in any order without changing its final bill. Other channels' counts, caps, and balances are unaffected.

The request signature alone authorizes payment under the fixed pricing rules. A signed jump from 10 to 100 authorizes a count of 100 without proving that 90 requests occurred. Signers must retain their highest signed count and never sign conflicting requests at the same count.

### Refund

Anyone may call `refund(channelId)` at `t ≥ claimUntil`. It sends only to `payer` and closes the channel once. Return:

`refund = B − A(N)`

Mark the channel refunded before transfer. Settlement and refunds cannot occur in the same time window. Failed or missing work does not allow early withdrawal or cancel signed payments.

Use an escrow contract whose code cannot be changed and whose administrators cannot take deposited funds. Changes require a new contract version; existing channels keep their collection and refund rules. The repository normally uses [upgradeable proxy contracts](contracts/README.md), so this exception requires approval before implementation.

## 6. Payment extension for ProofRequest

Add two fields to `ProofRequest` under a new request version. Keep its existing random identity nonce and single `signature` field. These are proposed additions, not implemented Rust changes:

```rust
// New fields in the upgraded ProofRequest.
pub channel_id: B256,
pub payment_nonce: U96,
```

`B256` and `U96` are Alloy primitive types. For settlement, copy the signed fields and existing signature into `SettlementClaim` from §5. It is a transport struct, not a separately signed message.

`rpRequestDigest` is the SHA-256 digest of the existing authorization fields defined in §2. Compute it with a separate helper after upgrading `digest_hash()` to return the new signing digest; do not recursively call the upgraded method. It does not commit to later biometric inputs, OPRF queries, or execution results. Require `request.rp_id == channel.rpId` and `claim.rpId == channel.rpId`.

Sign once using EIP-712 with domain `name = WorldIDFeeChannel`, `version = 2`, chain ID, and escrow address. Store that signature in `ProofRequest.signature`; `SettlementClaim.signature` copies the same bytes. Both verifiers use this exact type string, excluding the signature field:

```text
ProofRequest(bytes32 channelId,uint64 rpId,uint96 paymentNonce,bytes32 rpRequestDigest)
```

Both identity and settlement verifiers use this same typed hash. Opening requires the current registry signer to equal the channel's fixed `spendKey`. Identity verification checks current RP authorization; settlement recovers the fixed key without querying mutable registry or contract-signature policies. Reject invalid signatures, unsupported encodings, and zero-address recovery.

The existing [WIP-101 verification path](services/oprf-node/src/auth/rp_module/wip101.rs) does not supply this shared ECDSA authorization and does not cover the new channel fields. Supporting it requires a separate protocol upgrade; §5 rejects its contract signers before funding rather than accepting unusable channels.

Pack the nonce with the lane in the high 32 bits and count in the low 64 bits:

```solidity
uint96 paymentNonce = (uint96(laneId) << 64) | uint96(count);
uint32 laneId = uint32(paymentNonce >> 64);
uint64 count = uint64(paymentNonce);
```

Validate widths before packing; never truncate oversized inputs. Require `laneId < laneCount` and `count > 0`. Compare counts within a lane, not packed nonces across lanes. `channelId` and `paymentNonce` occupy 44 bytes in packed transport, but two 32-byte words under standard ABI and EIP-712 encoding.

Keep `channelId` signed. One open channel at a time would not prevent replay after renewal resets counts. The signed channel ID binds the RP and month; the domain also binds chain and escrow. Current and next month's channels may coexist.

The payment nonce starts at `(laneId, 1)`. Counts increase independently per lane; settlement accepts a higher cumulative count without requiring intermediate requests. Replaying a settled count adds no liability and is rejected. Signing two requests at the same count does not authorize two billing units.

A `ProofRequest` may lead to several service operations. The billing protocol does not infer their number from the request. Additional billing units require signed count increases; multiple signed requests may reference the same inner RP authorization digest.

The contract receives the compact authorization and the same request signature. It does not receive the full `ProofRequest` or service output, or repeat identity validation. Settlement remains valid after request expiry or registry changes because it checks the fixed `spendKey`.

This requires a new `RequestVersion` and upgrades to request signing, `digest_hash()`, and identity signature verifiers. Current V1 requests remain identity-only and cannot authorize channel spending. Never accept a legacy signature as covering the new fields or fall back to V1 after V2 verification fails. Existing identity checks and result formats otherwise remain unchanged.

## 7. Guarantees and limits

The appointed payment signer's signature authorizes spending from the identified channel, not the payer's wallet or another channel. All lanes in that channel share its cap. Settled counts do not reveal outstanding signed authorizations.

For each channel independently, preserve `N = Σ P_i` and:

`B = escrow remaining + paid + refunded`

For a channel with `B = 1,000` and `T = 90`, settling a total of ten units pays 100. If no further units settle, its remaining 900 is refundable after the collection deadline. Missing work does not cancel authorization. A second channel has its own quote and accounting.

Submit the highest authorization per lane before `claimUntil`, including zero-fee updates. Missing the deadline loses collection rights.

Settlement publishes the RP's channel, month, lane counts, and RP authorization digests. It publishes neither the full request nor identity inputs. An expired request remains payable. A compromised `spendKey` exposes the remaining deposits of all channels that appointed it. Registry signer rotation cannot revoke old payment authorizations, but the new signer cannot spend an existing channel; identity and payment remain jointly usable only while their signer requirements match.

Subscription seats, operation pricing policy, and payment enforcement are outside this protocol. World ID request signing changes under §6; other identity checks and signed results are unchanged.

## 8. Checks before implementation

1. Verify fee rounding, order-independent settlement, overflow bounds, zero-fee updates, and isolation of channels with different caps under the shared settings.
2. Verify lane bounds, cumulative jumps, duplicate claims, cross-channel replay, signature validation, and atomic token transfers.
3. Verify pricing signatures, month boundaries including leap years, consent expiry, and rejection of zero, mismatched, or code-bearing signers before funding; include WIP-101 and ERC-1271 fixtures.
4. Add cross-language vectors for the inner RP digest and shared V2 EIP-712 hash; test nonce packing boundaries, mismatched RPs, and channel substitution.
5. Add setup hash vectors; test V1/V2 separation, duplicate opening, one-time refunds, older quotes, and claim rights after expiry, registry rotation, or signer-code changes.

Implementation tests have not been run.

## Sources

- Request types and digest: [ProofRequest](crates/primitives/src/request/mod.rs), [RP signing message](crates/primitives/src/rp.rs), and [OPRF nonce scope](services/oprf-node/src/auth/nonce_history.rs).
- Setup authority: [RP registry interface](contracts/src/core/interfaces/IRpRegistry.sol) and [RP registry](contracts/src/core/RpRegistry.sol).
- Design inputs: [Sharded Payment Channels](https://app.notion.com/p/worldcoin/Sharded-Payment-Channels-for-World-ID-Fees-3608614bdf8c80feb28edbf3f69ffb6c) and [WIP-107](https://app.notion.com/p/worldcoin/WIP-107-Experimental-Transactional-Fees-4448614bdf8c825ab782015d3587d6aa).
