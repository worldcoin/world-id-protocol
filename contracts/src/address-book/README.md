# AddressBook

`AddressBook` is an action-scoped soft-cache for World ID proof verification results.

## Core model

- Context: `EpochData { action }`
- Active period: computed from `periodStartTimestamp` and `periodLengthSeconds`
- Storage key: `epochId = bytes32(action)`

## Registration

`register(account, targetPeriod, epoch, proof)` verifies the World ID proof and stores the result under `epochId(epoch)`.

`proof` carries the verifier public inputs needed by `WorldIDVerifier`, including `rpId`.

Constraints:

- one nullifier per `epochId`
- one address per `epochId`
- optional registration guard for current/next period only
- `proof.expiresAtMin` must cover the full target period:
  - `expiresAtMin >= periodStartTimestamp + (targetPeriod + 1) * periodLengthSeconds`

## Verification

`verify(epoch, account)` checks only the current period:

- compute `currentPeriod`
- lookup `epochId(epoch)`

Since `epochId` is action-only, verification does not roll over by period unless action values themselves are period-specific.

## Signal binding

The canonical UTF-8 signal string is just the registered account address hex string:

`signal = "<accountHex>"`

`signalHash = uint256(keccak256(bytes(signal))) >> 8`

This matches the authenticator path (`RequestItem.signal` -> hash raw UTF-8 bytes) and binds the proof to the registered account.

## E2E example

Assume:

- `periodLengthSeconds = 30 days`
- `epoch = EpochData { action: A_JAN }`
- current period at start is `P=10` (January)

### 1) Initial registration in January

1. A prover gets a valid World ID uniqueness proof for `(rpId=42, action=A_JAN)` and `signal = userAddress`.
2. Any caller can submit registration:
   - `register(userAddress, 10, epoch, proof)`
3. Contract verifies proof through `WorldIDVerifier.verify(...)` and stores:
   - `registered[epochId(A_JAN)][userAddress] = true`
4. Contract enforces `proof.expiresAtMin` is at least the end of period `10`.

### 2) Repeated checks in January

1. RP calls:
   - `verify(epoch, userAddress)`
2. Contract computes current period (`10`) and checks `epochId(A_JAN)`.
3. Result is `true` with a cheap storage lookup (no new full proof verification).

### 3) February rollover

1. Time moves forward by one period; now current period is `11`.
2. RP calls again:
   - `verify(epoch, userAddress)`
3. Contract still checks `epochId(A_JAN)`.
4. Result remains `true` unless a different action is required.

### 4) Pre-register next period

If pre-registration is enabled by policy:

1. During period `10`, user can register for period `11`:
   - `register(userAddress, 11, EpochData{action: A_FEB}, proofForAFEB)`
2. Before rollover, `verify(EpochData{A_FEB}, userAddress)` is `true` once registered.
3. After rollover to period `11`, the same call returns `true`.

Notes:

- If `enforceCurrentOrNextPeriod` is `true`, registering for period `12+` while current is `10` reverts.
- The contract treats `action` as provided by the RP flow; for periodic behavior, actions should be period-specific.
