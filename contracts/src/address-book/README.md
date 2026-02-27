# AddressBook

`AddressBook` is a period-scoped soft-cache for World ID proof verification results.

## Core model

- Context: `EpochData { rpId, action }`
- Active period: computed from `periodStartTimestamp` and `periodLengthSeconds`
- Storage key: `epochId = keccak256(abi.encode(period, rpId, action))`

## Registration

`register(account, targetPeriod, epoch, proof)` verifies the World ID proof and stores the result under `epochId(targetPeriod, epoch)`.

Authorization modes:

- direct mode: `msg.sender` must equal `account`
- relayer mode: `registerWithSignature(account, targetPeriod, epoch, proof, accountSignature)` where `accountSignature`
  is an EIP-712 signature by `account` over `(account, targetPeriod, rpId, action)` (digest helper: `computeRegistrationDigest(...)`)

Constraints:

- one nullifier per `epochId`
- one address per `epochId`
- optional registration guard for current/next period only

## Verification

`verify(epoch, account)` checks only the current period:

- compute `currentPeriod`
- lookup `epochId(currentPeriod, epoch)`

This means registrations automatically expire from `verify` after rollover.

## Signal binding

The contract defines a canonical UTF-8 signal string to bind proof context to account:

`signal = "world-id-address-book:v1:<chainId>:<contractAddressHex>:<epochIdHex>:<accountHex>"`

`signalHash = uint256(keccak256(bytes(signal))) >> 8`

This matches the authenticator path (`RequestItem.signal` -> hash raw UTF-8 bytes) and prevents proof reuse for a different account/context.

## E2E example

Assume:

- `periodLengthSeconds = 30 days`
- `epoch = EpochData { rpId: 42, action: A_JAN }`
- current period at start is `P=10` (January)

### 1) Initial registration in January

1. User gets a valid World ID uniqueness proof for `(rpId=42, action=A_JAN)`.
2. User signs registration authorization for `(account, period=10, rpId=42, action=A_JAN)`.
3. RP (or relayer) calls:
   - `register(userAddress, 10, epoch, proof)`
   - or `registerWithSignature(userAddress, 10, epoch, proof, accountSignature)`
4. Contract verifies proof through `WorldIDVerifier.verify(...)` and stores:
   - `registered[epochId(10, 42, A_JAN)][userAddress] = true`

### 2) Repeated checks in January

1. RP calls:
   - `verify(epoch, userAddress)`
2. Contract computes current period (`10`) and checks `epochId(10, 42, A_JAN)`.
3. Result is `true` with a cheap storage lookup (no new full proof verification).

### 3) February rollover

1. Time moves forward by one period; now current period is `11`.
2. RP calls again:
   - `verify(epoch, userAddress)`
3. Contract now checks `epochId(11, 42, A_JAN)`.
4. Result is `false` unless user registered for period `11`.

### 4) Pre-register next period

If pre-registration is enabled by policy:

1. During period `10`, user can register for period `11`:
   - `register(userAddress, 11, EpochData{rpId: 42, action: A_FEB}, proofForAFEB)`
2. Before rollover, `verify(EpochData{42, A_FEB}, userAddress)` is `false`.
3. After rollover to period `11`, the same call returns `true`.

Notes:

- If `enforceCurrentOrNextPeriod` is `true`, registering for period `12+` while current is `10` reverts.
- The contract treats `action` as provided by the RP flow; for periodic behavior, actions should be period-specific.
