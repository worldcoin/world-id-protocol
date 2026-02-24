# AddressBook Spec (World ID 4.0)

## Purpose

`AddressBook` is an on-chain soft cache for World ID proof verification results on World Chain.

The goal is to amortize expensive ZK proof verification by allowing cheap lookups during a scoped window:

- First interaction in scope: full proof verification via `WorldIDVerifier.verify(...)`
- Subsequent interactions in same scope: storage lookup via `verify(...)`

## Scope Model

The cache scope is:

- `period` (time window)
- `rpId`
- `action`

`EpochData` is:

- `rpId: uint64`
- `action: uint256`

The storage key is:

- `epochId = keccak256(abi.encode(period, rpId, action))`

Period is computed as:

- `period = floor((block.timestamp - periodStartTimestamp) / periodLengthSeconds)`

Reverts:

- `PeriodNotStarted()` if `block.timestamp < periodStartTimestamp`
- `PeriodOutOfRange()` if computed period does not fit `uint32`

## Contract Shape

Implementation:

- `contracts/src/address-book/AddressBook.sol`
- Interface: `contracts/src/address-book/interfaces/IAddressBook.sol`

Pattern:

- UUPS upgradeable through `WorldIDBase`
- EIP-712 domain in base (`name = "AddressBook"`, `version = "1.0"`)
- Non-pure external functions use `onlyProxy` + `onlyInitialized`

## Storage

- `mapping(bytes32 => mapping(address => bool)) _epochAddressRegistered`
- `mapping(bytes32 => mapping(uint256 => bool)) _epochNullifierUsed`

Interpretation:

- One address can be registered at most once per `epochId`
- One nullifier can be used at most once per `epochId`

## Registration

### Inputs

- `account`: address to register
- `targetPeriod`: period being registered
- `epoch`: `{rpId, action}`
- `proof`: World ID proof payload (`nullifier`, `nonce`, `expiresAtMin`, `issuerSchemaId`, `credentialGenesisIssuedAtMin`, `zeroKnowledgeProof`)

### Authorization Modes

1. Direct registration

- Function: `register(account, targetPeriod, epoch, proof)`
- Rule: `msg.sender == account`

2. Relayed registration

- Function: `registerWithSignature(account, targetPeriod, epoch, proof, accountSignature)`
- Rule: signature by `account` over EIP-712 digest for `(account, targetPeriod, rpId, action)`

Digest type:

- `RegisterAuthorization(address account,uint32 targetPeriod,uint64 rpId,uint256 action)`

Helper:

- `computeRegistrationDigest(account, targetPeriod, epoch) -> bytes32`

### Validation Sequence

For successful registration, all checks must pass:

1. `account != address(0)` else `InvalidAccount()`
2. Authorization valid else `InvalidAccountAuthorization()`
3. Current period computed (period start/range checks)
4. If `enforceCurrentOrNextPeriod == true`:
   - `targetPeriod == currentPeriod` OR `targetPeriod == currentPeriod + 1`
   - otherwise `InvalidTargetPeriod(targetPeriod, currentPeriod)`
5. `nullifier` unused for computed `epochId` else `NullifierAlreadyUsed(...)`
6. `account` not registered for computed `epochId` else `AddressAlreadyRegistered(...)`
7. On-chain proof verification via `WorldIDVerifier.verify(...)` with bound signal hash
8. Persist:
   - `_epochNullifierUsed[epochId][nullifier] = true`
   - `_epochAddressRegistered[epochId][account] = true`
9. Emit `AddressRegistered(...)`

## Verification

### Fast path

- `verify(epoch, account) -> bool`
- Uses **current** period only:
  - compute `currentPeriod`
  - lookup `_epochAddressRegistered[epochId(currentPeriod, epoch)][account]`

### Explicit period lookup

- `isRegisteredForPeriod(period, epoch, account) -> bool`

### Expiration Semantics

Registrations are not deleted, but `verify(...)` naturally expires previous periods because it always queries the current period key.

## Signal Binding

To bind proof to both context and registered account:

- Canonical signal string:
  - `"world-id-address-book:v1:<chainId>:<contractAddressHex>:<epochIdHex>:<accountHex>"`

- Signal hash:
  - `signalHash = uint256(keccak256(bytes(signal))) >> 8`

This is intentionally aligned with the authenticator pipeline:

- `RequestItem.signal` is UTF-8 bytes
- `signal_hash` uses `FieldElement::from_arbitrary_raw_bytes(signal.as_bytes())`

Implication:

- A proof generated for one `(period, rpId, action, account, contract, chain)` cannot be reused for another account/context in `AddressBook`.

## Admin Controls

Owner-only:

- `updateWorldIDVerifier(newVerifier)`
- `setEnforceCurrentOrNextPeriod(enabled)`

## Security Invariants

1. **Per-epoch nullifier uniqueness**
- A nullifier can be consumed only once within the same `epochId`.

2. **Per-epoch address uniqueness**
- The same account cannot be re-registered in the same `epochId`.

3. **Account-consent registration**
- Third parties cannot register a victim account via `register(...)`.
- Relayers must present a valid account signature via `registerWithSignature(...)`.

4. **Proof/account/context binding**
- `signalHash` binds account + epoch key + contract + chain.

5. **Automatic period expiry on verify**
- `verify(...)` returns `false` after period rollover unless re-registered for new period.

## E2E Flow

Assume:

- `periodLengthSeconds = 30 days`
- `epoch = {rpId: 42, action: A_JAN}`
- Current period at start is `P=10` (January)

### 1) Initial registration (January)

1. User obtains a valid World ID proof for `(rpId=42, action=A_JAN)` with signal equal to `computeSignal(10, epoch, userAddress)`.
2. User either:
   - calls `register(userAddress, 10, epoch, proof)` directly, or
   - signs `RegisterAuthorization(userAddress, 10, 42, A_JAN)` and a relayer calls `registerWithSignature(...)`.
3. Contract verifies proof and stores:
   - `registered[epochId(10, 42, A_JAN)][userAddress] = true`

### 2) Repeated checks (same period)

1. RP calls `verify(epoch, userAddress)`.
2. Contract checks current period key (`10`) and returns `true`.
3. No new ZK verification needed for this check.

### 3) Rollover (February)

1. Time advances to period `11`.
2. RP calls `verify(epoch, userAddress)`.
3. Contract now checks `epochId(11, 42, A_JAN)`.
4. Result is `false` unless user registered for period `11`.

### 4) Optional pre-registration

If `enforceCurrentOrNextPeriod` is enabled, users may still register for `current` or `next` period only.

Example while current is `10`:

- allowed: `targetPeriod = 10` or `11`
- rejected: `targetPeriod >= 12`

## Integration Notes for RPs / Authenticators

1. For registration proofs, the authenticator request must use `RequestItem.signal = computeSignal(targetPeriod, epoch, account)`.
2. Use `register(...)` when user is the caller.
3. Use `registerWithSignature(...)` for relayed flows.
4. Use `verify(...)` for cheap current-period checks.

## Test Coverage

Reference tests:

- `contracts/test/address-book/AddressBook.t.sol`
- `contracts/test/address-book/AddressBookUpgrade.t.sol`

Covered behaviors include:

- current/next period guard and overflow edge (`uint32.max`)
- signal hash compatibility and binding checks
- account authorization and relayed signature path
- nullifier/address uniqueness constraints
- rollover expiration semantics
- UUPS upgrade state preservation
