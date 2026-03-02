# AddressBook Spec (World ID 4.0)

## Purpose

`AddressBook` is an on-chain soft cache for World ID proof verification results on World Chain.

The goal is to amortize expensive ZK proof verification:

- First interaction for an action/account: full proof verification via `WorldIDVerifier.verify(...)`
- Subsequent interactions for the same action/account: storage lookup via `verify(...)`

## Scope Model

The cache scope key is:

- `action`

`EpochData` is:

- `action: uint256`

The storage key is:

- `epochId = bytes32(action)`

Period is still computed as:

- `period = floor((block.timestamp - periodStartTimestamp) / periodLengthSeconds)`

Period is used for registration policy and expiry checks (not for the storage key).

Reverts:

- `PeriodNotStarted()` if `block.timestamp < periodStartTimestamp`
- `PeriodOutOfRange()` if computed period does not fit `uint32`

## Contract Shape

Implementation:

- `contracts/src/address-book/AddressBook.sol`
- Interface: `contracts/src/address-book/interfaces/IAddressBook.sol`

Pattern:

- UUPS upgradeable through `WorldIDBase`
- Non-pure external functions use `onlyProxy` + `onlyInitialized`

## Storage

- `mapping(bytes32 => mapping(address => bool)) _epochAddressRegistered`
- `mapping(bytes32 => mapping(uint256 => bool)) _epochNullifierUsed`

Interpretation:

- One address can be registered at most once per `epochId` (action)
- One nullifier can be used at most once per `epochId` (action)

## Registration

### Inputs

- `account`: address to register
- `targetPeriod`: period being registered
- `epoch`: `{action}`
- `proof`: World ID proof payload:
  - `nullifier`
  - `rpId`
  - `nonce`
  - `expiresAtMin`
  - `issuerSchemaId`
  - `credentialGenesisIssuedAtMin`
  - `zeroKnowledgeProof`

### Authorization

- Function: `register(account, targetPeriod, epoch, proof)`
- Any caller may register any `account` (no account-signature requirement).

### Validation Sequence

For successful registration, all checks must pass:

1. `account != address(0)` else `InvalidAccount()`
2. Current period computed (period start/range checks)
3. If `enforceCurrentOrNextPeriod == true`:
   - `targetPeriod == currentPeriod` OR `targetPeriod == currentPeriod + 1`
   - otherwise `InvalidTargetPeriod(targetPeriod, currentPeriod)`
4. `proof.expiresAtMin` must cover full target period:
   - `proof.expiresAtMin >= periodStartTimestamp + (targetPeriod + 1) * periodLengthSeconds`
   - otherwise `ExpirationBeforeEpochEnd(expiresAtMin, epochPeriodEnd)`
5. `nullifier` unused for computed `epochId` else `NullifierAlreadyUsed(...)`
6. `account` not registered for computed `epochId` else `AddressAlreadyRegistered(...)`
7. On-chain proof verification via `WorldIDVerifier.verify(...)` with:
   - `action = epoch.action`
   - `rpId = proof.rpId`
   - bound `signalHash`
8. Persist:
   - `_epochNullifierUsed[epochId][nullifier] = true`
   - `_epochAddressRegistered[epochId][account] = true`
9. Emit `AddressRegistered(...)`

## Verification

### Fast path

- `verify(epoch, account) -> bool`
- Computes `currentPeriod` and checks `_epochAddressRegistered[epochId(action)][account]`

### Explicit period lookup

- `isRegisteredForPeriod(period, epoch, account) -> bool`
- Uses the same action key (`period` does not affect `epochId`)

### Expiration Semantics

Registrations are not deleted and do not auto-expire by period in storage.
If period-scoped behavior is desired, action values should be period-specific.

## Signal Binding

To bind proof to the registered account:

- Canonical signal string:
  - `"<accountHex>"`

- Signal hash:
  - `signalHash = uint256(keccak256(bytes(signal))) >> 8`

This is intentionally aligned with the authenticator pipeline:

- `RequestItem.signal` is UTF-8 bytes
- `signal_hash` uses `FieldElement::from_arbitrary_raw_bytes(signal.as_bytes())`

Implication:

- A proof generated for one account signal cannot be reused to register a different account.

## Admin Controls

Owner-only:

- `updateWorldIDVerifier(newVerifier)`
- `setEnforceCurrentOrNextPeriod(enabled)`

## Security Invariants

1. **Per-action nullifier uniqueness**
- A nullifier can be consumed only once within the same `epochId` (action).

2. **Per-action address uniqueness**
- The same account cannot be re-registered in the same `epochId` (action).

3. **Proof/account binding**
- `signalHash` binds the proof to the registered account.

4. **Permissionless registration**
- Third parties may register an account if they provide a valid proof bound to that account signal.

5. **Target-period expiry floor**
- Registration requires `expiresAtMin` to be at least the end of the target period.

## E2E Flow

Assume:

- `periodLengthSeconds = 30 days`
- `epoch = {action: A_JAN}`
- Current period at start is `P=10` (January)

### 1) Initial registration (January)

1. A prover obtains a valid World ID proof for `(rpId=42, action=A_JAN)` with signal equal to `computeSignal(10, epoch, userAddress)`.
2. Any caller submits:
   - `register(userAddress, 10, epoch, proof)`
3. Contract verifies proof and stores:
   - `registered[epochId(A_JAN)][userAddress] = true`
4. Contract enforces `proof.expiresAtMin` is at least end-of-period for period `10`.

### 2) Repeated checks

1. RP calls `verify(epoch, userAddress)`.
2. Contract checks action key `epochId(A_JAN)` and returns `true`.
3. No new ZK verification needed for this check.

### 3) Optional pre-registration

If `enforceCurrentOrNextPeriod` is enabled, users may still register for `current` or `next` period only.

Example while current is `10`:

- allowed: `targetPeriod = 10` or `11`
- rejected: `targetPeriod >= 12`

## Integration Notes for RPs / Authenticators

1. For registration proofs, use `RequestItem.signal = computeSignal(targetPeriod, epoch, account)` (account hex string).
2. Provide `rpId` in the `RegistrationProof` payload.
3. Use `register(...)` for all flows (no signature relay API).
4. Use `verify(...)` for cheap action/account checks.

## Test Coverage

Reference tests:

- `contracts/test/address-book/AddressBook.t.sol`
- `contracts/test/address-book/AddressBookUpgrade.t.sol`

Covered behaviors include:

- current/next period guard and overflow edge (`uint32.max`)
- signal hash compatibility and account binding checks
- permissionless third-party registration
- target-period expiration floor checks
- nullifier/address uniqueness constraints
- UUPS upgrade state preservation
