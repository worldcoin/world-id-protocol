  This project demonstrates a PoC for the Address Verification spoofing in World ID Protociol's `AccountRegistry` smart contract.



Anyone can create and claim that any Ethereum address is one of their "authenticators" without proving their address ownership. The contract forgets to check signatures during account creation, so an attacker can hijack your address for their account.



## Key idea (in plain words)

- An "authenticator address" should be a wallet that proves: "I agree to be an authenticator for this new account."  
- Proving this normally means the wallet signs a message (an ECDSA signature).  
- In `createAccount` and `createManyAccounts`, the contract never checks those signatures.  
- Result: Any attacker can submit your address as an authenticator and the contract will accept it.

##Files involved:
- `contracts/src/AccountRegistry.sol` — functions `createAccount` and `createManyAccounts` miss signature verification.
- Tests: `contracts/test/AddressVerificationSpoofing.t.sol` demonstrate it live.

### Affected Code

- `contracts/src/AccountRegistry.sol` (Line 232-241): `createAccount()`
- `contracts/src/AccountRegistry.sol` (Line 249-278): `createManyAccounts()`



image.png


### Commands Executed (WSL)

Executed from Windows PowerShell using WSL.

- Verify forge and run tests:
   - `/root/.foundry/bin/forge --version`
   - `cd /mnt/d/aabb/worldcoin/world-id-protocol/contracts && /root/.foundry/bin/forge test --match-path test/AddressVerificationSpoofing.t.sol -vvv




###What's actually happening

- Attacker picks others address.
- Attacker calls `createAccount` with others address but NO signature.
- Contract DOES NOT VERIFY ownership.
- Contract links your address to attacker’s account.

ASCII flow:

```
[Attacker Wallet]
     │  (no signature at all)
     ▼
[Tx: createAccount(victimAddress, ...)]
     │
     ▼
[AccountRegistry]
  ├─ verify signature?  ❌ (step missing)
  └─ update state: link victim address  ❌ (shouldn’t happen)
```



Note: The vulnerability ONLY affects account creation functions.