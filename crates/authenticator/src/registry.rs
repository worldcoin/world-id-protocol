//! Minimal World ID Registry contract bindings.
//!
//! This crate provides only the contract bindings and EIP-712 signing utilities.
//! It has no dependencies on other world-id crates to avoid circular dependencies.

use alloy::{
    primitives::{Address, Signature, U256},
    signers::{Signer, SignerSync},
    sol,
    sol_types::{Eip712Domain, SolStruct, eip712_domain},
};

sol!(
    /// The registry of World IDs. Each World ID is represented as a leaf in the Merkle tree.
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    WorldIdRegistry,
    "abi/WorldIDRegistryAbi.json"
);

sol!(
    /// V2 of the World ID registry: bundles the root-validity race-condition fix, WIP-104
    /// Proving Authenticators, and WIP-102 simplified optimistic Recovery Agent update
    /// (`updateRecoveryAgent` / `revertRecoveryAgentUpdate`). ABI is a superset of V1.
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    WorldIdRegistryV2,
    "abi/WorldIDRegistryV2Abi.json"
);

/// These structs are created in a private module to avoid confusion with their exports.
///
/// They are only used to compute the EIP-712 typed data for signature.
mod sol_types {
    use alloy::sol;

    sol! {
        /// EIP-712 typed-data payload for `updateAuthenticator`.
        ///
        /// This is used only for signature hashing/recovery, not as the Solidity call signature.
        struct UpdateAuthenticator {
            uint64 leafIndex;
            address oldAuthenticatorAddress;
            address newAuthenticatorAddress;
            uint32 pubkeyId;
            uint256 newAuthenticatorPubkey;
            uint256 newOffchainSignerCommitment;
            uint256 nonce;
        }

        /// EIP-712 typed-data payload for `insertAuthenticator`.
        ///
        /// This is used only for signature hashing/recovery, not as the Solidity call signature.
        struct InsertAuthenticator {
            uint64 leafIndex;
            address newAuthenticatorAddress;
            uint32 pubkeyId;
            uint256 newAuthenticatorPubkey;
            uint256 newOffchainSignerCommitment;
            uint256 nonce;
        }

        /// EIP-712 typed-data payload for `removeAuthenticator`.
        ///
        /// This is used only for signature hashing/recovery, not as the Solidity call signature.
        struct RemoveAuthenticator {
            uint64 leafIndex;
            address authenticatorAddress;
            uint32 pubkeyId;
            uint256 authenticatorPubkey;
            uint256 newOffchainSignerCommitment;
            uint256 nonce;
        }

        /// EIP-712 typed-data payload for `recoverAccount`.
        ///
        /// This is used only for signature hashing/recovery, not as the Solidity call signature.
        struct RecoverAccount {
            uint64 leafIndex;
            address newAuthenticatorAddress;
            uint256 newAuthenticatorPubkey;
            uint256 newOffchainSignerCommitment;
            uint256 nonce;
        }

        /// EIP-712 typed-data payload for `initiateRecoveryAgentUpdate`.
        ///
        /// Matches `INITIATE_RECOVERY_AGENT_UPDATE_TYPEHASH` on the contract:
        /// `InitiateRecoveryAgentUpdate(uint64 leafIndex,address newRecoveryAgent,uint256 nonce)`
        struct InitiateRecoveryAgentUpdate {
            uint64 leafIndex;
            address newRecoveryAgent;
            uint256 nonce;
        }

        /// EIP-712 typed-data payload for `cancelRecoveryAgentUpdate`.
        ///
        /// Matches `CANCEL_RECOVERY_AGENT_UPDATE_TYPEHASH` on the contract:
        /// `CancelRecoveryAgentUpdate(uint64 leafIndex,uint256 nonce)`.
        /// WIP-102 reuses this same typehash on `revertRecoveryAgentUpdate`
        /// entry point so pre-upgrade signatures remain valid post-upgrade.
        struct CancelRecoveryAgentUpdate {
            uint64 leafIndex;
            uint256 nonce;
        }
    }
}

/// EIP-712 typed-data signature payload for `updateAuthenticator`.
pub type UpdateAuthenticatorTypedData = sol_types::UpdateAuthenticator;
/// EIP-712 typed-data signature payload for `insertAuthenticator`.
pub type InsertAuthenticatorTypedData = sol_types::InsertAuthenticator;
/// EIP-712 typed-data signature payload for `removeAuthenticator`.
pub type RemoveAuthenticatorTypedData = sol_types::RemoveAuthenticator;
/// EIP-712 typed-data signature payload for `recoverAccount`.
pub type RecoverAccountTypedData = sol_types::RecoverAccount;
/// EIP-712 typed-data signature payload for `initiateRecoveryAgentUpdate`.
/// Also used by V2 `updateRecoveryAgent` (WIP-102 — reuses the V1 typehash).
pub type InitiateRecoveryAgentUpdateTypedData = sol_types::InitiateRecoveryAgentUpdate;
/// EIP-712 typed-data signature payload for `cancelRecoveryAgentUpdate`.
/// Also used by V2 `revertRecoveryAgentUpdate` (WIP-102 — reuses the V1 typehash).
pub type CancelRecoveryAgentUpdateTypedData = sol_types::CancelRecoveryAgentUpdate;

/// Returns the EIP-712 domain used by the `[WorldIdRegistry]` contract
/// for a given `chain_id` and `verifying_contract` address.
#[must_use]
pub const fn domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain!(
        name: "WorldIDRegistry",
        version: "1.0",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    )
}

/// Signs the EIP-712 payload for an `updateAuthenticator` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
#[allow(clippy::too_many_arguments)]
pub fn sign_update_authenticator<S: SignerSync + Sync>(
    signer: &S,
    leaf_index: u64,
    old_authenticator_address: Address,
    new_authenticator_address: Address,
    pubkey_id: u32,
    new_authenticator_pubkey: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = UpdateAuthenticatorTypedData {
        leafIndex: leaf_index,
        oldAuthenticatorAddress: old_authenticator_address,
        newAuthenticatorAddress: new_authenticator_address,
        pubkeyId: pubkey_id,
        newAuthenticatorPubkey: new_authenticator_pubkey,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash_sync(&digest)?)
}

/// Signs the EIP-712 payload for an `insertAuthenticator` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
#[allow(clippy::too_many_arguments)]
pub fn sign_insert_authenticator<S: SignerSync + Sync>(
    signer: &S,
    leaf_index: u64,
    new_authenticator_address: Address,
    pubkey_id: u32,
    new_authenticator_pubkey: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = InsertAuthenticatorTypedData {
        leafIndex: leaf_index,
        newAuthenticatorAddress: new_authenticator_address,
        pubkeyId: pubkey_id,
        newAuthenticatorPubkey: new_authenticator_pubkey,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash_sync(&digest)?)
}

/// Signs the EIP-712 payload for a `removeAuthenticator` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
#[allow(clippy::too_many_arguments)]
pub fn sign_remove_authenticator<S: SignerSync + Sync>(
    signer: &S,
    leaf_index: u64,
    authenticator_address: Address,
    pubkey_id: u32,
    authenticator_pubkey: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = RemoveAuthenticatorTypedData {
        leafIndex: leaf_index,
        authenticatorAddress: authenticator_address,
        pubkeyId: pubkey_id,
        authenticatorPubkey: authenticator_pubkey,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash_sync(&digest)?)
}

/// Signs the EIP-712 payload for a `recoverAccount` contract call.
///
/// The sign recover account uses the **async** `Signer` as this used
/// by Recovery Agents, who may implement different signing systems requiring
/// async processing. This is different from other operations that only
/// use a local keypair and can hence be done synchronously.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
pub async fn sign_recover_account<S: Signer + Sync>(
    signer: &S,
    leaf_index: u64,
    new_authenticator_address: Address,
    new_authenticator_pubkey: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = RecoverAccountTypedData {
        leafIndex: leaf_index,
        newAuthenticatorAddress: new_authenticator_address,
        newAuthenticatorPubkey: new_authenticator_pubkey,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash(&digest).await?)
}

/// Signs the EIP-712 payload for an `initiateRecoveryAgentUpdate` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
pub fn sign_initiate_recovery_agent_update<S: SignerSync + Sync>(
    signer: &S,
    leaf_index: u64,
    new_recovery_agent: Address,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = InitiateRecoveryAgentUpdateTypedData {
        leafIndex: leaf_index,
        newRecoveryAgent: new_recovery_agent,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash_sync(&digest)?)
}

/// Signs the EIP-712 payload for a `cancelRecoveryAgentUpdate` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
pub fn sign_cancel_recovery_agent_update<S: SignerSync + Sync>(
    signer: &S,
    leaf_index: u64,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = CancelRecoveryAgentUpdateTypedData {
        leafIndex: leaf_index,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash_sync(&digest)?)
}
#[cfg(test)]

mod tests {
    use super::*;
    use alloy::{
        primitives::{Address, U256, address},
        signers::local::PrivateKeySigner,
    };

    fn test_domain() -> Eip712Domain {
        domain(1, address!("0x1111111111111111111111111111111111111111"))
    }

    /// Verify that `sign_initiate_recovery_agent_update` produces a recoverable signature
    /// whose digest matches the contract's `INITIATE_RECOVERY_AGENT_UPDATE_TYPEHASH` struct.
    #[test]
    fn sign_initiate_recovery_agent_update_roundtrip() {
        let signer = PrivateKeySigner::random();
        let domain = test_domain();
        let leaf_index: u64 = 42;
        let new_recovery_agent: Address = address!("0x2222222222222222222222222222222222222222");
        let nonce = U256::from(7u64);

        let sig = sign_initiate_recovery_agent_update(
            &signer,
            leaf_index,
            new_recovery_agent,
            nonce,
            &domain,
        )
        .expect("signing must succeed");

        // Re-derive the digest and recover the address
        let payload = InitiateRecoveryAgentUpdateTypedData {
            leafIndex: leaf_index,
            newRecoveryAgent: new_recovery_agent,
            nonce,
        };
        let digest = payload.eip712_signing_hash(&domain);
        let recovered = sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(recovered, signer.address());
    }

    /// Verify that `sign_cancel_recovery_agent_update` produces a recoverable signature
    /// whose digest matches the contract's `CANCEL_RECOVERY_AGENT_UPDATE_TYPEHASH` struct.
    #[test]
    fn sign_cancel_recovery_agent_update_roundtrip() {
        let signer = PrivateKeySigner::random();
        let domain = test_domain();
        let leaf_index: u64 = 99;
        let nonce = U256::from(3u64);

        let sig = sign_cancel_recovery_agent_update(&signer, leaf_index, nonce, &domain)
            .expect("signing must succeed");

        let payload = CancelRecoveryAgentUpdateTypedData {
            leafIndex: leaf_index,
            nonce,
        };
        let digest = payload.eip712_signing_hash(&domain);
        let recovered = sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(recovered, signer.address());
    }

    /// Different leaf indices must produce different digests.
    #[test]
    fn sign_initiate_recovery_agent_update_different_leaf_indices() {
        let signer = PrivateKeySigner::random();
        let domain = test_domain();
        let new_recovery_agent: Address = address!("0x3333333333333333333333333333333333333333");
        let nonce = U256::ZERO;

        let sig1 =
            sign_initiate_recovery_agent_update(&signer, 1, new_recovery_agent, nonce, &domain)
                .unwrap();
        let sig2 =
            sign_initiate_recovery_agent_update(&signer, 2, new_recovery_agent, nonce, &domain)
                .unwrap();
        assert_ne!(sig1.as_bytes(), sig2.as_bytes());
    }

    /// Different nonces must produce different digests.
    #[test]
    fn sign_cancel_recovery_agent_update_different_nonces() {
        let signer = PrivateKeySigner::random();
        let domain = test_domain();

        let sig1 =
            sign_cancel_recovery_agent_update(&signer, 1, U256::from(0u64), &domain).unwrap();
        let sig2 =
            sign_cancel_recovery_agent_update(&signer, 1, U256::from(1u64), &domain).unwrap();
        assert_ne!(sig1.as_bytes(), sig2.as_bytes());
    }

    #[tokio::test]
    async fn sign_recover_account_roundtrip() {
        let signer = PrivateKeySigner::random();
        let domain = test_domain();
        let leaf_index: u64 = 10;
        let new_authenticator_address = address!("0x4444444444444444444444444444444444444444");
        let new_authenticator_pubkey = U256::from(123u64);
        let new_offchain_signer_commitment = U256::from(456u64);
        let nonce = U256::from(1u64);

        let sig = sign_recover_account(
            &signer,
            leaf_index,
            new_authenticator_address,
            new_authenticator_pubkey,
            new_offchain_signer_commitment,
            nonce,
            &domain,
        )
        .await
        .expect("signing must succeed");

        let payload = RecoverAccountTypedData {
            leafIndex: leaf_index,
            newAuthenticatorAddress: new_authenticator_address,
            newAuthenticatorPubkey: new_authenticator_pubkey,
            newOffchainSignerCommitment: new_offchain_signer_commitment,
            nonce,
        };
        let digest = payload.eip712_signing_hash(&domain);
        let recovered = sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(recovered, signer.address());
    }
}
