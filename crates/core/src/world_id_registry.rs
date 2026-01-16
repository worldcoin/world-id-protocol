//! This module allows interactions with the `WorldIDRegistry`.

use alloy::{
    primitives::{Address, Signature, U256},
    signers::Signer,
    sol,
    sol_types::{eip712_domain, Eip712Domain, SolStruct},
};

sol!(
    /// The registry of World IDs. Each World ID is represented as a leaf in the Merkle tree.
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    WorldIdRegistry,
    "contracts/out/WorldIDRegistry.sol/WorldIDRegistryAbi.json"
);

sol! {
    struct UpdateAuthenticator {
        uint256 leafIndex;
        address oldAuthenticatorAddress;
        address newAuthenticatorAddress;
        uint32 pubkeyId;
        uint256 newAuthenticatorPubkey;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }

    struct InsertAuthenticator {
        uint256 leafIndex;
        address newAuthenticatorAddress;
        uint32 pubkeyId;
        uint256 newAuthenticatorPubkey;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }

    struct RemoveAuthenticator {
        uint256 leafIndex;
        address authenticatorAddress;
        uint32 pubkeyId;
        uint256 authenticatorPubkey;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }

    struct RecoverAccount {
        uint256 leafIndex;
        address newAuthenticatorAddress;
        uint256 newAuthenticatorPubkey;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }
}

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

/// Signs `UpdateAuthenticator` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
#[allow(clippy::too_many_arguments)]
pub async fn sign_update_authenticator<S: Signer + Sync>(
    signer: &S,
    leaf_index: U256,
    old_authenticator_address: Address,
    new_authenticator_address: Address,
    pubkey_id: u32,
    new_authenticator_pubkey: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = UpdateAuthenticator {
        leafIndex: leaf_index,
        oldAuthenticatorAddress: old_authenticator_address,
        newAuthenticatorAddress: new_authenticator_address,
        pubkeyId: pubkey_id,
        newAuthenticatorPubkey: new_authenticator_pubkey,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash(&digest).await?)
}

/// Signs `InsertAuthenticator` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
#[allow(clippy::too_many_arguments)]
pub async fn sign_insert_authenticator<S: Signer + Sync>(
    signer: &S,
    leaf_index: U256,
    new_authenticator_address: Address,
    pubkey_id: u32,
    new_authenticator_pubkey: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = InsertAuthenticator {
        leafIndex: leaf_index,
        newAuthenticatorAddress: new_authenticator_address,
        pubkeyId: pubkey_id,
        newAuthenticatorPubkey: new_authenticator_pubkey,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash(&digest).await?)
}

/// Signs `RemoveAuthenticator` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
#[allow(clippy::too_many_arguments)]
pub async fn sign_remove_authenticator<S: Signer + Sync>(
    signer: &S,
    leaf_index: U256,
    authenticator_address: Address,
    pubkey_id: u32,
    authenticator_pubkey: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = RemoveAuthenticator {
        leafIndex: leaf_index,
        authenticatorAddress: authenticator_address,
        pubkeyId: pubkey_id,
        authenticatorPubkey: authenticator_pubkey,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash(&digest).await?)
}

/// Signs `RecoverAccount` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
pub async fn sign_recover_account<S: Signer + Sync>(
    signer: &S,
    leaf_index: U256,
    new_authenticator_address: Address,
    new_authenticator_pubkey: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = RecoverAccount {
        leafIndex: leaf_index,
        newAuthenticatorAddress: new_authenticator_address,
        newAuthenticatorPubkey: new_authenticator_pubkey,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash(&digest).await?)
}
