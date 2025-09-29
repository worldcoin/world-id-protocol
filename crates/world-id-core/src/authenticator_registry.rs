//! This module allows interactions with the `AuthenticatorRegistry`.

use alloy::sol_types::{eip712_domain, Eip712Domain, SolStruct};
use alloy::{
    primitives::{Address, Signature, U256},
    signers::Signer,
    sol,
};

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    AuthenticatorRegistry,
    "../../contracts/out/AccountRegistry.sol/AccountRegistry.json"
);

sol! {
    struct UpdateAuthenticator {
        uint256 accountIndex;
        address oldAuthenticatorAddress;
        address newAuthenticatorAddress;
        uint256 pubkeyId;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }

    struct InsertAuthenticator {
        uint256 accountIndex;
        address newAuthenticatorAddress;
        uint256 pubkeyId;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }

    struct RemoveAuthenticator {
        uint256 accountIndex;
        address authenticatorAddress;
        uint256 pubkeyId;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }

    struct RecoverAccount {
        uint256 accountIndex;
        address newAuthenticatorAddress;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }
}

/// Returns the EIP-712 domain used by the `AuthenticatorRegistry` contract
/// for a given `chain_id` and `verifying_contract` address.
#[must_use]
pub const fn domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    eip712_domain!(
        name: "AuthenticatorRegistry",
        version: "1.0",
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    )
}

/// Signs `UpdateAuthenticator` contract call.
///
/// # Errors
/// Will error if the signer unexpectedly fails to sign the hash.
pub async fn sign_update_authenticator<S: Signer + Sync>(
    signer: &S,
    account_index: U256,
    old_authenticator_address: Address,
    new_authenticator_address: Address,
    pubkey_id: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = UpdateAuthenticator {
        accountIndex: account_index,
        oldAuthenticatorAddress: old_authenticator_address,
        newAuthenticatorAddress: new_authenticator_address,
        pubkeyId: pubkey_id,
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
pub async fn sign_insert_authenticator<S: Signer + Sync>(
    signer: &S,
    account_index: U256,
    new_authenticator_address: Address,
    pubkey_id: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = InsertAuthenticator {
        accountIndex: account_index,
        newAuthenticatorAddress: new_authenticator_address,
        pubkeyId: pubkey_id,
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
pub async fn sign_remove_authenticator<S: Signer + Sync>(
    signer: &S,
    account_index: U256,
    authenticator_address: Address,
    pubkey_id: U256,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = RemoveAuthenticator {
        accountIndex: account_index,
        authenticatorAddress: authenticator_address,
        pubkeyId: pubkey_id,
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
    account_index: U256,
    new_authenticator_address: Address,
    new_offchain_signer_commitment: U256,
    nonce: U256,
    domain: &Eip712Domain,
) -> anyhow::Result<Signature> {
    let payload = RecoverAccount {
        accountIndex: account_index,
        newAuthenticatorAddress: new_authenticator_address,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = payload.eip712_signing_hash(domain);
    Ok(signer.sign_hash(&digest).await?)
}
