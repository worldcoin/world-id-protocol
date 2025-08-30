use alloy::{
    dyn_abi::Eip712Domain, primitives::{Address, Signature, U256}, signers::Signer, sol
};
use alloy::sol_types::eip712_domain;
use alloy::sol_types::SolStruct;

sol! {
    struct UpdateAuthenticator {
        uint256 accountIndex;
        address oldAuthenticatorAddress;
        address newAuthenticatorAddress;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }

    struct InsertAuthenticator {
        uint256 accountIndex;
        address newAuthenticatorAddress;
        uint256 newOffchainSignerCommitment;
        uint256 nonce;
    }

    struct RemoveAuthenticator {
        uint256 accountIndex;
        address authenticatorAddress;
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

static CHAIN_ID: u64 = 1;
static VERIFYING_CONTRACT: Address = Address::ZERO;
static EIP712_DOMAIN: Eip712Domain = eip712_domain!(
    name: "AuthenticatorRegistry",
    version: "1.0",
    chain_id: CHAIN_ID,
    verifying_contract: VERIFYING_CONTRACT,
);

/// Signs UpdateAuthenticator using Alloy signer.
pub async fn sign_update_authenticator<S: Signer + Sync>(
    signer: &S,
    account_index: U256,
    old_authenticator_address: Address,
    new_authenticator_address: Address,
    new_offchain_signer_commitment: U256,
    nonce: U256,
) -> anyhow::Result<Signature> {
    let msg = UpdateAuthenticator {
        accountIndex: account_index,
        oldAuthenticatorAddress: old_authenticator_address,
        newAuthenticatorAddress: new_authenticator_address,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = msg.eip712_signing_hash(&EIP712_DOMAIN);
    Ok(signer.sign_hash(&digest).await?)
}

pub async fn sign_insert_authenticator<S: Signer + Sync>(
    signer: &S,
    account_index: U256,
    new_authenticator_address: Address,
    new_offchain_signer_commitment: U256,
    nonce: U256,
) -> anyhow::Result<Signature> {
    let msg = InsertAuthenticator {
        accountIndex: account_index,
        newAuthenticatorAddress: new_authenticator_address,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = msg.eip712_signing_hash(&EIP712_DOMAIN);
    Ok(signer.sign_hash(&digest).await?)
}

pub async fn sign_remove_authenticator<S: Signer + Sync>(
    signer: &S,
    account_index: U256,
    authenticator_address: Address,
    new_offchain_signer_commitment: U256,
    nonce: U256,
) -> anyhow::Result<Signature> {
    let msg = RemoveAuthenticator {
        accountIndex: account_index,
        authenticatorAddress: authenticator_address,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = msg.eip712_signing_hash(&EIP712_DOMAIN);
    Ok(signer.sign_hash(&digest).await?)
}

pub async fn sign_recover_account<S: Signer + Sync>(
    signer: &S,
    account_index: U256,
    new_authenticator_address: Address,
    new_offchain_signer_commitment: U256,
    nonce: U256,
) -> anyhow::Result<Signature> {
    let msg = RecoverAccount {
        accountIndex: account_index,
        newAuthenticatorAddress: new_authenticator_address,
        newOffchainSignerCommitment: new_offchain_signer_commitment,
        nonce,
    };
    let digest = msg.eip712_signing_hash(&EIP712_DOMAIN);
    Ok(signer.sign_hash(&digest).await?)
}
