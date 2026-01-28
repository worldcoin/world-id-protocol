use crate::Signer;

use alloy::{network::EthereumWallet, providers::ProviderBuilder, sol};
use ark_ff::PrimeField;
use eddsa_babyjubjub::EdDSAPublicKey;
use ruint::aliases::U256;
use world_id_primitives::{Config, PrimitiveError};

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    CredentialSchemaIssuerRegistry,
    "contracts/out/CredentialSchemaIssuerRegistry.sol/CredentialSchemaIssuerRegistryAbi.json"
);

impl From<EdDSAPublicKey> for ICredentialSchemaIssuerRegistry::Pubkey {

    fn from(pubkey: EdDSAPublicKey) -> Self {
        Self {
            x: U256::from_limbs(pubkey.pk.x.into_bigint().0),
            y: U256::from_limbs(pubkey.pk.y.into_bigint().0),
        }
    }
}

/// Provides base functionality for issuing credentials.
#[derive(Debug)]
pub struct Issuer {
    signer: Signer,
    /// General configuration for the Protocol.
    pub config: Config,
}

impl Issuer {
    /// Create a new Issuer from a seed and config.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid.
    pub fn new(seed: &[u8], config: Config) -> Result<Self, IssuerError> {
        let signer = Signer::from_seed_bytes(seed)?;

        Ok(Self { signer, config })
    }

    /// Registers a new credential schema on-chain with the provided ID.
    ///
    /// # Errors
    /// Will error if the transaction fails or if the event is not found in the receipt.
    pub async fn register_schema(&mut self, issuer_schema_id: u64) -> Result<(), IssuerError> {
        let rpc_url = self
            .config
            .rpc_url()
            .ok_or(IssuerError::ConfigError("RPC URL must be set.".to_string()))?;

        // Create a wallet from the signer and set up provider with wallet
        let wallet = EthereumWallet::from(self.signer.onchain_signer().clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(rpc_url.clone());

        let contract =
            CredentialSchemaIssuerRegistry::new(*self.config.registry_address(), provider);

        let receipt = contract
            .register(
                issuer_schema_id,
                self.signer.offchain_signer_pubkey().into(),
                self.signer.onchain_signer_address(),
            )
            .send()
            .await
            .map_err(|e| IssuerError::Generic(format!("failed to send transaction: {e}")))?
            .get_receipt()
            .await?;

        if !receipt.status() {
            return Err(IssuerError::RegistrationFailed(format!(
                "transaction reverted (tx: {}, block: {})",
                receipt.transaction_hash,
                receipt.block_number.unwrap_or_default()
            )));
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    /// Primitive error
    #[error(transparent)]
    PrimitiveError(#[from] PrimitiveError),

    /// Config is not correctly defined
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Alloy pending transaction error
    #[error(transparent)]
    PendingTransactionError(#[from] alloy::providers::PendingTransactionError),

    /// Registration failed with revert
    #[error("Registration failed: {0}")]
    RegistrationFailed(String),

    /// Generic unexpected error
    #[error("Unexpected error: {0}")]
    Generic(String),
}
