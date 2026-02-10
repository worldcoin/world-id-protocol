use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{DynProvider, ProviderBuilder},
    sol,
};
use ark_ff::PrimeField;
use eddsa_babyjubjub::EdDSAPublicKey;
use ruint::aliases::U256;
use url::Url;
use world_id_primitives::{PrimitiveError, Signer};

use crate::CredentialSchemaIssuerRegistry::CredentialSchemaIssuerRegistryInstance;

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    CredentialSchemaIssuerRegistry,
    "../../contracts/abi/CredentialSchemaIssuerRegistry.sol/CredentialSchemaIssuerRegistryAbi.json"
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
    issuer_registry: CredentialSchemaIssuerRegistryInstance<DynProvider>,
}

impl Issuer {
    /// Create a new Issuer from a seed and config.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid.
    pub fn new(
        seed: &[u8],
        rpc_url: String,
        issuer_registry_address: Address,
    ) -> Result<Self, IssuerError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mut signer = Signer::from_seed_bytes(seed)?;

        let rpc_url = Url::parse(&rpc_url).map_err(|e| PrimitiveError::InvalidInput {
            reason: e.to_string(),
            attribute: "rpc_url".to_string(),
        })?;

        // Create a wallet from the signer and set up provider with wallet
        let wallet = EthereumWallet::from(signer.onchain_signer().clone());
        let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

        let issuer_registry = CredentialSchemaIssuerRegistry::new(
            issuer_registry_address,
            alloy::providers::Provider::erased(provider),
        );

        Ok(Self {
            signer,
            issuer_registry,
        })
    }

    /// Registers a new credential schema on-chain with the provided ID.
    ///
    /// # Errors
    /// Will error if the transaction fails or if the event is not found in the receipt.
    pub async fn register_schema(&mut self, issuer_schema_id: u64) -> Result<(), IssuerError> {
        let receipt = self
            .issuer_registry
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
