use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{DynProvider, ProviderBuilder},
    sol,
    sol_types::SolEvent as _,
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
    "abi/CredentialSchemaIssuerRegistryAbi.json"
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
        let expected_signer = self.signer.onchain_signer_address();

        let receipt = self
            .issuer_registry
            .register(
                issuer_schema_id,
                self.signer.offchain_signer_pubkey().into(),
                expected_signer,
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

        let event = receipt
            .logs()
            .iter()
            .find_map(|log| {
                CredentialSchemaIssuerRegistry::IssuerSchemaRegistered::decode_log(
                    log.inner.as_ref(),
                )
                .ok()
            })
            .ok_or(IssuerError::RegistrationEventMissing)?;

        if event.issuerSchemaId != issuer_schema_id || event.signer != expected_signer {
            return Err(IssuerError::RegistrationEventMismatch {
                expected_schema_id: issuer_schema_id,
                actual_schema_id: event.issuerSchemaId,
                expected_signer,
                actual_signer: event.signer,
            });
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

    /// `IssuerSchemaRegistered` event not emitted in receipt logs.
    #[error("Registration event `IssuerSchemaRegistered` was not emitted")]
    RegistrationEventMissing,

    /// `IssuerSchemaRegistered` event emitted with unexpected values.
    #[error(
        "Registration event mismatch: expected schema_id={expected_schema_id}, signer={expected_signer}; got schema_id={actual_schema_id}, signer={actual_signer}"
    )]
    RegistrationEventMismatch {
        expected_schema_id: u64,
        actual_schema_id: u64,
        expected_signer: Address,
        actual_signer: Address,
    },

    /// Generic unexpected error
    #[error("Unexpected error: {0}")]
    Generic(String),
}
