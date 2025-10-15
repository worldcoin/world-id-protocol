use crate::{config::Config, issuer::CredentialSchemaIssuerRegistry::Pubkey, Signer};
use alloy::{network::EthereumWallet, providers::ProviderBuilder, sol, sol_types::SolEvent};
use ark_ff::PrimeField;
use eyre::Result;
use oprf_client::EdDSAPublicKey;
use ruint::aliases::U256;

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    CredentialSchemaIssuerRegistry,
    "../../contracts/out/CredentialSchemaIssuerRegistry.sol/CredentialSchemaIssuerRegistry.json"
);

impl From<EdDSAPublicKey> for Pubkey {
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
    /// General configuration for the Issuer.
    pub config: Config,
}

impl Issuer {
    /// Create a new Issuer from a seed and config.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid.
    pub fn new(seed: &[u8], config: Config) -> Result<Self> {
        let signer = Signer::from_seed_bytes(seed)?;

        Ok(Self { signer, config })
    }

    /// Registers a new credential schema on-chain.
    ///
    /// # Errors
    /// Will error if the transaction fails or if the event is not found in the receipt.
    pub async fn register_schema(&mut self) -> Result<U256> {
        // Create a wallet from the signer and set up provider with wallet
        let wallet = EthereumWallet::from(self.signer.onchain_signer().clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.config.rpc_url().parse()?);

        let contract =
            CredentialSchemaIssuerRegistry::new(*self.config.registry_address(), provider);

        let receipt = contract
            .register(
                self.signer.offchain_signer_pubkey().into(),
                self.signer.onchain_signer_address(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        let issuer_schema_id = receipt
            .logs()
            .iter()
            .find_map(|log| {
                CredentialSchemaIssuerRegistry::IssuerSchemaRegistered::decode_log(
                    log.inner.as_ref(),
                )
                .ok()
            })
            .ok_or_else(|| {
                eyre::eyre!("IssuerSchemaRegistered event not found in transaction receipt")
            })?
            .issuerSchemaId;

        Ok(issuer_schema_id)
    }
}
