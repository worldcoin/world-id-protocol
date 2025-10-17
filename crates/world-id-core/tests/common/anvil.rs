use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy_node_bindings::{Anvil, AnvilInstance};
use eyre::{Context, ContextCompat, Result};

sol!(
    #[sol(rpc, ignore_unlinked)]
    CredentialSchemaIssuerRegistry,
    "../../contracts/out/CredentialSchemaIssuerRegistry.sol/CredentialSchemaIssuerRegistry.json"
);

pub struct TestAnvil {
    instance: AnvilInstance,
    rpc_url: String,
}

impl TestAnvil {
    const MNEMONIC: &'static str = "test test test test test test test test test test test junk";

    /// Spawns a fresh `anvil` instance configured for integration tests.
    pub fn spawn() -> Result<Self> {
        let instance = Anvil::new()
            .mnemonic(Self::MNEMONIC)
            .block_time(1)
            .try_spawn()
            .context("failed to start anvil")?;

        let rpc_url = instance.endpoint().to_string();

        Ok(Self { instance, rpc_url })
    }

    /// Returns the RPC endpoint URL exposed by the running `anvil` instance.
    pub fn endpoint(&self) -> &str {
        &self.rpc_url
    }

    /// Returns a [`PrivateKeySigner`] derived from the deterministic mnemonic at the provided index.
    pub fn signer(&self, index: usize) -> Result<PrivateKeySigner> {
        let key = self
            .instance
            .nth_key(index)
            .cloned()
            .context("requested anvil account index out of bounds")?;

        Ok(PrivateKeySigner::from(key))
    }

    /// Creates a read-only provider connected to the `anvil` instance.
    pub fn provider(&self) -> Result<DynProvider> {
        let provider = ProviderBuilder::new()
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);
        Ok(provider.erased())
    }

    /// Deploys the `CredentialSchemaIssuerRegistry` contract using the supplied signer.
    pub async fn deploy_credential_schema_issuer_registry(
        &self,
        signer: PrivateKeySigner,
    ) -> Result<Address> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);

        let instance = CredentialSchemaIssuerRegistry::deploy(provider)
            .await
            .context("failed to deploy CredentialSchemaIssuerRegistry")?;

        Ok(*instance.address())
    }
}
