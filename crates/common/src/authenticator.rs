use alloy::{primitives::U256, providers::ProviderBuilder, uint};

use crate::{authenticator_registry::AuthenticatorRegistry, AuthenticatorSigner, Config};

static U128_MASK: U256 =
    uint!(0x00000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_U256);

#[derive(Clone, Debug)]
pub struct Authenticator {
    tree_index: U256,
    signer: AuthenticatorSigner,
    config: Config,
}

impl Authenticator {
    /// Create a new Authenticator from a seed and config.
    /// This will fetch the tree index from the registry.
    pub async fn new(seed: &[u8], config: Config) -> anyhow::Result<Self> {
        let signer = AuthenticatorSigner::from_seed_bytes(seed)?;
        let provider = ProviderBuilder::new().connect_http(config.rpc_url().parse()?);
        let contract = AuthenticatorRegistry::new(*config.registry_address(), provider);
        let tree_index = contract
            .authenticatorAddressToPackedAccountIndex(signer.onchain_signer().address())
            .call()
            .await?;

        Ok(Self {
            tree_index: tree_index | U128_MASK,
            signer,
            config,
        })
    }

    /// Create a new Authenticator from a seed and config with a given tree index.
    pub fn new_with_tree_index(seed: &[u8], tree_index: U256, config: Config) -> Self {
        let signer = AuthenticatorSigner::from_seed_bytes(seed).unwrap();
        Self {
            tree_index,
            signer,
            config,
        }
    }

    /// Get the tree index of the Authenticator.
    pub fn tree_index(&self) -> U256 {
        self.tree_index
    }

    pub async fn inclusion_proof(&self) -> anyhow::Result<Vec<U256>> {
        unimplemented!()
    }

    pub async fn generate_proof(
        &self,
        rp_id: U256,
        action_id: U256,
        message_hash: U256,
    ) -> anyhow::Result<Vec<U256>> {
        unimplemented!()
    }
}
