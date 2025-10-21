use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, TxKind};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy_node_bindings::{Anvil, AnvilInstance};
use eyre::{Context, ContextCompat, Result};

sol!(
    #[sol(rpc, ignore_unlinked)]
    CredentialSchemaIssuerRegistry,
    "../../contracts/out/CredentialSchemaIssuerRegistry.sol/CredentialSchemaIssuerRegistry.json"
);

sol!(
    #[sol(rpc)]
    Poseidon2T2,
    "../../contracts/out/Poseidon2.sol/Poseidon2T2.json"
);

sol!(
    #[sol(rpc, ignore_unlinked)]
    BinaryIMT,
    "../../contracts/out/BinaryIMT.sol/BinaryIMT.json"
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    AccountRegistry,
    "../../contracts/out/AccountRegistry.sol/AccountRegistry.json"
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
    #[allow(dead_code)]
    pub fn provider(&self) -> Result<DynProvider> {
        let provider = ProviderBuilder::new()
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);
        Ok(provider.erased())
    }

    /// Deploys the `CredentialSchemaIssuerRegistry` contract using the supplied signer.
    #[allow(dead_code)]
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

    /// Deploys the `AccountRegistry` contract using the supplied signer.
    #[allow(dead_code)]
    pub async fn deploy_account_registry(&self, signer: PrivateKeySigner) -> Result<Address> {
        let tree_depth = 30u64;
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);

        // Step 1: Deploy Poseidon2T2 library (no dependencies)
        let poseidon = Poseidon2T2::deploy(provider.clone())
            .await
            .context("failed to deploy Poseidon2T2 library")?;

        // Step 2: Link Poseidon2T2 and deploy BinaryIMT library
        let binary_imt_bytecode = Self::link_library(
            include_str!("../../../../contracts/out/BinaryIMT.sol/BinaryIMT.json"),
            "src/hash/Poseidon2.sol:Poseidon2T2",
            *poseidon.address(),
        )?;

        let binary_imt_address =
            Self::deploy_contract(provider.clone(), binary_imt_bytecode, Bytes::new())
                .await
                .context("failed to deploy BinaryIMT library")?;

        // Step 3: Link BinaryIMT and deploy AccountRegistry
        let account_registry_bytecode = Self::link_library(
            include_str!("../../../../contracts/out/AccountRegistry.sol/AccountRegistry.json"),
            "src/tree/BinaryIMT.sol:BinaryIMT",
            binary_imt_address,
        )?;

        // Encode constructor arguments (tree_depth)
        let constructor_args = alloy::sol_types::SolValue::abi_encode(&tree_depth);

        let registry_address = Self::deploy_contract(
            provider.clone(),
            account_registry_bytecode,
            constructor_args.into(),
        )
        .await
        .context("failed to deploy AccountRegistry")?;

        Ok(registry_address)
    }

    /// Links a library address into contract bytecode by replacing all placeholder references.
    ///
    /// Alloy only supports the linking of libraries that are already deployed, or linking at compile time, hence this manual handling.
    fn link_library(json: &str, library_path: &str, library_address: Address) -> Result<Bytes> {
        let json: serde_json::Value = serde_json::from_str(json)?;
        let bytecode_str = json["bytecode"]["object"]
            .as_str()
            .context("bytecode not found in JSON")?
            .strip_prefix("0x")
            .unwrap_or_else(|| {
                json["bytecode"]["object"]
                    .as_str()
                    .expect("bytecode should be a string")
            });

        let link_refs = &json["bytecode"]["linkReferences"];
        let (file_path, library_name) = library_path
            .split_once(':')
            .context("library_path must be in format 'file:Library'")?;

        let references = link_refs
            .get(file_path)
            .and_then(|v| v.get(library_name))
            .and_then(|v| v.as_array())
            .context("library reference not found")?;

        // Format library address as 40-character hex (20 bytes, no 0x prefix)
        let lib_addr_hex = format!("{library_address:040x}");

        let mut linked_bytecode = bytecode_str.to_string();

        // Process all references in reverse order to maintain correct positions
        let mut refs: Vec<_> = references
            .iter()
            .filter_map(|r| {
                let start = r["start"].as_u64()? as usize * 2; // byte offset -> hex offset
                Some(start)
            })
            .collect();
        refs.sort_by(|a, b| b.cmp(a)); // Sort descending

        for start_pos in refs {
            if start_pos + 40 <= linked_bytecode.len() {
                linked_bytecode.replace_range(start_pos..start_pos + 40, &lib_addr_hex);
            }
        }

        Ok(Bytes::from(hex::decode(linked_bytecode)?))
    }

    /// Deploys a contract with the given bytecode and constructor arguments
    async fn deploy_contract<P: Provider>(
        provider: P,
        bytecode: Bytes,
        constructor_args: Bytes,
    ) -> Result<Address> {
        let mut deployment_bytecode = bytecode.to_vec();
        deployment_bytecode.extend_from_slice(&constructor_args);

        let tx = TransactionRequest {
            to: Some(TxKind::Create),
            input: deployment_bytecode.into(),
            ..Default::default()
        };

        let pending_tx = provider.send_transaction(tx).await?;
        let receipt = pending_tx.get_receipt().await?;

        receipt
            .contract_address
            .context("contract deployment failed - no address in receipt")
    }
}
