use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy_node_bindings::{Anvil, AnvilInstance};
use eyre::{Context, ContextCompat, Result};

sol!(
    #[sol(rpc, ignore_unlinked)]
    CredentialSchemaIssuerRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/CredentialSchemaIssuerRegistry.sol/CredentialSchemaIssuerRegistry.json"
    )
);

sol!(
    #[sol(rpc)]
    Poseidon2T2,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/Poseidon2.sol/Poseidon2T2.json"
    )
);

sol!(
    #[sol(rpc)]
    PackedAccountData,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/PackedAccountData.sol/PackedAccountData.json"
    )
);

sol!(
    #[sol(rpc, ignore_unlinked)]
    BinaryIMT,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/BinaryIMT.sol/BinaryIMT.json"
    )
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    AccountRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/AccountRegistry.sol/AccountRegistry.json"
    )
);

sol!(
    #[sol(rpc)]
    ERC1967Proxy,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/ERC1967Proxy.sol/ERC1967Proxy.json"
    )
);

pub struct TestAnvil {
    instance: AnvilInstance,
    rpc_url: String,
    ws_url: String,
}

impl TestAnvil {
    const MNEMONIC: &'static str = "test test test test test test test test test test test junk";

    /// Spawns a fresh `anvil` instance configured for integration tests.
    pub fn spawn() -> Result<Self> {
        Self::spawn_from_builder(Anvil::new())
    }

    /// Spawns an anvil instance forked from the provided RPC endpoint.
    pub fn spawn_fork(fork_url: &str) -> Result<Self> {
        Self::spawn_from_builder(Anvil::new().fork(fork_url))
    }

    fn spawn_from_builder(builder: Anvil) -> Result<Self> {
        let instance = builder
            .mnemonic(Self::MNEMONIC)
            .block_time(1)
            .try_spawn()
            .context("failed to start anvil")?;

        let rpc_url = instance.endpoint().to_string();
        let ws_url = instance.ws_endpoint();

        Ok(Self {
            instance,
            rpc_url,
            ws_url,
        })
    }

    /// Returns the RPC endpoint URL exposed by the running `anvil` instance.
    pub fn endpoint(&self) -> &str {
        &self.rpc_url
    }

    /// Returns the WebSocket endpoint URL exposed by the running `anvil` instance.
    pub fn ws_endpoint(&self) -> &str {
        &self.ws_url
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

        let implementation = CredentialSchemaIssuerRegistry::deploy(provider.clone())
            .await
            .context("failed to deploy CredentialSchemaIssuerRegistry implementation")?;

        let implementation_address = *implementation.address();

        let init_data = Bytes::from(CredentialSchemaIssuerRegistry::initializeCall {}.abi_encode());

        let proxy = ERC1967Proxy::deploy(provider, implementation_address, init_data)
            .await
            .context("failed to deploy CredentialSchemaIssuerRegistry proxy")?;

        Ok(*proxy.address())
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
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../contracts/out/BinaryIMT.sol/BinaryIMT.json"
            )),
            "src/hash/Poseidon2.sol:Poseidon2T2",
            *poseidon.address(),
        )?;

        let binary_imt_address =
            Self::deploy_contract(provider.clone(), binary_imt_bytecode, Bytes::new())
                .await
                .context("failed to deploy BinaryIMT library")?;

        // Step 3: Deploy PackedAccountData library (no dependencies)
        let packed_account_data = PackedAccountData::deploy(provider.clone())
            .await
            .context("failed to deploy PackedAccountData library")?;

        // Step 4: Link both BinaryIMT and PackedAccountData to AccountRegistry
        let account_registry_json = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/out/AccountRegistry.sol/AccountRegistry.json"
        ));

        // Link both libraries to AccountRegistry (keep as hex string until both are linked)
        let json_value: serde_json::Value = serde_json::from_str(account_registry_json)?;
        let mut bytecode_str = json_value["bytecode"]["object"]
            .as_str()
            .context("bytecode not found in JSON")?
            .strip_prefix("0x")
            .unwrap_or_else(|| {
                json_value["bytecode"]["object"]
                    .as_str()
                    .expect("bytecode should be a string")
            })
            .to_string();

        bytecode_str = Self::link_bytecode_hex(
            account_registry_json,
            &bytecode_str,
            "src/tree/BinaryIMT.sol:BinaryIMT",
            binary_imt_address,
        )?;

        bytecode_str = Self::link_bytecode_hex(
            account_registry_json,
            &bytecode_str,
            "src/lib/PackedAccountData.sol:PackedAccountData",
            *packed_account_data.address(),
        )?;

        // Decode the fully-linked bytecode
        let account_registry_bytecode = Bytes::from(hex::decode(bytecode_str)?);

        let implementation_address =
            Self::deploy_contract(provider.clone(), account_registry_bytecode, Bytes::new())
                .await
                .context("failed to deploy AccountRegistry implementation")?;

        let init_data = Bytes::from(
            AccountRegistry::initializeCall {
                treeDepth: U256::from(tree_depth),
            }
            .abi_encode(),
        );

        let proxy = ERC1967Proxy::deploy(provider, implementation_address, init_data)
            .await
            .context("failed to deploy AccountRegistry proxy")?;

        Ok(*proxy.address())
    }

    /// Links a library address into contract bytecode by replacing all placeholder references.
    ///
    /// Alloy only supports the linking of libraries that are already deployed, or linking at compile time, hence this manual handling.
    fn link_library(json: &str, library_path: &str, library_address: Address) -> Result<Bytes> {
        let json_value: serde_json::Value = serde_json::from_str(json)?;
        let bytecode_str = json_value["bytecode"]["object"]
            .as_str()
            .context("bytecode not found in JSON")?
            .strip_prefix("0x")
            .unwrap_or_else(|| {
                json_value["bytecode"]["object"]
                    .as_str()
                    .expect("bytecode should be a string")
            });

        Self::link_bytecode_str(json, bytecode_str, library_path, library_address)
    }

    /// Links a library to bytecode hex string and returns the hex string (no decoding).
    ///
    /// Use this when you need to link multiple libraries before decoding.
    fn link_bytecode_hex(
        json: &str,
        bytecode_str: &str,
        library_path: &str,
        library_address: Address,
    ) -> Result<String> {
        let json: serde_json::Value = serde_json::from_str(json)?;
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

        Ok(linked_bytecode)
    }

    /// Core linking logic: links a library address into a bytecode hex string and decodes it.
    ///
    /// This handles the actual replacement of library placeholders with addresses.
    fn link_bytecode_str(
        json: &str,
        bytecode_str: &str,
        library_path: &str,
        library_address: Address,
    ) -> Result<Bytes> {
        let linked_hex =
            Self::link_bytecode_hex(json, bytecode_str, library_path, library_address)?;
        Ok(Bytes::from(hex::decode(linked_hex)?))
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
