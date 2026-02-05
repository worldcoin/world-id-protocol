use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, TxKind, U256, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolEvent as _},
    uint,
};
use alloy_node_bindings::{Anvil, AnvilInstance};
use ark_ff::PrimeField as _;
use eddsa_babyjubjub::EdDSAPublicKey;
use eyre::{Context, ContextCompat, Result};
use taceo_oprf::types::OprfKeyId;
use taceo_oprf_test_utils::TestOprfKeyRegistry;
use world_id_primitives::{FieldElement, TREE_DEPTH, rp::RpId};

/// Canonical Multicall3 address (same on all EVM chains).
const MULTICALL3_ADDR: Address = address!("0xca11bde05977b3631167028862be2a173976ca11");

/// Multicall3 runtime bytecode (from mainnet at 0xcA11bde05977b3631167028862bE2a173976CA11).
const MULTICALL3_BYTECODE: &str = "6080604052600436106100f35760003560e01c80634d2301cc1161008a578063a8b0574e11610059578063a8b0574e1461025a578063bce38bd714610275578063c3077fa914610288578063ee82ac5e1461029b57600080fd5b80634d2301cc146101ec57806372425d9d1461022157806382ad56cb1461023457806386d516e81461024757600080fd5b80633408e470116100c65780633408e47014610191578063399542e9146101a45780633e64a696146101c657806342cbb15c146101d957600080fd5b80630f28c97d146100f8578063174dea711461011a578063252dba421461013a57806327e86d6e1461015b575b600080fd5b34801561010457600080fd5b50425b6040519081526020015b60405180910390f35b61012d610128366004610a85565b6102ba565b6040516101119190610bbe565b61014d610148366004610a85565b6104ef565b604051610111929190610bd8565b34801561016757600080fd5b50437fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0140610107565b34801561019d57600080fd5b5046610107565b6101b76101b2366004610c60565b610690565b60405161011193929190610cba565b3480156101d257600080fd5b5048610107565b3480156101e557600080fd5b5043610107565b3480156101f857600080fd5b50610107610207366004610ce2565b73ffffffffffffffffffffffffffffffffffffffff163190565b34801561022d57600080fd5b5044610107565b61012d610242366004610a85565b6106ab565b34801561025357600080fd5b5045610107565b34801561026657600080fd5b50604051418152602001610111565b61012d610283366004610c60565b61085a565b6101b7610296366004610a85565b610a1a565b3480156102a757600080fd5b506101076102b6366004610d18565b4090565b60606000828067ffffffffffffffff8111156102d8576102d8610d31565b60405190808252806020026020018201604052801561031e57816020015b6040805180820190915260008152606060208201528152602001906001900390816102f65790505b5092503660005b8281101561047757600085828151811061034157610341610d60565b6020026020010151905087878381811061035d5761035d610d60565b905060200281019061036f9190610d8f565b6040810135958601959093506103886020850185610ce2565b73ffffffffffffffffffffffffffffffffffffffff16816103ac6060870187610dcd565b6040516103ba929190610e32565b60006040518083038185875af1925050503d80600081146103f7576040519150601f19603f3d011682016040523d82523d6000602084013e6103fc565b606091505b50602080850191909152901515808452908501351761046d577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260846000fd5b5050600101610325565b508234146104e6576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601a60248201527f4d756c746963616c6c333a2076616c7565206d69736d6174636800000000000060448201526064015b60405180910390fd5b50505092915050565b436060828067ffffffffffffffff81111561050c5761050c610d31565b60405190808252806020026020018201604052801561053f57816020015b606081526020019060019003908161052a5790505b5091503660005b8281101561068657600087878381811061056257610562610d60565b90506020028101906105749190610e42565b92506105836020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166105a66020850185610dcd565b6040516105b4929190610e32565b6000604051808303816000865af19150503d80600081146105f1576040519150601f19603f3d011682016040523d82523d6000602084013e6105f6565b606091505b5086848151811061060957610609610d60565b602090810291909101015290508061067d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b50600101610546565b5050509250929050565b43804060606106a086868661085a565b905093509350939050565b6060818067ffffffffffffffff8111156106c7576106c7610d31565b60405190808252806020026020018201604052801561070d57816020015b6040805180820190915260008152606060208201528152602001906001900390816106e55790505b5091503660005b828110156104e657600084828151811061073057610730610d60565b6020026020010151905086868381811061074c5761074c610d60565b905060200281019061075e9190610e76565b925061076d6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166107906040850185610dcd565b60405161079e929190610e32565b6000604051808303816000865af19150503d80600081146107db576040519150601f19603f3d011682016040523d82523d6000602084013e6107e0565b606091505b506020808401919091529015158083529084013517610851577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260646000fd5b50600101610714565b6060818067ffffffffffffffff81111561087657610876610d31565b6040519080825280602002602001820160405280156108bc57816020015b6040805180820190915260008152606060208201528152602001906001900390816108945790505b5091503660005b82811015610a105760008482815181106108df576108df610d60565b602002602001015190508686838181106108fb576108fb610d60565b905060200281019061090d9190610e42565b925061091c6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff1661093f6020850185610dcd565b60405161094d929190610e32565b6000604051808303816000865af19150503d806000811461098a576040519150601f19603f3d011682016040523d82523d6000602084013e61098f565b606091505b506020830152151581528715610a07578051610a07576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b506001016108c3565b5050509392505050565b6000806060610a2b60018686610690565b919790965090945092505050565b60008083601f840112610a4b57600080fd5b50813567ffffffffffffffff811115610a6357600080fd5b6020830191508360208260051b8501011115610a7e57600080fd5b9250929050565b60008060208385031215610a9857600080fd5b823567ffffffffffffffff811115610aaf57600080fd5b610abb85828601610a39565b90969095509350505050565b6000815180845260005b81811015610aed57602081850181015186830182015201610ad1565b81811115610aff576000602083870101525b50601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169290920160200192915050565b600082825180855260208086019550808260051b84010181860160005b84811015610bb1578583037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe001895281518051151584528401516040858501819052610b9d81860183610ac7565b9a86019a9450505090830190600101610b4f565b5090979650505050505050565b602081526000610bd16020830184610b32565b9392505050565b600060408201848352602060408185015281855180845260608601915060608160051b870101935082870160005b82811015610c52577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0888703018452610c40868351610ac7565b95509284019290840190600101610c06565b509398975050505050505050565b600080600060408486031215610c7557600080fd5b83358015158114610c8557600080fd5b9250602084013567ffffffffffffffff811115610ca157600080fd5b610cad86828701610a39565b9497909650939450505050565b838152826020820152606060408201526000610cd96060830184610b32565b95945050505050565b600060208284031215610cf457600080fd5b813573ffffffffffffffffffffffffffffffffffffffff81168114610bd157600080fd5b600060208284031215610d2a57600080fd5b5035919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81833603018112610dc357600080fd5b9190910192915050565b60008083357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe1843603018112610e0257600080fd5b83018035915067ffffffffffffffff821115610e1d57600080fd5b602001915036819003821315610a7e57600080fd5b8183823760009101908152919050565b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc1833603018112610dc357600080fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa1833603018112610dc357600080fdfea2646970667358221220bb2b5c71a328032f97c676ae39a1ec2148d3e5d6f73d95e9b17910152d61f16264736f6c634300080c0033";

sol!(
    #[sol(rpc, ignore_unlinked)]
    CredentialSchemaIssuerRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/TestCredentialSchemaIssuerRegistry.sol/TestCredentialSchemaIssuerRegistry.json"
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
    WorldIDRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/WorldIDRegistry.sol/WorldIDRegistry.json"
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

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    RpRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/TestRpRegistry.sol/TestRpRegistry.json"
    )
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    ERC20Mock,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/ERC20Mock.sol/ERC20Mock.json"
    )
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    WorldIDVerifier,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/WorldIDVerifier.sol/WorldIDVerifier.json"
    )
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    Verifier,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/Verifier.sol/Verifier.json"
    )
);

pub struct TestAnvil {
    pub instance: AnvilInstance,
    pub rpc_url: String,
    pub ws_url: String,
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

    /// Spawns a fresh anvil instance with Multicall3 deployed at the canonical address.
    /// This avoids the need to fork from mainnet just to get Multicall3.
    pub async fn spawn_with_multicall3() -> Result<Self> {
        let anvil = Self::spawn()?;
        anvil.deploy_multicall3().await?;
        Ok(anvil)
    }

    /// Deploys Multicall3 bytecode at the canonical address using `anvil_setCode`.
    async fn deploy_multicall3(&self) -> Result<()> {
        let provider = ProviderBuilder::new()
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);

        let bytecode = Bytes::from(hex::decode(MULTICALL3_BYTECODE)?);

        // Use raw JSON-RPC call for anvil_setCode
        let _: () = provider
            .client()
            .request("anvil_setCode", (MULTICALL3_ADDR, bytecode))
            .await
            .context("anvil_setCode failed")?;

        Ok(())
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
        oprf_key_registry_address: Address,
    ) -> Result<Address> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);

        let erc20_mock = ERC20Mock::deploy(provider.clone())
            .await
            .context("failed to deploy ERC20Mock contract")?;

        let implementation = CredentialSchemaIssuerRegistry::deploy(provider.clone())
            .await
            .context("failed to deploy CredentialSchemaIssuerRegistry implementation")?;

        let implementation_address = *implementation.address();

        let init_data = Bytes::from(
            CredentialSchemaIssuerRegistry::initializeCall {
                feeRecipient: signer.address(),
                feeToken: *erc20_mock.address(),
                registrationFee: uint!(0_U256),
                oprfKeyRegistry: oprf_key_registry_address,
            }
            .abi_encode(),
        );

        let proxy = ERC1967Proxy::deploy(provider, implementation_address, init_data)
            .await
            .context("failed to deploy CredentialSchemaIssuerRegistry proxy")?;

        Ok(*proxy.address())
    }

    /// Deploys the `WorldIDRegistry` contract using the supplied signer.
    #[allow(dead_code)]
    pub async fn deploy_world_id_registry_with_depth(
        &self,
        signer: PrivateKeySigner,
        tree_depth: u64,
    ) -> Result<Address> {
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

        // Step 4: Link both BinaryIMT and PackedAccountData to WorldIDRegistry
        let world_id_registry_json = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/out/WorldIDRegistry.sol/WorldIDRegistry.json"
        ));

        // Link both libraries to WorldIDRegistry (keep as hex string until both are linked)
        let json_value: serde_json::Value = serde_json::from_str(world_id_registry_json)?;
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
            world_id_registry_json,
            &bytecode_str,
            "src/libraries/BinaryIMT.sol:BinaryIMT",
            binary_imt_address,
        )?;

        bytecode_str = Self::link_bytecode_hex(
            world_id_registry_json,
            &bytecode_str,
            "src/libraries/PackedAccountData.sol:PackedAccountData",
            *packed_account_data.address(),
        )?;

        // Decode the fully-linked bytecode
        let world_id_registry_bytecode = Bytes::from(hex::decode(bytecode_str)?);

        let implementation_address =
            Self::deploy_contract(provider.clone(), world_id_registry_bytecode, Bytes::new())
                .await
                .context("failed to deploy WorldIDRegistry implementation")?;

        let init_data = Bytes::from(
            WorldIDRegistry::initializeCall {
                initialTreeDepth: U256::from(tree_depth),
                feeRecipient: address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003"),
                feeToken: address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003"),
                registrationFee: U256::from(0),
            }
            .abi_encode(),
        );

        let proxy = ERC1967Proxy::deploy(provider, implementation_address, init_data)
            .await
            .context("failed to deploy WorldIDRegistry proxy")?;

        Ok(*proxy.address())
    }

    /// Deploys the `WorldIDRegistry` contract using the supplied signer with default tree depth from config.
    #[allow(dead_code)]
    pub async fn deploy_world_id_registry(&self, signer: PrivateKeySigner) -> Result<Address> {
        self.deploy_world_id_registry_with_depth(signer, TREE_DEPTH as u64)
            .await
    }

    /// Deploys the `RpRegistry` contract using the supplied signer.
    #[allow(dead_code)]
    pub async fn deploy_rp_registry(
        &self,
        signer: PrivateKeySigner,
        oprf_key_registry_contract: Address,
    ) -> Result<Address> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);

        let erc20_mock = ERC20Mock::deploy(provider.clone())
            .await
            .context("failed to deploy ERC20Mock contract")?;

        let rp_registry = RpRegistry::deploy(provider.clone())
            .await
            .context("failed to deploy RpRegistry contract")?;

        let init_data = Bytes::from(
            RpRegistry::initializeCall {
                feeRecipient: signer.address(),
                feeToken: *erc20_mock.address(),
                registrationFee: uint!(0_U256),
                oprfKeyRegistry: oprf_key_registry_contract,
            }
            .abi_encode(),
        );

        let proxy = ERC1967Proxy::deploy(provider, *rp_registry.address(), init_data)
            .await
            .context("failed to deploy RpRegistry proxy")?;

        Ok(*proxy.address())
    }

    /// Deploys the `OprfKeyRegistry` contract using the supplied signer.
    #[allow(dead_code)]
    pub async fn deploy_oprf_key_registry(&self, signer: PrivateKeySigner) -> Result<Address> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);

        taceo_oprf_test_utils::deploy_anvil::deploy_oprf_key_registry_25(
            provider.erased(),
            signer.address(),
        )
        .await
        .context("failed to deploy OprfKeyRegistry contract")
    }

    pub async fn deploy_world_id_verifier(
        &self,
        signer: PrivateKeySigner,
        credential_issuer_registry: Address,
        world_id_registry: Address,
        oprf_key_registry: Address,
    ) -> Result<Address> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);

        // Groth16 verifier (nullifier circuit)
        let groth16_verifier = Verifier::deploy(provider.clone())
            .await
            .context("failed to deploy Verifier (Groth16) contract")?;

        // WorldID verifier (upgradeable, delegates to Groth16 verifier)
        let world_id_verifier = WorldIDVerifier::deploy(provider.clone())
            .await
            .context("failed to deploy WorldIDVerifier contract")?;

        let init_data = Bytes::from(
            WorldIDVerifier::initializeCall {
                credentialIssuerRegistry: credential_issuer_registry,
                worldIDRegistry: world_id_registry,
                oprfKeyRegistry: oprf_key_registry,
                verifier: *groth16_verifier.address(),
                minExpirationThreshold: 3600,
            }
            .abi_encode(),
        );

        let proxy = ERC1967Proxy::deploy(provider, *world_id_verifier.address(), init_data)
            .await
            .context("failed to deploy WorldIDVerifier proxy")?;

        Ok(*proxy.address())
    }

    /// Registers the oprf nodes at the `OprfKeyRegistry`.
    pub async fn register_oprf_nodes(
        &self,
        oprf_key_registry_contract: Address,
        signer: PrivateKeySigner,
        node_addresses: Vec<Address>,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);
        let oprf_key_registry = TestOprfKeyRegistry::new(oprf_key_registry_contract, provider);
        let receipt = oprf_key_registry
            .registerOprfPeers(node_addresses)
            .send()
            .await?
            .get_receipt()
            .await?;
        if !receipt.status() {
            eyre::bail!("failed to init oprf key gen");
        }
        Ok(())
    }

    /// Adds an admin at the `OprfKeyRegistry` contract using the supplied signer.
    pub async fn add_oprf_key_registry_admin(
        &self,
        oprf_key_registry_contract: Address,
        signer: PrivateKeySigner,
        admin: Address,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);
        let oprf_key_registry = TestOprfKeyRegistry::new(oprf_key_registry_contract, provider);
        let receipt = oprf_key_registry
            .addKeyGenAdmin(admin)
            .send()
            .await?
            .get_receipt()
            .await?;
        if !receipt.status() {
            eyre::bail!("failed to add OprfKeyRegistry admin");
        }
        Ok(())
    }

    /// Register a new `RP` at the `RpRegistry` contract using the supplied signer.
    pub async fn register_rp(
        &self,
        rp_registry_contract: Address,
        signer: PrivateKeySigner,
        rp_id: RpId,
        rp_manager: Address,
        rp_signer: Address,
        rp_domain: String,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);
        let rp_registry = RpRegistry::new(rp_registry_contract, provider);
        let receipt = rp_registry
            .register(rp_id.into_inner(), rp_manager, rp_signer, rp_domain.clone())
            .gas(10000000) // FIXME
            .send()
            .await?
            .get_receipt()
            .await?;
        if !receipt.status() {
            eyre::bail!("failed to register RP");
        }
        Ok(())
    }

    /// Update an existing `RP` at the `RpRegistry` contract using the supplied signer.
    #[expect(clippy::too_many_arguments)]
    pub async fn update_rp_unchecked(
        &self,
        rp_registry_contract: Address,
        signer: PrivateKeySigner,
        rp_id: RpId,
        oprf_key_id: OprfKeyId,
        toggle_active: bool,
        rp_manager: Address,
        rp_signer: Address,
        rp_domain: String,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);
        let rp_registry = RpRegistry::new(rp_registry_contract, provider);
        let receipt = rp_registry
            .updateRpUnchecked(
                rp_id.into_inner(),
                oprf_key_id.into_inner(),
                rp_manager,
                rp_signer,
                toggle_active,
                rp_domain.clone(),
            )
            .gas(10000000) // FIXME
            .send()
            .await?
            .get_receipt()
            .await?;
        if !receipt.status() {
            eyre::bail!("failed to update RP");
        }
        Ok(())
    }

    /// Register a new issuer at the `CredentialSchemaIssuerRegistry` contract using the supplied signer.
    pub async fn register_issuer(
        &self,
        schema_issuer_registry_contract: Address,
        signer: PrivateKeySigner,
        issuer_schema_id: u64,
        issuer_public_key: EdDSAPublicKey,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);
        let issuer_registry =
            CredentialSchemaIssuerRegistry::new(schema_issuer_registry_contract, provider);

        let issuer_pubkey_repr = ICredentialSchemaIssuerRegistry::Pubkey {
            x: U256::from_limbs(issuer_public_key.pk.x.into_bigint().0),
            y: U256::from_limbs(issuer_public_key.pk.y.into_bigint().0),
        };

        let receipt = issuer_registry
            .register(issuer_schema_id, issuer_pubkey_repr, signer.address())
            .send()
            .await
            .wrap_err("failed to submit issuer registration")?
            .get_receipt()
            .await
            .wrap_err("failed to fetch issuer registration receipt")?;

        let registered_id = receipt
            .logs()
            .iter()
            .find_map(|log| {
                CredentialSchemaIssuerRegistry::IssuerSchemaRegistered::decode_log(
                    log.inner.as_ref(),
                )
                .ok()
            })
            .map(|event| event.issuerSchemaId)
            .ok_or_else(|| eyre::eyre!("IssuerSchemaRegistered event not emitted"))?;

        assert_eq!(
            registered_id, issuer_schema_id,
            "registered ID should match requested ID"
        );
        Ok(())
    }

    /// Removes an issuer at the `CredentialSchemaIssuerRegistry` contract using the supplied signer.
    pub async fn remove_issuer_unchecked(
        &self,
        schema_issuer_registry_contract: Address,
        signer: PrivateKeySigner,
        issuer_schema_id: u64,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer.clone()))
            .connect_http(self.rpc_url.parse().context("invalid anvil endpoint URL")?);
        let issuer_registry =
            CredentialSchemaIssuerRegistry::new(schema_issuer_registry_contract, provider);
        let receipt = issuer_registry
            .removeUnchecked(issuer_schema_id)
            .send()
            .await
            .wrap_err("failed to submit issuer removeUnchecked")?
            .get_receipt()
            .await
            .wrap_err("failed to fetch issuer removeUnchecked receipt")?;
        if !receipt.status() {
            eyre::bail!("failed to remove issuer");
        }
        Ok(())
    }

    pub async fn create_account(
        &self,
        world_id_registry: Address,
        signer: PrivateKeySigner,
        auth_addr: Address,
        pubkey: U256,
        commitment: U256,
    ) -> FieldElement {
        let registry = WorldIDRegistry::new(
            world_id_registry,
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(signer))
                .connect(&self.instance.endpoint())
                .await
                .unwrap(),
        );
        registry
            .createAccount(Address::ZERO, vec![auth_addr], vec![pubkey], commitment)
            .send()
            .await
            .expect("failed to submit createAccount transaction")
            .get_receipt()
            .await
            .expect("createAccount transaction failed");

        let root = registry
            .getLatestRoot()
            .call()
            .await
            .expect("failed to fetch root");

        FieldElement::try_from(root).expect("root is in field")
    }

    pub async fn set_root_validity_window(
        &self,
        world_id_registry: Address,
        signer: PrivateKeySigner,
        root_validity_window: u64,
    ) {
        let registry = WorldIDRegistry::new(
            world_id_registry,
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(signer))
                .connect(&self.instance.endpoint())
                .await
                .unwrap(),
        );
        registry
            .setRootValidityWindow(root_validity_window.try_into().unwrap())
            .send()
            .await
            .expect("failed to submit setRootValidityWindow transaction")
            .get_receipt()
            .await
            .expect("setRootValidityWindow transaction failed");
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
