use std::{str::FromStr as _, sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, U160, U256},
    providers::DynProvider,
    signers::{
        k256::ecdsa::SigningKey,
        local::{LocalSigner, PrivateKeySigner},
    },
};
use ark_ff::PrimeField as _;
use clap::Parser;
use eyre::Context as _;
use rand::{CryptoRng, Rng};
use secrecy::ExposeSecret as _;
use taceo_oprf::{
    client::Connector,
    core::oprf::BlindingFactor,
    dev_client::{DevClient, DevClientConfig, StressTestItem},
    types::{OprfKeyId, ShareEpoch, api::OprfRequest, crypto::OprfPublicKey},
};
use taceo_oprf_test_utils::{async_trait, health_checks};
use uuid::Uuid;
use world_id_core::{
    Authenticator, AuthenticatorError, EdDSAPrivateKey, EdDSASignature, FieldElement,
    proof::CircomGroth16Material,
};
use world_id_primitives::{
    TREE_DEPTH,
    authenticator::AuthenticatorPublicKeySet,
    merkle::MerkleInclusionProof,
    oprf::{CredentialBlindingFactorOprfRequestAuthV1, OprfModule},
};
use world_id_proof::{
    AuthenticatorProofInput, credential_blinding_factor::OprfCredentialBlindingFactor,
};
use world_id_test_utils::anvil::{CredentialSchemaIssuerRegistry, ICredentialSchemaIssuerRegistry};

#[derive(Parser, Debug)]
struct WorldDevClientConfig {
    /// Indexer address
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_INDEXER_URL",
        default_value = "http://localhost:8080"
    )]
    pub indexer_url: String,

    /// Gateway address
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_GATEWAY_URL",
        default_value = "http://localhost:8081"
    )]
    pub gateway_url: String,

    /// If set to `true` uses chain_id 31_337 (anvil). If set to `false` uses chain_id 480 (world chain).
    #[clap(long, env = "OPRF_DEV_CLIENT_ANVIL")]
    pub anvil: bool,

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_ISSUER_SCHEMA_ID")]
    pub issuer_schema_id: Option<u64>,

    /// The Address of the WorldIDRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_WORLD_ID_REGISTRY_CONTRACT")]
    pub world_id_registry_contract: Address,

    /// The Address of the RpRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_ISSUER_SCHEMA_REGISTRY_CONTRACT")]
    pub issuer_schema_registry_contract: Address,

    #[clap(flatten)]
    config: DevClientConfig,
}

struct WorldIdIssuerSchemaDevClient {
    issuer_schema_id: Option<u64>,
    issuer_schema_registry_contract: Address,
    authenticator: Authenticator,
    signer: LocalSigner<SigningKey>,
    authenticator_private_key: EdDSAPrivateKey,
    query_material: Arc<CircomGroth16Material>,
}

#[derive(Clone)]
struct WorldIdIssuerSchemaDevClientSetup {
    issuer_schema_id: u64,
    issuer_schema_oprf_public_key: OprfPublicKey,

    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    key_set: AuthenticatorPublicKeySet,
    key_index: u64,
}

#[async_trait::async_trait]
impl DevClient for WorldIdIssuerSchemaDevClient {
    type Setup = WorldIdIssuerSchemaDevClientSetup;
    type RequestAuth = CredentialBlindingFactorOprfRequestAuthV1;

    async fn setup_oprf_test(
        &self,
        config: &DevClientConfig,
        provider: DynProvider,
    ) -> eyre::Result<Self::Setup> {
        let signer_address = self.signer.address();

        let (inclusion_proof, key_set) = self.authenticator.fetch_inclusion_proof().await?;

        let key_index = key_set
            .iter()
            .position(|pk| {
                pk.as_ref()
                    .is_some_and(|pk| pk.pk == self.authenticator.offchain_pubkey().pk)
            })
            .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;

        let (issuer_schema_id, issuer_schema_oprf_public_key) = tokio::time::timeout(
            config.max_wait_time,
            self.setup_issuer(config, signer_address, &provider),
        )
        .await
        .context("cannot setup issuer-schema in time")?
        .context("while setup of issuer-schema")?;

        Ok(WorldIdIssuerSchemaDevClientSetup {
            issuer_schema_id,
            issuer_schema_oprf_public_key,
            inclusion_proof,
            key_set,
            key_index,
        })
    }

    async fn run_oprf(
        &self,
        config: &DevClientConfig,
        setup: Self::Setup,
        connector: Connector,
    ) -> eyre::Result<ShareEpoch> {
        let authenticator_input = AuthenticatorProofInput::new(
            setup.key_set.clone(),
            setup.inclusion_proof.clone(),
            self.authenticator_private_key.clone(),
            setup.key_index,
        );

        let blinding_factor = OprfCredentialBlindingFactor::generate(
            &config.nodes,
            config.threshold,
            &self.query_material,
            authenticator_input,
            setup.issuer_schema_id,
            FieldElement::ZERO, // for now action is always zero, might change in future
            connector,
        )
        .await?;

        Ok(blinding_factor.verifiable_oprf_output.epoch)
    }

    async fn prepare_stress_test_item<R: Rng + CryptoRng + Send>(
        &self,
        setup: &Self::Setup,
        rng: &mut R,
    ) -> eyre::Result<StressTestItem<Self::RequestAuth>> {
        let leaf_index = self.authenticator.leaf_index();
        let request_id = Uuid::new_v4();
        let action = FieldElement::ZERO;
        let nonce = FieldElement::random(rng);
        let query_hash = world_id_primitives::authenticator::oprf_query_digest(
            leaf_index,
            action,
            setup.issuer_schema_id.into(),
        );
        let oprf_blinding_factor = BlindingFactor::rand(rng);
        let signature = self.authenticator_private_key.sign(*query_hash);

        let oprf_request_auth = generate_oprf_auth_request(
            setup,
            action,
            nonce,
            &oprf_blinding_factor,
            signature,
            &self.query_material,
        )?;

        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(*query_hash, oprf_blinding_factor.clone());

        let init_request = OprfRequest {
            request_id,
            blinded_query: blinded_query.blinded_query(),
            auth: oprf_request_auth,
        };
        Ok(StressTestItem {
            request_id,
            blinded_query,
            init_request,
        })
    }

    fn get_oprf_key(&self, setup: &Self::Setup) -> OprfPublicKey {
        setup.issuer_schema_oprf_public_key
    }
    fn get_oprf_key_id(&self, setup: &Self::Setup) -> OprfKeyId {
        OprfKeyId::from(setup.issuer_schema_id)
    }

    fn auth_module(&self) -> String {
        OprfModule::CredentialBlindingFactor.to_string()
    }
}

impl WorldIdIssuerSchemaDevClient {
    async fn new(config: &WorldDevClientConfig) -> eyre::Result<Self> {
        let query_material = Arc::new(
            world_id_core::proof::load_embedded_query_material()
                .context("while loading query material")?,
        );
        let (authenticator, authenticator_private_key) =
            world_id_oprf_dev_client::init_authenticator(
                config.indexer_url.to_owned(),
                config.gateway_url.to_owned(),
                config.world_id_registry_contract,
                &config.config,
                config.anvil,
                Arc::clone(&query_material),
            )
            .await?;
        let signer = PrivateKeySigner::from_str(config.config.taceo_private_key.expose_secret())?;
        Ok(Self {
            issuer_schema_id: config.issuer_schema_id,
            issuer_schema_registry_contract: config.issuer_schema_registry_contract,
            authenticator,
            signer,
            authenticator_private_key,
            query_material,
        })
    }

    async fn setup_issuer(
        &self,
        config: &DevClientConfig,
        signer: Address,
        provider: &DynProvider,
    ) -> eyre::Result<(u64, OprfPublicKey)> {
        if let Some(issuer_schema_id) = self.issuer_schema_id {
            // TODO should maybe check if the oprf key id matches the registered one in case it was changed
            // in case they are not the same, we return them both
            let oprf_key_id = OprfKeyId::new(U160::from(issuer_schema_id));
            let share_epoch = ShareEpoch::default();
            let oprf_public_key = health_checks::oprf_public_key_from_services(
                oprf_key_id,
                share_epoch,
                &config.nodes,
                Duration::from_secs(10), // should already be there
            )
            .await?;
            Ok((issuer_schema_id, oprf_public_key))
        } else {
            tracing::info!("registering new credential schema issuer");
            let credential_schema_issuer_registry = CredentialSchemaIssuerRegistry::new(
                self.issuer_schema_registry_contract,
                provider.clone(),
            );
            let issuer_schema_id = rand::random::<u64>();
            let oprf_key_id = OprfKeyId::new(U160::from(issuer_schema_id));
            let seed = [8u8; 32];
            let issuer_private_key = EdDSAPrivateKey::from_bytes(seed);
            let issuer_public_key = ICredentialSchemaIssuerRegistry::Pubkey {
                x: U256::from_limbs(issuer_private_key.public().pk.x.into_bigint().0),
                y: U256::from_limbs(issuer_private_key.public().pk.y.into_bigint().0),
            };
            let receipt = credential_schema_issuer_registry
                .register(issuer_schema_id, issuer_public_key, signer)
                .gas(10000000)
                .send()
                .await?
                .get_receipt()
                .await?;
            if !receipt.status() {
                eyre::bail!("failed to register issuer");
            }
            tracing::info!("registered issuer with OPRF key: {oprf_key_id}");
            let oprf_public_key = health_checks::oprf_public_key_from_services(
                oprf_key_id,
                ShareEpoch::default(),
                &config.nodes,
                config.max_wait_time,
            )
            .await?;
            Ok((issuer_schema_id, oprf_public_key))
        }
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    taceo_nodes_observability::install_tracing(
        "world_id_oprf_dev_client_rp=trace,taceo_oprf_dev_client=trace,warn",
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");

    let config = WorldDevClientConfig::parse();
    tracing::info!("starting with config: {config:#?}");
    let dev_client = WorldIdIssuerSchemaDevClient::new(&config)
        .await
        .context("while creating dev-client")?;
    taceo_oprf::dev_client::run(config.config, dev_client).await
}

fn generate_oprf_auth_request(
    setup: &WorldIdIssuerSchemaDevClientSetup,
    action: FieldElement,
    nonce: FieldElement,
    blinding_factor: &BlindingFactor,
    authenticator_signature: EdDSASignature,
    query_material: &CircomGroth16Material,
) -> eyre::Result<CredentialBlindingFactorOprfRequestAuthV1> {
    let proof = world_id_oprf_dev_client::create_query_proof(
        world_id_oprf_dev_client::CreateQueryProofArgs {
            authenticator_signature,
            action,
            blinding_factor: blinding_factor.clone(),
            inclusion_proof: setup.inclusion_proof.clone(),
            key_set: setup.key_set.clone(),
            key_index: setup.key_index,
            query_material,
            nonce,
            rp_id: setup.issuer_schema_id,
        },
    )?;
    let auth = CredentialBlindingFactorOprfRequestAuthV1 {
        proof: proof.into(),
        action: *action,
        nonce: *nonce,
        merkle_root: *setup.inclusion_proof.root,
        issuer_schema_id: setup.issuer_schema_id,
    };

    Ok(auth)
}
