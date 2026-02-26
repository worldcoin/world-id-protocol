use std::time::Duration;

use alloy::{
    primitives::{Address, U160, U256},
    providers::DynProvider,
};
use ark_ff::PrimeField as _;
use clap::Parser;
use eyre::Context as _;
use rand::{CryptoRng, Rng};
use taceo_oprf::{
    client::Connector,
    core::oprf::BlindingFactor,
    dev_client::{DevClient, DevClientConfig, StressTestItem},
    types::{OprfKeyId, ShareEpoch, api::OprfRequest, crypto::OprfPublicKey},
};
use taceo_oprf_test_utils::{async_trait, health_checks};
use uuid::Uuid;
use world_id_core::{EdDSAPrivateKey, EdDSASignature, FieldElement, proof::CircomGroth16Material};
use world_id_oprf_dev_client::{SharedDevClientComponents, WorldDevClientConfig};
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
struct IssuerSchemaConfig {
    /// Issuer schema id of already registered issuer
    #[clap(long, env = "OPRF_DEV_CLIENT_ISSUER_SCHEMA_ID")]
    pub issuer_schema_id: Option<u64>,

    /// The Address of the IssuerSchemaRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_ISSUER_SCHEMA_REGISTRY_CONTRACT")]
    pub issuer_schema_registry_contract: Address,

    #[clap(flatten)]
    base: WorldDevClientConfig,
}

struct WorldIdIssuerSchemaDevClient {
    issuer_schema_id: Option<u64>,
    issuer_schema_registry_contract: Address,
    components: SharedDevClientComponents,
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
        let signer_address = self.components.signer.address();

        let (inclusion_proof, key_set, key_index) = self
            .components
            .fetch_inclusion_proof()
            .await
            .context("while fetching inclusion proof")?;

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
            self.components.authenticator_private_key.clone(),
            setup.key_index,
        );

        let blinding_factor = OprfCredentialBlindingFactor::generate(
            &config.nodes,
            config.threshold,
            &self.components.query_material,
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
        let leaf_index = self.components.authenticator.leaf_index();
        let request_id = Uuid::new_v4();
        let action = FieldElement::ZERO;
        let nonce = FieldElement::random(rng);
        let query_hash = world_id_primitives::authenticator::oprf_query_digest(
            leaf_index,
            action,
            setup.issuer_schema_id.into(),
        );
        let oprf_blinding_factor = BlindingFactor::rand(rng);
        let signature = self.components.authenticator_private_key.sign(*query_hash);

        let oprf_request_auth = generate_oprf_auth_request(
            setup,
            action,
            nonce,
            &oprf_blinding_factor,
            signature,
            &self.components.query_material,
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
    async fn new(config: &IssuerSchemaConfig) -> eyre::Result<Self> {
        let components = world_id_oprf_dev_client::init_shared_components(&config.base).await?;
        Ok(Self {
            issuer_schema_id: config.issuer_schema_id,
            issuer_schema_registry_contract: config.issuer_schema_registry_contract,
            components,
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

#[tokio::main]
async fn main() -> eyre::Result<()> {
    taceo_nodes_observability::install_tracing(
        "world_id_oprf_dev_client_issuer_blinding=trace,taceo_oprf_dev_client=trace,warn",
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");

    let issuer_config = IssuerSchemaConfig::parse();
    tracing::info!("starting with config: {issuer_config:#?}");

    let dev_client = WorldIdIssuerSchemaDevClient::new(&issuer_config)
        .await
        .context("while creating dev-client")?;

    taceo_oprf::dev_client::run(issuer_config.base.config, dev_client).await
}
