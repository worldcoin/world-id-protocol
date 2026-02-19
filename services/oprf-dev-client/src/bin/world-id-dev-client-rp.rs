use std::{
    str::FromStr as _,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Address, U160},
    providers::DynProvider,
    signers::{
        SignerSync as _,
        k256::ecdsa::SigningKey,
        local::{LocalSigner, PrivateKeySigner},
    },
};
use ark_ff::UniformRand as _;
use clap::Parser;
use eyre::Context as _;
use rand::{CryptoRng, Rng, SeedableRng as _};
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
    ProofRequest, RequestItem, RequestVersion, TREE_DEPTH,
    authenticator::AuthenticatorPublicKeySet,
    merkle::MerkleInclusionProof,
    oprf::{NullifierOprfRequestAuthV1, OprfModule},
    rp::RpId,
};
use world_id_test_utils::anvil::RpRegistry;

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
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_ID")]
    pub rp_id: Option<u64>,

    /// The Address of the WorldIDRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_WORLD_ID_REGISTRY_CONTRACT")]
    pub world_id_registry_contract: Address,

    /// The Address of the RpRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_REGISTRY_CONTRACT")]
    pub rp_registry_contract: Address,

    #[clap(flatten)]
    config: DevClientConfig,
}

struct WorldIdRpDevClient {
    rp_id: Option<u64>,
    rp_registry_contract: Address,
    authenticator: Authenticator,
    signer: LocalSigner<SigningKey>,
    authenticator_private_key: EdDSAPrivateKey,
    query_material: Arc<CircomGroth16Material>,
}

#[derive(Clone)]
struct WorldIdRpDevClientSetup {
    rp_id: RpId,
    rp_oprf_public_key: OprfPublicKey,

    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    key_set: AuthenticatorPublicKeySet,
    key_index: u64,
}

#[async_trait::async_trait]
impl DevClient for WorldIdRpDevClient {
    type Setup = WorldIdRpDevClientSetup;
    type RequestAuth = NullifierOprfRequestAuthV1;

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
        tracing::info!("fetched data from authenticator");

        let (rp_id, rp_oprf_public_key) = tokio::time::timeout(
            config.max_wait_time,
            self.setup_rp(config, signer_address, &provider),
        )
        .await
        .context("cannot setup RP in time")?
        .context("while setup of RP")?;

        Ok(WorldIdRpDevClientSetup {
            rp_id,
            rp_oprf_public_key,
            inclusion_proof,
            key_set,
            key_index,
        })
    }

    async fn run_oprf(
        &self,
        _config: &DevClientConfig,
        setup: Self::Setup,
        _connector: Connector,
    ) -> eyre::Result<ShareEpoch> {
        let mut rng = rand_chacha::ChaCha12Rng::from_rng(rand::thread_rng())?;
        let proof_request = create_proof_request(&setup, &self.signer, &mut rng)
            .context("while creating proof request")?;
        let nullifier = self
            .authenticator
            .generate_nullifier(
                &proof_request,
                setup.inclusion_proof.clone(),
                setup.key_set.clone(),
            )
            .await
            .context("while generating nullifier")?;

        Ok(nullifier.verifiable_oprf_output.epoch)
    }

    async fn prepare_stress_test_item<R: Rng + CryptoRng + Send>(
        &self,
        setup: &Self::Setup,
        rng: &mut R,
    ) -> eyre::Result<StressTestItem<Self::RequestAuth>> {
        let leaf_index = self.authenticator.leaf_index();
        let proof_request = create_proof_request(setup, &self.signer, rng)
            .context("while creating proof request")?;

        let request_id = Uuid::new_v4();
        let action = proof_request.computed_action(rng);
        let query_hash = world_id_primitives::authenticator::oprf_query_digest(
            leaf_index,
            action,
            proof_request.rp_id.into(),
        );
        let oprf_blinding_factor = BlindingFactor::rand(rng);
        let signature = self.authenticator_private_key.sign(*query_hash);

        let oprf_request_auth = generate_oprf_auth_request(
            setup,
            &proof_request,
            action,
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
        setup.rp_oprf_public_key
    }
    fn get_oprf_key_id(&self, setup: &Self::Setup) -> OprfKeyId {
        OprfKeyId::from(setup.rp_id.into_inner())
    }

    fn auth_module(&self) -> String {
        OprfModule::Nullifier.to_string()
    }
}

impl WorldIdRpDevClient {
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
            rp_id: config.rp_id,
            rp_registry_contract: config.rp_registry_contract,
            authenticator,
            signer,
            authenticator_private_key,
            query_material,
        })
    }

    async fn setup_rp(
        &self,
        config: &DevClientConfig,
        signer: Address,
        provider: &DynProvider,
    ) -> eyre::Result<(RpId, OprfPublicKey)> {
        if let Some(rp_id) = self.rp_id {
            let oprf_key_id = OprfKeyId::new(U160::from(rp_id));
            let share_epoch = ShareEpoch::new(config.share_epoch);
            let oprf_public_key = health_checks::oprf_public_key_from_services(
                oprf_key_id,
                share_epoch,
                &config.nodes,
                Duration::from_secs(10), // should already be there
            )
            .await?;
            Ok((RpId::new(rp_id), oprf_public_key))
        } else {
            let rp_registry = RpRegistry::new(self.rp_registry_contract, provider.clone());
            let rp_id = RpId::new(rand::random());
            let oprf_key_id = OprfKeyId::new(U160::from(rp_id.into_inner()));
            tracing::info!("registering new RP");
            let receipt = rp_registry
                .register(
                    rp_id.into_inner(),
                    signer,
                    signer,
                    "taceo.oprf.dev.client".to_string(),
                )
                .gas(10000000)
                .send()
                .await?
                .get_receipt()
                .await?;
            if !receipt.status() {
                eyre::bail!("failed to register RP");
            }
            tracing::info!("registered RP with OPRF key: {oprf_key_id}");
            tracing::info!("now waiting for key-gen to finish");
            let oprf_public_key = health_checks::oprf_public_key_from_services(
                oprf_key_id,
                ShareEpoch::default(),
                &config.nodes,
                config.max_wait_time,
            )
            .await?;
            Ok((rp_id, oprf_public_key))
        }
    }
}

fn create_proof_request<R: Rng + CryptoRng>(
    setup: &WorldIdRpDevClientSetup,
    signer: &LocalSigner<SigningKey>,
    rng: &mut R,
) -> eyre::Result<ProofRequest> {
    let action = ark_babyjubjub::Fq::rand(rng);
    let nonce = ark_babyjubjub::Fq::rand(rng);

    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let expiration_timestamp = current_timestamp + 300; // 5 minutes from now

    let msg = world_id_primitives::rp::compute_rp_signature_msg(
        nonce,
        current_timestamp,
        expiration_timestamp,
    );
    let signature = signer.sign_message_sync(&msg)?;

    Ok(ProofRequest {
        id: "test_request".to_string(),
        version: RequestVersion::V1,
        created_at: current_timestamp,
        expires_at: expiration_timestamp,
        rp_id: setup.rp_id,
        oprf_key_id: OprfKeyId::from(setup.rp_id.into_inner()),
        session_id: None,
        action: Some(FieldElement::from(action)),
        signature,
        nonce: FieldElement::from(nonce),
        requests: vec![RequestItem {
            identifier: "test_credential".to_string(),
            issuer_schema_id: 1,
            signal: Some("my_signal".to_string()),
            genesis_issued_at_min: None,
            expires_at_min: None,
        }],
        constraints: None,
    })
}

fn generate_oprf_auth_request(
    setup: &WorldIdRpDevClientSetup,
    proof_request: &ProofRequest,
    action: FieldElement,
    blinding_factor: &BlindingFactor,
    authenticator_signature: EdDSASignature,
    query_material: &CircomGroth16Material,
) -> eyre::Result<NullifierOprfRequestAuthV1> {
    let proof = world_id_oprf_dev_client::create_query_proof(
        world_id_oprf_dev_client::CreateQueryProofArgs {
            authenticator_signature,
            action,
            blinding_factor: blinding_factor.clone(),
            inclusion_proof: setup.inclusion_proof.clone(),
            key_set: setup.key_set.clone(),
            key_index: setup.key_index,
            query_material,
            nonce: proof_request.nonce,
            rp_id: setup.rp_id.into_inner(),
        },
    )?;

    let auth = NullifierOprfRequestAuthV1 {
        proof: proof.into(),
        action: *action,
        nonce: *proof_request.nonce,
        merkle_root: *setup.inclusion_proof.root,
        current_time_stamp: proof_request.created_at,
        expiration_timestamp: proof_request.expires_at,
        signature: proof_request.signature,
        rp_id: proof_request.rp_id,
    };

    Ok(auth)
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
    let dev_client = WorldIdRpDevClient::new(&config)
        .await
        .context("while creating dev-client")?;
    taceo_oprf::dev_client::run(config.config, dev_client).await
}
