use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    primitives::Address,
    providers::DynProvider,
    signers::{SignerSync as _, k256::ecdsa::SigningKey, local::LocalSigner},
};
use ark_ff::UniformRand as _;
use clap::Parser;
use eyre::Context as _;
use rand::{CryptoRng, Rng, SeedableRng as _};
use taceo_oprf::{
    client::Connector,
    core::oprf::BlindingFactor,
    dev_client::{DevClient, DevClientConfig, StressTestItem, health_checks},
    types::{OprfKeyId, ShareEpoch, api::OprfRequest, async_trait, crypto::OprfPublicKey},
};
use uuid::Uuid;
use world_id_core::{
    EdDSASignature, FieldElement, api_types::AccountInclusionProof, proof::CircomGroth16Material,
};
use world_id_oprf_dev_client::{SharedDevClientComponents, WorldDevClientConfig};
use world_id_primitives::{
    AuthenticatorPublicKeySet, ProofRequest, RequestItem, RequestVersion, SessionFeType,
    SessionFieldElement as _, SessionId, TREE_DEPTH,
    merkle::MerkleInclusionProof,
    oprf::{NullifierOprfRequestAuthV1, OprfModule},
    rp::RpId,
};
use world_id_test_utils::anvil::RpRegistry;

#[derive(Parser, Debug)]
struct RpConfig {
    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_ID")]
    pub rp_id: u64,

    /// If set to `true`, will try to create a new OPRF key
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_CREATE_KEY")]
    pub create_key: bool,

    /// The Address of the RpRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_REGISTRY_CONTRACT")]
    pub rp_registry_contract: Address,

    #[clap(flatten)]
    base: WorldDevClientConfig,
}

struct WorldIdRpDevClient {
    rp_id: u64,
    create_key: bool,
    rp_registry_contract: Address,
    components: SharedDevClientComponents,
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
        let signer_address = self.components.signer.address();

        let (inclusion_proof, key_set, key_index) = self
            .components
            .fetch_inclusion_proof()
            .await
            .context("while fetching inclusion proof")?;

        tracing::info!("fetched data from authenticator");

        let rp_oprf_public_key = tokio::time::timeout(
            config.max_wait_time,
            self.setup_rp(config, signer_address, &provider),
        )
        .await
        .context("cannot setup RP in time")?
        .context("while setup of RP")?;

        Ok(WorldIdRpDevClientSetup {
            rp_id: RpId::from(self.rp_id),
            rp_oprf_public_key,
            inclusion_proof,
            key_set,
            key_index,
        })
    }

    async fn run_oprf(
        &self,
        _: &DevClientConfig,
        setup: Self::Setup,
        _: Connector,
    ) -> eyre::Result<ShareEpoch> {
        let mut rng = rand_chacha::ChaCha12Rng::from_rng(rand::thread_rng())?;
        let proof_request_uniqueness = create_proof_request(
            &setup,
            &self.components.signer,
            OprfModule::Nullifier,
            &mut rng,
        )
        .context("while creating proof request")?;
        let proof_request_session = create_proof_request(
            &setup,
            &self.components.signer,
            OprfModule::Session,
            &mut rng,
        )
        .context("while creating proof request")?;

        let account_inclusion_proof =
            AccountInclusionProof::new(setup.inclusion_proof.clone(), setup.key_set.clone());

        let (uniquness_nullifier, session_nullifier) = tokio::join!(
            self.components.authenticator.generate_nullifier(
                &proof_request_uniqueness,
                Some(account_inclusion_proof.clone())
            ),
            self.components
                .authenticator
                .generate_nullifier(&proof_request_session, Some(account_inclusion_proof),)
        );

        let uniqueness_epoch = uniquness_nullifier
            .context("while computing uniqueness")?
            .verifiable_oprf_output
            .epoch;
        let session_epoch = session_nullifier
            .context("while computing uniqueness")?
            .verifiable_oprf_output
            .epoch;

        // this is used to check whether we successfully transitioned to the next epoch so taking the max here is fine
        Ok(ShareEpoch::from(u32::max(
            uniqueness_epoch.into_inner(),
            session_epoch.into_inner(),
        )))
    }

    async fn prepare_stress_test_item<R: Rng + CryptoRng + Send>(
        &self,
        setup: &Self::Setup,
        rng: &mut R,
    ) -> eyre::Result<StressTestItem<Self::RequestAuth>> {
        let leaf_index = self.components.authenticator.leaf_index();
        let module = if rng.r#gen() {
            OprfModule::Nullifier
        } else {
            OprfModule::Session
        };

        let proof_request = create_proof_request(setup, &self.components.signer, module, rng)
            .context("while creating proof request")?;

        let request_id = Uuid::new_v4();
        let action = proof_request
            .action
            .unwrap_or_else(|| FieldElement::random_for_session(rng, SessionFeType::Action));
        let query_hash = world_id_primitives::authenticator::oprf_query_digest(
            leaf_index,
            action,
            proof_request.rp_id.into(),
        );
        let oprf_blinding_factor = BlindingFactor::rand(rng);
        let signature = self.components.authenticator_private_key.sign(*query_hash);

        let oprf_request_auth = generate_oprf_auth_request(
            setup,
            &proof_request,
            action,
            oprf_blinding_factor,
            signature,
            &self.components.query_material,
        )?;

        let blinded_query =
            taceo_oprf::core::oprf::client::blind_query(*query_hash, oprf_blinding_factor);

        let init_request = OprfRequest {
            request_id,
            blinded_query: blinded_query.blinded_query(),
            auth: oprf_request_auth,
        };
        Ok(StressTestItem {
            request_id,
            blinded_query,
            init_request,
            auth_module: module.to_string(),
        })
    }

    fn get_oprf_key(&self, setup: &Self::Setup) -> OprfPublicKey {
        setup.rp_oprf_public_key
    }
    fn get_oprf_key_id(&self, setup: &Self::Setup) -> OprfKeyId {
        OprfKeyId::from(setup.rp_id.into_inner())
    }
}

impl WorldIdRpDevClient {
    async fn new(config: &RpConfig) -> eyre::Result<Self> {
        let components = world_id_oprf_dev_client::init_shared_components(&config.base).await?;
        Ok(Self {
            create_key: config.create_key,
            rp_id: config.rp_id,
            rp_registry_contract: config.rp_registry_contract,
            components,
        })
    }

    async fn setup_rp(
        &self,
        config: &DevClientConfig,
        signer: Address,
        provider: &DynProvider,
    ) -> eyre::Result<OprfPublicKey> {
        if self.create_key {
            tracing::info!("trying to create new RP: {}", self.rp_id);
            let rp_registry = RpRegistry::new(self.rp_registry_contract, provider.clone());
            let receipt = rp_registry
                .register(
                    self.rp_id,
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
            tracing::info!("registered RP with id: {}", self.rp_id);
        }
        tracing::info!("fetching key from nodes..");
        health_checks::oprf_public_key_from_services(
            OprfKeyId::from(self.rp_id),
            ShareEpoch::default(),
            &config.nodes,
            config.max_wait_time,
        )
        .await
        .context("while fetching public key from services")
    }
}

fn create_proof_request<R: Rng + CryptoRng>(
    setup: &WorldIdRpDevClientSetup,
    signer: &LocalSigner<SigningKey>,
    auth: OprfModule,
    rng: &mut R,
) -> eyre::Result<ProofRequest> {
    let (action, session_id) = match auth {
        OprfModule::Nullifier => {
            // Explicitly set first byte to 0x00 — reserved for nullifier actions
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes[1..]);
            bytes[0] = 0x00;
            let a = FieldElement::from_be_bytes(&bytes).expect("Works");
            (Some(*a), None)
        }
        OprfModule::Session => {
            // Session RP signature does NOT include action
            let session_id = SessionId::from_r_seed(
                setup.key_index,
                FieldElement::random(rng),
                FieldElement::random_for_session(rng, SessionFeType::OprfSeed),
            )
            .context("while building SessionId")?;
            (None, Some(session_id))
        }
        _ => unreachable!("only have session and nullifier modules here"),
    };
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
        action,
    );
    let signature = signer.sign_message_sync(&msg)?;

    Ok(ProofRequest {
        id: "test_request".to_string(),
        version: RequestVersion::V1,
        created_at: current_timestamp,
        expires_at: expiration_timestamp,
        rp_id: setup.rp_id,
        oprf_key_id: OprfKeyId::from(setup.rp_id.into_inner()),
        session_id,
        action: action.map(FieldElement::from),
        signature,
        nonce: FieldElement::from(nonce),
        requests: vec![RequestItem {
            identifier: "test_credential".to_string(),
            issuer_schema_id: 1,
            signal: Some(b"my_signal".to_vec()),
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
    blinding_factor: BlindingFactor,
    authenticator_signature: EdDSASignature,
    query_material: &CircomGroth16Material,
) -> eyre::Result<NullifierOprfRequestAuthV1> {
    let proof = world_id_oprf_dev_client::create_query_proof(
        world_id_oprf_dev_client::CreateQueryProofArgs {
            authenticator_signature,
            action,
            blinding_factor,
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
        signature: Some(proof_request.signature),
        rp_id: proof_request.rp_id,
        wip101_data: None,
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

    let rp_config = RpConfig::parse();
    tracing::info!("starting with config: {rp_config:#?}");

    let dev_client = WorldIdRpDevClient::new(&rp_config)
        .await
        .context("while creating dev-client")?;

    taceo_oprf::dev_client::run(rp_config.base.config, dev_client).await
}
