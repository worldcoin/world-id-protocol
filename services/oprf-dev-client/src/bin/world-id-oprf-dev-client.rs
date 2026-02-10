use std::{
    collections::HashMap,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U160, U256},
    providers::{Provider as _, ProviderBuilder},
    signers::{
        SignerSync as _,
        k256::ecdsa::SigningKey,
        local::{LocalSigner, PrivateKeySigner},
    },
};

use ark_ff::{PrimeField as _, UniformRand as _};
use clap::Parser;
use eyre::{Context as _, OptionExt};
use rand::SeedableRng;
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret, SecretString};
use taceo_oprf::{
    client::Connector,
    core::oprf::{BlindedOprfRequest, BlindedOprfResponse, BlindingFactor},
    dev_client::{Command, StressTestOprfCommand},
    types::{OprfKeyId, ShareEpoch, api::OprfRequest, crypto::OprfPublicKey},
};
use taceo_oprf_test_utils::health_checks;
use test_utils::{
    anvil::{CredentialSchemaIssuerRegistry, ICredentialSchemaIssuerRegistry, RpRegistry},
    fixtures::build_base_credential,
};
use uuid::Uuid;
use world_id_core::{
    Authenticator, AuthenticatorError, Credential, EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature,
    FieldElement,
    proof::CircomGroth16Material,
    requests::{ProofRequest, RequestItem, RequestVersion},
};
use world_id_primitives::{
    Config, TREE_DEPTH,
    authenticator::AuthenticatorPublicKeySet,
    circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput},
    merkle::MerkleInclusionProof,
    oprf::{NullifierOprfRequestAuthV1, OprfModule},
    rp::RpId,
};

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfDevClientConfig {
    /// The URLs to all OPRF nodes
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_NODES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002"
    )]
    pub nodes: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_DEV_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// The Address of the OprfKeyRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT")]
    pub oprf_key_registry_contract: Address,

    /// The Address of the WorldIDRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_WORLD_ID_REGISTRY_CONTRACT")]
    pub world_id_registry_contract: Address,

    /// The Address of the RpRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_REGISTRY_CONTRACT")]
    pub rp_registry_contract: Address,

    /// The Address of the CredentialSchemaIssuerRegistry contract
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CREDENTIAL_SCHEMA_ISSUER_REGISTRY_CONTRACT"
    )]
    pub credential_schema_issuer_registry_contract: Address,

    /// The RPC for chain communication
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CHAIN_RPC_URL",
        default_value = "http://localhost:8545"
    )]
    pub chain_rpc_url: SecretString,

    /// The PRIVATE_KEY of the TACEO admin wallet - used to register the OPRF peers
    ///
    /// Default is anvil wallet 0
    #[clap(
        long,
        env = "TACEO_ADMIN_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub taceo_private_key: SecretString,

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

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_ID")]
    pub rp_id: Option<u64>,

    /// issuer schema id of already registered issuer
    #[clap(long, env = "OPRF_DEV_CLIENT_ISSUER_SCHEMA_ID")]
    pub issuer_schema_id: Option<u64>,

    /// The share epoch. Will be ignored if `rp_id` is `None`.
    #[clap(long, env = "OPRF_DEV_CLIENT_SHARE_EPOCH", default_value = "0")]
    pub share_epoch: u32,

    /// max wait time for init key-gen/reshare to succeed.
    #[clap(long, env = "OPRF_DEV_CLIENT_MAX_WAIT_TIME", default_value="2min", value_parser=humantime::parse_duration)]
    pub max_wait_time: Duration,

    /// Command
    #[command(subcommand)]
    pub command: Command,
}

fn create_and_sign_credential(
    issuer_schema_id: u64,
    issuer_pk: EdDSAPublicKey,
    issuer_sk: EdDSAPrivateKey,
    leaf_index: u64,
    credential_sub_blinding_factor: FieldElement,
) -> eyre::Result<Credential> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let mut credential = build_base_credential(
        issuer_schema_id,
        leaf_index,
        now,
        now + 3600,
        credential_sub_blinding_factor,
    );
    credential.issuer = issuer_pk;
    let credential_hash = credential
        .hash()
        .wrap_err("failed to hash credential prior to signing")?;
    credential.signature = Some(issuer_sk.sign(*credential_hash));

    Ok(credential)
}

fn create_proof_request(
    rp_id: RpId,
    oprf_key_id: OprfKeyId,
    issuer_schema_id: u64,
    signer: &LocalSigner<SigningKey>,
) -> eyre::Result<ProofRequest> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let nonce = ark_babyjubjub::Fq::rand(&mut rng);

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
        rp_id,
        oprf_key_id,
        session_id: None,
        action: Some(FieldElement::from(action)),
        signature,
        nonce: FieldElement::from(nonce),
        requests: vec![RequestItem {
            identifier: "test_credential".to_string(),
            issuer_schema_id,
            signal: Some("my_signal".to_string()),
            genesis_issued_at_min: None,
            expires_at_min: None,
        }],
        constraints: None,
    })
}

async fn run_nullifier(
    authenticator: &Authenticator,
    rp_id: RpId,
    rp_oprf_key_id: OprfKeyId,
    issuer_schema_id: u64,
    signer: &LocalSigner<SigningKey>,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let credential_sub_blinding_factor = authenticator
        .generate_credential_blinding_factor(issuer_schema_id)
        .await?;

    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();
    let credential = create_and_sign_credential(
        issuer_schema_id,
        issuer_pk,
        issuer_sk,
        authenticator.leaf_index(),
        credential_sub_blinding_factor,
    )?;

    let proof_request = create_proof_request(rp_id, rp_oprf_key_id, issuer_schema_id, signer)
        .context("while creating proof request")?;
    let request_item = proof_request
        .find_request_by_issuer_schema_id(issuer_schema_id)
        .ok_or_eyre("unexpectedly not found relevant request_item")?;

    let nullifier = authenticator
        .generate_nullifier(&proof_request)
        .await
        .context("while generating nullifier")?;

    let _proof_response = authenticator
        .generate_single_proof(
            nullifier,
            request_item,
            &credential,
            credential_sub_blinding_factor,
            FieldElement::random(&mut rng),
            proof_request.session_id,
            proof_request.created_at,
        )
        .context("while generating proof")?;

    Ok(())
}

struct NullifierStressTestItem {
    id: Uuid,
    query_input: QueryProofCircuitInput<TREE_DEPTH>,
    oprf_blinding_factor: BlindingFactor,
    oprf_request: OprfRequest<NullifierOprfRequestAuthV1>,
    credential: Credential,
    credential_sub_blinding_factor: FieldElement,
    session_id_r_seed: FieldElement,
    proof_request: ProofRequest,
}

#[expect(clippy::too_many_arguments)]
fn generate_oprf_auth_request(
    proof_request: &ProofRequest,
    action: FieldElement,
    blinding_factor: &BlindingFactor,
    authenticator_signature: EdDSASignature,
    key_set: AuthenticatorPublicKeySet,
    key_index: u64,
    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    query_material: &CircomGroth16Material,
) -> eyre::Result<(
    NullifierOprfRequestAuthV1,
    QueryProofCircuitInput<TREE_DEPTH>,
)> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let siblings: [ark_babyjubjub::Fq; TREE_DEPTH] = inclusion_proof.siblings.map(|s| *s);

    let query_proof_input = QueryProofCircuitInput::<TREE_DEPTH> {
        pk: key_set.as_affine_array(),
        pk_index: key_index.into(),
        s: authenticator_signature.s,
        r: authenticator_signature.r,
        merkle_root: *inclusion_proof.root,
        depth: ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
        mt_index: inclusion_proof.leaf_index.into(),
        siblings,
        beta: blinding_factor.beta(),
        rp_id: *FieldElement::from(proof_request.rp_id),
        action: *action,
        nonce: *proof_request.nonce,
    };

    let (proof, public_inputs) = query_material.generate_proof(&query_proof_input, &mut rng)?;
    query_material
        .verify_proof(&proof, &public_inputs)
        .expect("proof verifies");

    let auth = NullifierOprfRequestAuthV1 {
        proof: proof.into(),
        action: *action,
        nonce: *proof_request.nonce,
        merkle_root: *inclusion_proof.root,
        current_time_stamp: proof_request.created_at,
        expiration_timestamp: proof_request.expires_at,
        signature: proof_request.signature,
        rp_id: proof_request.rp_id,
    };

    Ok((auth, query_proof_input))
}

#[expect(clippy::too_many_arguments)]
fn prepare_nullifier_stress_test_oprf_request(
    authenticator: &Authenticator,
    authenticator_private_key: &EdDSAPrivateKey,
    rp_id: RpId,
    oprf_key_id: OprfKeyId,
    issuer_schema_id: u64,
    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    key_set: AuthenticatorPublicKeySet,
    key_index: u64,
    query_material: &CircomGroth16Material,
    signer: &LocalSigner<SigningKey>,
) -> eyre::Result<NullifierStressTestItem> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();
    let leaf_index = authenticator.leaf_index();
    // Generate a random credential sub blinding factor for stress test
    let credential_sub_blinding_factor = FieldElement::random(&mut rng);
    let credential = create_and_sign_credential(
        issuer_schema_id,
        issuer_pk,
        issuer_sk,
        leaf_index,
        credential_sub_blinding_factor,
    )?;

    let proof_request = create_proof_request(rp_id, oprf_key_id, issuer_schema_id, signer)
        .context("while creating proof request")?;

    let request_id = Uuid::new_v4();
    let action = proof_request.computed_action(&mut rng);
    let query_hash = world_id_primitives::authenticator::oprf_query_digest(
        leaf_index,
        action,
        proof_request.rp_id.into(),
    );
    let oprf_blinding_factor = BlindingFactor::rand(&mut rng);
    let signature = authenticator_private_key.sign(*query_hash);

    let (oprf_request_auth, query_input) = generate_oprf_auth_request(
        &proof_request,
        action,
        &oprf_blinding_factor,
        signature,
        key_set,
        key_index,
        inclusion_proof,
        query_material,
    )?;

    let blinded_request =
        taceo_oprf::core::oprf::client::blind_query(*query_hash, oprf_blinding_factor.clone());

    let oprf_request = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        auth: oprf_request_auth,
    };

    let request = NullifierStressTestItem {
        id: request_id,
        query_input,
        oprf_blinding_factor,
        oprf_request,
        credential,
        credential_sub_blinding_factor,
        proof_request,
        session_id_r_seed: FieldElement::random(&mut rng),
    };

    Ok(request)
}

#[expect(clippy::too_many_arguments)]
async fn stress_test(
    authenticator: &Authenticator,
    authenticator_private_key: EdDSAPrivateKey,
    rp_id: RpId,
    rp_oprf_key_id: OprfKeyId,
    rp_oprf_public_key: OprfPublicKey,
    issuer_schema_id: u64,
    cmd: StressTestOprfCommand,
    connector: Connector,
    signer: &LocalSigner<SigningKey>,
) -> eyre::Result<()> {
    let mut rng = rand::thread_rng();
    let nodes = authenticator.config.nullifier_oracle_urls().to_vec();
    let threshold = authenticator.config.nullifier_oracle_threshold();
    let (inclusion_proof, key_set) = authenticator.fetch_inclusion_proof().await?;

    let key_index = key_set
        .iter()
        .position(|pk| pk.pk == authenticator.offchain_pubkey().pk)
        .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;

    let query_material =
        world_id_core::proof::load_embedded_query_material(Option::<PathBuf>::None)?;
    let nullifier_material =
        world_id_core::proof::load_embedded_nullifier_material(Option::<PathBuf>::None)?;

    let mut requests = HashMap::with_capacity(cmd.runs);
    let mut init_requests = HashMap::with_capacity(cmd.runs);

    tracing::info!("preparing requests..");
    for _ in 0..cmd.runs {
        let req = prepare_nullifier_stress_test_oprf_request(
            authenticator,
            &authenticator_private_key,
            rp_id,
            rp_oprf_key_id,
            issuer_schema_id,
            inclusion_proof.clone(),
            key_set.clone(),
            key_index,
            &query_material,
            signer,
        )?;
        init_requests.insert(req.id, req.oprf_request.clone());
        requests.insert(req.id, req);
    }

    tracing::info!("sending init requests..");
    let (sessions, finish_requests) = taceo_oprf::dev_client::send_init_requests(
        &nodes,
        OprfModule::Nullifier.to_string().as_str(),
        threshold,
        connector,
        cmd.sequential,
        init_requests,
    )
    .await?;

    tracing::info!("sending finish requests..");
    let responses = taceo_oprf::dev_client::send_finish_requests(
        sessions,
        cmd.sequential,
        finish_requests.clone(),
    )
    .await?;

    if !cmd.skip_checks {
        tracing::info!("checking nullifier + proofs");
        for (id, res) in responses {
            let req = requests.get(&id).expect("is there");
            let finish_request = finish_requests.get(&id).expect("is there").clone();
            let dlog_proof = taceo_oprf::client::verify_dlog_equality(
                id,
                rp_oprf_public_key,
                &BlindedOprfRequest::new(req.oprf_request.blinded_query),
                res,
                finish_request.clone(),
            )?;
            let blinded_response = finish_request.blinded_response();
            let blinding_factor_prepared = req.oprf_blinding_factor.clone().prepare();
            let oprf_blinded_response = BlindedOprfResponse::new(blinded_response);
            let unblinded_response =
                oprf_blinded_response.unblind_response(&blinding_factor_prepared);
            let cred_signature = req.credential.signature.clone().expect("signed cred");

            let nullifier_input = NullifierProofCircuitInput::<TREE_DEPTH> {
                query_input: req.query_input.clone(),
                dlog_e: dlog_proof.e,
                dlog_s: dlog_proof.s,
                oprf_pk: rp_oprf_public_key.inner(),
                oprf_response_blinded: blinded_response,
                oprf_response: unblinded_response,
                signal_hash: *req.proof_request.requests[0].signal_hash(),
                id_commitment_r: *req.session_id_r_seed,
                id_commitment: *req.proof_request.session_id.unwrap_or(FieldElement::ZERO),
                issuer_schema_id: req.credential.issuer_schema_id.into(),
                cred_pk: req.credential.issuer.pk,
                cred_hashes: [
                    *req.credential.claims_hash()?,
                    *req.credential.associated_data_hash,
                ],
                cred_genesis_issued_at: req.credential.genesis_issued_at.into(),
                cred_expires_at: req.credential.expires_at.into(),
                cred_s: cred_signature.s,
                cred_r: cred_signature.r,
                // no explicit expires_at_min constraint is passed, so the default is `created_at`
                current_timestamp: req.proof_request.created_at.into(),
                cred_genesis_issued_at_min: req.proof_request.requests[0]
                    .genesis_issued_at_min
                    .unwrap_or(0)
                    .into(),
                cred_sub_blinding_factor: *req.credential_sub_blinding_factor,
                cred_id: req.credential.id.into(),
            };

            let (proof, public) = nullifier_material.generate_proof(&nullifier_input, &mut rng)?;
            nullifier_material.verify_proof(&proof, &public)?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    taceo_nodes_observability::install_tracing(
        "world_id_oprf_dev_client=trace,taceo_oprf_dev_client=trace,warn",
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = OprfDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");

    tracing::info!("health check for all peers...");
    health_checks::services_health_check(&config.nodes, Duration::from_secs(5))
        .await
        .context("while doing health checks")?;
    tracing::info!("everyone online..");

    let private_key = PrivateKeySigner::from_str(config.taceo_private_key.expose_secret())?;
    let address = private_key.address();
    let wallet = EthereumWallet::from(private_key.clone());

    tracing::info!("init rpc provider..");
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(config.chain_rpc_url.expose_secret())
        .await
        .context("while connecting to RPC")?
        .erased();

    let (rp_id, rp_oprf_key_id, rp_oprf_public_key) = if let Some(rp_id) = config.rp_id {
        // TODO should maybe check if the oprf key id matches the registered one in case it was changed
        // in case they are not the same, we return them both
        let oprf_key_id = OprfKeyId::new(U160::from(rp_id));
        let share_epoch = ShareEpoch::new(config.share_epoch);
        let oprf_public_key = health_checks::oprf_public_key_from_services(
            oprf_key_id,
            share_epoch,
            &config.nodes,
            Duration::from_secs(10), // should already be there
        )
        .await?;
        (RpId::new(rp_id), oprf_key_id, oprf_public_key)
    } else {
        let rp_registry = RpRegistry::new(config.rp_registry_contract, provider.clone());
        let rp_id = RpId::new(rand::random());
        let oprf_key_id = OprfKeyId::new(U160::from(rp_id.into_inner()));
        tracing::info!("registering new RP");
        let receipt = rp_registry
            .register(
                rp_id.into_inner(),
                address,
                address,
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
        let oprf_public_key = health_checks::oprf_public_key_from_services(
            oprf_key_id,
            ShareEpoch::default(),
            &config.nodes,
            config.max_wait_time,
        )
        .await?;
        (rp_id, oprf_key_id, oprf_public_key)
    };

    let (issuer_schema_id, _issuer_oprf_public_key) =
        if let Some(issuer_schema_id) = config.issuer_schema_id {
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
            (issuer_schema_id, oprf_public_key)
        } else {
            tracing::info!("registering new credential schema issuer");
            let credential_schema_issuer_registry = CredentialSchemaIssuerRegistry::new(
                config.credential_schema_issuer_registry_contract,
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
                .register(issuer_schema_id, issuer_public_key, address)
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
            (issuer_schema_id, oprf_public_key)
        };

    let world_config = Config::new(
        Some(config.chain_rpc_url.expose_secret().to_string()),
        31_337, // anvil hardhat chain id
        config.world_id_registry_contract,
        config.indexer_url,
        config.gateway_url,
        config.nodes.clone(),
        config.threshold,
    )
    .unwrap();

    tracing::info!("creating account..");
    let seed = [7u8; 32];
    let authenticator = Authenticator::init_or_register(&seed, world_config.clone(), None).await?;
    let authenticator_private_key = EdDSAPrivateKey::from_bytes(seed);

    // setup TLS config - even if we are http
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(rustls_config));

    match config.command {
        Command::Test => {
            tracing::info!("running single nullifier");
            run_nullifier(
                &authenticator,
                rp_id,
                rp_oprf_key_id,
                issuer_schema_id,
                &private_key,
            )
            .await?;
            tracing::info!("nullifier successful");
        }
        Command::StressTestOprf(cmd) => {
            tracing::info!("running stress-test");
            stress_test(
                &authenticator,
                authenticator_private_key,
                rp_id,
                rp_oprf_key_id,
                rp_oprf_public_key,
                issuer_schema_id,
                cmd,
                connector,
                &private_key,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
        Command::StressTestKeyGen(_) => {
            todo!()
        }
        Command::ReshareTest(_) => {
            todo!()
            // tracing::info!("running reshare test");
            // tracing::info!("reshare test successful");
        }
    }

    Ok(())
}
