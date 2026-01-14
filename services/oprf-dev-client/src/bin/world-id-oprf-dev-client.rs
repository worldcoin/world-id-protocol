use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Address, U160},
    signers::k256::ecdsa::{signature::Signer as _, SigningKey},
};
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};
use clap::{Parser, Subcommand};
use eyre::Context as _;
use rand::SeedableRng;
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret, SecretString};
use taceo_oprf_client::Connector;
use taceo_oprf_core::oprf::{BlindedOprfRequest, BlindedOprfResponse, BlindingFactor};
use taceo_oprf_test::{health_checks, oprf_key_registry_scripts};
use taceo_oprf_types::{
    api::v1::{OprfRequest, ShareIdentifier},
    crypto::OprfPublicKey,
    OprfKeyId, ShareEpoch,
};
use test_utils::fixtures::build_base_credential;
use tokio::task::JoinSet;
use uuid::Uuid;
use world_id_core::{
    proof::CircomGroth16Material,
    requests::{ProofRequest, RequestItem, RequestVersion},
    Authenticator, AuthenticatorError, Credential, EdDSAPrivateKey, EdDSAPublicKey, FieldElement,
    HashableCredential,
};

use world_id_primitives::{
    authenticator::AuthenticatorPublicKeySet,
    circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput},
    merkle::MerkleInclusionProof,
    oprf::OprfRequestAuthV1,
    proof::SingleProofInput,
    rp::RpId,
    Config, TREE_DEPTH,
};

const ISSUER_SCHEMA_ID: u64 = 1;

#[derive(Parser, Debug)]
pub struct StressTestCommand {
    /// The amount of nullifiers to generate
    #[clap(long, env = "OPRF_DEV_CLIENT_NULLIFIER_NUM", default_value = "10")]
    pub nullifier_num: usize,

    /// Send requests sequentially instead of concurrently
    #[clap(long, env = "OPRF_DEV_CLIENT_SEQUENTIAL")]
    pub sequential: bool,

    /// Send requests sequentially instead of concurrently
    #[clap(long, env = "OPRF_DEV_CLIENT_SEQUENTIAL")]
    pub skip_checks: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Test,
    StressTest(StressTestCommand),
}

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfDevClientConfig {
    /// The URLs to all OPRF Services
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_SERVICES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002"
    )]
    pub services: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_DEV_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// The Address of the OprfKeyRegistry contract.
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT",
        default_value = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"
    )]
    pub oprf_key_registry_contract: Address,

    /// The Address of the WorldIDRegistry contract.
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_WORLD_ID_REGISTRY_CONTRACT",
        default_value = "0xB235407CA24410938A90890D9e218Bb60e8A65b6"
    )]
    pub world_id_registry_contract: Address,

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
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_ID")]
    pub oprf_key_id: Option<U160>,

    /// max wait time for init key-gen to succeed.
    #[clap(long, env = "OPRF_DEV_CLIENT_KEY_GEN_WAIT_TIME", default_value="2min", value_parser=humantime::parse_duration)]
    pub max_wait_time_key_gen: Duration,

    /// Command
    #[command(subcommand)]
    pub command: Command,
}

fn create_and_sign_credential(
    issuer_pk: EdDSAPublicKey,
    issuer_sk: EdDSAPrivateKey,
    leaf_index: u64,
) -> eyre::Result<(Credential, FieldElement)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let (mut credential, credential_sub_blinding_factor) =
        build_base_credential(ISSUER_SCHEMA_ID, leaf_index, now, now + 3600);
    credential.issuer = issuer_pk;
    let credential_hash = credential
        .hash()
        .wrap_err("failed to hash credential prior to signing")?;
    credential.signature = Some(issuer_sk.sign(*credential_hash));

    Ok((credential, credential_sub_blinding_factor))
}

async fn run_nullifier(
    authenticator: &Authenticator,
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();
    let (credential, credential_sub_blinding_factor) = create_and_sign_credential(
        issuer_pk,
        issuer_sk,
        authenticator
            .leaf_index()
            .try_into()
            .expect("leaf_index fits into u64"),
    )?;

    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let nonce = ark_babyjubjub::Fq::rand(&mut rng);
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_timestamp.to_le_bytes());
    let signing_key = SigningKey::random(&mut rng); // TODO oprf nodes need this to verify the signature (not done atm)
    let signature = signing_key.sign(&msg);

    let proof_request = ProofRequest {
        id: "test_request".to_string(),
        version: RequestVersion::V1,
        created_at: current_timestamp,
        expires_at: current_timestamp + 300, // 5 minutes from now
        rp_id: RpId::new(oprf_key_id.into_inner()),
        action: FieldElement::from(action),
        oprf_public_key,
        signature,
        nonce: FieldElement::from(nonce),
        requests: vec![RequestItem {
            identifier: "test_credential".to_string(),
            issuer_schema_id: ISSUER_SCHEMA_ID.into(),
            signal: Some("my_signal".to_string()),
            genesis_issued_at_min: None,
            session_id: None,
        }],
        constraints: None,
    };

    let (_proof, _nullifier) = authenticator
        .generate_proof(proof_request, credential, credential_sub_blinding_factor)
        .await
        .context("while generating proof")?;

    Ok(())
}

#[expect(clippy::too_many_arguments)]
fn prepare_nullifier_stress_test_oprf_request(
    authenticator: &Authenticator,
    authenticator_private_key: &EdDSAPrivateKey,
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    key_set: AuthenticatorPublicKeySet,
    key_index: u64,
    query_material: &CircomGroth16Material,
) -> eyre::Result<(
    SingleProofInput<TREE_DEPTH>,
    QueryProofCircuitInput<TREE_DEPTH>,
    BlindingFactor,
    OprfRequest<OprfRequestAuthV1>,
)> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();
    let (credential, credential_sub_blinding_factor) = create_and_sign_credential(
        issuer_pk,
        issuer_sk,
        authenticator
            .leaf_index()
            .try_into()
            .expect("leaf_index fits into u64"),
    )?;

    // TODO: convert rp_request to primitives types
    let primitives_rp_id = world_id_primitives::rp::RpId::new(oprf_key_id.into_inner());

    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let nonce = ark_babyjubjub::Fq::rand(&mut rng);
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_timestamp.to_le_bytes());
    let signing_key = SigningKey::random(&mut rng); // TODO oprf nodes need this to verify the signature (not done atm)
    let signature = signing_key.sign(&msg);

    let signal_hash = ark_babyjubjub::Fq::rand(&mut rng);

    let request_id = Uuid::new_v4();
    let mut rng = rand::thread_rng();

    // FIXME: sub blinding factor
    let args = SingleProofInput::<TREE_DEPTH> {
        credential,
        inclusion_proof,
        key_set,
        key_index,
        session_id_r_seed: FieldElement::random(&mut rng),
        rp_id: primitives_rp_id,
        share_epoch: ShareEpoch::default().into_inner(),
        action: action.into(),
        nonce: nonce.into(),
        current_timestamp,
        rp_signature: signature,
        oprf_public_key,
        signal_hash: signal_hash.into(),
        credential_sub_blinding_factor,
        genesis_issued_at_min: 0,
    };

    let query_hash =
        world_id_core::proof::query_hash(args.inclusion_proof.leaf_index, args.rp_id, args.action);
    let blinding_factor = BlindingFactor::rand(&mut rng);

    let (oprf_request_auth, query_input) = world_id_core::proof::oprf_request_auth(
        &args,
        query_material,
        authenticator_private_key,
        query_hash,
        &blinding_factor,
        &mut rng,
    )?;

    let blinded_request =
        taceo_oprf_core::oprf::client::blind_query(query_hash, blinding_factor.clone());

    let req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        share_identifier: ShareIdentifier {
            oprf_key_id,
            share_epoch: ShareEpoch::default(),
        },
        auth: oprf_request_auth,
    };

    Ok((args, query_input, blinding_factor, req))
}

fn avg(durations: &[Duration]) -> Duration {
    let n = durations.len();
    if n != 0 {
        let total = durations.iter().sum::<Duration>();
        total / n as u32
    } else {
        Duration::ZERO
    }
}

async fn stress_test(
    authenticator: &Authenticator,
    authenticator_private_key: EdDSAPrivateKey,
    oprf_key_id: OprfKeyId,
    oprf_public_key: OprfPublicKey,
    cmd: StressTestCommand,
    connector: Connector,
) -> eyre::Result<()> {
    let (inclusion_proof, key_set) = authenticator.fetch_inclusion_proof().await?;

    let key_index = key_set
        .iter()
        .position(|pk| pk.pk == authenticator.offchain_pubkey().pk)
        .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;

    let query_material = world_id_core::proof::load_embedded_query_material();
    let nullifier_material = world_id_core::proof::load_embedded_nullifier_material();

    tracing::info!("preparing requests..");
    let mut request_ids = HashMap::with_capacity(cmd.nullifier_num);
    let mut oprf_args = HashMap::with_capacity(cmd.nullifier_num);
    let mut query_inputs = HashMap::with_capacity(cmd.nullifier_num);
    let mut blinded_queries = HashMap::with_capacity(cmd.nullifier_num);
    let mut blinding_factors = HashMap::with_capacity(cmd.nullifier_num);
    let mut init_requests = Vec::with_capacity(cmd.nullifier_num);

    for idx in 0..cmd.nullifier_num {
        let (args, query_input, blinding_factor, req) = prepare_nullifier_stress_test_oprf_request(
            authenticator,
            &authenticator_private_key,
            oprf_key_id,
            oprf_public_key,
            inclusion_proof.clone(),
            key_set.clone(),
            key_index,
            &query_material,
        )?;
        request_ids.insert(idx, req.request_id);
        oprf_args.insert(idx, args);
        query_inputs.insert(idx, query_input);
        blinded_queries.insert(idx, req.blinded_query);
        blinding_factors.insert(idx, blinding_factor);
        init_requests.push(req);
    }

    let mut init_results = JoinSet::new();

    tracing::info!("start sending init requests..");
    let start = Instant::now();
    for (idx, req) in init_requests.into_iter().enumerate() {
        let services = authenticator.config.nullifier_oracle_urls().to_vec();
        let threshold = authenticator.config.nullifier_oracle_threshold();
        let connector = connector.clone();
        init_results.spawn(async move {
            let init_start = Instant::now();
            let sessions =
                taceo_oprf_client::init_sessions(&services, threshold, req, connector).await?;
            eyre::Ok((idx, sessions, init_start.elapsed()))
        });
        if cmd.sequential {
            init_results.join_next().await;
        }
    }
    let init_results = init_results.join_all().await;
    let init_full_duration = start.elapsed();
    let mut sessions = Vec::with_capacity(cmd.nullifier_num);
    let mut durations = Vec::with_capacity(cmd.nullifier_num);
    for result in init_results {
        match result {
            Ok((idx, session, duration)) => {
                sessions.push((idx, session));
                durations.push(duration);
            }
            Err(err) => tracing::error!("Got an error during init: {err:?}"),
        }
    }
    if durations.len() != cmd.nullifier_num {
        eyre::bail!("init did encounter errors - see logs");
    }
    let init_throughput = cmd.nullifier_num as f64 / init_full_duration.as_secs_f64();
    let init_avg = avg(&durations);

    let mut finish_challenges = sessions
        .iter()
        .map(|(idx, sessions)| {
            let challenge_request = taceo_oprf_client::generate_challenge_request(sessions);
            eyre::Ok((*idx, challenge_request))
        })
        .collect::<eyre::Result<HashMap<_, _>>>()?;

    let mut finish_results = JoinSet::new();

    tracing::info!("start sending finish requests..");
    durations.clear();
    let start = Instant::now();
    for (idx, sessions) in sessions {
        let challenge = finish_challenges.remove(&idx).expect("is there");
        finish_results.spawn(async move {
            let finish_start = Instant::now();
            let responses = taceo_oprf_client::finish_sessions(sessions, challenge.clone()).await?;
            let duration = finish_start.elapsed();
            eyre::Ok((idx, responses, challenge, duration))
        });
        if cmd.sequential {
            finish_results.join_next().await;
        }
    }
    let finish_results = finish_results.join_all().await;
    if cmd.skip_checks {
        tracing::info!("got all results - skipping checks");
    } else {
        tracing::info!("got all results - checking nullifiers + proofs");
    }
    let finish_full_duration = start.elapsed();

    let mut durations = Vec::with_capacity(cmd.nullifier_num);

    let mut rng = rand::thread_rng();
    for result in finish_results {
        match result {
            Ok((idx, responses, challenge, duration)) => {
                if !cmd.skip_checks {
                    let request_id = request_ids.remove(&idx).expect("is there");
                    let args = oprf_args.remove(&idx).expect("is there");
                    let query_input = query_inputs.remove(&idx).expect("is there");
                    let blinded_query = blinded_queries.remove(&idx).expect("is there");
                    let blinding_factor = blinding_factors.remove(&idx).expect("is there");
                    let dlog_proof = taceo_oprf_client::verify_dlog_equality(
                        request_id,
                        oprf_public_key,
                        &BlindedOprfRequest::new(blinded_query),
                        responses,
                        challenge.clone(),
                    )?;
                    let blinded_response = challenge.blinded_response();
                    let blinding_factor_prepared = blinding_factor.prepare();
                    let oprf_blinded_response = BlindedOprfResponse::new(blinded_response);
                    let unblinded_response =
                        oprf_blinded_response.unblind_response(&blinding_factor_prepared);
                    let cred_signature = args.credential.signature.clone().expect("signed cred");
                    let nullifier_input = NullifierProofCircuitInput::<TREE_DEPTH> {
                        query_input,
                        dlog_e: dlog_proof.e,
                        dlog_s: dlog_proof.s,
                        oprf_pk: oprf_public_key.inner(),
                        oprf_response_blinded: blinded_response,
                        oprf_response: unblinded_response,
                        signal_hash: *args.signal_hash,
                        id_commitment_r: *args.session_id_r_seed,
                        issuer_schema_id: args.credential.issuer_schema_id.into(),
                        cred_pk: args.credential.issuer.pk,
                        cred_hashes: [
                            *args.credential.claims_hash()?,
                            *args.credential.associated_data_hash,
                        ],
                        cred_genesis_issued_at: args.credential.genesis_issued_at.into(),
                        cred_expires_at: args.credential.expires_at.into(),
                        cred_s: cred_signature.s,
                        cred_r: cred_signature.r,
                        current_timestamp: args.current_timestamp.into(),
                        cred_genesis_issued_at_min: args.genesis_issued_at_min.into(),
                        cred_sub_blinding_factor: *args.credential_sub_blinding_factor,
                        cred_id: args.credential.id.into(),
                    };
                    let (proof, public) =
                        nullifier_material.generate_proof(&nullifier_input, &mut rng)?;
                    nullifier_material.verify_proof(&proof, &public)?;
                }
                durations.push(duration);
            }
            Err(err) => tracing::error!("Got an error during finish: {err:?}"),
        }
    }

    tracing::info!(
        "init req - total time: {init_full_duration:?} avg: {init_avg:?} throughput: {init_throughput} req/s"
    );
    let final_throughput = cmd.nullifier_num as f64 / finish_full_duration.as_secs_f64();
    let finish_avg = avg(&durations);
    tracing::info!(
        "finish req - total time: {finish_full_duration:?} avg: {finish_avg:?} throughput: {final_throughput} req/s"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    taceo_nodes_observability::install_tracing("world_id_oprf_dev_client=trace,warn");
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = OprfDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");

    tracing::info!("health check for all peers...");
    health_checks::services_health_check(&config.services, Duration::from_secs(5))
        .await
        .context("while doing health checks")?;
    tracing::info!("everyone online..");

    let (oprf_key_id, oprf_public_key) = if let Some(oprf_key_id) = config.oprf_key_id {
        let oprf_key_id = OprfKeyId::new(oprf_key_id);
        let oprf_public_key = taceo_oprf_test::health_checks::oprf_public_key_from_services(
            oprf_key_id,
            ShareEpoch::default(),
            &config.services,
            Duration::from_secs(10), // should already be there
        )
        .await?;
        (oprf_key_id, oprf_public_key)
    } else {
        let oprf_key_id = oprf_key_registry_scripts::init_key_gen(
            config.chain_rpc_url.expose_secret(),
            config.oprf_key_registry_contract,
            config.taceo_private_key.expose_secret(),
        );
        tracing::info!("registered OPRF key with: {oprf_key_id}");
        let oprf_public_key = taceo_oprf_test::health_checks::oprf_public_key_from_services(
            oprf_key_id,
            ShareEpoch::default(),
            &config.services,
            config.max_wait_time_key_gen,
        )
        .await?;
        (oprf_key_id, oprf_public_key)
    };

    let world_config = Config::new(
        Some(config.chain_rpc_url.expose_secret().to_string()),
        31_337, // anvil hardhat chain id
        config.world_id_registry_contract,
        config.indexer_url,
        config.gateway_url,
        config.services.clone(),
        config.threshold,
    )
    .unwrap();

    tracing::info!("creating account..");
    let seed = [7u8; 32];
    let authenticator = Authenticator::init_or_create_blocking(&seed, world_config, None)
        .await
        .context("failed to initialize or create authenticator")?;
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
            run_nullifier(&authenticator, oprf_key_id, oprf_public_key).await?;
            tracing::info!("nullifier successful");
        }
        Command::StressTest(cmd) => {
            tracing::info!("running stress-test");
            stress_test(
                &authenticator,
                authenticator_private_key,
                oprf_key_id,
                oprf_public_key,
                cmd,
                connector,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
    }

    Ok(())
}
