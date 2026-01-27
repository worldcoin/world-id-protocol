use std::{
    collections::HashMap,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U160},
    providers::{DynProvider, Provider as _, ProviderBuilder},
    signers::{
        SignerSync as _,
        k256::ecdsa::SigningKey,
        local::{LocalSigner, PrivateKeySigner},
    },
};
use ark_ff::UniformRand as _;
use clap::Parser;
use eyre::Context as _;
use rand::SeedableRng;
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret, SecretString};
use taceo_oprf_client::Connector;
use taceo_oprf_core::oprf::{BlindedOprfRequest, BlindedOprfResponse, BlindingFactor};
use taceo_oprf_dev_client::{Command, StressTestCommand};
use taceo_oprf_test_utils::health_checks;
use taceo_oprf_types::{
    OprfKeyId, ShareEpoch,
    api::v1::{OprfRequest, ShareIdentifier},
    crypto::OprfPublicKey,
};
use test_utils::{
    anvil::RpRegistry,
    fixtures::{MerkleFixture, build_base_credential},
};
use uuid::Uuid;
use world_id_core::{
    Authenticator, AuthenticatorError, Credential, EdDSAPrivateKey, EdDSAPublicKey, FieldElement,
    HashableCredential,
    proof::CircomGroth16Material,
    requests::{ProofRequest, RequestItem, RequestVersion},
    types::AccountInclusionProof,
};
use world_id_gateway::{GatewayConfig, ProviderArgs, SignerArgs};
use world_id_primitives::{
    Config, TREE_DEPTH,
    authenticator::AuthenticatorPublicKeySet,
    circuit_inputs::{NullifierProofCircuitInput, QueryProofCircuitInput},
    merkle::MerkleInclusionProof,
    oprf::OprfRequestAuthV1,
    proof::SingleProofInput,
    rp::RpId,
};

const ISSUER_SCHEMA_ID: u64 = 1;

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
    #[clap(long, env = "OPRF_DEV_CLIENT_INDEXER_URL")]
    pub indexer_url: Option<String>,

    /// Gateway address
    #[clap(long, env = "OPRF_DEV_CLIENT_GATEWAY_URL")]
    pub gateway_url: Option<String>,

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_RP_ID")]
    pub rp_id: Option<u64>,

    /// The share epoch. Will be ignored if `rp_id` is `None`.
    #[clap(long, env = "OPRF_DEV_CLIENT_SHARE_EPOCH", default_value = "0")]
    pub share_epoch: u128,

    /// max wait time for init key-gen/reshare to succeed.
    #[clap(long, env = "OPRF_DEV_CLIENT_MAX_WAIT_TIME", default_value="2min", value_parser=humantime::parse_duration)]
    pub max_wait_time: Duration,

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
    rp_id: RpId,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    signer: &LocalSigner<SigningKey>,
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
    let expiration_timestamp = current_timestamp + 300; // 5 minutes from now

    let msg = world_id_primitives::rp::compute_rp_signature_msg(
        nonce,
        action,
        current_timestamp,
        expiration_timestamp,
    );
    let signature = signer.sign_message_sync(&msg)?;

    let proof_request = ProofRequest {
        id: "test_request".to_string(),
        version: RequestVersion::V1,
        created_at: current_timestamp,
        expires_at: expiration_timestamp,
        rp_id,
        oprf_key_id,
        share_epoch,
        action: FieldElement::from(action),
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
    rp_id: RpId,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    key_set: AuthenticatorPublicKeySet,
    key_index: u64,
    query_material: &CircomGroth16Material,
    signer: &LocalSigner<SigningKey>,
) -> eyre::Result<(
    Uuid,
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

    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let nonce = ark_babyjubjub::Fq::rand(&mut rng);
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let expiration_timestamp = current_timestamp + 300; // 5 minutes from now

    let msg = world_id_primitives::rp::compute_rp_signature_msg(
        nonce,
        action,
        current_timestamp,
        expiration_timestamp,
    );
    let signature = signer.sign_message_sync(&msg)?;

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
        session_id: FieldElement::ZERO,
        rp_id,
        oprf_key_id,
        share_epoch: share_epoch.into_inner(),
        action: action.into(),
        nonce: nonce.into(),
        current_timestamp,
        expiration_timestamp,
        rp_signature: signature,
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

    Ok((request_id, args, query_input, blinding_factor, req))
}

#[expect(clippy::too_many_arguments)]
async fn stress_test(
    authenticator: &Authenticator,
    authenticator_private_key: EdDSAPrivateKey,
    rp_id: RpId,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    oprf_public_key: OprfPublicKey,
    cmd: StressTestCommand,
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

    let mut oprf_args = HashMap::with_capacity(cmd.runs);
    let mut query_inputs = HashMap::with_capacity(cmd.runs);
    let mut blinded_requests = HashMap::with_capacity(cmd.runs);
    let mut blinding_factors = HashMap::with_capacity(cmd.runs);
    let mut init_requests = HashMap::with_capacity(cmd.runs);

    tracing::info!("preparing requests..");
    for _ in 0..cmd.runs {
        let (request_id, args, query_input, blinding_factor, req) =
            prepare_nullifier_stress_test_oprf_request(
                authenticator,
                &authenticator_private_key,
                rp_id,
                oprf_key_id,
                share_epoch,
                inclusion_proof.clone(),
                key_set.clone(),
                key_index,
                &query_material,
                signer,
            )?;
        oprf_args.insert(request_id, args);
        query_inputs.insert(request_id, query_input);
        blinded_requests.insert(request_id, req.blinded_query);
        blinding_factors.insert(request_id, blinding_factor);
        init_requests.insert(request_id, req);
    }

    tracing::info!("sending init requests..");
    let (sessions, finish_requests) = taceo_oprf_dev_client::send_init_requests(
        &nodes,
        "rp",
        threshold,
        connector,
        cmd.sequential,
        init_requests,
    )
    .await?;

    tracing::info!("sending finish requests..");
    let responses = taceo_oprf_dev_client::send_finish_requests(
        sessions,
        cmd.sequential,
        finish_requests.clone(),
    )
    .await?;

    if !cmd.skip_checks {
        tracing::info!("checking nullifier + proofs");
        for (id, res) in responses {
            let args = oprf_args.get(&id).expect("is there");
            let query_input = query_inputs.get(&id).expect("is there").clone();
            let blinded_req = blinded_requests.get(&id).expect("is there");
            let blinding_factor = blinding_factors.get(&id).expect("is there").clone();
            let finish_request = finish_requests.get(&id).expect("is there").clone();
            let dlog_proof = taceo_oprf_client::verify_dlog_equality(
                id,
                oprf_public_key,
                &BlindedOprfRequest::new(*blinded_req),
                res,
                finish_request.clone(),
            )?;
            let blinded_response = finish_request.blinded_response();
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
                id_commitment: *args.session_id,
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
            let (proof, public) = nullifier_material.generate_proof(&nullifier_input, &mut rng)?;
            nullifier_material.verify_proof(&proof, &public)?;
        }
    }

    Ok(())
}

#[expect(clippy::too_many_arguments)]
async fn reshare_test(
    authenticator: &Authenticator,
    rp_id: RpId,
    oprf_key_id: OprfKeyId,
    share_epoch: ShareEpoch,
    oprf_public_key: OprfPublicKey,
    signer: &LocalSigner<SigningKey>,
    provider: DynProvider,
    oprf_key_registry: Address,
    max_wait_time: Duration,
) -> eyre::Result<()> {
    let nodes = authenticator.config.nullifier_oracle_urls().to_vec();

    tracing::info!("running single nullifier");
    run_nullifier(authenticator, rp_id, oprf_key_id, share_epoch, signer).await?;
    tracing::info!("nullifier successful");

    let (share_epoch_1, oprf_public_key_1) = taceo_oprf_dev_client::reshare(
        &nodes,
        oprf_key_registry,
        provider.clone(),
        max_wait_time,
        oprf_key_id,
        share_epoch,
    )
    .await?;
    assert_eq!(oprf_public_key, oprf_public_key_1);

    tracing::info!("running nullifier with epoch 0 after 1st reshare");
    run_nullifier(authenticator, rp_id, oprf_key_id, share_epoch, signer).await?;
    tracing::info!("nullifier successful");

    tracing::info!("running nullifier with epoch 1 after 1st reshare");
    run_nullifier(authenticator, rp_id, oprf_key_id, share_epoch_1, signer).await?;
    tracing::info!("nullifier successful");

    let (share_epoch_2, oprf_public_key_2) = taceo_oprf_dev_client::reshare(
        &nodes,
        oprf_key_registry,
        provider,
        max_wait_time,
        oprf_key_id,
        share_epoch_1,
    )
    .await?;
    assert_eq!(oprf_public_key, oprf_public_key_2);

    tracing::info!("running nullifier with epoch 1 after 2nd reshare");
    run_nullifier(authenticator, rp_id, oprf_key_id, share_epoch_1, signer).await?;
    tracing::info!("nullifier successful");

    tracing::info!("running nullifier with epoch 2 after 2nd reshare");
    run_nullifier(authenticator, rp_id, oprf_key_id, share_epoch_2, signer).await?;
    tracing::info!("nullifier successful");

    tracing::info!("running nullifier with epoch 0 after 2nd reshare - should fail");
    let _ = run_nullifier(authenticator, rp_id, oprf_key_id, share_epoch, signer)
        .await
        .expect_err("should fail");
    tracing::info!("nullifier failed as expected");

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

    let (rp_id, oprf_key_id, share_epoch, oprf_public_key) = if let Some(rp_id) = config.rp_id {
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
        (RpId::new(rp_id), oprf_key_id, share_epoch, oprf_public_key)
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
        (rp_id, oprf_key_id, ShareEpoch::default(), oprf_public_key)
    };

    let (gateway_url, _gateway_handle) = if let Some(gateway_url) = &config.gateway_url {
        (gateway_url.clone(), None)
    } else {
        // anvil wallet 0, only used for local tests
        let signer_args = SignerArgs::from_wallet(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string(),
        );
        let gateway_config = GatewayConfig {
            registry_addr: config.world_id_registry_contract,
            provider: ProviderArgs {
                http: Some(vec![
                    config.chain_rpc_url.expose_secret().to_string().parse()?,
                ]),
                signer: Some(signer_args.clone()),
                ..Default::default()
            },
            batch_ms: 200,
            listen_addr: (std::net::Ipv4Addr::LOCALHOST, 8081).into(),
            max_create_batch_size: 10,
            max_ops_batch_size: 10,
            redis_url: None,
        };
        let gateway_handle = world_id_gateway::spawn_gateway_for_tests(gateway_config)
            .await
            .map_err(|e| eyre::eyre!("failed to spawn gateway for tests: {e}"))?;
        ("http://localhost:8081".to_string(), Some(gateway_handle))
    };

    let world_config = Config::new(
        Some(config.chain_rpc_url.expose_secret().to_string()),
        31_337, // anvil hardhat chain id
        config.world_id_registry_contract,
        "http://localhost:8080".to_string(), // stub indexer url - will be replaced later
        gateway_url.clone(),
        config.nodes.clone(),
        config.threshold,
    )
    .unwrap();

    tracing::info!("creating account..");
    let seed = [7u8; 32];
    let authenticator = Authenticator::init_or_register(&seed, world_config.clone(), None).await?;
    let authenticator_private_key = EdDSAPrivateKey::from_bytes(seed);

    let (indexer_url, _indexer_handle) = if let Some(indexer_url) = &config.indexer_url {
        (indexer_url.clone(), None)
    } else {
        // Local indexer stub serving inclusion proof.
        let leaf_index_u64: u64 = authenticator
            .leaf_index()
            .try_into()
            .expect("account id fits in u64");
        let MerkleFixture {
            key_set,
            inclusion_proof: merkle_inclusion_proof,
            root: _,
            ..
        } = test_utils::fixtures::single_leaf_merkle_fixture(
            vec![authenticator.offchain_pubkey()],
            leaf_index_u64,
        )
        .wrap_err("failed to construct merkle fixture")?;

        let inclusion_proof =
            AccountInclusionProof::<{ TREE_DEPTH }>::new(merkle_inclusion_proof, key_set.clone())
                .wrap_err("failed to build inclusion proof")?;

        let (indexer_url, indexer_handle) =
            test_utils::stubs::spawn_indexer_stub(leaf_index_u64, inclusion_proof.clone())
                .await
                .wrap_err("failed to start indexer stub")?;
        (indexer_url, Some(indexer_handle))
    };

    let world_config = Config::new(
        Some(config.chain_rpc_url.expose_secret().to_string()),
        31_337, // anvil hardhat chain id
        config.world_id_registry_contract,
        indexer_url,
        gateway_url,
        config.nodes.clone(),
        config.threshold,
    )
    .unwrap();

    let authenticator = Authenticator::init(&seed, world_config.clone()).await?;

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
                oprf_key_id,
                share_epoch,
                &private_key,
            )
            .await?;
            tracing::info!("nullifier successful");
        }
        Command::StressTest(cmd) => {
            tracing::info!("running stress-test");
            stress_test(
                &authenticator,
                authenticator_private_key,
                rp_id,
                oprf_key_id,
                share_epoch,
                oprf_public_key,
                cmd,
                connector,
                &private_key,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
        Command::ReshareTest => {
            tracing::info!("running reshare test");
            reshare_test(
                &authenticator,
                rp_id,
                oprf_key_id,
                share_epoch,
                oprf_public_key,
                &private_key,
                provider,
                config.oprf_key_registry_contract,
                config.max_wait_time,
            )
            .await?;
            tracing::info!("reshare test successful");
        }
    }

    Ok(())
}
