//! The WIP-202 end-to-end setup: an account with a Proof of Human Credential and an RP's Proof of
//! Embedding Similarity request, on local registries, gateway, indexer stub and OPRF nodes, and
//! optionally a WIP-107 Billing Contract that bills the RP.

use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Address, U160, U256},
    providers::Provider as _,
    signers::{SignerSync as _, local::LocalSigner},
};
use eyre::{Result, bail, eyre};
use sha2::{Digest as _, Sha256};
use taceo_oprf::{
    dev_client::health_checks,
    types::{OprfKeyId, ShareEpoch},
};
use testcontainers_modules::{redis::Redis, testcontainers::ContainerAsync};
use world_id_core::{
    Authenticator, AuthenticatorError, CredentialInput, EdDSAPrivateKey, EdDSAPublicKey,
    FlamingoResult,
    artifacts::ZkArtifactSource,
    embedding_similarity::{
        AatPolicy, EmbeddingSimilarityPolicy, EmbeddingSimilarityVerificationError,
        FlamingoAttestationVerifier, verify_embedding_similarity,
    },
    requests::{ProofRequest, ProofType, RequestItem, RequestVersion},
};
use world_id_gateway::{
    BatchPolicyConfig, GatewayConfig, GatewayHandle, RegistryVersion, SignerArgs, defaults,
    spawn_gateway_for_tests,
};
use world_id_oprf_node::config::BillingContractConfig;
use world_id_primitives::{
    Config, EmbeddingSimilarityParams, FieldElement, OprfPrefix, OprfPrefixedFieldElement as _,
    ProofResponse, ServiceEndpoint, SessionRef, TREE_DEPTH,
    api_types::GatewayRequestState,
    billing::{BillingContext, BillingWitness, active_periods, registration_period_start},
    merkle::AccountInclusionProof,
};

use crate::{
    anvil::{TestAnvil, world_id_billing::IWorldIDBilling},
    fixtures::{
        MerkleFixture, RegistryTestContext, build_base_credential, generate_rp_fixture,
        single_leaf_merkle_fixture,
    },
    redis_testcontainer,
    stubs::{SpawnedKeyGens, spawn_indexer_stub, spawn_oprf_nodes_with_billing},
};

const ISSUER_SCHEMA_ID: u64 = 1;

/// An Authenticator holding a Credential over a PCP whose thumbnail is `credential_image`, and an
/// RP-signed request for a Proof of Embedding Similarity against `challenge`.
///
/// Keeps anvil, the containers and the spawned services alive until dropped.
pub struct EmbeddingSimilarityFixture {
    pub authenticator: Authenticator,
    pub proof_request: ProofRequest,
    pub credential: CredentialInput,
    /// The PCP's `hashes.json` that the Credential's claim 0 commits to.
    pub hashes_json: Vec<u8>,
    /// The PCP thumbnail that `hashes_json` lists.
    pub credential_image: Vec<u8>,
    /// The challenge image whose [`image_hash`] the request carries.
    pub challenge: Vec<u8>,
    /// The only valid root of the account tree.
    pub merkle_root: FieldElement,
    /// The Credential issuer's key.
    pub issuer_key: EdDSAPublicKey,
    pub artifacts: Arc<dyn ZkArtifactSource>,
    /// The Billing Contract that bills the RP, if the fixture was spawned billed.
    pub billing: Option<FixtureBilling>,
    _services: Services,
}

/// A Billing Contract that bills the fixture's RP, with capacity for one registration in
/// `scope`.
pub struct FixtureBilling {
    /// The chain's JSON-RPC endpoint.
    pub rpc_url: String,
    pub chain_id: u64,
    /// The `WorldIDBilling` proxy.
    pub contract: Address,
    /// The block the proxy was deployed in.
    pub deploy_block: u64,
    /// The context the account registers in, active now.
    pub scope: BillingContext,
}

struct Services {
    _anvil: TestAnvil,
    _redis: ContainerAsync<Redis>,
    _gateway: GatewayHandle,
    _indexer: tokio::task::JoinHandle<()>,
    _key_gens: SpawnedKeyGens,
}

impl EmbeddingSimilarityFixture {
    /// Spawns the services, creates the account and issues its Credential.
    ///
    /// Needs Docker, and anvil and forge on `PATH`. `artifacts` must serve the embedding
    /// similarity prover, and its verifier for [`Self::verify`].
    pub async fn spawn(artifacts: Arc<dyn ZkArtifactSource>) -> Result<Self> {
        Self::spawn_with(artifacts, false).await
    }

    /// [`Self::spawn`], with a Billing Contract that bills the RP and has capacity for the
    /// account's registration ([`Self::register_billing`]).
    pub async fn spawn_billed(artifacts: Arc<dyn ZkArtifactSource>) -> Result<Self> {
        Self::spawn_with(artifacts, true).await
    }

    async fn spawn_with(artifacts: Arc<dyn ZkArtifactSource>, billed: bool) -> Result<Self> {
        // Another provider may already be installed, which works as well.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Registries on Anvil, and the Billing Contract if billed.
        let RegistryTestContext {
            anvil,
            world_id_registry,
            rp_registry,
            oprf_key_registry,
            world_id_verifier,
            credential_registry,
        } = RegistryTestContext::new().await?;
        let deployer = anvil.signer(0)?;
        let chain_id = anvil.instance.chain_id();
        let deployment = if billed {
            let deployment = anvil
                .deploy_world_id_billing(deployer.clone(), world_id_verifier, rp_registry)
                .await?;
            // Anvil mines each transaction in its own block, the proxy's last.
            let deploy_block = anvil.provider()?.get_block_number().await?;
            Some((deployment, deploy_block))
        } else {
            None
        };

        // Gateway for account creation.
        let (redis, redis_url) = redis_testcontainer().await?;
        let gateway = spawn_gateway_for_tests(GatewayConfig {
            registry_addr: world_id_registry,
            registry_version: RegistryVersion::V2,
            billing_addr: deployment.map(|(deployment, _)| deployment.billing),
            provider: world_id_gateway::ProviderArgs {
                http: vec![anvil.endpoint().parse()?],
                signer: SignerArgs::from_wallet(hex::encode(deployer.to_bytes())),
                ..Default::default()
            },
            listen_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            max_create_batch_size: 10,
            max_ops_batch_size: 10,
            redis_url,
            request_timeout_secs: 10,
            rate_limit_max_requests: None,
            rate_limit_window_secs: None,
            sweeper_interval_secs: defaults::SWEEPER_INTERVAL_SECS,
            stale_queued_threshold_secs: defaults::STALE_QUEUED_THRESHOLD_SECS,
            stale_submitted_threshold_secs: defaults::STALE_SUBMITTED_THRESHOLD_SECS,
            batch_policy: BatchPolicyConfig::default(),
        })
        .await
        .map_err(|e| eyre!("failed to spawn gateway for tests: {e}"))?;
        let gateway_url = format!("http://{}", gateway.listen_addr);

        // Account, created through the gateway.
        let seed = [13u8; 32];
        let creation_config = Config::new(
            Some(anvil.endpoint().to_string()),
            chain_id,
            world_id_registry,
            ServiceEndpoint::direct("http://127.0.0.1:0".to_string()),
            ServiceEndpoint::direct(gateway_url.clone()),
            Vec::new(),
            3,
        )?;
        let authenticator = Authenticator::init_or_register(
            &seed,
            creation_config,
            Some(anvil.signer(1)?.address()),
            artifacts.clone(),
        )
        .await?;
        let leaf_index = authenticator.leaf_index();

        // Indexer stub serving the account's inclusion proof.
        let MerkleFixture {
            key_set,
            inclusion_proof,
            root: merkle_root,
            ..
        } = single_leaf_merkle_fixture(vec![authenticator.offchain_pubkey()], leaf_index)?;
        let (indexer_url, indexer) = spawn_indexer_stub(
            leaf_index,
            AccountInclusionProof::<{ TREE_DEPTH }>::new(inclusion_proof, key_set),
        )
        .await?;

        // OPRF nodes for credential blinding, and billing queries if billed.
        let connection_string = crate::shared_postgres_testcontainer().await?;
        let secret_managers =
            crate::stubs::init_test_secret_managers(connection_string.to_string().into()).await?;
        let key_gens =
            crate::stubs::spawn_key_gens(&anvil, connection_string, oprf_key_registry).await?;
        let nodes = spawn_oprf_nodes_with_billing(
            &anvil,
            secret_managers,
            world_id_registry,
            rp_registry,
            credential_registry,
            deployment
                .map(|(deployment, _)| BillingContractConfig::new(chain_id, deployment.billing)),
        )
        .await;
        health_checks::services_health_check(&nodes, Duration::from_secs(60)).await?;
        health_checks::services_health_check(&key_gens.urls, Duration::from_secs(60)).await?;

        // Issuer and RP, each with an OPRF key.
        let issuer_sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
        anvil
            .register_issuer(
                credential_registry,
                deployer.clone(),
                ISSUER_SCHEMA_ID,
                issuer_sk.public(),
            )
            .await?;
        let rp_fixture = generate_rp_fixture();
        let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
        anvil
            .register_rp(
                rp_registry,
                deployer.clone(),
                rp_fixture.world_rp_id,
                rp_signer.address(),
                rp_signer.address(),
                "poes.rp".to_string(),
            )
            .await?;
        for key_id in [
            rp_fixture.oprf_key_id,
            OprfKeyId::new(U160::from(ISSUER_SCHEMA_ID)),
        ] {
            health_checks::oprf_public_key_from_services(
                key_id,
                ShareEpoch::default(),
                &nodes,
                Duration::from_secs(120),
            )
            .await?;
        }

        // The RP is billed, with capacity for one registration in the current period.
        let billing = match deployment {
            Some((deployment, deploy_block)) => {
                let scope = BillingContext {
                    chain_id: U256::from(chain_id),
                    billing_contract: deployment.billing,
                    rp_id: rp_fixture.world_rp_id,
                    period_start: registration_period_start(active_periods(now_secs())?, false),
                };
                anvil
                    .purchase_billing_capacity(
                        deployer,
                        deployment,
                        IWorldIDBilling::BillingContext {
                            chainId: scope.chain_id,
                            billingContract: scope.billing_contract,
                            rpId: scope.rp_id.into_inner(),
                            periodStart: scope.period_start,
                        },
                        1,
                    )
                    .await?;
                Some(FixtureBilling {
                    rpc_url: anvil.endpoint().to_string(),
                    chain_id,
                    contract: deployment.billing,
                    deploy_block,
                    scope,
                })
            }
            None => None,
        };

        // Authenticator pointed at the indexer, gateway and OPRF nodes.
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        std::env::set_current_dir(&workspace_root)?;
        let authenticator = Authenticator::init(
            &seed,
            Config::new(
                Some(anvil.endpoint().to_string()),
                chain_id,
                world_id_registry,
                ServiceEndpoint::direct(indexer_url),
                ServiceEndpoint::direct(gateway_url),
                nodes.to_vec(),
                3,
            )?,
            artifacts.clone(),
        )
        .await?;

        // PoH Credential whose claim 0 commits to the PCP's `hashes.json`.
        let now = now_secs();
        let blinding_factor = authenticator
            .generate_credential_blinding_factor(ISSUER_SCHEMA_ID)
            .await?;
        let credential_image = b"orb thumbnail".to_vec();
        let hashes_json = hashes_json(&credential_image);
        let mut credential = build_base_credential(
            ISSUER_SCHEMA_ID,
            leaf_index,
            now,
            now + 3_600,
            blinding_factor,
        )
        .claim(0, &hashes_json)?;
        credential.issuer = issuer_sk.public();
        credential.signature = Some(issuer_sk.sign(*credential.hash()?));
        let credential = CredentialInput {
            credential,
            blinding_factor,
        };

        // RP-signed Proof of Embedding Similarity request.
        let challenge = b"meeting frame".to_vec();
        let action = FieldElement::random_with_prefix(
            &mut rand::thread_rng(),
            OprfPrefix::EmbeddingSimilarity,
        );
        let nonce = FieldElement::random(&mut rand::thread_rng());
        let created_at = now_secs();
        let expires_at = created_at + 300;
        let signature =
            rp_signer.sign_message_sync(&world_id_primitives::rp::compute_rp_signature_msg(
                *nonce,
                created_at,
                expires_at,
                Some(*action),
            ))?;
        let proof_request = ProofRequest {
            id: "embedding_similarity_request".to_string(),
            version: RequestVersion::V1,
            proof_type: ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
                action,
                challenge_hash: image_hash(&challenge),
                aat: None,
            }),
            created_at,
            expires_at,
            rp_id: rp_fixture.world_rp_id,
            oprf_key_id: rp_fixture.oprf_key_id,
            session_id: SessionRef::None,
            signature,
            nonce,
            requests: vec![RequestItem {
                identifier: "test_credential".to_string(),
                issuer_schema_id: ISSUER_SCHEMA_ID,
                signal: Some(b"meeting-42".to_vec()),
                genesis_issued_at_min: None,
                expires_at_min: None,
            }],
            constraints: None,
        };

        Ok(Self {
            authenticator,
            proof_request,
            credential,
            hashes_json,
            credential_image,
            challenge,
            merkle_root,
            issuer_key: issuer_sk.public(),
            artifacts,
            billing,
            _services: Services {
                _anvil: anvil,
                _redis: redis,
                _gateway: gateway,
                _indexer: indexer,
                _key_gens: key_gens,
            },
        })
    }

    /// Registers the account in the fixture's billing context through the gateway, as WIP-107
    /// §4.6 has the Authenticator do before its first proof, and waits until it is mined.
    ///
    /// Returns the witness [`Self::prove`] needs for a token carrying its `billing_nullifier`.
    pub async fn register_billing(&self) -> Result<BillingWitness> {
        let billing = self
            .billing
            .as_ref()
            .ok_or_else(|| eyre!("the fixture was spawned without billing"))?;
        let query = self
            .authenticator
            .generate_billing_nullifier(&self.proof_request, &billing.scope, now_secs(), None)
            .await?;
        let witness = query.billing_witness();
        let registration = self.authenticator.generate_billing_registration(
            &self.proof_request,
            &billing.scope,
            query,
            &self.credential,
        )?;
        let request_id = self
            .authenticator
            .submit_billing_registration(&registration)
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            match self.authenticator.poll_status(&request_id).await? {
                GatewayRequestState::Finalized { .. } => return Ok(witness),
                GatewayRequestState::Failed { error, error_code } => {
                    bail!("billing registration failed ({error_code:?}): {error}")
                }
                _ if tokio::time::Instant::now() > deadline => {
                    bail!("billing registration was not mined within 60 s")
                }
                _ => tokio::time::sleep(Duration::from_millis(250)).await,
            }
        }
    }

    /// Proves the fixture's request from a `flamingo` result, with the `billing` witness of its
    /// token's nonzero `billing_nullifier`.
    pub async fn prove(
        &self,
        flamingo: &FlamingoResult,
        billing: Option<&BillingWitness>,
    ) -> Result<ProofResponse, AuthenticatorError> {
        let result = self
            .authenticator
            .generate_embedding_similarity_proof(
                &self.proof_request,
                flamingo,
                &self.credential,
                &self.hashes_json,
                billing,
                None,
                None,
            )
            .await?;
        Ok(result.proof_response)
    }

    /// The RP's policy for the fixture's Credential, accepting `engine_config_hashes` and
    /// Flamingo Verifiers that `attestation` accepts, with no AAT.
    pub fn policy<A>(
        &self,
        attestation: A,
        engine_config_hashes: HashSet<FieldElement>,
    ) -> EmbeddingSimilarityPolicy<A> {
        EmbeddingSimilarityPolicy {
            attestation,
            engine_config_hashes,
            aat: AatPolicy::default(),
        }
    }

    /// Verifies `response` to `request` as the RP, trusting the fixture's root and issuer key.
    pub async fn verify<A: FlamingoAttestationVerifier + Sync>(
        &self,
        request: &ProofRequest,
        response: &ProofResponse,
        policy: &EmbeddingSimilarityPolicy<A>,
    ) -> Result<(), EmbeddingSimilarityVerificationError> {
        let merkle_root = self.merkle_root;
        let issuer_key = self.issuer_key.pk;
        verify_embedding_similarity(
            request,
            response,
            policy,
            |root| async move { Ok::<_, std::io::Error>(root == merkle_root) },
            |key: EdDSAPublicKey| async move { Ok::<_, std::io::Error>(key.pk == issuer_key) },
            self.artifacts.as_ref(),
        )
        .await
    }
}

/// `R(SHA-256(bytes))`, how WIP-201 lowers an image digest into the field.
pub fn image_hash(bytes: &[u8]) -> FieldElement {
    FieldElement::from_digest(&Sha256::digest(bytes).into())
}

/// A compact, key-sorted PCP `hashes.json` (WIP-202 §4.1) whose `thumbnail.png` is `thumbnail`,
/// padded with other files to the circuit's minimum length.
fn hashes_json(thumbnail: &[u8]) -> Vec<u8> {
    let mut entries: BTreeMap<String, String> = (0..48)
        .map(|i| {
            let name = format!("file_{i:02}.bin");
            let digest = hex::encode(Sha256::digest(name.as_bytes()));
            (name, digest)
        })
        .collect();
    entries.insert(
        "thumbnail.png".into(),
        hex::encode(Sha256::digest(thumbnail)),
    );
    entries.insert("version".into(), "3.0".into());
    let body = entries
        .iter()
        .map(|(key, value)| format!("\"{key}\":\"{value}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}").into_bytes()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}
