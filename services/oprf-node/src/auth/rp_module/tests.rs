#![allow(clippy::large_futures, reason = "Is ok in tests")]
#![allow(clippy::cast_sign_loss, reason = "Is ok in tests")]

use std::{sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, B256, Signature},
    providers::mock::Asserter,
    signers::{SignerSync as _, local::LocalSigner},
};
use ark_bn254::Bn254;
use ark_ff::PrimeField as _;
use circom_types::groth16::VerificationKey;
use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator as _};
use uuid::Uuid;
use world_id_primitives::{
    FieldElement, OprfPrefix, OprfPrefixedFieldElement as _, ProofType, RequestVersion,
    oprf::{NullifierOprfRequestAuthV1, error_codes},
    request::{
        RpAuthorizationProof, RpRequestAuthorization, RpRequestSessionMode,
        session_seed_authorization,
    },
    rp::RpId,
};

use crate::{
    QUERY_VERIFICATION_KEY,
    auth::{
        merkle_watcher::MerkleWatcher,
        nonce_history::NonceHistory,
        rp_module::{
            RpAccountType, RpModuleAuth, RpModuleAuthArgs, RpModuleError, wip101,
            wip101::Wip101Error,
        },
        rp_registry_watcher::RpRegistryWatcher,
        tests::{AuthModulesTestSetup, OprfRequestAuthTestSetup, SetupKind},
    },
    config::WatcherCacheConfig,
};

pub(crate) struct RpModuleTestSetup {
    pub(crate) setup: OprfRequestAuthTestSetup,
    pub(crate) request_authenticator: RpModuleAuth,
    pub(crate) request: OprfRequest<NullifierOprfRequestAuthV1>,
    /// Chain the authenticator under test is bound to for EIP-712 signing.
    pub(crate) chain_id: u64,
}

impl RpModuleTestSetup {
    pub(crate) async fn new_session() -> eyre::Result<Self> {
        Self::new_unbound_session_with_fe_type(OprfPrefix::SessionOprfSeed).await
    }

    /// Constructs a valid session test setup with the given session type.
    pub(crate) async fn new_unbound_session_with_fe_type(
        session_type: OprfPrefix,
    ) -> eyre::Result<Self> {
        let mut rng = rand::thread_rng();
        let infra = AuthModulesTestSetup::new(SetupKind::RpModule).await?;

        let request_authenticator = RpModuleAuth::new_session(infra.rp_module_args());

        // Session action must have the correct prefix byte (0x01 or 0x02)
        let session_action = FieldElement::random_with_prefix(&mut rng, session_type);
        let bundle = infra
            .generate_query_proof(session_action, infra.setup.rp_fixture.world_rp_id.into())?;

        let (authorization, signature) = signed_authorization(
            &infra.setup,
            infra.chain_id,
            bundle.nonce,
            *session_action,
            AuthorizedOperation {
                proof_type: ProofType::Session,
                session_mode: RpRequestSessionMode::Create,
                action: None,
                session_seed_opening: None,
            },
        );

        let auth = NullifierOprfRequestAuthV1 {
            proof: bundle.proof,
            oprf_action: *session_action,
            merkle_root: *infra.setup.merkle_inclusion_proof.root,
            authorization,
            authorization_proof: RpAuthorizationProof::Eoa { signature },
            session_seed_opening: None,
        };

        Ok(Self {
            setup: infra.setup,
            request_authenticator,
            chain_id: infra.chain_id,
            request: OprfRequest {
                request_id: Uuid::new_v4(),
                blinded_query: bundle.blinded_query,
                auth,
            },
        })
    }

    /// Constructs a valid create-and-bind session-seed test setup.
    pub(crate) async fn new_bound_session_seed() -> eyre::Result<Self> {
        let mut rng = rand::thread_rng();
        let infra = AuthModulesTestSetup::new(SetupKind::RpModule).await?;

        let request_authenticator = RpModuleAuth::new_session(infra.rp_module_args());

        let session_action =
            FieldElement::random_with_prefix(&mut rng, OprfPrefix::SessionOprfSeed);
        let bundle = infra
            .generate_query_proof(session_action, infra.setup.rp_fixture.world_rp_id.into())?;

        let (authorization, signature) = signed_authorization(
            &infra.setup,
            infra.chain_id,
            bundle.nonce,
            *session_action,
            AuthorizedOperation {
                proof_type: ProofType::Uniqueness,
                session_mode: RpRequestSessionMode::Create,
                action: Some(infra.setup.rp_fixture.action.into()),
                session_seed_opening: None,
            },
        );

        let auth = NullifierOprfRequestAuthV1 {
            proof: bundle.proof,
            oprf_action: *session_action,
            merkle_root: *infra.setup.merkle_inclusion_proof.root,
            authorization,
            authorization_proof: RpAuthorizationProof::Eoa { signature },
            session_seed_opening: None,
        };

        Ok(Self {
            setup: infra.setup,
            request_authenticator,
            chain_id: infra.chain_id,
            request: OprfRequest {
                request_id: Uuid::new_v4(),
                blinded_query: bundle.blinded_query,
                auth,
            },
        })
    }

    async fn new_uniqueness() -> eyre::Result<Self> {
        let infra = AuthModulesTestSetup::new(SetupKind::RpModule).await?;
        let request_authenticator = RpModuleAuth::new_uniqueness(infra.rp_module_args());

        // Uniqueness uses the fixture's pre-generated action (guaranteed 0x00 MSB),
        // which is also the exact action the authorization commits to.
        let bundle = infra.generate_query_proof(
            infra.setup.rp_fixture.action.into(),
            infra.setup.rp_fixture.world_rp_id.into(),
        )?;

        let (authorization, signature) = signed_authorization(
            &infra.setup,
            infra.chain_id,
            bundle.nonce,
            infra.setup.rp_fixture.action,
            AuthorizedOperation {
                proof_type: ProofType::Uniqueness,
                session_mode: RpRequestSessionMode::None,
                action: Some(infra.setup.rp_fixture.action.into()),
                session_seed_opening: None,
            },
        );

        let auth = NullifierOprfRequestAuthV1 {
            proof: bundle.proof,
            oprf_action: infra.setup.rp_fixture.action,
            merkle_root: *infra.setup.merkle_inclusion_proof.root,
            authorization,
            authorization_proof: RpAuthorizationProof::Eoa { signature },
            session_seed_opening: None,
        };

        Ok(Self {
            setup: infra.setup,
            request_authenticator,
            chain_id: infra.chain_id,
            request: OprfRequest {
                request_id: Uuid::new_v4(),
                blinded_query: bundle.blinded_query,
                auth,
            },
        })
    }

    /// Authenticates the request and asserts it succeeds with the fixture's OPRF key id.
    async fn assert_auth_ok(&self) -> eyre::Result<()> {
        let oprf_key_id = self
            .request_authenticator
            .authenticate(&self.request)
            .await
            .expect("should succeed");
        assert_eq!(self.setup.rp_fixture.oprf_key_id, oprf_key_id);
        Ok(())
    }

    /// Authenticates the request and asserts it fails with the given code and message.
    async fn assert_auth_err(&self, code: u16, msg: &str) -> eyre::Result<()> {
        let auth_error = self
            .request_authenticator
            .authenticate(&self.request)
            .await
            .expect_err("should fail");
        assert_eq!(auth_error.code(), code);
        assert_eq!(auth_error.message(), msg);
        Ok(())
    }

    /// Re-signs the request for a different authorized operation.
    fn authorize(
        &mut self,
        proof_type: ProofType,
        session_mode: RpRequestSessionMode,
        action: Option<FieldElement>,
        session_seed_opening: Option<B256>,
    ) {
        let (authorization, signature) = signed_authorization(
            &self.setup,
            self.chain_id,
            *self.request.auth.authorization.nonce,
            self.request.auth.oprf_action,
            AuthorizedOperation {
                proof_type,
                session_mode,
                action,
                session_seed_opening,
            },
        );

        self.request.auth.authorization = authorization;
        self.request.auth.authorization_proof = RpAuthorizationProof::Eoa { signature };
        self.request.auth.session_seed_opening = session_seed_opening;
    }
}

/// The operation an RP authorization permits.
#[derive(Clone, Copy)]
struct AuthorizedOperation {
    proof_type: ProofType,
    session_mode: RpRequestSessionMode,
    action: Option<FieldElement>,
    session_seed_opening: Option<B256>,
}

/// Builds the RP authorization for `oprf_action` and signs it with the fixture's RP key.
fn signed_authorization(
    setup: &OprfRequestAuthTestSetup,
    chain_id: u64,
    nonce: ark_babyjubjub::Fq,
    oprf_action: ark_babyjubjub::Fq,
    operation: AuthorizedOperation,
) -> (RpRequestAuthorization, Signature) {
    let existing_session_seed_authorization = operation
        .session_seed_opening
        .map_or(B256::ZERO, |opening| {
            session_seed_authorization(opening, oprf_action.into())
        });
    let authorization = RpRequestAuthorization {
        request_version: RequestVersion::V1,
        rp_id: setup.rp_fixture.world_rp_id,
        oprf_key_id: setup.rp_fixture.oprf_key_id,
        nonce: nonce.into(),
        created_at: setup.rp_fixture.current_timestamp,
        expires_at: setup.rp_fixture.expiration_timestamp,
        proof_type: operation.proof_type,
        session_mode: operation.session_mode,
        action: operation.action,
        existing_session_seed_authorization,
        details_hash: B256::repeat_byte(0x42),
    };
    let signer = LocalSigner::from_signing_key(setup.rp_fixture.signing_key.clone());
    let signature = signer
        .sign_hash_sync(&authorization.signing_hash(chain_id, setup.rp_registry))
        .expect("can sign authorization");
    (authorization, signature)
}

// ── Local test helpers ───────────────────────────────────────────────────

/// Random field element whose big-endian MSB is forced to `msb`
/// (used to build actions with a specific prefix byte).
fn action_with_msb(msb: u8) -> ark_babyjubjub::Fq {
    let mut bytes = rand::random::<[u8; 32]>();
    bytes[0] = msb;
    ark_babyjubjub::Fq::from_be_bytes_mod_order(&bytes)
}

// ── Shared test helpers ──────────────────────────────────────────────────

async fn check_success(setup: RpModuleTestSetup) -> eyre::Result<()> {
    setup.assert_auth_ok().await
}

// ── Session tests ────────────────────────────────────────────────────────
//
// Each check below is run once against a session authenticator. The checked
// code paths are variant-agnostic; the uniqueness happy path and the
// variant-specific action rules are covered by the standalone tests below.

#[tokio::test]
async fn test_session_success() -> eyre::Result<()> {
    check_success(RpModuleTestSetup::new_session().await?).await
}

#[tokio::test]
async fn test_session_expired_timestamp() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.authorization.created_at -= setup
        .request_authenticator
        .created_at_max_difference
        .num_seconds() as u64
        + 100;
    setup
        .assert_auth_err(error_codes::CREATED_AT_TOO_OLD, "created_at too old")
        .await
}

#[tokio::test]
async fn test_session_future_timestamp() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.authorization.created_at += setup
        .request_authenticator
        .created_at_max_difference
        .num_seconds() as u64
        + 100;
    setup
        .assert_auth_err(
            error_codes::CREATED_AT_TOO_FAR_IN_FUTURE,
            "created_at too far in future",
        )
        .await
}

#[tokio::test]
async fn test_session_expires_at_too_far() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.authorization.expires_at += setup
        .request_authenticator
        .expires_at_max_difference
        .num_seconds() as u64;
    setup
        .assert_auth_err(
            error_codes::EXPIRES_AT_TOO_FAR_IN_FUTURE,
            "expires_at too far in the future",
        )
        .await
}

#[tokio::test]
async fn test_session_timestamp_zero() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.authorization.created_at = 0;
    setup
        .assert_auth_err(error_codes::CREATED_AT_TOO_OLD, "created_at too old")
        .await
}

#[tokio::test]
async fn test_session_invalid_timestamp() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.authorization.created_at = u64::MAX;
    setup
        .assert_auth_err(
            error_codes::INVALID_TIMESTAMP,
            "cannot parse timestamp on request",
        )
        .await
}

#[tokio::test]
async fn test_session_invalid_query_proof() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.proof.pi_a = rand::random();
    setup
        .assert_auth_err(
            error_codes::INVALID_QUERY_PROOF,
            "cannot verify query proof",
        )
        .await
}

#[tokio::test]
async fn test_session_tampered_blinded_query() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.blinded_query = rand::random();
    setup
        .assert_auth_err(
            error_codes::INVALID_QUERY_PROOF,
            "cannot verify query proof",
        )
        .await
}

#[tokio::test]
async fn test_session_invalid_merkle_root() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.merkle_root = rand::random();
    setup
        .assert_auth_err(error_codes::INVALID_MERKLE_ROOT, "invalid merkle root")
        .await
}

#[tokio::test]
async fn test_session_invalid_rp_id() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.authorization.rp_id = RpId::new(rand::random());
    setup
        .assert_auth_err(error_codes::UNKNOWN_RP, "unknown RP")
        .await
}

#[tokio::test]
async fn test_session_invalid_signer() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.authorization.nonce = rand::random::<ark_babyjubjub::Fq>().into();
    setup
        .assert_auth_err(
            error_codes::INVALID_RP_SIGNATURE,
            "signature from RP cannot be verified",
        )
        .await
}

#[tokio::test]
async fn test_session_corrupt_signature() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    // r=0, s=0 produces an unrecoverable signature, triggering CorruptSignature (not InvalidSignature)
    setup.request.auth.authorization_proof = RpAuthorizationProof::Eoa {
        signature: alloy::primitives::Signature::new(
            alloy::primitives::U256::ZERO,
            alloy::primitives::U256::ZERO,
            false,
        ),
    };
    setup
        .assert_auth_err(
            error_codes::INVALID_RP_SIGNATURE,
            "signature from RP cannot be verified",
        )
        .await
}

#[tokio::test]
async fn test_session_tampered_expiration_timestamp() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.authorization.expires_at += 1;
    setup
        .assert_auth_err(
            error_codes::INVALID_RP_SIGNATURE,
            "signature from RP cannot be verified",
        )
        .await
}

#[tokio::test]
async fn test_session_expired_rp_signature() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.authorization.expires_at = 0;
    setup
        .assert_auth_err(error_codes::RP_SIGNATURE_EXPIRED, "RP signature expired")
        .await
}

#[tokio::test]
async fn test_session_replay() -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new_session().await?;
    setup
        .request_authenticator
        .authenticate(&setup.request)
        .await?;
    setup
        .assert_auth_err(error_codes::DUPLICATE_NONCE, "signature nonce already used")
        .await
}

#[tokio::test]
async fn test_session_inactive_rp() -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new_session().await?;
    let rp_fixture = setup.setup.rp_fixture.clone();
    let deployer = setup.setup.anvil.signer(0)?;
    let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
    setup
        .setup
        .anvil
        .update_rp(
            setup.setup.rp_registry,
            deployer,
            rp_signer.clone(),
            rp_fixture.world_rp_id,
            true,
            rp_signer.address(),
            rp_signer.address(),
            "taceo.oprf".to_string(),
        )
        .await?;
    setup
        .assert_auth_err(error_codes::INACTIVE_RP, "inactive RP")
        .await
}

#[tokio::test]
async fn test_session_wip101_aux_data_on_eoa() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    // An EOA signer cannot use the WIP-101 proof variant.
    setup.request.auth.authorization_proof = RpAuthorizationProof::Wip101 {
        data: vec![0x01, 0x02, 0x03],
    };
    setup
        .assert_auth_err(
            error_codes::WIP101_AUX_DATA_ON_EOA,
            "WIP101 authorization proof cannot be used with an EOA backed signer",
        )
        .await
}

// ── Session-specific tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_session_success_action() -> eyre::Result<()> {
    let setup =
        RpModuleTestSetup::new_unbound_session_with_fe_type(OprfPrefix::SessionAction).await?;
    setup.assert_auth_ok().await
}

#[tokio::test]
async fn test_session_invalid_action_nullifier_prefix() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    // rp_fixture.action has 0x00 prefix, which is valid for uniqueness but NOT for session
    setup.request.auth.oprf_action = setup.setup.rp_fixture.action;
    setup
        .assert_auth_err(
            error_codes::INVALID_ACTION_SESSION,
            "invalid action for session proofs",
        )
        .await
}

#[tokio::test]
async fn test_session_invalid_action_random_prefix() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    // MSB = 0x03 is not a valid session prefix
    setup.request.auth.oprf_action = action_with_msb(0x03);
    setup
        .assert_auth_err(
            error_codes::INVALID_ACTION_SESSION,
            "invalid action for session proofs",
        )
        .await
}

// ── Uniqueness-specific tests ────────────────────────────────────────────

#[tokio::test]
async fn test_uniqueness_success() -> eyre::Result<()> {
    check_success(RpModuleTestSetup::new_uniqueness().await?).await
}

#[tokio::test]
async fn test_uniqueness_requires_exact_signed_action() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_uniqueness().await?;
    setup.authorize(
        ProofType::Uniqueness,
        RpRequestSessionMode::None,
        Some(FieldElement::from(42_u64)),
        None,
    );
    setup
        .assert_auth_err(
            error_codes::INVALID_RP_AUTHORIZATION,
            "Invalid RP request authorization",
        )
        .await
}

#[tokio::test]
async fn test_uniqueness_without_session_cannot_derive_seed() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_bound_session_seed().await?;
    setup.authorize(
        ProofType::Uniqueness,
        RpRequestSessionMode::None,
        Some(setup.setup.rp_fixture.action.into()),
        None,
    );
    setup
        .assert_auth_err(
            error_codes::INVALID_RP_AUTHORIZATION,
            "Invalid RP request authorization",
        )
        .await
}

#[tokio::test]
async fn test_uniqueness_create_can_derive_seed() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_bound_session_seed().await?;
    setup.authorize(
        ProofType::Uniqueness,
        RpRequestSessionMode::Create,
        Some(setup.setup.rp_fixture.action.into()),
        None,
    );
    setup.assert_auth_ok().await
}

#[tokio::test]
async fn test_existing_session_requires_exact_seed_opening() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.authorize(
        ProofType::Session,
        RpRequestSessionMode::Existing,
        None,
        Some(B256::repeat_byte(0x24)),
    );
    setup.request.auth.session_seed_opening = Some(B256::repeat_byte(0x25));
    setup
        .assert_auth_err(
            error_codes::INVALID_RP_AUTHORIZATION,
            "Invalid RP request authorization",
        )
        .await
}

#[tokio::test]
async fn test_existing_session_seed_success() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.authorize(
        ProofType::Session,
        RpRequestSessionMode::Existing,
        None,
        Some(B256::repeat_byte(0x24)),
    );
    setup.assert_auth_ok().await
}

#[tokio::test]
async fn test_uniqueness_invalid_action() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_uniqueness().await?;
    // MSB = 0x01 is a session prefix, which is invalid for uniqueness
    setup.request.auth.oprf_action = action_with_msb(0x01);
    setup
        .assert_auth_err(
            error_codes::INVALID_ACTION_NULLIFIER,
            "invalid action for nullifier",
        )
        .await
}

#[tokio::test]
async fn test_uniqueness_invalid_action_session_prefix() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_uniqueness().await?;
    // MSB = 0x02 is the session Action prefix, invalid for uniqueness
    setup.request.auth.oprf_action = action_with_msb(0x02);
    setup
        .assert_auth_err(
            error_codes::INVALID_ACTION_NULLIFIER,
            "invalid action for nullifier",
        )
        .await
}

const DISPATCH_TIMEOUT: Duration = Duration::from_secs(1);

fn mock_session_auth(rpc_provider: taceo_nodes_common::web3::HttpRpcProvider) -> RpModuleAuth {
    let vk: VerificationKey<Bn254> =
        serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");
    RpModuleAuth::new_session(RpModuleAuthArgs {
        merkle_watcher: MerkleWatcher::init(
            Address::ZERO,
            &rpc_provider,
            WatcherCacheConfig::default(),
        ),
        rp_registry_watcher: RpRegistryWatcher::init(
            Address::ZERO,
            rpc_provider.clone(),
            DISPATCH_TIMEOUT,
            WatcherCacheConfig::default(),
        ),
        nonce_history: NonceHistory::init(Duration::from_secs(60)),
        created_at_max_difference: chrono::Duration::minutes(5),
        expires_at_max_difference: chrono::Duration::minutes(5),
        timeout_external_eth_call: DISPATCH_TIMEOUT,
        rpc_provider,
        rp_registry_address: Address::ZERO,
        chain_id: 1,
        query_vk: Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
    })
}

fn dispatch_request() -> OprfRequest<NullifierOprfRequestAuthV1> {
    OprfRequest {
        request_id: Uuid::new_v4(),
        blinded_query: ark_babyjubjub::EdwardsAffine::default(),
        auth: wip101::tests::dummy_auth(),
    }
}

#[tokio::test]
async fn test_dispatch_contract_signer_verifies_wip101() {
    let authenticator = mock_session_auth(wip101::tests::provider_with_success(
        &wip101::tests::success_magic_response(),
    ));
    let request = dispatch_request();
    let rp = wip101::tests::relying_party(RpAccountType::Contract);
    authenticator
        .ensure_authorization_valid(&rp, &request)
        .await
        .expect("contract RP with valid WIP101 response should pass");
}

#[tokio::test]
async fn test_dispatch_contract_signer_rejects_eoa_proof_without_rpc() {
    let authenticator = mock_session_auth(Asserter::new().into());
    let mut request = dispatch_request();
    request.auth.authorization_proof = RpAuthorizationProof::Eoa {
        signature: alloy::primitives::Signature::new(
            alloy::primitives::U256::ZERO,
            alloy::primitives::U256::ZERO,
            false,
        ),
    };
    let rp = wip101::tests::relying_party(RpAccountType::Contract);

    let error = authenticator
        .ensure_authorization_valid(&rp, &request)
        .await
        .expect_err("contract RP must reject an EOA authorization proof");

    assert!(matches!(
        error,
        RpModuleError::InvalidRpAuthorization {
            context: "EOA authorization proof cannot be used with a contract signer"
        }
    ));
}

#[tokio::test]
async fn test_dispatch_incompatible_wip101_signer() {
    let authenticator = mock_session_auth(Asserter::new().into());
    let request = dispatch_request();
    let rp = wip101::tests::relying_party(RpAccountType::IncompatibleWip101);
    let error = authenticator
        .ensure_authorization_valid(&rp, &request)
        .await
        .expect_err("incompatible WIP101 signer must fail");
    assert!(matches!(
        error,
        RpModuleError::Wip101(Wip101Error::IncompatibleRpSigner)
    ));
}
