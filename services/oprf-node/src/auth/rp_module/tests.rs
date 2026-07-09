#![allow(clippy::large_futures, reason = "Is ok in tests")]

use std::time::Duration;

use alloy::{
    primitives::Address,
    signers::{SignerSync as _, local::LocalSigner},
};
use ark_ff::PrimeField as _;
use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator as _};
use uuid::Uuid;
use world_id_primitives::{
    FieldElement, SessionFeType, SessionFieldElement as _,
    oprf::{NullifierOprfRequestAuthV1, error_codes},
    rp::RpId,
};

use crate::{
    accountant_batcher,
    auth::{
        rp_module::{
            RpModuleAuth,
            wip101::tests::{
                NoERC165, NoWIP101, WIP101BrokenERC165, WIP101Correct, WIP101CorrectWhenAuxData,
                WIP101PlainRevert, WIP101RevertsWithCode, WIP101TimeoutERC165, WIP101TimeoutVerify,
                WIP101WrongMagic, WrongSignature,
            },
        },
        tests::{AuthModulesTestSetup, OprfRequestAuthTestSetup, SetupKind},
    },
};

pub(crate) struct RpModuleTestSetup {
    pub(crate) setup: OprfRequestAuthTestSetup,
    pub(crate) request_authenticator: RpModuleAuth,
    pub(crate) request: OprfRequest<NullifierOprfRequestAuthV1>,
}

impl RpModuleTestSetup {
    pub(crate) async fn new_session() -> eyre::Result<Self> {
        Self::new_session_with_fe_type(SessionFeType::OprfSeed).await
    }

    /// Constructs a valid session test setup with the given session type.
    pub(crate) async fn new_session_with_fe_type(
        session_type: SessionFeType,
    ) -> eyre::Result<Self> {
        let mut rng = rand::thread_rng();
        let infra = AuthModulesTestSetup::new(SetupKind::RpModule).await?;

        let request_authenticator = RpModuleAuth::new_session(infra.rp_module_args());

        // Session action must have the correct prefix byte (0x01 or 0x02)
        let session_action = FieldElement::random_for_session(&mut rng, session_type);
        let bundle = infra
            .generate_query_proof(session_action, infra.setup.rp_fixture.world_rp_id.into())?;

        // Session RP signature does NOT include the action therefore we cannot use the rp_fixture
        let rp_signer = LocalSigner::from_signing_key(infra.setup.rp_fixture.signing_key.clone());
        let msg = world_id_primitives::rp::compute_rp_signature_msg(
            infra.setup.rp_fixture.nonce,
            infra.setup.rp_fixture.current_timestamp,
            infra.setup.rp_fixture.expiration_timestamp,
            None,
        );
        let signature = rp_signer.sign_message_sync(&msg).expect("can sign");

        let auth = NullifierOprfRequestAuthV1 {
            proof: bundle.proof,
            action: *session_action,
            nonce: bundle.nonce,
            merkle_root: *infra.setup.merkle_inclusion_proof.root,
            current_time_stamp: infra.setup.rp_fixture.current_timestamp,
            expiration_timestamp: infra.setup.rp_fixture.expiration_timestamp,
            signature: Some(signature),
            rp_id: infra.setup.rp_fixture.world_rp_id,
            wip101_data: None,
        };

        Ok(Self {
            setup: infra.setup,
            request_authenticator,
            request: OprfRequest {
                request_id: Uuid::new_v4(),
                blinded_query: bundle.blinded_query,
                auth,
            },
        })
    }

    async fn new_uniqueness() -> eyre::Result<Self> {
        let infra = AuthModulesTestSetup::new(SetupKind::RpModule).await?;
        let request_authenticator =
            RpModuleAuth::new_uniqueness(infra.rp_module_args(), accountant_batcher::dev_null());

        // Uniqueness uses the fixture's pre-generated action (guaranteed 0x00 MSB)
        // and a signature that includes the action
        let bundle = infra.generate_query_proof(
            infra.setup.rp_fixture.action.into(),
            infra.setup.rp_fixture.world_rp_id.into(),
        )?;

        let auth = NullifierOprfRequestAuthV1 {
            proof: bundle.proof,
            action: infra.setup.rp_fixture.action,
            nonce: bundle.nonce,
            merkle_root: *infra.setup.merkle_inclusion_proof.root,
            current_time_stamp: infra.setup.rp_fixture.current_timestamp,
            expiration_timestamp: infra.setup.rp_fixture.expiration_timestamp,
            signature: Some(infra.setup.rp_fixture.signature),
            rp_id: infra.setup.rp_fixture.world_rp_id,
            wip101_data: None,
        };

        Ok(Self {
            setup: infra.setup,
            request_authenticator,
            request: OprfRequest {
                request_id: Uuid::new_v4(),
                blinded_query: bundle.blinded_query,
                auth,
            },
        })
    }

    /// Points the RP's registered signer at `address` (a deployed WIP101 mock
    /// contract) and switches the request to contract-based auth.
    pub(crate) async fn set_contract_signer(&mut self, address: Address, data: Option<Vec<u8>>) {
        let signer = self
            .setup
            .anvil
            .signer(0)
            .expect("Should have an anvil signer");
        self.setup
            .anvil
            .update_rp(
                self.setup.rp_registry,
                signer,
                self.setup.rp_fixture.signing_key.clone().into(),
                self.setup.rp_fixture.world_rp_id,
                false,
                address,
                address,
                "some domain".to_owned(),
            )
            .await
            .expect("Should be able to update RP signer");

        self.request.auth.signature = None;
        self.request.auth.wip101_data = data;
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
}

// ── Local test helpers ───────────────────────────────────────────────────

/// Random field element whose big-endian MSB is forced to `msb`
/// (used to build actions with a specific prefix byte).
fn action_with_msb(msb: u8) -> ark_babyjubjub::Fq {
    let mut bytes = rand::random::<[u8; 32]>();
    bytes[0] = msb;
    ark_babyjubjub::Fq::from_be_bytes_mod_order(&bytes)
}

/// Deploys a WIP101 mock contract and returns its address.
macro_rules! deploy {
    ($contract:ident, $setup:expr) => {
        *$contract::deploy($setup.request_authenticator.rpc_provider.inner())
            .await
            .expect("Should be able to deploy contract")
            .address()
    };
}

// ── Shared test helpers ──────────────────────────────────────────────────

async fn check_success(setup: RpModuleTestSetup) -> eyre::Result<()> {
    setup.assert_auth_ok().await
}

/// Shared assertion for the WIP101-incompatible-signer checks below: the
/// message string appears once here instead of four times.
async fn assert_wip101_incompatible(
    mut setup: RpModuleTestSetup,
    addr: Address,
) -> eyre::Result<()> {
    setup.set_contract_signer(addr, None).await;
    setup
        .assert_auth_err(
            error_codes::WIP101_INCOMPATIBLE_RP_SIGNER,
            "RP has a contract backed signer but doesn't conform to WIP101",
        )
        .await
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
    setup.request.auth.current_time_stamp -= setup
        .request_authenticator
        .current_time_stamp_max_difference
        .as_secs()
        + 100;
    setup
        .assert_auth_err(
            error_codes::TIMESTAMP_TOO_OLD,
            "timestamp in request too old",
        )
        .await
}

#[tokio::test]
async fn test_session_future_timestamp() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.current_time_stamp += setup
        .request_authenticator
        .current_time_stamp_max_difference
        .as_secs()
        + 100;
    setup
        .assert_auth_err(
            error_codes::TIMESTAMP_TOO_FAR_IN_FUTURE,
            "timestamp too far in future",
        )
        .await
}

#[tokio::test]
async fn test_session_timestamp_zero() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.current_time_stamp = 0;
    setup
        .assert_auth_err(
            error_codes::TIMESTAMP_TOO_OLD,
            "timestamp in request too old",
        )
        .await
}

#[tokio::test]
async fn test_session_invalid_timestamp() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.current_time_stamp = u64::MAX;
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
    setup.request.auth.rp_id = RpId::new(rand::random());
    setup
        .assert_auth_err(error_codes::UNKNOWN_RP, "unknown RP")
        .await
}

#[tokio::test]
async fn test_session_blocked_rp_id() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    // 42 is the blocked RP in the mock
    setup.request.auth.rp_id = setup.setup.blocked_rp;
    setup
        .assert_auth_err(error_codes::BLOCKED_RP, "RP blocked by billing contract")
        .await
}

#[tokio::test]
async fn test_session_invalid_signer() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    setup.request.auth.nonce = rand::random();
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
    setup.request.auth.signature = Some(alloy::primitives::Signature::new(
        alloy::primitives::U256::ZERO,
        alloy::primitives::U256::ZERO,
        false,
    ));
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
    setup.request.auth.expiration_timestamp += 1;
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
    setup.request.auth.expiration_timestamp = 0;
    setup
        .assert_auth_err(error_codes::RP_SIGNATURE_EXPIRED, "RP signature expired")
        .await
}

#[tokio::test]
async fn test_session_missing_signature_eoa() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    // The signer is an EOA (default setup). Setting signature to None should fail.
    setup.request.auth.signature = None;
    setup
        .assert_auth_err(
            error_codes::RP_SIGNATURE_MISSING,
            "RP signature missing but signer is an EOA",
        )
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
async fn test_session_wip101_success() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101Correct, setup);
    setup.set_contract_signer(addr, None).await;
    setup.assert_auth_ok().await
}

#[tokio::test]
async fn test_session_wip101_success_max_data() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101Correct, setup);
    // should still work
    setup
        .set_contract_signer(addr, Some(vec![0xAB; 1024]))
        .await;
    setup.assert_auth_ok().await
}

#[tokio::test]
async fn test_session_wip101_success_if_data() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101CorrectWhenAuxData, setup);
    setup
        .set_contract_signer(addr, Some(vec![0xC0, 0xFF, 0xEE]))
        .await;
    setup.assert_auth_ok().await
}

#[tokio::test]
async fn test_session_wip101_no_data_failure() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101CorrectWhenAuxData, setup);
    setup.set_contract_signer(addr, None).await;
    // this should be the custom error as hex
    setup
        .assert_auth_err(error_codes::WIP101_VERIFICATION_FAILED, "0x1")
        .await
}

#[tokio::test]
async fn test_session_wip101_wrong_magic() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101WrongMagic, setup);
    setup.set_contract_signer(addr, None).await;
    setup
        .assert_auth_err(error_codes::WIP101_VERIFICATION_FAILED, "")
        .await
}

#[tokio::test]
async fn test_session_wip101_reverts_with_code() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101RevertsWithCode, setup);
    setup.set_contract_signer(addr, None).await;
    // this should be the custom error as hex
    setup
        .assert_auth_err(error_codes::WIP101_VERIFICATION_FAILED, "0x2a")
        .await
}

#[tokio::test]
async fn test_session_wip101_plain_revert() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101PlainRevert, setup);
    setup.set_contract_signer(addr, None).await;
    setup
        .assert_auth_err(
            error_codes::WIP101_CUSTOM_REVERT,
            "RP signer contract reverted with custom error (and not error RpInvalidRequest(uint256 code);)",
        )
        .await
}

#[tokio::test]
async fn test_session_wip101_broken_erc165() -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101BrokenERC165, setup);
    // whether the contract calls confirm to WIP101 as reported by ERC165 is irrelevant here
    assert_wip101_incompatible(setup, addr).await
}

#[tokio::test]
async fn test_session_wip101_no_erc165() -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(NoERC165, setup);
    assert_wip101_incompatible(setup, addr).await
}

#[tokio::test]
async fn test_session_wip101_no_verify_rp_request() -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(NoWIP101, setup);
    assert_wip101_incompatible(setup, addr).await
}

#[tokio::test]
async fn test_session_wip101_wrong_method_signature() -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WrongSignature, setup);
    assert_wip101_incompatible(setup, addr).await
}

#[tokio::test]
async fn test_session_wip101_aux_data_on_eoa() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    // EOA signer (default). Setting aux data should be rejected before any contract call.
    setup.request.auth.wip101_data = Some(vec![0x01, 0x02, 0x03]);
    setup
        .assert_auth_err(
            error_codes::WIP101_AUX_DATA_ON_EOA,
            "Auxiliary data must be empty with EOA backed signer",
        )
        .await
}

#[tokio::test]
async fn test_session_wip101_aux_data_too_large() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101Correct, setup);
    // 1025 bytes exceeds MAX_AUX_DATA_SIZE (1024)
    setup
        .set_contract_signer(addr, Some(vec![0xAB; 1025]))
        .await;
    setup
        .assert_auth_err(
            error_codes::WIP101_AUX_DATA_TOO_LARGE,
            "Auxiliary data for WIP101 contract too large - max 1024 bytes",
        )
        .await
}

#[tokio::test]
async fn test_session_wip101_verification_timeout() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    let addr = deploy!(WIP101TimeoutVerify, setup);
    setup.set_contract_signer(addr, None).await;
    // set timeout to 0
    setup.request_authenticator.timeout_external_eth_call = Duration::from_secs(0);
    setup
        .assert_auth_err(
            error_codes::WIP101_VERIFICATION_TIMEOUT,
            "WIP101 verification ran into timeout",
        )
        .await
}

#[tokio::test]
async fn test_session_wip101_account_check_timeout() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    // set timeout to 0
    setup
        .request_authenticator
        .rp_registry_watcher
        .set_timeout_external_eth_call(Duration::from_secs(0));
    let addr = deploy!(WIP101TimeoutERC165, setup);
    setup.set_contract_signer(addr, None).await;
    setup
        .assert_auth_err(
            error_codes::WIP101_ACCOUNT_CHECK_TIMEOUT,
            "Ran into timeout while doing WIP101/ERC165 check on RP's signer",
        )
        .await
}

// ── Session-specific tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_session_success_action() -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new_session_with_fe_type(SessionFeType::Action).await?;
    setup.assert_auth_ok().await
}

#[tokio::test]
async fn test_session_invalid_action_nullifier_prefix() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_session().await?;
    // rp_fixture.action has 0x00 prefix, which is valid for uniqueness but NOT for session
    setup.request.auth.action = setup.setup.rp_fixture.action;
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
    setup.request.auth.action = action_with_msb(0x03);
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
async fn test_uniqueness_invalid_action() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new_uniqueness().await?;
    // MSB = 0x01 is a session prefix, which is invalid for uniqueness
    setup.request.auth.action = action_with_msb(0x01);
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
    setup.request.auth.action = action_with_msb(0x02);
    setup
        .assert_auth_err(
            error_codes::INVALID_ACTION_NULLIFIER,
            "invalid action for nullifier",
        )
        .await
}
