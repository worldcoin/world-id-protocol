#![allow(clippy::large_futures, reason = "Is ok in tests")]

use std::{sync::Arc, time::Duration};

use alloy::{
    primitives::Address,
    signers::{SignerSync as _, local::LocalSigner},
};
use ark_bn254::Bn254;
use ark_ff::PrimeField as _;
use circom_types::groth16::VerificationKey;
use taceo_oprf::types::api::{OprfRequest, OprfRequestAuthenticator as _};
use uuid::Uuid;
use world_id_core::{FieldElement, primitives};
use world_id_primitives::{
    SessionFeType, SessionFieldElement as _, oprf::NullifierOprfRequestAuthV1, rp::RpId,
};

use crate::{
    QUERY_VERIFICATION_KEY,
    auth::{
        rp_module::{
            RpModuleAuth, RpModuleKind,
            wip101::tests::{
                NoERC165, NoWIP101, WIP101BrokenERC165, WIP101Correct, WIP101CorrectWhenAuxData,
                WIP101PlainRevert, WIP101RevertsWithCode, WIP101TimeoutERC165, WIP101TimeoutVerify,
                WIP101WrongMagic, WrongSignature,
            },
        },
        tests::{AuthModulesTestSetup, OprfRequestAuthTestSetup},
    },
};

pub(crate) struct RpModuleTestSetup {
    pub(crate) setup: OprfRequestAuthTestSetup,
    pub(crate) request_authenticator: RpModuleAuth,
    pub(crate) request: OprfRequest<NullifierOprfRequestAuthV1>,
}

impl RpModuleTestSetup {
    /// Constructs a valid test setup for the given kind.
    ///
    /// Session defaults to [`SessionFeType::OprfSeed`].
    /// Use [`Self::new_session`] to specify a different session type.
    pub(crate) async fn new(kind: RpModuleKind) -> eyre::Result<Self> {
        match kind {
            RpModuleKind::Session => Self::new_session(SessionFeType::OprfSeed).await,
            RpModuleKind::Uniqueness => Self::new_uniqueness().await,
        }
    }

    /// Constructs a valid session test setup with the given session type.
    pub(crate) async fn new_session(session_type: SessionFeType) -> eyre::Result<Self> {
        let mut rng = rand::thread_rng();
        let infra = AuthModulesTestSetup::new().await?;
        let vk: VerificationKey<Bn254> =
            serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");

        let request_authenticator = RpModuleAuth::new_session(
            infra.merkle_watcher.clone(),
            infra.rp_registry_watcher.clone(),
            infra.nonce_history.clone(),
            infra.current_time_stamp_max_difference,
            infra.timeout_external_eth_call,
            infra.rpc_provider.clone(),
            Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
        );

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
            auxiliary_wip101_bytes: None,
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
        let infra = AuthModulesTestSetup::new().await?;
        let vk: VerificationKey<Bn254> =
            serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");

        let request_authenticator = RpModuleAuth::new_uniqueness(
            infra.merkle_watcher.clone(),
            infra.rp_registry_watcher.clone(),
            infra.nonce_history.clone(),
            infra.current_time_stamp_max_difference,
            infra.timeout_external_eth_call,
            infra.rpc_provider.clone(),
            Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
        );

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
            auxiliary_wip101_bytes: None,
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

    pub(crate) async fn wip101_test(&mut self, address: Address) {
        self.wip101_test_with_data(address, None).await;
    }

    pub(crate) async fn wip101_test_with_data(&mut self, address: Address, data: Option<Vec<u8>>) {
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
        self.request.auth.auxiliary_wip101_bytes = data;
    }
}

// ── Shared test helpers ──────────────────────────────────────────────────

async fn check_success(kind: RpModuleKind) -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new(kind).await?;
    let oprf_key_id = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect("should succeed");
    assert_eq!(setup.setup.rp_fixture.oprf_key_id, oprf_key_id);
    Ok(())
}

async fn check_expired_timestamp(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.current_time_stamp -= setup
        .request_authenticator
        .current_time_stamp_max_difference
        .as_secs()
        + 100;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::TIMESTAMP_TOO_OLD
    );
    assert_eq!(auth_error.message(), "timestamp in request too old");
    Ok(())
}

async fn check_future_timestamp(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.current_time_stamp += setup
        .request_authenticator
        .current_time_stamp_max_difference
        .as_secs()
        + 100;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::TIMESTAMP_TOO_FAR_IN_FUTURE
    );
    assert_eq!(auth_error.message(), "timestamp too far in future");
    Ok(())
}

async fn check_invalid_query_proof(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.proof.pi_a = rand::random();
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_QUERY_PROOF
    );
    assert_eq!(auth_error.message(), "cannot verify query proof");
    Ok(())
}

async fn check_invalid_merkle_root(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.merkle_root = rand::random();
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_MERKLE_ROOT
    );
    assert_eq!(auth_error.message(), "invalid merkle root");
    Ok(())
}

async fn check_invalid_rp_id(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.rp_id = RpId::new(rand::random());
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(auth_error.code(), primitives::oprf::error_codes::UNKNOWN_RP);
    assert_eq!(auth_error.message(), "unknown RP");
    Ok(())
}

async fn check_invalid_signer(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.nonce = rand::random();
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_RP_SIGNATURE
    );
    assert_eq!(auth_error.message(), "signature from RP cannot be verified");
    Ok(())
}

async fn check_corrupt_signature(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // r=0, s=0 produces an unrecoverable signature, triggering CorruptSignature (not InvalidSignature)
    setup.request.auth.signature = Some(alloy::primitives::Signature::new(
        alloy::primitives::U256::ZERO,
        alloy::primitives::U256::ZERO,
        false,
    ));
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_RP_SIGNATURE
    );
    assert_eq!(auth_error.message(), "signature from RP cannot be verified");
    Ok(())
}

async fn check_replay(kind: RpModuleKind) -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new(kind).await?;
    setup
        .request_authenticator
        .authenticate(&setup.request)
        .await?;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::DUPLICATE_NONCE
    );
    assert_eq!(auth_error.message(), "signature nonce already used");
    Ok(())
}

async fn check_inactive_rp(kind: RpModuleKind) -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new(kind).await?;
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
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INACTIVE_RP
    );
    assert_eq!(auth_error.message(), "inactive RP");
    Ok(())
}

async fn check_tampered_blinded_query(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.blinded_query = rand::random();
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_QUERY_PROOF
    );
    assert_eq!(auth_error.message(), "cannot verify query proof");
    Ok(())
}

async fn check_tampered_expiration_timestamp(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.expiration_timestamp += 1;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_RP_SIGNATURE
    );
    assert_eq!(auth_error.message(), "signature from RP cannot be verified");
    Ok(())
}

async fn check_timestamp_zero(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.current_time_stamp = 0;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::TIMESTAMP_TOO_OLD
    );
    assert_eq!(auth_error.message(), "timestamp in request too old");
    Ok(())
}

async fn check_invalid_timestamp(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.current_time_stamp = u64::MAX;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_TIMESTAMP
    );
    assert_eq!(auth_error.message(), "cannot parse timestamp on request");
    Ok(())
}

async fn check_expired_rp_signature(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    setup.request.auth.expiration_timestamp = 0;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::RP_SIGNATURE_EXPIRED
    );
    assert_eq!(auth_error.message(), "RP signature expired");
    Ok(())
}

async fn check_missing_signature_eoa(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // The signer is an EOA (default setup). Setting signature to None should fail.
    setup.request.auth.signature = None;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail when EOA signature is missing");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::RP_SIGNATURE_MISSING
    );
    assert_eq!(
        auth_error.message(),
        "RP signature missing but signer is an EOA"
    );
    Ok(())
}

async fn check_wip101_success(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance = WIP101Correct::deploy(setup.request_authenticator.rpc_provider.http())
        .await
        .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    let oprf_key_id = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect("Should succeed");
    assert_eq!(oprf_key_id, setup.setup.rp_fixture.oprf_key_id);
    Ok(())
}

async fn check_wip101_with_max_data_success(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance = WIP101Correct::deploy(setup.request_authenticator.rpc_provider.http())
        .await
        .expect("Should be able to deploy contract");
    // should still work
    setup
        .wip101_test_with_data(*wip101_instance.address(), Some(vec![0xAB; 1024]))
        .await;

    let oprf_key_id = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect("Should succeed");
    assert_eq!(oprf_key_id, setup.setup.rp_fixture.oprf_key_id);
    Ok(())
}

async fn check_wip101_success_if_data(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance =
        WIP101CorrectWhenAuxData::deploy(setup.request_authenticator.rpc_provider.http())
            .await
            .expect("Should be able to deploy contract");
    setup
        .wip101_test_with_data(*wip101_instance.address(), Some(vec![0xC0, 0xFF, 0xEE]))
        .await;

    let oprf_key_id = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect("Should succeed");
    assert_eq!(oprf_key_id, setup.setup.rp_fixture.oprf_key_id);
    Ok(())
}

async fn check_wip101_no_data_failure(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance =
        WIP101CorrectWhenAuxData::deploy(setup.request_authenticator.rpc_provider.http())
            .await
            .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    let auth_err = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should error");
    assert_eq!(
        auth_err.code(),
        primitives::oprf::error_codes::WIP101_VERIFICATION_FAILED
    );
    // this should be the custom error as hex
    assert_eq!(auth_err.message(), "0x1");
    Ok(())
}

async fn check_wip101_wrong_magic(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance = WIP101WrongMagic::deploy(setup.request_authenticator.rpc_provider.http())
        .await
        .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    let auth_err = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should error");
    assert_eq!(
        auth_err.code(),
        primitives::oprf::error_codes::WIP101_VERIFICATION_FAILED
    );
    assert_eq!(auth_err.message(), "");
    Ok(())
}

async fn check_wip101_reverts_with_code(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance =
        WIP101RevertsWithCode::deploy(setup.request_authenticator.rpc_provider.http())
            .await
            .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    let auth_err = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should error");
    assert_eq!(
        auth_err.code(),
        primitives::oprf::error_codes::WIP101_VERIFICATION_FAILED
    );
    // this should be the custom error as hex
    assert_eq!(auth_err.message(), "0x2a");
    Ok(())
}

async fn check_wip101_plain_revert(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance =
        WIP101PlainRevert::deploy(setup.request_authenticator.rpc_provider.http())
            .await
            .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    let auth_err = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should error");
    assert_eq!(
        auth_err.code(),
        primitives::oprf::error_codes::WIP101_CUSTOM_REVERT
    );
    assert_eq!(
        auth_err.message(),
        "RP signer contract reverted with custom error (and not error RpInvalidRequest(uint256 code);)"
    );
    Ok(())
}

async fn check_wip101_broken_erc165(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance =
        WIP101BrokenERC165::deploy(setup.request_authenticator.rpc_provider.http())
            .await
            .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    // as call the contract irrelevant whether it confirms to WIP101 as reported by ERC165, this will still work
    let auth_err = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should err");
    assert_eq!(
        auth_err.code(),
        primitives::oprf::error_codes::WIP101_INCOMPATIBLE_RP_SIGNER
    );
    assert_eq!(
        auth_err.message(),
        "RP has a contract backed signer but doesn't conform to WIP101"
    );
    Ok(())
}

async fn check_wip101_no_erc165(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance = NoERC165::deploy(setup.request_authenticator.rpc_provider.http())
        .await
        .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    let auth_err = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should error");
    assert_eq!(
        auth_err.code(),
        primitives::oprf::error_codes::WIP101_INCOMPATIBLE_RP_SIGNER
    );
    assert_eq!(
        auth_err.message(),
        "RP has a contract backed signer but doesn't conform to WIP101"
    );
    Ok(())
}

async fn check_wip101_no_verify_rp_request(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance = NoWIP101::deploy(setup.request_authenticator.rpc_provider.http())
        .await
        .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    let auth_err = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should error");
    assert_eq!(
        auth_err.code(),
        primitives::oprf::error_codes::WIP101_INCOMPATIBLE_RP_SIGNER
    );
    assert_eq!(
        auth_err.message(),
        "RP has a contract backed signer but doesn't conform to WIP101"
    );
    Ok(())
}

async fn check_wip101_wrong_method_signature(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // deploy success

    let wip101_instance = WrongSignature::deploy(setup.request_authenticator.rpc_provider.http())
        .await
        .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    let auth_err = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should error");
    assert_eq!(
        auth_err.code(),
        primitives::oprf::error_codes::WIP101_INCOMPATIBLE_RP_SIGNER
    );
    assert_eq!(
        auth_err.message(),
        "RP has a contract backed signer but doesn't conform to WIP101"
    );
    Ok(())
}

async fn check_wip101_aux_data_on_eoa(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // EOA signer (default). Setting aux data should be rejected before any contract call.
    setup.request.auth.auxiliary_wip101_bytes = Some(vec![0x01, 0x02, 0x03]);
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail when EOA has aux data");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::WIP101_AUX_DATA_ON_EOA
    );
    assert_eq!(
        auth_error.message(),
        "Auxiliary data must be empty with EOA backed signer"
    );
    Ok(())
}

async fn check_wip101_verification_timeout(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;

    let wip101_instance =
        WIP101TimeoutVerify::deploy(setup.request_authenticator.rpc_provider.http())
            .await
            .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;

    // set timeout to 0
    setup.request_authenticator.timeout_external_eth_call = Duration::from_secs(0);
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail when timeout is zero");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::WIP101_VERIFICATION_TIMEOUT
    );
    assert_eq!(auth_error.message(), "WIP101 verification ran into timeout");
    Ok(())
}

async fn check_wip101_account_check_timeout(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    // set timeout to 0
    setup
        .request_authenticator
        .rp_registry_watcher
        .set_timeout_external_eth_call(Duration::from_secs(0));
    let wip101_instance =
        WIP101TimeoutERC165::deploy(setup.request_authenticator.rpc_provider.http())
            .await
            .expect("Should be able to deploy contract");
    setup.wip101_test(*wip101_instance.address()).await;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail when timeout is zero");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::WIP101_ACCOUNT_CHECK_TIMEOUT
    );
    assert_eq!(
        auth_error.message(),
        "Ran into timeout while doing WIP101/ERC165 check on RP's signer"
    );
    Ok(())
}

async fn check_wip101_aux_data_too_large(kind: RpModuleKind) -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(kind).await?;
    let wip101_instance = WIP101Correct::deploy(setup.request_authenticator.rpc_provider.http())
        .await
        .expect("Should be able to deploy contract");
    // 1025 bytes exceeds MAX_AUX_DATA_SIZE (1024)
    setup
        .wip101_test_with_data(*wip101_instance.address(), Some(vec![0xAB; 1025]))
        .await;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail when aux data too large");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::WIP101_AUX_DATA_TOO_LARGE
    );
    assert_eq!(
        auth_error.message(),
        "Auxiliary data for WIP101 contract too large - max 1024 bytes"
    );
    Ok(())
} // ── Session-specific tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_session_success_oprf_seed() -> eyre::Result<()> {
    check_success(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_success_action() -> eyre::Result<()> {
    let setup = RpModuleTestSetup::new_session(SessionFeType::Action).await?;
    setup
        .request_authenticator
        .authenticate(&setup.request)
        .await?;
    Ok(())
}

#[tokio::test]
async fn test_session_invalid_action_nullifier_prefix() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(RpModuleKind::Session).await?;
    // rp_fixture.action has 0x00 prefix, which is valid for uniqueness but NOT for session
    setup.request.auth.action = setup.setup.rp_fixture.action;
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_ACTION_SESSION
    );
    assert_eq!(auth_error.message(), "invalid action for session proofs");
    Ok(())
}

#[tokio::test]
async fn test_session_invalid_action_random_prefix() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(RpModuleKind::Session).await?;
    // MSB = 0x03 is not a valid session prefix
    let mut bytes = rand::random::<[u8; 32]>();
    bytes[0] = 0x03;
    setup.request.auth.action = ark_babyjubjub::Fq::from_be_bytes_mod_order(&bytes);
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_ACTION_SESSION
    );
    assert_eq!(auth_error.message(), "invalid action for session proofs");
    Ok(())
}

// ── Uniqueness-specific tests ────────────────────────────────────────────

#[tokio::test]
async fn test_uniqueness_success() -> eyre::Result<()> {
    check_success(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_invalid_action() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(RpModuleKind::Uniqueness).await?;
    // MSB = 0x01 is a session prefix, which is invalid for uniqueness
    let mut bytes = rand::random::<[u8; 32]>();
    bytes[0] = 0x01;
    setup.request.auth.action = ark_babyjubjub::Fq::from_be_bytes_mod_order(&bytes);
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_ACTION_NULLIFIER
    );
    assert_eq!(auth_error.message(), "invalid action for nullifier");
    Ok(())
}

#[tokio::test]
async fn test_uniqueness_invalid_action_session_prefix() -> eyre::Result<()> {
    let mut setup = RpModuleTestSetup::new(RpModuleKind::Uniqueness).await?;
    // MSB = 0x02 is the session Action prefix, invalid for uniqueness
    let mut bytes = rand::random::<[u8; 32]>();
    bytes[0] = 0x02;
    setup.request.auth.action = ark_babyjubjub::Fq::from_be_bytes_mod_order(&bytes);
    let auth_error = setup
        .request_authenticator
        .authenticate(&setup.request)
        .await
        .expect_err("Should fail");
    assert_eq!(
        auth_error.code(),
        primitives::oprf::error_codes::INVALID_ACTION_NULLIFIER
    );
    assert_eq!(auth_error.message(), "invalid action for nullifier");
    Ok(())
}

// ── Shared tests: session ────────────────────────────────────────────────

#[tokio::test]
async fn test_session_expired_timestamp() -> eyre::Result<()> {
    check_expired_timestamp(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_invalid_merkle_root() -> eyre::Result<()> {
    check_invalid_merkle_root(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_invalid_rp_id() -> eyre::Result<()> {
    check_invalid_rp_id(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_invalid_signer() -> eyre::Result<()> {
    check_invalid_signer(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_invalid_proof() -> eyre::Result<()> {
    check_invalid_query_proof(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_replay() -> eyre::Result<()> {
    check_replay(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_inactive_rp() -> eyre::Result<()> {
    check_inactive_rp(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_tampered_blinded_query() -> eyre::Result<()> {
    check_tampered_blinded_query(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_tampered_expiration_timestamp() -> eyre::Result<()> {
    check_tampered_expiration_timestamp(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_timestamp_zero() -> eyre::Result<()> {
    check_timestamp_zero(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_invalid_query_proof() -> eyre::Result<()> {
    check_invalid_query_proof(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_expired_rp_signature() -> eyre::Result<()> {
    check_expired_rp_signature(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_corrupt_signature() -> eyre::Result<()> {
    check_corrupt_signature(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_corrupt_timestamp() -> eyre::Result<()> {
    check_invalid_timestamp(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_check_future_timestamp() -> eyre::Result<()> {
    check_future_timestamp(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_missing_signature_eoa() -> eyre::Result<()> {
    check_missing_signature_eoa(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_success() -> eyre::Result<()> {
    check_wip101_success(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_success_max_data() -> eyre::Result<()> {
    check_wip101_with_max_data_success(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_wrong_magic() -> eyre::Result<()> {
    check_wip101_wrong_magic(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_reverts_with_code() -> eyre::Result<()> {
    check_wip101_reverts_with_code(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_plain_revert() -> eyre::Result<()> {
    check_wip101_plain_revert(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_broken_erc165() -> eyre::Result<()> {
    check_wip101_broken_erc165(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_no_erc165() -> eyre::Result<()> {
    check_wip101_no_erc165(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_no_verify_rp_request() -> eyre::Result<()> {
    check_wip101_no_verify_rp_request(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_wrong_method_signature() -> eyre::Result<()> {
    check_wip101_wrong_method_signature(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_success_if_data() -> eyre::Result<()> {
    check_wip101_success_if_data(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_no_data_failure() -> eyre::Result<()> {
    check_wip101_no_data_failure(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_aux_data_on_eoa() -> eyre::Result<()> {
    check_wip101_aux_data_on_eoa(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_aux_data_too_large() -> eyre::Result<()> {
    check_wip101_aux_data_too_large(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_verification_timeout() -> eyre::Result<()> {
    check_wip101_verification_timeout(RpModuleKind::Session).await
}

#[tokio::test]
async fn test_session_wip101_account_check_timeout() -> eyre::Result<()> {
    check_wip101_account_check_timeout(RpModuleKind::Session).await
}

// ── Shared tests: uniqueness ─────────────────────────────────────────────

#[tokio::test]
async fn test_uniqueness_expired_timestamp() -> eyre::Result<()> {
    check_expired_timestamp(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_invalid_merkle_root() -> eyre::Result<()> {
    check_invalid_merkle_root(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_invalid_rp_id() -> eyre::Result<()> {
    check_invalid_rp_id(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_invalid_signer() -> eyre::Result<()> {
    check_invalid_signer(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_invalid_proof() -> eyre::Result<()> {
    check_invalid_query_proof(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_replay() -> eyre::Result<()> {
    check_replay(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_inactive_rp() -> eyre::Result<()> {
    check_inactive_rp(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_tampered_blinded_query() -> eyre::Result<()> {
    check_tampered_blinded_query(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_tampered_expiration_timestamp() -> eyre::Result<()> {
    check_tampered_expiration_timestamp(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_timestamp_zero() -> eyre::Result<()> {
    check_timestamp_zero(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_invalid_query_proof() -> eyre::Result<()> {
    check_invalid_query_proof(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_expired_rp_signature() -> eyre::Result<()> {
    check_expired_rp_signature(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_corrupt_signature() -> eyre::Result<()> {
    check_corrupt_signature(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_corrupt_timestamp() -> eyre::Result<()> {
    check_invalid_timestamp(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_check_future_timestamp() -> eyre::Result<()> {
    check_future_timestamp(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_missing_signature_eoa() -> eyre::Result<()> {
    check_missing_signature_eoa(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_success() -> eyre::Result<()> {
    check_wip101_success(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_success_max_data() -> eyre::Result<()> {
    check_wip101_with_max_data_success(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_wrong_magic() -> eyre::Result<()> {
    check_wip101_wrong_magic(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_reverts_with_code() -> eyre::Result<()> {
    check_wip101_reverts_with_code(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_plain_revert() -> eyre::Result<()> {
    check_wip101_plain_revert(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_broken_erc165() -> eyre::Result<()> {
    check_wip101_broken_erc165(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_no_erc165() -> eyre::Result<()> {
    check_wip101_no_erc165(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_no_verify_rp_request() -> eyre::Result<()> {
    check_wip101_no_verify_rp_request(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_wrong_method_signature() -> eyre::Result<()> {
    check_wip101_wrong_method_signature(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_success_if_data() -> eyre::Result<()> {
    check_wip101_success_if_data(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_no_data_failure() -> eyre::Result<()> {
    check_wip101_no_data_failure(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_aux_data_on_eoa() -> eyre::Result<()> {
    check_wip101_aux_data_on_eoa(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_aux_data_too_large() -> eyre::Result<()> {
    check_wip101_aux_data_too_large(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_verification_timeout() -> eyre::Result<()> {
    check_wip101_verification_timeout(RpModuleKind::Uniqueness).await
}

#[tokio::test]
async fn test_uniqueness_wip101_account_check_timeout() -> eyre::Result<()> {
    check_wip101_account_check_timeout(RpModuleKind::Uniqueness).await
}
