use std::time::Duration;

use alloy::{
    primitives::{Address, B256, Bytes, FixedBytes, U160, U256},
    providers::mock::Asserter,
    rpc::json_rpc::ErrorPayload,
    sol_types::{SolCall as _, SolError as _, SolValue as _},
};
use taceo_oprf::types::OprfKeyId;
use world_id_primitives::{
    FieldElement, ProofType, RequestVersion,
    oprf::NullifierOprfRequestAuthV1,
    rp::{IWIP101, RpId, RpRequestAuthorization, RpRequestSessionMode},
};

use super::Wip101Error;
use crate::auth::rp_module::{RelyingParty, RpAccountType};

const TEST_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) fn provider_with_success<T: serde::Serialize>(
    value: &T,
) -> taceo_nodes_common::web3::HttpRpcProvider {
    let asserter = Asserter::new();
    asserter.push_success(value);
    asserter.into()
}

fn provider_with_revert(data: &Bytes) -> taceo_nodes_common::web3::HttpRpcProvider {
    let asserter = Asserter::new();
    let json = format!(r#"{{"code":3,"message":"execution reverted","data":"{data}"}}"#);
    asserter.push_failure(
        serde_json::from_str::<ErrorPayload>(&json).expect("revert payload should be valid JSON"),
    );
    asserter.into()
}

pub(crate) fn relying_party(account_type: RpAccountType) -> RelyingParty {
    RelyingParty {
        signer: Address::ZERO,
        oprf_key_id: OprfKeyId::new(U160::ZERO),
        account_type,
    }
}

fn dummy_authorization() -> RpRequestAuthorization {
    RpRequestAuthorization {
        request_version: RequestVersion::V1,
        rp_id: RpId::new(0),
        oprf_key_id: OprfKeyId::new(U160::ZERO),
        nonce: FieldElement::from(2u64),
        created_at: 1,
        expires_at: 2,
        proof_type: ProofType::Uniqueness,
        session_mode: RpRequestSessionMode::None,
        action: Some(FieldElement::from(1u64)),
        existing_session_seed_authorization: B256::ZERO,
        details_hash: B256::repeat_byte(0x42),
    }
}

pub(crate) fn dummy_auth() -> NullifierOprfRequestAuthV1 {
    NullifierOprfRequestAuthV1 {
        proof: circom_types::groth16::Proof {
            pi_a: ark_bn254::G1Affine::default(),
            pi_b: ark_bn254::G2Affine::default(),
            pi_c: ark_bn254::G1Affine::default(),
            protocol: "groth16".to_string(),
            curve: "bn254".to_string(),
        },
        action: ark_babyjubjub::Fq::from(1u64),
        nonce: ark_babyjubjub::Fq::from(2u64),
        merkle_root: ark_babyjubjub::Fq::from(3u64),
        created_at: 1,
        expires_at: 2,
        signature: None,
        rp_id: RpId::new(0),
        wip101_data: None,
        rp_request_authorization: dummy_authorization(),
        session_seed_opening: None,
    }
}

pub(crate) fn success_magic_response() -> Bytes {
    Bytes::from(FixedBytes::<4>::from(IWIP101::verifyRpRequestCall::SELECTOR).abi_encode())
}

#[tokio::test]
async fn verify_success() {
    let auth = dummy_auth();
    relying_party(RpAccountType::Contract)
        .verify_wip101(
            &auth,
            &provider_with_success(&success_magic_response()),
            TEST_TIMEOUT,
        )
        .await
        .expect("valid response should succeed");
}

#[tokio::test]
async fn verify_wrong_magic() {
    let auth = dummy_auth();
    let response = FixedBytes::<4>::from([0xde, 0xad, 0xbe, 0xef]).abi_encode();
    let error = relying_party(RpAccountType::Contract)
        .verify_wip101(
            &auth,
            &provider_with_success(&Bytes::from(response)),
            TEST_TIMEOUT,
        )
        .await
        .expect_err("wrong magic must fail");
    assert!(matches!(error, Wip101Error::VerificationFailed(None)));
}

#[tokio::test]
async fn verify_custom_error() {
    let auth = dummy_auth();
    let revert = IWIP101::RpInvalidRequest {
        code: U256::from(42),
    }
    .abi_encode();
    let error = relying_party(RpAccountType::Contract)
        .verify_wip101(&auth, &provider_with_revert(&revert.into()), TEST_TIMEOUT)
        .await
        .expect_err("custom error must fail");
    assert!(matches!(error, Wip101Error::VerificationFailed(Some(code)) if code == U256::from(42)));
}

#[tokio::test]
async fn verify_plain_revert() {
    let auth = dummy_auth();
    let error = relying_party(RpAccountType::Contract)
        .verify_wip101(
            &auth,
            &provider_with_revert(&Bytes::from_static(b"reason")),
            TEST_TIMEOUT,
        )
        .await
        .expect_err("plain revert must fail");
    assert!(matches!(error, Wip101Error::CustomRevert));
}

#[tokio::test]
async fn verify_empty_revert_is_incompatible() {
    let auth = dummy_auth();
    let error = relying_party(RpAccountType::Contract)
        .verify_wip101(&auth, &provider_with_revert(&Bytes::new()), TEST_TIMEOUT)
        .await
        .expect_err("empty revert must fail");
    assert!(matches!(error, Wip101Error::IncompatibleRpSigner));
}

#[tokio::test]
async fn verify_empty_response_is_incompatible() {
    let auth = dummy_auth();
    let error = relying_party(RpAccountType::Contract)
        .verify_wip101(&auth, &provider_with_success(&Bytes::new()), TEST_TIMEOUT)
        .await
        .expect_err("empty response must fail");
    assert!(matches!(error, Wip101Error::IncompatibleRpSigner));
}

#[tokio::test]
async fn verify_auxiliary_data_limits() {
    let mut auth = dummy_auth();
    auth.wip101_data = Some(vec![0xab; super::MAX_AUX_DATA_SIZE]);
    relying_party(RpAccountType::Contract)
        .verify_wip101(
            &auth,
            &provider_with_success(&success_magic_response()),
            TEST_TIMEOUT,
        )
        .await
        .expect("maximum auxiliary data size should succeed");

    auth.wip101_data = Some(vec![0xab; super::MAX_AUX_DATA_SIZE + 1]);
    let error = relying_party(RpAccountType::Contract)
        .verify_wip101(&auth, &Asserter::new().into(), TEST_TIMEOUT)
        .await
        .expect_err("oversized auxiliary data must fail");
    assert!(matches!(error, Wip101Error::AuxDataTooLarge));
}

#[tokio::test]
async fn verify_timeout() {
    // A listener that accepts but never answers keeps the RPC call pending
    // until the timeout fires.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("can bind");
    let url = format!("http://{}", listener.local_addr().expect("has local addr"));
    let provider = taceo_nodes_common::web3::HttpRpcProviderBuilder::with_default_values([url])
        .expect("can build provider builder")
        .environment(taceo_nodes_common::Environment::Dev)
        .build()
        .expect("can build provider");

    let auth = dummy_auth();
    let error = relying_party(RpAccountType::Contract)
        .verify_wip101(&auth, &provider, Duration::from_millis(100))
        .await
        .expect_err("hanging RPC must time out");
    assert!(matches!(error, Wip101Error::VerificationTimeout));
}

fn account_provider(
    responses: impl IntoIterator<Item = Bytes>,
) -> taceo_nodes_common::web3::HttpRpcProvider {
    let asserter = Asserter::new();
    for response in responses {
        asserter.push_success(&response);
    }
    asserter.into()
}

// The FIFO Asserter responses answer the three `supportsInterface` probes of
// `erc165_supports_interface` in its `tokio::join!` poll order:
// 1. the target interface (verifyRpRequest selector),
// 2. the ERC-165 conformance probe (0x01ffc9a7, must be supported),
// 3. the invalid-interface sanity probe (0xffffffff, must NOT be supported).

#[tokio::test]
async fn account_check_compatible_contract() {
    let supports_wip101 = Bytes::from(true.abi_encode());
    let supports_erc165 = Bytes::from(true.abi_encode());
    let supports_invalid_interface = Bytes::from(false.abi_encode());
    let account = super::account_check(
        Address::ZERO,
        &account_provider([supports_wip101, supports_erc165, supports_invalid_interface]),
    )
    .await
    .expect("account check should succeed");
    assert_eq!(account, RpAccountType::Contract);
}

#[tokio::test]
async fn account_check_incompatible_contract() {
    let no = Bytes::from(false.abi_encode());
    let account = super::account_check(
        Address::ZERO,
        &account_provider([no.clone(), no.clone(), no]),
    )
    .await
    .expect("account check should succeed");
    assert_eq!(account, RpAccountType::IncompatibleWip101);
}

#[tokio::test]
async fn account_check_eoa() {
    // Empty return data on all three probes means no code at the address.
    let empty = Bytes::new();
    let account = super::account_check(
        Address::ZERO,
        &account_provider([empty.clone(), empty.clone(), empty]),
    )
    .await
    .expect("account check should succeed");
    assert_eq!(account, RpAccountType::Eoa);
}
