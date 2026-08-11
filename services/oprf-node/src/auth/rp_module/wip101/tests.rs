use std::time::Duration;

use alloy::{
    primitives::{Address, Bytes, FixedBytes, U160, U256},
    providers::mock::Asserter,
    rpc::json_rpc::ErrorPayload,
    sol_types::{SolError as _, SolValue as _},
};
use taceo_oprf::types::OprfKeyId;

use super::{IWIP101, Wip101Error};
use crate::auth::rp_module::{RelyingParty, RpAccountType, tests::RpModuleTestSetup};

const TEST_TIMEOUT: Duration = Duration::from_secs(1);

fn provider_with_success<T: serde::Serialize>(
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

fn relying_party() -> RelyingParty {
    RelyingParty {
        signer: Address::ZERO,
        oprf_key_id: OprfKeyId::new(U160::ZERO),
        account_type: RpAccountType::Contract,
        is_blocked: false,
        fetched_at_block: U256::ZERO,
        fetched_at_timestamp: U256::ZERO,
    }
}

async fn request_auth() -> world_id_primitives::oprf::NullifierOprfRequestAuthV1 {
    RpModuleTestSetup::new_session()
        .await
        .expect("should build request")
        .request
        .auth
}

#[tokio::test]
async fn verify_success() {
    let auth = request_auth().await;
    let response = FixedBytes::<4>::from(super::SUCCESS_MAGIC_VALUE).abi_encode();
    relying_party()
        .verify_wip101(
            auth.action,
            &auth,
            &provider_with_success(&Bytes::from(response)),
            TEST_TIMEOUT,
        )
        .await
        .expect("valid response should succeed");
}

#[tokio::test]
async fn verify_wrong_magic() {
    let auth = request_auth().await;
    let response = FixedBytes::<4>::from([0xde, 0xad, 0xbe, 0xef]).abi_encode();
    let error = relying_party()
        .verify_wip101(
            auth.action,
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
    let auth = request_auth().await;
    let revert = IWIP101::RpInvalidRequest {
        code: U256::from(42),
    }
    .abi_encode();
    let error = relying_party()
        .verify_wip101(
            auth.action,
            &auth,
            &provider_with_revert(&revert.into()),
            TEST_TIMEOUT,
        )
        .await
        .expect_err("custom error must fail");
    assert!(matches!(error, Wip101Error::VerificationFailed(Some(code)) if code == U256::from(42)));
}

#[tokio::test]
async fn verify_plain_revert() {
    let auth = request_auth().await;
    let error = relying_party()
        .verify_wip101(
            auth.action,
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
    let auth = request_auth().await;
    let error = relying_party()
        .verify_wip101(
            auth.action,
            &auth,
            &provider_with_revert(&Bytes::new()),
            TEST_TIMEOUT,
        )
        .await
        .expect_err("empty revert must fail");
    assert!(matches!(error, Wip101Error::IncompatibleRpSigner));
}

#[tokio::test]
async fn verify_auxiliary_data_limits() {
    let mut auth = request_auth().await;
    auth.wip101_data = Some(vec![0xab; super::MAX_AUX_DATA_SIZE]);
    let response = FixedBytes::<4>::from(super::SUCCESS_MAGIC_VALUE).abi_encode();
    relying_party()
        .verify_wip101(
            auth.action,
            &auth,
            &provider_with_success(&Bytes::from(response)),
            TEST_TIMEOUT,
        )
        .await
        .expect("maximum auxiliary data size should succeed");

    auth.wip101_data = Some(vec![0xab; super::MAX_AUX_DATA_SIZE + 1]);
    let error = relying_party()
        .verify_wip101(auth.action, &auth, &Asserter::new().into(), TEST_TIMEOUT)
        .await
        .expect_err("oversized auxiliary data must fail");
    assert!(matches!(error, Wip101Error::AuxDataTooLarge));
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

#[tokio::test]
async fn account_check_compatible_contract() {
    let yes = Bytes::from(true.abi_encode());
    let no = Bytes::from(false.abi_encode());
    let account = super::account_check(Address::ZERO, &account_provider([yes.clone(), yes, no]))
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
    let empty = Bytes::new();
    let account = super::account_check(
        Address::ZERO,
        &account_provider([empty.clone(), empty.clone(), empty]),
    )
    .await
    .expect("account check should succeed");
    assert_eq!(account, RpAccountType::Eoa);
}
