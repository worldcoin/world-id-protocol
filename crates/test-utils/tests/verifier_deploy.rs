use alloy::{
    primitives::{Address, U256},
    providers::ProviderBuilder,
};
use world_id_test_utils::{anvil::WorldIDVerifierV3, fixtures::RegistryTestContext};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deployed_verifier_has_packed_account_data_library_linked() {
    let ctx = RegistryTestContext::new()
        .await
        .expect("failed to build registry test context");

    let provider = ProviderBuilder::new().connect_http(
        ctx.anvil
            .endpoint()
            .parse()
            .expect("invalid anvil endpoint"),
    );
    let verifier = WorldIDVerifierV3::new(ctx.world_id_verifier, provider);

    // Unpacking runs through the library, so this reverts if the deploy left it unlinked.
    let packed = verifier
        .getPackedAccountData(Address::from([0x11; 20]))
        .call()
        .await
        .expect("getPackedAccountData reverted; PackedAccountData is likely unlinked");

    assert_eq!(packed, U256::ZERO, "unknown authenticator should return 0");
}
