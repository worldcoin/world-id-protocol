#![cfg(feature = "authenticator")]

use test_utils::anvil::TestAnvil;
use world_id_core::{Authenticator, AuthenticatorError};
use world_id_primitives::Config;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_register_issuer_schema() {
    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");

    let deployer = anvil.signer(0).unwrap();

    let registry_address = anvil
        .deploy_account_registry(deployer.clone())
        .await
        .expect("failed to deploy account registry");

    let config = Config::new(
        anvil.endpoint().to_string(),
        registry_address,
        "http://127.0.0.1:0".to_string(),
        "http://127.0.0.1:0".to_string(),
        Vec::new(),
    );

    let mut authenticator = Authenticator::new(&[1u8; 32], config).unwrap();

    // Assert the right error is returned when the account has not been registered.
    let result = authenticator.account_index().await.unwrap_err();
    assert_eq!(
        result.downcast_ref::<AuthenticatorError>().unwrap(),
        &AuthenticatorError::AccountDoesNotExist
    );

    // TODO: call gateway to register the account.
}
