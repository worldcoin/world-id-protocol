use alloy::{
    primitives::{TxHash, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use reqwest::StatusCode;
use world_id_primitives::api_types::{CreateAccountRequest, GatewayStatusResponse};

use crate::common::{
    GW_PRIVATE_KEY, GW_SECOND_PRIVATE_KEY, spawn_test_gateway_with_wallet_pool, wait_for_finalized,
};

mod common;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submissions_cycle_across_wallet_pool() {
    let gateway = spawn_test_gateway_with_wallet_pool(Some(100)).await;
    let provider = ProviderBuilder::new()
        .connect_http(gateway.rpc_url.parse().expect("invalid Anvil endpoint URL"));
    let expected_senders =
        [GW_PRIVATE_KEY, GW_SECOND_PRIVATE_KEY, GW_PRIVATE_KEY].map(|private_key| {
            private_key
                .parse::<PrivateKeySigner>()
                .expect("invalid test private key")
                .address()
        });

    let mut actual_senders = Vec::new();
    for index in 0..expected_senders.len() {
        let account = PrivateKeySigner::random().address();
        let request = CreateAccountRequest {
            recovery_address: Some(account),
            authenticator_addresses: vec![account],
            authenticator_pubkeys: vec![U256::from(index + 1)],
            offchain_signer_commitment: U256::from(index + 1),
        };
        let response = gateway
            .client
            .post(format!("{}/create-account", gateway.base_url))
            .json(&request)
            .send()
            .await
            .expect("failed to submit create-account request");
        assert_eq!(response.status(), StatusCode::OK);

        let accepted: GatewayStatusResponse = response
            .json()
            .await
            .expect("invalid create-account response");
        let tx_hash: TxHash =
            wait_for_finalized(&gateway.client, &gateway.base_url, &accepted.request_id)
                .await
                .parse()
                .expect("invalid finalized transaction hash");
        let receipt = provider
            .get_transaction_receipt(tx_hash)
            .await
            .expect("failed to fetch transaction receipt")
            .expect("finalized transaction receipt is missing");
        actual_senders.push(receipt.from);
    }

    assert_eq!(actual_senders, expected_senders);
}
