use std::collections::HashSet;

use alloy::{
    primitives::{TxHash, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use futures::{StreamExt, stream::FuturesUnordered};
use reqwest::StatusCode;
use world_id_primitives::api_types::{CreateAccountRequest, GatewayStatusResponse};

use crate::common::{
    GW_PRIVATE_KEY, GW_SECOND_PRIVATE_KEY, spawn_test_gateway_with_large_wallet_pool,
    spawn_test_gateway_with_wallet_pool, wait_for_finalized,
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

/// This test validates that with multiple accounts available to the gateway,
/// the gateway can handle a large number of account creation requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_many_accounts() {
    // Max batch for account creations is 10 - so we'll end up with 100 transactions in total
    const NUM_ACCOUNTS_TO_CREATE: usize = 1_000;

    let gateway = spawn_test_gateway_with_large_wallet_pool(Some(100)).await;

    let provider = ProviderBuilder::new()
        .connect_http(gateway.rpc_url.parse().expect("invalid Anvil endpoint URL"));

    println!("Submitting gateway account creation requests...");
    let mut request_ids = vec![];
    for index in 0..NUM_ACCOUNTS_TO_CREATE {
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

        request_ids.push(accepted.request_id);
    }

    println!("Waiting for gateway requests to finalize...");
    let mut futures = FuturesUnordered::new();
    for request_id in request_ids {
        let client = gateway.client.clone();
        let base_url = gateway.base_url.clone();

        futures.push(async move { wait_for_finalized(&client, &base_url, &request_id).await });
    }

    println!("Asserting all transactions have finalized...");
    let mut tx_hashes = HashSet::new();
    while let Some(tx_hash) = futures.next().await {
        let tx_hash = tx_hash.parse().expect("invalid tx hash");

        tx_hashes.insert(tx_hash);

        let receipt = provider
            .get_transaction_receipt(tx_hash)
            .await
            .expect("failed to fetch transaction receipt")
            .expect("finalized transaction receipt is missing");

        assert!(receipt.status(), "{} should be successful", tx_hash)
    }

    println!("Submitted a total of {} transactions", tx_hashes.len());
}
