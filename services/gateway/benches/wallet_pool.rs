use std::{collections::HashSet, num::NonZeroUsize, time::Instant};

use alloy::{
    primitives::{TxHash, U256},
    providers::{Provider as _, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use futures::{StreamExt as _, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use world_id_primitives::api_types::{CreateAccountRequest, GatewayStatusResponse};

#[path = "../tests/common.rs"]
mod common;

use common::{TestGateway, spawn_test_gateway_with_large_wallet_pool, wait_for_finalized};

const BATCH_REEVALUATION_MS: u64 = 100;

#[derive(Debug, Parser)]
#[command(about = "Load benchmark for Gateway account creation with a wallet pool")]
struct Args {
    /// Flag passed automatically by `cargo bench`.
    #[arg(long = "bench", hide = true)]
    _bench: bool,

    /// Number of account creation requests to submit.
    #[arg(long, default_value = "1000")]
    requests: NonZeroUsize,

    /// Maximum number of concurrent HTTP submissions.
    #[arg(long, default_value = "100")]
    concurrency: NonZeroUsize,
}

fn progress_bar(progress: &MultiProgress, length: usize, message: &'static str) -> ProgressBar {
    let bar = progress.add(ProgressBar::new(length as u64));
    bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} {msg} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}",
        )
        .expect("invalid progress bar template")
        .progress_chars("=>-"),
    );
    bar.set_message(message);
    bar
}

async fn submit_and_finalize_accounts(
    gateway: &TestGateway,
    requests: usize,
    concurrency: usize,
    progress: &MultiProgress,
) -> Vec<TxHash> {
    let submissions = progress_bar(progress, requests, "Submitting");
    let request_ids = stream::iter(0..requests)
        .map(|index| {
            let client = gateway.client.clone();
            let base_url = gateway.base_url.clone();
            let submissions = submissions.clone();
            let commitment = u64::try_from(index + 1).expect("account index exceeds u64");

            async move {
                let account = PrivateKeySigner::random().address();
                let request = CreateAccountRequest {
                    recovery_address: Some(account),
                    authenticator_addresses: vec![account],
                    authenticator_pubkeys: vec![U256::from(commitment)],
                    offchain_signer_commitment: U256::from(commitment),
                };

                let response = client
                    .post(format!("{base_url}/create-account"))
                    .json(&request)
                    .send()
                    .await
                    .expect("failed to submit create-account request")
                    .error_for_status()
                    .expect("gateway rejected create-account request");

                let accepted: GatewayStatusResponse = response
                    .json()
                    .await
                    .expect("invalid create-account response");
                submissions.inc(1);
                accepted.request_id
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;
    submissions.finish_with_message("Submitted");

    let finalizations = progress_bar(progress, requests, "Finalizing");
    let transaction_hashes = stream::iter(request_ids)
        .map(|request_id| {
            let client = gateway.client.clone();
            let base_url = gateway.base_url.clone();
            let finalizations = finalizations.clone();
            async move {
                let transaction_hash = wait_for_finalized(&client, &base_url, request_id)
                    .await
                    .parse::<TxHash>()
                    .expect("invalid finalized transaction hash");
                finalizations.inc(1);
                transaction_hash
            }
        })
        .buffer_unordered(requests)
        .collect()
        .await;
    finalizations.finish_with_message("Finalized");

    transaction_hashes
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = Args::parse();
    let progress = MultiProgress::new();

    let setup = progress.add(ProgressBar::new_spinner());
    setup.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .expect("invalid setup spinner template"),
    );
    setup.enable_steady_tick(std::time::Duration::from_millis(100));
    setup.set_message("Starting Anvil, Redis, and Gateway");

    // This starts local Anvil, a Redis testcontainer, and Gateway. The setup is
    // intentionally excluded from the measured workload.
    let gateway = spawn_test_gateway_with_large_wallet_pool(Some(BATCH_REEVALUATION_MS)).await;
    let provider = ProviderBuilder::new()
        .connect_http(gateway.rpc_url.parse().expect("invalid Anvil endpoint URL"));
    setup.finish_with_message("Anvil, Redis, and Gateway ready");

    let started_at = Instant::now();
    let transaction_hashes = submit_and_finalize_accounts(
        &gateway,
        args.requests.get(),
        args.concurrency.get(),
        &progress,
    )
    .await;
    let elapsed = started_at.elapsed();
    let finalized_requests = transaction_hashes.len();

    let transaction_hashes = transaction_hashes.into_iter().collect::<HashSet<_>>();
    let receipt_checks = progress_bar(&progress, transaction_hashes.len(), "Checking receipts");
    let mut senders = HashSet::new();
    let mut successful_batches = 0;
    let mut failed_batches = 0;
    for transaction_hash in &transaction_hashes {
        let receipt = provider
            .get_transaction_receipt(*transaction_hash)
            .await
            .expect("failed to fetch transaction receipt")
            .expect("finalized transaction receipt is missing");
        if receipt.status() {
            successful_batches += 1;
        } else {
            failed_batches += 1;
        }
        senders.insert(receipt.from);
        receipt_checks.inc(1);
    }
    receipt_checks.finish_with_message("Receipts checked");

    let elapsed_seconds = elapsed.as_secs_f64();
    let requests_per_second = finalized_requests as f64 / elapsed_seconds;
    let batches_per_second = transaction_hashes.len() as f64 / elapsed_seconds;
    let average_batch_size = if transaction_hashes.is_empty() {
        0.0
    } else {
        finalized_requests as f64 / transaction_hashes.len() as f64
    };

    println!("requested={}", args.requests);
    println!("finalized_requests={finalized_requests}");
    println!("successful_batches={successful_batches}");
    println!("failed_batches={failed_batches}");
    println!("wallets_used={}", senders.len());
    println!("elapsed_seconds={elapsed_seconds:.3}");
    println!("requests_per_second={requests_per_second:.2}");
    println!("batches_per_second={batches_per_second:.2}");
    println!("average_batch_size={average_batch_size:.2}");
}
