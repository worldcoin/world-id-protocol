//! E2E tests for recovery-agent-update gateway routes.
//!
//! Exercises `initiate-recovery-agent-update`, `cancel-recovery-agent-update`,
//! and `execute-recovery-agent-update` against both a V1 registry and a
//! V2-upgraded one (which translates legacy URLs into WIP-102 selectors), plus
//! the new V2-native `update-recovery-agent` / `revert-recovery-agent-update`
//! URLs. Helpers are shared across V1 and V2 tests since the V2 contract
//! preserves the V1 ABI shape for `getPendingRecoveryAgentUpdate`.
//!
//! TODO(WIP-102): once all clients have migrated to the V2 URLs, delete the V1
//! legacy handlers and the corresponding tests in this file
//! (`e2e_initiate_and_cancel_recovery_agent_update`,
//! `e2e_initiate_and_execute_recovery_agent_update`,
//! `e2e_initiate_and_cancel_recovery_agent_update_v2`,
//! `e2e_initiate_then_window_elapse_and_execute_noop_v2`). Only the V2-native
//! `e2e_update_and_revert_via_v2_urls` test needs to survive.

use std::{future::Future, time::Duration};

use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use reqwest::StatusCode;
use world_id_core::{
    api_types::{
        CancelRecoveryAgentUpdateRequest, ExecuteRecoveryAgentUpdateRequest, GatewayRequestState,
        GatewayStatusResponse, UpdateRecoveryAgentRequest,
    },
    world_id_registry::{
        WorldIdRegistry, domain as ag_domain, sign_cancel_recovery_agent_update,
        sign_initiate_recovery_agent_update,
    },
};

use crate::common::{TestGateway, spawn_test_gateway, spawn_test_gateway_v2, wait_for_finalized};

mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const POLL_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

async fn wait_for_condition<F, Fut>(timeout_message: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + POLL_TIMEOUT;
    loop {
        if condition().await {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("{timeout_message}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_account_mapping<F, Fut>(mut get_packed_account_data: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = U256>,
{
    wait_for_condition("timeout waiting for create-account mapping", move || {
        let packed_account_data = get_packed_account_data();
        async move { packed_account_data.await != U256::ZERO }
    })
    .await;
}

async fn wait_for_pending_recovery_agent_update<F, Fut>(
    mut get_pending_recovery_agent_update: F,
    expected_recovery_agent: Address,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = (Address, U256)>,
{
    wait_for_condition(
        "timeout waiting for pending recovery agent update on-chain",
        move || {
            let pending_recovery_agent_update = get_pending_recovery_agent_update();
            async move {
                let (pending_recovery_agent, execute_after) = pending_recovery_agent_update.await;
                if pending_recovery_agent == expected_recovery_agent {
                    assert!(
                        execute_after > U256::ZERO,
                        "executeAfter timestamp should be set on-chain"
                    );
                    true
                } else {
                    false
                }
            }
        },
    )
    .await;
}

async fn wait_for_pending_recovery_agent_update_to_clear<F, Fut>(
    mut get_pending_recovery_agent_update: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = (Address, U256)>,
{
    wait_for_condition(
        "timeout waiting for pending recovery agent update to clear",
        move || {
            let pending_recovery_agent_update = get_pending_recovery_agent_update();
            async move {
                let (pending_recovery_agent, execute_after) = pending_recovery_agent_update.await;
                pending_recovery_agent == Address::ZERO && execute_after == U256::ZERO
            }
        },
    )
    .await;
}

async fn wait_for_recovery_agent_update<F, Fut>(
    mut get_recovery_agent: F,
    expected_recovery_agent: Address,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = Address>,
{
    let deadline = std::time::Instant::now() + POLL_TIMEOUT;
    loop {
        let recovery_agent = get_recovery_agent().await;
        if recovery_agent == expected_recovery_agent {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "timeout waiting for recovery agent to update on-chain. current={recovery_agent}, expected={expected_recovery_agent}"
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Create an account via the gateway and wait until it is finalized on-chain.
/// Returns the signer and its on-chain address.
async fn create_account(gw: &TestGateway) -> (PrivateKeySigner, Address) {
    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    let body_create = serde_json::json!({
        "recovery_address": wallet_addr.to_string(),
        "authenticator_addresses": [wallet_addr.to_string()],
        "authenticator_pubkeys": ["0x64"],
        "offchain_signer_commitment": "0x1",
    });
    let resp = gw
        .client
        .post(format!("{}/create-account", gw.base_url))
        .json(&body_create)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!("create-account failed: status={status_code}, body={body}");
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let _tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &accepted.request_id).await;

    // Wait until the mapping shows up on-chain.
    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider);
    wait_for_account_mapping(|| async {
        contract
            .getPackedAccountData(wallet_addr)
            .call()
            .await
            .unwrap()
    })
    .await;

    (signer, wallet_addr)
}

/// Advance anvil's clock past the V1 cooldown / V2 revert window so the
/// pending update either becomes executable (V1) or self-activates (V2).
async fn advance_past_revert_window<P: Provider>(provider: &P, contract_addr: Address) {
    // V2 reuses the existing `_recoveryAgentUpdateCooldown` storage as the
    // revert-window length, so the V1 ABI's `getRecoveryAgentUpdateCooldown`
    // returns the right value for both.
    let contract = WorldIdRegistry::new(contract_addr, provider);
    let cooldown = contract
        .getRecoveryAgentUpdateCooldown()
        .call()
        .await
        .unwrap();
    let jump_secs: u64 = cooldown.to::<u64>() + 60;
    let _: u64 = provider
        .client()
        .request("evm_increaseTime", (jump_secs,))
        .await
        .expect("evm_increaseTime failed");
    let _: serde_json::Value = provider
        .client()
        .request("evm_mine", ())
        .await
        .expect("evm_mine failed");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// End-to-end: initiate a recovery agent update, verify on-chain pending state,
/// then cancel it and verify the pending state is cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_initiate_and_cancel_recovery_agent_update() {
    let gw = spawn_test_gateway(None).await;
    let (signer, _wallet_addr) = create_account(&gw).await;

    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider.clone());
    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);

    let leaf_index: u64 = 1; // first account
    let nonce = U256::from(0);
    let new_recovery_agent: Address = "0x000000000000000000000000000000000000beef"
        .parse()
        .unwrap();

    // ── 1. Initiate recovery-agent update ─────────────────────────────
    let sig_init = sign_initiate_recovery_agent_update(
        &signer,
        leaf_index,
        new_recovery_agent,
        nonce,
        &domain,
    )
    .unwrap();

    let body_init = UpdateRecoveryAgentRequest {
        leaf_index,
        new_recovery_agent,
        signature: sig_init,
        nonce,
    };

    let resp = gw
        .client
        .post(format!("{}/initiate-recovery-agent-update", gw.base_url))
        .json(&body_init)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!("initiate-recovery-agent-update failed: status={status_code}, body={body}");
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let init_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &init_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "initiate-recovery-agent-update should return a finalized tx hash"
    );

    // Verify on-chain: pending update exists with correct new recovery agent.
    wait_for_pending_recovery_agent_update(
        || async {
            let pending = contract
                .getPendingRecoveryAgentUpdate(leaf_index)
                .call()
                .await
                .unwrap();
            (pending.newRecoveryAgent, pending.executeAfter)
        },
        new_recovery_agent,
    )
    .await;

    // ── 2. Cancel the pending recovery-agent update ───────────────────
    let nonce = nonce + U256::from(1);
    let sig_cancel =
        sign_cancel_recovery_agent_update(&signer, leaf_index, nonce, &domain).unwrap();

    let body_cancel = CancelRecoveryAgentUpdateRequest {
        leaf_index,
        signature: sig_cancel,
        nonce,
    };

    let resp = gw
        .client
        .post(format!("{}/cancel-recovery-agent-update", gw.base_url))
        .json(&body_cancel)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!("cancel-recovery-agent-update failed: status={status_code}, body={body}");
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let cancel_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &cancel_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "cancel-recovery-agent-update should return a finalized tx hash"
    );

    // Verify on-chain: pending update is cleared (address zero, executeAfter zero).
    wait_for_pending_recovery_agent_update_to_clear(|| async {
        let pending = contract
            .getPendingRecoveryAgentUpdate(leaf_index)
            .call()
            .await
            .unwrap();
        (pending.newRecoveryAgent, pending.executeAfter)
    })
    .await;
}

/// End-to-end: initiate → fast-forward time → execute recovery agent update,
/// then verify the on-chain recovery agent has actually changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_initiate_and_execute_recovery_agent_update() {
    let gw = spawn_test_gateway(None).await;
    let (signer, wallet_addr) = create_account(&gw).await;

    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider.clone());
    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);

    let leaf_index: u64 = 1;
    let nonce = U256::from(0);
    let new_recovery_agent: Address = "0x000000000000000000000000000000000000cafe"
        .parse()
        .unwrap();

    // Confirm the current recovery agent is the wallet address.
    let current_agent = contract.getRecoveryAgent(leaf_index).call().await.unwrap();
    assert_eq!(
        current_agent, wallet_addr,
        "recovery agent should be the creator wallet"
    );

    // ── 1. Initiate ───────────────────────────────────────────────────
    let sig_init = sign_initiate_recovery_agent_update(
        &signer,
        leaf_index,
        new_recovery_agent,
        nonce,
        &domain,
    )
    .unwrap();

    let body_init = UpdateRecoveryAgentRequest {
        leaf_index,
        new_recovery_agent,
        signature: sig_init,
        nonce,
    };

    let resp = gw
        .client
        .post(format!("{}/initiate-recovery-agent-update", gw.base_url))
        .json(&body_init)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!("initiate-recovery-agent-update failed: status={status_code}, body={body}");
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let _tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &accepted.request_id).await;

    // Wait until pending update is on-chain.
    wait_for_pending_recovery_agent_update(
        || async {
            let pending = contract
                .getPendingRecoveryAgentUpdate(leaf_index)
                .call()
                .await
                .unwrap();
            (pending.newRecoveryAgent, pending.executeAfter)
        },
        new_recovery_agent,
    )
    .await;

    // ── 2. Fast-forward anvil past the 14-day cooldown ────────────────
    advance_past_revert_window(&provider, gw.registry_addr).await;

    // ── 3. Execute the pending update ─────────────────────────────────
    let body_exec = ExecuteRecoveryAgentUpdateRequest { leaf_index };

    let resp = gw
        .client
        .post(format!("{}/execute-recovery-agent-update", gw.base_url))
        .json(&body_exec)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        let body = resp.text().await.unwrap_or_default();
        panic!("execute-recovery-agent-update failed: status={status_code}, body={body}");
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let _tx_hash = wait_for_finalized(&gw.client, &gw.base_url, &accepted.request_id).await;

    // Verify on-chain: recovery agent has been updated.
    wait_for_recovery_agent_update(
        || async { contract.getRecoveryAgent(leaf_index).call().await.unwrap() },
        new_recovery_agent,
    )
    .await;

    // Also verify pending update is cleared.
    let pending = contract
        .getPendingRecoveryAgentUpdate(leaf_index)
        .call()
        .await
        .unwrap();
    assert_eq!(
        pending.newRecoveryAgent,
        Address::ZERO,
        "pending update should be cleared after execution"
    );
}

// ---------------------------------------------------------------------------
// V2 (WIP-102) tests — gateway against a V2-upgraded registry
// ---------------------------------------------------------------------------

/// Backwards-compat scenario: client calls the legacy `/initiate-` and
/// `/cancel-` URLs against a V2 registry, signing with the V1 typehash. The
/// gateway translates each to the V2 selector internally and the contract
/// accepts the V1-typehash signatures (typehash reuse).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_initiate_and_cancel_recovery_agent_update_v2() {
    let gw = spawn_test_gateway_v2(None).await;
    let (signer, wallet_addr) = create_account(&gw).await;

    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider.clone());
    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);

    let leaf_index: u64 = 1;
    let nonce = U256::from(0);
    let new_recovery_agent: Address = "0x000000000000000000000000000000000000beef"
        .parse()
        .unwrap();

    // 1. Legacy URL → V2 `updateRecoveryAgent`.
    let sig_init = sign_initiate_recovery_agent_update(
        &signer,
        leaf_index,
        new_recovery_agent,
        nonce,
        &domain,
    )
    .unwrap();
    let body_init = UpdateRecoveryAgentRequest {
        leaf_index,
        new_recovery_agent,
        signature: sig_init,
        nonce,
    };
    let resp = gw
        .client
        .post(format!("{}/initiate-recovery-agent-update", gw.base_url))
        .json(&body_init)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "initiate failed: {:?}", resp);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let _ = wait_for_finalized(&gw.client, &gw.base_url, &accepted.request_id).await;

    // V2-translated `getPendingRecoveryAgentUpdate` returns the scheduled new
    // agent and the `invalidAfter` timestamp.
    wait_for_pending_recovery_agent_update(
        || async {
            let pending = contract
                .getPendingRecoveryAgentUpdate(leaf_index)
                .call()
                .await
                .unwrap();
            (pending.newRecoveryAgent, pending.executeAfter)
        },
        new_recovery_agent,
    )
    .await;

    // Inside the revert window the *effective* recovery agent is still the
    // original one — that's the WIP-102 security property.
    let effective = contract.getRecoveryAgent(leaf_index).call().await.unwrap();
    assert_eq!(
        effective, wallet_addr,
        "during revert window, effective agent should remain the original signer"
    );

    // 2. Legacy URL → V2 `revertRecoveryAgentUpdate`.
    let nonce = nonce + U256::from(1);
    let sig_cancel =
        sign_cancel_recovery_agent_update(&signer, leaf_index, nonce, &domain).unwrap();
    let body_cancel = CancelRecoveryAgentUpdateRequest {
        leaf_index,
        signature: sig_cancel,
        nonce,
    };
    let resp = gw
        .client
        .post(format!("{}/cancel-recovery-agent-update", gw.base_url))
        .json(&body_cancel)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "cancel failed: {:?}", resp);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let _ = wait_for_finalized(&gw.client, &gw.base_url, &accepted.request_id).await;

    // Pending mapping cleared, original agent still effective.
    wait_for_pending_recovery_agent_update_to_clear(|| async {
        let pending = contract
            .getPendingRecoveryAgentUpdate(leaf_index)
            .call()
            .await
            .unwrap();
        (pending.newRecoveryAgent, pending.executeAfter)
    })
    .await;
    let effective = contract.getRecoveryAgent(leaf_index).call().await.unwrap();
    assert_eq!(effective, wallet_addr, "agent should be the original");
}

/// WIP-102 mechanics: after `/initiate-` lands on V2, fast-forward past the
/// revert window. The new agent becomes effective with no `/execute-` call
/// required. Then call `/execute-recovery-agent-update` and verify it's a
/// synthetic no-op (200 OK, status `Queued`, no on-chain side effect).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_initiate_then_window_elapse_and_execute_noop_v2() {
    let gw = spawn_test_gateway_v2(None).await;
    let (signer, wallet_addr) = create_account(&gw).await;

    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider.clone());
    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);

    let leaf_index: u64 = 1;
    let nonce = U256::from(0);
    let new_recovery_agent: Address = "0x000000000000000000000000000000000000cafe"
        .parse()
        .unwrap();

    let pre = contract.getRecoveryAgent(leaf_index).call().await.unwrap();
    assert_eq!(pre, wallet_addr);

    // Legacy URL initiates the V2 update.
    let sig_init = sign_initiate_recovery_agent_update(
        &signer,
        leaf_index,
        new_recovery_agent,
        nonce,
        &domain,
    )
    .unwrap();
    let body_init = UpdateRecoveryAgentRequest {
        leaf_index,
        new_recovery_agent,
        signature: sig_init,
        nonce,
    };
    let resp = gw
        .client
        .post(format!("{}/initiate-recovery-agent-update", gw.base_url))
        .json(&body_init)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let _ = wait_for_finalized(&gw.client, &gw.base_url, &accepted.request_id).await;

    wait_for_pending_recovery_agent_update(
        || async {
            let pending = contract
                .getPendingRecoveryAgentUpdate(leaf_index)
                .call()
                .await
                .unwrap();
            (pending.newRecoveryAgent, pending.executeAfter)
        },
        new_recovery_agent,
    )
    .await;

    // Fast-forward anvil past the revert window.
    advance_past_revert_window(&provider, gw.registry_addr).await;

    // No execute call yet — the new agent should already be effective on its own.
    wait_for_recovery_agent_update(
        || async { contract.getRecoveryAgent(leaf_index).call().await.unwrap() },
        new_recovery_agent,
    )
    .await;

    // The translated `getPendingRecoveryAgentUpdate` view returns (0, 0) once
    // the window has elapsed, since V2 considers the update no longer "pending".
    let pending = contract
        .getPendingRecoveryAgentUpdate(leaf_index)
        .call()
        .await
        .unwrap();
    assert_eq!(pending.newRecoveryAgent, Address::ZERO);
    assert_eq!(pending.executeAfter, U256::ZERO);

    // Now call `/execute-recovery-agent-update`. On V2 this is a synthetic
    // no-op: the gateway returns 200 with state Queued without touching chain.
    let body_exec = ExecuteRecoveryAgentUpdateRequest { leaf_index };
    let resp = gw
        .client
        .post(format!("{}/execute-recovery-agent-update", gw.base_url))
        .json(&body_exec)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: GatewayStatusResponse = resp.json().await.unwrap();
    assert!(
        matches!(body.status, GatewayRequestState::Queued),
        "execute should return synthetic Queued, got {:?}",
        body.status
    );

    // On-chain state hasn't moved (no extra tx).
    let still_effective = contract.getRecoveryAgent(leaf_index).call().await.unwrap();
    assert_eq!(still_effective, new_recovery_agent);
}

/// New WIP-102 URLs: `/update-recovery-agent` and `/revert-recovery-agent-update`
/// work directly against V2 with the (V1-compatible) signing helpers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_update_and_revert_via_v2_urls() {
    let gw = spawn_test_gateway_v2(None).await;
    let (signer, wallet_addr) = create_account(&gw).await;

    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider.clone());
    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);

    let leaf_index: u64 = 1;
    let nonce = U256::from(0);
    let new_recovery_agent: Address = "0x00000000000000000000000000000000000000aa"
        .parse()
        .unwrap();

    // POST /update-recovery-agent
    let sig_update = sign_initiate_recovery_agent_update(
        &signer,
        leaf_index,
        new_recovery_agent,
        nonce,
        &domain,
    )
    .unwrap();
    let body_update = UpdateRecoveryAgentRequest {
        leaf_index,
        new_recovery_agent,
        signature: sig_update,
        nonce,
    };
    let resp = gw
        .client
        .post(format!("{}/update-recovery-agent", gw.base_url))
        .json(&body_update)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "update failed: {:?}", resp);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let _ = wait_for_finalized(&gw.client, &gw.base_url, &accepted.request_id).await;

    wait_for_pending_recovery_agent_update(
        || async {
            let pending = contract
                .getPendingRecoveryAgentUpdate(leaf_index)
                .call()
                .await
                .unwrap();
            (pending.newRecoveryAgent, pending.executeAfter)
        },
        new_recovery_agent,
    )
    .await;
    let effective = contract.getRecoveryAgent(leaf_index).call().await.unwrap();
    assert_eq!(
        effective, wallet_addr,
        "prev agent still effective in window"
    );

    // POST /revert-recovery-agent-update
    let nonce = nonce + U256::from(1);
    let sig_revert =
        sign_cancel_recovery_agent_update(&signer, leaf_index, nonce, &domain).unwrap();
    let body_revert = CancelRecoveryAgentUpdateRequest {
        leaf_index,
        signature: sig_revert,
        nonce,
    };
    let resp = gw
        .client
        .post(format!("{}/revert-recovery-agent-update", gw.base_url))
        .json(&body_revert)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "revert failed: {:?}", resp);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let _ = wait_for_finalized(&gw.client, &gw.base_url, &accepted.request_id).await;

    wait_for_pending_recovery_agent_update_to_clear(|| async {
        let pending = contract
            .getPendingRecoveryAgentUpdate(leaf_index)
            .call()
            .await
            .unwrap();
        (pending.newRecoveryAgent, pending.executeAfter)
    })
    .await;
    let effective = contract.getRecoveryAgent(leaf_index).call().await.unwrap();
    assert_eq!(
        effective, wallet_addr,
        "after revert the original agent is restored"
    );
}
