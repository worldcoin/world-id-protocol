use std::time::Duration;

use alloy::primitives::{address, Address, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use reqwest::{Client, StatusCode};
use test_utils::anvil::TestAnvil;
use world_id_core::account_registry::{
    domain as ag_domain, sign_insert_authenticator, sign_recover_account,
    sign_remove_authenticator, sign_update_authenticator, AccountRegistry,
};
use world_id_core::types::{
    GatewayStatusResponse, InsertAuthenticatorRequest, RecoverAccountRequest,
    RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
};
use world_id_gateway::{spawn_gateway_for_tests, GatewayConfig};

use crate::common::{wait_for_finalized, wait_http_ready};

mod common;

const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const GW_PORT: u16 = 4101;
const RPC_FORK_URL: &str = "https://reth-ethereum.ithaca.xyz/rpc";

fn default_sibling_nodes() -> Vec<String> {
    vec![
        "0x0",
        "0x228981b886e5effb2c05a6be7ab4a05fde6bf702a2d039e46c87057dd729ef97",
        "0x218fbf2e2f12f0475d3dcf2e0ab1bd4b9ab528e954738c18c4b7c9b5f4b84964",
        "0x2e16a8d602271ea50b5a1bd35b854610ef0bddf8f385bdeb0bb31c4562fa0cd6",
        "0x2b44a101801fa0b810feb3d82c25e71b88bc6f4aeecd9fcdc2152b1f3c38d044",
        "0x19f2fcaf65567ab8803e4fb84e67854815d83a4e1b7be24c6814ba2ba9bdc5ca",
        "0x1a3bd772e2782ad018b9c451bf66c3b0ad223a0e68347fae11c78681bf6478df",
        "0x34d4539eb24682272ab024133ca575c1cade051f9fdce5948b6b806767e225b",
        "0x2971eb2b9cd60a1270db7ab8aada485f64fae5a5e85bed736c67329c410fffee",
        "0x2ef220cf75c94a6bc8f4900fe8153ce53132c2de05163d55ecd0fd13519104b4",
        "0x2075381e03f1e1f60029fc3079d49b918c967b58e2655b1770c86ca3984ab65c",
        "0x1d4789eb40dffb09091a0690d88df7ff993c23d172e866a93631f6792909118c",
        "0x2b082d0afac14544d746c924d6fc882f6931b7b6aacd796c82d7fe81ce33ce4c",
        "0x175c16bc97822dba5fdf5580638d4983831dab655f5095bde23b6685f61981cd",
        "0xc4b05c87053bf236ef505872eac4304546d3c4f989b1d19b93ef9115e883f66",
        "0x2d7e044c16807771000769efac4e9147a90359c5f58da39880697de3afdd6d56",
        "0x18b029a33a590d748323e8d6cb8ac7636cdff4a154ddb7e19ac9cb6845adff69",
        "0x1e45bd2b39d74ef50d211fc7303d55a06478517cd44887308ba40cb6d4d44216",
        "0x189b2c3495c37308649a0c3e9fe3dd06e83612e9cb1528833acf358bc9b43271",
        "0xec11644818dab9d62fdacacda9fdc5d2fb6f4627a332e3b25bbbc7dfb0672e7",
        "0x119827e780a1850d7b7e34646edc1ce918211c26dda4e13bcd1611f6f81c3680",
        "0x84449b11bad2bd26ab39b799cccb9408c4f3bcdbef4210f5cd6544d821c85c6",
        "0x2f313f5eaf87dd5e81f34e8ef6b98c2928272ba35b80821267b95176775a5dd",
        "0x2d01ab8332efd3bcd5d4fe99cdb66d809fbf6a1a84c931942ea40fb5cf4ebdaa",
        "0x2adfa5bb110a920158ca367f5cfa6f632aeb78a9a7b1f2d9c0d29f2a197c244b",
        "0x1045e59b73045e7bb07ad0bd51e8b5ec08c2b71abc64eaec485ad91a2a528ea8",
        "0x1549ebd6196d7d303bf4791a3b33c08809f19e5ebf9a5ef5ba438d3ec4d9a324",
        "0x305e08a953165f5d8e4560d619ca03d05c06e7514dfb7f7a2a25dfaf558907dc",
        "0xfb5add1601d2850978d2c5b2de15426a50b7c766c5939843637f759a34ab617",
        "0x232052690c527bf35f76a2fd8db54c96f1dd28d009e19c6d00af6d389188fac5",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_gateway_full_flow() {
    let anvil = TestAnvil::spawn_fork(RPC_FORK_URL).expect("failed to spawn forked anvil");
    let deployer = anvil.signer(0).expect("failed to fetch deployer signer");
    let registry_addr = anvil
        .deploy_account_registry(deployer)
        .await
        .expect("failed to deploy AccountRegistry");
    let rpc_url = anvil.endpoint().to_string();

    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    let cfg = GatewayConfig {
        registry_addr,
        rpc_url: rpc_url.clone(),
        wallet_private_key: Some(GW_PRIVATE_KEY.to_string()),
        aws_kms_key_id: None,
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, GW_PORT).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: None, // Use in-memory storage for tests
    };
    let gw = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");

    // HTTP client
    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, GW_PORT).await;
    let base = format!("http://127.0.0.1:{GW_PORT}");

    // Build Alloy provider for on-chain assertions and chain id
    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = AccountRegistry::new(registry_addr, provider.clone());

    // First, create the initial account through the API so tree depth stays 0 for following ops
    let body_create = serde_json::json!({
        "recovery_address": wallet_addr.to_string(),
        "authenticator_addresses": [wallet_addr.to_string()],
        "authenticator_pubkeys": ["0x64"],
        "offchain_signer_commitment": "0x1",
    });
    let resp = client
        .post(format!("{}/create-account", base))
        .json(&body_create)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::ACCEPTED {
        let body = resp.text().await.unwrap_or_default();
        panic!("create-account failed: status={status_code}, body={body}",);
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let create_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&client, GW_PORT, &create_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "create-account should return a finalized tx hash"
    );

    // Wait until createManyAccounts is reflected on-chain
    let deadline_ca = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let packed_after = contract
            .authenticatorAddressToPackedAccountData(wallet_addr)
            .call()
            .await
            .unwrap();
        if packed_after != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline_ca {
            panic!("timeout waiting for createManyAccounts mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Sanity: build provider and contract for on-chain assertions
    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = AccountRegistry::new(registry_addr, provider.clone());
    // The wallet address must be registered as authenticator for account 1
    let packed = contract
        .authenticatorAddressToPackedAccountData(wallet_addr)
        .call()
        .await
        .unwrap();
    assert!(
        packed != U256::ZERO,
        "creator wallet not registered as authenticator"
    );

    let chain_id = provider.get_chain_id().await.unwrap();

    // EIP-712 domain via common helpers
    let domain = ag_domain(chain_id, registry_addr);

    // Nonce tracker
    let mut nonce = U256::from(0);

    // insert-authenticator
    let new_auth2: Address = address!("0x00000000000000000000000000000000000000a2");
    let sig_ins = sign_insert_authenticator(
        &signer,
        U256::from(1),
        new_auth2,
        1,
        U256::from(200),
        U256::from(2),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let body_ins = InsertAuthenticatorRequest {
        leaf_index: U256::from(1),
        new_authenticator_address: new_auth2,
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(2),
        sibling_nodes: default_sibling_nodes()
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        signature: sig_ins.as_bytes().to_vec(),
        nonce,
        pubkey_id: 1,
        new_authenticator_pubkey: U256::from(200),
    };
    // Issue request to gateway
    let resp = client
        .post(format!("{}/insert-authenticator", base))
        .json(&body_ins)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::ACCEPTED {
        let body = resp.text().await.unwrap_or_default();
        panic!(
            "insert-authenticator failed: status={}, body={}",
            status_code, body
        );
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let insert_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&client, GW_PORT, &insert_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "insert-authenticator should return a finalized tx hash"
    );
    // wait until mapping shows up
    let deadline2 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v = contract
            .authenticatorAddressToPackedAccountData(new_auth2)
            .call()
            .await
            .unwrap();
        if v != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline2 {
            panic!("timeout waiting for insert-authenticator mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // increment nonce
    nonce += U256::from(1);

    // remove-authenticator (remove the one we inserted)
    let sig_rem = sign_remove_authenticator(
        &signer,
        U256::from(1),
        new_auth2,
        1,
        U256::from(200),
        U256::from(3),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let body_rem = RemoveAuthenticatorRequest {
        leaf_index: U256::from(1),
        authenticator_address: new_auth2,
        old_offchain_signer_commitment: U256::from(2),
        new_offchain_signer_commitment: U256::from(3),
        sibling_nodes: default_sibling_nodes()
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        signature: sig_rem.as_bytes().to_vec(),
        nonce,
        pubkey_id: Some(1),
        authenticator_pubkey: Some(U256::from(200)),
    };
    let resp = client
        .post(format!("{base}/remove-authenticator"))
        .json(&body_rem)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::ACCEPTED {
        let body = resp.text().await.unwrap_or_default();
        panic!("remove-authenticator failed: status={status_code}, body={body}",);
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let remove_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&client, GW_PORT, &remove_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "remove-authenticator should return a finalized tx hash"
    );
    // wait until mapping cleared
    let deadline3 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v = contract
            .authenticatorAddressToPackedAccountData(new_auth2)
            .call()
            .await
            .unwrap();
        if v == U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline3 {
            panic!("timeout waiting for remove-authenticator mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    nonce += U256::from(1);

    let signer_new = PrivateKeySigner::random();
    let wallet_addr_new: Address = signer_new.address();

    // recover-account (signed by recovery address == wallet)
    let sig_rec = sign_recover_account(
        &signer,
        U256::from(1),
        wallet_addr_new,
        U256::from(300),
        U256::from(4),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let body_rec = RecoverAccountRequest {
        leaf_index: U256::from(1),
        new_authenticator_address: wallet_addr_new,
        old_offchain_signer_commitment: U256::from(3),
        new_offchain_signer_commitment: U256::from(4),
        sibling_nodes: default_sibling_nodes()
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        signature: sig_rec.as_bytes().to_vec(),
        nonce,
        new_authenticator_pubkey: Some(U256::from(300)),
    };
    let resp = client
        .post(format!("{}/recover-account", base))
        .json(&body_rec)
        .send()
        .await
        .unwrap();

    let status_code = resp.status();
    if status_code != StatusCode::ACCEPTED {
        let body = resp.text().await.unwrap_or_default();
        panic!(
            "recover-account failed: status={}, body={}",
            status_code, body
        );
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let recover_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&client, GW_PORT, &recover_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "recover-account should return a finalized tx hash"
    );
    // wait mapping
    let deadline4 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v = contract
            .authenticatorAddressToPackedAccountData(wallet_addr_new)
            .call()
            .await
            .unwrap();
        if v != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline4 {
            panic!("timeout waiting for recover-account mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    nonce += U256::from(1);

    // update-authenticator: replace original wallet authenticator with new one
    let new_auth4: Address = address!("0x00000000000000000000000000000000000000a4");
    let sig_upd = sign_update_authenticator(
        &signer_new,
        U256::from(1),
        wallet_addr_new,
        new_auth4,
        0,
        U256::from(400),
        U256::from(5),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let body_upd = UpdateAuthenticatorRequest {
        leaf_index: U256::from(1),
        old_authenticator_address: wallet_addr_new,
        new_authenticator_address: new_auth4,
        old_offchain_signer_commitment: U256::from(4),
        new_offchain_signer_commitment: U256::from(5),
        sibling_nodes: default_sibling_nodes()
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        signature: sig_upd.as_bytes().to_vec(),
        nonce,
        pubkey_id: Some(0),
        new_authenticator_pubkey: Some(U256::from(400)),
    };
    let resp = client
        .post(format!("{}/update-authenticator", base))
        .json(&body_upd)
        .send()
        .await
        .unwrap();
    let status_code = resp.status();
    if status_code != StatusCode::ACCEPTED {
        let body = resp.text().await.unwrap_or_default();
        panic!(
            "update-authenticator failed: status={}, body={}",
            status_code, body
        );
    }
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let update_request_id = accepted.request_id.clone();
    let tx_hash = wait_for_finalized(&client, GW_PORT, &update_request_id).await;
    assert!(
        !tx_hash.is_empty(),
        "update-authenticator should return a finalized tx hash"
    );
    // wait mapping: old removed, new present
    let deadline5 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let old_v = contract
            .authenticatorAddressToPackedAccountData(wallet_addr_new)
            .call()
            .await
            .unwrap();
        let new_v = contract
            .authenticatorAddressToPackedAccountData(new_auth4)
            .call()
            .await
            .unwrap();
        if old_v == U256::ZERO && new_v != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline5 {
            panic!("timeout waiting for update-authenticator mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Cleanup
    let _ = gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_authenticator_already_exists_error_code() {
    let anvil = TestAnvil::spawn_fork(RPC_FORK_URL).expect("failed to spawn forked anvil");
    let deployer = anvil.signer(0).expect("failed to fetch deployer signer");
    let registry_addr = anvil
        .deploy_account_registry(deployer)
        .await
        .expect("failed to deploy AccountRegistry");
    let rpc_url = anvil.endpoint().to_string();

    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    let cfg = GatewayConfig {
        registry_addr,
        rpc_url: rpc_url.clone(),
        wallet_private_key: Some(GW_PRIVATE_KEY.to_string()),
        aws_kms_key_id: None,
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 4102).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: None,
    };
    let gw = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");

    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, 4102).await;
    let base = format!("http://127.0.0.1:4102");

    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = AccountRegistry::new(registry_addr, provider.clone());

    // Create account with wallet_addr as authenticator
    let body_create = serde_json::json!({
        "recovery_address": wallet_addr.to_string(),
        "authenticator_addresses": [wallet_addr.to_string()],
        "authenticator_pubkeys": ["100"],
        "offchain_signer_commitment": "1",
    });

    let resp = client
        .post(format!("{}/create-account", base))
        .json(&body_create)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let create_request_id = accepted.request_id.clone();
    let _tx_hash = wait_for_finalized(&client, 4102, &create_request_id).await;

    // Wait until createManyAccounts is reflected on-chain
    let deadline_ca = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let packed_after = contract
            .authenticatorAddressToPackedAccountData(wallet_addr)
            .call()
            .await
            .unwrap();
        if packed_after != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline_ca {
            panic!("timeout waiting for createManyAccounts mapping");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, registry_addr);

    // Try to insert the same authenticator again (wallet_addr is already an authenticator)
    let nonce = U256::from(0);
    let sig_ins = sign_insert_authenticator(
        &signer,
        U256::from(1),
        wallet_addr, // Same address that's already an authenticator for account 1
        0,
        U256::from(100),
        U256::from(2),
        nonce,
        &domain,
    )
    .await
    .unwrap();

    let body_ins = InsertAuthenticatorRequest {
        leaf_index: U256::from(1),
        new_authenticator_address: wallet_addr,
        old_offchain_signer_commitment: U256::from(1),
        new_offchain_signer_commitment: U256::from(2),
        sibling_nodes: default_sibling_nodes()
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        signature: sig_ins.as_bytes().to_vec(),
        nonce,
        pubkey_id: 0,
        new_authenticator_pubkey: U256::from(100),
    };

    let resp = client
        .post(format!("{}/insert-authenticator", base))
        .json(&body_ins)
        .send()
        .await
        .unwrap();

    // Simulation should fail synchronously and return 400 immediately
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let error_body: serde_json::Value = resp.json().await.unwrap();
    // Check either the message field or the code field for the error
    let error_msg = error_body
        .get("message")
        .and_then(|e| e.as_str())
        .or_else(|| error_body.get("code").and_then(|e| e.as_str()))
        .unwrap_or("");
    assert!(
        error_msg
            .to_lowercase()
            .replace('_', " ")
            .contains("authenticator already exists"),
        "Error should indicate 'authenticator already exists', got: {error_msg}"
    );

    let _ = gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_same_authenticator_different_accounts() {
    let anvil = TestAnvil::spawn_fork(RPC_FORK_URL).expect("failed to spawn forked anvil");
    let deployer = anvil.signer(0).expect("failed to fetch deployer signer");
    let registry_addr = anvil
        .deploy_account_registry(deployer)
        .await
        .expect("failed to deploy AccountRegistry");
    let rpc_url = anvil.endpoint().to_string();

    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    let cfg = GatewayConfig {
        registry_addr,
        rpc_url: rpc_url.clone(),
        wallet_private_key: Some(GW_PRIVATE_KEY.to_string()),
        aws_kms_key_id: None,
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 4103).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: None,
    };
    let gw = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");

    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, 4103).await;
    let base = format!("http://127.0.0.1:4103");

    // Create first account with wallet_addr as authenticator
    let body_create1 = serde_json::json!({
        "recovery_address": wallet_addr.to_string(),
        "authenticator_addresses": [wallet_addr.to_string()],
        "authenticator_pubkeys": ["100"],
        "offchain_signer_commitment": "1",
    });

    let resp = client
        .post(format!("{}/create-account", base))
        .json(&body_create1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    let request_id_1 = accepted.request_id.clone();
    let _tx_hash_1 = wait_for_finalized(&client, 4103, &request_id_1).await;

    // Try to create second account with the SAME wallet_addr as authenticator
    let body_create2 = serde_json::json!({
        "recovery_address": address!("0x0000000000000000000000000000000000000002").to_string(),
        "authenticator_addresses": [wallet_addr.to_string()], // Same authenticator!
        "authenticator_pubkeys": ["200"],
        "offchain_signer_commitment": "2",
    });

    let resp = client
        .post(format!("{}/create-account", base))
        .json(&body_create2)
        .send()
        .await
        .unwrap();

    // Simulation should fail synchronously and return 400 immediately
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let error_body: serde_json::Value = resp.json().await.unwrap();
    // Check either the message field or the code field for the error
    let error_msg = error_body
        .get("message")
        .and_then(|e| e.as_str())
        .or_else(|| error_body.get("code").and_then(|e| e.as_str()))
        .unwrap_or("");
    assert!(
        error_msg
            .to_lowercase()
            .replace('_', " ")
            .contains("authenticator already exists"),
        "Error should indicate 'authenticator already exists', got: {error_msg}"
    );

    let _ = gw.shutdown().await;
}
