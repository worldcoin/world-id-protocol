use std::process::{Command, Stdio};
use std::time::Duration;

use alloy::primitives::{address, Address, U256};
use alloy::signers::local::PrivateKeySigner;
use common::authenticator_registry::{
    domain as ag_domain, sign_insert_authenticator, sign_recover_account,
    sign_remove_authenticator, sign_update_authenticator, AuthenticatorRegistry,
};
use regex::Regex;
use reqwest::Client;
use registry_gateway::{spawn_gateway, GatewayConfig};

const ANVIL_PORT: u16 = 8551;
const ANVIL_HTTP_URL: &str = "http://127.0.0.1:8551";
const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";
const GW_PORT: u16 = 4101;

fn start_anvil() -> std::process::Child {
    let mut cmd = Command::new("anvil");
    cmd.arg("-p")
        .arg(ANVIL_PORT.to_string())
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--mnemonic")
        .arg(ANVIL_MNEMONIC)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    cmd.spawn().expect("failed to start anvil")
}

fn deploy_registry() -> String {
    let mut cmd = Command::new("forge");
    cmd.current_dir("../../contracts")
        .arg("script")
        .arg("script/AuthenticatorRegistry.s.sol:CounterScript")
        .arg("--fork-url")
        .arg(ANVIL_HTTP_URL)
        .arg("--broadcast")
        .arg("--mnemonics")
        .arg(ANVIL_MNEMONIC)
        .arg("--mnemonic-indexes")
        .arg("0")
        .arg("-vvvv");
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"AuthenticatorRegistry deployed to:\s*(0x[0-9a-fA-F]{40})").unwrap();
    let addr = re
        .captures(&stdout)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .expect("failed to parse deployed address from script output");
    addr
}

fn derive_wallet_key() -> String {
    let output = Command::new("cast")
        .arg("wallet")
        .arg("private-key")
        .arg("--mnemonic")
        .arg(ANVIL_MNEMONIC)
        .arg("--mnemonic-index")
        .arg("0")
        .output()
        .expect("cast wallet private-key failed");
    assert!(
        output.status.success(),
        "cast wallet private-key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

// gateway is now spawned in-process via library API

async fn wait_http_ready(client: &Client) {
    let base = format!("http://127.0.0.1:{}", GW_PORT);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(resp) = client.get(format!("{}/health", base)).send().await {
            if resp.status().is_success() {
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("gateway not ready");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_gateway_full_flow() {
    // Kill any existing anvil
    Command::new("pkill")
        .arg("anvil")
        .status()
        .expect("pkill anvil");

    // Start anvil
    let mut anvil = start_anvil();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Deploy registry
    let registry = deploy_registry();

    // Derive wallet key and address
    let wallet_key = derive_wallet_key();
    let signer: alloy::signers::local::PrivateKeySigner = wallet_key.parse().unwrap();
    let wallet_addr: Address = signer.address();

    // Start gateway (in-process via lib)
    let cfg = GatewayConfig {
        registry_addr: registry.parse().unwrap(),
        rpc_url: ANVIL_HTTP_URL.to_string(),
        wallet_key: wallet_key.clone(),
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, GW_PORT).into(),
    };
    let gw = spawn_gateway(cfg).await.expect("spawn gateway");

    // HTTP client
    let client = Client::builder().build().unwrap();
    wait_http_ready(&client).await;

    // Build Alloy provider for on-chain assertions and chain id
    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(ANVIL_HTTP_URL.parse().unwrap());
    let contract = AuthenticatorRegistry::new(registry.parse().unwrap(), provider.clone());

    // First, create the initial account directly on-chain so tree depth stays 0 for following ops
    let direct = contract
        .createManyAccounts(
            vec![wallet_addr],
            vec![vec![wallet_addr]],
            vec![U256::from(1)],
        )
        .send()
        .await
        .expect("direct createManyAccounts");
    println!("direct createManyAccounts tx: 0x{:x}", direct.tx_hash());
    // Wait until createManyAccounts is reflected on-chain
    let deadline_ca = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let packed_after = contract
            .authenticatorAddressToPackedAccountIndex(wallet_addr)
            .call()
            .await
            .unwrap();
        println!("mapping for wallet after create: {}", packed_after);
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
        .connect_http(ANVIL_HTTP_URL.parse().unwrap());
    let contract = AuthenticatorRegistry::new(registry.parse().unwrap(), provider.clone());
    // The wallet address must be registered as authenticator for account 1
    let packed = contract
        .authenticatorAddressToPackedAccountIndex(wallet_addr)
        .call()
        .await
        .unwrap();
    assert!(
        packed != U256::ZERO,
        "creator wallet not registered as authenticator"
    );

    let chain_id: u64 = 31337;
    let base = format!("http://127.0.0.1:{}", GW_PORT);

    // EIP-712 domain via common helpers
    let domain = ag_domain(chain_id, registry.parse::<Address>().unwrap());

    // Nonce tracker
    let mut nonce = U256::from(0);

    // insert-authenticator
    let new_auth2: Address = address!("0x00000000000000000000000000000000000000a2");
    let sig_ins = sign_insert_authenticator(
        &signer,
        U256::from(1),
        new_auth2,
        U256::from(2),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let sig_ins_hex = format!("0x{}", hex::encode(sig_ins.as_bytes()));
    let body_ins = serde_json::json!({
        "account_index": "0x1",
        "new_authenticator_address": format!("0x{:x}", new_auth2),
        "old_offchain_signer_commitment": "1",
        "new_offchain_signer_commitment": "2",
        "sibling_nodes": [],
        "signature": sig_ins_hex,
        "nonce": format!("0x{:x}", nonce),
    });
    // Issue request to gateway
    let resp = client
        .post(format!("{}/insert-authenticator", base))
        .json(&body_ins)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "insert-authenticator failed: {:?}",
        resp.text().await.unwrap()
    );
    // wait until mapping shows up
    let deadline2 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v = contract
            .authenticatorAddressToPackedAccountIndex(new_auth2)
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
    nonce = nonce + U256::from(1);

    // remove-authenticator (remove the one we inserted)
    let sig_rem = sign_remove_authenticator(
        &signer,
        U256::from(1),
        new_auth2,
        U256::from(3),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let sig_rem_hex = format!("0x{}", hex::encode(sig_rem.as_bytes()));
    let body_rem = serde_json::json!({
        "account_index": "0x1",
        "authenticator_address": format!("0x{:x}", new_auth2),
        "old_offchain_signer_commitment": "2",
        "new_offchain_signer_commitment": "3",
        "sibling_nodes": [],
        "signature": sig_rem_hex,
        "nonce": format!("0x{:x}", nonce),
    });
    let resp = client
        .post(format!("{}/remove-authenticator", base))
        .json(&body_rem)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "remove-authenticator failed: {:?}",
        resp.text().await.unwrap()
    );
    // wait until mapping cleared
    let deadline3 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v = contract
            .authenticatorAddressToPackedAccountIndex(new_auth2)
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
    nonce = nonce + U256::from(1);

    let signer_new = PrivateKeySigner::random();
    let wallet_addr_new: Address = signer_new.address();

    // recover-account (signed by recovery address == wallet)
    let sig_rec = sign_recover_account(
        &signer,
        U256::from(1),
        wallet_addr_new,
        U256::from(4),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let sig_rec_hex = format!("0x{}", hex::encode(sig_rec.as_bytes()));
    let body_rec = serde_json::json!({
        "account_index": "0x1",
        "new_authenticator_address": format!("0x{:x}", wallet_addr_new),
        "old_offchain_signer_commitment": "3",
        "new_offchain_signer_commitment": "4",
        "sibling_nodes": [],
        "signature": sig_rec_hex,
        "nonce": format!("0x{:x}", nonce),
    });
    let resp = client
        .post(format!("{}/recover-account", base))
        .json(&body_rec)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "recover-account failed: {:?}",
        resp.text().await.unwrap()
    );
    // wait mapping
    let deadline4 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v = contract
            .authenticatorAddressToPackedAccountIndex(wallet_addr_new)
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
    nonce = nonce + U256::from(1);

    // update-authenticator: replace original wallet authenticator with new one
    let new_auth4: Address = address!("0x00000000000000000000000000000000000000a4");
    let sig_upd = sign_update_authenticator(
        &signer_new,
        U256::from(1),
        wallet_addr_new,
        new_auth4,
        U256::from(5),
        nonce,
        &domain,
    )
    .await
    .unwrap();
    let sig_upd_hex = format!("0x{}", hex::encode(sig_upd.as_bytes()));
    let body_upd = serde_json::json!({
        "account_index": "0x1",
        "old_authenticator_address": format!("0x{:x}", wallet_addr_new),
        "new_authenticator_address": format!("0x{:x}", new_auth4),
        "old_offchain_signer_commitment": "4",
        "new_offchain_signer_commitment": "5",
        "sibling_nodes": [],
        "signature": sig_upd_hex,
        "nonce": format!("0x{:x}", nonce),
    });
    let resp = client
        .post(format!("{}/update-authenticator", base))
        .json(&body_upd)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "update-authenticator failed: {:?}",
        resp.text().await.unwrap()
    );
    // wait mapping: old removed, new present
    let deadline5 = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let old_v = contract
            .authenticatorAddressToPackedAccountIndex(wallet_addr_new)
            .call()
            .await
            .unwrap();
        let new_v = contract
            .authenticatorAddressToPackedAccountIndex(new_auth4)
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
    let _ = anvil.kill();
}
