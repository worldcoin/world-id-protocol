use std::process::Command;
use std::time::Duration;

use alloy::node_bindings::Anvil;
use alloy::primitives::{address, Address, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use regex::Regex;
use registry_gateway::{spawn_gateway, GatewayConfig};
use reqwest::Client;
use world_id_core::authenticator_registry::{
    domain as ag_domain, sign_insert_authenticator, sign_recover_account,
    sign_remove_authenticator, sign_update_authenticator, AuthenticatorRegistry,
};

const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";
const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const GW_PORT: u16 = 4101;
const RPC_FORK_URL: &str = "https://reth-ethereum.ithaca.xyz/rpc";

fn default_sibling_nodes() -> Vec<String> {
    vec![
        "0",
        "14744269619966411208579211824598458697587494354926760081771325075741142829156",
        "7423237065226347324353380772367382631490014989348495481811164164159255474657",
        "11286972368698509976183087595462810875513684078608517520839298933882497716792",
        "3607627140608796879659380071776844901612302623152076817094415224584923813162",
        "19712377064642672829441595136074946683621277828620209496774504837737984048981",
        "20775607673010627194014556968476266066927294572720319469184847051418138353016",
        "3396914609616007258851405644437304192397291162432396347162513310381425243293",
        "21551820661461729022865262380882070649935529853313286572328683688269863701601",
        "6573136701248752079028194407151022595060682063033565181951145966236778420039",
        "12413880268183407374852357075976609371175688755676981206018884971008854919922",
        "14271763308400718165336499097156975241954733520325982997864342600795471836726",
        "20066985985293572387227381049700832219069292839614107140851619262827735677018",
        "9394776414966240069580838672673694685292165040808226440647796406499139370960",
        "11331146992410411304059858900317123658895005918277453009197229807340014528524",
        "15819538789928229930262697811477882737253464456578333862691129291651619515538",
        "19217088683336594659449020493828377907203207941212636669271704950158751593251",
        "21035245323335827719745544373081896983162834604456827698288649288827293579666",
        "6939770416153240137322503476966641397417391950902474480970945462551409848591",
        "10941962436777715901943463195175331263348098796018438960955633645115732864202",
        "15019797232609675441998260052101280400536945603062888308240081994073687793470",
        "11702828337982203149177882813338547876343922920234831094975924378932809409969",
        "11217067736778784455593535811108456786943573747466706329920902520905755780395",
        "16072238744996205792852194127671441602062027943016727953216607508365787157389",
        "17681057402012993898104192736393849603097507831571622013521167331642182653248",
        "21694045479371014653083846597424257852691458318143380497809004364947786214945",
        "8163447297445169709687354538480474434591144168767135863541048304198280615192",
        "14081762237856300239452543304351251708585712948734528663957353575674639038357",
        "16619959921569409661790279042024627172199214148318086837362003702249041851090",
        "7022159125197495734384997711896547675021391130223237843255817587255104160365",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

fn deploy_registry(rpc_url: &str) -> String {
    // TODO: improve this and use alloy's deploy (linking needs to be figured out)
    let mut cmd = Command::new("forge");
    cmd.current_dir("../../contracts")
        .arg("script")
        .arg("script/AuthenticatorRegistry.s.sol:CounterScript")
        .arg("--rpc-url")
        .arg(rpc_url)
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
#[ignore = "requires additional setup"]
async fn e2e_gateway_full_flow() {
    let anvil = Anvil::new().fork(RPC_FORK_URL).try_spawn().unwrap();

    let registry = deploy_registry(anvil.endpoint_url().to_string().as_str());

    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    let cfg = GatewayConfig {
        registry_addr: registry.parse().unwrap(),
        rpc_url: anvil.endpoint_url().to_string(),
        wallet_key: GW_PRIVATE_KEY.to_string(),
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, GW_PORT).into(),
    };
    let gw = spawn_gateway(cfg).await.expect("spawn gateway");

    // HTTP client
    let client = Client::builder().build().unwrap();
    wait_http_ready(&client).await;
    let base = format!("http://127.0.0.1:{}", GW_PORT);

    // Build Alloy provider for on-chain assertions and chain id
    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(anvil.endpoint_url());
    let contract = AuthenticatorRegistry::new(registry.parse().unwrap(), provider.clone());

    // First, create the initial account through the API so tree depth stays 0 for following ops
    let body_create = serde_json::json!({
        "recovery_address": format!("0x{:x}", wallet_addr),
        "authenticator_addresses": [format!("0x{:x}", wallet_addr)],
        "offchain_signer_commitment": "1",
    });
    let resp = client
        .post(format!("{}/create-account", base))
        .json(&body_create)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "create-account failed: {:?}",
        resp.text().await.unwrap()
    );

    // Wait until createManyAccounts is reflected on-chain
    let deadline_ca = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let packed_after = contract
            .authenticatorAddressToPackedAccountIndex(wallet_addr)
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
        .connect_http(anvil.endpoint_url());
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

    let chain_id = provider.get_chain_id().await.unwrap();

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
        U256::from(1),
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
        "sibling_nodes": default_sibling_nodes(),
        "signature": sig_ins_hex,
        "nonce": format!("0x{:x}", nonce),
        "pubkey_id": "0x1",
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
        U256::from(1),
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
        "sibling_nodes": default_sibling_nodes(),
        "signature": sig_rem_hex,
        "nonce": format!("0x{:x}", nonce),
        "pubkey_id": "0x1",
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
        "sibling_nodes": default_sibling_nodes(),
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
        U256::from(0),
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
        "sibling_nodes": default_sibling_nodes(),
        "signature": sig_upd_hex,
        "nonce": format!("0x{:x}", nonce),
        "pubkey_id": "0x0",
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
}
