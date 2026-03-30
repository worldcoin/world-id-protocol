use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::{node_bindings::Anvil, primitives::U256, providers::ProviderBuilder, sol};
use tokio::sync::watch;

use crate::{
    config::{ContractConfig, ExplorerConfig},
    subscription::{ContractRuntime, run_contract_subscription},
};

// ── Minimal contract that emits `event Ping(uint256 value)` ─────────────

sol! {
    #[sol(rpc, bytecode = "6080604052348015600f57600080fd5b5061014e8061001f6000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806329f51a9314610030575b600080fd5b61004a600480360381019061004591906100c1565b61004c565b005b7f48257dc961b6f792c2b78a080dacfed693b660960a702de21cee364e20270e2f8160405161007b91906100fd565b60405180910390a150565b600080fd5b6000819050919050565b61009e8161008b565b81146100a957600080fd5b50565b6000813590506100bb81610095565b92915050565b6000602082840312156100d7576100d6610086565b5b60006100e5848285016100ac565b91505092915050565b6100f78161008b565b82525050565b600060208201905061011260008301846100ee565b9291505056fea264697066735822122097d890151ccced08bda87aaf017de1741bc688e50eca11a56f50a6d9c07be12664736f6c634300081e0033")]
    contract Emitter {
        event Ping(uint256 value);

        function emitPing(uint256 value) external;
    }
}

const EMITTER_ABI_JSON: &str = r#"[{"type":"function","name":"emitPing","inputs":[{"name":"value","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"event","name":"Ping","inputs":[{"name":"value","type":"uint256","indexed":false,"internalType":"uint256"}],"anonymous":false}]"#;

// ── Tracing layer that captures structured log messages ─────────────────

/// A minimal tracing layer that collects formatted log messages into a shared
/// buffer so we can assert on their content after the watcher processes events.
struct CapturingLayer {
    buf: Arc<Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturingLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        self.buf.lock().unwrap().push(visitor.0);
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, "{}={:?} ", field.name(), value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        use std::fmt::Write;
        let _ = write!(self.0, "{}={} ", field.name(), value);
    }
}

// ── Test ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_watcher_receives_event() {
    // 1. Set up tracing capture
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let layer = CapturingLayer {
        buf: captured.clone(),
    };
    let subscriber = tracing_subscriber::registry::Registry::default();
    use tracing_subscriber::layer::SubscriberExt;
    let subscriber = subscriber.with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // 2. Spawn Anvil
    let anvil = Anvil::new()
        .arg("--hardfork")
        .arg("paris")
        .try_spawn()
        .expect("failed to spawn anvil");
    let ws_url = anvil.ws_endpoint();

    // 3. Deploy the Emitter contract (via HTTP for setup)
    let signer: alloy::signers::local::PrivateKeySigner = anvil.keys()[0].clone().into();
    let wallet = alloy::network::EthereumWallet::from(signer);
    let http_provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(anvil.endpoint_url());
    let contract = Emitter::deploy(&http_provider)
        .await
        .expect("failed to deploy Emitter");
    let contract_address = *contract.address();

    // 4. Start mockito server to fake Etherscan API
    let mut server = mockito::Server::new_async().await;

    // getsourcecode → non-proxy
    let sourcecode_body = serde_json::json!({
        "status": "1",
        "message": "OK",
        "result": [{
            "Proxy": "0",
            "Implementation": ""
        }]
    });
    let _m1 = server
        .mock("GET", "/")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("module".into(), "contract".into()),
            mockito::Matcher::UrlEncoded("action".into(), "getsourcecode".into()),
            mockito::Matcher::UrlEncoded("address".into(), format!("{contract_address:#x}")),
        ]))
        .with_status(200)
        .with_body(sourcecode_body.to_string())
        .create_async()
        .await;

    // getabi → the Emitter ABI
    let abi_body = serde_json::json!({
        "status": "1",
        "message": "OK",
        "result": EMITTER_ABI_JSON
    });
    let _m2 = server
        .mock("GET", "/")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("module".into(), "contract".into()),
            mockito::Matcher::UrlEncoded("action".into(), "getabi".into()),
            mockito::Matcher::UrlEncoded("address".into(), format!("{contract_address:#x}")),
        ]))
        .with_status(200)
        .with_body(abi_body.to_string())
        .create_async()
        .await;

    // 5. Build the runtime — ABI is now fetched lazily by the task.
    let explorer = ExplorerConfig {
        url: server.url(),
        api_key: None,
    };

    let runtime = ContractRuntime {
        chain_name: "anvil-test".to_owned(),
        chain_id: anvil.chain_id(),
        ws_rpc_url: ws_url,
        explorer,
        contract: ContractConfig {
            name: "emitter".to_owned(),
            contract_address,
            event_names: None,
        },
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut prepared = None;
        let _ = run_contract_subscription(&runtime, &mut prepared, shutdown_rx).await;
    });

    // Give the subscription a moment to connect and fetch the ABI
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 6. Emit the event: call emitPing(42)
    contract
        .emitPing(U256::from(42))
        .send()
        .await
        .expect("failed to send tx")
        .watch()
        .await
        .expect("tx failed");

    // 7. Wait for the watcher to log the event
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut found = false;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let logs = captured.lock().unwrap();
        if logs
            .iter()
            .any(|msg| msg.contains("observed on-chain event") && msg.contains("42"))
        {
            found = true;
            break;
        }
    }

    assert!(
        found,
        "watcher did not emit the expected event log within 10s"
    );

    // 8. Shutdown
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}
