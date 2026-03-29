use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::{node_bindings::Anvil, primitives::U256, providers::ProviderBuilder, sol};
use reqwest::Client;
use tokio::sync::watch;

use crate::{
    abi_decoder::prepare_contract,
    config::{ContractConfig, ExplorerConfig, ServiceConfig},
    subscription::{ContractRuntime, run_contract_subscription},
};

// ── Minimal contract that emits `event Ping(uint256 value)` ─────────────

sol! {
    #[sol(rpc, bytecode = "6080604052348015600e575f5ffd5b5061012c8061001c5f395ff3fe6080604052348015600e575f5ffd5b50600436106026575f3560e01c806329f51a9314602a575b5f5ffd5b60406004803603810190603c919060ac565b6042565b005b7f48257dc961b6f792c2b78a080dacfed693b660960a702de21cee364e20270e2f81604051606f919060df565b60405180910390a150565b5f5ffd5b5f819050919050565b608e81607e565b81146097575f5ffd5b50565b5f8135905060a6816087565b92915050565b5f6020828403121560be5760bd607a565b5b5f60c984828501609a565b91505092915050565b60d981607e565b82525050565b5f60208201905060f05f83018460d2565b9291505056fea2646970667358221220497a2328bccda4ff6ce16717f97778257312322fb03b36ac6155411cf5cafe7764736f6c634300081e0033")]
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
    let anvil = Anvil::new().try_spawn().expect("failed to spawn anvil");
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

    // 5. Prepare the contract decoder via the mock explorer (no filter — all
    //    events)
    let http_client = Client::builder().build().unwrap();
    let explorer = ExplorerConfig {
        url: server.url(),
        api_key: None,
    };

    let prepared = prepare_contract(
        &http_client,
        &explorer,
        anvil.chain_id(),
        contract_address,
        None, // subscribe to all events
    )
    .await
    .expect("failed to prepare contract");

    assert_eq!(prepared.decoders.len(), 1);
    let first_event = prepared.decoders.values().next().unwrap();
    assert_eq!(first_event.event_name, "Ping");

    // 6. Build the runtime and spawn the subscription task
    let runtime = ContractRuntime {
        chain_name: "anvil-test".to_owned(),
        chain_id: anvil.chain_id(),
        ws_rpc_url: ws_url,
        service: ServiceConfig {
            reconnect_initial_backoff_ms: 100,
            reconnect_max_backoff_ms: 1000,
        },
        contract: ContractConfig {
            name: "emitter".to_owned(),
            contract_address,
            enabled: true,
            event_names: None,
        },
        prepared,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let _ = run_contract_subscription(runtime, shutdown_rx).await;
    });

    // Give the subscription a moment to connect
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 7. Emit the event: call emitPing(42)
    contract
        .emitPing(U256::from(42))
        .send()
        .await
        .expect("failed to send tx")
        .watch()
        .await
        .expect("tx failed");

    // 8. Wait for the watcher to log the event
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

    // 9. Shutdown
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}
