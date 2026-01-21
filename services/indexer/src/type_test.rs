use alloy::providers::{ProviderBuilder, WsConnect};

pub async fn test_types() {
    let http = ProviderBuilder::new().connect_http("http://localhost:8545".parse().unwrap());
    let ws = ProviderBuilder::new().connect_ws(WsConnect::new("ws://localhost:8545")).await.unwrap();
    
    // Force compiler to show types
    let _: () = http;
    let _: () = ws;
}
