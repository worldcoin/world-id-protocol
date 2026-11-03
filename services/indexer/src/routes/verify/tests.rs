use super::*;
use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    sol_types::{SolCall, SolError},
};
use axum::{Router, response::IntoResponse, routing::post};
use http::StatusCode;
use serde_json::{Value, json};

fn request(inputs: Value) -> IndexerVerifyRequest {
    let mut value = json!({
        "rp_id": "1", "nonce": "2", "signal_hash": "3",
        "expires_at_min": "4", "issuer_schema_id": "5",
        "credential_genesis_issued_at_min": "6", "proof": "00".repeat(160),
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(inputs.as_object().unwrap().clone());
    serde_json::from_value(value).unwrap()
}

/// Check the actual RPC method, target and calldata, rather than just returning success.
async fn mock_verifier(
    expected_calldata: Vec<u8>,
    response: Value,
) -> (
    WorldIdVerifierInstance<DynProvider>,
    tokio::task::JoinHandle<()>,
) {
    let router = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let expected_calldata = expected_calldata.clone();
            let response = response.clone();
            async move {
                assert_eq!(req["method"], "eth_call");
                assert_eq!(req["params"][0]["to"], json!(Address::repeat_byte(1)));
                let call = &req["params"][0];
                let input = call.get("input").or_else(|| call.get("data")).unwrap();
                assert_eq!(
                    input,
                    &json!(format!("0x{}", hex::encode(expected_calldata)))
                );
                let mut response = response;
                response["jsonrpc"] = json!("2.0");
                response["id"] = req["id"].clone();
                Json(response)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let provider = ProviderBuilder::new()
        .connect_http(format!("http://{addr}").parse().unwrap())
        .erased();
    (
        WorldIdVerifier::new(Address::repeat_byte(1), provider),
        task,
    )
}

fn uniqueness_call(nonce: u64) -> Vec<u8> {
    WorldIdVerifier::verifyCall {
        nullifier: U256::from(7),
        action: U256::from(8),
        rpId: 1,
        nonce: U256::from(nonce),
        signalHash: U256::from(3),
        expiresAtMin: 4,
        issuerSchemaId: 5,
        credentialGenesisIssuedAtMin: U256::from(6),
        zeroKnowledgeProof: [U256::ZERO; 5],
    }
    .abi_encode()
}

#[tokio::test]
async fn forwards_uniqueness_and_session_inputs() {
    let (verifier, task) = mock_verifier(uniqueness_call(2), json!({"result": "0x"})).await;
    let req = request(json!({"proof_type": "uniqueness", "nullifier": "7", "action": "8"}));
    let response = verify(&verifier, req).await.unwrap();
    assert_eq!(
        serde_json::to_value(response.0).unwrap(),
        json!({"valid": true})
    );
    task.abort();

    let session_action = U256::from(2) << 248;
    let session_nullifier = world_id_primitives::SessionNullifier::from_ethereum_representation([
        U256::from(7),
        session_action,
    ])
    .unwrap();
    let expected = WorldIdVerifier::verifySessionCall {
        rpId: 1,
        nonce: U256::from(2),
        signalHash: U256::from(3),
        expiresAtMin: 4,
        issuerSchemaId: 5,
        credentialGenesisIssuedAtMin: U256::from(6),
        sessionId: U256::ZERO,
        sessionNullifier: [U256::from(7), session_action],
        zeroKnowledgeProof: [U256::ZERO; 5],
    }
    .abi_encode();
    let (verifier, task) = mock_verifier(expected, json!({"result": "0x"})).await;
    let req = request(
        json!({"proof_type": "session", "session_id": "0", "session_nullifier": session_nullifier}),
    );
    assert!(verify(&verifier, req).await.unwrap().0.valid);
    task.abort();
}

#[tokio::test]
async fn distinguishes_proof_rejection_from_rpc_and_unknown_revert_errors() {
    for (error, status, code) in [
        (
            json!({"code": 3, "message": "execution reverted", "data": format!("0x{}", hex::encode(ProofInvalid::SELECTOR))}),
            StatusCode::BAD_REQUEST,
            "invalid_proof",
        ),
        (
            json!({"code": -32603, "message": "upstream unavailable"}),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_server_error",
        ),
        (
            json!({"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_server_error",
        ),
    ] {
        // Change the expected nonce: the rejection must not turn into a successful check.
        let (verifier, task) = mock_verifier(uniqueness_call(99), json!({"error": error})).await;
        let mut req = request(json!({"proof_type": "uniqueness", "nullifier": "7", "action": "8"}));
        req.nonce = U256::from(99);
        let response = verify(&verifier, req).await.unwrap_err().into_response();
        assert_eq!(response.status(), status);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["code"],
            code
        );
        task.abort();
    }
}

// Uses the same checked-in proofs and registry fixtures as the Solidity verifier tests.
#[cfg(feature = "integration-tests")]
mod real_proof;
