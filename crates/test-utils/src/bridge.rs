//! An in-memory stand-in for the wallet-bridge (message-bridge), with the same request and
//! response semantics: single-use reads, `409` on a second write and a session that ends once
//! its response is stored. Entries never expire.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use eyre::{Context as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

#[derive(Clone, Serialize, Deserialize)]
struct Payload {
    iv: String,
    payload: String,
}

#[derive(Deserialize)]
struct PublishBody {
    request_id: String,
    iv: String,
    payload: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Initialized,
    Retrieved,
}

#[derive(Default)]
struct Sessions {
    requests: HashMap<String, Payload>,
    statuses: HashMap<String, Status>,
    responses: HashMap<String, Payload>,
}

type Shared = Arc<Mutex<Sessions>>;

/// A running bridge stub. Dropping it does not stop the server; call [`BridgeStub::abort`].
pub struct BridgeStub {
    /// The base URL of the stub, e.g. `http://127.0.0.1:1234`.
    pub url: String,
    handle: JoinHandle<()>,
}

impl BridgeStub {
    /// Starts a bridge stub on a random local port.
    ///
    /// # Errors
    /// Returns an error if the listener cannot be bound.
    pub async fn spawn() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .wrap_err("failed to bind bridge stub listener")?;
        let url = format!(
            "http://{}",
            listener
                .local_addr()
                .wrap_err("failed to read listener address")?
        );
        let app = Router::new()
            .route("/request", post(publish_request))
            .route("/request/{id}", get(take_request))
            .route("/response/{id}", get(fetch_response).put(put_response))
            .with_state(Shared::default());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("bridge stub server crashed");
        });
        Ok(Self { url, handle })
    }

    /// Stops the server.
    pub fn abort(self) {
        self.handle.abort();
    }
}

async fn publish_request(
    State(state): State<Shared>,
    Json(body): Json<PublishBody>,
) -> Result<Json<Value>, StatusCode> {
    let id = body.request_id.to_lowercase();
    let mut sessions = state.lock().expect("bridge stub lock poisoned");
    if sessions.requests.contains_key(&id) {
        return Err(StatusCode::CONFLICT);
    }
    sessions.requests.insert(
        id.clone(),
        Payload {
            iv: body.iv,
            payload: body.payload,
        },
    );
    sessions.statuses.insert(id.clone(), Status::Initialized);
    Ok(Json(json!({ "request_id": id })))
}

async fn take_request(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Payload>, StatusCode> {
    let id = id.to_lowercase();
    let mut sessions = state.lock().expect("bridge stub lock poisoned");
    let request = sessions.requests.remove(&id).ok_or(StatusCode::NOT_FOUND)?;
    sessions.statuses.insert(id, Status::Retrieved);
    Ok(Json(request))
}

async fn fetch_response(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let id = id.to_lowercase();
    let mut sessions = state.lock().expect("bridge stub lock poisoned");
    if let Some(response) = sessions.responses.remove(&id) {
        return Ok(Json(json!({ "status": "completed", "response": response })));
    }
    match sessions.statuses.get(&id) {
        Some(Status::Initialized) => Ok(Json(json!({ "status": "initialized", "response": null }))),
        Some(Status::Retrieved) => Ok(Json(json!({ "status": "retrieved", "response": null }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn put_response(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<Payload>,
) -> StatusCode {
    let id = id.to_lowercase();
    let mut sessions = state.lock().expect("bridge stub lock poisoned");
    if !sessions.statuses.contains_key(&id) {
        return StatusCode::BAD_REQUEST;
    }
    if sessions.responses.contains_key(&id) {
        return StatusCode::CONFLICT;
    }
    sessions.responses.insert(id.clone(), body);
    sessions.statuses.remove(&id);
    StatusCode::CREATED
}
