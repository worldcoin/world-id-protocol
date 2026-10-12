//! An in-memory stand-in for the message-bridge, with its request and response semantics:
//! single-use reads, `409` on a second write and a session that ends once its response is
//! fetched. Sessions never expire.

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

/// An encrypted message, opaque to the bridge.
#[derive(Clone, Serialize, Deserialize)]
struct Payload {
    iv: String,
    payload: String,
}

/// The body of `POST /request`.
#[derive(Deserialize)]
struct PublishBody {
    request_id: String,
    #[serde(flatten)]
    request: Payload,
}

/// One session, keyed by its lowercase request id.
enum Session {
    /// The request waits to be taken.
    Initialized(Payload),
    /// The request was taken; the response has not arrived.
    Retrieved,
    /// The response waits to be fetched.
    Completed(Payload),
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

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
            .with_state(Sessions::default());
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

/// Stores a request, unless one is already waiting under its id.
async fn publish_request(
    State(sessions): State<Sessions>,
    Json(body): Json<PublishBody>,
) -> Result<Json<Value>, StatusCode> {
    let id = body.request_id.to_lowercase();
    let mut sessions = sessions.lock().expect("bridge stub lock poisoned");
    if let Some(Session::Initialized(_)) = sessions.get(&id) {
        return Err(StatusCode::CONFLICT);
    }
    sessions.insert(id.clone(), Session::Initialized(body.request));
    Ok(Json(json!({ "request_id": id })))
}

/// Hands out a waiting request once.
async fn take_request(
    State(sessions): State<Sessions>,
    Path(id): Path<String>,
) -> Result<Json<Payload>, StatusCode> {
    let id = id.to_lowercase();
    let mut sessions = sessions.lock().expect("bridge stub lock poisoned");
    match sessions.remove(&id) {
        Some(Session::Initialized(request)) => {
            sessions.insert(id, Session::Retrieved);
            Ok(Json(request))
        }
        Some(session) => {
            sessions.insert(id, session);
            Err(StatusCode::NOT_FOUND)
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Reports the session status, handing out a stored response once and ending the session.
async fn fetch_response(
    State(sessions): State<Sessions>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let id = id.to_lowercase();
    let mut sessions = sessions.lock().expect("bridge stub lock poisoned");
    match sessions.remove(&id) {
        Some(Session::Completed(response)) => {
            Ok(Json(json!({ "status": "completed", "response": response })))
        }
        Some(waiting) => {
            let status = match waiting {
                Session::Initialized(_) => "initialized",
                _ => "retrieved",
            };
            sessions.insert(id, waiting);
            Ok(Json(json!({ "status": status, "response": null })))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Stores the response of a live session that has none yet.
async fn put_response(
    State(sessions): State<Sessions>,
    Path(id): Path<String>,
    Json(response): Json<Payload>,
) -> StatusCode {
    let id = id.to_lowercase();
    let mut sessions = sessions.lock().expect("bridge stub lock poisoned");
    match sessions.get(&id) {
        Some(Session::Initialized(_) | Session::Retrieved) => {
            sessions.insert(id, Session::Completed(response));
            StatusCode::CREATED
        }
        Some(Session::Completed(_)) => StatusCode::CONFLICT,
        None => StatusCode::BAD_REQUEST,
    }
}
