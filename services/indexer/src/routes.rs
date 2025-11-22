use axum::Router;

use crate::config::AppState;

mod get_packed_account;
mod health;
mod inclusion_proof;

pub(crate) fn handler(state: AppState) -> Router {
    Router::new()
        .route(
            "/proof/:account_index",
            axum::routing::get(inclusion_proof::handler),
        )
        .route(
            "/packed_account",
            axum::routing::post(get_packed_account::handler),
        )
        .route("/health", axum::routing::get(health::handler))
        .with_state(state)
}
