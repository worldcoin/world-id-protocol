use axum::Router;
use sqlx::PgPool;

mod health;
mod inclusion_proof;

pub(crate) fn handler(pool: PgPool) -> Router {
    Router::new()
        .route(
            "/proof/:account_index",
            axum::routing::get(inclusion_proof::handler),
        )
        .route("/health", axum::routing::get(health::handler))
        .with_state(pool)
}
