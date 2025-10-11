use authtree_indexer::GlobalConfig;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "authtree-indexer")]
#[command(about = "AuthTree Indexer - tracks chain data and serves HTTP API", long_about = None)]
struct Args {
    /// Enable the indexer (tracks chain and writes to DB)
    #[arg(long, default_value_t = false)]
    indexer: bool,

    /// Enable the HTTP server (serves API endpoints)
    #[arg(long, default_value_t = false)]
    http: bool,
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    let args = Args::parse();

    // Determine mode based on flags
    // If neither flag is set, default to both (backward compatibility)
    // FIXME: Don't override on default
    let mode = match (args.indexer, args.http) {
        (true, true) => "both",
        (true, false) => "indexer",
        (false, true) => "http",
        (false, false) => "both", // default
    };

    std::env::set_var("RUN_MODE", mode);

    tracing_subscriber::registry()
        .with(EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "authtree_indexer=info".into()),
        ))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true),
        )
        .init();

    tracing::info!("Starting world-id-indexer...");

    let config = GlobalConfig::from_env();

    authtree_indexer::run_indexer(config)
        .await
        .expect("indexer run failed");
}
