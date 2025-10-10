use clap::Parser;

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
    let args = Args::parse();

    // Determine mode based on flags
    // If neither flag is set, default to both (backward compatibility)
    let mode = match (args.indexer, args.http) {
        (true, true) => "both",
        (true, false) => "indexer",
        (false, true) => "http",
        (false, false) => "both", // default
    };

    std::env::set_var("RUN_MODE", mode);

    authtree_indexer::run_from_env()
        .await
        .expect("indexer run failed");
}
