#[tokio::main]
async fn main() {
    authtree_indexer::run_from_env()
        .await
        .expect("indexer run failed");
}
