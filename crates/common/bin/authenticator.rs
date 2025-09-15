use common::{Authenticator, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_json("config.json").unwrap();

    let seed = &hex::decode(std::env::var("SEED").expect("SEED is required"))?;
    let authenticator = Authenticator::new(seed, config).await?;
    println!("Authenticator: {:?}", authenticator);
    Ok(())
}
