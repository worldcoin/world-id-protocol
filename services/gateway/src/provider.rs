use crate::SignerConfig;
use alloy::{
    network::{EthereumWallet, TxSigner},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::{aws::AwsSigner, local::PrivateKeySigner},
    transports::http::reqwest::Url,
};
use aws_config::BehaviorVersion;

pub(crate) async fn build_wallet(
    signer_config: SignerConfig,
    rpc_url: &str,
) -> anyhow::Result<EthereumWallet> {
    match signer_config {
        SignerConfig::PrivateKey(pk) => {
            let signer = pk
                .parse::<PrivateKeySigner>()
                .map_err(|e| anyhow::anyhow!("invalid private key: {e}"))?;
            Ok(EthereumWallet::from(signer))
        }
        SignerConfig::AwsKms(key_id) => {
            tracing::info!("Initializing AWS KMS signer with key_id: {}", key_id);

            // Create a temporary provider to fetch the chain ID
            let url = Url::parse(rpc_url)?;
            let temp_provider = ProviderBuilder::new().connect_http(url);
            let chain_id = temp_provider.get_chain_id().await?;
            tracing::info!("Fetched chain_id: {}", chain_id);

            // Initialize AWS KMS signer with the chain ID
            let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
            let client = aws_sdk_kms::Client::new(&config);
            let aws_signer = AwsSigner::new(client, key_id, Some(chain_id))
                .await
                .map_err(|e| anyhow::anyhow!("failed to initialize AWS KMS signer: {e}"))?;
            tracing::info!(
                "AWS KMS signer initialized with address: {}",
                aws_signer.address()
            );
            Ok(EthereumWallet::from(aws_signer))
        }
    }
}

pub(crate) fn build_provider(
    rpc_url: &str,
    ethereum_wallet: EthereumWallet,
) -> anyhow::Result<DynProvider> {
    let url = Url::parse(rpc_url)?;
    let provider = ProviderBuilder::new()
        .wallet(ethereum_wallet)
        .connect_http(url);
    Ok(provider.erased())
}
