//! Per-network KMS or legacy private-key signing.

use alloy::{network::EthereumWallet, signers::local::PrivateKeySigner};
use world_id_services_common::alloy::provider::SignerArgs as CommonSignerArgs;

/// Relay signing configuration.
#[derive(clap::Args, Clone, Default)]
pub struct SignerArgs {
    /// Sign with the key in each `{NETWORK}_AWS_KMS_KEY_ID` environment variable.
    #[arg(long, env = "AWS_KMS_SIGNING")]
    pub aws_kms_signing: bool,

    /// Hex private key used for *every* network (legacy, local development).
    #[arg(long, env = "WALLET_PRIVATE_KEY", hide_env_values = true)]
    pub wallet_private_key: Option<String>,
}

impl SignerArgs {
    /// Builds a wallet, pinning KMS signing to the configured chain ID.
    pub async fn wallet_for(&self, network: &str, chain_id: u64) -> eyre::Result<EthereumWallet> {
        eyre::ensure!(
            self.aws_kms_signing != self.wallet_private_key.is_some(),
            "set either AWS_KMS_SIGNING=true or WALLET_PRIVATE_KEY"
        );
        let wallet = if let Some(key) = &self.wallet_private_key {
            let signer = key
                .parse::<PrivateKeySigner>()
                .map_err(|e| eyre::eyre!("failed to parse WALLET_PRIVATE_KEY: {e}"))?;
            EthereumWallet::from(signer)
        } else {
            let env_var = format!("{}_AWS_KMS_KEY_ID", network.to_uppercase());
            let key_id = std::env::var(&env_var)
                .map_err(|_| eyre::eyre!("{env_var} is required for KMS signing"))?;
            CommonSignerArgs::aws_kms_wallet_for_chain(&key_id, chain_id).await?
        };
        tracing::info!(
            %network,
            chain_id,
            aws_kms = self.aws_kms_signing,
            wallet = %wallet.default_signer().address(),
            "initialized relay signer"
        );
        Ok(wallet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::process::Command;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        signer: SignerArgs,
    }

    #[test]
    fn signer_environment() {
        const CASE: &str = "RELAY_SIGNER_TEST_CASE";
        const TEST_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

        if let Ok(expected) = std::env::var(CASE) {
            let result = TestCli::try_parse_from(["relay"])
                .map_err(eyre::Report::from)
                .and_then(|cli| {
                    tokio::runtime::Runtime::new()?
                        .block_on(cli.signer.wallet_for("worldchain", 480))
                });
            match expected.as_str() {
                "private" => assert_eq!(
                    result.unwrap().default_signer().address(),
                    TEST_KEY.parse::<PrivateKeySigner>().unwrap().address()
                ),
                "kms" => assert_eq!(
                    result.unwrap_err().to_string(),
                    "WORLDCHAIN_AWS_KMS_KEY_ID is required for KMS signing"
                ),
                "invalid" => assert_eq!(
                    result.unwrap_err().to_string(),
                    "set either AWS_KMS_SIGNING=true or WALLET_PRIVATE_KEY"
                ),
                "invalid_key" => assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .starts_with("failed to parse WALLET_PRIVATE_KEY:")
                ),
                _ => panic!("unknown signer test case"),
            }
            return;
        }

        for (kms, private_key, expected) in [
            (Some("false"), Some(TEST_KEY), "private"),
            (None, Some(TEST_KEY), "private"),
            (Some("true"), None, "kms"),
            (Some("true"), Some(TEST_KEY), "invalid"),
            (Some("false"), None, "invalid"),
            (None, None, "invalid"),
            (Some("false"), Some("invalid"), "invalid_key"),
        ] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "signer::tests::signer_environment",
                    "--nocapture",
                ])
                .env_clear()
                .env(CASE, expected);
            if let Some(value) = kms {
                command.env("AWS_KMS_SIGNING", value);
            }
            if let Some(value) = private_key {
                command.env("WALLET_PRIVATE_KEY", value);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "KMS={kms:?}, private_key={}: {}{}",
                private_key.is_some(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
