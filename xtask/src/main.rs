#[macro_use]
mod telemetry;

mod anvil;
pub mod bindings;
mod bootstrap;
mod fuzz;
mod invariants;
mod relay_harness;

use clap::Parser;
use eyre::Result;

#[derive(Parser)]
#[command(name = "xtask", version, about = "World ID Protocol task runner")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Bootstrap all services: anvils, contracts, relay.
    /// Blocks until Ctrl+C.
    Bootstrap,

    /// Fuzz the relay by spamming random registry updates.
    Fuzz {
        /// Number of rounds (0 = infinite until Ctrl+C).
        #[arg(long, default_value = "10")]
        rounds: u64,

        /// Delay between rounds in milliseconds.
        #[arg(long, default_value = "500")]
        delay_ms: u64,

        /// Propagation timeout per round (seconds).
        #[arg(long, default_value = "60")]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    telemetry!();
    let cli = Cli::parse();

    match cli.cmd {
        Command::Bootstrap => bootstrap::run().await,
        Command::Fuzz {
            rounds,
            delay_ms,
            timeout,
        } => {
            fuzz::run(fuzz::FuzzConfig {
                rounds,
                delay_ms,
                propagation_timeout_secs: timeout,
            })
            .await
        }
    }
}
