

use clap::Parser;
use eyre::Result;

#[derive(Parser)]
#[command(name = "xtask", version, about = "World ID Protocol task runner")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Run a full E2E relay test using alloy providers (no forge scripts).
    DeployHarness,
}