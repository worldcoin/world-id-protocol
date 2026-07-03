//! CLI for migrating legacy V1 pending Recovery Agent updates into
//! `WorldIDRegistryV2` semantics via `migrateLegacyRecoveryAgentUpdate`.
//!
//! Two subcommands:
//! - `fetch`: reconstructs still-pending legacy updates from the registry's full
//!   event history and writes them to a JSON file.
//! - `migrate`: reads that JSON file and calls `migrateLegacyRecoveryAgentUpdate`
//!   for each entry, skipping leaves whose pending update has since been cleared
//!   so re-runs are idempotent.
//!
//! Note that after the V2 upgrade the legacy `_pendingRecoveryAgentUpdates`
//! storage has no public getter (`getPendingRecoveryAgentUpdate` is overridden
//! with V2 revert-window semantics), so `fetch` derives pending state purely
//! from events: a leaf still has a legacy pending update iff the latest
//! relevant event for it is `RecoveryAgentUpdateInitiated`. All of
//! `RecoveryAgentUpdateExecuted`, `RecoveryAgentUpdateCancelled`,
//! `AccountRecovered` (V1+V2 recoveries), and the V2 `RecoveryAgentUpdated`
//! (emitted by both `updateRecoveryAgent` and `migrateLegacyRecoveryAgentUpdate`,
//! which both delete the legacy entry) clear it.

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::{Filter, Log},
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use clap::{Args, Parser, Subcommand};
use eyre::{Context, Result, eyre};
use serde::{Deserialize, Serialize};
use world_id_registries::world_id::WorldIdRegistryV2::{
    self, AccountRecovered, RecoveryAgentUpdateCancelled, RecoveryAgentUpdateExecuted,
    RecoveryAgentUpdateInitiated, RecoveryAgentUpdated, WorldIdRegistryV2Errors,
};

/// Bounded retries for `eth_getLogs` chunk queries.
const GET_LOGS_ATTEMPTS: u32 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "legacy-recovery-migration",
    version,
    about = "Migrates legacy V1 pending Recovery Agent updates on WorldIDRegistryV2"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Fetch all still-pending legacy Recovery Agent updates and save them to a JSON file.
    Fetch(FetchArgs),
    /// Execute `migrateLegacyRecoveryAgentUpdate` for every entry in the JSON file.
    Migrate(MigrateArgs),
}

#[derive(Args, Debug)]
struct FetchArgs {
    /// RPC endpoint of the chain the registry is deployed on.
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,

    /// `WorldIDRegistry` proxy address (same address pre- and post-V2 upgrade).
    #[arg(long, env = "REGISTRY_ADDRESS")]
    registry: Address,

    /// Block the registry was deployed at; log scanning starts here.
    /// Scanning from an intermediate block risks missing clearing events
    /// and producing false pending entries.
    #[arg(long)]
    from_block: u64,

    /// Last block to scan (default: latest).
    #[arg(long)]
    to_block: Option<u64>,

    /// Max block range per `eth_getLogs` request.
    #[arg(long, default_value_t = 5_000)]
    chunk_size: u64,

    /// Output JSON file.
    #[arg(long, default_value = "pending-legacy-migrations.json")]
    output: PathBuf,
}

#[derive(Args, Debug)]
struct MigrateArgs {
    /// RPC endpoint of the chain the registry is deployed on.
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,

    /// Private key of the transaction sender (the method is permissionless).
    #[arg(long, env = "WALLET_PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// Input JSON file produced by `fetch`.
    #[arg(long, default_value = "pending-legacy-migrations.json")]
    input: PathBuf,

    /// Simulate each migration with `eth_call` instead of sending transactions.
    #[arg(long)]
    dry_run: bool,
}

/// A legacy pending Recovery Agent update that still needs migration.
#[derive(Debug, Serialize, Deserialize)]
struct PendingMigration {
    leaf_index: u64,
    new_recovery_agent: Address,
    execute_after: U256,
}

/// Output of `fetch` / input of `migrate`.
#[derive(Debug, Serialize, Deserialize)]
struct MigrationFile {
    chain_id: u64,
    registry: Address,
    scanned_from_block: u64,
    scanned_to_block: u64,
    pending: Vec<PendingMigration>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Fetch(args) => fetch(args).await,
        Command::Migrate(args) => migrate(args).await,
    }
}

/// The latest legacy-pending-state transition observed for a leaf.
#[derive(Debug)]
enum LeafState {
    /// Last event was `RecoveryAgentUpdateInitiated`: update is still pending.
    Pending {
        new_recovery_agent: Address,
        execute_after: U256,
    },
    /// Last event cleared the legacy pending entry.
    Cleared,
}

async fn fetch(args: FetchArgs) -> Result<()> {
    let provider = ProviderBuilder::new()
        .connect(&args.rpc_url)
        .await
        .wrap_err_with(|| format!("failed to connect to RPC at {}", args.rpc_url))?
        .erased();
    let chain_id = provider.get_chain_id().await?;

    let to_block = match args.to_block {
        Some(b) => b,
        None => provider.get_block_number().await?,
    };
    eyre::ensure!(
        args.from_block <= to_block,
        "from_block {} is past to_block {to_block}",
        args.from_block
    );

    // Latest relevant event per leaf, keyed by (block number, log index) order.
    // eth_getLogs returns logs in chain order, so plain overwrites suffice.
    let mut leaf_states: BTreeMap<u64, LeafState> = BTreeMap::new();

    let mut start = args.from_block;
    while start <= to_block {
        let end = to_block.min(start + args.chunk_size - 1);
        let logs = get_logs_with_retry(&provider, args.registry, start, end).await?;
        tracing::info!(start, end, logs = logs.len(), "scanned block range");
        for log in &logs {
            apply_log(&mut leaf_states, log)?;
        }
        start = end + 1;
    }

    let mut pending: Vec<PendingMigration> = leaf_states
        .into_iter()
        .filter_map(|(leaf_index, state)| match state {
            LeafState::Pending {
                new_recovery_agent,
                execute_after,
            } => Some(PendingMigration {
                leaf_index,
                new_recovery_agent,
                execute_after,
            }),
            LeafState::Cleared => None,
        })
        .collect();
    pending.sort_by_key(|p| p.leaf_index);

    let file = MigrationFile {
        chain_id,
        registry: args.registry,
        scanned_from_block: args.from_block,
        scanned_to_block: to_block,
        pending,
    };
    std::fs::write(&args.output, serde_json::to_string_pretty(&file)?)
        .wrap_err_with(|| format!("failed to write {}", args.output.display()))?;
    tracing::info!(
        pending = file.pending.len(),
        output = %args.output.display(),
        "wrote pending legacy migrations"
    );
    Ok(())
}

/// Folds a single registry log into the per-leaf legacy pending state.
fn apply_log(leaf_states: &mut BTreeMap<u64, LeafState>, log: &Log) -> Result<()> {
    let Some(&topic0) = log.topic0() else {
        return Ok(());
    };
    let (leaf_index, state) = match topic0 {
        RecoveryAgentUpdateInitiated::SIGNATURE_HASH => {
            let ev = RecoveryAgentUpdateInitiated::decode_log(&log.inner)?;
            (
                ev.leafIndex,
                LeafState::Pending {
                    new_recovery_agent: ev.newRecoveryAgent,
                    execute_after: ev.executeAfter,
                },
            )
        }
        RecoveryAgentUpdateExecuted::SIGNATURE_HASH => {
            let ev = RecoveryAgentUpdateExecuted::decode_log(&log.inner)?;
            (ev.leafIndex, LeafState::Cleared)
        }
        RecoveryAgentUpdateCancelled::SIGNATURE_HASH => {
            let ev = RecoveryAgentUpdateCancelled::decode_log(&log.inner)?;
            (ev.leafIndex, LeafState::Cleared)
        }
        RecoveryAgentUpdated::SIGNATURE_HASH => {
            let ev = RecoveryAgentUpdated::decode_log(&log.inner)?;
            (ev.leafIndex, LeafState::Cleared)
        }
        AccountRecovered::SIGNATURE_HASH => {
            let ev = AccountRecovered::decode_log(&log.inner)?;
            (ev.leafIndex, LeafState::Cleared)
        }
        _ => return Ok(()),
    };
    leaf_states.insert(leaf_index, state);
    Ok(())
}

/// Queries all legacy-pending-state events for a block range with bounded retries.
async fn get_logs_with_retry(
    provider: &DynProvider,
    registry: Address,
    from: u64,
    to: u64,
) -> Result<Vec<Log>> {
    let filter = Filter::new()
        .address(registry)
        .from_block(from)
        .to_block(to)
        .event_signature(vec![
            RecoveryAgentUpdateInitiated::SIGNATURE_HASH,
            RecoveryAgentUpdateExecuted::SIGNATURE_HASH,
            RecoveryAgentUpdateCancelled::SIGNATURE_HASH,
            RecoveryAgentUpdated::SIGNATURE_HASH,
            AccountRecovered::SIGNATURE_HASH,
        ]);

    let mut last_err = None;
    for attempt in 1..=GET_LOGS_ATTEMPTS {
        match provider.get_logs(&filter).await {
            Ok(logs) => return Ok(logs),
            Err(e) => {
                tracing::warn!(from, to, attempt, error = %e, "eth_getLogs failed");
                last_err = Some(e);
                tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
            }
        }
    }
    Err(eyre!(last_err.unwrap()).wrap_err(format!(
        "eth_getLogs failed for range {from}..={to} after {GET_LOGS_ATTEMPTS} attempts"
    )))
}

async fn migrate(args: MigrateArgs) -> Result<()> {
    let contents = std::fs::read_to_string(&args.input)
        .wrap_err_with(|| format!("failed to read {}", args.input.display()))?;
    let file: MigrationFile = serde_json::from_str(&contents)
        .wrap_err_with(|| format!("failed to parse {}", args.input.display()))?;

    let signer: PrivateKeySigner = args
        .private_key
        .parse()
        .map_err(|e| eyre!("failed to parse private key: {e}"))?;
    let sender = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect(&args.rpc_url)
        .await
        .wrap_err_with(|| format!("failed to connect to RPC at {}", args.rpc_url))?
        .erased();

    let chain_id = provider.get_chain_id().await?;
    eyre::ensure!(
        chain_id == file.chain_id,
        "chain id mismatch: RPC reports {chain_id}, file was fetched on {}",
        file.chain_id
    );
    let registry = WorldIdRegistryV2::new(file.registry, provider);

    tracing::info!(
        registry = %file.registry,
        entries = file.pending.len(),
        %sender,
        dry_run = args.dry_run,
        "starting legacy recovery agent update migration"
    );

    let (mut migrated, mut skipped, mut failed) = (0usize, 0usize, 0usize);
    for entry in &file.pending {
        let leaf_index = entry.leaf_index;
        let call = registry.migrateLegacyRecoveryAgentUpdate(leaf_index);

        // Simulate first: `NoPendingRecoveryAgentUpdate` means the legacy entry
        // was cleared since fetch (migrated, updated, or recovered) — skip so
        // re-runs are idempotent. Any other revert is a real failure.
        if let Err(e) = call.call().await {
            let no_pending = e
                .as_decoded_interface_error::<WorldIdRegistryV2Errors>()
                .is_some_and(|err| {
                    matches!(
                        err,
                        WorldIdRegistryV2Errors::NoPendingRecoveryAgentUpdate(_)
                    )
                });
            if no_pending {
                tracing::info!(leaf_index, "no pending legacy update on-chain, skipping");
                skipped += 1;
            } else {
                tracing::error!(leaf_index, error = %e, "migration would revert");
                failed += 1;
            }
            continue;
        }

        if args.dry_run {
            tracing::info!(leaf_index, "dry-run: migration would succeed");
            migrated += 1;
            continue;
        }

        let result = async {
            let receipt = call
                .send()
                .await
                .wrap_err("failed to send transaction")?
                .get_receipt()
                .await
                .wrap_err("failed to fetch receipt")?;
            eyre::ensure!(
                receipt.status(),
                "transaction {} reverted",
                receipt.transaction_hash
            );
            Ok::<_, eyre::Report>(receipt.transaction_hash)
        }
        .await;

        match result {
            Ok(tx_hash) => {
                tracing::info!(leaf_index, %tx_hash, "migrated");
                migrated += 1;
            }
            Err(e) => {
                tracing::error!(leaf_index, error = %e, "migration failed");
                failed += 1;
            }
        }
    }

    tracing::info!(migrated, skipped, failed, "migration run complete");
    eyre::ensure!(failed == 0, "{failed} migrations failed, see logs above");
    Ok(())
}
