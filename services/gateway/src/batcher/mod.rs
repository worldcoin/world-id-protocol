//! Self-healing batch executor.
//!
//! Batches retry until terminal: Finalized or Exhausted.

mod chain;
pub mod gas_policy;

use chain::{ChainMonitor, ChainMonitorConfig};
pub use gas_policy::{GasPolicy, GasPolicyConfig, GasPolicyTrait};

use alloy::primitives::{address, Address, U256};
use alloy::providers::{DynProvider, Provider};
use backon::{ExponentialBuilder, Retryable};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{timeout, Instant};
use tracing::{debug, error};
use uuid::Uuid;
use world_id_core::types::parse_contract_error;

use crate::storage::RequestTracker;
use world_id_core::types::{CreateAccountRequest, GatewayErrorCode, GatewayRequestState};
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

// ═══════════════════════════════════════════════════════════════════════════════
// MULTICALL3
// ═══════════════════════════════════════════════════════════════════════════════

const MULTICALL3: Address = address!("0xca11bde05977b3631167028862be2a173976ca11");

alloy::sol! {
    #[sol(rpc)]
    contract Multicall3 {
        struct Call3 { address target; bool allowFailure; bytes callData; }
        struct Result { bool success; bytes returnData; }
        function aggregate3(Call3[] calldata calls) payable returns (Result[] memory);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHAIN STATE
// ═══════════════════════════════════════════════════════════════════════════════

/// Chain state for gas policy decisions.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub block_number: u64,
    pub base_fee: u64,
    pub base_fee_ema: f64,
    /// Base fee trend in [-1, 1] where -1 = falling, +1 = rising.
    pub base_fee_trend: f64,
    pub block_gas_limit: u64,
    pub recent_utilization: f64,
    pub last_updated: Instant,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            block_number: 0,
            base_fee: 0,
            base_fee_ema: 0.0,
            base_fee_trend: 0.0,
            block_gas_limit: 30_000_000,
            recent_utilization: 0.5,
            last_updated: Instant::now(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

use alloy::primitives::Bytes;

/// Default gas estimates for operation types.
pub const GAS_CREATE_ACCOUNT: u64 = 150_000;
pub const GAS_DEFAULT_OP: u64 = 200_000;

/// Batching Operations.
#[derive(Debug, Clone)]
pub enum Command {
    CreateAccount {
        id: Uuid,
        request: CreateAccountRequest,
        gas: u64,
        received_at: Instant,
    },
    Operation {
        id: Uuid,
        calldata: Bytes,
        gas: u64,
        received_at: Instant,
    },
}

impl Command {
    /// Create a CreateAccount command.
    pub fn create_account(id: Uuid, request: CreateAccountRequest, gas: u64) -> Self {
        Self::CreateAccount {
            id,
            request,
            gas,
            received_at: Instant::now(),
        }
    }

    /// Create an operation command from raw calldata.
    pub fn operation(id: Uuid, calldata: Bytes, gas: u64) -> Self {
        Self::Operation {
            id,
            calldata,
            gas,
            received_at: Instant::now(),
        }
    }

    /// Get the command ID.
    pub fn id(&self) -> Uuid {
        match self {
            Self::CreateAccount { id, .. } => *id,
            Self::Operation { id, .. } => *id,
        }
    }

    /// Get the gas estimate.
    pub fn gas(&self) -> u64 {
        match self {
            Self::CreateAccount { gas, .. } => *gas,
            Self::Operation { gas, .. } => *gas,
        }
    }
}

/// Handle for submitting commands to the batcher.
#[derive(Clone)]
pub struct Commands {
    command: mpsc::Sender<Command>,
}

impl Commands {
    /// Submit a command to the batcher.
    pub async fn submit(&self, cmd: Command) -> bool {
        self.command.send(cmd).await.is_ok()
    }
}

// Re-export for backwards compatibility
pub type BatcherHandle = Commands;

/// Configuration for the batcher.
#[derive(Clone)]
pub struct BatcherConfig {
    /// How long to wait before processing a batch.
    pub batch_window: Duration,
    /// Gas policy configuration.
    pub gas_policy: GasPolicyConfig,
    /// Chain monitor configuration.
    pub chain_monitor: ChainMonitorConfig,
}

impl Default for BatcherConfig {
    fn default() -> Self {
        Self {
            batch_window: Duration::from_millis(2000),
            gas_policy: GasPolicyConfig::default(),
            chain_monitor: ChainMonitorConfig::default(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCHER
// ═══════════════════════════════════════════════════════════════════════════════

/// Dual-queue batcher with priority for createAccount operations.
pub struct Batcher<G: GasPolicyTrait = GasPolicy> {
    /// Single receiver for all commands
    rx: mpsc::Receiver<Command>,
    /// Queue for createAccount operations (priority)
    create_queue: Vec<Command>,
    /// Queue for other operations
    ops_queue: Vec<Command>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    tracker: RequestTracker,
    chain_monitor: Arc<ChainMonitor<DynProvider>>,
    gas_policy: G,
    config: BatcherConfig,
    shutdown: broadcast::Sender<()>,
}

impl<G: GasPolicyTrait> Batcher<G> {
    pub fn new(
        provider: Arc<DynProvider>,
        registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
        tracker: RequestTracker,
        config: BatcherConfig,
        gas_policy: G,
    ) -> (Commands, Self) {
        let (tx, rx) = mpsc::channel(10_000);
        let (shutdown, _) = broadcast::channel(1);

        let chain_monitor = ChainMonitor::new(provider.clone(), config.chain_monitor.clone());

        let batcher = Self {
            rx,
            create_queue: Vec::new(),
            ops_queue: Vec::new(),
            registry,
            tracker,
            chain_monitor,
            gas_policy,
            config,
            shutdown,
        };

        (Commands { command: tx }, batcher)
    }

    pub async fn run(mut self) {
        // Spawn chain monitor
        let monitor = self.chain_monitor.clone();
        let shutdown_rx = self.shutdown.subscribe();
        tokio::spawn(async move {
            if let Err(e) = monitor.run(shutdown_rx).await {
                tracing::error!(target: "world_id_gateway::batcher", error = %e, "chain monitor error");
            }
        });

        let mut timer = tokio::time::interval(self.config.batch_window);

        tracing::info!(
            target: "world_id_gateway::batcher",
            batch_window_ms = self.config.batch_window.as_millis(),
            "Batcher started"
        );

        loop {
            tokio::select! {
                biased;

                _ = timer.tick() => {
                    self.process_batches().await;
                }

                Some(cmd) = self.rx.recv() => {
                    match &cmd {
                        Command::CreateAccount { .. } => self.create_queue.push(cmd),
                        Command::Operation { .. } => self.ops_queue.push(cmd),
                    }
                    self.check_gas_capacity().await;
                }
            }
        }
    }

    async fn check_gas_capacity(&mut self) {
        let state = self.chain_monitor.current_state();
        let total_ops = self.create_queue.len() + self.ops_queue.len();
        let params = self.gas_policy.compute_batch_params(&state, total_ops);

        let total_gas: u64 = self
            .create_queue
            .iter()
            .chain(self.ops_queue.iter())
            .map(|c| c.gas())
            .sum();

        if params.gas_budget > 0 && total_gas >= params.gas_budget {
            self.process_batches().await;
        }
    }

    async fn process_batches(&mut self) {
        let state = self.chain_monitor.current_state();
        let total_ops = self.create_queue.len() + self.ops_queue.len();
        let params = self.gas_policy.compute_batch_params(&state, total_ops);

        if params.gas_budget == 0 {
            return;
        }

        let mut remaining_gas = params.gas_budget;

        // Priority 1: Process createAccount operations
        if !self.create_queue.is_empty() {
            let (batch, leftover_gas) = self.drain_create_batch(remaining_gas);
            if !batch.is_empty() {
                remaining_gas = leftover_gas;
                self.spawn_create_batch(batch);
            }
        }

        // Priority 2: Process other operations with remaining gas
        if !self.ops_queue.is_empty() && remaining_gas > 0 {
            let batch = self.drain_ops_batch(remaining_gas);
            if !batch.is_empty() {
                self.spawn_ops_batch(batch);
            }
        }
    }

    fn drain_create_batch(&mut self, gas_budget: u64) -> (Vec<Command>, u64) {
        let mut batch = Vec::new();
        let mut used_gas = 0u64;

        while let Some(cmd) = self.create_queue.first() {
            if used_gas + cmd.gas() > gas_budget {
                break;
            }
            let cmd = self.create_queue.remove(0);
            used_gas += cmd.gas();
            batch.push(cmd);
        }

        (batch, gas_budget.saturating_sub(used_gas))
    }

    fn drain_ops_batch(&mut self, gas_budget: u64) -> Vec<Command> {
        let mut batch = Vec::new();
        let mut used_gas = 0u64;

        while let Some(cmd) = self.ops_queue.first() {
            if used_gas + cmd.gas() > gas_budget {
                break;
            }
            let cmd = self.ops_queue.remove(0);
            used_gas += cmd.gas();
            batch.push(cmd);
        }

        batch
    }

    fn spawn_create_batch(&self, batch: Vec<Command>) {
        let registry = self.registry.clone();
        let tracker = self.tracker.clone();

        tokio::spawn(async move {
            execute_create_batch(batch, registry, tracker).await;
        });
    }

    fn spawn_ops_batch(&self, batch: Vec<Command>) {
        let provider = self.registry.provider().clone();
        let target = *self.registry.address();
        let tracker = self.tracker.clone();
        let retry = RetryConfig::default();

        tokio::spawn(async move {
            execute_ops_batch(batch, provider, target, tracker, &retry).await;
        });
    }
}

/// Configuration for retry behavior with exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_retries: usize,
    /// Initial delay between retries.
    pub min_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Multiplier for exponential backoff (default 2.0).
    pub factor: f32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 10,
            min_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            factor: 2.0,
        }
    }
}

impl RetryConfig {
    /// Build a backon ExponentialBuilder from this config.
    pub fn backoff(&self) -> ExponentialBuilder {
        ExponentialBuilder::default()
            .with_min_delay(self.min_delay)
            .with_max_delay(self.max_delay)
            .with_factor(self.factor)
            .with_max_times(self.max_retries)
    }
}

/// Execute a batch of createAccount operations using `createManyAccounts`.
async fn execute_create_batch(
    commands: Vec<Command>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    tracker: RequestTracker,
) {
    // Extract typed CreateAccountRequest data from commands
    let mut ids = Vec::with_capacity(commands.len());
    let mut recovery_addresses = Vec::with_capacity(commands.len());
    let mut authenticator_addresses = Vec::with_capacity(commands.len());
    let mut authenticator_pubkeys = Vec::with_capacity(commands.len());
    let mut offchain_signer_commitments = Vec::with_capacity(commands.len());

    for cmd in commands {
        match cmd {
            Command::CreateAccount { id, request, .. } => {
                ids.push(id.to_string());
                recovery_addresses.push(request.recovery_address.unwrap_or(Address::ZERO));
                authenticator_addresses.push(request.authenticator_addresses.clone());
                authenticator_pubkeys.push(request.authenticator_pubkeys.clone());
                offchain_signer_commitments.push(request.offchain_signer_commitment);
            }
            Command::Operation { .. } => {
                tracing::warn!(target: "world_id_gateway::batcher", "non-createAccount command in create batch");
            }
        }
    }

    if ids.is_empty() {
        return;
    }

    // Mark as batching
    tracker
        .set_status_batch(&ids, GatewayRequestState::Batching)
        .await;

    // Submit createManyAccounts
    let tx_hash = match submit_create_many(
        &registry,
        recovery_addresses,
        authenticator_addresses,
        authenticator_pubkeys,
        offchain_signer_commitments,
    )
    .await
    {
        Ok(hash) => hash,
        Err(e) => {
            let code = parse_contract_error(&e);
            tracing::error!(target: "world_id_gateway::batcher", %e, "createManyAccounts failed");
            tracker
                .set_status_batch(&ids, GatewayRequestState::failed(&e, Some(code)))
                .await;
            return;
        }
    };

    let hash_str = format!("{tx_hash:#x}");
    tracker
        .set_status_batch(
            &ids,
            GatewayRequestState::Submitted {
                tx_hash: hash_str.clone(),
            },
        )
        .await;

    match await_receipt(registry.provider(), tx_hash).await {
        Ok(true) => {
            tracker
                .set_status_batch(&ids, GatewayRequestState::Finalized { tx_hash: hash_str })
                .await;
            debug!(target: "world_id_gateway::batcher", %tx_hash, count = ids.len(), "create batch finalized");
        }
        Ok(false) => {
            tracker
                .set_status_batch(
                    &ids,
                    GatewayRequestState::failed(
                        format!("transaction reverted on-chain (tx: {hash_str})"),
                        Some(GatewayErrorCode::TransactionReverted),
                    ),
                )
                .await;
        }
        Err(e) => {
            error!(target: "world_id_gateway::batcher", %e, "receipt fetch failed");
            tracker
                .set_status_batch(
                    &ids,
                    GatewayRequestState::failed(&e, Some(GatewayErrorCode::ConfirmationError)),
                )
                .await;
        }
    }
}

/// Submit createManyAccounts with retry.
async fn submit_create_many(
    registry: &Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    recovery_addresses: Vec<Address>,
    authenticator_addresses: Vec<Vec<Address>>,
    authenticator_pubkeys: Vec<Vec<U256>>,
    offchain_signer_commitments: Vec<U256>,
) -> Result<alloy::primitives::TxHash, String> {
    registry
        .createManyAccounts(
            recovery_addresses,
            authenticator_addresses,
            authenticator_pubkeys,
            offchain_signer_commitments,
        )
        .send()
        .await
        .map(|pending| *pending.tx_hash())
        .map_err(|e| e.to_string())
}

/// Execute a batch of operations using Multicall3.
async fn execute_ops_batch(
    mut commands: Vec<Command>,
    provider: Arc<DynProvider>,
    target: Address,
    tracker: RequestTracker,
    retry: &RetryConfig,
) {
    let mc = Multicall3::new(MULTICALL3, provider.clone());

    loop {
        // 1. Simulate with allowFailure=true to identify failing ops
        let calls = build_multicalls_from_commands(&commands, target, true);
        let results = match simulate_multicall(&mc, calls, retry).await {
            Ok(r) => r,
            Err(e) => {
                fail_command_batch(
                    &commands,
                    &tracker,
                    &e,
                    GatewayErrorCode::InternalServerError,
                )
                .await;
                return;
            }
        };

        // 2. Evict invalid ops
        commands = evict_failed_commands(commands, &results, &tracker).await;
        if commands.is_empty() {
            tracing::debug!(target: "world_id_gateway::batcher", "batch exhausted");
            return;
        }

        let calls = build_multicalls_from_commands(&commands, target, false);
        let tx_hash = match submit_multicall(&mc, calls, retry).await {
            Ok(hash) => hash,
            Err(e) => {
                fail_command_batch(
                    &commands,
                    &tracker,
                    &e,
                    GatewayErrorCode::InternalServerError,
                )
                .await;
                return;
            }
        };

        let ids: Vec<_> = commands.iter().map(|c| c.id().to_string()).collect();
        let hash_str = format!("{tx_hash:#x}");
        tracker
            .set_status_batch(
                &ids,
                GatewayRequestState::Submitted {
                    tx_hash: hash_str.clone(),
                },
            )
            .await;

        match await_receipt(&provider, tx_hash).await {
            Ok(true) => {
                tracker
                    .set_status_batch(&ids, GatewayRequestState::Finalized { tx_hash: hash_str })
                    .await;
                tracing::info!(target: "world_id_gateway::batcher", %tx_hash, count = ids.len(), "batch finalized");
                return;
            }
            Ok(false) => {
                tracing::warn!(target: "world_id_gateway::batcher", %tx_hash, "batch reverted, re-simulating");
                // Loop continues to re-simulate and evict the bad op
            }
            Err(e) => {
                tracing::error!(target: "world_id_gateway::batcher", %e, "receipt fetch failed");
                return;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRANSACTION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Wait for transaction receipt and return success status.
async fn await_receipt(
    provider: &Arc<DynProvider>,
    tx_hash: alloy::primitives::TxHash,
) -> Result<bool, String> {
    let fut = async {
        loop {
            match provider.get_transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => return Ok(receipt.status()),
                Ok(None) => tokio::time::sleep(Duration::from_millis(500)).await,
                Err(e) => return Err(e.to_string()),
            }
        }
    };

    let res = timeout(Duration::from_secs(120), fut).await;
    res.map_err(|e| e.to_string())?
}

fn build_multicalls_from_commands(
    commands: &[Command],
    target: Address,
    allow_failure: bool,
) -> Vec<Multicall3::Call3> {
    commands
        .iter()
        .filter_map(|cmd| match cmd {
            Command::Operation { calldata, .. } => Some(Multicall3::Call3 {
                target,
                allowFailure: allow_failure,
                callData: calldata.clone(),
            }),
            Command::CreateAccount { .. } => None,
        })
        .collect()
}

async fn simulate_multicall(
    mc: &Multicall3::Multicall3Instance<Arc<DynProvider>>,
    calls: Vec<Multicall3::Call3>,
    retry: &RetryConfig,
) -> Result<Vec<Multicall3::Result>, String> {
    let mc = mc.clone();
    (move || {
        let mc = mc.clone();
        let calls = calls.clone();
        async move {
            let result = mc
                .aggregate3(calls)
                .call()
                .await
                .map_err(|e: alloy::contract::Error| e.to_string())?;
            Ok(result)
        }
    })
    .retry(retry.backoff())
    .await
}

async fn submit_multicall(
    mc: &Multicall3::Multicall3Instance<Arc<DynProvider>>,
    calls: Vec<Multicall3::Call3>,
    retry: &RetryConfig,
) -> Result<alloy::primitives::TxHash, String> {
    let mc = mc.clone();
    (move || {
        let mc = mc.clone();
        let calls = calls.clone();
        async move {
            mc.aggregate3(calls)
                .send()
                .await
                .map(|pending| *pending.tx_hash())
                .map_err(|e| e.to_string())
        }
    })
    .retry(retry.backoff())
    .await
}

async fn evict_failed_commands(
    commands: Vec<Command>,
    results: &[Multicall3::Result],
    tracker: &RequestTracker,
) -> Vec<Command> {
    let mut valid = Vec::with_capacity(commands.len());

    for (cmd, result) in commands.into_iter().zip(results.iter()) {
        if result.success {
            valid.push(cmd);
        } else {
            let error_hex = format!("0x{}", hex::encode(&result.returnData));
            let code = parse_contract_error(&error_hex);
            tracing::debug!(target: "world_id_gateway::batcher", id = %cmd.id(), %error_hex, "op evicted");
            tracker
                .set_status(
                    &cmd.id().to_string(),
                    GatewayRequestState::failed(&error_hex, Some(code)),
                )
                .await;
        }
    }

    valid
}

async fn fail_command_batch(
    commands: &[Command],
    tracker: &RequestTracker,
    error: &str,
    code: GatewayErrorCode,
) {
    let ids: Vec<_> = commands.iter().map(|c| c.id().to_string()).collect();
    tracing::error!(target: "world_id_gateway::batcher", %error, "batch failed");
    tracker
        .set_status_batch(&ids, GatewayRequestState::failed(error, Some(code)))
        .await;
}
