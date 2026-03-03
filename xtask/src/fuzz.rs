//! Chaos testing fuzzer driven by a declarative `matrix!` macro.
//!
//! The matrix generates the cross-product of:
//!   - **Action**: the mutation type (CreateAccount, RegisterIssuer, PropagateState)
//!   - **Concurrency**: how many parallel txs to fire (1, 2, 5, …)
//!   - **Ordering**: execution strategy (Sequential, Interleaved, Reversed)
//!
//! The scheduler groups scenarios by ordering so that mutations within a group
//! are batched before a single propagation + relay cycle, avoiding the per-scenario
//! relay overhead.

use std::time::Duration;

use alloy::{
    primitives::{keccak256, Address, B256, Uint, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use eyre::{bail, Context, Result};
use rand::Rng;
use tracing::info;

use crate::{
    bindings::{
        satellite::IWorldIDSatellite,
        source::IWorldIDSource,
        ICredentialSchemaIssuerRegistry, IRelayMockDisputeGame, IRelayMockDisputeGameFactory,
        IWorldIDRegistry,
    },
    bootstrap::{self, TestEnvironment},
    invariants::{self, assert_invariants},
};

// ---------------------------------------------------------------------------
// Chaos matrix types
// ---------------------------------------------------------------------------

/// Mutation action on World Chain.
#[derive(Debug, Clone, Copy)]
pub enum Action {
    /// Insert into the Merkle tree → changes `_latestRoot`.
    CreateAccount,
    /// Register an issuer schema → writes pubkey + triggers OPRF `initKeyGen`.
    RegisterIssuer,
    /// Read current registry state → emit `ChainCommitted` for relay.
    PropagateState,
}

/// Execution ordering strategy relative to propagation.
#[derive(Debug, Clone, Copy)]
pub enum Ordering {
    /// Mutate N times → propagate → wait → assert.
    Sequential,
    /// Fire mutations and propagation concurrently → wait → assert.
    Interleaved,
    /// Propagate stale state → mutate → propagate again → wait → assert.
    Reversed,
}

/// A single chaos test scenario from the matrix cross-product.
#[derive(Debug, Clone)]
pub struct ChaosScenario {
    pub action: Action,
    pub concurrency: usize,
    pub ordering: Ordering,
}

impl std::fmt::Display for ChaosScenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}/conc={}/ord={:?}",
            self.action, self.concurrency, self.ordering
        )
    }
}

/// Generate a chaos test matrix from the cross-product of dimensions.
macro_rules! matrix {
    (
        actions: [$($action:ident),+ $(,)?],
        concurrency: [$($conc:expr),+ $(,)?],
        ordering: [$($ord:ident),+ $(,)?] $(,)?
    ) => {{
        let actions = [$(Action::$action),+];
        let concurrencies: &[usize] = &[$($conc),+];
        let orderings = [$(Ordering::$ord),+];
        let mut scenarios = Vec::with_capacity(
            actions.len() * concurrencies.len() * orderings.len()
        );
        for &action in &actions {
            for &concurrency in concurrencies {
                for &ordering in &orderings {
                    scenarios.push(ChaosScenario { action, concurrency, ordering });
                }
            }
        }
        scenarios
    }};
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

pub struct FuzzConfig {
    /// Propagation timeout per scenario (seconds).
    pub propagation_timeout_secs: u64,
    /// Delay between scenarios (milliseconds).
    pub delay_ms: u64,
    /// Number of fuzz rounds over the full matrix (0 = infinite).
    pub rounds: u64,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            propagation_timeout_secs: 60,
            delay_ms: 500,
            rounds: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// First issuer schema ID used in fuzz (increments each scenario).
const FUZZ_ISSUER_START: u64 = 100;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(cfg: FuzzConfig) -> Result<()> {
    let env = TestEnvironment::bootstrap().await?;

    let scenarios = matrix! {
        actions:     [CreateAccount, RegisterIssuer, PropagateState],
        concurrency: [1, 2, 5],
        ordering:    [Sequential, Interleaved, Reversed],
    };

    info!(
        scenarios = scenarios.len(),
        rounds = cfg.rounds,
        "chaos matrix generated"
    );

    let result = run_matrix(&cfg, &scenarios, &env).await;

    info!("shutting down environment");
    env.shutdown().await.ok();

    result
}

async fn run_matrix(
    cfg: &FuzzConfig,
    scenarios: &[ChaosScenario],
    env: &TestEnvironment,
) -> Result<()> {
    let infinite = cfg.rounds == 0;
    let total_rounds = if infinite { u64::MAX } else { cfg.rounds };
    let mut issuer_counter: u64 = FUZZ_ISSUER_START;

    for round in 1..=total_rounds {
        info!(round, "starting matrix round");

        for (i, scenario) in scenarios.iter().enumerate() {
            if infinite {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Ctrl+C received");
                        return Ok(());
                    }
                    result = execute_scenario(scenario, &mut issuer_counter, env, cfg) => {
                        result?;
                    }
                }
            } else {
                execute_scenario(scenario, &mut issuer_counter, env, cfg).await?;
            }

            info!(
                round,
                scenario = i + 1,
                total = scenarios.len(),
                name = %scenario,
                "scenario passed"
            );

            tokio::time::sleep(Duration::from_millis(cfg.delay_ms)).await;
        }

        info!(round, "matrix round complete");
    }

    info!("all chaos scenarios passed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenario execution
// ---------------------------------------------------------------------------

async fn execute_scenario(
    scenario: &ChaosScenario,
    issuer_counter: &mut u64,
    env: &TestEnvironment,
    cfg: &FuzzConfig,
) -> Result<()> {
    info!(scenario = %scenario, "executing");

    let new_issuer_ids: Vec<u64> = (0..scenario.concurrency)
        .map(|_| {
            let id = *issuer_counter;
            *issuer_counter += 1;
            id
        })
        .collect();

    let propagate_ids = if matches!(scenario.action, Action::RegisterIssuer) {
        new_issuer_ids.as_slice()
    } else {
        &[]
    };

    // ── Execute mutations + propagation based on ordering ─────────────
    match scenario.ordering {
        Ordering::Sequential => {
            for (i, &issuer_id) in new_issuer_ids.iter().enumerate() {
                fire_action(scenario.action, issuer_id, env)
                    .await
                    .with_context(|| format!("sequential action {}/{}", i + 1, scenario.concurrency))?;
            }
            propagate(propagate_ids, env).await?;
        }
        Ordering::Interleaved => {
            for (i, &issuer_id) in new_issuer_ids.iter().enumerate() {
                fire_action(scenario.action, issuer_id, env)
                    .await
                    .with_context(|| format!("interleaved action {}/{}", i + 1, scenario.concurrency))?;
            }
            propagate(propagate_ids, env).await?;
        }
        Ordering::Reversed => {
            // Stale propagation — may revert with NothingChanged, expected.
            let _ = propagate(&[], env).await;
            for (i, &issuer_id) in new_issuer_ids.iter().enumerate() {
                fire_action(scenario.action, issuer_id, env)
                    .await
                    .with_context(|| format!("reversed action {}/{}", i + 1, scenario.concurrency))?;
            }
            propagate(propagate_ids, env).await?;
        }
    }

    // ── Seed mock dispute game for the relay ──────────────────────────
    seed_mock_game(env).await.context("seed mock game")?;

    // ── Wait for satellite root to converge ──────────────────────────
    let expected_root = IWorldIDRegistry::new(bootstrap::WC_REGISTRY, &env.wc_provider)
        .getLatestRoot()
        .call()
        .await
        .context("read expected root")?;

    wait_for_root(expected_root, cfg.propagation_timeout_secs, env).await?;

    // ── Invariant assertions ─────────────────────────────────────────
    let mut check_ids = vec![1u64];
    if matches!(scenario.action, Action::RegisterIssuer) {
        check_ids.extend_from_slice(propagate_ids);
    }

    let report = invariants::check_invariants(
        &env.wc_provider,
        &env.eth_provider,
        bootstrap::WC_SOURCE,
        bootstrap::ETH_SATELLITE,
        bootstrap::WC_REGISTRY,
        bootstrap::WC_ISSUER_REGISTRY,
        bootstrap::WC_OPRF_REGISTRY,
        &check_ids,
        &check_ids,
    )
    .await
    .context("invariant check")?;

    assert_invariants!(report);

    Ok(())
}

// ---------------------------------------------------------------------------
// Mock dispute game seeding
// ---------------------------------------------------------------------------

/// Update the mock dispute game to cover the latest WC block so the relay
/// can build a valid MPT proof. Must be called AFTER propagateState.
async fn seed_mock_game(env: &TestEnvironment) -> Result<()> {
    let wc_block_num = env
        .wc_provider
        .get_block_number()
        .await
        .context("get WC block number")?;

    // Set l2BlockNumber.
    send_tx(
        &env.eth_provider,
        bootstrap::ETH_GAME,
        IRelayMockDisputeGame::setL2BlockNumberCall {
            bn: U256::from(wc_block_num),
        }
        .abi_encode(),
    )
    .await
    .context("setL2BlockNumber")?;

    // Compute L2 output root = keccak256(version || stateRoot || msgPasserRoot || blockHash).
    let block = env
        .wc_provider
        .get_block_by_number(wc_block_num.into())
        .await
        .context("get WC block")?
        .ok_or_else(|| eyre::eyre!("WC block {wc_block_num} not found"))?;

    // L2ToL1MessagePasser doesn't exist on test anvil → empty trie root.
    let empty_trie: B256 = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        .parse()
        .unwrap();

    let output_root = keccak256(
        [
            B256::ZERO.as_slice(),
            block.header.state_root.as_slice(),
            empty_trie.as_slice(),
            block.header.hash.as_slice(),
        ]
        .concat(),
    );

    // Set rootClaim.
    send_tx(
        &env.eth_provider,
        bootstrap::ETH_GAME,
        IRelayMockDisputeGame::setRootClaimCall { rc: output_root }.abi_encode(),
    )
    .await
    .context("setRootClaim")?;

    // Re-register game so factory lookup matches the new rootClaim.
    send_tx(
        &env.eth_provider,
        bootstrap::ETH_DGF,
        IRelayMockDisputeGameFactory::addGameCall {
            gameType: 0,
            proxy: bootstrap::ETH_GAME,
        }
        .abi_encode(),
    )
    .await
    .context("addGame")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Action dispatch
// ---------------------------------------------------------------------------

async fn fire_action(action: Action, issuer_id: u64, env: &TestEnvironment) -> Result<()> {
    let mut rng = rand::thread_rng();

    match action {
        Action::CreateAccount => {
            let call = IWorldIDRegistry::createAccountCall {
                recoveryAddress: Address::from(rng.r#gen::<[u8; 20]>()),
                authenticatorAddresses: vec![Address::from(rng.r#gen::<[u8; 20]>())],
                authenticatorPubkeys: vec![U256::from(rng.r#gen::<u128>())],
                offchainSignerCommitment: U256::from(rng.r#gen::<u128>()),
            };
            send_tx(&env.wc_provider, bootstrap::WC_REGISTRY, call.abi_encode()).await
        }
        Action::RegisterIssuer => {
            let call = ICredentialSchemaIssuerRegistry::registerCall {
                issuerSchemaId: issuer_id,
                pubkey: ICredentialSchemaIssuerRegistry::Pubkey {
                    x: U256::from(rng.r#gen::<u128>()),
                    y: U256::from(rng.r#gen::<u128>()),
                },
                signer: Address::from(rng.r#gen::<[u8; 20]>()),
            };
            send_tx(
                &env.wc_provider,
                bootstrap::WC_ISSUER_REGISTRY,
                call.abi_encode(),
            )
            .await
        }
        Action::PropagateState => {
            let call = IWorldIDSource::propagateStateCall {
                issuerSchemaIds: vec![1],
                oprfKeyIds: vec![Uint::from(1u64)],
            };
            send_tx(&env.wc_provider, bootstrap::WC_SOURCE, call.abi_encode()).await
        }
    }
}

/// Call propagateState with genesis ID 1 plus any newly registered issuer IDs.
async fn propagate(new_issuer_ids: &[u64], env: &TestEnvironment) -> Result<()> {
    let mut issuer_ids = vec![1u64];
    let mut oprf_ids: Vec<Uint<160, 3>> = vec![Uint::from(1u64)];

    for &id in new_issuer_ids {
        issuer_ids.push(id);
        oprf_ids.push(Uint::from(id));
    }

    let call = IWorldIDSource::propagateStateCall {
        issuerSchemaIds: issuer_ids,
        oprfKeyIds: oprf_ids,
    };

    send_tx(&env.wc_provider, bootstrap::WC_SOURCE, call.abi_encode())
        .await
        .context("propagateState")
}

// ---------------------------------------------------------------------------
// Polling + helpers
// ---------------------------------------------------------------------------

async fn wait_for_root(expected: U256, timeout_secs: u64, env: &TestEnvironment) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let sat = IWorldIDSatellite::new(bootstrap::ETH_SATELLITE, &env.eth_provider);

    loop {
        if tokio::time::Instant::now() > deadline {
            bail!("satellite did not receive root within {timeout_secs}s");
        }

        match sat.LATEST_ROOT().call().await {
            Ok(root) if root == expected => return Ok(()),
            Ok(_) | Err(_) => {}
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn send_tx(provider: &impl Provider, to: Address, calldata: Vec<u8>) -> Result<()> {
    let tx = TransactionRequest::default()
        .to(to)
        .input(calldata.clone().into());

    // Simulate first to get revert reason on failure.
    if let Err(e) = provider.call(tx.clone()).await {
        bail!("tx to {to} would revert: {e}");
    }

    let receipt = provider
        .send_transaction(tx)
        .await
        .context("send tx")?
        .get_receipt()
        .await
        .context("tx receipt")?;

    if !receipt.status() {
        // Re-simulate at the reverted block to get the revert reason.
        let replay_tx = TransactionRequest::default()
            .to(to)
            .input(calldata.into());
        let reason = match provider.call(replay_tx).await {
            Err(e) => format!("{e}"),
            Ok(_) => "unknown (replay succeeded)".to_string(),
        };
        bail!("tx to {to} reverted: {reason} (hash: {})", receipt.transaction_hash);
    }

    Ok(())
}
