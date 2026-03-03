//! Cross-chain invariant assertions.
//!
//! Compares World Chain source state against satellite state on destination
//! chains to verify the relay propagated everything correctly.

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use eyre::Result;
use tracing::{error, info};

use crate::bindings::{
    satellite::IWorldIDSatellite, ICredentialSchemaIssuerRegistry, IOprfKeyRegistry,
    IWorldIDRegistry,
};

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// Result of a single issuer pubkey invariant check.
#[allow(dead_code)]
pub struct IssuerCheck {
    pub key_id: u64,
    pub source: (U256, U256),
    pub satellite: (U256, U256),
    pub matches: bool,
}

/// Result of a single OPRF key invariant check.
#[allow(dead_code)]
pub struct OprfCheck {
    pub key_id: u64,
    pub source: (U256, U256),
    pub satellite: (U256, U256),
    pub matches: bool,
}

/// Aggregated invariant report from a single check pass.
#[allow(dead_code)]
pub struct InvariantReport {
    pub root_match: bool,
    pub issuer_checks: Vec<IssuerCheck>,
    pub oprf_checks: Vec<OprfCheck>,
    pub failures: Vec<String>,
}

impl InvariantReport {
    /// Returns `true` when every invariant held.
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Assertion macro
// ---------------------------------------------------------------------------

/// Bail with structured error logging when invariants fail.
macro_rules! assert_invariants {
    ($report:expr) => {
        if !$report.passed() {
            for f in &$report.failures {
                tracing::error!(failure = %f);
            }
            eyre::bail!(
                "invariant check failed: {} failure(s)",
                $report.failures.len()
            );
        }
    };
}

pub(crate) use assert_invariants;

// ---------------------------------------------------------------------------
// Core check function
// ---------------------------------------------------------------------------

/// Run all invariant checks between WC source contracts and an ETH satellite.
///
/// Reads state from both chains and compares roots, issuer pubkeys, and OPRF
/// keys. Returns a structured report; callers decide whether to bail.
#[allow(clippy::too_many_arguments)]
pub async fn check_invariants(
    wc_provider: &DynProvider,
    eth_provider: &DynProvider,
    _source_proxy: Address,
    satellite_proxy: Address,
    registry: Address,
    issuer_registry: Address,
    oprf_registry: Address,
    issuer_ids: &[u64],
    oprf_key_ids: &[u64],
) -> Result<InvariantReport> {
    let mut failures = Vec::new();

    // -- Root --
    let wc_root = IWorldIDRegistry::new(registry, wc_provider)
        .getLatestRoot()
        .call()
        .await?;

    let sat_root = IWorldIDSatellite::new(satellite_proxy, eth_provider)
        .LATEST_ROOT()
        .call()
        .await?;

    let root_match = wc_root == sat_root;
    if !root_match {
        let msg = format!("root mismatch: source={wc_root}, satellite={sat_root}");
        error!(%wc_root, %sat_root, "root invariant violated");
        failures.push(msg);
    }

    // -- Issuer pubkeys --
    let wc_issuer = ICredentialSchemaIssuerRegistry::new(issuer_registry, wc_provider);
    let sat = IWorldIDSatellite::new(satellite_proxy, eth_provider);

    let mut issuer_checks = Vec::with_capacity(issuer_ids.len());
    for &key_id in issuer_ids {
        let src = wc_issuer
            .issuerSchemaIdToPubkey(key_id)
            .call()
            .await?;

        let dst = sat
            .issuerSchemaIdToPubkeyAndProofId(key_id)
            .call()
            .await?;

        let source = (src.x, src.y);
        let satellite = (dst.pubKeyX, dst.pubKeyY);
        let matches = source == satellite;

        if !matches {
            let msg = format!(
                "issuer key_id={key_id} mismatch: source=({}, {}), satellite=({}, {})",
                src.x, src.y, dst.pubKeyX, dst.pubKeyY,
            );
            error!(key_id, "issuer invariant violated");
            failures.push(msg);
        }

        issuer_checks.push(IssuerCheck {
            key_id,
            source,
            satellite,
            matches,
        });
    }

    // -- OPRF keys --
    let wc_oprf = IOprfKeyRegistry::new(oprf_registry, wc_provider);

    let mut oprf_checks = Vec::with_capacity(oprf_key_ids.len());
    for &key_id in oprf_key_ids {
        let src = wc_oprf
            .getOprfPublicKeyAndEpoch(alloy::primitives::Uint::from(key_id))
            .call()
            .await?;

        let dst = sat
            .oprfKeyIdToPubkeyAndProofId(alloy::primitives::Uint::from(key_id))
            .call()
            .await?;

        let source = (src.key.x, src.key.y);
        let satellite = (dst.pubKeyX, dst.pubKeyY);
        let matches = source == satellite;

        if !matches {
            let msg = format!(
                "oprf key_id={key_id} mismatch: source=({}, {}), satellite=({}, {})",
                src.key.x, src.key.y, dst.pubKeyX, dst.pubKeyY,
            );
            error!(key_id, "oprf invariant violated");
            failures.push(msg);
        }

        oprf_checks.push(OprfCheck {
            key_id,
            source,
            satellite,
            matches,
        });
    }

    if failures.is_empty() {
        info!("all invariants passed");
    }

    Ok(InvariantReport {
        root_match,
        issuer_checks,
        oprf_checks,
        failures,
    })
}
