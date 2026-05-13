/// Fallback gas limit used when `eth_estimateGas` returns a JSON-RPC error
/// because the transaction would revert on-chain.
///
/// The fallback only needs to cover the cost of a basic revert while still
/// allowing the transaction to be submitted to avoid nonce gaps.
pub const GAS_ESTIMATION_FALLBACK: u64 = 500_000;

const GAS_ESTIMATION_MARGIN_NUMERATOR: u64 = 120;
const GAS_ESTIMATION_MARGIN_DENOMINATOR: u64 = 100;

/// Applies a 20 % safety margin to a raw `eth_estimateGas` result.
pub const fn apply_gas_margin(estimate: u64) -> u64 {
    estimate.saturating_mul(GAS_ESTIMATION_MARGIN_NUMERATOR)
        / GAS_ESTIMATION_MARGIN_DENOMINATOR
}
