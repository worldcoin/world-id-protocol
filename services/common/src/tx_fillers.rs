use alloy::{
    network::{Network, TransactionBuilder},
    providers::{
        Provider, SendableTx,
        fillers::{FillerControlFlow, TxFiller},
    },
    transports::{RpcError, TransportResult},
};

/// Fallback gas limit used when `eth_estimateGas` returns a JSON-RPC error
/// because the transaction would revert on-chain.
///
/// The fallback only needs to cover the cost of a basic revert while still
/// allowing the transaction to be submitted to avoid nonce gaps.
pub(crate) const GAS_ESTIMATION_FALLBACK: u64 = 500_000;

const GAS_ESTIMATION_MARGIN_NUMERATOR: u64 = 120;
const GAS_ESTIMATION_MARGIN_DENOMINATOR: u64 = 100;

/// A transaction filler that populates missing gas limits via
/// `eth_estimateGas`, with a fallback when estimation fails.
///
/// Two error cases are handled differently:
///
/// - **Execution revert** (`eth_estimateGas` returned a JSON-RPC `ErrorResp`
///   because the transaction would fail on-chain): the filler uses
///   [`GAS_ESTIMATION_FALLBACK`] and logs a warning, allowing the transaction
///   to be submitted so the revert is recorded and nonce gaps are avoided.
///
/// - **Transport / RPC error** (network failure, timeout, malformed response,
///   etc.): the error is propagated to the caller so it can be retried or
///   surfaced appropriately.
///
/// This filler only sets `gas_limit`, leaving gas price / fee fields to the
/// standard alloy [`GasFiller`](alloy::providers::fillers::GasFiller).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GasEstimateWithFallbackFiller;

impl GasEstimateWithFallbackFiller {
    const fn apply_margin(estimate: u64) -> u64 {
        estimate.saturating_mul(GAS_ESTIMATION_MARGIN_NUMERATOR) / GAS_ESTIMATION_MARGIN_DENOMINATOR
    }
}

impl<N> TxFiller<N> for GasEstimateWithFallbackFiller
where
    N: Network,
    N::TransactionRequest: TransactionBuilder<N>,
{
    type Fillable = u64;

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        if tx.gas_limit().is_some() {
            FillerControlFlow::Finished
        } else {
            FillerControlFlow::Ready
        }
    }

    fn fill_sync(&self, _tx: &mut SendableTx<N>) {}

    async fn prepare<P>(
        &self,
        provider: &P,
        tx: &N::TransactionRequest,
    ) -> TransportResult<Self::Fillable>
    where
        P: Provider<N>,
    {
        let gas_limit = match provider.estimate_gas(tx.clone()).await {
            Ok(estimate) => Self::apply_margin(estimate),
            // JSON-RPC error: the node ran the transaction and it reverted.
            // Use the fallback so we can still submit and record the failure.
            Err(RpcError::ErrorResp(error)) => {
                tracing::warn!(
                    %error,
                    gas_limit = GAS_ESTIMATION_FALLBACK,
                    "eth_estimateGas returned an execution error, \
                     transaction will likely revert — using fallback gas limit"
                );
                GAS_ESTIMATION_FALLBACK
            }
            // Transport / infrastructure error: propagate so the caller can
            // retry or surface the failure.
            Err(error) => return Err(error),
        };

        Ok(gas_limit)
    }

    async fn fill(
        &self,
        gas_limit: Self::Fillable,
        mut tx: SendableTx<N>,
    ) -> TransportResult<SendableTx<N>> {
        if let Some(builder) = tx.as_mut_builder() {
            builder.set_gas_limit(gas_limit);
        }

        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        network::{Ethereum, TransactionBuilder},
        providers::{
            ProviderBuilder,
            fillers::{FillerControlFlow, TxFiller},
        },
        rpc::types::TransactionRequest,
        transports::mock::Asserter,
    };

    use super::{GAS_ESTIMATION_FALLBACK, GasEstimateWithFallbackFiller};

    fn gas_limit_of(tx: alloy::providers::SendableTx<Ethereum>) -> u64 {
        tx.try_into_request()
            .unwrap()
            .gas
            .expect("gas limit should be set")
    }

    #[test]
    fn status_is_finished_when_gas_limit_is_already_set() {
        let tx = TransactionRequest::default().with_gas_limit(123_456);
        assert_eq!(
            <GasEstimateWithFallbackFiller as TxFiller<Ethereum>>::status(
                &GasEstimateWithFallbackFiller,
                &tx,
            ),
            FillerControlFlow::Finished
        );
    }

    #[tokio::test]
    async fn scales_estimated_gas_limit_by_twenty_percent() {
        let asserter = Asserter::new();
        asserter.push_success(&210_000u64);

        let provider = ProviderBuilder::default()
            .filler(GasEstimateWithFallbackFiller)
            .connect_mocked_client(asserter.clone());

        let filled_tx = provider.fill(TransactionRequest::default()).await.unwrap();

        assert_eq!(gas_limit_of(filled_tx), 252_000);
        assert!(
            asserter.read_q().is_empty(),
            "all mock responses should be used"
        );
    }

    #[tokio::test]
    async fn falls_back_on_execution_revert_error() {
        let asserter = Asserter::new();
        // push_failure_msg pushes a JSON-RPC ErrorPayload → RpcError::ErrorResp
        asserter.push_failure_msg("execution reverted");

        let provider = ProviderBuilder::default()
            .filler(GasEstimateWithFallbackFiller)
            .connect_mocked_client(asserter.clone());

        let filled_tx = provider.fill(TransactionRequest::default()).await.unwrap();

        assert_eq!(gas_limit_of(filled_tx), GAS_ESTIMATION_FALLBACK);
        assert!(
            asserter.read_q().is_empty(),
            "all mock responses should be used"
        );
    }

    #[tokio::test]
    async fn propagates_transport_error() {
        let asserter = Asserter::new();
        // Empty asserter queue → MockTransport returns TransportErrorKind::Custom
        // which surfaces as RpcError::Transport — not ErrorResp.

        let provider = ProviderBuilder::default()
            .filler(GasEstimateWithFallbackFiller)
            .connect_mocked_client(asserter.clone());

        let result: Result<alloy::providers::SendableTx<Ethereum>, _> =
            provider.fill(TransactionRequest::default()).await;

        assert!(
            result.is_err(),
            "transport errors must be propagated, not swallowed"
        );
    }
}
