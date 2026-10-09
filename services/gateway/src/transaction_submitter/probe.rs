//! Chain probes that decide the fate of one outstanding wallet transaction.
//!
//! Kept free of submitter state so the decision matrix can be tested against a
//! mocked provider.

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{DynProvider, Provider},
    rpc::types::TransactionReceipt,
};

use crate::{metrics, storage::wallet_store::Submission};

/// What the resolver learned about one outstanding transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Probe {
    /// No definitive answer yet.
    Wait,
    /// The RPC failed, so nothing was learned. Treated like [`Probe::Wait`],
    /// but tells the resolver to back off.
    Unavailable,
    /// The transaction is on chain, with a canonical receipt.
    Included {
        /// Whether the transaction succeeded rather than reverted.
        success: bool,
        /// Blocks from the inclusion block to the head, counting the inclusion
        /// block itself.
        confirmations: u64,
    },
    /// The nonce was consumed by a different transaction, so ours will not land.
    Replaced,
    /// The transaction is in no mempool and its nonce is untouched.
    Absent {
        /// The wallet's mined transaction count on the answering node. Below
        /// the transaction's nonce, the transaction was signed behind a gap.
        latest: u64,
    },
}

/// What a receipt says about inclusion.
enum ReceiptCheck {
    /// The receipt settles the probe, or tells it to wait.
    Decided(Probe),
    /// The receipt's block is no longer canonical, so only the nonce can tell
    /// whether the transaction was dropped or replaced.
    Reorged,
}

/// Probes the chain for one outstanding transaction.
///
/// The receipt lookup is treated as the source of truth. An RPC failure is
/// never evidence of anything, so it always yields [`Probe::Unavailable`]. Failures
/// are counted in `wallet.error{phase="resolve",class="rpc"}` and logged only
/// at debug, because an RPC outage repeats them every pass for every wallet.
///
/// [`Probe::Absent`] is concluded only from a node whose head block is at
/// least `absent_after` (unix seconds): a stuck or lagging node also knows
/// nothing of the transaction and reports its nonce free.
pub(super) async fn probe(
    provider: &DynProvider,
    wallet: Address,
    submission: &Submission,
    release_confirmations: u64,
    absent_after: u64,
) -> Probe {
    let tx_hash = submission.tx_hash;

    let receipt = match provider.get_transaction_receipt(tx_hash).await {
        Ok(receipt) => receipt,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::debug!(%error, %tx_hash, "failed to fetch transaction receipt");
            return Probe::Unavailable;
        }
    };

    if let Some(receipt) = receipt {
        match classify_receipt(provider, submission, &receipt, release_confirmations).await {
            // Fall through: a reorg can also have consumed the nonce with a
            // different transaction, which only the probe below can tell.
            ReceiptCheck::Reorged => {}
            ReceiptCheck::Decided(probe) => return probe,
        }
    }

    // No canonical receipt. Distinguish "never landed" from "landed then reorged out"
    // by asking where the transaction and its nonce are.
    match provider.get_transaction_by_hash(tx_hash).await {
        Ok(Some(_)) => return pending_in_mempool(provider, wallet, submission).await,
        Ok(None) => {}
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::debug!(%error, %tx_hash, "failed to look up transaction by hash");
            return Probe::Unavailable;
        }
    }

    let latest = match provider.get_transaction_count(wallet).latest().await {
        Ok(count) => count,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::debug!(%error, "failed to read latest transaction count");
            return Probe::Unavailable;
        }
    };

    if latest > submission.nonce {
        // The nonce is mined. If it were ours we would have a receipt, but a
        // load-balanced RPC fleet can answer these two calls from different
        // nodes, so re-read the receipt before drawing a conclusion.
        return match provider.get_transaction_receipt(tx_hash).await {
            Ok(Some(receipt)) => {
                match classify_receipt(provider, submission, &receipt, release_confirmations).await
                {
                    // Reorged out again: let the next pass start over rather
                    // than concluding a replacement from a stale snapshot.
                    ReceiptCheck::Reorged => Probe::Wait,
                    ReceiptCheck::Decided(probe) => probe,
                }
            }
            Ok(None) => Probe::Replaced,
            Err(error) => {
                metrics::increment_wallet_error("resolve", "rpc");
                tracing::debug!(%error, %tx_hash, "failed to re-read receipt; not concluding replacement");
                Probe::Unavailable
            }
        };
    }

    let pending = match provider.get_transaction_count(wallet).pending().await {
        Ok(count) => count,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::debug!(%error, "failed to read pending transaction count");
            return Probe::Unavailable;
        }
    };

    if pending > submission.nonce {
        // The nonce is occupied in a mempool, so the transaction may still
        // land whether or not the entry is ours.
        return Probe::Wait;
    }

    match provider.get_block_by_number(BlockNumberOrTag::Latest).await {
        Ok(Some(head)) if head.header.timestamp >= absent_after => Probe::Absent { latest },
        // The node has not caught up with the time the transaction should have
        // reached it, so its silence proves nothing yet.
        Ok(_) => Probe::Wait,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::debug!(%error, "failed to read the head block");
            Probe::Unavailable
        }
    }
}

/// Turns a receipt into a probe outcome, verifying it is still canonical.
async fn classify_receipt(
    provider: &DynProvider,
    submission: &Submission,
    receipt: &TransactionReceipt,
    release_confirmations: u64,
) -> ReceiptCheck {
    let Some(block_number) = receipt.block_number else {
        return ReceiptCheck::Decided(Probe::Wait);
    };

    // A receipt without a block hash cannot be checked against the chain.
    // Waiting is the only answer that neither treats the transaction as
    // reorganised out on no evidence nor releases the wallet below the
    // configured confirmation floor.
    let Some(receipt_block_hash) = receipt.block_hash else {
        tracing::warn!(
            tx_hash = %submission.tx_hash,
            "receipt has no block hash; cannot verify inclusion yet"
        );
        return ReceiptCheck::Decided(Probe::Wait);
    };

    match provider.get_block_by_number(block_number.into()).await {
        Ok(Some(block)) if block.header.hash == receipt_block_hash => {}
        // The block that included this transaction is no longer canonical,
        // so the transaction is no longer included.
        Ok(Some(_) | None) => return ReceiptCheck::Reorged,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::debug!(
                %error,
                tx_hash = %submission.tx_hash,
                "failed to check whether the inclusion block is still canonical"
            );
            return ReceiptCheck::Decided(Probe::Unavailable);
        }
    }

    let head = match provider.get_block_number().await {
        Ok(head) => head,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::debug!(%error, "failed to read the chain head");
            return ReceiptCheck::Decided(Probe::Unavailable);
        }
    };

    // Count the inclusion block itself, so the default of one confirmation
    // means "included" and an operator raises it purely for reorg margin.
    // Counting blocks *on top* instead would make a lone transaction on a
    // quiet chain wait for a block that may never come: nothing else is
    // transacting, so the wallet would never be released.
    let confirmations = head.saturating_sub(block_number).saturating_add(1);
    if confirmations < release_confirmations {
        return ReceiptCheck::Decided(Probe::Wait);
    }

    ReceiptCheck::Decided(Probe::Included {
        success: receipt.status(),
        confirmations,
    })
}

/// Probe result for a transaction the node holds in its mempool.
///
/// Normally it is simply not mined yet. If an earlier nonce of the wallet is
/// still unmined, though, the transaction is queued behind a gap and cannot be
/// mined until something fills it; that is surfaced so an operator can act
/// before the wallet parks.
async fn pending_in_mempool(
    provider: &DynProvider,
    wallet: Address,
    submission: &Submission,
) -> Probe {
    match provider.get_transaction_count(wallet).latest().await {
        Ok(latest) if latest < submission.nonce => {
            metrics::increment_wallet_error("resolve", "nonce_gap");
            tracing::warn!(
                %wallet,
                latest,
                nonce = submission.nonce,
                "wallet transaction is queued behind a nonce gap"
            );
            Probe::Wait
        }
        Ok(_) => Probe::Wait,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::debug!(%error, "failed to read latest transaction count");
            Probe::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{B256, TxHash, address},
        providers::{Provider as _, ProviderBuilder, mock::Asserter},
        rpc::types::Block,
    };
    use serde_json::json;

    use super::*;
    use crate::batch_type::BatchType;

    const WALLET: Address = address!("1111111111111111111111111111111111111111");
    const NONCE: u64 = 7;
    const INCLUSION_BLOCK: u64 = 100;
    const INCLUSION_HASH: B256 = B256::repeat_byte(0xaa);

    fn submission() -> Submission {
        Submission {
            nonce: NONCE,
            tx_hash: TxHash::repeat_byte(0x11),
            request_ids: vec!["request-1".to_string()],
            batch_type: BatchType::Ops,
            submitted_at: 0,
        }
    }

    fn provider(asserter: &Asserter) -> DynProvider {
        ProviderBuilder::new()
            .connect_mocked_client(asserter.clone())
            .erased()
    }

    fn receipt(block_hash: Option<B256>, success: bool) -> serde_json::Value {
        json!({
            "type": "0x2",
            "status": if success { "0x1" } else { "0x0" },
            "cumulativeGasUsed": "0x5208",
            "logs": [],
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "transactionHash": TxHash::repeat_byte(0x11),
            "transactionIndex": "0x0",
            "blockHash": block_hash,
            "blockNumber": format!("{INCLUSION_BLOCK:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x1",
            "from": WALLET,
            "to": WALLET,
            "contractAddress": null,
        })
    }

    fn block(hash: B256) -> Block {
        let mut block = Block::<alloy::rpc::types::Transaction>::default();
        block.header.hash = hash;
        block.header.inner.number = INCLUSION_BLOCK;
        block
    }

    /// Earliest head timestamp from which `Absent` may be concluded.
    const ABSENT_AFTER: u64 = 1_000;

    async fn run(asserter: &Asserter, release_confirmations: u64) -> Probe {
        probe(
            &provider(asserter),
            WALLET,
            &submission(),
            release_confirmations,
            ABSENT_AFTER,
        )
        .await
    }

    // The mock answers calls in order, so each helper names the call it stands
    // for: receipt, transaction by hash, latest nonce, pending nonce, head.

    fn no_receipt(asserter: &Asserter) {
        asserter.push_success(&serde_json::Value::Null);
    }

    fn unknown_by_hash(asserter: &Asserter) {
        asserter.push_success(&serde_json::Value::Null);
    }

    fn nonce(asserter: &Asserter, nonce: u64) {
        asserter.push_success(&format!("{nonce:#x}"));
    }

    fn head_number(asserter: &Asserter, number: u64) {
        asserter.push_success(&format!("{number:#x}"));
    }

    fn head_at(asserter: &Asserter, timestamp: u64) {
        let mut head = block(B256::repeat_byte(0xcc));
        head.header.inner.timestamp = timestamp;
        asserter.push_success(&head);
    }

    #[tokio::test]
    async fn an_rpc_failure_is_never_evidence() {
        let asserter = Asserter::new();
        asserter.push_failure_msg("upstream returned 502");
        assert_eq!(run(&asserter, 1).await, Probe::Unavailable);
    }

    #[tokio::test]
    async fn a_canonical_receipt_is_included() {
        let asserter = Asserter::new();
        asserter.push_success(&receipt(Some(INCLUSION_HASH), true));
        asserter.push_success(&block(INCLUSION_HASH));
        head_number(&asserter, INCLUSION_BLOCK + 2);
        assert_eq!(
            run(&asserter, 1).await,
            Probe::Included {
                success: true,
                confirmations: 3,
            }
        );
    }

    #[tokio::test]
    async fn a_reverted_receipt_is_included_as_a_failure() {
        let asserter = Asserter::new();
        asserter.push_success(&receipt(Some(INCLUSION_HASH), false));
        asserter.push_success(&block(INCLUSION_HASH));
        head_number(&asserter, INCLUSION_BLOCK);
        assert_eq!(
            run(&asserter, 1).await,
            Probe::Included {
                success: false,
                confirmations: 1,
            }
        );
    }

    #[tokio::test]
    async fn a_receipt_below_the_confirmation_floor_waits() {
        let asserter = Asserter::new();
        asserter.push_success(&receipt(Some(INCLUSION_HASH), true));
        asserter.push_success(&block(INCLUSION_HASH));
        head_number(&asserter, INCLUSION_BLOCK);
        assert_eq!(run(&asserter, 3).await, Probe::Wait);
    }

    #[tokio::test]
    async fn a_receipt_without_a_block_hash_waits() {
        let asserter = Asserter::new();
        asserter.push_success(&receipt(None, true));
        // Without the block-hash check these would make it `Included`.
        asserter.push_success(&block(INCLUSION_HASH));
        head_number(&asserter, INCLUSION_BLOCK);
        assert_eq!(run(&asserter, 1).await, Probe::Wait);
    }

    #[tokio::test]
    async fn a_reorged_receipt_whose_nonce_was_reused_is_replaced() {
        let asserter = Asserter::new();
        // Receipt points at a block that is no longer canonical.
        asserter.push_success(&receipt(Some(INCLUSION_HASH), true));
        asserter.push_success(&block(B256::repeat_byte(0xbb)));
        // Unknown by hash, nonce consumed, and the re-read still finds nothing.
        unknown_by_hash(&asserter);
        nonce(&asserter, NONCE + 1);
        no_receipt(&asserter);
        assert_eq!(run(&asserter, 1).await, Probe::Replaced);
    }

    #[tokio::test]
    async fn a_consumed_nonce_with_a_late_receipt_is_not_replaced() {
        let asserter = Asserter::new();
        no_receipt(&asserter);
        unknown_by_hash(&asserter);
        nonce(&asserter, NONCE + 1);
        // A load-balanced node answers the re-read with the receipt after all.
        asserter.push_success(&receipt(Some(INCLUSION_HASH), true));
        asserter.push_success(&block(INCLUSION_HASH));
        head_number(&asserter, INCLUSION_BLOCK);
        assert_eq!(
            run(&asserter, 1).await,
            Probe::Included {
                success: true,
                confirmations: 1,
            }
        );
    }

    #[tokio::test]
    async fn a_failed_re_read_does_not_conclude_replacement() {
        let asserter = Asserter::new();
        no_receipt(&asserter);
        unknown_by_hash(&asserter);
        nonce(&asserter, NONCE + 1);
        asserter.push_failure_msg("request timed out");
        assert_eq!(run(&asserter, 1).await, Probe::Unavailable);
    }

    #[tokio::test]
    async fn an_occupied_pending_nonce_waits() {
        let asserter = Asserter::new();
        no_receipt(&asserter);
        unknown_by_hash(&asserter);
        nonce(&asserter, NONCE);
        nonce(&asserter, NONCE + 1);
        assert_eq!(run(&asserter, 1).await, Probe::Wait);
    }

    #[tokio::test]
    async fn an_unknown_transaction_with_a_free_nonce_is_absent() {
        let asserter = Asserter::new();
        no_receipt(&asserter);
        unknown_by_hash(&asserter);
        nonce(&asserter, NONCE);
        nonce(&asserter, NONCE);
        head_at(&asserter, ABSENT_AFTER);
        assert_eq!(run(&asserter, 1).await, Probe::Absent { latest: NONCE });
    }

    #[tokio::test]
    async fn a_lagging_node_never_concludes_absent() {
        let asserter = Asserter::new();
        no_receipt(&asserter);
        unknown_by_hash(&asserter);
        nonce(&asserter, NONCE);
        nonce(&asserter, NONCE);
        head_at(&asserter, ABSENT_AFTER - 1);
        assert_eq!(run(&asserter, 1).await, Probe::Wait);
    }
}
