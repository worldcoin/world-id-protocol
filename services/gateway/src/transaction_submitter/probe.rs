//! Chain probes that decide the fate of one outstanding wallet transaction.
//!
//! Kept free of submitter state so the decision matrix can be tested against a
//! mocked provider.

use alloy::{
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
    Absent,
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
/// never evidence of anything, so it always yields [`Probe::Wait`].
pub(super) async fn probe(
    provider: &DynProvider,
    wallet: Address,
    submission: &Submission,
    release_confirmations: u64,
) -> Probe {
    let tx_hash = submission.tx_hash;

    let receipt = match provider.get_transaction_receipt(tx_hash).await {
        Ok(receipt) => receipt,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::warn!(%error, %tx_hash, "failed to fetch transaction receipt");
            return Probe::Wait;
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
        Ok(Some(_)) => return Probe::Wait,
        Ok(None) => {}
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::warn!(%error, %tx_hash, "failed to look up transaction by hash");
            return Probe::Wait;
        }
    }

    let latest = match provider.get_transaction_count(wallet).latest().await {
        Ok(count) => count,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::warn!(%error, "failed to read latest transaction count");
            return Probe::Wait;
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
                tracing::warn!(%error, %tx_hash, "failed to re-read receipt; not concluding replacement");
                Probe::Wait
            }
        };
    }

    let pending = match provider.get_transaction_count(wallet).pending().await {
        Ok(count) => count,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::warn!(%error, "failed to read pending transaction count");
            return Probe::Wait;
        }
    };

    if pending > submission.nonce {
        // The nonce is occupied in a mempool, so the transaction may still
        // land whether or not the entry is ours.
        Probe::Wait
    } else {
        Probe::Absent
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
            tracing::warn!(
                %error,
                tx_hash = %submission.tx_hash,
                "failed to check whether the inclusion block is still canonical"
            );
            return ReceiptCheck::Decided(Probe::Wait);
        }
    }

    let head = match provider.get_block_number().await {
        Ok(head) => head,
        Err(error) => {
            metrics::increment_wallet_error("resolve", "rpc");
            tracing::warn!(%error, "failed to read the chain head");
            return ReceiptCheck::Decided(Probe::Wait);
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

    async fn run(asserter: &Asserter, release_confirmations: u64) -> Probe {
        probe(
            &provider(asserter),
            WALLET,
            &submission(),
            release_confirmations,
        )
        .await
    }

    #[tokio::test]
    async fn an_rpc_failure_is_never_evidence() {
        let asserter = Asserter::new();
        asserter.push_failure_msg("upstream returned 502");
        assert_eq!(run(&asserter, 1).await, Probe::Wait);
    }

    #[tokio::test]
    async fn a_canonical_receipt_is_included() {
        let asserter = Asserter::new();
        asserter.push_success(&receipt(Some(INCLUSION_HASH), true));
        asserter.push_success(&block(INCLUSION_HASH));
        asserter.push_success(&format!("{:#x}", INCLUSION_BLOCK + 2));
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
        asserter.push_success(&format!("{INCLUSION_BLOCK:#x}"));
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
        asserter.push_success(&format!("{INCLUSION_BLOCK:#x}"));
        assert_eq!(run(&asserter, 3).await, Probe::Wait);
    }

    #[tokio::test]
    async fn a_receipt_without_a_block_hash_waits() {
        let asserter = Asserter::new();
        asserter.push_success(&receipt(None, true));
        assert_eq!(run(&asserter, 1).await, Probe::Wait);
    }

    #[tokio::test]
    async fn a_reorged_receipt_whose_nonce_was_reused_is_replaced() {
        let asserter = Asserter::new();
        // Receipt points at a block that is no longer canonical.
        asserter.push_success(&receipt(Some(INCLUSION_HASH), true));
        asserter.push_success(&block(B256::repeat_byte(0xbb)));
        // Unknown by hash, nonce consumed, and the re-read still finds nothing.
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_success(&format!("{:#x}", NONCE + 1));
        asserter.push_success(&serde_json::Value::Null);
        assert_eq!(run(&asserter, 1).await, Probe::Replaced);
    }

    #[tokio::test]
    async fn a_consumed_nonce_with_a_late_receipt_is_not_replaced() {
        let asserter = Asserter::new();
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_success(&format!("{:#x}", NONCE + 1));
        // A load-balanced node answers the re-read with the receipt after all.
        asserter.push_success(&receipt(Some(INCLUSION_HASH), true));
        asserter.push_success(&block(INCLUSION_HASH));
        asserter.push_success(&format!("{INCLUSION_BLOCK:#x}"));
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
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_success(&format!("{:#x}", NONCE + 1));
        asserter.push_failure_msg("request timed out");
        assert_eq!(run(&asserter, 1).await, Probe::Wait);
    }

    #[tokio::test]
    async fn an_occupied_pending_nonce_waits() {
        let asserter = Asserter::new();
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_success(&format!("{NONCE:#x}"));
        asserter.push_success(&format!("{:#x}", NONCE + 1));
        assert_eq!(run(&asserter, 1).await, Probe::Wait);
    }

    #[tokio::test]
    async fn an_unknown_transaction_with_a_free_nonce_is_absent() {
        let asserter = Asserter::new();
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_success(&format!("{NONCE:#x}"));
        asserter.push_success(&format!("{NONCE:#x}"));
        assert_eq!(run(&asserter, 1).await, Probe::Absent);
    }
}
