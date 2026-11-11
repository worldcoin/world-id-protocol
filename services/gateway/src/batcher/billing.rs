//! Sender for WIP-107 `WorldIDBilling.register` calls.
//!
//! A registration is on the critical path of a user's first Proof of Embedding Similarity for an
//! RP in a period, so each one is sent in its own transaction as soon as it arrives: no batching
//! policy, no deferral under high gas. Its own transaction also means a registration that reverts
//! at inclusion, e.g. on an RP's exhausted capacity, fails only itself. Sends share the gateway's
//! signer, so they still go out one at a time under its send lock.

use std::sync::Arc;

use alloy::{
    network::TransactionBuilder as _,
    primitives::Address,
    providers::{DynProvider, Provider as _},
    rpc::types::TransactionRequest,
};
use tokio::sync::{Mutex, mpsc};

use crate::RequestTracker;

use super::{OpsEnvelope, PendingBatchTx, claim_requests, send_claimed};

/// Label of billing transactions in metrics and logs.
const BATCH_TYPE: &str = "billing";

#[derive(Clone)]
pub struct BillingSenderHandle {
    pub tx: mpsc::Sender<OpsEnvelope>,
}

/// Sends each received registration to the Billing Contract in its own transaction.
pub(crate) struct BillingSender {
    rx: mpsc::Receiver<OpsEnvelope>,
    provider: Arc<DynProvider>,
    billing_contract: Address,
    tracker: RequestTracker,
    tx_send_lock: Arc<Mutex<()>>,
}

impl BillingSender {
    pub(crate) const fn new(
        rx: mpsc::Receiver<OpsEnvelope>,
        provider: Arc<DynProvider>,
        billing_contract: Address,
        tracker: RequestTracker,
        tx_send_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            rx,
            provider,
            billing_contract,
            tracker,
            tx_send_lock,
        }
    }

    pub(crate) async fn run(mut self) {
        while let Some(envelope) = self.rx.recv().await {
            self.send(envelope).await;
        }
        tracing::info!("{BATCH_TYPE} sender channel closed");
    }

    async fn send(&self, envelope: OpsEnvelope) {
        let Some((mut claimed, ids)) =
            claim_requests(&self.tracker, BATCH_TYPE, vec![envelope]).await
        else {
            return;
        };
        let Some(envelope) = claimed.pop() else {
            return;
        };
        let request = TransactionRequest::default()
            .with_to(self.billing_contract)
            .with_input(envelope.calldata);
        let send = async {
            let builder = self.provider.send_transaction(request).await?;
            Ok(PendingBatchTx::new(builder))
        };
        send_claimed(&self.tracker, &self.tx_send_lock, BATCH_TYPE, ids, send).await;
    }
}
