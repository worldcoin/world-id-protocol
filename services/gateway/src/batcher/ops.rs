//! Operations batcher for insert/remove/recover/update operations.
//!
//! This batcher collects operations and submits them via Multicall3.
//! Gas estimation is handled automatically by the `GasEstimateWithFallbackFiller`
//! in the shared provider stack.

use std::sync::Arc;

use alloy::{
    primitives::{Address, Bytes, address},
    providers::DynProvider,
    rpc::types::TransactionRequest,
};
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

use crate::batch_type::BatchType;

use super::{BatchSubmitStrategy, BatcherEnvelope, GenericBatcher};

const MULTICALL3_ADDR: Address = address!("0xca11bde05977b3631167028862be2a173976ca11");

alloy::sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Multicall3 {
        struct Call3 { address target; bool allowFailure; bytes callData; }
        struct Result { bool success; bytes returnData; }
        function aggregate3(Call3[] calldata calls) payable returns (Result[] memory returnData);
    }
}

/// Envelope for ops batcher containing pre-computed calldata for a single
/// registry operation.
#[derive(Debug)]
pub struct OpsEnvelope {
    pub id: String,
    pub calldata: Bytes,
}

impl BatcherEnvelope for OpsEnvelope {
    fn request_id(&self) -> &str {
        &self.id
    }
}

#[derive(Default)]
pub(crate) struct OpsStrategy;

impl BatchSubmitStrategy<OpsEnvelope> for OpsStrategy {
    fn batch_type(&self) -> BatchType {
        BatchType::Ops
    }

    fn build_tx(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
        batch: Vec<OpsEnvelope>,
    ) -> TransactionRequest {
        let mc = Multicall3::new(MULTICALL3_ADDR, registry.provider().clone());

        let calls: Vec<Multicall3::Call3> = batch
            .into_iter()
            .map(|envelope| Multicall3::Call3 {
                target: *registry.address(),
                allowFailure: false,
                callData: envelope.calldata,
            })
            .collect();

        // No explicit gas limit — the GasEstimateWithFallbackFiller in the
        // shared provider stack will call eth_estimateGas on the assembled
        // Multicall3 batch and apply a 20 % margin automatically.
        mc.aggregate3(calls).into_transaction_request()
    }
}

pub type OpsBatcher = GenericBatcher<OpsEnvelope, OpsStrategy>;
