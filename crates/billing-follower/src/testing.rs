//! An in-memory chain for tests: mine blocks with events, reorganize it, and make reads fail.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, PoisonError},
};

use alloy::primitives::{B256, keccak256};

use crate::source::{BillingEvent, BlockRef, ChainLog, ChainSource, EventSet, SourceError};

pub const CHAIN_ID: u64 = 480;

#[derive(Clone)]
struct FakeBlock {
    block: BlockRef,
    events: Vec<BillingEvent>,
}

#[derive(Default)]
struct Inner {
    blocks: Vec<FakeBlock>,
    /// Distinguishes the hashes of blocks mined on different forks.
    fork: u64,
    /// Reads that fail before any succeeds, by method.
    failures: VecDeque<&'static str>,
    /// `eth_getLogs` ranges wider than this fail.
    max_log_range: Option<u64>,
    log_calls: Vec<(u64, u64, EventSet)>,
}

/// A chain whose clones share one state.
#[derive(Clone, Default)]
pub struct FakeChain {
    inner: Arc<Mutex<Inner>>,
}

impl FakeChain {
    /// A chain with a genesis block at `timestamp`.
    pub fn new(timestamp: u64) -> Self {
        let chain = Self::default();
        chain.mine_at(timestamp, Vec::new());
        chain
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Mines a block 2 s after the previous one.
    pub fn mine(&self, events: Vec<BillingEvent>) -> BlockRef {
        let timestamp = self
            .lock()
            .blocks
            .last()
            .map_or(0, |b| b.block.timestamp + 2);
        self.mine_at(timestamp, events)
    }

    /// Mines `count` empty blocks.
    pub fn mine_empty(&self, count: u64) {
        for _ in 0..count {
            self.mine(Vec::new());
        }
    }

    pub fn mine_at(&self, timestamp: u64, events: Vec<BillingEvent>) -> BlockRef {
        let mut inner = self.lock();
        let number = inner.blocks.len() as u64;
        let parent_hash = inner.blocks.last().map_or(B256::ZERO, |b| b.block.hash);
        let mut preimage = number.to_be_bytes().to_vec();
        preimage.extend(inner.fork.to_be_bytes());
        let block = BlockRef {
            number,
            hash: keccak256(preimage),
            parent_hash,
            timestamp,
        };
        inner.blocks.push(FakeBlock { block, events });
        block
    }

    /// Drops the newest `depth` blocks, so the next mined ones form another fork.
    pub fn reorg(&self, depth: u64) {
        let mut inner = self.lock();
        let keep = inner.blocks.len() - usize::try_from(depth).unwrap();
        inner.blocks.truncate(keep);
        inner.fork += 1;
    }

    /// Makes the next `count` reads of `method` fail.
    pub fn fail(&self, method: &'static str, count: usize) {
        let mut inner = self.lock();
        for _ in 0..count {
            inner.failures.push_back(method);
        }
    }

    pub fn limit_log_range(&self, max: u64) {
        self.lock().max_log_range = Some(max);
    }

    pub fn log_calls(&self) -> Vec<(u64, u64, EventSet)> {
        self.lock().log_calls.clone()
    }

    pub fn head(&self) -> BlockRef {
        self.lock().blocks.last().unwrap().block
    }

    fn check_failure(&self, method: &'static str) -> Result<(), SourceError> {
        let mut inner = self.lock();
        if inner.failures.front() == Some(&method) {
            inner.failures.pop_front();
            return Err(SourceError::Timeout { method });
        }
        Ok(())
    }
}

impl ChainSource for FakeChain {
    async fn chain_id(&self) -> Result<u64, SourceError> {
        Ok(CHAIN_ID)
    }

    async fn latest(&self) -> Result<BlockRef, SourceError> {
        self.check_failure("eth_getBlockByNumber")?;
        Ok(self.head())
    }

    async fn block(&self, number: u64) -> Result<Option<BlockRef>, SourceError> {
        self.check_failure("eth_getBlockByNumber")?;
        Ok(self
            .lock()
            .blocks
            .get(usize::try_from(number).unwrap())
            .map(|b| b.block))
    }

    async fn logs(
        &self,
        from: u64,
        to: u64,
        events: EventSet,
    ) -> Result<Vec<ChainLog>, SourceError> {
        self.check_failure("eth_getLogs")?;
        let mut inner = self.lock();
        inner.log_calls.push((from, to, events));
        if inner.max_log_range.is_some_and(|max| to - from + 1 > max) {
            return Err(SourceError::Malformed {
                method: "eth_getLogs",
                reason: "range too large".to_owned(),
            });
        }
        let mut logs = Vec::new();
        for block in inner
            .blocks
            .iter()
            .filter(|b| (from..=to).contains(&b.block.number))
        {
            for (index, event) in block.events.iter().enumerate() {
                let wanted = events == EventSet::All
                    || matches!(event, BillingEvent::BilledRpUpdated { .. });
                if wanted {
                    logs.push(ChainLog {
                        block_number: block.block.number,
                        block_hash: block.block.hash,
                        log_index: index as u64,
                        event: *event,
                    });
                }
            }
        }
        Ok(logs)
    }
}
