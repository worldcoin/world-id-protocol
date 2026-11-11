#![doc = include_str!("../README.md")]

// Used by the integration tests only.
#[cfg(test)]
use {eyre as _, world_id_test_utils as _};

mod follower;
mod metrics;
mod rpc;
mod schedule;
mod source;
#[cfg(test)]
mod testing;

pub use follower::{BillingFollower, BillingUpdate, FollowerConfig, FollowerError};
pub use rpc::RpcSource;
pub use source::{BillingEvent, BlockRef, ChainLog, ChainSource, EventSet, SourceError};
