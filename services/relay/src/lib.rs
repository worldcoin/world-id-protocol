#[allow(clippy::too_many_arguments)]
pub mod bindings;
pub mod cli;
pub mod engine;
pub mod log;
pub mod primitives;
pub mod proof;
pub mod relay;
pub mod satellite;
pub mod stream;

// Re-export the relay crate's public API items used by integration tests.
pub use log::CommitmentLog;
pub use primitives::{ChainCommitment, KeccakChain};
