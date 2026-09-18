//! The two independent transaction streams the gateway submits.
//!
//! Replaces the stringly-typed batch labels that used to be threaded through the
//! batcher, the policy and the metrics. Serializes as `snake_case` so it can be
//! stored in wallet records without a separate representation.

use serde::{Deserialize, Serialize};

/// A batch stream that produces one transaction per batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BatchType {
    /// Account creation, submitted as a single `createManyAccounts` call.
    Create,
    /// Account operations, submitted as one `Multicall3.aggregate3` call.
    Ops,
}

impl BatchType {
    /// Metric label and log field value.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Ops => "ops",
        }
    }
}

impl std::fmt::Display for BatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
