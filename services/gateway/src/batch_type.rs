use std::fmt;

use serde::{Deserialize, Serialize};

/// Kind of transaction batch submitted by the gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BatchType {
    Create,
    Ops,
}

impl BatchType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Ops => "ops",
        }
    }
}

impl fmt::Display for BatchType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
