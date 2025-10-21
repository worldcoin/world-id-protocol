use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::BaseField;

/// The id of a relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RpId(u128);

impl RpId {
    /// Converts the RP id to an u128
    pub fn into_inner(self) -> u128 {
        self.0
    }

    /// Creates a new `RpId` by wrapping a `u128`
    pub fn new(value: u128) -> Self {
        Self(value)
    }
}

impl fmt::Display for RpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // FIXME: hex
        f.write_str(&format!("rp_{}", self.0))
    }
}

impl FromStr for RpId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(id) = s.strip_prefix("rp_") {
            Ok(Self(
                id.parse::<u128>()
                    .map_err(|_| "Invalid RP ID format".to_string())?,
            ))
        } else {
            Err("A valid RP ID must start with 'rp_'".to_string())
        }
    }
}

impl From<u128> for RpId {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<RpId> for BaseField {
    fn from(value: RpId) -> Self {
        Self::from(value.0)
    }
}
