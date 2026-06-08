use alloy::primitives::U256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchKind {
    Forward,
    Rollback,
}

impl BatchKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Rollback => "rollback",
        }
    }
}

impl TryFrom<&str> for BatchKind {
    type Error = crate::db::DBError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "forward" => Ok(Self::Forward),
            "rollback" => Ok(Self::Rollback),
            _ => Err(crate::invalid_field!("kind", "unknown sync batch kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafChange {
    pub leaf_index: u64,
    pub commitment: Option<U256>,
}

impl LeafChange {
    pub fn new(leaf_index: u64, commitment: U256) -> Self {
        Self {
            leaf_index,
            commitment: Some(commitment),
        }
    }

    pub fn cleared(leaf_index: u64) -> Self {
        Self {
            leaf_index,
            commitment: None,
        }
    }

    pub fn value(&self) -> U256 {
        self.commitment.unwrap_or(U256::ZERO)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchOrigin {
    pub block_number: u64,
    pub log_index: u64,
    pub onchain_timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchHeader {
    pub kind: BatchKind,
    pub expected_root: U256,
    pub next_leaf_index: u64,
    pub origin: BatchOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub header: BatchHeader,
    pub changes: Vec<LeafChange>,
}

impl Batch {
    /// Map to the `(leaf_index, value)` form `TreeState::simulate_root` expects.
    pub fn simulation_changes(&self) -> Vec<(usize, U256)> {
        self.changes
            .iter()
            .map(|change| (change.leaf_index as usize, change.value()))
            .collect()
    }
}

/// A value loaded from the DB together with its assigned `batch_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Persisted<T> {
    pub batch_id: u64,
    pub inner: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchRootCheck {
    Match,
    Mismatch { simulated: U256 },
}
