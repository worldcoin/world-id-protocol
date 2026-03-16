use std::sync::Arc;

use alloy::sol_types::SolValue;
use alloy_primitives::{B256, Bytes, Keccak256, U256, Uint, keccak256};

use crate::bindings::IWorldIDSource;

// ── Identity types ──────────────────────────────────────────────────────────

/// Convenience alias for `Uint<160, 3>`.
pub type U160 = Uint<160, 3>;

/// Issuer schema identifier -- `uint64` on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IssuerSchemaId(pub u64);

/// OPRF key identifier -- `uint160` on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OprfKeyId(pub U160);

// ── Commitment types ────────────────────────────────────────────────────────

/// A decoded `ChainCommitted` event with everything needed for relay.
#[derive(Debug, Clone)]
pub struct ChainCommitment {
    /// The new keccak chain head after this commitment.
    pub chain_head: B256,
    /// The WC block number at which the commitment was made.
    pub block_number: u64,
    /// The WC chain ID.
    pub chain_id: u64,
    /// The raw ABI-encoded `Commitment[]` payload from the event.
    pub commitment_payload: Bytes,
    /// The block timestamp at which the commitment was observed.
    pub timestamp: u64,
}

/// A pending merkle-root update.
#[derive(Debug, Clone)]
pub struct RootCommitment {
    pub root: U256,
    pub timestamp: u64,
}

/// A pending credential-issuer public-key update.
#[derive(Debug, Clone)]
pub struct IssuerKeyUpdate {
    pub affine: IWorldIDSource::Affine,
    pub timestamp: u64,
    pub id: IssuerSchemaId,
}

/// A pending OPRF public-key update.
#[derive(Debug, Clone)]
pub struct OprfKeyUpdate {
    pub affine: IWorldIDSource::Affine,
    pub timestamp: u64,
    pub id: OprfKeyId,
}

// ── StateCommitment enum ────────────────────────────────────────────────────

/// A commitment key used for deduplication and indexing.
pub type CommitmentKey = B256;

/// Union of every commitment variant the relay tracks.
#[derive(Debug, Clone)]
pub enum StateCommitment {
    ChainCommitted(ChainCommitment),
    RootCommitment(RootCommitment),
    IssuerPubKey(IssuerKeyUpdate),
    OprfPubKey(OprfKeyUpdate),
}

impl std::fmt::Display for StateCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainCommitted(c) => {
                write!(f, "ChainCommitted(block={}, head={})", c.block_number, c.chain_head)
            }
            Self::RootCommitment(r) => write!(f, "RootRecorded(root={})", r.root),
            Self::IssuerPubKey(p) => write!(f, "IssuerPubKey(id={})", p.id.0),
            Self::OprfPubKey(p) => write!(f, "OprfPubKey(id={})", p.id.0),
        }
    }
}

impl StateCommitment {
    /// Returns a deterministic key that uniquely identifies this commitment.
    pub fn key(&self) -> CommitmentKey {
        match self {
            Self::ChainCommitted(c) => c.chain_head,
            Self::RootCommitment(r) => keccak256(r.root.as_le_bytes_trimmed()),
            Self::IssuerPubKey(p) => keccak256(p.id.0.to_be_bytes()),
            Self::OprfPubKey(p) => keccak256(p.id.0.as_le_bytes_trimmed()),
        }
    }

    /// Returns `true` if this is a `ChainCommitted` variant.
    pub fn is_chain_commitment(&self) -> bool {
        matches!(self, Self::ChainCommitted(_))
    }

    /// Returns the block timestamp at which this commitment was observed.
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::ChainCommitted(c) => c.timestamp,
            Self::RootCommitment(r) => r.timestamp,
            Self::IssuerPubKey(p) => p.timestamp,
            Self::OprfPubKey(p) => p.timestamp,
        }
    }
}

// ── KeccakChain ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeccakChain {
    pub head: B256,
    pub length: u64,
}

impl KeccakChain {
    pub fn new(head: B256, length: u64) -> Self {
        Self { head, length }
    }

    /// Updates the chain head by applying the given commitments in order.
    pub fn commit_chained(&mut self, commitments: &[IWorldIDSource::Commitment]) {
        for c in commitments {
            let mut hasher = Keccak256::new();
            hasher.update(self.head.as_slice());
            hasher.update(c.blockHash.as_slice());
            hasher.update(c.data.as_ref());
            self.head = hasher.finalize();
            self.length += 1;
        }
    }

    /// Computes the hash of the chain after applying the given commitments,
    /// without modifying the chain itself.
    pub fn hash_chained(&self, commitments: &[IWorldIDSource::Commitment]) -> B256 {
        let mut hash = self.head;
        for c in commitments {
            let mut hasher = Keccak256::new();
            hasher.update(hash.as_slice());
            hasher.update(c.blockHash.as_slice());
            hasher.update(c.data.as_ref());
            hash = hasher.finalize();
        }
        hash
    }
}

// ── reduce ──────────────────────────────────────────────────────────────────

/// Merges a sequence of chain commitments into a single combined commitment.
pub fn reduce(delta: &[Arc<ChainCommitment>]) -> eyre::Result<ChainCommitment> {
    let last = delta.last().ok_or_else(|| eyre::eyre!("empty delta"))?;

    let mut merged = Vec::new();
    for c in delta {
        merged.extend(Vec::<IWorldIDSource::Commitment>::abi_decode_params(
            &c.commitment_payload,
        )?);
    }

    Ok(ChainCommitment {
        chain_head: last.chain_head,
        block_number: last.block_number,
        chain_id: last.chain_id,
        commitment_payload: merged.abi_encode_params().into(),
        timestamp: last.timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes, U256};

    fn make_chain_commitment(head: B256) -> ChainCommitment {
        ChainCommitment {
            chain_head: head,
            block_number: 1,
            chain_id: 480,
            commitment_payload: Bytes::from(vec![0u8; 4]),
            timestamp: 100,
        }
    }

    fn make_root_commitment(root: U256) -> RootCommitment {
        RootCommitment {
            root,
            timestamp: 200,
        }
    }

    fn make_issuer_update(id: u64) -> IssuerKeyUpdate {
        IssuerKeyUpdate {
            affine: IWorldIDSource::Affine {
                x: U256::from(1u64),
                y: U256::from(2u64),
            },
            timestamp: 300,
            id: IssuerSchemaId(id),
        }
    }

    fn make_oprf_update(id: u64) -> OprfKeyUpdate {
        OprfKeyUpdate {
            affine: IWorldIDSource::Affine {
                x: U256::from(1u64),
                y: U256::from(2u64),
            },
            timestamp: 400,
            id: OprfKeyId(U160::from(id)),
        }
    }

    #[test]
    fn state_commitment_key_distinct() {
        let chain = StateCommitment::ChainCommitted(make_chain_commitment(B256::from([1u8; 32])));
        let root = StateCommitment::RootCommitment(make_root_commitment(U256::from(42u64)));
        let issuer = StateCommitment::IssuerPubKey(make_issuer_update(10));
        let oprf = StateCommitment::OprfPubKey(make_oprf_update(20));

        let keys = [chain.key(), root.key(), issuer.key(), oprf.key()];

        // All four keys must be distinct from each other.
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "keys at indices {i} and {j} must differ");
            }
        }
    }

    #[test]
    fn is_chain_commitment() {
        let chain = StateCommitment::ChainCommitted(make_chain_commitment(B256::ZERO));
        assert!(chain.is_chain_commitment());

        let root = StateCommitment::RootCommitment(make_root_commitment(U256::from(1u64)));
        assert!(!root.is_chain_commitment());

        let issuer = StateCommitment::IssuerPubKey(make_issuer_update(1));
        assert!(!issuer.is_chain_commitment());

        let oprf = StateCommitment::OprfPubKey(make_oprf_update(2));
        assert!(!oprf.is_chain_commitment());
    }

    #[test]
    fn timestamp_access() {
        let chain = StateCommitment::ChainCommitted(ChainCommitment {
            chain_head: B256::ZERO,
            block_number: 1,
            chain_id: 480,
            commitment_payload: Bytes::new(),
            timestamp: 111,
        });
        assert_eq!(chain.timestamp(), 111);

        let root = StateCommitment::RootCommitment(RootCommitment {
            root: U256::from(1u64),
            timestamp: 222,
        });
        assert_eq!(root.timestamp(), 222);

        let issuer = StateCommitment::IssuerPubKey(IssuerKeyUpdate {
            affine: IWorldIDSource::Affine {
                x: U256::ZERO,
                y: U256::ZERO,
            },
            timestamp: 333,
            id: IssuerSchemaId(1),
        });
        assert_eq!(issuer.timestamp(), 333);

        let oprf = StateCommitment::OprfPubKey(OprfKeyUpdate {
            affine: IWorldIDSource::Affine {
                x: U256::ZERO,
                y: U256::ZERO,
            },
            timestamp: 444,
            id: OprfKeyId(U160::from(2u64)),
        });
        assert_eq!(oprf.timestamp(), 444);
    }
}
