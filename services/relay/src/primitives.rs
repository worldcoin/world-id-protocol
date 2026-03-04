use std::sync::Arc;

use alloy::sol_types::SolValue;
use alloy_primitives::{B256, Bytes, U256, Uint, keccak256};

use crate::bindings::IWorldIDSource;

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
        for commitment in commitments {
            self.head = alloy_primitives::keccak256(
                [
                    self.head.as_slice(),
                    commitment.blockHash.as_slice(),
                    commitment.data.as_ref(),
                ]
                .concat(),
            );
            self.length += 1;
        }
    }

    /// Computes the hash of the chain after applying the given commitments,
    /// without modifying the chain itself.
    pub fn hash_chained(&self, commitments: &[IWorldIDSource::Commitment]) -> B256 {
        let mut hash = self.head;
        for commitment in commitments {
            hash = alloy_primitives::keccak256(
                [
                    hash.as_slice(),
                    commitment.blockHash.as_slice(),
                    commitment.data.as_ref(),
                ]
                .concat(),
            );
        }
        hash
    }
}

// ── ChainCommitment ──────────────────────────────────────────────────────────

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
    /// The position
    pub position: BlockTimestampAndLogIndex,
}

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
        position: last.position.clone(),
    })
}

pub type PubKeyId = Uint<160, 3>;

#[derive(Debug, Clone)]
pub struct BlockTimestampAndLogIndex {
    pub timestamp: u64,
    pub log_index: usize,
}

#[derive(Debug, Clone)]
pub struct PubKeyCommitment {
    pub affine: IWorldIDSource::Affine,
    pub position: BlockTimestampAndLogIndex,
    pub id: PubKeyId,
}

#[derive(Debug, Clone)]
pub struct RootCommitment {
    pub position: BlockTimestampAndLogIndex,
    pub root: U256,
}

/// Generates the `StateCommitment` enum and its core methods from a declarative
/// table of variants.
///
/// The macro always produces a distinguished `ChainCommitted` arm (whose key is
/// the chain head hash) plus an arbitrary number of additional "pending update"
/// variants, each with a custom key-extraction closure.
macro_rules! define_state_commitments {
    (
        chain_committed => $chain_ty:ty,
        $( $variant:ident ( $inner:ty ) => { key: $key_expr:expr $(,)? } ),* $(,)?
    ) => {
        #[derive(Debug, Clone)]
        pub enum StateCommitment {
            ChainCommitted($chain_ty),
            $( $variant($inner), )*
        }

        impl StateCommitment {
            pub fn key(&self) -> $crate::log::CommitmentKey {
                match self {
                    Self::ChainCommitted(c) => c.chain_head,
                    $( Self::$variant(inner) => ($key_expr)(inner), )*
                }
            }

            pub fn is_chain_commitment(&self) -> bool {
                matches!(self, Self::ChainCommitted(_))
            }

            pub fn is_pending_update(&self) -> bool {
                !self.is_chain_commitment()
            }

            pub fn position(&self) -> &BlockTimestampAndLogIndex {
                match self {
                    Self::ChainCommitted(c) => &c.position,
                    $( Self::$variant(inner) => &inner.position, )*
                }
            }
        }
    };
}

define_state_commitments! {
    chain_committed => ChainCommitment,
    RootCommitment(RootCommitment) => {
        key: |r: &RootCommitment| keccak256(r.root.as_le_bytes_trimmed()),
    },
    CredentialIssuerPubKey(PubKeyCommitment) => {
        key: |p: &PubKeyCommitment| keccak256(p.id.as_le_bytes_trimmed()),
    },
    OprfPubKey(PubKeyCommitment) => {
        key: |p: &PubKeyCommitment| keccak256(p.id.as_le_bytes_trimmed()),
    },
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
            position: BlockTimestampAndLogIndex {
                timestamp: 100,
                log_index: 0,
            },
        }
    }

    fn make_root_commitment(root: U256) -> RootCommitment {
        RootCommitment {
            position: BlockTimestampAndLogIndex {
                timestamp: 200,
                log_index: 1,
            },
            root,
        }
    }

    fn make_pubkey_commitment(id: u64) -> PubKeyCommitment {
        PubKeyCommitment {
            affine: IWorldIDSource::Affine {
                x: U256::from(1u64),
                y: U256::from(2u64),
            },
            position: BlockTimestampAndLogIndex {
                timestamp: 300,
                log_index: 2,
            },
            id: PubKeyId::from(id),
        }
    }

    #[test]
    fn state_commitment_key_distinct() {
        let chain = StateCommitment::ChainCommitted(make_chain_commitment(B256::from([1u8; 32])));
        let root = StateCommitment::RootCommitment(make_root_commitment(U256::from(42u64)));
        let issuer = StateCommitment::CredentialIssuerPubKey(make_pubkey_commitment(10));
        let oprf = StateCommitment::OprfPubKey(make_pubkey_commitment(20));

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
        assert!(!chain.is_pending_update());

        let root = StateCommitment::RootCommitment(make_root_commitment(U256::from(1u64)));
        assert!(!root.is_chain_commitment());

        let issuer = StateCommitment::CredentialIssuerPubKey(make_pubkey_commitment(1));
        assert!(!issuer.is_chain_commitment());

        let oprf = StateCommitment::OprfPubKey(make_pubkey_commitment(2));
        assert!(!oprf.is_chain_commitment());
    }

    #[test]
    fn is_pending_update() {
        let chain = StateCommitment::ChainCommitted(make_chain_commitment(B256::ZERO));
        assert!(!chain.is_pending_update());

        let root = StateCommitment::RootCommitment(make_root_commitment(U256::from(1u64)));
        assert!(root.is_pending_update());

        let issuer = StateCommitment::CredentialIssuerPubKey(make_pubkey_commitment(1));
        assert!(issuer.is_pending_update());

        let oprf = StateCommitment::OprfPubKey(make_pubkey_commitment(2));
        assert!(oprf.is_pending_update());
    }

    #[test]
    fn position_access() {
        let chain = StateCommitment::ChainCommitted(ChainCommitment {
            chain_head: B256::ZERO,
            block_number: 1,
            chain_id: 480,
            commitment_payload: Bytes::new(),
            position: BlockTimestampAndLogIndex {
                timestamp: 111,
                log_index: 5,
            },
        });
        assert_eq!(chain.position().timestamp, 111);
        assert_eq!(chain.position().log_index, 5);

        let root = StateCommitment::RootCommitment(RootCommitment {
            position: BlockTimestampAndLogIndex {
                timestamp: 222,
                log_index: 10,
            },
            root: U256::from(1u64),
        });
        assert_eq!(root.position().timestamp, 222);
        assert_eq!(root.position().log_index, 10);

        let issuer = StateCommitment::CredentialIssuerPubKey(PubKeyCommitment {
            affine: IWorldIDSource::Affine {
                x: U256::ZERO,
                y: U256::ZERO,
            },
            position: BlockTimestampAndLogIndex {
                timestamp: 333,
                log_index: 15,
            },
            id: PubKeyId::from(1u64),
        });
        assert_eq!(issuer.position().timestamp, 333);
        assert_eq!(issuer.position().log_index, 15);

        let oprf = StateCommitment::OprfPubKey(PubKeyCommitment {
            affine: IWorldIDSource::Affine {
                x: U256::ZERO,
                y: U256::ZERO,
            },
            position: BlockTimestampAndLogIndex {
                timestamp: 444,
                log_index: 20,
            },
            id: PubKeyId::from(2u64),
        });
        assert_eq!(oprf.position().timestamp, 444);
        assert_eq!(oprf.position().log_index, 20);
    }
}
