use alloy::primitives::U256;
use ark_bn254::Fr;
use poseidon2::{Poseidon2, POSEIDON2_BN254_T2_PARAMS};
use semaphore_rs_hasher::Hasher;
use semaphore_rs_trees::lazy::{Canonical, LazyMerkleTree};
use sqlx::PgPool;
use sqlx::Row;
use std::sync::LazyLock;
use tokio::sync::RwLock;
use world_id_primitives::TREE_DEPTH;

static POSEIDON_HASHER: LazyLock<Poseidon2<Fr, 2, 5>> =
    LazyLock::new(|| Poseidon2::new(&POSEIDON2_BN254_T2_PARAMS));

pub struct PoseidonHasher {}

impl Hasher for PoseidonHasher {
    type Hash = U256;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let left: Fr = left.try_into().unwrap();
        let right: Fr = right.try_into().unwrap();
        let mut input = [left, right];
        let feed_forward = input[0];
        POSEIDON_HASHER.permutation_in_place(&mut input);
        input[0] += feed_forward;
        input[0].into()
    }
}

pub fn tree_capacity() -> usize {
    1usize << TREE_DEPTH
}

// Global Merkle tree (singleton). Protected by an async RwLock for concurrent reads.
pub static GLOBAL_TREE: LazyLock<RwLock<LazyMerkleTree<PoseidonHasher, Canonical>>> =
    LazyLock::new(|| {
        RwLock::new(LazyMerkleTree::<PoseidonHasher>::new(
            TREE_DEPTH,
            U256::ZERO,
        ))
    });

pub async fn set_leaf_at_index(leaf_index: usize, value: U256) -> anyhow::Result<()> {
    if leaf_index >= tree_capacity() {
        anyhow::bail!("leaf index {leaf_index} out of range for tree depth {TREE_DEPTH}");
    }

    let mut tree = GLOBAL_TREE.write().await;
    take_mut::take(&mut *tree, |tree| {
        tree.update_with_mutation(leaf_index, &value)
    });
    Ok(())
}

pub async fn build_tree_from_db(pool: &PgPool) -> anyhow::Result<()> {
    let rows = sqlx::query(
        "select leaf_index, offchain_signer_commitment from accounts order by leaf_index asc",
    )
    .fetch_all(pool)
    .await?;

    tracing::info!("There are {:?} rows in the table.", rows.len());

    let mut leaves: Vec<(usize, U256)> = Vec::with_capacity(rows.len());
    for r in rows {
        let leaf_index: String = r.get("leaf_index");
        let offchain: String = r.get("offchain_signer_commitment");
        let leaf_index: U256 = leaf_index.parse::<U256>()?;
        if leaf_index == U256::ZERO {
            continue;
        }
        let leaf_index = leaf_index.as_limbs()[0] as usize;
        let leaf_val = offchain.parse::<U256>()?;
        leaves.push((leaf_index, leaf_val));
    }

    let mut new_tree = LazyMerkleTree::<PoseidonHasher>::new(TREE_DEPTH, U256::ZERO);
    for (idx, value) in leaves {
        if idx >= tree_capacity() {
            anyhow::bail!(
                "leaf index {idx} out of range while rebuilding tree (depth {TREE_DEPTH})",
            );
        }
        new_tree = new_tree.update_with_mutation(idx, &value);
    }

    let root = new_tree.root();
    {
        let mut tree = GLOBAL_TREE.write().await;
        *tree = new_tree;
    }
    tracing::info!(
        root = %format!("0x{:x}", root),
        depth = TREE_DEPTH,
        "tree built from DB"
    );
    Ok(())
}

pub async fn update_tree_with_commitment(
    leaf_index: U256,
    new_commitment: U256,
) -> anyhow::Result<()> {
    if leaf_index == 0 {
        anyhow::bail!("account index cannot be zero");
    }
    let leaf_index = leaf_index.as_limbs()[0] as usize;
    set_leaf_at_index(leaf_index, new_commitment).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::uint;
    use semaphore_rs_trees::Branch;

    use super::*;

    #[test]
    fn test_poseidon2_merkle_tree() {
        let tree = LazyMerkleTree::<PoseidonHasher>::new(10, U256::ZERO);
        let proof = tree.proof(0);
        let proof = proof.0.iter().collect::<Vec<_>>();
        assert!(
            *proof[1]
                == Branch::Left(uint!(
                15621590199821056450610068202457788725601603091791048810523422053872049975191_U256
            ))
        );
    }
}
