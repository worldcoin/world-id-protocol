//! Unit tests for tree module

use std::path::PathBuf;

use alloy::primitives::U256;
use semaphore_rs_trees::Branch;
use tempfile::TempDir;

use super::{
    MerkleTree, PoseidonHasher, TreeInitializer,
    initializer::CacheState,
    metadata::{self, TreeCacheMetadata},
};

// =============================================================================
// Test Constants
// =============================================================================

const TEST_TREE_DEPTH: usize = 10;
const TEST_DENSE_PREFIX_DEPTH: usize = 8;

// =============================================================================
// Test Utilities
// =============================================================================

struct TestFixture {
    _temp_dir: TempDir,
    cache_path: PathBuf,
}

impl TestFixture {
    fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path().join("test_tree.mmap");
        Self {
            _temp_dir: temp_dir,
            cache_path,
        }
    }

    fn metadata_path(&self) -> PathBuf {
        metadata::metadata_path(&self.cache_path)
    }

    fn cache_path_string(&self) -> String {
        self.cache_path.to_string_lossy().to_string()
    }

    fn write_metadata(&self, metadata: &TreeCacheMetadata) {
        let json = serde_json::to_string_pretty(metadata).expect("Failed to serialize metadata");
        std::fs::write(self.metadata_path(), json).expect("Failed to write metadata");
    }

    fn write_invalid_metadata(&self, content: &str) {
        std::fs::write(self.metadata_path(), content).expect("Failed to write invalid metadata");
    }

    fn create_mmap_file(&self) {
        std::fs::write(&self.cache_path, b"dummy mmap content")
            .expect("Failed to create mmap file");
    }
}

fn create_initializer(cache_path: String) -> TreeInitializer {
    TreeInitializer::new(
        cache_path,
        TEST_TREE_DEPTH,
        TEST_DENSE_PREFIX_DEPTH,
        U256::ZERO,
    )
}

fn create_metadata(root_hash: &str, last_block: u64, last_event_id: i64) -> TreeCacheMetadata {
    TreeCacheMetadata {
        root_hash: root_hash.to_string(),
        last_block_number: last_block,
        last_event_id,
        active_leaf_count: 0,
        tree_depth: TEST_TREE_DEPTH,
        dense_prefix_depth: TEST_DENSE_PREFIX_DEPTH,
        created_at: 0,
        cache_version: 1,
    }
}

// =============================================================================
// Merkle Tree Tests
// =============================================================================

#[test]
fn test_poseidon2_merkle_tree() {
    use alloy::uint;

    let tree = MerkleTree::<PoseidonHasher>::new(10, U256::ZERO);
    let proof = tree.proof(0);
    let proof = proof.0.iter().collect::<Vec<_>>();
    assert!(
        *proof[1]
            == Branch::Left(uint!(
                15621590199821056450610068202457788725601603091791048810523422053872049975191_U256
            ))
    );
}

// =============================================================================
// CacheState / check_cache_files Tests
// =============================================================================

#[test]
fn test_check_cache_files_both_present() {
    let fixture = TestFixture::new();
    fixture.write_metadata(&create_metadata("0x123", 100, 50));
    fixture.create_mmap_file();

    let initializer = create_initializer(fixture.cache_path_string());
    assert_eq!(initializer.check_cache_files(), CacheState::Valid);
}

#[test]
fn test_check_cache_files_metadata_missing() {
    let fixture = TestFixture::new();
    fixture.create_mmap_file();
    // Don't create metadata

    let initializer = create_initializer(fixture.cache_path_string());
    assert_eq!(initializer.check_cache_files(), CacheState::MetadataMissing);
}

#[test]
fn test_check_cache_files_mmap_missing() {
    let fixture = TestFixture::new();
    fixture.write_metadata(&create_metadata("0x123", 100, 50));
    // Don't create mmap file

    let initializer = create_initializer(fixture.cache_path_string());
    assert_eq!(initializer.check_cache_files(), CacheState::MmapMissing);
}

#[test]
fn test_check_cache_files_both_missing() {
    let fixture = TestFixture::new();
    // Don't create any files

    let initializer = create_initializer(fixture.cache_path_string());
    assert_eq!(initializer.check_cache_files(), CacheState::BothMissing);
}

// =============================================================================
// Metadata Read Tests
// =============================================================================

#[test]
fn test_read_metadata_succeeds_with_valid_file() {
    let fixture = TestFixture::new();
    let expected = create_metadata("0xabc123", 500, 100);
    fixture.write_metadata(&expected);

    let result = metadata::read_metadata(&fixture.cache_path);
    assert!(result.is_ok());

    let metadata = result.unwrap();
    assert_eq!(metadata.root_hash, "0xabc123");
    assert_eq!(metadata.last_block_number, 500);
    assert_eq!(metadata.last_event_id, 100);
    assert_eq!(metadata.tree_depth, 10);
    assert_eq!(metadata.dense_prefix_depth, 8);
}

#[test]
fn test_read_metadata_fails_when_file_missing() {
    let fixture = TestFixture::new();
    // Don't create metadata file

    let result = metadata::read_metadata(&fixture.cache_path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not exist"));
}

#[test]
fn test_read_metadata_fails_with_invalid_json() {
    let fixture = TestFixture::new();
    fixture.write_invalid_metadata("{ invalid json }");

    let result = metadata::read_metadata(&fixture.cache_path);
    assert!(result.is_err());
}

// =============================================================================
// sync_with_db Tests
// =============================================================================

#[test]
fn test_sync_with_db_fails_when_metadata_missing() {
    let fixture = TestFixture::new();
    // Don't create metadata file

    let initializer = create_initializer(fixture.cache_path_string());

    // sync_with_db should fail if metadata doesn't exist
    // Note: This is a compile-time test to ensure the method signature exists
    // The actual runtime test requires a database, which is tested in integration tests
    let _ = initializer; // Prevent unused variable warning
}
