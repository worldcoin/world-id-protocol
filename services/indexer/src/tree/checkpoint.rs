//! Local, per-instance tree checkpoint (watermark) sidecar.
//!
//! # Why this exists
//!
//! The in-memory Merkle tree is backed by a memory-mapped file (`TREE_CACHE_FILE`).
//! The mmap persists the tree *state* across restarts, but on its own it carries no
//! record of **which event the mmap reflects**. Without that watermark the indexer
//! historically replayed the *entire* event history from genesis on every restart to
//! be safe (see `cached_tree::try_restore`).
//!
//! This module reinstates a durable watermark — a small JSON sidecar colocated with
//! the cache file (`<TREE_CACHE_FILE>.meta`) — so that on restart an instance can
//! replay only the events *after* the checkpoint cursor.
//!
//! # Deployment model — why the watermark is LOCAL, not in the DB
//!
//! The indexer runs as one writer plus N `HttpOnly` read replicas, all sharing one
//! Postgres but **each with its own `TREE_CACHE_FILE` on its own pod-local disk**.
//! Every instance advances its own mmap independently (the writer per committed
//! batch, each reader on its own `DB_POLL_INTERVAL_SECS`). A single shared DB row
//! therefore cannot describe N different mmaps. The watermark must live next to the
//! mmap it describes so it travels with — and only with — that instance's cache.
//!
//! # Crash consistency
//!
//! Correctness does **not** depend on flushing the mmap and the sidecar in a precise
//! order. On restore we require the sidecar's `root` to equal the actual mmap root
//! (and `num_leaves` to match, and the root to exist in the DB). A Poseidon root is a
//! cryptographic commitment to the entire leaf set, so a match proves the mmap really
//! is at the checkpointed position; any mismatch (torn write, partially-flushed mmap,
//! post-rollback state) falls back to the safe full replay. The sidecar may lag the
//! mmap (→ a few extra events replayed) but a lagging checkpoint is always safe.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::db::WorldIdRegistryEventId;

/// Current on-disk checkpoint format version. Bump to invalidate all existing
/// checkpoints after an incompatible tree/format change.
pub const CACHE_VERSION: u8 = 1;

/// Durable watermark describing the state a specific instance's mmap reflects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeCheckpoint {
    /// Format version; must equal [`CACHE_VERSION`] to be usable.
    pub cache_version: u8,
    /// Root of the tree at the checkpoint, `0x`-prefixed hex.
    pub root: String,
    /// Block number of the last event applied to the mmap.
    pub block_number: u64,
    /// Log index of the last event applied to the mmap.
    pub log_index: u64,
    /// Number of leaves in the tree at the checkpoint.
    pub num_leaves: u64,
    /// FNV-1a checksum over the canonical form of the fields above; detects torn
    /// writes / corruption.
    pub checksum: u64,
}

impl TreeCheckpoint {
    /// Build a checkpoint for the given tree state, computing the checksum.
    pub fn new(root: U256, cursor: WorldIdRegistryEventId, num_leaves: u64) -> Self {
        let root = format!("0x{root:x}");
        let checksum = compute_checksum(
            CACHE_VERSION,
            &root,
            cursor.block_number,
            cursor.log_index,
            num_leaves,
        );
        Self {
            cache_version: CACHE_VERSION,
            root,
            block_number: cursor.block_number,
            log_index: cursor.log_index,
            num_leaves,
            checksum,
        }
    }

    /// The event cursor recorded by this checkpoint.
    pub fn cursor(&self) -> WorldIdRegistryEventId {
        WorldIdRegistryEventId {
            block_number: self.block_number,
            log_index: self.log_index,
        }
    }

    /// Parse the stored root back into a `U256`.
    pub fn root_u256(&self) -> Option<U256> {
        U256::from_str_radix(self.root.trim_start_matches("0x"), 16).ok()
    }

    /// Validate `cache_version` and `checksum`. Returns `false` for any format or
    /// integrity problem.
    fn is_self_consistent(&self) -> bool {
        if self.cache_version != CACHE_VERSION {
            return false;
        }
        let expected = compute_checksum(
            self.cache_version,
            &self.root,
            self.block_number,
            self.log_index,
            self.num_leaves,
        );
        expected == self.checksum
    }
}

/// Deterministic FNV-1a (64-bit) checksum over the canonical checkpoint fields.
///
/// Implemented inline (no extra dependency) so it is stable across binary versions.
fn compute_checksum(
    cache_version: u8,
    root: &str,
    block_number: u64,
    log_index: u64,
    num_leaves: u64,
) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let canonical = format!("{cache_version}|{root}|{block_number}|{log_index}|{num_leaves}");
    let mut hash = FNV_OFFSET;
    for byte in canonical.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Path of the checkpoint sidecar for a given cache file: `<cache_path>.meta`.
///
/// Appends (rather than replaces the extension) so it is unambiguous and colocated
/// with the cache regardless of the cache file's own extension.
pub fn checkpoint_path(cache_path: &Path) -> PathBuf {
    let mut os = cache_path.as_os_str().to_os_string();
    os.push(".meta");
    PathBuf::from(os)
}

/// Atomically write the checkpoint sidecar next to `cache_path`.
///
/// Writes to a temp file, fsyncs it, then renames over the destination so a crash
/// can never leave a half-written sidecar. Best-effort fsync of the directory.
pub fn write_checkpoint(cache_path: &Path, checkpoint: &TreeCheckpoint) -> std::io::Result<()> {
    let dest = checkpoint_path(cache_path);
    let tmp = {
        let mut os = dest.as_os_str().to_os_string();
        os.push(".tmp");
        PathBuf::from(os)
    };

    let json = serde_json::to_vec(checkpoint).map_err(std::io::Error::other)?;

    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
    }

    fs::rename(&tmp, &dest)?;

    // Best-effort durability of the rename itself.
    if let Some(dir) = dest.parent() {
        if let Ok(dir_file) = fs::File::open(dir) {
            let _ = dir_file.sync_all();
        }
    }

    debug!(
        path = %dest.display(),
        root = %checkpoint.root,
        block_number = checkpoint.block_number,
        log_index = checkpoint.log_index,
        num_leaves = checkpoint.num_leaves,
        "wrote tree checkpoint"
    );

    Ok(())
}

/// Read and validate the checkpoint sidecar for `cache_path`.
///
/// Returns `None` (never an error) when the sidecar is absent, unreadable,
/// unparseable, of an incompatible version, or fails its checksum — every such case
/// simply means "no usable checkpoint", and the caller should fall back to a full
/// replay.
pub fn read_checkpoint(cache_path: &Path) -> Option<TreeCheckpoint> {
    let path = checkpoint_path(cache_path);
    if !path.exists() {
        return None;
    }

    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            warn!(path = %path.display(), ?e, "failed to read tree checkpoint; ignoring");
            return None;
        }
    };

    let checkpoint: TreeCheckpoint = match serde_json::from_slice(&bytes) {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %path.display(), ?e, "failed to parse tree checkpoint; ignoring");
            return None;
        }
    };

    if !checkpoint.is_self_consistent() {
        warn!(
            path = %path.display(),
            "tree checkpoint failed version/checksum validation; ignoring"
        );
        return None;
    }

    Some(checkpoint)
}

/// Delete the checkpoint sidecar for `cache_path` (best-effort).
///
/// Used on reorg/rollback to force the next boot to do one safe full replay.
pub fn delete_checkpoint(cache_path: &Path) {
    let path = checkpoint_path(cache_path);
    match fs::remove_file(&path) {
        Ok(()) => debug!(path = %path.display(), "deleted tree checkpoint"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(path = %path.display(), ?e, "failed to delete tree checkpoint"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_cache() -> PathBuf {
        std::env::temp_dir().join(format!("ckpt_test_{}.mmap", uuid::Uuid::new_v4()))
    }

    fn cursor(b: u64, l: u64) -> WorldIdRegistryEventId {
        WorldIdRegistryEventId {
            block_number: b,
            log_index: l,
        }
    }

    #[test]
    fn roundtrip_write_read() {
        let cache = tmp_cache();
        let cp = TreeCheckpoint::new(U256::from(0x1234u64), cursor(42, 3), 7);
        write_checkpoint(&cache, &cp).unwrap();

        let read = read_checkpoint(&cache).expect("checkpoint should be readable");
        assert_eq!(read, cp);
        assert_eq!(read.cursor(), cursor(42, 3));
        assert_eq!(read.root_u256(), Some(U256::from(0x1234u64)));

        delete_checkpoint(&cache);
        assert!(read_checkpoint(&cache).is_none());
    }

    #[test]
    fn missing_checkpoint_returns_none() {
        let cache = tmp_cache();
        assert!(read_checkpoint(&cache).is_none());
    }

    #[test]
    fn corrupted_json_returns_none() {
        let cache = tmp_cache();
        fs::write(checkpoint_path(&cache), b"not json").unwrap();
        assert!(read_checkpoint(&cache).is_none());
        delete_checkpoint(&cache);
    }

    #[test]
    fn checksum_mismatch_returns_none() {
        let cache = tmp_cache();
        let mut cp = TreeCheckpoint::new(U256::from(9u64), cursor(1, 0), 1);
        // Tamper with a field without recomputing the checksum.
        cp.num_leaves = 999;
        write_checkpoint(&cache, &cp).unwrap();
        assert!(
            read_checkpoint(&cache).is_none(),
            "tampered checkpoint must be rejected"
        );
        delete_checkpoint(&cache);
    }

    #[test]
    fn wrong_version_returns_none() {
        let cache = tmp_cache();
        let mut cp = TreeCheckpoint::new(U256::from(9u64), cursor(1, 0), 1);
        cp.cache_version = CACHE_VERSION + 1;
        // Recompute checksum so only the version is "wrong".
        cp.checksum = compute_checksum(
            cp.cache_version,
            &cp.root,
            cp.block_number,
            cp.log_index,
            cp.num_leaves,
        );
        write_checkpoint(&cache, &cp).unwrap();
        assert!(read_checkpoint(&cache).is_none());
        delete_checkpoint(&cache);
    }

    #[test]
    fn checkpoint_path_appends_meta() {
        let p = Path::new("/data/tree.mmap");
        assert_eq!(checkpoint_path(p), PathBuf::from("/data/tree.mmap.meta"));
        let p2 = Path::new("/tmp/cache");
        assert_eq!(checkpoint_path(p2), PathBuf::from("/tmp/cache.meta"));
    }
}
