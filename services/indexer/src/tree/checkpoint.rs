//! Local, per-instance tree checkpoint (watermark) sidecar.
//!
//! # Why this exists
//!
//! The in-memory Merkle tree is backed by a memory-mapped file (`TREE_CACHE_FILE`).
//! The mmap persists the tree *state* across restarts, but on its own it carries no
//! record of **which event the mmap reflects**. Without that watermark the indexer
//! historically replayed the *entire* event history from genesis on every restart.
//!
//! This module reinstates a durable watermark — a small JSON sidecar colocated with
//! the cache file (`<TREE_CACHE_FILE>.meta`) — so that on restart an instance can
//! replay only the events *after* the checkpoint cursor.
//!
//! # Deployment model — why the watermark is LOCAL, not in the DB
//!
//! The indexer runs as one writer plus N `HttpOnly` read replicas, all sharing one
//! Postgres but **each with its own `TREE_CACHE_FILE` on its own pod-local disk**.
//! Every instance advances its own mmap independently. A single shared DB row
//! therefore cannot describe N different mmaps. The watermark must live next to the
//! mmap it describes so it travels with — and only with — that instance's cache.
//!
//! # Crash consistency
//!
//! Correctness does **not** depend on flushing the mmap and the sidecar in a precise
//! order. On restore we require the sidecar's `root` to equal the actual mmap root.
//! A Poseidon root is a cryptographic commitment to the entire leaf set, so a match
//! proves the mmap really is at the checkpointed position; any mismatch (torn write,
//! partially-flushed mmap, post-rollback state) falls back to the safe full replay.
//! The sidecar may lag the mmap (→ a few extra events replayed) but a lagging
//! checkpoint is always safe.

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
///
/// v2: `root` is now serialized as an `alloy` `U256` (was a `0x`-prefixed hex
/// string) and the event cursor is `#[serde(flatten)]`ed from
/// [`WorldIdRegistryEventId`] (was separate `block_number`/`log_index`
/// fields). Both are on-disk format changes, so old v1 checkpoints are
/// invalidated by this single bump.
pub const CACHE_VERSION: u8 = 2;

/// Durable watermark describing the state a specific instance's mmap reflects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeCheckpoint {
    /// Format version; must equal [`CACHE_VERSION`] to be usable.
    pub cache_version: u8,
    /// Root of the tree at the checkpoint.
    pub root: U256,
    /// Cursor of the last event applied to the mmap.
    #[serde(flatten)]
    pub event: WorldIdRegistryEventId,
}

impl TreeCheckpoint {
    pub fn new(root: U256, cursor: WorldIdRegistryEventId) -> Self {
        Self {
            cache_version: CACHE_VERSION,
            root,
            event: cursor,
        }
    }

    /// The event cursor recorded by this checkpoint.
    pub fn cursor(&self) -> WorldIdRegistryEventId {
        self.event
    }
}

/// Path of the checkpoint sidecar for a given cache file: `<cache_path>.meta`.
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

    if let Some(dir) = dest.parent()
        && let Ok(dir_file) = fs::File::open(dir)
    {
        let _ = dir_file.sync_all();
    }

    debug!(
        path = %dest.display(),
        root = %checkpoint.root,
        block_number = checkpoint.event.block_number,
        log_index = checkpoint.event.log_index,
        "wrote tree checkpoint"
    );

    Ok(())
}

/// Read and validate the checkpoint sidecar for `cache_path`.
///
/// Returns `None` when the sidecar is absent, unreadable, unparseable, or of an
/// incompatible version — every such case means "no usable checkpoint" and the
/// caller should fall back to a full replay.
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

    if checkpoint.cache_version != CACHE_VERSION {
        warn!(
            path = %path.display(),
            cache_version = checkpoint.cache_version,
            "tree checkpoint has incompatible version; ignoring"
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
        let cp = TreeCheckpoint::new(U256::from(0x1234u64), cursor(42, 3));
        write_checkpoint(&cache, &cp).unwrap();

        let read = read_checkpoint(&cache).expect("checkpoint should be readable");
        assert_eq!(read, cp);
        assert_eq!(read.cursor(), cursor(42, 3));
        assert_eq!(read.root, U256::from(0x1234u64));

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
    fn wrong_version_returns_none() {
        let cache = tmp_cache();
        let mut cp = TreeCheckpoint::new(U256::from(9u64), cursor(1, 0));
        cp.cache_version = CACHE_VERSION + 1;
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
