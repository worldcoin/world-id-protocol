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

/// On-disk checkpoint format version.
///
/// This is a typed enum rather than a raw integer so that an old or otherwise
/// unknown version number on disk fails to deserialize (via [`TryFrom<u8>`]),
/// which the checkpoint-read path already treats as "no usable checkpoint, do a
/// full rebuild". Bump by adding a new variant after an incompatible
/// tree/format change; old variants only need to be retained while their
/// on-disk format remains restorable.
///
/// v2: `root` is serialized as an `alloy` `U256` (was a `0x`-prefixed hex
/// string) and the event cursor is `#[serde(flatten)]`ed from
/// [`WorldIdRegistryEventId`] (was separate `block_number`/`log_index`
/// fields). Both are on-disk format changes, so any earlier (v1) checkpoint is
/// incompatible; there is deliberately no `V1` variant, so v1 (or any unknown)
/// version numbers fail to deserialize and safely fall back to a full rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum CacheVersion {
    V2 = 2,
}

/// The current checkpoint format version written by this build.
pub const CURRENT_CACHE_VERSION: CacheVersion = CacheVersion::V2;

impl From<CacheVersion> for u8 {
    fn from(v: CacheVersion) -> Self {
        v as u8
    }
}

impl TryFrom<u8> for CacheVersion {
    type Error = UnknownCacheVersion;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(CacheVersion::V2),
            other => Err(UnknownCacheVersion(other)),
        }
    }
}

/// Error produced when a stored version number does not correspond to any known
/// [`CacheVersion`]. Surfaced through serde as a deserialization failure, which
/// the checkpoint-read path treats as "no usable checkpoint".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownCacheVersion(pub u8);

impl std::fmt::Display for UnknownCacheVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown checkpoint cache version: {}", self.0)
    }
}

impl std::error::Error for UnknownCacheVersion {}

/// Durable watermark describing the state a specific instance's mmap reflects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeCheckpoint {
    /// Format version; must equal [`CURRENT_CACHE_VERSION`] to be usable. An
    /// unknown/old value fails to deserialize and is treated as no checkpoint.
    pub cache_version: CacheVersion,
    /// Root of the tree at the checkpoint.
    pub root: U256,
    /// Cursor of the last event applied to the mmap.
    #[serde(flatten)]
    pub event: WorldIdRegistryEventId,
}

impl TreeCheckpoint {
    pub fn new(root: U256, cursor: WorldIdRegistryEventId) -> Self {
        Self {
            cache_version: CURRENT_CACHE_VERSION,
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

    // An unknown/old version number already fails to deserialize above (see
    // [`CacheVersion`]'s `try_from = "u8"`), landing in the parse-error branch
    // and returning `None`. This explicit check additionally guards against a
    // known-but-not-current version once more variants exist.
    if checkpoint.cache_version != CURRENT_CACHE_VERSION {
        warn!(
            path = %path.display(),
            cache_version = u8::from(checkpoint.cache_version),
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
        // A well-formed sidecar carrying an *unknown* version number must be
        // rejected. Because [`CacheVersion`] only knows `V2`, an old (v1) or
        // future (v99) number fails to deserialize the enum, which the read
        // path treats as "no usable checkpoint" — no panic, safe full rebuild.
        for stale in [1u8, 3u8, 99u8] {
            let cache = tmp_cache();
            let cp = TreeCheckpoint::new(U256::from(9u64), cursor(1, 0));
            // Serialize a valid checkpoint, then rewrite its version field to a
            // value the enum does not recognize.
            let mut value: serde_json::Value =
                serde_json::from_slice(&serde_json::to_vec(&cp).unwrap()).unwrap();
            value["cache_version"] = serde_json::json!(stale);
            fs::write(checkpoint_path(&cache), serde_json::to_vec(&value).unwrap()).unwrap();

            assert!(
                read_checkpoint(&cache).is_none(),
                "stale version {stale} must be treated as no checkpoint"
            );
            delete_checkpoint(&cache);
        }
    }

    #[test]
    fn cache_version_roundtrips_as_u8() {
        assert_eq!(u8::from(CacheVersion::V2), 2);
        assert_eq!(CacheVersion::try_from(2u8).unwrap(), CacheVersion::V2);
        for bad in [0u8, 1, 3, 99, 255] {
            assert!(CacheVersion::try_from(bad).is_err());
        }
    }

    #[test]
    fn cache_version_serde_roundtrip() {
        // The enum serializes as its numeric wire form and reads back cleanly.
        let json = serde_json::to_string(&CacheVersion::V2).unwrap();
        assert_eq!(json, "2");
        let back: CacheVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CacheVersion::V2);
        // Unknown numbers fail to deserialize.
        assert!(serde_json::from_str::<CacheVersion>("1").is_err());
        assert!(serde_json::from_str::<CacheVersion>("99").is_err());
    }

    #[test]
    fn checkpoint_path_appends_meta() {
        let p = Path::new("/data/tree.mmap");
        assert_eq!(checkpoint_path(p), PathBuf::from("/data/tree.mmap.meta"));
        let p2 = Path::new("/tmp/cache");
        assert_eq!(checkpoint_path(p2), PathBuf::from("/tmp/cache.meta"));
    }
}
