use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::TreeError;

pub const METADATA_VERSION: u32 = 2;

/// Sidecar metadata describing the verified sync-log checkpoint for a mmap cache file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub version: u32,
    pub tree_depth: usize,
    #[serde(flatten)]
    pub status: CacheStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CacheStatus {
    Clean {
        last_verified_batch_id: u64,
    },
    Dirty {
        base_batch_id: u64,
        target_batch_id: u64,
    },
}

impl CacheMetadata {
    pub fn clean(tree_depth: usize, last_verified_batch_id: u64) -> Self {
        Self {
            version: METADATA_VERSION,
            tree_depth,
            status: CacheStatus::Clean {
                last_verified_batch_id,
            },
        }
    }

    pub fn dirty(tree_depth: usize, base_batch_id: u64, target_batch_id: u64) -> Self {
        Self {
            version: METADATA_VERSION,
            tree_depth,
            status: CacheStatus::Dirty {
                base_batch_id,
                target_batch_id,
            },
        }
    }

    pub fn validate_version(&self) -> Result<(), TreeError> {
        if self.version != METADATA_VERSION {
            return Err(TreeError::InvalidCacheMetadata(format!(
                "unsupported metadata version {}",
                self.version
            )));
        }
        Ok(())
    }

    pub fn ensure_tree_depth(&self, expected: usize) -> Result<(), TreeError> {
        if self.tree_depth != expected {
            return Err(TreeError::TreeDepthMismatch {
                metadata: self.tree_depth,
                configured: expected,
            });
        }
        Ok(())
    }
}

/// Returns the sidecar path for a cache file: `<cache_path>.meta.json`.
pub fn metadata_path(cache_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.meta.json", cache_path.display()))
}

pub fn read_metadata(meta_path: &Path) -> Result<CacheMetadata, TreeError> {
    let contents = fs::read_to_string(meta_path).map_err(|source| {
        TreeError::InvalidCacheMetadata(format!("failed to read metadata file: {source}"))
    })?;
    let metadata: CacheMetadata = serde_json::from_str(&contents).map_err(|source| {
        TreeError::InvalidCacheMetadata(format!("failed to parse metadata file: {source}"))
    })?;
    metadata.validate_version()?;
    Ok(metadata)
}

pub fn write_metadata_atomic(meta_path: &Path, metadata: &CacheMetadata) -> Result<(), TreeError> {
    metadata.validate_version()?;

    let parent = meta_path.parent().ok_or(TreeError::InvalidCacheFilePath)?;
    fs::create_dir_all(parent).map_err(|source| {
        TreeError::InvalidCacheMetadata(format!("failed to create metadata directory: {source}"))
    })?;

    let tmp_path = meta_path.with_extension("meta.json.tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|source| {
                TreeError::InvalidCacheMetadata(format!(
                    "failed to open temp metadata file: {source}"
                ))
            })?;
        serde_json::to_writer_pretty(&mut file, metadata).map_err(|source| {
            TreeError::InvalidCacheMetadata(format!("failed to serialize metadata: {source}"))
        })?;
        file.sync_all().map_err(|source| {
            TreeError::InvalidCacheMetadata(format!("failed to fsync temp metadata file: {source}"))
        })?;
    }

    fs::rename(&tmp_path, meta_path).map_err(|source| {
        TreeError::InvalidCacheMetadata(format!("failed to rename metadata file: {source}"))
    })?;

    if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

pub fn write_clean_metadata(
    cache_path: &Path,
    tree_depth: usize,
    last_verified_batch_id: u64,
) -> Result<(), TreeError> {
    let metadata = CacheMetadata::clean(tree_depth, last_verified_batch_id);
    write_metadata_atomic(&metadata_path(cache_path), &metadata)
}

pub fn write_dirty_metadata(
    cache_path: &Path,
    tree_depth: usize,
    base_batch_id: u64,
    target_batch_id: u64,
) -> Result<(), TreeError> {
    let metadata = CacheMetadata::dirty(tree_depth, base_batch_id, target_batch_id);
    write_metadata_atomic(&metadata_path(cache_path), &metadata)
}

pub fn remove_cache_files(cache_path: &Path) {
    if cache_path.exists() {
        if let Err(error) = fs::remove_file(cache_path) {
            warn!(?error, path = %cache_path.display(), "failed to delete cache file");
        }
    }

    let meta_path = metadata_path(cache_path);
    if meta_path.exists() {
        if let Err(error) = fs::remove_file(&meta_path) {
            warn!(?error, path = %meta_path.display(), "failed to delete cache metadata file");
        }
    }
}

pub fn persist_clean_checkpoint(
    cache_path: Option<&Path>,
    tree_depth: usize,
    batch_id: u64,
) -> Result<(), TreeError> {
    let Some(cache_path) = cache_path else {
        return Ok(());
    };

    write_clean_metadata(cache_path, tree_depth, batch_id)?;
    info!(
        batch_id,
        path = %cache_path.display(),
        "wrote clean cache metadata"
    );
    Ok(())
}

pub fn persist_dirty_checkpoint(
    cache_path: Option<&Path>,
    tree_depth: usize,
    base_batch_id: u64,
    target_batch_id: u64,
) -> Result<(), TreeError> {
    let Some(cache_path) = cache_path else {
        return Ok(());
    };

    write_dirty_metadata(cache_path, tree_depth, base_batch_id, target_batch_id)?;
    info!(
        base_batch_id,
        target_batch_id,
        path = %cache_path.display(),
        "wrote dirty cache metadata"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn metadata_roundtrip_and_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("tree.mmap");
        let meta_path = metadata_path(&cache_path);

        write_clean_metadata(&cache_path, 30, 42).unwrap();
        let metadata = read_metadata(&meta_path).unwrap();
        assert_eq!(metadata, CacheMetadata::clean(30, 42));

        write_dirty_metadata(&cache_path, 30, 10, 20).unwrap();
        let metadata = read_metadata(&meta_path).unwrap();
        assert_eq!(metadata, CacheMetadata::dirty(30, 10, 20));

        assert!(!meta_path.with_extension("meta.json.tmp").exists());
        let _ = fs::remove_file(&meta_path);
    }
}
