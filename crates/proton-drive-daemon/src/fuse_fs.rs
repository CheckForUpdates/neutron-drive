use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow, FUSE_ROOT_ID,
};

use crate::client::{RemoteDrive, StorageQuota};
use crate::metadata_db::{generate_uuid, MetadataDB, Node, SyncStatus};

const TTL: Duration = Duration::from_secs(1);
const STREAM_BLOCK_SIZE: u64 = crate::native::transfer::BLOCK_SIZE as u64;

/// Cached `(block_index, decrypted_bytes)` for single-block sequential streaming reads.
pub type StreamBlockCache = Arc<Mutex<Option<(u64, Vec<u8>)>>>;

#[derive(Debug)]
pub struct OpenHandle {
    pub file: Option<File>,
    pub path: String,
    pub cache_id: String,
    pub local_cache: PathBuf,
    pub writable: bool,
    pub wrote: bool,
    pub remote_size: u64,
    pub stream_block_cache: StreamBlockCache,
}

#[derive(Debug)]
pub struct ActivityRegistry {
    pub open_handles: Mutex<HashMap<u64, OpenHandle>>,
    pub inflight: Mutex<HashSet<String>>,
    pub tracked_dirs: Mutex<HashSet<String>>,
}

impl Default for ActivityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivityRegistry {
    pub fn new() -> Self {
        let mut tracked_dirs = HashSet::new();
        tracked_dirs.insert("/".to_string());
        Self {
            open_handles: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashSet::new()),
            tracked_dirs: Mutex::new(tracked_dirs),
        }
    }

    fn normalize_dir_path(path: &str) -> String {
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            "/".to_string()
        } else {
            trimmed.to_string()
        }
    }

    pub fn track_dir(&self, path: &str) {
        let norm = Self::normalize_dir_path(path);
        self.tracked_dirs.lock().unwrap().insert(norm);
    }

    pub fn untrack_dir(&self, path: &str) {
        let clean = Self::normalize_dir_path(path);
        if clean == "/" {
            return;
        }
        let prefix = format!("{}/", clean);
        let mut dirs = self.tracked_dirs.lock().unwrap();
        dirs.retain(|d| d != &clean && !d.starts_with(&prefix));
    }

    pub fn rename_tracked_dirs(&self, old_path: &str, new_path: &str) {
        let clean_old = Self::normalize_dir_path(old_path);
        let clean_new = Self::normalize_dir_path(new_path);
        if clean_old == "/" {
            return;
        }
        let prefix = format!("{}/", clean_old);
        let mut dirs = self.tracked_dirs.lock().unwrap();
        let updated: HashSet<String> = dirs
            .drain()
            .map(|d| {
                if d == clean_old {
                    clean_new.clone()
                } else if d.starts_with(&prefix) {
                    let suffix = &d[clean_old.len()..];
                    format!("{}{}", clean_new, suffix)
                } else {
                    d
                }
            })
            .collect();
        *dirs = updated;
        dirs.insert("/".to_string());
    }

    pub fn tracked_dirs(&self) -> Vec<String> {
        let dirs = self.tracked_dirs.lock().unwrap();
        let mut list: Vec<String> = dirs.iter().cloned().collect();
        list.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
        list
    }

    pub fn has_writable_handle(&self, cache_id: &str) -> bool {
        let handles = self.open_handles.lock().unwrap();
        handles
            .values()
            .any(|h| h.cache_id == cache_id && h.writable)
    }

    pub fn has_open_handle(&self, cache_id: &str) -> bool {
        let handles = self.open_handles.lock().unwrap();
        handles.values().any(|h| h.cache_id == cache_id)
    }

    pub fn is_inflight(&self, cache_id: &str) -> bool {
        let inflight = self.inflight.lock().unwrap();
        inflight.contains(cache_id)
    }

    pub fn mark_inflight(&self, cache_id: &str) -> bool {
        let mut inflight = self.inflight.lock().unwrap();
        inflight.insert(cache_id.to_string())
    }

    pub fn remove_inflight(&self, cache_id: &str) -> bool {
        let mut inflight = self.inflight.lock().unwrap();
        inflight.remove(cache_id)
    }

    pub fn is_inflight_subtree(&self, path: &str, db: &MetadataDB) -> bool {
        let inflight = self.inflight.lock().unwrap();
        if inflight.is_empty() {
            return false;
        }
        if inflight.contains(path) {
            return true;
        }
        if let Some(node) = db.get_node(path) {
            if inflight.contains(&node.cache_id) {
                return true;
            }
        }
        let nodes = db.get_subtree_nodes(path);
        nodes
            .iter()
            .any(|n| inflight.contains(&n.cache_id) || inflight.contains(&n.path))
    }

    pub fn rename_handle_paths(&self, old_path: &str, new_path: &str) {
        let clean_old = if old_path == "/" {
            "/"
        } else {
            old_path.trim_end_matches('/')
        };
        let clean_new = if new_path == "/" {
            "/"
        } else {
            new_path.trim_end_matches('/')
        };
        let prefix = format!("{}/", clean_old);
        let mut handles = self.open_handles.lock().unwrap();
        for handle in handles.values_mut() {
            if handle.path == clean_old {
                handle.path = clean_new.to_string();
            } else if handle.path.starts_with(&prefix) {
                let suffix = &handle.path[clean_old.len()..];
                handle.path = format!("{}{}", clean_new, suffix);
            }
        }
    }

    pub fn clear(&self) {
        self.open_handles.lock().unwrap().clear();
        self.inflight.lock().unwrap().clear();
        let mut dirs = self.tracked_dirs.lock().unwrap();
        dirs.clear();
        dirs.insert("/".to_string());
    }
}

pub fn format_remote_path(root_section: &str, path: &str) -> String {
    let clean = path.trim_matches('/');
    if clean.is_empty() {
        root_section.to_string()
    } else {
        format!("{}/{}", root_section.trim_end_matches('/'), clean)
    }
}

pub fn is_safe_cache_file_path(cache_dir: &Path, path: &Path) -> bool {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } {
            return false;
        }
    }

    let Ok(canonical_cache) = cache_dir.canonicalize() else {
        return false;
    };
    let Ok(canonical_path) = path.canonicalize() else {
        return false;
    };

    canonical_path.starts_with(&canonical_cache) && canonical_path != canonical_cache
}

pub fn reconcile_directory(
    client: &dyn RemoteDrive,
    db: &MetadataDB,
    cache_dir: &Path,
    activity: &ActivityRegistry,
    root_section: &str,
    path: &str,
) -> Result<(), String> {
    if path == "/" && db.get_node("/").is_none() {
        let _ = db.upsert_node(
            "/",
            "",
            "",
            "folder",
            0,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            None,
            None,
            Some(true),
            None,
        );
    }

    let remote = format_remote_path(root_section, path);
    let items = client.list_path(&remote)?;

    let mut remote_names = HashSet::new();
    for item in &items {
        let name = &item.name;
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            continue;
        }
        remote_names.insert(name.clone());

        let child_path = if path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", path.trim_end_matches('/'), name)
        };

        let existing = db.get_node(&child_path);
        match existing {
            None => {
                let _ = db.upsert_node(
                    &child_path,
                    path,
                    name,
                    &item.node_type,
                    item.size,
                    item.modify_time,
                    None,
                    Some(SyncStatus::CLOUD_ONLY),
                    None,
                    item.uid.as_deref(),
                    None,
                    None,
                    Some(true),
                    None,
                );
            }
            Some(ex) => {
                let is_dirty = ex.sync_status == SyncStatus::MODIFIED
                    || ex.sync_status == SyncStatus::SYNCING
                    || ex.sync_status == SyncStatus::ERROR;
                let is_inflight =
                    activity.is_inflight(&ex.cache_id) || activity.is_inflight(&ex.path);
                let has_open = activity.has_open_handle(&ex.cache_id);

                if is_dirty || is_inflight || has_open {
                    continue;
                }

                if ex.sync_status == SyncStatus::SYNCED || ex.sync_status == SyncStatus::CLOUD_ONLY
                {
                    let size_changed =
                        ex.node_type != "folder" && ex.node_type != "album" && item.size != ex.size;
                    let mtime_changed = match item.modify_time {
                        Some(t) => (t - ex.mtime).abs() > 0.001,
                        None => false,
                    };
                    let uid_changed =
                        item.uid.is_some() && item.uid.as_deref() != ex.uid.as_deref();
                    let type_changed = item.node_type != ex.node_type;

                    if size_changed || mtime_changed || uid_changed || type_changed {
                        if ex.sync_status == SyncStatus::SYNCED && ex.local_cache_path.is_some() {
                            if let Some(ref lp) = ex.local_cache_path {
                                let p = PathBuf::from(lp);
                                if is_safe_cache_file_path(cache_dir, &p) {
                                    let _ = fs::remove_file(&p);
                                }
                            }
                            let _ = db.invalidate_node_cache(
                                &child_path,
                                item.size,
                                item.modify_time,
                                item.uid.as_deref(),
                                &item.node_type,
                            );
                        } else {
                            let _ = db.update_clean_remote_metadata(
                                &child_path,
                                item.size,
                                item.modify_time,
                                item.uid.as_deref(),
                                &item.node_type,
                            );
                        }
                    } else {
                        let _ = db.update_remote_exists(&child_path, true);
                    }
                }
            }
        }
    }

    let local_children = db.get_children(path);
    for child in local_children {
        if !remote_names.contains(&child.name) {
            let is_local_only = !child.remote_exists;
            let is_dirty = child.sync_status == SyncStatus::MODIFIED
                || child.sync_status == SyncStatus::SYNCING
                || child.sync_status == SyncStatus::ERROR;
            let is_inflight =
                activity.is_inflight(&child.cache_id) || activity.is_inflight(&child.path);
            let has_open = activity.has_open_handle(&child.cache_id);

            let has_dirty_descendant = (child.node_type == "folder" || child.node_type == "album")
                && {
                    let subtree = db.get_subtree_nodes(&child.path);
                    subtree.iter().any(|n| {
                        !n.remote_exists
                            || n.sync_status == SyncStatus::MODIFIED
                            || n.sync_status == SyncStatus::SYNCING
                            || n.sync_status == SyncStatus::ERROR
                            || activity.is_inflight(&n.cache_id)
                            || activity.is_inflight(&n.path)
                            || activity.has_open_handle(&n.cache_id)
                    })
                };

            if is_local_only || is_dirty || is_inflight || has_open || has_dirty_descendant {
                continue;
            }

            if child.remote_exists
                && (child.sync_status == SyncStatus::SYNCED
                    || child.sync_status == SyncStatus::CLOUD_ONLY)
            {
                let subtree = if child.node_type == "folder" || child.node_type == "album" {
                    db.get_subtree_nodes(&child.path)
                } else {
                    vec![child.clone()]
                };

                db.delete_node(&child.path);
                if child.node_type == "folder" || child.node_type == "album" {
                    activity.untrack_dir(&child.path);
                }

                for n in subtree {
                    if let Some(ref lp) = n.local_cache_path {
                        let p = PathBuf::from(lp);
                        if is_safe_cache_file_path(cache_dir, &p) {
                            let _ = fs::remove_file(&p);
                        }
                    }
                }
            }
        }
    }

    client.backfill_native_ids(db);
    db.update_last_checked(path);
    Ok(())
}

fn is_protected_by_pin(node: &Node, pinned_roots: &[String]) -> bool {
    if node.pinned {
        return true;
    }
    pinned_roots.iter().any(|root| {
        if root == "/" || root == &node.path {
            return true;
        }
        let prefix = format!("{}/", root.trim_end_matches('/'));
        node.path.starts_with(&prefix)
    })
}

pub fn evict_cache_by_policy(
    db: &MetadataDB,
    cache_dir: &Path,
    activity: &ActivityRegistry,
    max_size_bytes: u64,
    ttl: Option<Duration>,
) -> (usize, usize) {
    let nodes = db.get_all_nodes();
    let pinned_roots = db.list_pinned_paths();
    let mut evicted = 0;
    let mut skipped = 0;
    let mut total_bytes_on_disk: u64 = 0;
    let mut eligible: Vec<(SystemTime, String, PathBuf, u64)> = Vec::new();
    let now = SystemTime::now();

    for node in nodes {
        if node.node_type != "file" {
            continue;
        }

        let Some(ref lp) = node.local_cache_path else {
            continue;
        };

        let p = PathBuf::from(lp);
        if !is_safe_cache_file_path(cache_dir, &p) {
            skipped += 1;
            continue;
        }

        let meta = match fs::metadata(&p) {
            Ok(m) => m,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let file_len = meta.len();
        let modified_time = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        if node.sync_status != SyncStatus::SYNCED
            || !node.remote_exists
            || is_protected_by_pin(&node, &pinned_roots)
            || activity.is_inflight(&node.cache_id)
            || activity.is_inflight(&node.path)
            || activity.has_open_handle(&node.cache_id)
        {
            total_bytes_on_disk = total_bytes_on_disk.saturating_add(file_len);
            skipped += 1;
            continue;
        }

        if let Some(max_age) = ttl {
            if !max_age.is_zero() && now.duration_since(modified_time).unwrap_or_default() > max_age
            {
                if fs::remove_file(&p).is_ok() {
                    db.clear_local_cache(&node.path);
                    evicted += 1;
                    continue;
                } else {
                    total_bytes_on_disk = total_bytes_on_disk.saturating_add(file_len);
                    skipped += 1;
                    continue;
                }
            }
        }

        total_bytes_on_disk = total_bytes_on_disk.saturating_add(file_len);
        eligible.push((modified_time, node.path, p, file_len));
    }

    if max_size_bytes > 0 && total_bytes_on_disk > max_size_bytes {
        eligible.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        for (_, node_path, p, file_len) in eligible {
            if total_bytes_on_disk <= max_size_bytes {
                break;
            }
            if fs::remove_file(&p).is_ok() {
                db.clear_local_cache(&node_path);
                total_bytes_on_disk = total_bytes_on_disk.saturating_sub(file_len);
                evicted += 1;
            } else {
                skipped += 1;
            }
        }
    }

    (evicted, skipped)
}

const STATFS_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Default)]
struct QuotaCacheState {
    quota: StorageQuota,
    last_updated: Option<Instant>,
    last_attempt: Option<Instant>,
    inflight: bool,
}

#[derive(Default)]
struct DirRefreshTracker {
    inflight: HashSet<String>,
    last_attempt: HashMap<String, Instant>,
}

#[derive(Clone)]
pub struct ProtonDriveFUSE {
    client: Arc<dyn RemoteDrive>,
    db: MetadataDB,
    cache_dir: PathBuf,
    root_section: String,
    next_fh: Arc<Mutex<u64>>,
    activity: Arc<ActivityRegistry>,
    inode_to_path: Arc<Mutex<HashMap<u64, String>>>,
    path_to_inode: Arc<Mutex<HashMap<String, u64>>>,
    next_inode: Arc<Mutex<u64>>,
    quota_cache: Arc<Mutex<QuotaCacheState>>,
    dir_refresh: Arc<Mutex<DirRefreshTracker>>,
}

impl ProtonDriveFUSE {
    pub fn new(
        client: Arc<dyn RemoteDrive>,
        db: MetadataDB,
        cache_dir: PathBuf,
        root_section: Option<&str>,
        activity: Arc<ActivityRegistry>,
    ) -> Self {
        let _ = fs::create_dir_all(&cache_dir);
        #[cfg(unix)]
        let _ = fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700));

        let mut inode_to_path = HashMap::new();
        let mut path_to_inode = HashMap::new();
        inode_to_path.insert(FUSE_ROOT_ID, "/".to_string());
        path_to_inode.insert("/".to_string(), FUSE_ROOT_ID);

        let fs = Self {
            client,
            db,
            cache_dir,
            root_section: root_section
                .unwrap_or("/my-files")
                .trim_end_matches('/')
                .to_string(),
            next_fh: Arc::new(Mutex::new(100)),
            activity,
            inode_to_path: Arc::new(Mutex::new(inode_to_path)),
            path_to_inode: Arc::new(Mutex::new(path_to_inode)),
            next_inode: Arc::new(Mutex::new(FUSE_ROOT_ID + 1)),
            quota_cache: Arc::new(Mutex::new(QuotaCacheState::default())),
            dir_refresh: Arc::new(Mutex::new(DirRefreshTracker::default())),
        };

        fs.ensure_root_node();
        fs
    }

    pub fn new_standalone(
        client: Arc<dyn RemoteDrive>,
        db: MetadataDB,
        cache_dir: PathBuf,
        root_section: Option<&str>,
    ) -> Self {
        Self::new(
            client,
            db,
            cache_dir,
            root_section,
            Arc::new(ActivityRegistry::new()),
        )
    }

    pub fn activity(&self) -> &Arc<ActivityRegistry> {
        &self.activity
    }

    fn ensure_root_node(&self) {
        if self.db.get_node("/").is_none() {
            let _ = self.db.upsert_node(
                "/",
                "",
                "",
                "folder",
                0,
                None,
                None,
                Some(SyncStatus::SYNCED),
                None,
                None,
                None,
                None,
                Some(true),
                None,
            );
        }
    }

    pub fn get_or_create_inode(&self, path: &str) -> u64 {
        let mut p2i = self.path_to_inode.lock().unwrap();
        let mut i2p = self.inode_to_path.lock().unwrap();
        if let Some(&ino) = p2i.get(path) {
            return ino;
        }
        let mut next = self.next_inode.lock().unwrap();
        let ino = *next;
        *next += 1;
        p2i.insert(path.to_string(), ino);
        i2p.insert(ino, path.to_string());
        ino
    }

    pub fn get_path_for_inode(&self, ino: u64) -> Option<String> {
        let i2p = self.inode_to_path.lock().unwrap();
        i2p.get(&ino).cloned()
    }

    pub fn get_inode_for_path(&self, path: &str) -> Option<u64> {
        let p2i = self.path_to_inode.lock().unwrap();
        p2i.get(path).copied()
    }

    pub fn update_inode_paths(&self, old_path: &str, new_path: &str) {
        let clean_old = if old_path == "/" {
            "/"
        } else {
            old_path.trim_end_matches('/')
        };
        let clean_new = if new_path == "/" {
            "/"
        } else {
            new_path.trim_end_matches('/')
        };
        let prefix = format!("{}/", clean_old);

        let mut p2i = self.path_to_inode.lock().unwrap();
        let mut i2p = self.inode_to_path.lock().unwrap();

        let to_update: Vec<(String, String, u64)> = p2i
            .iter()
            .filter_map(|(p, &ino)| {
                if p == clean_old {
                    Some((p.clone(), clean_new.to_string(), ino))
                } else if p.starts_with(&prefix) {
                    let suffix = &p[clean_old.len()..];
                    let updated = format!("{}{}", clean_new, suffix);
                    Some((p.clone(), updated, ino))
                } else {
                    None
                }
            })
            .collect();

        for (old_p, new_p, ino) in to_update {
            p2i.remove(&old_p);
            p2i.insert(new_p.clone(), ino);
            i2p.insert(ino, new_p);
        }
    }

    pub fn to_remote_path(&self, path: &str) -> String {
        format_remote_path(&self.root_section, path)
    }

    fn cache_path_for_node(&self, node: &Node) -> PathBuf {
        if let Some(ref lp) = node.local_cache_path {
            let p = PathBuf::from(lp);
            if p.parent() == Some(&self.cache_dir) {
                return p;
            }
        }
        self.cache_dir.join(format!("{}.dat", node.cache_id))
    }

    pub fn is_safe_cache_file(&self, path: &Path) -> bool {
        is_safe_cache_file_path(&self.cache_dir, path)
    }

    pub fn node_to_attr(&self, ino: u64, node: &Node) -> FileAttr {
        let now = SystemTime::now();
        let mtime = UNIX_EPOCH + Duration::from_secs_f64(node.mtime.max(0.0));
        let is_dir = node.node_type == "folder" || node.node_type == "album";
        let size = if is_dir {
            4096
        } else if let Some(ref lp) = node.local_cache_path {
            fs::metadata(lp)
                .map(|m| m.len())
                .unwrap_or(node.size.max(0) as u64)
        } else {
            node.size.max(0) as u64
        };

        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: now,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind: if is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if is_dir { 0o700 } else { 0o600 },
            nlink: if is_dir { 2 } else { 1 },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    pub fn reconcile_dir(&self, path: &str) -> Result<(), String> {
        reconcile_directory(
            &*self.client,
            &self.db,
            &self.cache_dir,
            &self.activity,
            &self.root_section,
            path,
        )
    }

    pub fn refresh_dir_if_needed(&self, path: &str, max_age_sec: f64) {
        let node = self.db.get_node(path);
        let now = crate::metadata_db::now_sec();
        if let Some(ref n) = node {
            if now - n.last_checked.unwrap_or(0.0) < max_age_sec {
                self.activity.track_dir(path);
                return;
            }
        }

        if self.reconcile_dir(path).is_ok() {
            self.activity.track_dir(path);
        }
    }

    fn should_attempt_sync_refresh(&self, path: &str, cooldown_sec: f64) -> bool {
        let mut tracker = self.dir_refresh.lock().unwrap();
        if tracker.inflight.contains(path) {
            return false;
        }
        if let Some(prev) = tracker.last_attempt.get(path) {
            if prev.elapsed().as_secs_f64() < cooldown_sec {
                return false;
            }
        }
        tracker
            .last_attempt
            .insert(path.to_string(), Instant::now());
        true
    }

    fn refresh_dir_for_fuse(&self, path: &str, max_age_sec: f64) {
        let dir_node = self.db.get_node(path);
        let never_checked = dir_node.as_ref().and_then(|n| n.last_checked).is_none();
        if never_checked {
            if self.should_attempt_sync_refresh(path, 5.0) {
                self.refresh_dir_if_needed(path, max_age_sec);
            }
        } else {
            let age = crate::metadata_db::now_sec()
                - dir_node.and_then(|n| n.last_checked).unwrap_or(0.0);
            if age >= max_age_sec {
                self.trigger_background_dir_refresh(path, 5.0_f64.max(max_age_sec.min(10.0)));
            } else {
                self.activity.track_dir(path);
            }
        }
    }

    pub fn trigger_background_dir_refresh(&self, path: &str, min_cooldown_sec: f64) {
        {
            let mut tracker = self.dir_refresh.lock().unwrap();
            if tracker.inflight.contains(path) {
                return;
            }
            if let Some(prev) = tracker.last_attempt.get(path) {
                if prev.elapsed().as_secs_f64() < min_cooldown_sec {
                    return;
                }
            }
            tracker.inflight.insert(path.to_string());
            tracker
                .last_attempt
                .insert(path.to_string(), Instant::now());
        }

        let fuse_c = self.clone();
        let path_owned = path.to_string();
        if std::thread::Builder::new()
            .name("fuse-dir-refresh".to_string())
            .spawn(move || {
                struct InflightGuard {
                    tracker: Arc<Mutex<DirRefreshTracker>>,
                    path: String,
                }
                impl Drop for InflightGuard {
                    fn drop(&mut self) {
                        if let Ok(mut guard) = self.tracker.lock() {
                            guard.inflight.remove(&self.path);
                        }
                    }
                }
                let _guard = InflightGuard {
                    tracker: Arc::clone(&fuse_c.dir_refresh),
                    path: path_owned.clone(),
                };
                if fuse_c.reconcile_dir(&path_owned).is_ok() {
                    fuse_c.activity.track_dir(&path_owned);
                }
            })
            .is_err()
        {
            if let Ok(mut guard) = self.dir_refresh.lock() {
                guard.inflight.remove(path);
            }
        }
    }

    pub fn hydrate(&self, path: &str, node: &Node) -> Result<PathBuf, libc::c_int> {
        let local_cache = self.cache_path_for_node(node);
        if local_cache.exists() && node.sync_status != SyncStatus::CLOUD_ONLY {
            return Ok(local_cache);
        }

        self.activity.mark_inflight(&node.cache_id);
        struct InflightGuard<'a> {
            activity: &'a ActivityRegistry,
            cache_id: &'a str,
        }
        impl<'a> Drop for InflightGuard<'a> {
            fn drop(&mut self) {
                self.activity.remove_inflight(self.cache_id);
            }
        }
        let _guard = InflightGuard {
            activity: &self.activity,
            cache_id: &node.cache_id,
        };

        let temp_dir = tempfile::Builder::new()
            .prefix("download-")
            .tempdir_in(&self.cache_dir)
            .map_err(|_| libc::EIO)?;

        let remote = self.to_remote_path(path);
        let success = self
            .client
            .download_file(&remote, temp_dir.path(), "remove");
        let downloaded = temp_dir.path().join(&node.name);

        if !success || !downloaded.exists() {
            self.db
                .update_sync_status(path, SyncStatus::CLOUD_ONLY, None, Some("Download failed"));
            return Err(libc::EIO);
        }

        #[cfg(unix)]
        let _ = fs::set_permissions(&downloaded, fs::Permissions::from_mode(0o600));

        fs::rename(&downloaded, &local_cache).map_err(|_| libc::EIO)?;

        self.db.update_sync_status(
            path,
            SyncStatus::SYNCED,
            Some(&local_cache.to_string_lossy()),
            None,
        );
        Ok(local_cache)
    }

    pub fn evict_clean_cache(&self) -> (usize, usize) {
        let nodes = self.db.get_all_nodes();
        let pinned_roots = self.db.list_pinned_paths();
        let mut evicted = 0;
        let mut skipped = 0;

        for node in nodes {
            if node.node_type != "file" {
                continue;
            }
            if node.sync_status != SyncStatus::SYNCED
                || !node.remote_exists
                || is_protected_by_pin(&node, &pinned_roots)
            {
                skipped += 1;
                continue;
            }
            if self.activity.is_inflight(&node.cache_id)
                || self.activity.is_inflight(&node.path)
                || self.activity.has_open_handle(&node.cache_id)
            {
                skipped += 1;
                continue;
            }

            if let Some(ref lp) = node.local_cache_path {
                let p = PathBuf::from(lp);
                if self.is_safe_cache_file(&p) && fs::remove_file(&p).is_ok() {
                    self.db.clear_local_cache(&node.path);
                    evicted += 1;
                    continue;
                }
            }
            skipped += 1;
        }
        (evicted, skipped)
    }

    pub fn hydrate_pinned_target(&self, virtual_path: &str) -> (usize, usize) {
        let Some(target) = self.db.get_node(virtual_path) else {
            return (0, 0);
        };

        if target.node_type == "file" {
            let needs_hydration = target.remote_exists
                && (target.sync_status == SyncStatus::CLOUD_ONLY
                    || target.local_cache_path.is_none());
            if !needs_hydration {
                return (0, 0);
            }
            return match self.hydrate(&target.path, &target) {
                Ok(_) => (1, 0),
                Err(_) => (0, 1),
            };
        }

        let prefix = if virtual_path == "/" {
            "/".to_string()
        } else {
            format!("{}/", virtual_path.trim_end_matches('/'))
        };
        let mut hydrated = 0;
        let mut failed = 0;
        for node in self.db.get_all_nodes() {
            if node.node_type != "file" || !node.remote_exists {
                continue;
            }
            if virtual_path != "/" && !node.path.starts_with(&prefix) {
                continue;
            }
            let needs_hydration =
                node.sync_status == SyncStatus::CLOUD_ONLY || node.local_cache_path.is_none();
            if !needs_hydration {
                continue;
            }
            match self.hydrate(&node.path, &node) {
                Ok(_) => hydrated += 1,
                Err(_) => failed += 1,
            }
        }
        (hydrated, failed)
    }

    pub fn evict_cache_by_policy(
        &self,
        max_size_bytes: u64,
        ttl: Option<Duration>,
    ) -> (usize, usize) {
        evict_cache_by_policy(
            &self.db,
            &self.cache_dir,
            &self.activity,
            max_size_bytes,
            ttl,
        )
    }

    pub fn update_cached_quota(&self, quota: StorageQuota) {
        if let Ok(mut guard) = self.quota_cache.lock() {
            guard.quota = quota;
            guard.last_updated = Some(Instant::now());
            guard.last_attempt = Some(Instant::now());
        }
    }

    fn statfs_from_quota(&self, quota: &StorageQuota) -> (u64, u64, u64, u64, u64, u32, u32, u32) {
        let bsize: u32 = 4096;
        // `proton-drive filesystem size` only reports used_bytes (total_bytes == 0).
        // Fall back to a 100 GiB virtual free ceiling so file managers don't see a 4 KiB disk.
        let effective_total = if quota.total_bytes > 0 {
            quota.total_bytes
        } else {
            quota.used_bytes.saturating_add(100 * 1024 * 1024 * 1024)
        };
        let total_blocks = (effective_total / u64::from(bsize)).max(1);
        let used_blocks = quota.used_bytes.min(effective_total) / u64::from(bsize);
        let free_blocks = total_blocks.saturating_sub(used_blocks);
        let files = self.db.get_all_nodes().len() as u64;
        (
            total_blocks,
            free_blocks,
            free_blocks,
            files,
            1_000_000,
            bsize,
            255,
            bsize,
        )
    }

    pub fn compute_statfs(&self) -> (u64, u64, u64, u64, u64, u32, u32, u32) {
        let quota = self.client.get_storage_quota();
        self.update_cached_quota(quota.clone());
        self.statfs_from_quota(&quota)
    }

    pub fn compute_statfs_nonblocking(&self) -> (u64, u64, u64, u64, u64, u32, u32, u32) {
        let cached_quota = {
            let mut guard = self.quota_cache.lock().unwrap();
            let stale = guard
                .last_attempt
                .map(|t| t.elapsed() >= STATFS_CACHE_TTL)
                .unwrap_or(true);
            if stale && !guard.inflight {
                guard.inflight = true;
                guard.last_attempt = Some(Instant::now());
                let client_c = Arc::clone(&self.client);
                let cache_c = Arc::clone(&self.quota_cache);
                if std::thread::Builder::new()
                    .name("fuse-statfs-quota".to_string())
                    .spawn(move || {
                        let quota = client_c.get_storage_quota();
                        if let Ok(mut qguard) = cache_c.lock() {
                            if quota.total_bytes > 0
                                || quota.used_bytes > 0
                                || qguard.last_updated.is_none()
                            {
                                qguard.quota = quota;
                                qguard.last_updated = Some(Instant::now());
                            }
                            qguard.inflight = false;
                        }
                    })
                    .is_err()
                {
                    guard.inflight = false;
                }
            }
            guard.quota.clone()
        };
        self.statfs_from_quota(&cached_quota)
    }

    pub fn create_dir(&self, parent_path: &str, name: &str) -> Result<Node, libc::c_int> {
        let remote_parent = self.to_remote_path(parent_path);
        if !self.client.create_folder(&remote_parent, name) {
            return Err(libc::EIO);
        }

        let child_path = if parent_path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent_path.trim_end_matches('/'), name)
        };

        let _ = self.db.upsert_node(
            &child_path,
            parent_path,
            name,
            "folder",
            0,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            None,
            None,
            Some(true),
            None,
        );

        self.db.get_node(&child_path).ok_or(libc::EIO)
    }

    pub fn remove_dir(&self, parent_path: &str, name: &str) -> Result<(), libc::c_int> {
        let child_path = if parent_path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent_path.trim_end_matches('/'), name)
        };

        if !self.db.get_children(&child_path).is_empty() {
            return Err(libc::ENOTEMPTY);
        }

        let remote = self.to_remote_path(&child_path);
        if !self.client.trash(&remote) {
            return Err(libc::EIO);
        }

        self.db.delete_node(&child_path);
        self.activity.untrack_dir(&child_path);
        Ok(())
    }

    pub fn unlink_file(&self, parent_path: &str, name: &str) -> Result<(), libc::c_int> {
        let child_path = if parent_path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent_path.trim_end_matches('/'), name)
        };

        let node = match self.db.get_node(&child_path) {
            Some(n) => n,
            None => return Err(libc::ENOENT),
        };

        if node.remote_exists {
            let remote = self.to_remote_path(&child_path);
            if !self.client.trash(&remote) {
                return Err(libc::EIO);
            }
        }

        self.db.delete_node(&child_path);
        if let Some(ref lp) = node.local_cache_path {
            let _ = fs::remove_file(lp);
        }
        Ok(())
    }

    fn join_fuse_path(parent: &str, name: &str) -> String {
        if parent == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent.trim_end_matches('/'), name)
        }
    }

    fn remove_inode_for_path(&self, path: &str) {
        let mut p2i = self.path_to_inode.lock().unwrap();
        let mut i2p = self.inode_to_path.lock().unwrap();
        if let Some(ino) = p2i.remove(path) {
            i2p.remove(&ino);
        }
    }

    pub fn rename_node(
        &self,
        old_parent: &str,
        old_name: &str,
        new_parent: &str,
        new_name: &str,
    ) -> Result<(), libc::c_int> {
        let old_path = Self::join_fuse_path(old_parent, old_name);
        let new_path = Self::join_fuse_path(new_parent, new_name);

        let node = match self.db.get_node(&old_path) {
            Some(n) => n,
            None => return Err(libc::ENOENT),
        };

        if old_path == new_path {
            return Ok(());
        }

        let node_is_dir = node.node_type == "folder";
        if node_is_dir && new_path.starts_with(&format!("{}/", old_path.trim_end_matches('/'))) {
            return Err(libc::EINVAL);
        }

        if self.activity.is_inflight_subtree(&old_path, &self.db) {
            return Err(libc::EBUSY);
        }

        let norm_old_parent = if old_parent == "/" {
            "/"
        } else {
            old_parent.trim_end_matches('/')
        };
        let norm_new_parent = if new_parent == "/" {
            "/"
        } else {
            new_parent.trim_end_matches('/')
        };

        let is_cross_parent_rename =
            norm_old_parent != norm_new_parent && old_name != new_name && node.remote_exists;
        let use_atomic_move_and_rename =
            is_cross_parent_rename && self.client.supports_atomic_move_and_rename();

        // Pre-validate non-colliding intermediate path before any remote mutation
        // when the backend must sequence separate rename and move calls.
        let use_rename_then_move = if is_cross_parent_rename && !use_atomic_move_and_rename {
            let inter_rename_first = Self::join_fuse_path(norm_old_parent, new_name);
            let inter_move_first = Self::join_fuse_path(norm_new_parent, old_name);
            if self.db.get_node(&inter_rename_first).is_none() {
                true
            } else if self.db.get_node(&inter_move_first).is_none() {
                false
            } else {
                return Err(libc::EEXIST);
            }
        } else {
            false
        };

        // POSIX atomic overwrite validation & target cleanup when destination exists.
        if let Some(target) = self.db.get_node(&new_path) {
            let target_is_dir = target.node_type == "folder";
            if node_is_dir && !target_is_dir {
                return Err(libc::ENOTDIR);
            }
            if !node_is_dir && target_is_dir {
                return Err(libc::EISDIR);
            }
            if target_is_dir && !self.db.get_children(&new_path).is_empty() {
                return Err(libc::ENOTEMPTY);
            }
            if self.activity.is_inflight_subtree(&new_path, &self.db) {
                return Err(libc::EBUSY);
            }

            if target.remote_exists {
                let remote_target = self.to_remote_path(&new_path);
                if !self.client.trash(&remote_target) {
                    return Err(libc::EIO);
                }
            }

            self.db.delete_node(&new_path);
            if let Some(ref lp) = target.local_cache_path {
                let _ = fs::remove_file(lp);
            }
            if target_is_dir {
                self.activity.untrack_dir(&new_path);
            }
            self.remove_inode_for_path(&new_path);
        }

        if node.remote_exists {
            let remote_old = self.to_remote_path(&old_path);
            let remote_new_parent = self.to_remote_path(norm_new_parent);
            let success = if use_atomic_move_and_rename {
                self.client
                    .move_and_rename(&remote_old, &remote_new_parent, new_name)
            } else if is_cross_parent_rename {
                if use_rename_then_move {
                    if !self.client.rename(&remote_old, new_name) {
                        false
                    } else {
                        let inter_path = Self::join_fuse_path(norm_old_parent, new_name);
                        let remote_inter = self.to_remote_path(&inter_path);
                        if self.client.move_node(&remote_inter, &remote_new_parent) {
                            true
                        } else {
                            // Best-effort rollback to keep remote consistent with local DB.
                            let _ = self.client.rename(&remote_inter, old_name);
                            false
                        }
                    }
                } else if !self.client.move_node(&remote_old, &remote_new_parent) {
                    false
                } else {
                    let inter_path = Self::join_fuse_path(norm_new_parent, old_name);
                    let remote_inter = self.to_remote_path(&inter_path);
                    if self.client.rename(&remote_inter, new_name) {
                        true
                    } else {
                        let remote_old_parent = self.to_remote_path(norm_old_parent);
                        let _ = self.client.move_node(&remote_inter, &remote_old_parent);
                        false
                    }
                }
            } else if norm_old_parent == norm_new_parent {
                self.client.rename(&remote_old, new_name)
            } else {
                self.client.move_node(&remote_old, &remote_new_parent)
            };
            if !success {
                return Err(libc::EIO);
            }
        }

        if self.db.move_subtree(&old_path, &new_path).is_err() {
            return Err(libc::EIO);
        }

        self.activity.rename_handle_paths(&old_path, &new_path);
        self.activity.rename_tracked_dirs(&old_path, &new_path);
        self.update_inode_paths(&old_path, &new_path);

        Ok(())
    }

    pub fn sync_cache_directory(&self) -> Result<(), std::io::Error> {
        if let Ok(dir) = File::open(&self.cache_dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    pub fn open_file_handle(&self, path: &str, writable: bool) -> Result<u64, std::io::Error> {
        let node = self
            .db
            .get_node(path)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;

        let cache_path = self.cache_path_for_node(&node);
        let use_streaming = !writable
            && node.sync_status == SyncStatus::CLOUD_ONLY
            && self.client.supports_block_range_reads()
            && !cache_path.exists();

        let (file, local_cache) = if use_streaming {
            (None, cache_path)
        } else {
            let local_cache = self
                .hydrate(path, &node)
                .map_err(std::io::Error::from_raw_os_error)?;

            let file = OpenOptions::new()
                .read(true)
                .write(writable)
                .open(&local_cache)?;
            (Some(file), local_cache)
        };

        let fh = {
            let mut next = self.next_fh.lock().unwrap();
            let val = *next;
            *next += 1;
            val
        };

        let handle = OpenHandle {
            file,
            path: path.to_string(),
            cache_id: node.cache_id.clone(),
            local_cache,
            writable,
            wrote: false,
            remote_size: u64::try_from(node.size.max(0)).unwrap_or(0),
            stream_block_cache: Arc::new(Mutex::new(None)),
        };

        self.activity
            .open_handles
            .lock()
            .unwrap()
            .insert(fh, handle);
        Ok(fh)
    }

    pub fn create_file_handle(
        &self,
        parent_path: &str,
        name_str: &str,
    ) -> Result<u64, std::io::Error> {
        let child_path = if parent_path == "/" {
            format!("/{}", name_str)
        } else {
            format!("{}/{}", parent_path.trim_end_matches('/'), name_str)
        };

        if self.db.get_node(&child_path).is_some() {
            return Err(std::io::Error::from_raw_os_error(libc::EEXIST));
        }

        let cache_id = generate_uuid();
        let local_cache = self.cache_dir.join(format!("{}.dat", cache_id));

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&local_cache)?;

        #[cfg(unix)]
        let _ = fs::set_permissions(&local_cache, fs::Permissions::from_mode(0o600));

        let _ = self.db.upsert_node(
            &child_path,
            parent_path,
            name_str,
            "file",
            0,
            None,
            Some(&local_cache.to_string_lossy()),
            Some(SyncStatus::MODIFIED),
            None,
            None,
            Some(&cache_id),
            Some(1),
            Some(false),
            None,
        );

        let _ino = self.get_or_create_inode(&child_path);

        let fh = {
            let mut next = self.next_fh.lock().unwrap();
            let val = *next;
            *next += 1;
            val
        };

        let handle = OpenHandle {
            file: Some(file),
            path: child_path,
            cache_id,
            local_cache,
            writable: true,
            wrote: true,
            remote_size: 0,
            stream_block_cache: Arc::new(Mutex::new(None)),
        };

        self.activity
            .open_handles
            .lock()
            .unwrap()
            .insert(fh, handle);
        Ok(fh)
    }

    pub fn read_from_handle(
        &self,
        fh: u64,
        offset: u64,
        size: usize,
    ) -> Result<Vec<u8>, std::io::Error> {
        enum ReadTarget {
            Local(File),
            Streaming {
                path: String,
                remote_size: u64,
                block_cache: StreamBlockCache,
            },
        }

        let target = {
            let handles = self.activity.open_handles.lock().unwrap();
            let handle = handles
                .get(&fh)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EBADF))?;
            if let Some(ref f) = handle.file {
                ReadTarget::Local(f.try_clone()?)
            } else {
                ReadTarget::Streaming {
                    path: handle.path.clone(),
                    remote_size: handle.remote_size,
                    block_cache: Arc::clone(&handle.stream_block_cache),
                }
            }
        };

        match target {
            ReadTarget::Local(file_clone) => {
                let mut buf = vec![0u8; size];
                let bytes_read = file_clone.read_at(&mut buf, offset)?;
                buf.truncate(bytes_read);
                Ok(buf)
            }
            ReadTarget::Streaming {
                path,
                remote_size,
                block_cache,
            } => self.read_streaming_blocks(fh, &path, remote_size, &block_cache, offset, size),
        }
    }

    fn read_streaming_blocks(
        &self,
        fh: u64,
        path: &str,
        remote_size: u64,
        block_cache: &Mutex<Option<(u64, Vec<u8>)>>,
        offset: u64,
        size: usize,
    ) -> Result<Vec<u8>, std::io::Error> {
        if size == 0 || offset >= remote_size {
            return Ok(Vec::new());
        }

        let remaining = (remote_size - offset).min(size as u64) as usize;
        if remaining == 0 {
            return Ok(Vec::new());
        }

        let remote_path = self.to_remote_path(path);
        let start_block = offset / STREAM_BLOCK_SIZE;
        let end_block = (offset + remaining as u64 - 1) / STREAM_BLOCK_SIZE;
        let mut out = Vec::with_capacity(remaining);

        for block_idx in start_block..=end_block {
            let block_global_start = block_idx * STREAM_BLOCK_SIZE;
            let within_start = offset.saturating_sub(block_global_start) as usize;
            let within_end = (offset + remaining as u64)
                .saturating_sub(block_global_start)
                .min(STREAM_BLOCK_SIZE) as usize;
            let expected_slice_len = within_end.saturating_sub(within_start);

            let cached_slice = {
                let guard = block_cache.lock().unwrap();
                match *guard {
                    Some((cached_idx, ref block_bytes)) if cached_idx == block_idx => {
                        if within_start >= block_bytes.len() {
                            Some(Vec::new())
                        } else {
                            let end = within_end.min(block_bytes.len());
                            Some(block_bytes[within_start..end].to_vec())
                        }
                    }
                    _ => None,
                }
            };

            if let Some(slice) = cached_slice {
                let eof = slice.len() < expected_slice_len;
                out.extend_from_slice(&slice);
                if eof {
                    break;
                }
                continue;
            }

            match self.client.read_block_range(
                &remote_path,
                block_global_start,
                STREAM_BLOCK_SIZE as usize,
            ) {
                Some(Ok(block_bytes)) => {
                    let block_len = block_bytes.len();
                    if within_start < block_len {
                        let end = within_end.min(block_len);
                        out.extend_from_slice(&block_bytes[within_start..end]);
                    }
                    *block_cache.lock().unwrap() = Some((block_idx, block_bytes));
                    if block_len < within_end {
                        break;
                    }
                }
                Some(Err(err)) => {
                    log::error!(
                        "Streaming read failed for {} (block {}): {}",
                        path,
                        block_idx,
                        err
                    );
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
                None => {
                    // Fallback to full hydration if the active backend cannot serve block ranges.
                    let node = self
                        .db
                        .get_node(path)
                        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
                    let local_cache = self
                        .hydrate(path, &node)
                        .map_err(std::io::Error::from_raw_os_error)?;
                    let file = OpenOptions::new().read(true).open(&local_cache)?;
                    let resume_offset = offset + out.len() as u64;
                    let resume_size = remaining.saturating_sub(out.len());
                    let mut tail = vec![0u8; resume_size];
                    let n = file.read_at(&mut tail, resume_offset)?;
                    tail.truncate(n);
                    out.extend_from_slice(&tail);
                    if let Some(handle) = self.activity.open_handles.lock().unwrap().get_mut(&fh) {
                        handle.file = Some(file);
                    }
                    return Ok(out);
                }
            }
        }

        Ok(out)
    }

    pub fn write_to_handle(
        &self,
        fh: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, std::io::Error> {
        let (file_clone, local_cache, cache_id, path) = {
            let handles = self.activity.open_handles.lock().unwrap();
            let handle = handles
                .get(&fh)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EBADF))?;

            if !handle.writable {
                return Err(std::io::Error::from_raw_os_error(libc::EBADF));
            }

            let file_ref = handle
                .file
                .as_ref()
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EBADF))?;

            let node = self
                .db
                .get_node_by_cache_id(&handle.cache_id)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "Node not found")
                })?;

            (
                file_ref.try_clone()?,
                handle.local_cache.clone(),
                handle.cache_id.clone(),
                node.path,
            )
        };

        // 1. Persist dirty intent with mark_pending before content mutation
        self.db
            .mark_pending(&path, &local_cache.to_string_lossy(), None)
            .map_err(|e| std::io::Error::other(format!("mark_pending failed: {}", e)))?;

        // 2. Perform positional write_all_at
        file_clone.write_all_at(data, offset)?;

        // 3. On write success, update new size in DB and mark handle dirty
        let new_size = file_clone.metadata().map(|m| m.len() as i64).unwrap_or(0);
        let _ = self.db.update_local_size(&cache_id, new_size);

        {
            let mut handles = self.activity.open_handles.lock().unwrap();
            if let Some(handle) = handles.get_mut(&fh) {
                handle.wrote = true;
                handle.path = path;
            }
        }

        Ok(data.len())
    }

    pub fn flush_handle(&self, fh: u64) -> Result<(), std::io::Error> {
        let file_clone = {
            let handles = self.activity.open_handles.lock().unwrap();
            let handle = handles
                .get(&fh)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EBADF))?;
            handle.file.as_ref().map(|f| f.try_clone()).transpose()?
        };
        if let Some(file) = file_clone {
            file.sync_data()?;
        }
        let _ = self.sync_cache_directory();
        self.db
            .sync_storage()
            .map_err(|e| std::io::Error::other(format!("sync_storage failed: {}", e)))?;
        Ok(())
    }

    pub fn fsync_handle(&self, fh: u64, datasync: bool) -> Result<(), std::io::Error> {
        let file_clone = {
            let handles = self.activity.open_handles.lock().unwrap();
            let handle = handles
                .get(&fh)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EBADF))?;
            handle.file.as_ref().map(|f| f.try_clone()).transpose()?
        };
        if let Some(file) = file_clone {
            if datasync {
                file.sync_data()?;
            } else {
                file.sync_all()?;
            }
        }
        let _ = self.sync_cache_directory();
        self.db
            .sync_storage()
            .map_err(|e| std::io::Error::other(format!("sync_storage failed: {}", e)))?;
        Ok(())
    }

    pub fn release_handle(&self, fh: u64) -> Result<(), std::io::Error> {
        let handle = self.activity.open_handles.lock().unwrap().remove(&fh);
        if let Some(handle) = handle {
            if handle.wrote {
                if let Some(ref file) = handle.file {
                    file.sync_all()?;
                }
                let _ = self.sync_cache_directory();
                self.db
                    .sync_storage()
                    .map_err(|e| std::io::Error::other(format!("sync_storage failed: {}", e)))?;
            }
        }
        Ok(())
    }
}

impl Filesystem for ProtonDriveFUSE {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_path = match self.get_path_for_inode(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        let name_str = match name.to_str() {
            Some(s) => s,
            None => return reply.error(libc::ENOENT),
        };

        let child_path = if parent_path == "/" {
            format!("/{}", name_str)
        } else {
            format!("{}/{}", parent_path.trim_end_matches('/'), name_str)
        };

        let mut node = self.db.get_node(&child_path);
        if node.is_none() {
            self.refresh_dir_for_fuse(&parent_path, 5.0);
            node = self.db.get_node(&child_path);
        }

        match node {
            Some(n) => {
                let ino = self.get_or_create_inode(&child_path);
                let attr = self.node_to_attr(ino, &n);
                reply.entry(&TTL, &attr, 0);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let path = match self.get_path_for_inode(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        if path == "/" {
            let now = SystemTime::now();
            let attr = FileAttr {
                ino: FUSE_ROOT_ID,
                size: 4096,
                blocks: 8,
                atime: now,
                mtime: now,
                ctime: now,
                crtime: now,
                kind: FileType::Directory,
                perm: 0o700,
                nlink: 2,
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
                rdev: 0,
                blksize: 4096,
                flags: 0,
            };
            return reply.attr(&TTL, &attr);
        }

        let mut node = self.db.get_node(&path);
        if node.is_none() {
            if let Some(parent) = Path::new(&path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
            {
                self.refresh_dir_for_fuse(&parent, 5.0);
                node = self.db.get_node(&path);
            }
        }

        match node {
            Some(n) => {
                let attr = self.node_to_attr(ino, &n);
                reply.attr(&TTL, &attr);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let path = match self.get_path_for_inode(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        let node = match self.db.get_node(&path) {
            Some(n) => n,
            None => return reply.error(libc::ENOENT),
        };

        if let Some(new_size) = size {
            let local_cache = match self.hydrate(&path, &node) {
                Ok(p) => p,
                Err(e) => return reply.error(e),
            };

            if let Ok(file) = OpenOptions::new().write(true).open(&local_cache) {
                if file.set_len(new_size).is_err() {
                    return reply.error(libc::EIO);
                }
            }
            let _ =
                self.db
                    .mark_pending(&path, &local_cache.to_string_lossy(), Some(new_size as i64));
        }

        let updated = self.db.get_node(&path).unwrap_or(node);
        let attr = self.node_to_attr(ino, &updated);
        reply.attr(&TTL, &attr);
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = match self.get_path_for_inode(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        self.refresh_dir_for_fuse(&path, 30.0);

        let children = self.db.get_children(&path);
        let mut entries = vec![
            (ino, FileType::Directory, ".".to_string()),
            (FUSE_ROOT_ID, FileType::Directory, "..".to_string()),
        ];

        for child in children {
            let child_ino = self.get_or_create_inode(&child.path);
            let kind = if child.node_type == "folder" || child.node_type == "album" {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            entries.push((child_ino, kind, child.name));
        }

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = match self.get_path_for_inode(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        let writable = (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0;
        match self.open_file_handle(&path, writable) {
            Ok(fh) => reply.opened(fh, 0),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.get_path_for_inode(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        let name_str = match name.to_str() {
            Some(s) => s,
            None => return reply.error(libc::EINVAL),
        };

        match self.create_file_handle(&parent_path, name_str) {
            Ok(fh) => {
                let child_path = if parent_path == "/" {
                    format!("/{}", name_str)
                } else {
                    format!("{}/{}", parent_path.trim_end_matches('/'), name_str)
                };
                let ino = self.get_or_create_inode(&child_path);
                let node = self.db.get_node(&child_path).unwrap();
                let attr = self.node_to_attr(ino, &node);
                reply.created(&TTL, &attr, 0, fh, 0);
            }
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if offset < 0 {
            return reply.error(libc::EINVAL);
        }
        match self.read_from_handle(fh, offset as u64, size as usize) {
            Ok(buf) => reply.data(&buf),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if offset < 0 {
            return reply.error(libc::EINVAL);
        }
        match self.write_to_handle(fh, offset as u64, data) {
            Ok(written) => reply.written(written as u32),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn flush(&mut self, _req: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        match self.flush_handle(fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.release_handle(fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn fsync(&mut self, _req: &Request, _ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        match self.fsync_handle(fh, datasync) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_path = match self.get_path_for_inode(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        let name_str = match name.to_str() {
            Some(s) => s,
            None => return reply.error(libc::EINVAL),
        };

        match self.create_dir(&parent_path, name_str) {
            Ok(node) => {
                let ino = self.get_or_create_inode(&node.path);
                let attr = self.node_to_attr(ino, &node);
                reply.entry(&TTL, &attr, 0);
            }
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.get_path_for_inode(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        let name_str = match name.to_str() {
            Some(s) => s,
            None => return reply.error(libc::EINVAL),
        };

        match self.remove_dir(&parent_path, name_str) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.get_path_for_inode(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        let name_str = match name.to_str() {
            Some(s) => s,
            None => return reply.error(libc::EINVAL),
        };

        match self.unlink_file(&parent_path, name_str) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let old_parent = match self.get_path_for_inode(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let new_parent = match self.get_path_for_inode(newparent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };

        let old_name = match name.to_str() {
            Some(s) => s,
            None => return reply.error(libc::EINVAL),
        };
        let new_name = match newname.to_str() {
            Some(s) => s,
            None => return reply.error(libc::EINVAL),
        };

        match self.rename_node(&old_parent, old_name, &new_parent, new_name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        let (blocks, bfree, bavail, files, ffree, bsize, namelen, frsize) =
            self.compute_statfs_nonblocking();
        reply.statfs(blocks, bfree, bavail, files, ffree, bsize, namelen, frsize);
    }
}
