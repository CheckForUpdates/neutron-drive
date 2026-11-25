use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use crate::client::RemoteDrive;
pub use crate::fuse_fs::ActivityRegistry;
use crate::metadata_db::MetadataDB;
use log::info;

pub struct AppSyncStatus;

impl AppSyncStatus {
    pub const IDLE: &'static str = "idle";
    pub const SYNCING: &'static str = "syncing";
    pub const PAUSED: &'static str = "paused";
    pub const OFFLINE: &'static str = "offline";
    pub const ERROR: &'static str = "error";
}

pub type StatusCallback = Box<dyn Fn(&str) + Send + Sync>;
pub type StatusListeners = Arc<Mutex<Vec<StatusCallback>>>;

pub struct SyncEngine {
    client: Arc<dyn RemoteDrive>,
    db: MetadataDB,
    cache_dir: PathBuf,
    poll_interval_ms: Arc<AtomicU64>,
    activity: Arc<ActivityRegistry>,
    paused: Arc<AtomicBool>,
    offline_mode: Arc<AtomicBool>,
    cache_max_size_mb: Arc<AtomicU64>,
    cache_ttl_hours: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    cycle_active: Arc<(Mutex<bool>, Condvar)>,
    status: Arc<Mutex<String>>,
    status_listeners: StatusListeners,
    tracked_paths: Arc<Mutex<HashSet<String>>>,
}

impl SyncEngine {
    pub fn new(
        client: Arc<dyn RemoteDrive>,
        db: MetadataDB,
        cache_dir: PathBuf,
        poll_interval_sec: u64,
        activity: Arc<ActivityRegistry>,
    ) -> Self {
        let mut tracked = HashSet::new();
        tracked.insert("/".to_string());
        Self {
            client,
            db,
            cache_dir,
            poll_interval_ms: Arc::new(AtomicU64::new(poll_interval_sec.max(5) * 1000)),
            activity,
            paused: Arc::new(AtomicBool::new(false)),
            offline_mode: Arc::new(AtomicBool::new(false)),
            cache_max_size_mb: Arc::new(AtomicU64::new(0)),
            cache_ttl_hours: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            cycle_active: Arc::new((Mutex::new(false), Condvar::new())),
            status: Arc::new(Mutex::new(AppSyncStatus::IDLE.to_string())),
            status_listeners: Arc::new(Mutex::new(Vec::new())),
            tracked_paths: Arc::new(Mutex::new(tracked)),
        }
    }

    pub fn new_standalone(
        client: Arc<dyn RemoteDrive>,
        db: MetadataDB,
        cache_dir: PathBuf,
        poll_interval_sec: u64,
    ) -> Self {
        Self::new(
            client,
            db,
            cache_dir,
            poll_interval_sec,
            Arc::new(ActivityRegistry::new()),
        )
    }

    pub fn activity(&self) -> &Arc<ActivityRegistry> {
        &self.activity
    }

    pub fn track_path(&self, path: &str) {
        self.activity.track_dir(path);
        let mut t = self.tracked_paths.lock().unwrap();
        t.insert(path.to_string());
    }

    pub fn untrack_path(&self, path: &str) {
        self.activity.untrack_dir(path);
        let mut t = self.tracked_paths.lock().unwrap();
        if path != "/" {
            t.remove(path);
        }
    }

    pub fn set_poll_interval_sec(&self, sec: u64) {
        self.poll_interval_ms
            .store(sec.max(5) * 1000, Ordering::SeqCst);
    }

    pub fn poll_interval_sec(&self) -> u64 {
        self.poll_interval_ms.load(Ordering::SeqCst) / 1000
    }

    pub fn set_offline_mode(&self, offline: bool) {
        self.offline_mode.store(offline, Ordering::SeqCst);
        if !self.is_paused() {
            if offline {
                self.notify_status(AppSyncStatus::OFFLINE);
            } else if self.status() == AppSyncStatus::OFFLINE {
                self.notify_status(AppSyncStatus::IDLE);
            }
        }
    }

    pub fn is_offline_mode(&self) -> bool {
        self.offline_mode.load(Ordering::SeqCst)
    }

    pub fn set_cache_policy(&self, max_size_mb: u64, ttl_hours: u64) {
        self.cache_max_size_mb.store(max_size_mb, Ordering::SeqCst);
        self.cache_ttl_hours.store(ttl_hours, Ordering::SeqCst);
    }

    pub fn enforce_cache_policy(&self) -> (usize, usize) {
        let max_bytes = self
            .cache_max_size_mb
            .load(Ordering::SeqCst)
            .saturating_mul(1024 * 1024);
        let ttl_hours = self.cache_ttl_hours.load(Ordering::SeqCst);
        let ttl = if ttl_hours > 0 {
            Some(Duration::from_secs(ttl_hours.saturating_mul(3600)))
        } else {
            None
        };
        crate::fuse_fs::evict_cache_by_policy(
            &self.db,
            &self.cache_dir,
            &self.activity,
            max_bytes,
            ttl,
        )
    }

    pub fn poll_remote_changes(&self) {
        Self::do_poll_remote_changes(
            &*self.client,
            &self.db,
            &self.cache_dir,
            &self.activity,
            &self.tracked_paths,
            &self.offline_mode,
            &self.paused,
            &self.status,
            &self.status_listeners,
        );
    }

    pub fn process_uploads(&self) {
        let max_mb = self.cache_max_size_mb.load(Ordering::SeqCst);
        let ttl_hours = self.cache_ttl_hours.load(Ordering::SeqCst);
        Self::do_process_uploads(
            &*self.client,
            &self.db,
            &self.cache_dir,
            &self.activity,
            &self.offline_mode,
            &self.paused,
            max_mb,
            ttl_hours,
            &self.status,
            &self.status_listeners,
        );
    }

    pub fn sync_once(&self) {
        self.poll_remote_changes();
        self.process_uploads();
    }

    pub fn status(&self) -> String {
        self.status.lock().unwrap().clone()
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    pub fn add_status_listener<F>(&self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.status_listeners
            .lock()
            .unwrap()
            .push(Box::new(callback));
    }

    fn notify_status(&self, new_status: &str) {
        let mut cur = self.status.lock().unwrap();
        if *cur != new_status {
            *cur = new_status.to_string();
            let listeners = self.status_listeners.lock().unwrap();
            for cb in listeners.iter() {
                cb(new_status);
            }
        }
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        self.notify_status(AppSyncStatus::PAUSED);
    }

    /// Wait until any currently executing background sync cycle completes.
    pub fn wait_until_idle(&self, timeout: Duration) -> bool {
        let (lock, cvar) = &*self.cycle_active;
        let deadline = std::time::Instant::now() + timeout;
        let mut active = lock.lock().unwrap();
        while *active {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let (guard, wait_res) = cvar.wait_timeout(active, deadline - now).unwrap();
            active = guard;
            if wait_res.timed_out() && *active {
                return false;
            }
        }
        true
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        if self.is_offline_mode() {
            self.notify_status(AppSyncStatus::OFFLINE);
        } else {
            self.notify_status(AppSyncStatus::IDLE);
        }
    }

    /// Transition out of the transient `error` status once errors are retried or cleared.
    pub fn clear_error_status(&self) {
        if self.status() == AppSyncStatus::ERROR {
            if self.is_paused() {
                self.notify_status(AppSyncStatus::PAUSED);
            } else if self.is_offline_mode() {
                self.notify_status(AppSyncStatus::OFFLINE);
            } else {
                self.notify_status(AppSyncStatus::IDLE);
            }
        }
    }

    pub fn toggle_pause(&self) -> bool {
        if self.is_paused() {
            self.resume();
            false
        } else {
            self.pause();
            true
        }
    }

    pub fn start(&self) {
        if self.running.load(Ordering::SeqCst) {
            return;
        }

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let cycle_active = Arc::clone(&self.cycle_active);
        let paused = Arc::clone(&self.paused);
        let offline_mode = Arc::clone(&self.offline_mode);
        let cache_max_size_mb = Arc::clone(&self.cache_max_size_mb);
        let cache_ttl_hours = Arc::clone(&self.cache_ttl_hours);
        let client = Arc::clone(&self.client);
        let db = self.db.clone();
        let cache_dir = self.cache_dir.clone();
        let poll_interval_ms = Arc::clone(&self.poll_interval_ms);
        let activity = Arc::clone(&self.activity);
        let status = Arc::clone(&self.status);
        let listeners = Arc::clone(&self.status_listeners);
        let tracked_paths = Arc::clone(&self.tracked_paths);

        thread::Builder::new()
            .name("sync-engine".to_string())
            .spawn(move || {
                info!("Sync engine started");
                while running.load(Ordering::SeqCst) {
                    {
                        let (lock, _) = &*cycle_active;
                        let mut active = lock.lock().unwrap();
                        *active = true;
                    }
                    struct CycleGuard(Arc<(Mutex<bool>, Condvar)>);
                    impl Drop for CycleGuard {
                        fn drop(&mut self) {
                            let (lock, cvar) = &*self.0;
                            let mut active = lock.lock().unwrap();
                            *active = false;
                            cvar.notify_all();
                        }
                    }
                    let _cycle_guard = CycleGuard(Arc::clone(&cycle_active));

                    if !paused.load(Ordering::SeqCst) {
                        Self::do_poll_remote_changes(
                            &*client,
                            &db,
                            &cache_dir,
                            &activity,
                            &tracked_paths,
                            &offline_mode,
                            &paused,
                            &status,
                            &listeners,
                        );
                        if !paused.load(Ordering::SeqCst) && running.load(Ordering::SeqCst) {
                            Self::do_process_uploads(
                                &*client,
                                &db,
                                &cache_dir,
                                &activity,
                                &offline_mode,
                                &paused,
                                cache_max_size_mb.load(Ordering::SeqCst),
                                cache_ttl_hours.load(Ordering::SeqCst),
                                &status,
                                &listeners,
                            );
                        }
                    }
                    drop(_cycle_guard);
                    let interval_ms = poll_interval_ms.load(Ordering::SeqCst);
                    let steps = (interval_ms / 100).max(1);
                    for _ in 0..steps {
                        if !running.load(Ordering::SeqCst) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            })
            .expect("Failed to spawn sync engine thread");
    }

    fn set_status_if_unpaused(
        paused: &AtomicBool,
        status: &Arc<Mutex<String>>,
        listeners: &StatusListeners,
        new_status: &str,
    ) {
        let mut cur = status.lock().unwrap();
        if paused.load(Ordering::SeqCst) {
            return;
        }
        if *cur != new_status {
            *cur = new_status.to_string();
            let l = listeners.lock().unwrap();
            for cb in l.iter() {
                cb(new_status);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn do_process_uploads(
        client: &dyn RemoteDrive,
        db: &MetadataDB,
        cache_dir: &Path,
        activity: &ActivityRegistry,
        offline_mode: &AtomicBool,
        paused: &AtomicBool,
        cache_max_size_mb: u64,
        cache_ttl_hours: u64,
        status: &Arc<Mutex<String>>,
        listeners: &StatusListeners,
    ) {
        if paused.load(Ordering::SeqCst) {
            return;
        }

        if offline_mode.load(Ordering::SeqCst) {
            Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::OFFLINE);
            return;
        }

        let pending = db.get_pending_nodes();
        if pending.is_empty() {
            if *status.lock().unwrap() == AppSyncStatus::SYNCING {
                Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::IDLE);
            }
            if cache_max_size_mb > 0 || cache_ttl_hours > 0 {
                let max_bytes = cache_max_size_mb.saturating_mul(1024 * 1024);
                let ttl = if cache_ttl_hours > 0 {
                    Some(Duration::from_secs(cache_ttl_hours.saturating_mul(3600)))
                } else {
                    None
                };
                let _ =
                    crate::fuse_fs::evict_cache_by_policy(db, cache_dir, activity, max_bytes, ttl);
            }
            return;
        }

        let (auth_ok, _) = client.check_auth_status();
        if !auth_ok {
            Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::OFFLINE);
            return;
        }

        for queued in pending {
            if paused.load(Ordering::SeqCst) {
                return;
            }

            let cache_id = queued.cache_id;
            let generation = queued.generation;

            if activity.has_writable_handle(&cache_id) || activity.is_inflight(&cache_id) {
                continue;
            }

            let node = match db.get_node_by_cache_id(&cache_id) {
                Some(n) if n.generation == generation => n,
                _ => continue,
            };

            if activity.has_writable_handle(&cache_id) || activity.is_inflight(&cache_id) {
                continue;
            }

            let local_path_str = match node.local_cache_path {
                Some(p) => p,
                None => {
                    db.mark_upload_error(&cache_id, generation, "Local cache path missing");
                    Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::ERROR);
                    continue;
                }
            };

            let local_file = PathBuf::from(&local_path_str);
            if !local_file.exists() {
                db.mark_upload_error(&cache_id, generation, "Local file not found");
                Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::ERROR);
                continue;
            }

            if !db.mark_uploading(&cache_id, generation) {
                continue;
            }

            activity.mark_inflight(&cache_id);
            struct InflightGuard<'a> {
                activity: &'a ActivityRegistry,
                cache_id: &'a str,
            }
            impl<'a> Drop for InflightGuard<'a> {
                fn drop(&mut self) {
                    self.activity.remove_inflight(self.cache_id);
                }
            }
            let _inflight_guard = InflightGuard {
                activity,
                cache_id: &cache_id,
            };

            Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::SYNCING);

            // Snapshot to staging directory
            let staging_dir = match tempfile::Builder::new()
                .prefix("upload-")
                .tempdir_in(cache_dir)
            {
                Ok(d) => d,
                Err(e) => {
                    db.mark_upload_error(&cache_id, generation, &format!("Staging error: {}", e));
                    Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::ERROR);
                    continue;
                }
            };

            let snapshot = staging_dir.path().join(&node.name);
            if let Err(e) = fs::copy(&local_file, &snapshot) {
                db.mark_upload_error(&cache_id, generation, &format!("Copy error: {}", e));
                Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::ERROR);
                continue;
            }

            #[cfg(unix)]
            let _ = fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o600));

            let remote_parent = format!("/my-files/{}", node.parent_path.trim_matches('/'));
            let clean_parent = remote_parent.trim_end_matches('/');

            let success = client.upload_file(&snapshot, clean_parent, "create-new-revision");
            if success {
                db.acknowledge_upload(&cache_id, generation);
            } else {
                db.mark_upload_error(&cache_id, generation, "Upload command failed");
                Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::ERROR);
            }
        }

        if db.get_pending_nodes().is_empty() {
            Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::IDLE);
        }

        if cache_max_size_mb > 0 || cache_ttl_hours > 0 {
            let max_bytes = cache_max_size_mb.saturating_mul(1024 * 1024);
            let ttl = if cache_ttl_hours > 0 {
                Some(Duration::from_secs(cache_ttl_hours.saturating_mul(3600)))
            } else {
                None
            };
            let _ = crate::fuse_fs::evict_cache_by_policy(db, cache_dir, activity, max_bytes, ttl);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn do_poll_remote_changes(
        client: &dyn RemoteDrive,
        db: &MetadataDB,
        cache_dir: &Path,
        activity: &ActivityRegistry,
        tracked_paths: &Arc<Mutex<HashSet<String>>>,
        offline_mode: &AtomicBool,
        paused: &AtomicBool,
        status: &Arc<Mutex<String>>,
        listeners: &StatusListeners,
    ) {
        if offline_mode.load(Ordering::SeqCst) {
            Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::OFFLINE);
            return;
        }

        let (auth_ok, _) = client.check_auth_status();
        if !auth_ok {
            Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::OFFLINE);
            return;
        }

        let was_offline = {
            let cur = status.lock().unwrap();
            *cur == AppSyncStatus::OFFLINE
        };

        if was_offline {
            let pending = db.get_pending_nodes();
            if !pending.is_empty() {
                Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::SYNCING);
            } else {
                Self::set_status_if_unpaused(paused, status, listeners, AppSyncStatus::IDLE);
            }
        }

        let mut combined: HashSet<String> = {
            let t = tracked_paths.lock().unwrap();
            t.iter().cloned().collect()
        };
        for d in activity.tracked_dirs() {
            combined.insert(d);
        }
        let mut paths: Vec<String> = combined.into_iter().collect();
        paths.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

        if let Some(event_res) = client.poll_events(db, cache_dir, activity) {
            if event_res.is_ok() {
                let refresh_epoch = db
                    .get_setting("native_refresh_epoch")
                    .unwrap_or_else(|| "0".to_string());
                let mut extra_folders: Vec<String> = Vec::new();
                for node in db.get_all_nodes() {
                    if (node.node_type == "folder" || node.node_type == "album")
                        && !paths.contains(&node.path)
                    {
                        let boot_key = format!("native_dir_bootstrapped:{}", node.path);
                        if let Some(prev_epoch) = db.get_setting(&boot_key) {
                            if prev_epoch != refresh_epoch {
                                extra_folders.push(node.path);
                            }
                        }
                    }
                }
                extra_folders.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
                paths.extend(extra_folders);

                for p in paths {
                    let exists = if p == "/" {
                        db.get_node("/").is_some()
                    } else {
                        match db.get_node(&p) {
                            None => {
                                activity.untrack_dir(&p);
                                tracked_paths.lock().unwrap().remove(&p);
                                false
                            }
                            Some(_) => true,
                        }
                    };
                    let boot_key = format!("native_dir_bootstrapped:{}", p);
                    let needs_bootstrap = exists
                        && db.get_setting(&boot_key).as_deref() != Some(refresh_epoch.as_str());
                    if needs_bootstrap
                        && crate::fuse_fs::reconcile_directory(
                            client,
                            db,
                            cache_dir,
                            activity,
                            "/my-files",
                            &p,
                        )
                        .is_ok()
                    {
                        db.set_setting(&boot_key, &refresh_epoch);
                    }
                }
                return;
            }
        }

        for p in paths {
            if p != "/" && db.get_node(&p).is_none() {
                activity.untrack_dir(&p);
                tracked_paths.lock().unwrap().remove(&p);
                continue;
            }
            let _ = crate::fuse_fs::reconcile_directory(
                client,
                db,
                cache_dir,
                activity,
                "/my-files",
                &p,
            );
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Drop for SyncEngine {
    fn drop(&mut self) {
        self.stop();
    }
}
