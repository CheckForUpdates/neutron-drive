use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fuser::{BackgroundSession, MountOption};
use log::{error, info};

use crate::client::{RemoteDrive, StorageQuota};
use crate::config::{
    block_cache_dir, config_file, db_path, load_config_from, socket_path, validate_backend, Config,
    APP_DISPLAY_NAME, APP_VERSION, BACKEND_NATIVE,
};
use crate::fuse_fs::{ActivityRegistry, ProtonDriveFUSE};
use crate::ipc::IpcServer;
use crate::metadata_db::MetadataDB;
use crate::sync_engine::SyncEngine;

static SHUTDOWN_SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN_SIGNAL_RECEIVED.store(true, Ordering::SeqCst);
}

fn normalize_pin_virtual_path(raw: &str, mount_point: &Path) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Missing or empty path".to_string());
    }
    let mount_str = mount_point.to_string_lossy();
    let mount_trimmed = mount_str.trim_end_matches('/');
    let stripped = if !mount_trimmed.is_empty()
        && (trimmed == mount_trimmed || trimmed.starts_with(&format!("{}/", mount_trimmed)))
    {
        &trimmed[mount_trimmed.len()..]
    } else {
        trimmed
    };

    let with_slash = if stripped.is_empty() || stripped == "/" {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.trim_end_matches('/').to_string()
    } else {
        format!("/{}", stripped.trim_end_matches('/'))
    };

    for seg in with_slash.split('/').filter(|s| !s.is_empty()) {
        if seg == "." || seg == ".." {
            return Err("Invalid path: traversal segments are not allowed".to_string());
        }
    }
    Ok(with_slash)
}

#[derive(Debug, Clone, Default)]
pub struct CachedStatus {
    pub authenticated: bool,
    pub auth_message: String,
    pub quota: StorageQuota,
    pub last_refreshed: Option<std::time::Instant>,
}

pub struct ProtonDriveDaemon {
    config: Arc<Mutex<Config>>,
    config_path: PathBuf,
    client: Arc<dyn RemoteDrive>,
    db: MetadataDB,
    sync_engine: Arc<SyncEngine>,
    ipc_server: Arc<IpcServer>,
    mount_session: Arc<Mutex<Option<BackgroundSession>>>,
    active_fuse: Arc<Mutex<Option<Arc<ProtonDriveFUSE>>>>,
    mount_point: Arc<Mutex<PathBuf>>,
    running: Arc<AtomicBool>,
    cache_dir: PathBuf,
    activity: Arc<ActivityRegistry>,
    cached_status: Arc<Mutex<CachedStatus>>,
    status_refresh_inflight: Arc<AtomicBool>,
}

pub fn select_remote_drive_for_config(
    config: &Config,
    db: &MetadataDB,
) -> Result<Arc<dyn RemoteDrive>, String> {
    match validate_backend(&config.backend)? {
        BACKEND_NATIVE => Ok(Arc::new(crate::native::NativeProtonClient::new(
            db.clone(),
            None,
        )?)),
        _ => unreachable!(),
    }
}

impl ProtonDriveDaemon {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        crate::config::ensure_directories()?;

        let config_file_path = config_file();
        let config = load_config_from(&config_file_path);
        let db = MetadataDB::new(&db_path())?;
        let cache_dir = block_cache_dir();
        let socket = socket_path();

        let client = select_remote_drive_for_config(&config, &db)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        Self::new_with_deps(client, db, config, cache_dir, socket, config_file_path)
    }

    pub fn with_remote_drive(
        client: Arc<dyn RemoteDrive>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        crate::config::ensure_directories()?;

        let config_file_path = config_file();
        let config = load_config_from(&config_file_path);
        let db = MetadataDB::new(&db_path())?;
        let cache_dir = block_cache_dir();
        let socket = socket_path();

        Self::new_with_deps(client, db, config, cache_dir, socket, config_file_path)
    }

    pub fn new_with_deps(
        client: Arc<dyn RemoteDrive>,
        db: MetadataDB,
        config: Config,
        cache_dir: PathBuf,
        socket_path: PathBuf,
        config_path: PathBuf,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_deps_and_activity(
            client,
            db,
            config,
            cache_dir,
            socket_path,
            config_path,
            Arc::new(ActivityRegistry::new()),
        )
    }

    pub fn new_with_deps_and_activity(
        client: Arc<dyn RemoteDrive>,
        db: MetadataDB,
        config: Config,
        cache_dir: PathBuf,
        socket_path: PathBuf,
        config_path: PathBuf,
        activity: Arc<ActivityRegistry>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let _ = fs::create_dir_all(&cache_dir);
        if !config_path.exists() {
            let _ = crate::config::save_config_to(&config, &config_path);
        }
        let mount_point = PathBuf::from(&config.mount_point);

        let sync_engine = Arc::new(SyncEngine::new(
            client.clone(),
            db.clone(),
            cache_dir.clone(),
            config.event_poll_interval_sec,
            activity.clone(),
        ));
        sync_engine.set_cache_policy(config.cache_max_size_mb, config.cache_ttl_hours);
        if config.offline_mode {
            sync_engine.set_offline_mode(true);
        }
        if config.sync_paused {
            sync_engine.pause();
        }

        let ipc_server = Arc::new(IpcServer::new(socket_path));
        let cached_status = Arc::new(Mutex::new(CachedStatus::default()));
        let status_refresh_inflight = Arc::new(AtomicBool::new(false));

        let daemon = Self {
            config: Arc::new(Mutex::new(config)),
            config_path,
            client,
            db,
            sync_engine,
            ipc_server,
            mount_session: Arc::new(Mutex::new(None)),
            active_fuse: Arc::new(Mutex::new(None)),
            mount_point: Arc::new(Mutex::new(mount_point)),
            running: Arc::new(AtomicBool::new(false)),
            cache_dir,
            activity,
            cached_status,
            status_refresh_inflight,
        };

        daemon.setup_ipc_handlers();
        Ok(daemon)
    }

    fn setup_ipc_handlers(&self) {
        let client = self.client.clone();
        let db = self.db.clone();
        let sync_engine = Arc::clone(&self.sync_engine);
        let mount_point = Arc::clone(&self.mount_point);
        let mount_session = Arc::clone(&self.mount_session);
        let active_fuse = Arc::clone(&self.active_fuse);
        let config = Arc::clone(&self.config);
        let config_path = self.config_path.clone();
        let running = Arc::clone(&self.running);
        let ipc_server = Arc::clone(&self.ipc_server);
        let cache_dir = self.cache_dir.clone();
        let activity = Arc::clone(&self.activity);

        // ping
        self.ipc_server.register_handler("ping", move |_| {
            serde_json::json!({
                "status": "ok",
                "app": APP_DISPLAY_NAME,
                "version": APP_VERSION,
            })
        });

        // status
        let sync_engine_c = Arc::clone(&sync_engine);
        let mount_point_c = Arc::clone(&mount_point);
        let mount_session_c = Arc::clone(&mount_session);
        let cached_status_c = Arc::clone(&self.cached_status);
        let client_c = client.clone();
        let db_c = db.clone();
        let inflight_c = Arc::clone(&self.status_refresh_inflight);
        self.ipc_server.register_handler("status", move |_| {
            let (auth_ok, auth_msg, quota, should_refresh) = {
                let guard = cached_status_c.lock().unwrap();
                let need = match guard.last_refreshed {
                    None => true,
                    Some(t) => t.elapsed() >= Duration::from_secs(60),
                };
                (
                    guard.authenticated,
                    guard.auth_message.clone(),
                    guard.quota.clone(),
                    need,
                )
            };

            if should_refresh {
                Self::trigger_status_refresh(&client_c, &cached_status_c, &inflight_c);
            }

            let is_mounted = mount_session_c.lock().unwrap().is_some();
            let mp = mount_point_c.lock().unwrap().to_string_lossy().to_string();
            let (pending_uploads, error_count) = db_c.get_sync_counts();
            let pinned_count = db_c.list_pinned_paths().len();
            let last_error = db_c
                .get_recent_errors(1)
                .into_iter()
                .next()
                .map(|(p, e)| format!("{}: {}", p, e));

            serde_json::json!({
                "status": "ok",
                "authenticated": auth_ok,
                "auth_message": auth_msg,
                "backend": client_c.backend_name(),
                "sync_status": sync_engine_c.status(),
                "is_paused": sync_engine_c.is_paused(),
                "offline_mode": sync_engine_c.is_offline_mode(),
                "pending_uploads": pending_uploads,
                "error_count": error_count,
                "pinned_count": pinned_count,
                "last_error": last_error,
                "is_mounted": is_mounted,
                "mount_point": mp,
                "quota": {
                    "used_bytes": quota.used_bytes,
                    "total_bytes": quota.total_bytes,
                    "percent_used": quota.percent_used,
                }
            })
        });

        // mount
        let client_c = client.clone();
        let db_c = db.clone();
        let mount_session_c = Arc::clone(&mount_session);
        let mount_point_c = Arc::clone(&mount_point);
        let active_fuse_c = Arc::clone(&active_fuse);
        let cache_dir_c = cache_dir.clone();
        let activity_c = Arc::clone(&activity);
        let cached_status_mount_c = Arc::clone(&self.cached_status);
        self.ipc_server.register_handler("mount", move |args| {
            let mut session_guard = mount_session_c.lock().unwrap();
            if session_guard.is_some() {
                return serde_json::json!({
                    "status": "ok",
                    "message": "Already mounted",
                    "mount_point": mount_point_c.lock().unwrap().to_string_lossy().to_string()
                });
            }

            let mp = if let Some(p) = args.get("mount_point").and_then(|v| v.as_str()) {
                PathBuf::from(p)
            } else {
                mount_point_c.lock().unwrap().clone()
            };

            Self::cleanup_stale_mount(&mp);
            let _ = fs::create_dir_all(&mp);

            let fuse_fs = ProtonDriveFUSE::new(
                client_c.clone(),
                db_c.clone(),
                cache_dir_c.clone(),
                Some("/my-files"),
                activity_c.clone(),
            );
            if let Ok(guard) = cached_status_mount_c.lock() {
                if guard.quota.total_bytes > 0 || guard.quota.used_bytes > 0 {
                    fuse_fs.update_cached_quota(guard.quota.clone());
                }
            }

            let options = vec![
                MountOption::FSName("neutron-drive".to_string()),
                MountOption::AutoUnmount,
            ];

            let fuse_arc = Arc::new(fuse_fs.clone());
            match fuser::spawn_mount2(fuse_fs, &mp, &options) {
                Ok(session) => {
                    *session_guard = Some(session);
                    *active_fuse_c.lock().unwrap() = Some(fuse_arc);
                    *mount_point_c.lock().unwrap() = mp.clone();
                    serde_json::json!({
                        "status": "ok",
                        "mount_point": mp.to_string_lossy().to_string()
                    })
                }
                Err(e) => {
                    error!("Mount failed: {}", e);
                    serde_json::json!({
                        "status": "error",
                        "message": format!("Mount failed: {}", e)
                    })
                }
            }
        });

        // unmount
        let mount_session_c = Arc::clone(&mount_session);
        let active_fuse_c = Arc::clone(&active_fuse);
        self.ipc_server.register_handler("unmount", move |_| {
            let mut session_guard = mount_session_c.lock().unwrap();
            *active_fuse_c.lock().unwrap() = None;
            if let Some(session) = session_guard.take() {
                drop(session); // Dropping session unmounts the filesystem
                serde_json::json!({"status": "ok", "message": "Unmounted successfully"})
            } else {
                serde_json::json!({"status": "ok", "message": "Not mounted"})
            }
        });

        // pause
        let sync_engine_c = Arc::clone(&sync_engine);
        self.ipc_server.register_handler("pause", move |_| {
            sync_engine_c.pause();
            serde_json::json!({"status": "ok"})
        });

        // resume
        let sync_engine_c = Arc::clone(&sync_engine);
        self.ipc_server.register_handler("resume", move |_| {
            sync_engine_c.resume();
            serde_json::json!({"status": "ok"})
        });

        // refresh
        let client_c = client.clone();
        let sync_engine_c = Arc::clone(&sync_engine);
        let active_fuse_c = Arc::clone(&active_fuse);
        let db_c = db.clone();
        let cache_dir_c = cache_dir.clone();
        let activity_c = Arc::clone(&activity);
        let cached_status_c = Arc::clone(&self.cached_status);
        self.ipc_server.register_handler("refresh", move |_| {
            let (auth_ok, auth_msg) = client_c.check_auth_status();
            if !auth_ok {
                if let Ok(mut guard) = cached_status_c.lock() {
                    guard.authenticated = false;
                    guard.auth_message = auth_msg;
                    guard.last_refreshed = Some(std::time::Instant::now());
                }
                return serde_json::json!({
                    "status": "error",
                    "message": "Not authenticated"
                });
            }

            let quota = client_c.get_storage_quota();
            if let Ok(mut guard) = cached_status_c.lock() {
                guard.authenticated = true;
                guard.auth_message = "Authenticated".to_string();
                guard.quota = quota.clone();
                guard.last_refreshed = Some(std::time::Instant::now());
            }

            let tracked = activity_c.tracked_dirs();
            let active = active_fuse_c.lock().unwrap().clone();
            if let Some(fuse_fs) = active {
                fuse_fs.update_cached_quota(quota);
                for dir in tracked {
                    if dir != "/" && db_c.get_node(&dir).is_none() {
                        activity_c.untrack_dir(&dir);
                        continue;
                    }
                    fuse_fs.refresh_dir_if_needed(&dir, 0.0);
                }
            } else {
                for dir in tracked {
                    if dir != "/" && db_c.get_node(&dir).is_none() {
                        activity_c.untrack_dir(&dir);
                        continue;
                    }
                    let _ = crate::fuse_fs::reconcile_directory(
                        &*client_c,
                        &db_c,
                        &cache_dir_c,
                        &activity_c,
                        "/my-files",
                        &dir,
                    );
                }
            }

            sync_engine_c.sync_once();

            serde_json::json!({
                "status": "ok",
                "message": "Refreshed"
            })
        });

        // clear-cache
        let active_fuse_c = Arc::clone(&active_fuse);
        self.ipc_server.register_handler("clear-cache", move |_| {
            let active = active_fuse_c.lock().unwrap().clone();
            match active {
                Some(fuse_fs) => {
                    let (evicted, skipped) = fuse_fs.evict_clean_cache();
                    serde_json::json!({
                        "status": "ok",
                        "evicted": evicted,
                        "skipped": skipped
                    })
                }
                None => {
                    serde_json::json!({
                        "status": "error",
                        "message": "Cannot clear cache: Drive is not mounted"
                    })
                }
            }
        });

        // retry-errors
        let db_c = db.clone();
        let sync_engine_c = Arc::clone(&sync_engine);
        self.ipc_server
            .register_handler("retry-errors", move |_| match db_c.retry_errors() {
                Ok(retried) => {
                    sync_engine_c.clear_error_status();
                    if retried > 0 && !sync_engine_c.is_paused() && !sync_engine_c.is_offline_mode()
                    {
                        let engine = Arc::clone(&sync_engine_c);
                        thread::spawn(move || {
                            engine.process_uploads();
                        });
                    }
                    serde_json::json!({
                        "status": "ok",
                        "retried": retried,
                        "message": format!("Re-queued {} failed item(s) for upload", retried),
                    })
                }
                Err(e) => serde_json::json!({
                    "status": "error",
                    "message": e,
                }),
            });

        // clear-errors
        let db_c = db.clone();
        let sync_engine_c = Arc::clone(&sync_engine);
        self.ipc_server
            .register_handler("clear-errors", move |_| match db_c.clear_errors() {
                Ok((cleared, requeued)) => {
                    sync_engine_c.clear_error_status();
                    serde_json::json!({
                        "status": "ok",
                        "cleared": cleared,
                        "requeued": requeued,
                        "message": format!(
                            "Cleared {} stale error(s); {} item(s) with local changes re-queued",
                            cleared, requeued
                        ),
                    })
                }
                Err(e) => serde_json::json!({
                    "status": "error",
                    "message": e,
                }),
            });

        // pin
        let db_c = db.clone();
        let mount_point_c = Arc::clone(&mount_point);
        let active_fuse_c = Arc::clone(&active_fuse);
        self.ipc_server.register_handler("pin", move |args| {
            let Some(raw_path) = args.get("path").and_then(|v| v.as_str()) else {
                return serde_json::json!({
                    "status": "error",
                    "message": "Missing 'path' argument",
                });
            };
            let mp = mount_point_c.lock().unwrap().clone();
            let vpath = match normalize_pin_virtual_path(raw_path, &mp) {
                Ok(p) => p,
                Err(e) => {
                    return serde_json::json!({
                        "status": "error",
                        "message": e,
                    });
                }
            };
            match db_c.set_pinned(&vpath, true) {
                Ok(true) => {
                    let (hydrated, failed) = match active_fuse_c.lock().unwrap().clone() {
                        Some(fuse_fs) => fuse_fs.hydrate_pinned_target(&vpath),
                        None => (0, 0),
                    };
                    serde_json::json!({
                        "status": "ok",
                        "path": vpath,
                        "pinned": true,
                        "hydrated": hydrated,
                        "failed": failed,
                        "message": format!(
                            "Pinned '{}' for offline access (hydrated: {}, failed: {})",
                            vpath, hydrated, failed
                        ),
                    })
                }
                Ok(false) => serde_json::json!({
                    "status": "error",
                    "message": format!("Path not found in metadata index: {}", vpath),
                }),
                Err(e) => serde_json::json!({
                    "status": "error",
                    "message": e,
                }),
            }
        });

        // unpin
        let db_c = db.clone();
        let mount_point_c = Arc::clone(&mount_point);
        self.ipc_server.register_handler("unpin", move |args| {
            let Some(raw_path) = args.get("path").and_then(|v| v.as_str()) else {
                return serde_json::json!({
                    "status": "error",
                    "message": "Missing 'path' argument",
                });
            };
            let mp = mount_point_c.lock().unwrap().clone();
            let vpath = match normalize_pin_virtual_path(raw_path, &mp) {
                Ok(p) => p,
                Err(e) => {
                    return serde_json::json!({
                        "status": "error",
                        "message": e,
                    });
                }
            };
            match db_c.set_pinned(&vpath, false) {
                Ok(true) => serde_json::json!({
                    "status": "ok",
                    "path": vpath,
                    "pinned": false,
                    "message": format!("Unpinned '{}'; cached blocks can now be evicted", vpath),
                }),
                Ok(false) => serde_json::json!({
                    "status": "error",
                    "message": format!("Path not found in metadata index: {}", vpath),
                }),
                Err(e) => serde_json::json!({
                    "status": "error",
                    "message": e,
                }),
            }
        });

        // pinned
        let db_c = db.clone();
        self.ipc_server.register_handler("pinned", move |_| {
            let paths = db_c.list_pinned_paths();
            serde_json::json!({
                "status": "ok",
                "count": paths.len(),
                "paths": paths,
            })
        });

        // list-errors
        let db_c = db.clone();
        self.ipc_server.register_handler("list-errors", move |_| {
            let errors = db_c.get_recent_errors(50);
            let items: Vec<serde_json::Value> = errors
                .into_iter()
                .map(|(path, error)| {
                    serde_json::json!({
                        "path": path,
                        "error": error,
                    })
                })
                .collect();
            serde_json::json!({
                "status": "ok",
                "count": items.len(),
                "items": items,
            })
        });

        // resolve-conflict
        let db_c = db.clone();
        let cache_dir_c = cache_dir.clone();
        let mount_point_c = Arc::clone(&mount_point);
        let sync_engine_c = Arc::clone(&sync_engine);
        self.ipc_server
            .register_handler("resolve-conflict", move |args| {
                let Some(raw_path) = args.get("path").and_then(|v| v.as_str()) else {
                    return serde_json::json!({
                        "status": "error",
                        "message": "Missing 'path' argument",
                    });
                };
                let strategy = args
                    .get("strategy")
                    .and_then(|v| v.as_str())
                    .unwrap_or("keep-local");
                let mp = mount_point_c.lock().unwrap().clone();
                let vpath = match normalize_pin_virtual_path(raw_path, &mp) {
                    Ok(p) => p,
                    Err(e) => {
                        return serde_json::json!({
                            "status": "error",
                            "message": e,
                        });
                    }
                };
                match db_c.resolve_error_node(&vpath, strategy, &cache_dir_c) {
                    Ok(msg) => {
                        sync_engine_c.clear_error_status();
                        if (strategy == "keep-local" || strategy == "keep-both")
                            && !sync_engine_c.is_paused()
                            && !sync_engine_c.is_offline_mode()
                        {
                            let engine = Arc::clone(&sync_engine_c);
                            thread::spawn(move || {
                                engine.process_uploads();
                            });
                        }
                        serde_json::json!({
                            "status": "ok",
                            "path": vpath,
                            "strategy": strategy,
                            "message": msg,
                        })
                    }
                    Err(e) => serde_json::json!({
                        "status": "error",
                        "message": e,
                    }),
                }
            });

        // restore-trash
        let client_c = client.clone();
        self.ipc_server
            .register_handler("restore-trash", move |args| {
                let Some(link_id) = args
                    .get("link_id")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                else {
                    return serde_json::json!({
                        "status": "error",
                        "message": "Missing or empty 'link_id' argument",
                    });
                };
                if client_c.restore_from_trash(link_id) {
                    serde_json::json!({
                        "status": "ok",
                        "link_id": link_id,
                        "message": format!("Restored link '{}' from Proton Drive Trash", link_id),
                    })
                } else {
                    serde_json::json!({
                        "status": "error",
                        "message": format!("Failed to restore link '{}' from Trash", link_id),
                    })
                }
            });

        // login
        let client_c = client.clone();
        let cached_status_c = Arc::clone(&self.cached_status);
        let inflight_c = Arc::clone(&self.status_refresh_inflight);
        self.ipc_server.register_handler("login", move |args| {
            let username = args.get("username").and_then(|v| v.as_str());
            let password = args.get("password").and_then(|v| v.as_str());
            let totp = args.get("totp").and_then(|v| v.as_str());

            let res = match (username, password) {
                (Some(u), Some(p)) => client_c.authenticate(u, p, totp),
                _ => client_c.start_login(),
            };

            match res {
                Ok(msg) => {
                    Self::trigger_status_refresh(&client_c, &cached_status_c, &inflight_c);
                    serde_json::json!({
                        "status": "ok",
                        "message": msg
                    })
                }
                Err(err) if err.starts_with("2FA_REQUIRED") => {
                    let detail = err
                        .strip_prefix("2FA_REQUIRED:")
                        .unwrap_or("Two-factor TOTP code required")
                        .trim();
                    serde_json::json!({
                        "status": "2fa_required",
                        "message": detail
                    })
                }
                Err(err) => serde_json::json!({
                    "status": "error",
                    "message": err
                }),
            }
        });

        // start-browser-login
        let client_c = client.clone();
        self.ipc_server
            .register_handler("start-browser-login", move |_| {
                match client_c.start_browser_login() {
                    Ok((login_url, user_code)) => serde_json::json!({
                        "status": "ok",
                        "login_url": login_url,
                        "user_code": user_code
                    }),
                    Err(err) => serde_json::json!({
                        "status": "error",
                        "message": err
                    }),
                }
            });

        // poll-browser-login
        let client_c = client.clone();
        let cached_status_c = Arc::clone(&self.cached_status);
        let inflight_c = Arc::clone(&self.status_refresh_inflight);
        self.ipc_server
            .register_handler("poll-browser-login", move |_| {
                match client_c.poll_browser_login() {
                    Ok(Some(msg)) => {
                        Self::trigger_status_refresh(&client_c, &cached_status_c, &inflight_c);
                        serde_json::json!({
                            "status": "ok",
                            "message": msg
                        })
                    }
                    Ok(None) => serde_json::json!({
                        "status": "pending"
                    }),
                    Err(err) => serde_json::json!({
                        "status": "error",
                        "message": err
                    }),
                }
            });

        // logout
        let client_c = client.clone();
        let cached_status_c = Arc::clone(&self.cached_status);
        self.ipc_server.register_handler("logout", move |_| {
            let ok = client_c.logout();
            if ok {
                if let Ok(mut guard) = cached_status_c.lock() {
                    guard.authenticated = false;
                    guard.auth_message = "Not authenticated".to_string();
                    guard.quota = Default::default();
                    guard.last_refreshed = Some(std::time::Instant::now());
                }
            }
            serde_json::json!({"status": if ok { "ok" } else { "error" }})
        });

        // stop
        let mount_session_c = Arc::clone(&mount_session);
        let active_fuse_c = Arc::clone(&active_fuse);
        let sync_engine_c = Arc::clone(&sync_engine);
        let running_c = Arc::clone(&running);
        let ipc_server_c = Arc::clone(&ipc_server);
        self.ipc_server.register_handler("stop", move |_| {
            // Safely unmount if mounted
            *active_fuse_c.lock().unwrap() = None;
            if let Some(session) = mount_session_c.lock().unwrap().take() {
                drop(session);
            }

            // Stop sync engine
            sync_engine_c.stop();

            // Signal daemon shutdown
            running_c.store(false, Ordering::SeqCst);

            // Schedule daemon/IPC shutdown so response is sent first
            let ipc = Arc::clone(&ipc_server_c);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                ipc.stop();
            });

            serde_json::json!({
                "status": "ok",
                "message": "Stopping daemon"
            })
        });

        // get-config
        let config_c = Arc::clone(&config);
        self.ipc_server.register_handler("get-config", move |_| {
            let cfg = config_c.lock().unwrap().clone();
            serde_json::json!({
                "status": "ok",
                "config": cfg,
            })
        });

        // update-config
        let config_c = Arc::clone(&config);
        let config_path_c = config_path.clone();
        let mount_point_c = Arc::clone(&mount_point);
        let mount_session_c = Arc::clone(&mount_session);
        let active_fuse_c = Arc::clone(&active_fuse);
        let client_c = client;
        let db_c = db;
        let cache_dir_c = cache_dir;
        let activity_c = Arc::clone(&activity);
        let sync_engine_c = Arc::clone(&sync_engine);

        self.ipc_server.register_handler("update-config", move |args| {
            let update_map = if let Some(cfg_obj) = args.get("config").and_then(|v| v.as_object()) {
                cfg_obj
            } else if let Some(map) = args.as_object() {
                map
            } else {
                return serde_json::json!({
                    "status": "error",
                    "message": "Invalid request payload: expected a JSON object"
                });
            };

            for (key, _) in update_map {
                match key.as_str() {
                    "mount_point"
                    | "auto_mount_on_start"
                    | "cache_max_size_mb"
                    | "cache_ttl_hours"
                    | "event_poll_interval_sec"
                    | "offline_mode"
                    | "sync_paused"
                    | "start_at_login"
                    | "backend" => {}
                    _ => {
                        return serde_json::json!({
                            "status": "error",
                            "message": format!("Unknown configuration field: '{}'", key)
                        });
                    }
                }
            }

            let mut new_mount_point: Option<String> = None;
            if let Some(v) = update_map.get("mount_point") {
                match v.as_str() {
                    Some(s) if !s.trim().is_empty() => {
                        new_mount_point = Some(s.to_string());
                    }
                    Some(_) => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'mount_point' cannot be empty"
                        });
                    }
                    None => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'mount_point' must be a string"
                        });
                    }
                }
            }

            let mut new_auto_mount: Option<bool> = None;
            if let Some(v) = update_map.get("auto_mount_on_start") {
                match v.as_bool() {
                    Some(b) => new_auto_mount = Some(b),
                    None => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'auto_mount_on_start' must be a boolean"
                        });
                    }
                }
            }

            let mut new_start_at_login: Option<bool> = None;
            if let Some(v) = update_map.get("start_at_login") {
                match v.as_bool() {
                    Some(b) => new_start_at_login = Some(b),
                    None => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'start_at_login' must be a boolean"
                        });
                    }
                }
            }

            let mut new_offline_mode: Option<bool> = None;
            if let Some(v) = update_map.get("offline_mode") {
                match v.as_bool() {
                    Some(b) => new_offline_mode = Some(b),
                    None => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'offline_mode' must be a boolean"
                        });
                    }
                }
            }

            let mut new_sync_paused: Option<bool> = None;
            if let Some(v) = update_map.get("sync_paused") {
                match v.as_bool() {
                    Some(b) => new_sync_paused = Some(b),
                    None => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'sync_paused' must be a boolean"
                        });
                    }
                }
            }

            let mut new_cache_max_size_mb: Option<u64> = None;
            if let Some(v) = update_map.get("cache_max_size_mb") {
                match v.as_u64() {
                    Some(n) => new_cache_max_size_mb = Some(n),
                    None => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'cache_max_size_mb' must be an unsigned integer"
                        });
                    }
                }
            }

            let mut new_cache_ttl_hours: Option<u64> = None;
            if let Some(v) = update_map.get("cache_ttl_hours") {
                match v.as_u64() {
                    Some(n) => new_cache_ttl_hours = Some(n),
                    None => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'cache_ttl_hours' must be an unsigned integer"
                        });
                    }
                }
            }

            let mut new_event_poll_interval_sec: Option<u64> = None;
            if let Some(v) = update_map.get("event_poll_interval_sec") {
                match v.as_u64() {
                    Some(n) if n > 0 => new_event_poll_interval_sec = Some(n),
                    Some(_) => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'event_poll_interval_sec' must be greater than 0"
                        });
                    }
                    None => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'event_poll_interval_sec' must be a positive integer"
                        });
                    }
                }
            }

            let mut new_backend: Option<String> = None;
            if let Some(v) = update_map.get("backend") {
                match v.as_str() {
                    Some(s) => match validate_backend(s) {
                        Ok(valid) => {
                            new_backend = Some(valid.to_string());
                        }
                        Err(msg) => {
                            return serde_json::json!({
                                "status": "error",
                                "message": format!("Validation failed: {}", msg)
                            });
                        }
                    },
                    None => {
                        return serde_json::json!({
                            "status": "error",
                            "message": "Validation failed: 'backend' must be a string"
                        });
                    }
                }
            }

            let mut remount_performed = false;
            let mut remount_required = false;

            if let Some(ref new_mp_str) = new_mount_point {
                let new_mp = PathBuf::from(new_mp_str);
                let mut mp_guard = mount_point_c.lock().unwrap();
                if *mp_guard != new_mp {
                    let mut session_guard = mount_session_c.lock().unwrap();
                    if session_guard.is_some() {
                        *active_fuse_c.lock().unwrap() = None;
                        if let Some(session) = session_guard.take() {
                            drop(session);
                        }

                        Self::cleanup_stale_mount(&new_mp);
                        let _ = fs::create_dir_all(&new_mp);
                        let fuse_fs = ProtonDriveFUSE::new(
                            client_c.clone(),
                            db_c.clone(),
                            cache_dir_c.clone(),
                            Some("/my-files"),
                            activity_c.clone(),
                        );
                        let options = vec![
                            MountOption::FSName("neutron-drive".to_string()),
                            MountOption::AutoUnmount,
                        ];
                        let fuse_arc = Arc::new(fuse_fs.clone());
                        match fuser::spawn_mount2(fuse_fs, &new_mp, &options) {
                            Ok(session) => {
                                *session_guard = Some(session);
                                *active_fuse_c.lock().unwrap() = Some(fuse_arc);
                                *mp_guard = new_mp;
                                remount_performed = true;
                            }
                            Err(e) => {
                                error!("Remount at {:?} failed: {}", new_mp, e);
                                *mp_guard = new_mp;
                                remount_required = true;
                            }
                        }
                    } else {
                        *mp_guard = new_mp;
                    }
                }
            }

            if let Some(paused) = new_sync_paused {
                if paused {
                    sync_engine_c.pause();
                } else {
                    sync_engine_c.resume();
                }
            }

            if let Some(offline) = new_offline_mode {
                sync_engine_c.set_offline_mode(offline);
            }

            if let Some(poll_sec) = new_event_poll_interval_sec {
                sync_engine_c.set_poll_interval_sec(poll_sec);
            }

            let mut cfg_guard = config_c.lock().unwrap();
            let mut updated_config = cfg_guard.clone();
            if let Some(mp) = new_mount_point {
                updated_config.mount_point = mp;
            }
            if let Some(v) = new_auto_mount {
                updated_config.auto_mount_on_start = v;
            }
            if let Some(v) = new_start_at_login {
                updated_config.start_at_login = v;
            }
            if let Some(v) = new_offline_mode {
                updated_config.offline_mode = v;
            }
            if let Some(v) = new_sync_paused {
                updated_config.sync_paused = v;
            }
            if let Some(v) = new_cache_max_size_mb {
                updated_config.cache_max_size_mb = v;
            }
            if let Some(v) = new_cache_ttl_hours {
                updated_config.cache_ttl_hours = v;
            }
            if let Some(v) = new_event_poll_interval_sec {
                updated_config.event_poll_interval_sec = v;
            }
            let backend_changed = new_backend
                .as_ref()
                .is_some_and(|b| b != client_c.backend_name());
            if let Some(v) = new_backend {
                updated_config.backend = v;
            }

            if new_cache_max_size_mb.is_some() || new_cache_ttl_hours.is_some() {
                sync_engine_c.set_cache_policy(
                    updated_config.cache_max_size_mb,
                    updated_config.cache_ttl_hours,
                );
            }

            if let Some(enabled) = new_start_at_login {
                let _ = crate::config::sync_autostart_entry(&config_path_c, enabled);
            }

            if let Err(e) = crate::config::save_config_to(&updated_config, &config_path_c) {
                return serde_json::json!({
                    "status": "error",
                    "message": format!("Failed to persist config: {}", e)
                });
            }

            *cfg_guard = updated_config.clone();
            drop(cfg_guard);

            let mut resp = serde_json::json!({
                "status": "ok",
                "config": updated_config
            });
            if remount_performed {
                resp["remounted"] = serde_json::json!(true);
            }
            if remount_required {
                resp["remount_required"] = serde_json::json!(true);
            }
            if backend_changed {
                resp["restart_required"] = serde_json::json!(true);
            }
            resp
        });
    }

    pub fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.running.store(true, Ordering::SeqCst);
        self.ipc_server.start()?;
        self.sync_engine.start();

        // Refresh cached status in background on startup
        Self::trigger_status_refresh(
            &self.client,
            &self.cached_status,
            &self.status_refresh_inflight,
        );

        // Controlled periodic background status refresh (e.g. every 60s)
        let client_bg = Arc::clone(&self.client);
        let cached_bg = Arc::clone(&self.cached_status);
        let inflight_bg = Arc::clone(&self.status_refresh_inflight);
        let running_bg = Arc::clone(&self.running);

        thread::spawn(move || {
            while running_bg.load(Ordering::SeqCst) {
                for _ in 0..600 {
                    if !running_bg.load(Ordering::SeqCst) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                if running_bg.load(Ordering::SeqCst) {
                    Self::trigger_status_refresh(&client_bg, &cached_bg, &inflight_bg);
                }
            }
        });

        let cfg = self.config.lock().unwrap().clone();
        if cfg.auto_mount_on_start {
            let _ = self.mount(None);
        }

        Ok(())
    }

    #[cfg(unix)]
    pub fn install_signal_handlers() {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handle_shutdown_signal as *const () as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
        }
    }

    #[cfg(not(unix))]
    pub fn install_signal_handlers() {}

    fn cleanup_stale_mount(mp: &std::path::Path) {
        if let Err(err) = fs::metadata(mp) {
            if err.raw_os_error() == Some(libc::ENOTCONN) {
                info!(
                    "Detected stale FUSE mount at {:?}; attempting lazy unmount",
                    mp
                );
                for tool in ["fusermount3", "fusermount"] {
                    if let Ok(status) = std::process::Command::new(tool)
                        .args(["-u", "-z"])
                        .arg(mp)
                        .status()
                    {
                        if status.success() {
                            break;
                        }
                    }
                }
            }
        }
    }

    pub fn mount(&self, custom_mount: Option<PathBuf>) -> Result<(), String> {
        let mut session_guard = self.mount_session.lock().unwrap();
        if session_guard.is_some() {
            return Ok(());
        }

        let mp = custom_mount.unwrap_or_else(|| self.mount_point.lock().unwrap().clone());
        Self::cleanup_stale_mount(&mp);
        let _ = fs::create_dir_all(&mp);

        let fuse_fs = ProtonDriveFUSE::new(
            self.client.clone(),
            self.db.clone(),
            self.cache_dir.clone(),
            Some("/my-files"),
            self.activity.clone(),
        );

        let options = vec![
            MountOption::FSName("proton-drive".to_string()),
            MountOption::AutoUnmount,
        ];

        let fuse_arc = Arc::new(fuse_fs.clone());
        let session = fuser::spawn_mount2(fuse_fs, &mp, &options)
            .map_err(|e| format!("Failed to mount at {:?}: {}", mp, e))?;

        *session_guard = Some(session);
        *self.active_fuse.lock().unwrap() = Some(fuse_arc);
        *self.mount_point.lock().unwrap() = mp;
        Ok(())
    }

    pub fn unmount(&self) {
        let mut session_guard = self.mount_session.lock().unwrap();
        *self.active_fuse.lock().unwrap() = None;
        if let Some(session) = session_guard.take() {
            drop(session);
        }
    }

    pub fn run_forever(&self) {
        SHUTDOWN_SIGNAL_RECEIVED.store(false, Ordering::SeqCst);
        Self::install_signal_handlers();
        info!("{} daemon running...", crate::config::APP_DISPLAY_NAME);
        while self.running.load(Ordering::SeqCst) {
            if SHUTDOWN_SIGNAL_RECEIVED.swap(false, Ordering::SeqCst) {
                info!(
                    "Shutdown signal received; stopping {} daemon",
                    crate::config::APP_DISPLAY_NAME
                );
                self.running.store(false, Ordering::SeqCst);
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.stop();
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.unmount();
        self.sync_engine.stop();
        self.ipc_server.stop();
    }

    pub fn client(&self) -> &Arc<dyn RemoteDrive> {
        &self.client
    }

    pub fn db(&self) -> &MetadataDB {
        &self.db
    }

    pub fn sync_engine(&self) -> &Arc<SyncEngine> {
        &self.sync_engine
    }

    pub fn ipc_server(&self) -> &Arc<IpcServer> {
        &self.ipc_server
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn mount_point(&self) -> PathBuf {
        self.mount_point.lock().unwrap().clone()
    }

    pub fn config(&self) -> Config {
        self.config.lock().unwrap().clone()
    }

    pub fn config_path(&self) -> &std::path::Path {
        &self.config_path
    }

    pub fn activity(&self) -> &Arc<ActivityRegistry> {
        &self.activity
    }

    pub fn active_fuse(&self) -> Option<Arc<ProtonDriveFUSE>> {
        self.active_fuse.lock().unwrap().clone()
    }

    pub fn set_active_fuse(&self, fuse: Option<Arc<ProtonDriveFUSE>>) {
        *self.active_fuse.lock().unwrap() = fuse;
    }

    pub fn trigger_status_refresh(
        client: &Arc<dyn RemoteDrive>,
        cached_status: &Arc<Mutex<CachedStatus>>,
        inflight: &Arc<AtomicBool>,
    ) -> bool {
        if inflight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }

        let client = Arc::clone(client);
        let cached_status = Arc::clone(cached_status);
        let inflight = Arc::clone(inflight);

        thread::spawn(move || {
            let (auth_ok, auth_msg) = client.check_auth_status();
            let quota = if auth_ok {
                client.get_storage_quota()
            } else {
                Default::default()
            };

            if let Ok(mut guard) = cached_status.lock() {
                guard.authenticated = auth_ok;
                guard.auth_message = auth_msg;
                guard.quota = quota;
                guard.last_refreshed = Some(std::time::Instant::now());
            }

            inflight.store(false, Ordering::SeqCst);
        });

        true
    }

    pub fn cached_status(&self) -> Arc<Mutex<CachedStatus>> {
        Arc::clone(&self.cached_status)
    }

    pub fn status_refresh_inflight(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.status_refresh_inflight)
    }
}

impl Drop for ProtonDriveDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct DummyRemote {
        auth_call_count: AtomicUsize,
    }

    impl DummyRemote {
        fn new() -> Self {
            Self {
                auth_call_count: AtomicUsize::new(0),
            }
        }
    }

    impl RemoteDrive for DummyRemote {
        fn check_auth_status(&self) -> (bool, String) {
            self.auth_call_count.fetch_add(1, Ordering::SeqCst);
            (true, "Authenticated".to_string())
        }

        fn logout(&self) -> bool {
            true
        }

        fn list_path(&self, _remote_path: &str) -> Result<Vec<crate::client::RemoteNode>, String> {
            Ok(vec![])
        }

        fn download_file(
            &self,
            _remote_path: &str,
            _local_target_dir: &std::path::Path,
            _conflict_strategy: &str,
        ) -> bool {
            true
        }

        fn upload_file(
            &self,
            _local_file: &std::path::Path,
            _remote_parent_path: &str,
            _conflict_strategy: &str,
        ) -> bool {
            true
        }

        fn create_folder(&self, _remote_parent: &str, _folder_name: &str) -> bool {
            true
        }

        fn rename(&self, _remote_path: &str, _new_name: &str) -> bool {
            true
        }

        fn move_node(&self, _source_path: &str, _target_parent_path: &str) -> bool {
            true
        }

        fn trash(&self, _remote_path: &str) -> bool {
            true
        }

        fn delete(&self, _remote_path: &str) -> bool {
            true
        }

        fn get_storage_quota(&self) -> StorageQuota {
            StorageQuota {
                used_bytes: 1024,
                total_bytes: 4096,
                percent_used: 25.0,
            }
        }
    }

    #[test]
    fn test_cached_status_initial_default() {
        let cached = CachedStatus::default();
        assert!(!cached.authenticated);
        assert_eq!(cached.quota.used_bytes, 0);
        assert!(cached.last_refreshed.is_none());
    }

    #[test]
    fn test_trigger_status_refresh_updates_cache_and_bounds_inflight() {
        let remote: Arc<dyn RemoteDrive> = Arc::new(DummyRemote::new());
        let cached = Arc::new(Mutex::new(CachedStatus::default()));
        let inflight = Arc::new(AtomicBool::new(false));

        // First trigger should succeed
        let triggered = ProtonDriveDaemon::trigger_status_refresh(&remote, &cached, &inflight);
        assert!(triggered);

        // While thread is running or immediately after, second concurrent trigger returns false if inflight is true
        // Wait for thread to finish
        for _ in 0..100 {
            if !inflight.load(Ordering::SeqCst) && cached.lock().unwrap().last_refreshed.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        let guard = cached.lock().unwrap();
        assert!(guard.authenticated);
        assert_eq!(guard.auth_message, "Authenticated");
        assert_eq!(guard.quota.used_bytes, 1024);
        assert!(guard.last_refreshed.is_some());
        assert!(!inflight.load(Ordering::SeqCst));
    }

    #[test]
    fn test_inflight_flag_prevents_duplicate_refresh() {
        let remote: Arc<dyn RemoteDrive> = Arc::new(DummyRemote::new());
        let cached = Arc::new(Mutex::new(CachedStatus::default()));
        let inflight = Arc::new(AtomicBool::new(true)); // simulate already inflight

        let triggered = ProtonDriveDaemon::trigger_status_refresh(&remote, &cached, &inflight);
        assert!(
            !triggered,
            "Should not trigger refresh when already inflight"
        );
    }

    #[test]
    fn test_select_remote_drive_for_config() {
        let temp = tempfile::tempdir().unwrap();
        let db = MetadataDB::new(&temp.path().join("meta.db")).unwrap();

        let native_cfg = Config::default();
        assert_eq!(native_cfg.backend, BACKEND_NATIVE);
        let native_drive = select_remote_drive_for_config(&native_cfg, &db).unwrap();
        assert_eq!(native_drive.backend_name(), BACKEND_NATIVE);

        let cli_cfg = Config {
            backend: "cli".to_string(),
            ..Default::default()
        };
        assert!(select_remote_drive_for_config(&cli_cfg, &db).is_err());

        let bad_cfg = Config {
            backend: "bogus".to_string(),
            ..Default::default()
        };
        assert!(select_remote_drive_for_config(&bad_cfg, &db).is_err());
    }
}
