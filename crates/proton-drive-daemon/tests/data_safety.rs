mod support;

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use neutron_drive_daemon::client::{RemoteDrive, RemoteNode, StorageQuota};
use neutron_drive_daemon::ipc::IpcClient;
use neutron_drive_daemon::metadata_db::SyncStatus;
use neutron_drive_daemon::sync_engine::AppSyncStatus;
use support::{ActivityRegistry, FakeRemoteDrive, MetadataDB, RemoteCall, SyncEngine, TestFixture};

#[test]
fn test_isolated_paths_cannot_touch_real_user_xdg_data() {
    let fixture = TestFixture::new();
    let temp_root = fixture.root_path().to_path_buf();

    // Verify all fixture paths are within the isolated temp directory
    assert!(fixture.db_path.starts_with(&temp_root));
    assert!(fixture.cache_dir.starts_with(&temp_root));
    assert!(fixture.mount_dir.starts_with(&temp_root));
    assert!(fixture.socket_path.starts_with(&temp_root));

    // Real user directories from config
    let real_data_dir = neutron_drive_daemon::config::app_data_dir();
    let real_cache_dir = neutron_drive_daemon::config::block_cache_dir();
    let real_mount_point = neutron_drive_daemon::config::default_mount_point();

    // Verify fixture paths do not match real user directories
    assert_ne!(fixture.cache_dir, real_cache_dir);
    assert_ne!(fixture.mount_dir, real_mount_point);
    assert_ne!(fixture.db_path, neutron_drive_daemon::config::db_path());

    // Exercise FUSE, DB, and Sync using the isolated fixture
    let fuse = fixture.create_fuse();
    let dir_node = fuse
        .create_dir("/", "safe_test_dir")
        .expect("create_dir failed");
    assert_eq!(dir_node.path, "/safe_test_dir");

    // Write a test cache file in the isolated cache
    let cache_file = fixture.cache_dir.join("isolated_block.dat");
    fs::write(&cache_file, b"isolated content").expect("failed to write isolated cache file");
    assert!(cache_file.exists());

    // Verify the file was written ONLY inside temp_root and not in real cache
    assert!(cache_file.starts_with(&temp_root));
    assert!(!real_cache_dir.join("isolated_block.dat").exists());
    assert!(!real_data_dir.join("safe_test_dir").exists());
    assert!(!real_mount_point.join("safe_test_dir").exists());
}

#[test]
fn test_fuse_sync_and_daemon_run_without_real_binary() {
    let fixture = TestFixture::new();

    // Configure fake remote responses
    fixture.fake_remote.set_auth_status(true, "Authenticated");
    fixture.fake_remote.set_storage_quota(StorageQuota {
        used_bytes: 4096,
        total_bytes: 1024 * 1024 * 1024,
        percent_used: 0.0004,
    });
    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![RemoteNode {
            name: "initial_file.txt".to_string(),
            node_type: "file".to_string(),
            size: 256,
            modify_time: Some(1700000000.0),
            uid: None,
        }]),
    );

    // 1. FUSE logic execution without real CLI
    let fuse = fixture.create_fuse();
    fuse.refresh_dir_if_needed("/", 0.0);
    let child = fixture.db.get_node("/initial_file.txt");
    assert!(child.is_some(), "Node should be populated from fake remote");
    assert_eq!(child.unwrap().sync_status, SyncStatus::CLOUD_ONLY);

    let created_dir = fuse
        .create_dir("/", "my_docs")
        .expect("mkdir should succeed");
    assert_eq!(created_dir.name, "my_docs");

    fuse.rename_node("/", "my_docs", "/", "documents")
        .expect("rename should succeed");
    assert!(fixture.db.get_node("/documents").is_some());
    assert!(fixture.db.get_node("/my_docs").is_none());

    fuse.remove_dir("/", "documents")
        .expect("rmdir should succeed");
    assert!(fixture.db.get_node("/documents").is_none());

    // 2. Sync Engine execution without real CLI
    let sync_engine = fixture.create_sync_engine(5);
    let staged_file = fixture.cache_dir.join("sync_test.dat");
    fs::write(&staged_file, b"test payload for sync").unwrap();

    let _ = fixture.db.upsert_node(
        "/sync_test.txt",
        "/",
        "sync_test.txt",
        "file",
        21,
        None,
        Some(&staged_file.to_string_lossy()),
        Some(SyncStatus::MODIFIED),
        None,
        None,
        Some("cache-uuid-1234"),
        Some(1),
        Some(false),
        None,
    );
    let _ = fixture
        .db
        .mark_pending("/sync_test.txt", &staged_file.to_string_lossy(), Some(21));

    sync_engine.sync_once();
    assert_eq!(sync_engine.status(), AppSyncStatus::IDLE);
    let node_after = fixture.db.get_node("/sync_test.txt").unwrap();
    assert_eq!(node_after.sync_status, SyncStatus::SYNCED);

    // 3. Daemon execution and IPC handling without real CLI
    let daemon = fixture.create_daemon();
    daemon.start().expect("Daemon start should succeed");
    std::thread::sleep(Duration::from_millis(50));

    let ipc_client = IpcClient::new(Some(fixture.socket_path.clone()));
    let ping_resp = ipc_client
        .send_command("ping", serde_json::json!({}))
        .unwrap();
    assert_eq!(ping_resp.get("status").unwrap().as_str().unwrap(), "ok");

    let status_resp = ipc_client
        .send_command("status", serde_json::json!({}))
        .unwrap();
    assert_eq!(status_resp.get("status").unwrap().as_str().unwrap(), "ok");
    assert!(status_resp.get("authenticated").unwrap().as_bool().unwrap());

    let quota = status_resp.get("quota").unwrap();
    assert_eq!(quota.get("used_bytes").unwrap().as_u64().unwrap(), 4096);

    let pause_resp = ipc_client
        .send_command("pause", serde_json::json!({}))
        .unwrap();
    assert_eq!(pause_resp.get("status").unwrap().as_str().unwrap(), "ok");

    let resume_resp = ipc_client
        .send_command("resume", serde_json::json!({}))
        .unwrap();
    assert_eq!(resume_resp.get("status").unwrap().as_str().unwrap(), "ok");

    daemon.stop();
}

#[test]
fn test_fake_remote_drive_can_block_and_fail_all_operations() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();
    let sync_engine = fixture.create_sync_engine(5);

    // 1. Auth failure
    fixture
        .fake_remote
        .set_auth_status(false, "You need to login first");
    sync_engine.sync_once();
    assert_eq!(sync_engine.status(), AppSyncStatus::OFFLINE);

    let (auth_ok, auth_msg) = fixture.fake_remote.check_auth_status();
    assert!(!auth_ok);
    assert_eq!(auth_msg, "You need to login first");

    // 2. List failure
    fixture
        .fake_remote
        .set_default_list_result(Err("Network connection failed".to_string()));
    // Should gracefully handle list error without panicking
    fuse.refresh_dir_if_needed("/", 0.0);
    assert_eq!(fixture.db.get_children("/").len(), 0);

    // 3. Download failure
    let _ = fixture.db.upsert_node(
        "/cloud_file.txt",
        "/",
        "cloud_file.txt",
        "file",
        100,
        None,
        None,
        Some(SyncStatus::CLOUD_ONLY),
        None,
        None,
        Some("cloud-cache-id"),
        Some(1),
        Some(true),
        None,
    );
    let cloud_node = fixture.db.get_node("/cloud_file.txt").unwrap();
    fixture.fake_remote.set_download_result(false);
    let hydrate_result = fuse.hydrate("/cloud_file.txt", &cloud_node);
    assert_eq!(hydrate_result, Err(libc::EIO));
    let cloud_node_after = fixture.db.get_node("/cloud_file.txt").unwrap();
    assert_eq!(cloud_node_after.sync_status, SyncStatus::CLOUD_ONLY);
    assert_eq!(
        cloud_node_after.last_error.as_deref(),
        Some("Download failed")
    );

    // 4. Upload failure
    fixture.fake_remote.set_auth_status(true, "Authenticated");
    let local_file = fixture.cache_dir.join("fail_upload.dat");
    fs::write(&local_file, b"content to fail upload").unwrap();
    let _ = fixture.db.upsert_node(
        "/fail_upload.txt",
        "/",
        "fail_upload.txt",
        "file",
        22,
        None,
        Some(&local_file.to_string_lossy()),
        Some(SyncStatus::MODIFIED),
        None,
        None,
        Some("fail-upload-id"),
        Some(1),
        Some(false),
        None,
    );
    let _ = fixture
        .db
        .mark_pending("/fail_upload.txt", &local_file.to_string_lossy(), Some(22));
    fixture.fake_remote.set_upload_result(false);
    sync_engine.sync_once();
    assert_eq!(sync_engine.status(), AppSyncStatus::ERROR);
    let failed_node = fixture.db.get_node("/fail_upload.txt").unwrap();
    assert_eq!(failed_node.sync_status, SyncStatus::ERROR);

    // 5. Create folder failure
    fixture.fake_remote.set_create_folder_result(false);
    let mkdir_result = fuse.create_dir("/", "fail_folder");
    assert_eq!(mkdir_result.err(), Some(libc::EIO));
    assert!(fixture.db.get_node("/fail_folder").is_none());

    // 6. Rename failure
    let _ = fixture.db.upsert_node(
        "/item_to_rename.txt",
        "/",
        "item_to_rename.txt",
        "file",
        50,
        None,
        None,
        Some(SyncStatus::SYNCED),
        None,
        None,
        Some("rename-id"),
        Some(1),
        Some(true),
        None,
    );
    fixture.fake_remote.set_rename_result(false);
    let rename_result = fuse.rename_node("/", "item_to_rename.txt", "/", "renamed.txt");
    assert_eq!(rename_result, Err(libc::EIO));
    assert!(fixture.db.get_node("/item_to_rename.txt").is_some());
    assert!(fixture.db.get_node("/renamed.txt").is_none());

    // 7. Move node failure
    let _ = fixture.db.upsert_node(
        "/item_to_move.txt",
        "/",
        "item_to_move.txt",
        "file",
        50,
        None,
        None,
        Some(SyncStatus::SYNCED),
        None,
        None,
        Some("move-id"),
        Some(1),
        Some(true),
        None,
    );
    fixture.fake_remote.set_move_node_result(false);
    let move_result = fuse.rename_node(
        "/",
        "item_to_move.txt",
        "/target_folder",
        "item_to_move.txt",
    );
    assert_eq!(move_result, Err(libc::EIO));
    assert!(fixture.db.get_node("/item_to_move.txt").is_some());

    // 8. Trash failure (unlink and rmdir)
    let _ = fixture.db.upsert_node(
        "/item_to_trash.txt",
        "/",
        "item_to_trash.txt",
        "file",
        50,
        None,
        None,
        Some(SyncStatus::SYNCED),
        None,
        None,
        Some("trash-id"),
        Some(1),
        Some(true),
        None,
    );
    fixture.fake_remote.set_trash_result(false);
    let unlink_result = fuse.unlink_file("/", "item_to_trash.txt");
    assert_eq!(unlink_result, Err(libc::EIO));
    assert!(fixture.db.get_node("/item_to_trash.txt").is_some());

    let _ = fixture.db.upsert_node(
        "/folder_to_trash",
        "/",
        "folder_to_trash",
        "folder",
        0,
        None,
        None,
        Some(SyncStatus::SYNCED),
        None,
        None,
        Some("trash-folder-id"),
        Some(1),
        Some(true),
        None,
    );
    let rmdir_result = fuse.remove_dir("/", "folder_to_trash");
    assert_eq!(rmdir_result, Err(libc::EIO));
    assert!(fixture.db.get_node("/folder_to_trash").is_some());

    // 9. Delete failure
    fixture.fake_remote.set_delete_result(false);
    assert!(!fixture
        .fake_remote
        .delete("/my-files/permanently_delete.txt"));
}

#[test]
fn test_call_arguments_recorded_for_upload_and_namespace_ops() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();
    let sync_engine = fixture.create_sync_engine(5);

    // 1. Verify upload call recording and arguments
    let upload_content = b"Safety harness verification upload payload";
    let staged_file = fixture.cache_dir.join("recorded_upload.dat");
    fs::write(&staged_file, upload_content).unwrap();

    let _ = fixture.db.upsert_node(
        "/recorded_upload.txt",
        "/",
        "recorded_upload.txt",
        "file",
        upload_content.len() as i64,
        None,
        Some(&staged_file.to_string_lossy()),
        Some(SyncStatus::MODIFIED),
        None,
        None,
        Some("upload-recording-uuid"),
        Some(1),
        Some(false),
        None,
    );
    let _ = fixture.db.mark_pending(
        "/recorded_upload.txt",
        &staged_file.to_string_lossy(),
        Some(upload_content.len() as i64),
    );

    sync_engine.sync_once();

    let upload_calls = fixture.fake_remote.upload_calls();
    assert_eq!(
        upload_calls.len(),
        1,
        "Exactly one upload call should be recorded"
    );
    let upload_call = &upload_calls[0];
    assert_eq!(upload_call.remote_parent_path, "/my-files");
    assert_eq!(upload_call.conflict_strategy, "create-new-revision");
    assert_eq!(
        upload_call.file_content.as_deref(),
        Some(&upload_content[..])
    );

    // 2. Verify namespace operations call recording and arguments
    // Create folder
    let _ = fuse
        .create_dir("/", "Projects")
        .expect("create_dir should succeed");
    let create_folder_calls = fixture.fake_remote.create_folder_calls();
    assert_eq!(create_folder_calls.len(), 1);
    assert_eq!(create_folder_calls[0].remote_parent, "/my-files");
    assert_eq!(create_folder_calls[0].folder_name, "Projects");

    // Rename file
    let _ = fixture.db.upsert_node(
        "/Projects/draft.txt",
        "/Projects",
        "draft.txt",
        "file",
        100,
        None,
        None,
        Some(SyncStatus::SYNCED),
        None,
        None,
        Some("rename-call-uuid"),
        Some(1),
        Some(true),
        None,
    );
    fuse.rename_node("/Projects", "draft.txt", "/Projects", "final.txt")
        .expect("rename should succeed");
    let rename_calls = fixture.fake_remote.rename_calls();
    assert_eq!(rename_calls.len(), 1);
    assert_eq!(rename_calls[0].remote_path, "/my-files/Projects/draft.txt");
    assert_eq!(rename_calls[0].new_name, "final.txt");

    // Move file across directories
    let _ = fuse
        .create_dir("/", "Archive")
        .expect("create_dir should succeed");
    fuse.rename_node("/Projects", "final.txt", "/Archive", "final.txt")
        .expect("move should succeed");
    let move_calls = fixture.fake_remote.move_node_calls();
    assert_eq!(move_calls.len(), 1);
    assert_eq!(move_calls[0].source_path, "/my-files/Projects/final.txt");
    assert_eq!(move_calls[0].target_parent_path, "/my-files/Archive");

    // Trash file
    fuse.unlink_file("/Archive", "final.txt")
        .expect("unlink should succeed");
    let trash_calls = fixture.fake_remote.trash_calls();
    assert_eq!(trash_calls.len(), 1);
    assert_eq!(trash_calls[0].remote_path, "/my-files/Archive/final.txt");

    // 3. Verify total recorded calls log
    let all_calls = fixture.fake_remote.recorded_calls();
    assert!(
        all_calls
            .iter()
            .any(|c| matches!(c, RemoteCall::UploadFile(_))),
        "Calls log must contain UploadFile"
    );
    assert!(
        all_calls
            .iter()
            .any(|c| matches!(c, RemoteCall::CreateFolder(_))),
        "Calls log must contain CreateFolder"
    );
    assert!(
        all_calls.iter().any(|c| matches!(c, RemoteCall::Rename(_))),
        "Calls log must contain Rename"
    );
    assert!(
        all_calls
            .iter()
            .any(|c| matches!(c, RemoteCall::MoveNode(_))),
        "Calls log must contain MoveNode"
    );
    assert!(
        all_calls.iter().any(|c| matches!(c, RemoteCall::Trash(_))),
        "Calls log must contain Trash"
    );
}

struct HookRemote {
    inner: FakeRemoteDrive,
    upload_started: Arc<Barrier>,
    upload_finish: Arc<Barrier>,
    hook_active: Arc<AtomicBool>,
}

impl HookRemote {
    fn new(
        inner: FakeRemoteDrive,
        upload_started: Arc<Barrier>,
        upload_finish: Arc<Barrier>,
        hook_active: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            upload_started,
            upload_finish,
            hook_active,
        }
    }
}

impl RemoteDrive for HookRemote {
    fn check_auth_status(&self) -> (bool, String) {
        self.inner.check_auth_status()
    }

    fn logout(&self) -> bool {
        self.inner.logout()
    }

    fn list_path(&self, remote_path: &str) -> Result<Vec<RemoteNode>, String> {
        self.inner.list_path(remote_path)
    }

    fn download_file(
        &self,
        remote_path: &str,
        local_target_dir: &Path,
        conflict_strategy: &str,
    ) -> bool {
        self.inner
            .download_file(remote_path, local_target_dir, conflict_strategy)
    }

    fn upload_file(
        &self,
        local_file: &Path,
        remote_parent_path: &str,
        conflict_strategy: &str,
    ) -> bool {
        if self.hook_active.load(Ordering::SeqCst) {
            self.upload_started.wait();
            self.upload_finish.wait();
        }
        self.inner
            .upload_file(local_file, remote_parent_path, conflict_strategy)
    }

    fn create_folder(&self, remote_parent: &str, folder_name: &str) -> bool {
        self.inner.create_folder(remote_parent, folder_name)
    }

    fn rename(&self, remote_path: &str, new_name: &str) -> bool {
        self.inner.rename(remote_path, new_name)
    }

    fn move_node(&self, source_path: &str, target_parent_path: &str) -> bool {
        self.inner.move_node(source_path, target_parent_path)
    }

    fn trash(&self, remote_path: &str) -> bool {
        self.inner.trash(remote_path)
    }

    fn delete(&self, remote_path: &str) -> bool {
        self.inner.delete(remote_path)
    }

    fn get_storage_quota(&self) -> StorageQuota {
        self.inner.get_storage_quota()
    }
}

#[test]
fn test_writable_open_file_is_not_uploaded() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();
    let sync_engine = fixture.create_sync_engine(5);

    fixture.fake_remote.set_auth_status(true, "Authenticated");

    // 1. Create a file and write to it with an open handle (without releasing)
    let fh = fuse
        .create_file_handle("/", "open.txt")
        .expect("create_file_handle failed");
    fuse.write_to_handle(fh, 0, b"UNFINISHED")
        .expect("write_to_handle failed");

    // Verify handle is writable and registered in shared activity
    let node = fixture.db.get_node("/open.txt").expect("node should exist");
    assert!(fixture.activity.has_writable_handle(&node.cache_id));

    // 2. Run upload processing - must NOT upload while writable handle is open
    sync_engine.sync_once();
    assert_eq!(
        fixture.fake_remote.upload_calls().len(),
        0,
        "File with open writable handle must not be uploaded"
    );

    // 3. Release the handle
    fuse.release_handle(fh).expect("release_handle failed");
    assert!(!fixture.activity.has_writable_handle(&node.cache_id));

    // 4. Run upload processing again - now it should upload!
    sync_engine.sync_once();
    let upload_calls = fixture.fake_remote.upload_calls();
    assert_eq!(
        upload_calls.len(),
        1,
        "File should be uploaded after handle is released"
    );
    assert_eq!(
        upload_calls[0].file_content.as_deref(),
        Some(&b"UNFINISHED"[..])
    );

    // Node sync_status in DB should now be SYNCED
    let node_after = fixture.db.get_node("/open.txt").unwrap();
    assert_eq!(node_after.sync_status, SyncStatus::SYNCED);
}

#[test]
fn test_edit_during_upload_keeps_new_generation_pending() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    fixture.fake_remote.set_auth_status(true, "Authenticated");

    // 1. Create a local file and write initial content "OLD"
    let fh = fuse
        .create_file_handle("/", "race.txt")
        .expect("create failed");
    fuse.write_to_handle(fh, 0, b"OLD").expect("write failed");
    fuse.release_handle(fh).expect("release failed");

    let initial_node = fixture.db.get_node("/race.txt").expect("node should exist");
    assert_eq!(initial_node.sync_status, SyncStatus::MODIFIED);
    let initial_gen = initial_node.generation;

    // 2. Set up HookRemote to intercept the upload
    let upload_started = Arc::new(Barrier::new(2));
    let upload_finish = Arc::new(Barrier::new(2));
    let hook_active = Arc::new(AtomicBool::new(true));

    let hook_remote = Arc::new(HookRemote::new(
        fixture.fake_remote.clone(),
        Arc::clone(&upload_started),
        Arc::clone(&upload_finish),
        Arc::clone(&hook_active),
    ));

    let hooked_sync = SyncEngine::new(
        hook_remote,
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        5,
        Arc::clone(&fixture.activity),
    );

    // 3. Start upload on worker thread
    let worker = std::thread::spawn(move || {
        hooked_sync.sync_once();
    });

    // Wait until upload_file has been called and is paused
    upload_started.wait();

    // 4. While upload is in flight, edit the file with new content "NEW"
    let edit_fh = fuse
        .open_file_handle("/race.txt", true)
        .expect("open failed");
    fuse.write_to_handle(edit_fh, 0, b"NEW")
        .expect("write NEW failed");
    fuse.release_handle(edit_fh).expect("release failed");

    // Allow upload of "OLD" to complete
    upload_finish.wait();
    worker.join().expect("worker thread panicked");

    // 5. Verify the first upload was recorded with "OLD"
    let upload_calls = fixture.fake_remote.upload_calls();
    assert_eq!(upload_calls.len(), 1);
    assert_eq!(upload_calls[0].file_content.as_deref(), Some(&b"OLD"[..]));

    // Verify local cache has "NEW"
    let node_after_first = fixture.db.get_node("/race.txt").expect("node should exist");
    let local_bytes = fs::read(node_after_first.local_cache_path.as_ref().unwrap()).unwrap();
    assert_eq!(&local_bytes, b"NEW");

    // CRITICAL: New generation MUST remain pending (MODIFIED) and remote_exists == true!
    assert_eq!(node_after_first.sync_status, SyncStatus::MODIFIED);
    assert!(node_after_first.remote_exists);
    assert_eq!(node_after_first.generation, initial_gen + 1);

    // 6. Run sync again with hook disabled - it should upload "NEW"
    hook_active.store(false, Ordering::SeqCst);
    let normal_sync = fixture.create_sync_engine(5);
    normal_sync.sync_once();

    let all_uploads = fixture.fake_remote.upload_calls();
    assert_eq!(all_uploads.len(), 2);
    assert_eq!(all_uploads[1].file_content.as_deref(), Some(&b"NEW"[..]));

    let final_node = fixture.db.get_node("/race.txt").unwrap();
    assert_eq!(final_node.sync_status, SyncStatus::SYNCED);
}

#[test]
fn test_fsync_and_flush_propagate_durability_errors() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let fh = fuse
        .create_file_handle("/", "sync_durability.txt")
        .expect("create_file_handle failed");
    fuse.write_to_handle(fh, 0, b"durability test data")
        .expect("write_to_handle failed");

    // 1. SQLite checkpoint failure propagation
    fixture.db.set_fail_sync_storage(true);

    let fsync_err = fuse.fsync_handle(fh, false);
    assert!(
        fsync_err.is_err(),
        "fsync_handle must propagate SQLite checkpoint error"
    );

    let flush_err = fuse.flush_handle(fh);
    assert!(
        flush_err.is_err(),
        "flush_handle must propagate SQLite checkpoint error"
    );

    let release_err = fuse.release_handle(fh);
    assert!(
        release_err.is_err(),
        "release_handle must propagate SQLite checkpoint error"
    );

    fixture.db.set_fail_sync_storage(false);

    // 2. File sync error propagation
    let fh2 = fuse
        .open_file_handle("/sync_durability.txt", true)
        .expect("open_file_handle failed");
    fuse.write_to_handle(fh2, 0, b"more data")
        .expect("write_to_handle failed");

    #[cfg(unix)]
    {
        // Replace handle file with /dev/null which returns EINVAL on fsync/fdatasync
        let dev_null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        {
            let mut handles = fixture.activity.open_handles.lock().unwrap();
            let handle = handles.get_mut(&fh2).unwrap();
            handle.file = Some(dev_null);
        }

        let fsync_file_err = fuse.fsync_handle(fh2, false);
        assert!(
            fsync_file_err.is_err(),
            "fsync_handle must propagate file sync error"
        );

        let flush_file_err = fuse.flush_handle(fh2);
        assert!(
            flush_file_err.is_err(),
            "flush_handle must propagate file sync error"
        );

        let release_file_err = fuse.release_handle(fh2);
        assert!(
            release_file_err.is_err(),
            "release_handle must propagate file sync error"
        );
    }
}

#[test]
fn test_shared_handle_concurrent_writes_use_explicit_offsets() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let fh = fuse
        .create_file_handle("/", "concurrent_writes.txt")
        .expect("create failed");
    fuse.write_to_handle(fh, 0, b"..........")
        .expect("initial write failed");
    fuse.release_handle(fh).expect("release failed");

    let open_fh = fuse
        .open_file_handle("/concurrent_writes.txt", true)
        .expect("open failed");

    let barrier = Arc::new(Barrier::new(3));
    let fuse_arc = Arc::new(fuse);

    let t1_barrier = Arc::clone(&barrier);
    let t1_fuse = Arc::clone(&fuse_arc);
    let t1 = std::thread::spawn(move || {
        t1_barrier.wait();
        t1_fuse
            .write_to_handle(open_fh, 0, b"AA")
            .expect("t1 write failed");
    });

    let t2_barrier = Arc::clone(&barrier);
    let t2_fuse = Arc::clone(&fuse_arc);
    let t2 = std::thread::spawn(move || {
        t2_barrier.wait();
        t2_fuse
            .write_to_handle(open_fh, 5, b"BB")
            .expect("t2 write failed");
    });

    barrier.wait();
    t1.join().unwrap();
    t2.join().unwrap();

    fuse_arc.release_handle(open_fh).expect("release failed");

    let node = fixture.db.get_node("/concurrent_writes.txt").unwrap();
    let content = fs::read(node.local_cache_path.as_ref().unwrap()).expect("read failed");
    assert_eq!(&content, b"AA...BB...");
}

#[test]
fn test_crash_recovery_leaves_work_retryable() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    fixture.fake_remote.set_auth_status(true, "Authenticated");

    // Case 1: Write and release before upload, simulate crash and restart
    let fh1 = fuse
        .create_file_handle("/", "crash1.txt")
        .expect("create failed");
    fuse.write_to_handle(fh1, 0, b"CRASH_AFTER_WRITE")
        .expect("write failed");
    fuse.release_handle(fh1).expect("release failed");

    // Case 2: Interrupted upload (node left in SYNCING state when process crashes)
    let fh2 = fuse
        .create_file_handle("/", "crash2.txt")
        .expect("create failed");
    fuse.write_to_handle(fh2, 0, b"INTERRUPTED_SYNC")
        .expect("write failed");
    fuse.release_handle(fh2).expect("release failed");
    fixture
        .db
        .update_sync_status("/crash2.txt", SyncStatus::SYNCING, None, None);
    assert_eq!(
        fixture.db.get_node("/crash2.txt").unwrap().sync_status,
        SyncStatus::SYNCING
    );

    // Case 3: Write started (mark_pending called) but crash before release
    let fh3 = fuse
        .create_file_handle("/", "crash3.txt")
        .expect("create failed");
    fuse.write_to_handle(fh3, 0, b"CRASH_BEFORE_RELEASE")
        .expect("write failed");
    // Do not call release_handle - simulates process killed with unreleased open writer!

    // Drop fuse to simulate process crash
    drop(fuse);

    // Simulate restart by reopening the database and initializing a fresh FUSE and SyncEngine
    let reopened_db = MetadataDB::new(&fixture.db_path).expect("reopen DB failed");

    // Check all three nodes recovered to retryable state (MODIFIED)
    let node1 = reopened_db
        .get_node("/crash1.txt")
        .expect("node1 should exist");
    assert_eq!(node1.sync_status, SyncStatus::MODIFIED);

    let node2 = reopened_db
        .get_node("/crash2.txt")
        .expect("node2 should exist");
    assert_eq!(
        node2.sync_status,
        SyncStatus::MODIFIED,
        "Interrupted SYNCING node must recover to MODIFIED"
    );

    let node3 = reopened_db
        .get_node("/crash3.txt")
        .expect("node3 should exist");
    assert_eq!(
        node3.sync_status,
        SyncStatus::MODIFIED,
        "Unreleased dirty node must remain MODIFIED"
    );

    let new_activity = Arc::new(ActivityRegistry::new());
    let reopened_sync = SyncEngine::new(
        fixture.remote_client(),
        reopened_db.clone(),
        fixture.cache_dir.clone(),
        5,
        new_activity,
    );

    reopened_sync.sync_once();

    assert_eq!(
        reopened_db.get_node("/crash1.txt").unwrap().sync_status,
        SyncStatus::SYNCED
    );
    assert_eq!(
        reopened_db.get_node("/crash2.txt").unwrap().sync_status,
        SyncStatus::SYNCED
    );
    assert_eq!(
        reopened_db.get_node("/crash3.txt").unwrap().sync_status,
        SyncStatus::SYNCED
    );

    let uploads = fixture.fake_remote.upload_calls();
    assert_eq!(uploads.len(), 3);
    assert!(uploads
        .iter()
        .any(|u| u.file_content.as_deref() == Some(&b"CRASH_AFTER_WRITE"[..])));
    assert!(uploads
        .iter()
        .any(|u| u.file_content.as_deref() == Some(&b"INTERRUPTED_SYNC"[..])));
    assert!(uploads
        .iter()
        .any(|u| u.file_content.as_deref() == Some(&b"CRASH_BEFORE_RELEASE"[..])));
}
