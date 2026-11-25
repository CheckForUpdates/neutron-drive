#![allow(unused_imports, dead_code)]

mod support;

use std::fs;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use support::*;

#[test]
fn test_remote_create_appears_locally_after_refresh() {
    let fixture = TestFixture::new();
    fixture.fake_remote.set_auth_status(true, "Authenticated");

    // Remote contains a new file and a new folder
    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![
            RemoteNode {
                name: "new_file.txt".to_string(),
                node_type: "file".to_string(),
                size: 1024,
                modify_time: Some(1700000000.0),
                uid: Some("uid-remote-file".to_string()),
            },
            RemoteNode {
                name: "new_folder".to_string(),
                node_type: "folder".to_string(),
                size: 0,
                modify_time: Some(1700000010.0),
                uid: Some("uid-remote-dir".to_string()),
            },
        ]),
    );

    let fuse = fixture.create_fuse();
    fuse.refresh_dir_if_needed("/", 0.0);

    let file_node = fixture
        .db
        .get_node("/new_file.txt")
        .expect("new_file.txt should exist in db");
    assert_eq!(file_node.name, "new_file.txt");
    assert_eq!(file_node.parent_path, "/");
    assert_eq!(file_node.node_type, "file");
    assert_eq!(file_node.size, 1024);
    assert!((file_node.mtime - 1700000000.0).abs() < 0.001);
    assert_eq!(file_node.uid.as_deref(), Some("uid-remote-file"));
    assert_eq!(file_node.sync_status, SyncStatus::CLOUD_ONLY);
    assert!(file_node.remote_exists);
    assert!(file_node.local_cache_path.is_none());

    let dir_node = fixture
        .db
        .get_node("/new_folder")
        .expect("new_folder should exist in db");
    assert_eq!(dir_node.name, "new_folder");
    assert_eq!(dir_node.node_type, "folder");
    assert_eq!(dir_node.sync_status, SyncStatus::CLOUD_ONLY);
    assert!(dir_node.remote_exists);
}

#[test]
fn test_remote_update_updates_metadata_and_invalidates_clean_cache() {
    let fixture = TestFixture::new();
    fixture.fake_remote.set_auth_status(true, "Authenticated");

    // Local clean cached file
    let cache_file = fixture.cache_dir.join("clean_file.dat");
    fs::write(&cache_file, b"original clean cached content").unwrap();

    fixture
        .db
        .upsert_node(
            "/clean_doc.txt",
            "/",
            "clean_doc.txt",
            "file",
            29,
            Some(1650000000.0),
            Some(cache_file.to_str().unwrap()),
            Some(SyncStatus::SYNCED),
            None,
            Some("uid-old"),
            None,
            None,
            Some(true),
            None,
        )
        .unwrap();

    assert!(cache_file.exists());
    let initial_node = fixture.db.get_node("/clean_doc.txt").unwrap();
    assert_eq!(initial_node.sync_status, SyncStatus::SYNCED);
    assert_eq!(initial_node.size, 29);

    // Remote has an update: new size, new mtime, new uid, new content
    let new_content = b"this is the updated content from remote drive";
    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![RemoteNode {
            name: "clean_doc.txt".to_string(),
            node_type: "file".to_string(),
            size: new_content.len() as i64,
            modify_time: Some(1720000000.0),
            uid: Some("uid-new".to_string()),
        }]),
    );
    fixture
        .fake_remote
        .set_download_content("/my-files/clean_doc.txt", new_content.to_vec());

    let fuse = fixture.create_fuse();
    fuse.refresh_dir_if_needed("/", 0.0);

    // Check DB: metadata updated, sync_status became CLOUD_ONLY, cache path cleared
    let updated_node = fixture
        .db
        .get_node("/clean_doc.txt")
        .expect("clean_doc.txt should still exist");
    assert_eq!(updated_node.size, new_content.len() as i64);
    assert!((updated_node.mtime - 1720000000.0).abs() < 0.001);
    assert_eq!(updated_node.uid.as_deref(), Some("uid-new"));
    assert_eq!(updated_node.sync_status, SyncStatus::CLOUD_ONLY);
    assert!(updated_node.local_cache_path.is_none());

    // Old cache file on disk must be removed
    assert!(
        !cache_file.exists(),
        "Old clean cache file should be deleted on remote update"
    );

    // Subsequent read / hydrate re-hydrates fresh content from remote
    let hydrated_path = fuse
        .hydrate("/clean_doc.txt", &updated_node)
        .expect("hydrate should succeed");
    assert!(hydrated_path.exists());
    let read_back = fs::read(&hydrated_path).unwrap();
    assert_eq!(read_back, new_content);

    let rehydrated_node = fixture.db.get_node("/clean_doc.txt").unwrap();
    assert_eq!(rehydrated_node.sync_status, SyncStatus::SYNCED);
}

#[test]
fn test_remote_delete_removes_clean_local_node_and_clean_cache_file() {
    let fixture = TestFixture::new();
    fixture.fake_remote.set_auth_status(true, "Authenticated");

    // 1. Clean file with cached content
    let cache_file = fixture.cache_dir.join("to_delete.dat");
    fs::write(&cache_file, b"cache content to be deleted").unwrap();

    fixture
        .db
        .upsert_node(
            "/to_delete.txt",
            "/",
            "to_delete.txt",
            "file",
            27,
            Some(1650000000.0),
            Some(cache_file.to_str().unwrap()),
            Some(SyncStatus::SYNCED),
            None,
            Some("uid-del-1"),
            None,
            None,
            Some(true),
            None,
        )
        .unwrap();

    // 2. Clean cloud-only file
    fixture
        .db
        .upsert_node(
            "/cloud_only_del.txt",
            "/",
            "cloud_only_del.txt",
            "file",
            500,
            Some(1650000000.0),
            None,
            Some(SyncStatus::CLOUD_ONLY),
            None,
            Some("uid-del-2"),
            None,
            None,
            Some(true),
            None,
        )
        .unwrap();

    // Remote listing is empty
    fixture.fake_remote.set_list_result("/my-files", Ok(vec![]));

    let fuse = fixture.create_fuse();
    fuse.refresh_dir_if_needed("/", 0.0);

    // Nodes must be removed from DB
    assert!(fixture.db.get_node("/to_delete.txt").is_none());
    assert!(fixture.db.get_node("/cloud_only_del.txt").is_none());

    // Cache file must be removed from disk
    assert!(
        !cache_file.exists(),
        "Cache file must be deleted when clean remote node is deleted"
    );
}

#[test]
fn test_local_dirty_uploading_open_and_local_only_nodes_survive_refresh() {
    let fixture = TestFixture::new();
    fixture.fake_remote.set_auth_status(true, "Authenticated");

    // 1. Local dirty node (MODIFIED)
    let dirty_cache = fixture.cache_dir.join("dirty.dat");
    fs::write(&dirty_cache, b"dirty content").unwrap();
    fixture
        .db
        .upsert_node(
            "/dirty.txt",
            "/",
            "dirty.txt",
            "file",
            13,
            Some(1600000000.0),
            Some(dirty_cache.to_str().unwrap()),
            Some(SyncStatus::MODIFIED),
            None,
            Some("uid-dirty"),
            None,
            None,
            Some(true),
            None,
        )
        .unwrap();

    // 2. Local uploading node (SYNCING)
    let uploading_cache = fixture.cache_dir.join("uploading.dat");
    fs::write(&uploading_cache, b"uploading content").unwrap();
    fixture
        .db
        .upsert_node(
            "/uploading.txt",
            "/",
            "uploading.txt",
            "file",
            17,
            Some(1600000000.0),
            Some(uploading_cache.to_str().unwrap()),
            Some(SyncStatus::SYNCING),
            None,
            Some("uid-uploading"),
            None,
            None,
            Some(true),
            None,
        )
        .unwrap();

    // 3. Local node with open handle
    let open_cache = fixture.cache_dir.join("open.dat");
    fs::write(&open_cache, b"open file content").unwrap();
    fixture
        .db
        .upsert_node(
            "/open.txt",
            "/",
            "open.txt",
            "file",
            17,
            Some(1600000000.0),
            Some(open_cache.to_str().unwrap()),
            Some(SyncStatus::SYNCED),
            None,
            Some("uid-open"),
            None,
            None,
            Some(true),
            None,
        )
        .unwrap();
    let open_node = fixture.db.get_node("/open.txt").unwrap();
    let open_f = fs::File::open(&open_cache).unwrap();
    fixture.activity.open_handles.lock().unwrap().insert(
        999,
        OpenHandle {
            file: Some(open_f),
            path: "/open.txt".to_string(),
            cache_id: open_node.cache_id.clone(),
            local_cache: open_cache.clone(),
            writable: false,
            wrote: false,
            remote_size: 0,
            stream_block_cache: Arc::new(std::sync::Mutex::new(None)),
        },
    );

    // 4. Local-only newly created node (remote_exists == false)
    let local_only_cache = fixture.cache_dir.join("local_only.dat");
    fs::write(&local_only_cache, b"local only content").unwrap();
    fixture
        .db
        .upsert_node(
            "/local_only.txt",
            "/",
            "local_only.txt",
            "file",
            18,
            Some(1600000000.0),
            Some(local_only_cache.to_str().unwrap()),
            Some(SyncStatus::MODIFIED),
            None,
            None,
            None,
            None,
            Some(false),
            None,
        )
        .unwrap();

    // Remote listing does NOT have any of these files
    fixture.fake_remote.set_list_result("/my-files", Ok(vec![]));

    let fuse = fixture.create_fuse();
    fuse.refresh_dir_if_needed("/", 0.0);

    // All 4 files must survive!
    let dirty = fixture
        .db
        .get_node("/dirty.txt")
        .expect("dirty node must survive remote delete");
    assert_eq!(dirty.sync_status, SyncStatus::MODIFIED);
    assert_eq!(fs::read(&dirty_cache).unwrap(), b"dirty content");

    let uploading = fixture
        .db
        .get_node("/uploading.txt")
        .expect("uploading node must survive remote delete");
    assert_eq!(uploading.sync_status, SyncStatus::SYNCING);
    assert_eq!(fs::read(&uploading_cache).unwrap(), b"uploading content");

    let open = fixture
        .db
        .get_node("/open.txt")
        .expect("open node must survive remote delete");
    assert_eq!(open.sync_status, SyncStatus::SYNCED);
    assert_eq!(fs::read(&open_cache).unwrap(), b"open file content");

    let local_only = fixture
        .db
        .get_node("/local_only.txt")
        .expect("local-only node must survive remote delete");
    assert!(!local_only.remote_exists);
    assert_eq!(fs::read(&local_only_cache).unwrap(), b"local only content");

    // Test remote conflicting update does NOT overwrite local dirty work
    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![RemoteNode {
            name: "dirty.txt".to_string(),
            node_type: "file".to_string(),
            size: 9999,
            modify_time: Some(2000000000.0),
            uid: Some("uid-remote-conflicting".to_string()),
        }]),
    );

    fuse.refresh_dir_if_needed("/", 0.0);

    let dirty_after = fixture.db.get_node("/dirty.txt").unwrap();
    assert_eq!(
        dirty_after.sync_status,
        SyncStatus::MODIFIED,
        "Dirty status must be preserved"
    );
    assert_eq!(dirty_after.size, 13, "Local dirty size must be preserved");
    assert_eq!(fs::read(&dirty_cache).unwrap(), b"dirty content");
}

#[test]
fn test_offline_to_online_recovery_restores_status_and_triggers_uploads() {
    let fixture = TestFixture::new();

    // Start offline
    fixture
        .fake_remote
        .set_auth_status(false, "You need to login first");

    let sync_engine = fixture.create_sync_engine(5);

    // Initial sync while offline
    sync_engine.sync_once();
    assert_eq!(sync_engine.status(), AppSyncStatus::OFFLINE);

    // Create a local pending file to upload
    let pending_cache = fixture.cache_dir.join("pending_upload.dat");
    fs::write(&pending_cache, b"offline created data to upload").unwrap();
    fixture
        .db
        .upsert_node(
            "/pending_upload.txt",
            "/",
            "pending_upload.txt",
            "file",
            30,
            Some(1700000000.0),
            Some(pending_cache.to_str().unwrap()),
            Some(SyncStatus::MODIFIED),
            None,
            None,
            None,
            None,
            Some(false),
            None,
        )
        .unwrap();

    // Still offline: sync_once does not upload
    sync_engine.sync_once();
    assert_eq!(sync_engine.status(), AppSyncStatus::OFFLINE);
    assert_eq!(fixture.fake_remote.upload_calls().len(), 0);
    assert_eq!(
        fixture
            .db
            .get_node("/pending_upload.txt")
            .unwrap()
            .sync_status,
        SyncStatus::MODIFIED
    );

    // Now come online!
    fixture.fake_remote.set_auth_status(true, "Authenticated");
    fixture.fake_remote.set_list_result("/my-files", Ok(vec![]));

    // Offline-to-online recovery triggers pending uploads and restores status
    sync_engine.sync_once();

    assert_eq!(fixture.fake_remote.upload_calls().len(), 1);
    let uploaded = &fixture.fake_remote.upload_calls()[0];
    assert_eq!(uploaded.remote_parent_path, "/my-files");

    let node_after = fixture.db.get_node("/pending_upload.txt").unwrap();
    assert_eq!(node_after.sync_status, SyncStatus::SYNCED);
    assert!(node_after.remote_exists);
    assert_eq!(sync_engine.status(), AppSyncStatus::IDLE);

    // Verify recovery with no pending work restores directly to IDLE
    fixture.fake_remote.set_auth_status(false, "Logged out");
    sync_engine.sync_once();
    assert_eq!(sync_engine.status(), AppSyncStatus::OFFLINE);

    fixture.fake_remote.set_auth_status(true, "Authenticated");
    sync_engine.sync_once();
    assert_eq!(sync_engine.status(), AppSyncStatus::IDLE);
}

#[test]
fn test_ipc_refresh_command() {
    let fixture = TestFixture::new();
    fixture.fake_remote.set_auth_status(true, "Authenticated");

    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![RemoteNode {
            name: "refreshed_via_ipc.txt".to_string(),
            node_type: "file".to_string(),
            size: 64,
            modify_time: Some(1700000000.0),
            uid: Some("uid-ipc".to_string()),
        }]),
    );

    let daemon = fixture.create_daemon();
    daemon.start().expect("Daemon start should succeed");
    thread::sleep(Duration::from_millis(100));

    let client = fixture.create_ipc_client();
    assert!(client.is_daemon_running());

    // 1. Authenticated refresh succeeds
    let resp = client
        .send_command("refresh", serde_json::json!({}))
        .expect("IPC refresh command");
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(
        resp.get("message").and_then(|v| v.as_str()),
        Some("Refreshed")
    );

    // Verify reconciliation occurred in DB
    let node = fixture.db.get_node("/refreshed_via_ipc.txt");
    assert!(
        node.is_some(),
        "Node should be created from remote listing after refresh IPC"
    );

    // 2. Unauthenticated refresh fails with error
    fixture
        .fake_remote
        .set_auth_status(false, "Not authenticated");
    let resp_err = client
        .send_command("refresh", serde_json::json!({}))
        .expect("IPC refresh command unauth");
    assert_eq!(
        resp_err.get("status").and_then(|v| v.as_str()),
        Some("error")
    );
    assert_eq!(
        resp_err.get("message").and_then(|v| v.as_str()),
        Some("Not authenticated")
    );

    daemon.stop();
}

#[test]
fn test_tracked_subdirectory_polled_and_updated_across_rename_and_delete() {
    let fixture = TestFixture::new();
    fixture.fake_remote.set_auth_status(true, "Authenticated");

    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![RemoteNode {
            name: "projects".to_string(),
            node_type: "folder".to_string(),
            size: 0,
            modify_time: Some(1700000000.0),
            uid: Some("uid-projects".to_string()),
        }]),
    );
    fixture.fake_remote.set_list_result(
        "/my-files/projects",
        Ok(vec![RemoteNode {
            name: "spec.md".to_string(),
            node_type: "file".to_string(),
            size: 100,
            modify_time: Some(1700000001.0),
            uid: Some("uid-spec".to_string()),
        }]),
    );

    let fuse = fixture.create_fuse();
    let sync_engine = fixture.create_sync_engine(5);

    fuse.refresh_dir_if_needed("/", 0.0);
    fuse.refresh_dir_if_needed("/projects", 0.0);

    assert!(fixture
        .activity
        .tracked_dirs()
        .contains(&"/projects".to_string()));
    assert!(fixture.db.get_node("/projects/spec.md").is_some());

    // Remote adds a second file inside /projects; SyncEngine polls tracked subdirs automatically
    fixture.fake_remote.set_list_result(
        "/my-files/projects",
        Ok(vec![
            RemoteNode {
                name: "spec.md".to_string(),
                node_type: "file".to_string(),
                size: 100,
                modify_time: Some(1700000001.0),
                uid: Some("uid-spec".to_string()),
            },
            RemoteNode {
                name: "plan.md".to_string(),
                node_type: "file".to_string(),
                size: 200,
                modify_time: Some(1700000002.0),
                uid: Some("uid-plan".to_string()),
            },
        ]),
    );

    sync_engine.poll_remote_changes();
    assert!(
        fixture.db.get_node("/projects/plan.md").is_some(),
        "Background poll must reconcile tracked subdirectory /projects"
    );

    // Rename /projects -> /archive and ensure tracking follows
    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![RemoteNode {
            name: "archive".to_string(),
            node_type: "folder".to_string(),
            size: 0,
            modify_time: Some(1700000003.0),
            uid: Some("uid-projects".to_string()),
        }]),
    );
    fixture.fake_remote.set_list_result(
        "/my-files/archive",
        Ok(vec![
            RemoteNode {
                name: "spec.md".to_string(),
                node_type: "file".to_string(),
                size: 100,
                modify_time: Some(1700000001.0),
                uid: Some("uid-spec".to_string()),
            },
            RemoteNode {
                name: "plan.md".to_string(),
                node_type: "file".to_string(),
                size: 200,
                modify_time: Some(1700000002.0),
                uid: Some("uid-plan".to_string()),
            },
            RemoteNode {
                name: "notes.md".to_string(),
                node_type: "file".to_string(),
                size: 50,
                modify_time: Some(1700000004.0),
                uid: Some("uid-notes".to_string()),
            },
        ]),
    );

    fuse.rename_node("/", "projects", "/", "archive")
        .expect("rename /projects -> /archive should succeed");

    let tracked_after_rename = fixture.activity.tracked_dirs();
    assert!(tracked_after_rename.contains(&"/archive".to_string()));
    assert!(!tracked_after_rename.contains(&"/projects".to_string()));

    sync_engine.poll_remote_changes();
    assert!(fixture.db.get_node("/archive/notes.md").is_some());

    // Remote deletion of /archive untracks it cleanly
    fixture.fake_remote.set_list_result("/my-files", Ok(vec![]));
    sync_engine.poll_remote_changes();
    assert!(fixture.db.get_node("/archive").is_none());
    assert!(!fixture
        .activity
        .tracked_dirs()
        .contains(&"/archive".to_string()));
}

#[test]
fn test_nonblocking_statfs_and_background_dir_refresh() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    fixture
        .fake_remote
        .set_storage_quota(neutron_drive_daemon::client::StorageQuota {
            used_bytes: 4096 * 25,
            total_bytes: 4096 * 200,
            percent_used: 12.5,
        });

    // First call returns immediately and triggers background quota refresh
    let _ = fuse.compute_statfs_nonblocking();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let (blocks, bfree, _, _, _, _, _, _) = fuse.compute_statfs_nonblocking();
        if blocks == 200 && bfree == 175 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Cached statfs quota did not warm in background"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // Background directory refresh populates SQLite without blocking caller
    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![RemoteNode {
            name: "bg.txt".to_string(),
            node_type: "file".to_string(),
            size: 12,
            modify_time: Some(1700000001.0),
            uid: Some("uid-bg".to_string()),
        }]),
    );
    fuse.trigger_background_dir_refresh("/", 0.0);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while fixture.db.get_node("/bg.txt").is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "Background dir refresh did not populate /bg.txt"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
