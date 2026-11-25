mod support;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use support::{generate_uuid, IpcServer, Node, SyncStatus, TestFixture};

// ============================================================================
// 1. Inode & Mount Permissions
// ============================================================================

#[test]
fn test_permission_enforcement_and_private_modes() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    // Directory node permissions: 0o700
    let dir_node = Node {
        path: "/private_dir".to_string(),
        parent_path: "/".to_string(),
        name: "private_dir".to_string(),
        node_type: "folder".to_string(),
        size: 4096,
        mtime: 1000.0,
        local_cache_path: None,
        sync_status: SyncStatus::SYNCED.to_string(),
        etag: None,
        uid: None,
        volume_id: None,
        share_id: None,
        link_id: None,
        parent_link_id: None,
        revision_id: None,
        name_hash: None,
        last_checked: None,
        cache_id: "dir-cache-id".to_string(),
        generation: 1,
        remote_exists: true,
        last_error: None,
    };
    let dir_attr = fuse.node_to_attr(10, &dir_node);
    assert_eq!(
        dir_attr.perm, 0o700,
        "Directory node attribute must advertise 0o700 permissions"
    );

    // Root directory permissions: 0o700
    let root_node = fixture.db.get_node("/").unwrap();
    let root_attr = fuse.node_to_attr(1, &root_node);
    assert_eq!(
        root_attr.perm, 0o700,
        "Root directory attribute must advertise 0o700 permissions"
    );

    // File node permissions: 0o600
    let file_node = Node {
        path: "/private_file.txt".to_string(),
        parent_path: "/".to_string(),
        name: "private_file.txt".to_string(),
        node_type: "file".to_string(),
        size: 1024,
        mtime: 1000.0,
        local_cache_path: None,
        sync_status: SyncStatus::SYNCED.to_string(),
        etag: None,
        uid: None,
        volume_id: None,
        share_id: None,
        link_id: None,
        parent_link_id: None,
        revision_id: None,
        name_hash: None,
        last_checked: None,
        cache_id: "file-cache-id".to_string(),
        generation: 1,
        remote_exists: true,
        last_error: None,
    };
    let file_attr = fuse.node_to_attr(11, &file_node);
    assert_eq!(
        file_attr.perm, 0o600,
        "File node attribute must advertise 0o600 permissions"
    );

    // Newly created file handle produces a cache file on disk with 0o600 permissions
    let fh = fuse
        .create_file_handle("/", "new_secret.txt")
        .expect("create_file_handle should succeed");
    let secret_node = fixture.db.get_node("/new_secret.txt").unwrap();
    let cache_path = PathBuf::from(secret_node.local_cache_path.as_ref().unwrap());
    let cache_meta = fs::metadata(&cache_path).expect("Cache file should exist");
    assert_eq!(
        cache_meta.permissions().mode() & 0o777,
        0o600,
        "Cache file on disk must have 0o600 permissions"
    );
    let secret_attr = fuse.node_to_attr(12, &secret_node);
    assert_eq!(
        secret_attr.perm, 0o600,
        "Created file attribute must advertise 0o600 permissions"
    );
    fuse.release_handle(fh).unwrap();

    // IPC Socket permissions: 0o600 on socket file and 0o700 on parent dir
    let ipc_server = IpcServer::new(fixture.socket_path.clone());
    ipc_server.start().expect("IPC server start should succeed");

    let sock_meta = fs::metadata(&fixture.socket_path).expect("Socket file should exist");
    assert_eq!(
        sock_meta.permissions().mode() & 0o777,
        0o600,
        "IPC socket file must have 0o600 permissions"
    );

    let parent_meta =
        fs::metadata(fixture.socket_path.parent().unwrap()).expect("Parent dir should exist");
    assert_eq!(
        parent_meta.permissions().mode() & 0o777,
        0o700,
        "Socket parent directory must have 0o700 permissions"
    );

    ipc_server.stop();
}

// ============================================================================
// 2. IPC Peer UID Verification
// ============================================================================

#[test]
fn test_ipc_peer_uid_validation_and_rejection() {
    let fixture = TestFixture::new();
    let ipc_server = IpcServer::new(fixture.socket_path.clone());
    ipc_server.register_handler("ping", |_| serde_json::json!({"status": "ok"}));
    ipc_server.start().expect("IPC server start should succeed");
    thread::sleep(Duration::from_millis(50));

    let stream = UnixStream::connect(&fixture.socket_path).expect("Connection should succeed");

    // Connected peer UID matches current effective UID
    let current_euid = unsafe { libc::geteuid() };
    let peer_uid = IpcServer::get_peer_uid(&stream).expect("get_peer_uid should succeed");
    assert_eq!(
        peer_uid, current_euid,
        "Peer UID from SO_PEERCRED must match current process EUID"
    );

    assert!(
        IpcServer::is_peer_authorized(&stream),
        "Same EUID peer must be authorized"
    );

    // Foreign UID must be rejected
    let foreign_uid = current_euid + 1000;
    assert!(
        !IpcServer::verify_peer_uid(&stream, foreign_uid),
        "Foreign UID must NOT be authorized"
    );

    ipc_server.stop();
}

// ============================================================================
// 3. IPC Framing, Payloads & Timeouts
// ============================================================================

#[test]
fn test_ipc_oversized_payload_rejection() {
    let fixture = TestFixture::new();
    let ipc_server = IpcServer::new(fixture.socket_path.clone());
    ipc_server.register_handler(
        "echo",
        |args| serde_json::json!({"status": "ok", "echoed": args}),
    );
    ipc_server.start().expect("IPC server start should succeed");
    thread::sleep(Duration::from_millis(50));

    let mut stream = UnixStream::connect(&fixture.socket_path).expect("Connection should succeed");

    // Send payload > 64 KB (65536 bytes)
    let oversized_arg = "A".repeat(70_000);
    let req = serde_json::json!({
        "command": "echo",
        "args": oversized_arg
    });
    let req_bytes = req.to_string();
    assert!(req_bytes.len() > 65536);

    let _ = stream.write_all(req_bytes.as_bytes());
    let _ = stream.flush();

    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .expect("Read should complete cleanly");

    let resp: serde_json::Value =
        serde_json::from_slice(&response_buf).expect("Response must be valid JSON");
    assert_eq!(
        resp.get("status").and_then(|v| v.as_str()),
        Some("error"),
        "Oversized payload must return status: error"
    );
    assert!(
        resp.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("exceeds maximum allowed size"),
        "Error message must specify size limit exceeded"
    );

    ipc_server.stop();
}

#[test]
fn test_ipc_malformed_json_response() {
    let fixture = TestFixture::new();
    let ipc_server = IpcServer::new(fixture.socket_path.clone());
    ipc_server.start().expect("IPC server start should succeed");
    thread::sleep(Duration::from_millis(50));

    let mut stream = UnixStream::connect(&fixture.socket_path).expect("Connection should succeed");

    // Write syntax-invalid JSON
    stream
        .write_all(b"NOT_A_VALID_JSON_STRING")
        .expect("Write should succeed");
    let _ = stream.flush();

    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .expect("Read should complete");

    let resp: serde_json::Value =
        serde_json::from_slice(&response_buf).expect("Response must be structured JSON");
    assert_eq!(
        resp.get("status").and_then(|v| v.as_str()),
        Some("error"),
        "Malformed JSON must return status: error"
    );
    assert!(
        resp.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("Invalid JSON request"),
        "Error message must indicate invalid JSON"
    );

    ipc_server.stop();
}

#[test]
fn test_ipc_partial_json_stalled_timeout() {
    let fixture = TestFixture::new();
    // Server with short 200ms timeout
    let ipc_server =
        IpcServer::new(fixture.socket_path.clone()).with_timeout(Duration::from_millis(200));
    ipc_server.start().expect("IPC server start should succeed");
    thread::sleep(Duration::from_millis(50));

    let mut stream = UnixStream::connect(&fixture.socket_path).expect("Connection should succeed");

    // Write partial JSON and stall without closing socket
    stream
        .write_all(b"{\"command\": \"ping\", \"args\":")
        .expect("Write should succeed");
    let _ = stream.flush();

    // Wait for server read timeout to fire and return structured error response
    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .expect("Read should complete after timeout");

    let resp: serde_json::Value =
        serde_json::from_slice(&response_buf).expect("Response must be structured JSON");
    assert_eq!(
        resp.get("status").and_then(|v| v.as_str()),
        Some("error"),
        "Partial JSON timeout must return status: error"
    );
    assert!(
        resp.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("partial JSON"),
        "Error message should mention partial JSON or timeout"
    );

    ipc_server.stop();
}

#[test]
fn test_ipc_stalled_connection_timeout() {
    let fixture = TestFixture::new();
    let ipc_server =
        IpcServer::new(fixture.socket_path.clone()).with_timeout(Duration::from_millis(200));
    ipc_server.start().expect("IPC server start should succeed");
    thread::sleep(Duration::from_millis(50));

    let mut stream = UnixStream::connect(&fixture.socket_path).expect("Connection should succeed");

    // Send nothing at all
    let mut buf = [0u8; 16];
    let bytes_read = stream
        .read(&mut buf)
        .expect("Read should return EOF on timeout");
    assert_eq!(
        bytes_read, 0,
        "Server must close connection on stalled client timeout"
    );

    ipc_server.stop();
}

#[test]
fn test_ipc_concurrent_connection_bounding() {
    let fixture = TestFixture::new();
    let ipc_server = IpcServer::new(fixture.socket_path.clone()).with_max_connections(2);
    ipc_server.register_handler("ping", |_| serde_json::json!({"status": "ok"}));
    ipc_server.start().expect("IPC server start should succeed");
    thread::sleep(Duration::from_millis(50));

    // Connect 2 clients to consume connection limit
    let _conn1 = UnixStream::connect(&fixture.socket_path).expect("Conn 1 should connect");
    let _conn2 = UnixStream::connect(&fixture.socket_path).expect("Conn 2 should connect");
    thread::sleep(Duration::from_millis(50));

    // Client 3 should be rejected with busy error
    let mut conn3 = UnixStream::connect(&fixture.socket_path).expect("Conn 3 should connect");
    let mut response_buf = Vec::new();
    conn3
        .read_to_end(&mut response_buf)
        .expect("Read should receive rejection");

    let resp: serde_json::Value =
        serde_json::from_slice(&response_buf).expect("Rejection must be valid JSON");
    assert_eq!(
        resp.get("status").and_then(|v| v.as_str()),
        Some("error"),
        "Connection exceeding limit must be rejected"
    );
    assert!(
        resp.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("Server busy"),
        "Rejection message must indicate server busy"
    );

    ipc_server.stop();
}

// ============================================================================
// 4. Cache Eviction Security Hardening
// ============================================================================

#[test]
fn test_evict_clean_cache_skips_open_read_and_write_handles() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    // 1. Create synced node with read handle
    let id_read = generate_uuid();
    let cache_read = fixture.cache_dir.join(format!("{}.dat", id_read));
    fs::write(&cache_read, b"read contents").unwrap();
    fs::set_permissions(&cache_read, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/read.txt",
            "/",
            "read.txt",
            "file",
            13,
            None,
            Some(&cache_read.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_read),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();
    let fh_read = fuse.open_file_handle("/read.txt", false).unwrap();

    // 2. Create synced node with write handle
    let id_write = generate_uuid();
    let cache_write = fixture.cache_dir.join(format!("{}.dat", id_write));
    fs::write(&cache_write, b"write contents").unwrap();
    fs::set_permissions(&cache_write, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/write.txt",
            "/",
            "write.txt",
            "file",
            14,
            None,
            Some(&cache_write.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_write),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();
    let fh_write = fuse.open_file_handle("/write.txt", true).unwrap();

    // 3. Create clean synced node without any handles
    let id_clean = generate_uuid();
    let cache_clean = fixture.cache_dir.join(format!("{}.dat", id_clean));
    fs::write(&cache_clean, b"clean contents").unwrap();
    fs::set_permissions(&cache_clean, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/clean.txt",
            "/",
            "clean.txt",
            "file",
            14,
            None,
            Some(&cache_clean.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_clean),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();

    // Evict clean cache
    let (evicted, skipped) = fuse.evict_clean_cache();
    assert_eq!(
        evicted, 1,
        "Only clean file without handles should be evicted"
    );
    assert_eq!(skipped, 2, "Both open handles must be skipped");

    // Clean file cache deleted and cleared in DB
    assert!(!cache_clean.exists(), "Clean cache file must be deleted");
    let clean_node = fixture.db.get_node("/clean.txt").unwrap();
    assert!(
        clean_node.local_cache_path.is_none(),
        "Clean node local_cache_path must be cleared"
    );

    // Read and write handle cache files must still exist
    assert!(
        cache_read.exists(),
        "Read handle cache file must be preserved"
    );
    assert!(
        cache_write.exists(),
        "Write handle cache file must be preserved"
    );

    fuse.release_handle(fh_read).unwrap();
    fuse.release_handle(fh_write).unwrap();
}

#[test]
fn test_evict_clean_cache_skips_inflight_and_hydrating_nodes() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let id_inflight = generate_uuid();
    let cache_inflight = fixture.cache_dir.join(format!("{}.dat", id_inflight));
    fs::write(&cache_inflight, b"inflight contents").unwrap();
    fs::set_permissions(&cache_inflight, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/inflight.txt",
            "/",
            "inflight.txt",
            "file",
            17,
            None,
            Some(&cache_inflight.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_inflight),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();

    // Mark node inflight (e.g. sync upload or download in progress)
    fixture.activity.mark_inflight(&id_inflight);

    let (evicted, skipped) = fuse.evict_clean_cache();
    assert_eq!(evicted, 0, "Inflight node must not be evicted");
    assert_eq!(skipped, 1, "Inflight node must be skipped");
    assert!(
        cache_inflight.exists(),
        "Inflight cache file must remain on disk"
    );

    fixture.activity.remove_inflight(&id_inflight);

    // Now eviction succeeds
    let (evicted2, _) = fuse.evict_clean_cache();
    assert_eq!(evicted2, 1, "Once inflight clears, eviction must succeed");
    assert!(!cache_inflight.exists(), "Cache file should now be evicted");
}

#[test]
fn test_evict_clean_cache_skips_dirty_modified_nodes() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    // Modified node (dirty)
    let id_mod = generate_uuid();
    let cache_mod = fixture.cache_dir.join(format!("{}.dat", id_mod));
    fs::write(&cache_mod, b"modified data").unwrap();
    fs::set_permissions(&cache_mod, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/modified.txt",
            "/",
            "modified.txt",
            "file",
            13,
            None,
            Some(&cache_mod.to_string_lossy()),
            Some(SyncStatus::MODIFIED),
            None,
            None,
            Some(&id_mod),
            Some(2),
            Some(true),
            None,
        )
        .unwrap();

    // Syncing node (dirty)
    let id_syncing = generate_uuid();
    let cache_syncing = fixture.cache_dir.join(format!("{}.dat", id_syncing));
    fs::write(&cache_syncing, b"syncing data").unwrap();
    fs::set_permissions(&cache_syncing, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/syncing.txt",
            "/",
            "syncing.txt",
            "file",
            12,
            None,
            Some(&cache_syncing.to_string_lossy()),
            Some(SyncStatus::SYNCING),
            None,
            None,
            Some(&id_syncing),
            Some(2),
            Some(true),
            None,
        )
        .unwrap();

    // Node without remote counterpart (remote_exists = false)
    let id_noremote = generate_uuid();
    let cache_noremote = fixture.cache_dir.join(format!("{}.dat", id_noremote));
    fs::write(&cache_noremote, b"local only").unwrap();
    fs::set_permissions(&cache_noremote, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/local_only.txt",
            "/",
            "local_only.txt",
            "file",
            10,
            None,
            Some(&cache_noremote.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_noremote),
            Some(1),
            Some(false),
            None,
        )
        .unwrap();

    let (evicted, skipped) = fuse.evict_clean_cache();
    assert_eq!(evicted, 0, "Dirty/unpushed files must never be evicted");
    assert_eq!(skipped, 3, "All 3 dirty/unpushed nodes must be skipped");

    assert!(
        cache_mod.exists(),
        "Modified cache file must not be deleted"
    );
    assert!(
        cache_syncing.exists(),
        "Syncing cache file must not be deleted"
    );
    assert!(
        cache_noremote.exists(),
        "Local-only cache file must not be deleted"
    );
}

#[test]
fn test_evict_clean_cache_skips_paths_outside_cache_and_symlinks() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    // 1. Path outside cache_dir
    let outside_path = fixture.temp_dir.path().join("outside_system_file.dat");
    fs::write(&outside_path, b"critical outside data").unwrap();
    fs::set_permissions(&outside_path, fs::Permissions::from_mode(0o600)).unwrap();

    assert!(
        !fuse.is_safe_cache_file(&outside_path),
        "File outside cache_dir must be rejected by is_safe_cache_file"
    );

    let id_outside = generate_uuid();
    fixture
        .db
        .upsert_node(
            "/outside.txt",
            "/",
            "outside.txt",
            "file",
            21,
            None,
            Some(&outside_path.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_outside),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();

    // 2. Symlink inside cache_dir pointing outside
    let symlink_outside = fixture.cache_dir.join("symlink_to_outside.dat");
    std::os::unix::fs::symlink(&outside_path, &symlink_outside).unwrap();

    assert!(
        !fuse.is_safe_cache_file(&symlink_outside),
        "Symlink inside cache_dir pointing outside must be rejected"
    );

    let id_sym_out = generate_uuid();
    fixture
        .db
        .upsert_node(
            "/sym_out.txt",
            "/",
            "sym_out.txt",
            "file",
            21,
            None,
            Some(&symlink_outside.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_sym_out),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();

    // 3. Symlink inside cache_dir pointing inside cache_dir
    let real_cache_file = fixture.cache_dir.join("real_target.dat");
    fs::write(&real_cache_file, b"real target data").unwrap();
    fs::set_permissions(&real_cache_file, fs::Permissions::from_mode(0o600)).unwrap();

    let symlink_inside = fixture.cache_dir.join("symlink_to_inside.dat");
    std::os::unix::fs::symlink(&real_cache_file, &symlink_inside).unwrap();

    assert!(
        !fuse.is_safe_cache_file(&symlink_inside),
        "Symlink pointing inside cache_dir must still be rejected"
    );

    let id_sym_in = generate_uuid();
    fixture
        .db
        .upsert_node(
            "/sym_in.txt",
            "/",
            "sym_in.txt",
            "file",
            16,
            None,
            Some(&symlink_inside.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_sym_in),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();

    // Run eviction
    let (evicted, skipped) = fuse.evict_clean_cache();
    assert_eq!(evicted, 0, "No unsafe paths or symlinks should be evicted");
    assert_eq!(skipped, 3, "All 3 unsafe paths must be skipped");

    // All files and symlinks remain untouched
    assert!(outside_path.exists(), "Outside target must not be deleted");
    assert!(
        symlink_outside.exists(),
        "Symlink to outside must not be deleted"
    );
    assert!(
        symlink_inside.exists(),
        "Symlink to inside must not be deleted"
    );
    assert!(
        real_cache_file.exists(),
        "Real cache file must not be deleted"
    );
}

#[test]
fn test_evict_clean_cache_leaves_unknown_files_untouched() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    // Create unknown file in cache_dir that is not tracked in the metadata DB
    let unknown_file = fixture.cache_dir.join("foreign_unknown_file.bin");
    fs::write(&unknown_file, b"foreign contents").unwrap();

    // Create tracked clean file
    let id_tracked = generate_uuid();
    let cache_tracked = fixture.cache_dir.join(format!("{}.dat", id_tracked));
    fs::write(&cache_tracked, b"tracked clean data").unwrap();
    fs::set_permissions(&cache_tracked, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/tracked.txt",
            "/",
            "tracked.txt",
            "file",
            18,
            None,
            Some(&cache_tracked.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_tracked),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();

    let (evicted, skipped) = fuse.evict_clean_cache();
    assert_eq!(evicted, 1, "Tracked clean file must be evicted");
    assert_eq!(skipped, 0);

    // Tracked file deleted
    assert!(
        !cache_tracked.exists(),
        "Tracked cache file must be deleted"
    );

    // Unknown foreign file is completely untouched
    assert!(
        unknown_file.exists(),
        "Unknown file in cache_dir must NEVER be deleted by cache eviction"
    );
    assert_eq!(
        fs::read(&unknown_file).unwrap(),
        b"foreign contents",
        "Unknown file content must be preserved untouched"
    );
}

#[test]
fn test_clear_cache_ipc_fails_when_unmounted_and_succeeds_when_mounted() {
    let fixture = TestFixture::new();
    let daemon = fixture.create_daemon();
    daemon.start().expect("Daemon start should succeed");
    thread::sleep(Duration::from_millis(50));

    let client = fixture.create_ipc_client();

    // 1. When drive is unmounted, clear-cache must fail with structured error
    let unmounted_resp = client
        .send_command("clear-cache", serde_json::json!({}))
        .expect("clear-cache should return structured response");
    assert_eq!(
        unmounted_resp.get("status").and_then(|v| v.as_str()),
        Some("error"),
        "clear-cache must fail when drive is not mounted"
    );
    assert_eq!(
        unmounted_resp.get("message").and_then(|v| v.as_str()),
        Some("Cannot clear cache: Drive is not mounted"),
        "Error message must specify drive is not mounted"
    );

    // 2. When active fuse is mounted, clear-cache succeeds
    let fuse = Arc::new(fixture.create_fuse());
    daemon.set_active_fuse(Some(fuse));

    let mounted_resp = client
        .send_command("clear-cache", serde_json::json!({}))
        .expect("clear-cache should succeed when mounted");
    assert_eq!(
        mounted_resp.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "clear-cache must succeed when drive is mounted"
    );
    assert!(mounted_resp.get("evicted").is_some());
    assert!(mounted_resp.get("skipped").is_some());

    daemon.stop();
}

// ============================================================================
// 5. SDK Executable Trust & Provenance Hardening
// ============================================================================

#[test]
fn test_policy_cache_eviction_enforces_ttl_and_max_size_safely() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    // 1. Two clean synced files (100 bytes each), written sequentially so old_clean has older mtime
    let id_old = generate_uuid();
    let cache_old = fixture.cache_dir.join(format!("{}.dat", id_old));
    fs::write(&cache_old, vec![b'a'; 100]).unwrap();
    fs::set_permissions(&cache_old, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/old_clean.txt",
            "/",
            "old_clean.txt",
            "file",
            100,
            None,
            Some(&cache_old.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_old),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();

    thread::sleep(Duration::from_millis(50));

    let id_new = generate_uuid();
    let cache_new = fixture.cache_dir.join(format!("{}.dat", id_new));
    fs::write(&cache_new, vec![b'b'; 100]).unwrap();
    fs::set_permissions(&cache_new, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/new_clean.txt",
            "/",
            "new_clean.txt",
            "file",
            100,
            None,
            Some(&cache_new.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_new),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();

    // 2. Protected dirty, open-handle, and inflight files (100 bytes each = 300 protected bytes)
    let id_dirty = generate_uuid();
    let cache_dirty = fixture.cache_dir.join(format!("{}.dat", id_dirty));
    fs::write(&cache_dirty, vec![b'c'; 100]).unwrap();
    fs::set_permissions(&cache_dirty, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/dirty.txt",
            "/",
            "dirty.txt",
            "file",
            100,
            None,
            Some(&cache_dirty.to_string_lossy()),
            Some(SyncStatus::MODIFIED),
            None,
            None,
            Some(&id_dirty),
            Some(2),
            Some(true),
            None,
        )
        .unwrap();

    let id_open = generate_uuid();
    let cache_open = fixture.cache_dir.join(format!("{}.dat", id_open));
    fs::write(&cache_open, vec![b'd'; 100]).unwrap();
    fs::set_permissions(&cache_open, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/open.txt",
            "/",
            "open.txt",
            "file",
            100,
            None,
            Some(&cache_open.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_open),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();
    let fh_open = fuse.open_file_handle("/open.txt", false).unwrap();

    let id_inflight = generate_uuid();
    let cache_inflight = fixture.cache_dir.join(format!("{}.dat", id_inflight));
    fs::write(&cache_inflight, vec![b'e'; 100]).unwrap();
    fs::set_permissions(&cache_inflight, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
        .db
        .upsert_node(
            "/inflight.txt",
            "/",
            "inflight.txt",
            "file",
            100,
            None,
            Some(&cache_inflight.to_string_lossy()),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(&id_inflight),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();
    fixture.activity.mark_inflight(&id_inflight);

    // Total on disk = 500 bytes. Max size = 420 bytes should evict only the oldest clean file.
    let (evicted, skipped) = fuse.evict_cache_by_policy(420, None);
    assert_eq!(evicted, 1, "Only oldest clean file should be evicted");
    assert_eq!(
        skipped, 3,
        "Dirty, open, and inflight files must be skipped"
    );
    assert!(!cache_old.exists());
    assert!(cache_new.exists());
    assert!(cache_dirty.exists());
    assert!(cache_open.exists());
    assert!(cache_inflight.exists());

    // Wait briefly so new_clean exceeds a 10ms TTL, while protected files remain safe
    thread::sleep(Duration::from_millis(30));
    let (evicted_ttl, skipped_ttl) = fuse.evict_cache_by_policy(0, Some(Duration::from_millis(10)));
    assert_eq!(
        evicted_ttl, 1,
        "Remaining clean file past TTL must be evicted"
    );
    assert_eq!(skipped_ttl, 3, "Protected files must survive TTL eviction");
    assert!(!cache_new.exists());
    assert!(cache_dirty.exists());
    assert!(cache_open.exists());
    assert!(cache_inflight.exists());

    fixture.activity.remove_inflight(&id_inflight);
    fuse.release_handle(fh_open).unwrap();

    // Verify statfs reflects StorageQuota
    fixture
        .fake_remote
        .set_storage_quota(neutron_drive_daemon::client::StorageQuota {
            used_bytes: 4096 * 10,
            total_bytes: 4096 * 100,
            percent_used: 10.0,
        });
    let (blocks, bfree, bavail, _files, _ffree, bsize, _namelen, _frsize) = fuse.compute_statfs();
    assert_eq!(blocks, 100);
    assert_eq!(bfree, 90);
    assert_eq!(bavail, 90);
    assert_eq!(bsize, 4096);
}

#[test]
fn test_install_sh_native_destdir_and_legacy_cli_cleanup() {
    let temp_dir = tempfile::tempdir().expect("tempdir creation");
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let install_script = repo_root.join("install.sh");
    let release_daemon =
        repo_root.join("crates/proton-drive-daemon/target/release/neutron-drive-daemon");
    let release_gui = repo_root.join("build/neutron-drive-gui");

    if install_script.exists() && release_daemon.exists() && release_gui.exists() {
        let destdir = temp_dir.path().join("destdir_native");
        // Seed a stale legacy CLI binary to verify install.sh removes it on install/upgrade
        let legacy_cli_path = destdir.join("usr/local/bin/proton-drive");
        fs::create_dir_all(legacy_cli_path.parent().unwrap()).unwrap();
        fs::write(&legacy_cli_path, b"legacy-cli").unwrap();

        let out = std::process::Command::new(&install_script)
            .env("DESTDIR", &destdir)
            .args(["--prefix", "/usr/local"])
            .output()
            .expect("Failed to run install.sh");
        assert!(
            out.status.success(),
            "install.sh must succeed without bundled CLI binary; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(destdir.join("usr/local/bin/neutron-drive-daemon").exists());
        assert!(destdir.join("usr/local/bin/neutron-drive-gui").exists());
        assert!(destdir.join("usr/local/bin/neutron-drive").exists());
        assert!(
            !legacy_cli_path.exists(),
            "Legacy proton-drive CLI binary must be cleaned up on native install/upgrade"
        );
        assert!(destdir
            .join("usr/local/share/applications/neutron-drive.desktop")
            .exists());
        assert!(destdir
            .join("usr/local/share/systemd/user/neutron-drive.service")
            .exists());
    }
}

#[test]
fn test_install_sh_uninstall_removes_launch_artifacts_and_preserves_user_data() {
    let temp_dir = tempfile::tempdir().expect("tempdir creation");
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let install_script = repo_root.join("install.sh");
    let prefix = temp_dir.path().join("prefix");
    let xdg_config = temp_dir.path().join("config");
    let xdg_data = temp_dir.path().join("data");

    let installed_binary = prefix.join("bin/neutron-drive");
    let installed_desktop = prefix.join("share/applications/neutron-drive.desktop");
    let installed_service = prefix.join("share/systemd/user/neutron-drive.service");
    let autostart_entry = xdg_config.join("autostart/neutron-drive.desktop");
    let saved_config = xdg_config.join("neutron-drive/config.json");
    let saved_database = xdg_data.join("neutron-drive/metadata.db");

    for path in [
        &installed_binary,
        &installed_desktop,
        &installed_service,
        &autostart_entry,
        &saved_config,
        &saved_database,
    ] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"test-data").unwrap();
    }

    let out = std::process::Command::new(&install_script)
        .env("HOME", temp_dir.path().join("home"))
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_DATA_HOME", &xdg_data)
        .args(["--uninstall", "--prefix"])
        .arg(&prefix)
        .output()
        .expect("Failed to run install.sh --uninstall");

    assert!(
        out.status.success(),
        "uninstall must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!installed_binary.exists());
    assert!(!installed_desktop.exists());
    assert!(!installed_service.exists());
    assert!(
        !autostart_entry.exists(),
        "uninstall must remove Neutron Drive's XDG autostart entry"
    );
    assert!(
        saved_config.exists(),
        "uninstall must preserve user configuration"
    );
    assert!(
        saved_database.exists(),
        "uninstall must preserve local metadata"
    );
}

#[test]
fn test_install_sh_check_is_read_only_and_reports_a_preflight_summary() {
    let temp_dir = tempfile::tempdir().expect("tempdir creation");
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let install_script = repo_root.join("install.sh");
    let prefix = temp_dir.path().join("prefix");

    let out = std::process::Command::new(&install_script)
        .env("HOME", temp_dir.path().join("home"))
        .env("XDG_CONFIG_HOME", temp_dir.path().join("config"))
        .env("XDG_DATA_HOME", temp_dir.path().join("data"))
        .args(["--check", "--prefix"])
        .arg(&prefix)
        .output()
        .expect("Failed to run install.sh --check");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Neutron Drive installation preflight"),
        "--check must print a preflight summary; stdout: {stdout}"
    );
    assert!(
        !prefix.exists(),
        "--check must not create the installation prefix"
    );
}
