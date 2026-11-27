mod support;

use std::fs;
use std::thread;
use std::time::Duration;

use neutron_drive_daemon::client::RemoteNode;
use serde_json::json;
use support::{
    load_config_from, save_config_to, Config, ProtonDriveDaemon, SyncStatus, TestFixture,
};

#[test]
fn test_daemon_startup_and_graceful_stop() {
    let fixture = TestFixture::new();
    let daemon = fixture.create_daemon();

    daemon.start().expect("Daemon start failed");
    assert!(
        daemon.is_running(),
        "Daemon should report running after start"
    );
    assert!(
        fixture.socket_path.exists(),
        "Socket file must exist after start"
    );

    let client = fixture.create_ipc_client();
    assert!(
        client.is_daemon_running(),
        "IpcClient should ping daemon successfully"
    );

    let resp = client
        .send_command("stop", json!({}))
        .expect("Stop command should succeed");
    assert_eq!(
        resp.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "Stop status must be 'ok'"
    );
    assert_eq!(
        resp.get("message").and_then(|v| v.as_str()),
        Some("Stopping daemon"),
        "Stop response must indicate 'Stopping daemon'"
    );

    // Verify daemon terminates and socket is removed within bounded timeout (5 seconds)
    let mut terminated = false;
    for _ in 0..50 {
        thread::sleep(Duration::from_millis(100));
        if !daemon.is_running() && !fixture.socket_path.exists() {
            terminated = true;
            break;
        }
    }
    assert!(
        terminated,
        "Daemon failed to shut down and remove socket within 5 seconds"
    );
    assert!(
        !client.is_daemon_running(),
        "IpcClient ping must fail after daemon stop"
    );
}

#[test]
fn test_daemon_get_config_returns_persisted_default_config() {
    let fixture = TestFixture::new();
    assert!(
        !fixture.config_path.exists(),
        "Config file should not exist before daemon initialization"
    );

    let daemon = fixture.create_daemon();
    assert!(
        fixture.config_path.exists(),
        "Daemon creation should persist the default config to config_path"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&fixture.config_path).expect("Failed to get config metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "Config file must have 0o600 permissions"
        );
        let parent_meta = fs::metadata(fixture.config_path.parent().unwrap())
            .expect("Failed to get parent metadata");
        assert_eq!(
            parent_meta.permissions().mode() & 0o777,
            0o700,
            "Config parent directory must have 0o700 permissions"
        );
    }

    daemon.start().expect("Daemon start failed");
    let client = fixture.create_ipc_client();

    let resp = client
        .send_command("get-config", json!({}))
        .expect("get-config should return successfully");
    assert_eq!(
        resp.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "get-config status must be 'ok'"
    );

    let config_val = resp.get("config").expect("missing config object");
    assert_eq!(
        config_val.get("mount_point").and_then(|v| v.as_str()),
        Some(fixture.mount_dir.to_str().unwrap())
    );
    assert_eq!(
        config_val
            .get("auto_mount_on_start")
            .and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        config_val.get("start_at_login").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        config_val.get("cache_max_size_mb").and_then(|v| v.as_u64()),
        Some(5120)
    );
    assert_eq!(
        config_val.get("cache_ttl_hours").and_then(|v| v.as_u64()),
        Some(72)
    );
    assert_eq!(
        config_val
            .get("event_poll_interval_sec")
            .and_then(|v| v.as_u64()),
        Some(10)
    );
    assert_eq!(
        config_val.get("offline_mode").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        config_val.get("sync_paused").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        config_val.get("backend").and_then(|v| v.as_str()),
        Some("native")
    );

    let on_disk = load_config_from(&fixture.config_path);
    assert_eq!(on_disk.mount_point, fixture.mount_dir.to_string_lossy());
    assert!(!on_disk.auto_mount_on_start);
    assert_eq!(on_disk.backend, "native");

    daemon.stop();
}

#[test]
fn test_daemon_update_config_persists_and_survives_restart() {
    let fixture = TestFixture::new();
    let daemon = fixture.create_daemon();
    daemon.start().expect("Daemon start failed");

    let client = fixture.create_ipc_client();
    let new_mount_dir = fixture.root_path().join("updated_mount_dir");

    let update_payload = json!({
        "auto_mount_on_start": true,
        "start_at_login": false,
        "mount_point": new_mount_dir.to_string_lossy().to_string(),
        "event_poll_interval_sec": 25,
        "cache_max_size_mb": 8192,
        "cache_ttl_hours": 36,
        "offline_mode": true,
        "sync_paused": true,
    });

    let resp = client
        .send_command("update-config", update_payload)
        .expect("update-config should succeed");
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("ok"));

    let updated_cfg = resp
        .get("config")
        .expect("missing config in update response");
    assert_eq!(
        updated_cfg
            .get("auto_mount_on_start")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        updated_cfg.get("start_at_login").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        updated_cfg.get("mount_point").and_then(|v| v.as_str()),
        Some(new_mount_dir.to_str().unwrap())
    );
    assert_eq!(
        updated_cfg
            .get("event_poll_interval_sec")
            .and_then(|v| v.as_u64()),
        Some(25)
    );
    assert_eq!(
        updated_cfg
            .get("cache_max_size_mb")
            .and_then(|v| v.as_u64()),
        Some(8192)
    );
    assert_eq!(
        updated_cfg.get("cache_ttl_hours").and_then(|v| v.as_u64()),
        Some(36)
    );
    assert_eq!(
        updated_cfg.get("offline_mode").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        updated_cfg.get("sync_paused").and_then(|v| v.as_bool()),
        Some(true)
    );

    // Verify written atomically to disk
    let on_disk = load_config_from(&fixture.config_path);
    assert!(on_disk.auto_mount_on_start);
    assert!(!on_disk.start_at_login);
    assert_eq!(on_disk.mount_point, new_mount_dir.to_string_lossy());
    assert_eq!(on_disk.event_poll_interval_sec, 25);
    assert_eq!(on_disk.cache_max_size_mb, 8192);
    assert_eq!(on_disk.cache_ttl_hours, 36);
    assert!(on_disk.offline_mode);
    assert!(on_disk.sync_paused);

    // Stop first daemon instance
    let stop_resp = client.send_command("stop", json!({})).unwrap();
    assert_eq!(stop_resp.get("status").and_then(|v| v.as_str()), Some("ok"));

    let mut stopped = false;
    for _ in 0..50 {
        thread::sleep(Duration::from_millis(100));
        if !fixture.socket_path.exists() {
            stopped = true;
            break;
        }
    }
    assert!(stopped, "First daemon instance failed to stop");

    // Start a new daemon instance using the same isolated fixture
    let daemon2 = fixture.create_daemon();
    daemon2.start().expect("Second daemon start failed");

    let resp2 = client
        .send_command("get-config", json!({}))
        .expect("get-config on restarted daemon should succeed");
    assert_eq!(resp2.get("status").and_then(|v| v.as_str()), Some("ok"));
    let cfg2 = resp2.get("config").expect("missing config object");

    assert_eq!(
        cfg2.get("auto_mount_on_start").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        cfg2.get("start_at_login").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        cfg2.get("mount_point").and_then(|v| v.as_str()),
        Some(new_mount_dir.to_str().unwrap())
    );
    assert_eq!(
        cfg2.get("event_poll_interval_sec").and_then(|v| v.as_u64()),
        Some(25)
    );
    assert_eq!(
        cfg2.get("cache_max_size_mb").and_then(|v| v.as_u64()),
        Some(8192)
    );
    assert_eq!(
        cfg2.get("offline_mode").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        cfg2.get("sync_paused").and_then(|v| v.as_bool()),
        Some(true)
    );

    daemon2.stop();
}

#[test]
fn test_invalid_config_update_returns_error_response() {
    let fixture = TestFixture::new();
    let daemon = fixture.create_daemon();
    daemon.start().expect("Daemon start failed");

    let client = fixture.create_ipc_client();
    let initial_config = daemon.config();

    // 1. Empty mount_point
    let resp = client
        .send_command("update-config", json!({"mount_point": ""}))
        .unwrap();
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("error"));
    assert!(
        resp.get("message")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("cannot be empty"),
        "Message should report empty mount_point"
    );

    // 2. Whitespace-only mount_point
    let resp = client
        .send_command("update-config", json!({"mount_point": "   "}))
        .unwrap();
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("error"));

    // 3. Non-string mount_point
    let resp = client
        .send_command("update-config", json!({"mount_point": 9999}))
        .unwrap();
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("error"));

    // 4. Invalid boolean type
    let resp = client
        .send_command("update-config", json!({"auto_mount_on_start": "true"}))
        .unwrap();
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("error"));

    // 5. Zero event_poll_interval_sec
    let resp = client
        .send_command("update-config", json!({"event_poll_interval_sec": 0}))
        .unwrap();
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("error"));

    // 6. Unknown configuration field
    let resp = client
        .send_command("update-config", json!({"unrecognized_option": 123}))
        .unwrap();
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("error"));
    assert!(
        resp.get("message")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("Unknown configuration field"),
        "Message should reject unknown field"
    );

    // 7. Non-object payload
    let resp = client
        .send_command("update-config", json!("just a string"))
        .unwrap();
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("error"));

    // Ensure state was not mutated by any failed updates
    assert_eq!(daemon.config(), initial_config);
    assert_eq!(load_config_from(&fixture.config_path), initial_config);

    daemon.stop();
}

#[test]
fn test_cli_stop_contract_verified_against_running_daemon() {
    let fixture = TestFixture::new();
    let runtime_dir = fixture.root_path().join("runtime");
    fs::create_dir_all(&runtime_dir).expect("Failed to create isolated runtime directory");
    let socket_path = runtime_dir.join("neutron-drive.sock");

    let config = Config {
        mount_point: fixture.mount_dir.to_string_lossy().to_string(),
        auto_mount_on_start: false,
        ..Default::default()
    };

    let daemon = ProtonDriveDaemon::new_with_deps(
        fixture.remote_client(),
        fixture.db.clone(),
        config,
        fixture.cache_dir.clone(),
        socket_path.clone(),
        fixture.config_path.clone(),
    )
    .expect("Failed to create daemon for CLI stop test");

    daemon.start().expect("Daemon start failed");
    assert!(socket_path.exists(), "Socket must exist before CLI stop");
    assert!(
        daemon.is_running(),
        "Daemon must be running before CLI stop"
    );

    let bin_path = env!("CARGO_BIN_EXE_neutron-drive-daemon");

    // Execute `neutron-drive-daemon stop`
    let output = std::process::Command::new(bin_path)
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .arg("stop")
        .output()
        .expect("Failed to run 'neutron-drive-daemon stop'");

    assert!(
        output.status.success(),
        "CLI stop process exited with error status: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Neutron Drive daemon stopped."),
        "CLI output must contain success message. Actual stdout: {}",
        stdout
    );

    assert!(
        !socket_path.exists(),
        "Socket file must be removed after CLI stop completes"
    );
    assert!(
        !daemon.is_running(),
        "Daemon must report not running after CLI stop"
    );

    // Running stop again on a stopped daemon should output 'daemon is not running' and exit successfully
    let output2 = std::process::Command::new(bin_path)
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .arg("stop")
        .output()
        .expect("Failed to run 'neutron-drive-daemon stop' second time");

    assert!(output2.status.success());
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        stdout2.contains("Neutron Drive daemon is not running."),
        "CLI output must state daemon is not running. Actual stdout: {}",
        stdout2
    );
}

#[test]
fn test_daemon_update_config_partial_and_nested_payload() {
    let fixture = TestFixture::new();
    let daemon = fixture.create_daemon();
    daemon.start().expect("Daemon start failed");

    let client = fixture.create_ipc_client();

    // Partial update 1: sync_paused
    let resp1 = client
        .send_command("update-config", json!({"sync_paused": true}))
        .unwrap();
    assert_eq!(resp1.get("status").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(
        resp1["config"].get("sync_paused").and_then(|v| v.as_bool()),
        Some(true)
    );

    // Partial update 2: nested under "config" key
    let resp2 = client
        .send_command(
            "update-config",
            json!({
                "config": {
                    "event_poll_interval_sec": 30
                }
            }),
        )
        .unwrap();
    assert_eq!(resp2.get("status").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(
        resp2["config"]
            .get("event_poll_interval_sec")
            .and_then(|v| v.as_u64()),
        Some(30)
    );
    assert_eq!(
        resp2["config"].get("sync_paused").and_then(|v| v.as_bool()),
        Some(true)
    );

    daemon.stop();
}

#[test]
fn test_daemon_enforces_runtime_config_and_autostart() {
    let fixture = TestFixture::new();
    let daemon = fixture.create_daemon();
    daemon.start().expect("Daemon start failed");

    let client = fixture.create_ipc_client();

    let resp = client
        .send_command(
            "update-config",
            json!({
                "offline_mode": true,
                "event_poll_interval_sec": 15,
                "cache_max_size_mb": 256,
                "cache_ttl_hours": 12,
                "start_at_login": true
            }),
        )
        .expect("update-config should succeed");
    assert_eq!(resp.get("status").and_then(|v| v.as_str()), Some("ok"));

    let autostart_path =
        neutron_drive_daemon::config::autostart_file_for_config(&fixture.config_path);
    assert!(
        autostart_path.exists(),
        "Isolated autostart desktop file must be created at {:?}",
        autostart_path
    );

    let status_resp = client
        .send_command("status", json!({}))
        .expect("status command should succeed");
    assert_eq!(
        status_resp.get("status").and_then(|v| v.as_str()),
        Some("ok")
    );
    assert_eq!(
        status_resp.get("offline_mode").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        status_resp.get("pending_uploads").and_then(|v| v.as_u64()),
        Some(0)
    );
    assert_eq!(
        status_resp.get("error_count").and_then(|v| v.as_u64()),
        Some(0)
    );

    let resp_disable = client
        .send_command(
            "update-config",
            json!({
                "offline_mode": false,
                "start_at_login": false
            }),
        )
        .expect("second update-config should succeed");
    assert_eq!(
        resp_disable.get("status").and_then(|v| v.as_str()),
        Some("ok")
    );
    assert!(
        !autostart_path.exists(),
        "Isolated autostart desktop file must be removed when start_at_login=false"
    );

    let status_after = client
        .send_command("status", json!({}))
        .expect("status after update should succeed");
    assert_eq!(
        status_after.get("offline_mode").and_then(|v| v.as_bool()),
        Some(false)
    );

    let login_resp = client
        .send_command("login", json!({}))
        .expect("login IPC should return valid JSON response");
    assert_eq!(
        login_resp.get("status").and_then(|v| v.as_str()),
        Some("ok")
    );

    daemon.stop();
}

#[test]
fn test_daemon_sigterm_triggers_clean_shutdown_and_removes_socket() {
    let fixture = TestFixture::new();
    let root = fixture.root_path();
    let runtime_dir = root.join("sigterm_runtime");
    let config_dir = root.join("sigterm_config");
    let data_dir = root.join("sigterm_data");
    let cache_dir = root.join("sigterm_cache");
    let mount_dir = root.join("sigterm_mount");

    fs::create_dir_all(&runtime_dir).unwrap();
    fs::create_dir_all(config_dir.join("neutron-drive")).unwrap();
    fs::create_dir_all(&data_dir).unwrap();
    fs::create_dir_all(&cache_dir).unwrap();
    fs::create_dir_all(&mount_dir).unwrap();

    let cfg = Config {
        mount_point: mount_dir.to_string_lossy().to_string(),
        auto_mount_on_start: false,
        start_at_login: false,
        ..Default::default()
    };
    save_config_to(&cfg, &config_dir.join("neutron-drive").join("config.json")).unwrap();

    let socket_path = runtime_dir.join("neutron-drive.sock");
    let bin_path = env!("CARGO_BIN_EXE_neutron-drive-daemon");

    let mut child = std::process::Command::new(bin_path)
        .env("HOME", root)
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env("XDG_CONFIG_HOME", &config_dir)
        .env("XDG_DATA_HOME", &data_dir)
        .env("XDG_CACHE_HOME", &cache_dir)
        .arg("daemon")
        .spawn()
        .expect("Failed to spawn neutron-drive-daemon");

    let isolated_ipc = support::IpcClient::new(Some(socket_path.clone()));
    let mut ready = false;
    for _ in 0..50 {
        if socket_path.exists() && isolated_ipc.is_daemon_running() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("Daemon did not become ready on isolated socket");
    }

    let kill_rc = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(kill_rc, 0, "Sending SIGTERM to daemon must succeed");

    let mut exit_status = None;
    for _ in 0..50 {
        if let Some(st) = child.try_wait().expect("try_wait failed") {
            exit_status = Some(st);
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let status = match exit_status {
        Some(st) => st,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("Daemon did not exit within 5 seconds after SIGTERM");
        }
    };

    assert!(
        status.success(),
        "Daemon should exit cleanly (status 0) on SIGTERM, got: {:?}",
        status
    );
    assert!(
        !socket_path.exists(),
        "IPC socket must be cleaned up on SIGTERM shutdown"
    );
}

#[test]
fn test_daemon_upgrades_legacy_cli_config_to_native_and_rejects_cli_update() {
    use neutron_drive_daemon::config::load_config_from;

    let fixture = TestFixture::new();
    std::fs::write(
        &fixture.config_path,
        format!(
            r#"{{"mount_point":"{}","auto_mount_on_start":false,"backend":"cli"}}"#,
            fixture.mount_dir.to_string_lossy()
        ),
    )
    .unwrap();

    let migrated = load_config_from(&fixture.config_path);
    assert_eq!(migrated.backend, "native");

    let daemon = fixture.create_daemon();
    daemon.start().unwrap();
    let ipc = fixture.create_ipc_client();

    let bad = ipc
        .send_command("update-config", json!({"backend": "cli"}))
        .unwrap();
    assert_eq!(bad.get("status").and_then(|v| v.as_str()), Some("error"));
    let msg = bad.get("message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg.contains("retired") || msg.contains("native"),
        "Expected retired CLI backend error, got: {}",
        msg
    );

    daemon.stop();
}

#[test]
fn test_daemon_retry_errors_and_clear_errors_ipc() {
    use neutron_drive_daemon::metadata_db::SyncStatus;

    let fixture = TestFixture::new();
    let daemon = fixture.create_daemon();
    daemon.start().unwrap();
    let ipc = fixture.create_ipc_client();

    // Pause sync and wait for any in-flight startup cycle to finish so the
    // background thread cannot race with test fixtures or assertions.
    ipc.send_command("pause", json!({})).unwrap();
    assert!(
        daemon.sync_engine().wait_until_idle(Duration::from_secs(5)),
        "Sync engine did not become idle after pause"
    );

    let local_dirty = fixture.cache_dir.join("dirty.bin");
    fs::write(&local_dirty, b"important data").unwrap();

    daemon
        .db()
        .upsert_node(
            "/dirty.bin",
            "/",
            "dirty.bin",
            "file",
            14,
            None,
            Some(local_dirty.to_str().unwrap()),
            Some(SyncStatus::ERROR),
            None,
            None,
            None,
            None,
            Some(false),
            Some("upload failed"),
        )
        .unwrap();

    daemon
        .db()
        .upsert_node(
            "/stale.bin",
            "/",
            "stale.bin",
            "file",
            10,
            None,
            None,
            Some(SyncStatus::ERROR),
            None,
            None,
            None,
            None,
            Some(true),
            Some("stale error"),
        )
        .unwrap();

    let st1 = ipc.send_command("status", json!({})).unwrap();
    assert_eq!(st1.get("error_count").and_then(|v| v.as_u64()), Some(2));
    assert!(st1.get("last_error").and_then(|v| v.as_str()).is_some());

    let retry_resp = ipc.send_command("retry-errors", json!({})).unwrap();
    assert_eq!(
        retry_resp.get("status").and_then(|v| v.as_str()),
        Some("ok")
    );
    assert_eq!(retry_resp.get("retried").and_then(|v| v.as_u64()), Some(2));

    let st2 = ipc.send_command("status", json!({})).unwrap();
    assert_eq!(st2.get("error_count").and_then(|v| v.as_u64()), Some(0));
    assert!(st2.get("last_error").unwrap().is_null());

    // Re-mark error and verify clear-errors safely clears stale and re-queues dirty
    daemon
        .db()
        .update_sync_status("/dirty.bin", SyncStatus::ERROR, None, Some("err1"));
    daemon
        .db()
        .update_sync_status("/stale.bin", SyncStatus::ERROR, None, Some("err2"));

    let clear_resp = ipc.send_command("clear-errors", json!({})).unwrap();
    assert_eq!(
        clear_resp.get("status").and_then(|v| v.as_str()),
        Some("ok")
    );
    assert_eq!(clear_resp.get("cleared").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(clear_resp.get("requeued").and_then(|v| v.as_u64()), Some(1));

    let st3 = ipc.send_command("status", json!({})).unwrap();
    assert_eq!(st3.get("error_count").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(
        daemon.db().get_node("/dirty.bin").unwrap().sync_status,
        SyncStatus::MODIFIED
    );
    assert_eq!(
        daemon.db().get_node("/stale.bin").unwrap().sync_status,
        SyncStatus::CLOUD_ONLY
    );

    daemon.stop();
}

#[test]
fn test_pause_during_active_poll_stops_upload_and_preserves_paused_status() {
    use std::path::Path;
    use std::sync::{mpsc, Arc, Mutex};
    use support::{FakeRemoteDrive, RemoteDrive, RemoteNode, StorageQuota, SyncStatus};

    struct BlockingPollClient {
        inner: FakeRemoteDrive,
        entered_poll_tx: Mutex<Option<mpsc::Sender<()>>>,
        release_poll_rx: Mutex<Option<mpsc::Receiver<()>>>,
    }

    impl RemoteDrive for BlockingPollClient {
        fn check_auth_status(&self) -> (bool, String) {
            self.inner.check_auth_status()
        }
        fn logout(&self) -> bool {
            self.inner.logout()
        }
        fn list_path(&self, remote_path: &str) -> Result<Vec<RemoteNode>, String> {
            if let Some(tx) = self.entered_poll_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            if let Some(rx) = self.release_poll_rx.lock().unwrap().take() {
                let _ = rx.recv_timeout(Duration::from_secs(5));
            }
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

    let fixture = TestFixture::new();
    let local_dirty = fixture.cache_dir.join("pending.bin");
    fs::write(&local_dirty, b"queued while polling").unwrap();
    fixture
        .db
        .upsert_node(
            "/pending.bin",
            "/",
            "pending.bin",
            "file",
            20,
            None,
            Some(local_dirty.to_str().unwrap()),
            Some(SyncStatus::ERROR),
            None,
            None,
            None,
            None,
            Some(false),
            Some("prior error"),
        )
        .unwrap();

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let client = Arc::new(BlockingPollClient {
        inner: fixture.fake_remote.clone(),
        entered_poll_tx: Mutex::new(Some(entered_tx)),
        release_poll_rx: Mutex::new(Some(release_rx)),
    });

    let cfg = Config {
        mount_point: fixture.mount_dir.to_string_lossy().to_string(),
        auto_mount_on_start: false,
        ..Default::default()
    };
    let daemon = ProtonDriveDaemon::new_with_deps_and_activity(
        client,
        fixture.db.clone(),
        cfg,
        fixture.cache_dir.clone(),
        fixture.socket_path.clone(),
        fixture.config_path.clone(),
        std::sync::Arc::clone(&fixture.activity),
    )
    .unwrap();

    daemon.start().unwrap();
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("Sync engine should enter list_path during startup cycle");

    let ipc = fixture.create_ipc_client();
    let pause_resp = ipc.send_command("pause", json!({})).unwrap();
    assert_eq!(
        pause_resp.get("status").and_then(|v| v.as_str()),
        Some("ok")
    );

    release_tx.send(()).unwrap();
    assert!(
        daemon.sync_engine().wait_until_idle(Duration::from_secs(5)),
        "Sync engine should become idle after releasing poll"
    );

    let st = ipc.send_command("status", json!({})).unwrap();
    assert_eq!(
        st.get("sync_status").and_then(|v| v.as_str()),
        Some("paused")
    );
    assert_eq!(st.get("is_paused").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(st.get("error_count").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(fixture.fake_remote.upload_calls().len(), 0);

    daemon.stop();
}

#[test]
fn test_ipc_pin_unpin_and_list_pinned_paths() {
    let fixture = TestFixture::new();
    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![RemoteNode {
            name: "Docs".to_string(),
            node_type: "folder".to_string(),
            size: 0,
            modify_time: Some(1000.0),
            uid: Some("docs-uid".to_string()),
        }]),
    );
    fixture.fake_remote.set_list_result(
        "/my-files/Docs",
        Ok(vec![RemoteNode {
            name: "spec.md".to_string(),
            node_type: "file".to_string(),
            size: 128,
            modify_time: Some(1000.0),
            uid: Some("spec-uid".to_string()),
        }]),
    );
    fixture
        .db
        .upsert_node(
            "/Docs",
            "/",
            "Docs",
            "folder",
            0,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("docs-cid"),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();
    fixture
        .db
        .upsert_node(
            "/Docs/spec.md",
            "/Docs",
            "spec.md",
            "file",
            128,
            None,
            None,
            Some(SyncStatus::CLOUD_ONLY),
            None,
            None,
            Some("spec-cid"),
            Some(1),
            Some(true),
            None,
        )
        .unwrap();

    let daemon = fixture.create_daemon();
    daemon.start().expect("Daemon start failed");
    let ipc = fixture.create_ipc_client();

    // Pin using local mount-point prefixed path
    let mount_prefixed = fixture.mount_dir.join("Docs/spec.md");
    let pin_resp = ipc
        .send_command("pin", json!({ "path": mount_prefixed }))
        .unwrap();
    assert_eq!(pin_resp["status"], "ok");
    assert_eq!(pin_resp["path"], "/Docs/spec.md");
    assert_eq!(pin_resp["pinned"], true);

    let list_resp = ipc.send_command("pinned", json!({})).unwrap();
    assert_eq!(list_resp["status"], "ok");
    assert_eq!(list_resp["count"], 1);
    assert_eq!(list_resp["paths"], json!(["/Docs/spec.md"]));

    let status_resp = ipc.send_command("status", json!({})).unwrap();
    assert_eq!(status_resp["pinned_count"], 1);

    // Missing path returns error
    let missing_resp = ipc
        .send_command("pin", json!({ "path": "/Docs/missing.md" }))
        .unwrap();
    assert_eq!(missing_resp["status"], "error");

    // Traversal segment is rejected
    let trav_resp = ipc
        .send_command("pin", json!({ "path": "/Docs/../etc/passwd" }))
        .unwrap();
    assert_eq!(trav_resp["status"], "error");

    // Unpin clears pinned state
    let unpin_resp = ipc
        .send_command("unpin", json!({ "path": "/Docs/spec.md" }))
        .unwrap();
    assert_eq!(unpin_resp["status"], "ok");
    assert_eq!(unpin_resp["pinned"], false);

    let list_after = ipc.send_command("pinned", json!({})).unwrap();
    assert_eq!(list_after["count"], 0);
    assert_eq!(list_after["paths"], json!([]));

    daemon.stop();
}

#[test]
fn test_ipc_list_errors_resolve_conflict_and_restore_trash() {
    let fixture = TestFixture::new();
    fixture.fake_remote.set_list_result(
        "/my-files",
        Ok(vec![
            RemoteNode {
                name: "keep_local.txt".to_string(),
                node_type: "file".to_string(),
                size: 11,
                modify_time: Some(1000.0),
                uid: Some("kl-uid".to_string()),
            },
            RemoteNode {
                name: "keep_remote.txt".to_string(),
                node_type: "file".to_string(),
                size: 11,
                modify_time: Some(1000.0),
                uid: Some("kr-uid".to_string()),
            },
            RemoteNode {
                name: "keep_both.txt".to_string(),
                node_type: "file".to_string(),
                size: 14,
                modify_time: Some(1000.0),
                uid: Some("kb-uid".to_string()),
            },
        ]),
    );

    let cache_kl = fixture.cache_dir.join("kl-cid.dat");
    let cache_kr = fixture.cache_dir.join("kr-cid.dat");
    let cache_kb = fixture.cache_dir.join("kb-cid.dat");
    let cache_lo = fixture.cache_dir.join("lo-cid.dat");
    fs::write(&cache_kl, b"local-edits").unwrap();
    fs::write(&cache_kr, b"stale-local").unwrap();
    fs::write(&cache_kb, b"conflict-bytes").unwrap();
    fs::write(&cache_lo, b"only-local-bytes").unwrap();

    for (path, name, size, cache_p, cid, remote_exists, err) in [
        (
            "/keep_local.txt",
            "keep_local.txt",
            11,
            &cache_kl,
            "kl-cid",
            true,
            "upload conflict",
        ),
        (
            "/keep_remote.txt",
            "keep_remote.txt",
            11,
            &cache_kr,
            "kr-cid",
            true,
            "upload conflict",
        ),
        (
            "/keep_both.txt",
            "keep_both.txt",
            14,
            &cache_kb,
            "kb-cid",
            true,
            "upload conflict",
        ),
        (
            "/local_only_err.txt",
            "local_only_err.txt",
            16,
            &cache_lo,
            "lo-cid",
            false,
            "network timeout",
        ),
    ] {
        fixture
            .db
            .upsert_node(
                path,
                "/",
                name,
                "file",
                size,
                None,
                Some(&cache_p.to_string_lossy()),
                Some(SyncStatus::ERROR),
                None,
                None,
                Some(cid),
                Some(1),
                Some(remote_exists),
                Some(err),
            )
            .unwrap();
    }

    let daemon = fixture.create_daemon_with_config(Config {
        mount_point: fixture.mount_dir.to_string_lossy().to_string(),
        auto_mount_on_start: false,
        sync_paused: true,
        ..Default::default()
    });
    daemon.start().expect("Daemon start failed");
    let ipc = fixture.create_ipc_client();

    let errors_resp = ipc.send_command("list-errors", json!({})).unwrap();
    assert_eq!(errors_resp["status"], "ok");
    assert_eq!(errors_resp["count"], 4);

    // 1. keep-local -> transitions to modified without discarding local cache
    let kl_resp = ipc
        .send_command(
            "resolve-conflict",
            json!({ "path": "/keep_local.txt", "strategy": "keep-local" }),
        )
        .unwrap();
    assert_eq!(kl_resp["status"], "ok");
    let kl_node = fixture.db.get_node("/keep_local.txt").unwrap();
    assert_eq!(kl_node.sync_status, SyncStatus::MODIFIED);
    assert!(kl_node.last_error.is_none());
    assert!(cache_kl.exists());

    // 2. keep-remote -> removes local cache and reverts to cloud_only
    let kr_resp = ipc
        .send_command(
            "resolve-conflict",
            json!({ "path": "/keep_remote.txt", "strategy": "keep-remote" }),
        )
        .unwrap();
    assert_eq!(kr_resp["status"], "ok");
    let kr_node = fixture.db.get_node("/keep_remote.txt").unwrap();
    assert_eq!(kr_node.sync_status, SyncStatus::CLOUD_ONLY);
    assert!(kr_node.local_cache_path.is_none());
    assert!(!cache_kr.exists());

    // 3. keep-both -> creates sibling (conflict) file and reverts original to cloud_only
    let kb_resp = ipc
        .send_command(
            "resolve-conflict",
            json!({ "path": "/keep_both.txt", "strategy": "keep-both" }),
        )
        .unwrap();
    assert_eq!(kb_resp["status"], "ok");
    let kb_orig = fixture.db.get_node("/keep_both.txt").unwrap();
    assert_eq!(kb_orig.sync_status, SyncStatus::CLOUD_ONLY);
    assert!(kb_orig.local_cache_path.is_none());
    let kb_copy = fixture
        .db
        .get_node("/keep_both (conflict).txt")
        .expect("Conflict sibling copy must be created");
    assert_eq!(kb_copy.sync_status, SyncStatus::MODIFIED);
    assert!(!kb_copy.remote_exists);
    let copy_cache = kb_copy.local_cache_path.unwrap();
    assert_eq!(fs::read(&copy_cache).unwrap(), b"conflict-bytes");

    // 4. Local-only node refuses keep-remote so user bytes are not silently lost
    let lo_resp = ipc
        .send_command(
            "resolve-conflict",
            json!({ "path": "/local_only_err.txt", "strategy": "keep-remote" }),
        )
        .unwrap();
    assert_eq!(lo_resp["status"], "error");
    assert!(cache_lo.exists());

    // 5. restore-trash invokes RemoteDrive::restore_from_trash
    let restore_resp = ipc
        .send_command("restore-trash", json!({ "link_id": "trashed-link-99" }))
        .unwrap();
    assert_eq!(restore_resp["status"], "ok");
    let calls = fixture.fake_remote.restore_trash_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].link_id, "trashed-link-99");

    daemon.stop();
}
