use neutron_drive_daemon::ipc::{IpcClient, IpcServer};
use serde_json::json;
use std::thread;
use std::time::Duration;

#[test]
fn test_ipc_ping_and_command() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    let server = IpcServer::new(sock_path.clone());
    server.register_handler(
        "ping",
        |_| json!({"status": "ok", "app": "Proton Drive Test", "version": "3.0.3"}),
    );
    server.register_handler("echo", |args| json!({"status": "ok", "echoed": args}));

    server.start().expect("Server failed to start");
    thread::sleep(Duration::from_millis(100));

    let client = IpcClient::new(Some(sock_path));
    assert!(client.is_daemon_running());

    let ping_resp = client.send_command("ping", json!({})).unwrap();
    assert_eq!(ping_resp.get("status").unwrap().as_str().unwrap(), "ok");
    assert_eq!(
        ping_resp.get("app").unwrap().as_str().unwrap(),
        "Proton Drive Test"
    );

    let echo_resp = client
        .send_command("echo", json!({"hello": "world"}))
        .unwrap();
    assert_eq!(echo_resp.get("status").unwrap().as_str().unwrap(), "ok");
    assert_eq!(
        echo_resp
            .get("echoed")
            .unwrap()
            .get("hello")
            .unwrap()
            .as_str()
            .unwrap(),
        "world"
    );

    server.stop();
}
