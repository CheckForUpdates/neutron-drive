use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use log::{error, info};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub command: String,
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub status: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub type HandlerFn = Arc<dyn Fn(serde_json::Value) -> serde_json::Value + Send + Sync>;

pub struct IpcServer {
    socket_path: PathBuf,
    handlers: Arc<Mutex<HashMap<String, HandlerFn>>>,
    running: Arc<AtomicBool>,
    timeout: Duration,
    max_request_size: usize,
    max_connections: usize,
    active_connections: Arc<AtomicUsize>,
}

impl IpcServer {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            handlers: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            timeout: Duration::from_secs(5),
            max_request_size: 64 * 1024,
            max_connections: 32,
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn with_max_request_size(mut self, size: usize) -> Self {
        self.max_request_size = size;
        self
    }

    pub fn set_max_request_size(&mut self, size: usize) {
        self.max_request_size = size;
    }

    pub fn with_max_connections(mut self, limit: usize) -> Self {
        self.max_connections = limit;
        self
    }

    pub fn set_max_connections(&mut self, limit: usize) {
        self.max_connections = limit;
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    pub fn get_peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = stream.as_raw_fd();
            let mut ucred = libc::ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut ucred as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(ucred.uid)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stream;
            Ok(unsafe { libc::geteuid() })
        }
    }

    pub fn is_peer_authorized(stream: &UnixStream) -> bool {
        match Self::get_peer_uid(stream) {
            Ok(peer_uid) => peer_uid == unsafe { libc::geteuid() },
            Err(_) => false,
        }
    }

    pub fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> bool {
        match Self::get_peer_uid(stream) {
            Ok(peer_uid) => peer_uid == expected_uid,
            Err(_) => false,
        }
    }

    pub fn register_handler<F>(&self, command: &str, handler: F)
    where
        F: Fn(serde_json::Value) -> serde_json::Value + Send + Sync + 'static,
    {
        let mut map = self.handlers.lock().unwrap();
        map.insert(command.to_string(), Arc::new(handler));
    }

    pub fn start(&self) -> std::io::Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        if let Some(parent) = self.socket_path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }

        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.socket_path, fs::Permissions::from_mode(0o600))?;
        }
        listener.set_nonblocking(true)?;

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let handlers = Arc::clone(&self.handlers);
        let socket_path = self.socket_path.clone();
        let timeout = self.timeout;
        let max_request_size = self.max_request_size;
        let max_connections = self.max_connections;
        let active_connections = Arc::clone(&self.active_connections);

        thread::Builder::new()
            .name("ipc-server".to_string())
            .spawn(move || {
                info!("IPC server listening on {:?}", socket_path);
                while running.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            if !Self::is_peer_authorized(&stream) {
                                continue;
                            }

                            if active_connections.load(Ordering::SeqCst) >= max_connections {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "message": "Server busy: maximum concurrent connections reached"
                                });
                                let _ = stream.write_all(err_resp.to_string().as_bytes());
                                let _ = stream.flush();
                                continue;
                            }

                            active_connections.fetch_add(1, Ordering::SeqCst);
                            let handlers_clone = Arc::clone(&handlers);
                            let active_conn_clone = Arc::clone(&active_connections);

                            thread::spawn(move || {
                                struct ConnGuard(Arc<AtomicUsize>);
                                impl Drop for ConnGuard {
                                    fn drop(&mut self) {
                                        self.0.fetch_sub(1, Ordering::SeqCst);
                                    }
                                }
                                let _guard = ConnGuard(active_conn_clone);

                                Self::handle_connection(
                                    &mut stream,
                                    &handlers_clone,
                                    timeout,
                                    max_request_size,
                                );
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(50));
                        }
                        Err(e) => {
                            if running.load(Ordering::SeqCst) {
                                error!("IPC accept error: {}", e);
                            }
                            break;
                        }
                    }
                }
                let _ = fs::remove_file(&socket_path);
            })?;

        Ok(())
    }

    fn handle_connection(
        stream: &mut UnixStream,
        handlers: &Arc<Mutex<HashMap<String, HandlerFn>>>,
        timeout: Duration,
        max_request_size: usize,
    ) {
        if !Self::is_peer_authorized(stream) {
            return;
        }

        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 8192];
        let mut is_oversized = false;

        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > max_request_size {
                        is_oversized = true;
                        break;
                    }
                    if serde_json::from_slice::<IpcRequest>(&buf).is_ok() {
                        break;
                    }
                    if let Err(e) = serde_json::from_slice::<serde_json::Value>(&buf) {
                        if !e.is_eof() {
                            break;
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if !buf.is_empty() {
                        let err_resp = serde_json::json!({
                            "status": "error",
                            "message": "Timed out waiting for complete request: partial JSON received"
                        });
                        let _ = stream.write_all(err_resp.to_string().as_bytes());
                        let _ = stream.flush();
                    }
                    return;
                }
                Err(_) => return,
            }
        }

        if is_oversized {
            let err_resp = serde_json::json!({
                "status": "error",
                "message": format!("Request exceeds maximum allowed size of {} bytes", max_request_size)
            });
            let _ = stream.write_all(err_resp.to_string().as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
            return;
        }

        if buf.is_empty() {
            return;
        }

        let req: IpcRequest = match serde_json::from_slice(&buf) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = serde_json::json!({
                    "status": "error",
                    "message": format!("Invalid JSON request: {}", e)
                });
                let _ = stream.write_all(err_resp.to_string().as_bytes());
                let _ = stream.flush();
                return;
            }
        };

        let handler = {
            let map = handlers.lock().unwrap();
            map.get(&req.command).cloned()
        };

        let response = if let Some(h) = handler {
            h(req.args)
        } else {
            serde_json::json!({
                "status": "error",
                "message": format!("Unknown command: {}", req.command)
            })
        };

        let _ = stream.write_all(response.to_string().as_bytes());
        let _ = stream.flush();
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    pub fn new(socket_path: Option<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.unwrap_or_else(crate::config::socket_path),
        }
    }

    pub fn is_daemon_running(&self) -> bool {
        self.send_command("ping", serde_json::json!({})).is_ok()
    }

    pub fn send_command(
        &self,
        command: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| format!("Cannot connect to socket {:?}: {}", self.socket_path, e))?;

        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

        let req = serde_json::json!({
            "command": command,
            "args": args
        });

        stream
            .write_all(req.to_string().as_bytes())
            .map_err(|e| format!("Write failed: {}", e))?;

        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .map_err(|e| format!("Read failed: {}", e))?;

        if buf.is_empty() {
            return Err("Empty response from daemon".to_string());
        }

        serde_json::from_slice(&buf).map_err(|e| format!("JSON decode failed: {}", e))
    }
}
