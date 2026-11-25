use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use clap::{Parser, Subcommand};
use neutron_drive_daemon::client::RemoteDrive;
use neutron_drive_daemon::config::{
    db_path, default_mount_point, ensure_directories, socket_path, APP_DISPLAY_NAME, APP_NAME,
    APP_VERSION,
};
use neutron_drive_daemon::daemon::ProtonDriveDaemon;
use neutron_drive_daemon::ipc::IpcClient;
use neutron_drive_daemon::metadata_db::MetadataDB;
use neutron_drive_daemon::native::NativeProtonClient;

const THIRD_PARTY_AUTH_NOTICE: &str =
    "Notice: This is a third-party application not officially supported by Proton.";

#[derive(Parser)]
#[command(
    name = APP_NAME,
    version = APP_VERSION,
    about = "Neutron Drive — Unofficial Linux Client & Daemon for Proton Drive"
)]
struct Cli {
    #[arg(short, long, help = "Enable verbose debug logging")]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Run daemon in foreground")]
    Daemon,

    #[command(about = "Start daemon in background")]
    Start,

    #[command(about = "Stop running daemon")]
    Stop,

    #[command(about = "Query daemon and sync status")]
    Status {
        #[arg(short, long, help = "Output as JSON")]
        json: bool,
    },

    #[command(about = "Mount Neutron Drive virtual filesystem")]
    Mount {
        #[arg(short, long, help = "Target mount point directory")]
        path: Option<PathBuf>,
    },

    #[command(about = "Unmount Neutron Drive virtual filesystem")]
    Unmount,

    #[command(about = "Pause background syncing")]
    Pause,

    #[command(about = "Resume background syncing")]
    Resume,

    #[command(about = "Evict cached downloaded blocks")]
    ClearCache,

    #[command(about = "Retry failed upload sync items")]
    RetryErrors,

    #[command(about = "Clear stale sync errors safely")]
    ClearErrors,

    #[command(about = "Log in to Proton Drive via Neutron Drive (unofficial third-party client)")]
    Login {
        #[arg(
            long,
            help = "Sign in via browser SSO session forking (native backend)"
        )]
        browser: bool,
    },

    #[command(about = "Log out from Neutron Drive")]
    Logout,

    #[command(about = "Force a metadata resync with cloud")]
    Refresh,
}

fn main() {
    let cli = Cli::parse();

    let log_level = if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::new().filter_level(log_level).init();

    let _ = ensure_directories();

    match cli.command.unwrap_or(Commands::Status { json: false }) {
        Commands::Daemon => {
            let daemon = match ProtonDriveDaemon::new() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Failed to initialize daemon: {}", e);
                    std::process::exit(1);
                }
            };
            if let Err(e) = daemon.start() {
                eprintln!("Failed to start daemon: {}", e);
                std::process::exit(1);
            }
            daemon.run_forever();
        }

        Commands::Start => {
            let ipc = IpcClient::new(None);
            if ipc.is_daemon_running() {
                println!("{} daemon is already running.", APP_DISPLAY_NAME);
                return;
            }

            let exe =
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("neutron-drive-daemon"));
            let child = Command::new(exe).arg("daemon").spawn();

            match child {
                Ok(proc) => {
                    for _ in 0..25 {
                        thread::sleep(Duration::from_millis(200));
                        if ipc.is_daemon_running() {
                            println!(
                                "{} daemon started successfully (PID {}).",
                                APP_DISPLAY_NAME,
                                proc.id()
                            );
                            return;
                        }
                    }
                    println!("Daemon spawned, waiting for socket to initialize...");
                }
                Err(e) => {
                    eprintln!("Failed to start daemon process: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Stop => {
            let ipc = IpcClient::new(None);
            if !ipc.is_daemon_running() {
                println!("{} daemon is not running.", APP_DISPLAY_NAME);
                return;
            }
            match ipc.send_command("stop", serde_json::json!({})) {
                Ok(_) => {
                    let sock = socket_path();
                    let mut stopped = false;
                    for _ in 0..50 {
                        thread::sleep(Duration::from_millis(100));
                        if !sock.exists() && !ipc.is_daemon_running() {
                            stopped = true;
                            break;
                        }
                    }
                    if stopped {
                        println!("{} daemon stopped.", APP_DISPLAY_NAME);
                    } else {
                        eprintln!("Timed out waiting for {} daemon to stop.", APP_DISPLAY_NAME);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to send stop command to daemon: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Status { json } => {
            let ipc = IpcClient::new(None);
            match ipc.send_command("status", serde_json::json!({})) {
                Ok(resp) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                    } else {
                        let auth = resp
                            .get("authenticated")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let auth_msg = resp
                            .get("auth_message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let backend = resp
                            .get("backend")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let sync = resp
                            .get("sync_status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let mounted = resp
                            .get("is_mounted")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let mount_point = resp
                            .get("mount_point")
                            .and_then(|v| v.as_str())
                            .unwrap_or("N/A");

                        println!("--- {} Status ---", APP_DISPLAY_NAME);
                        println!("Daemon:        Running");
                        println!("Backend:       {}", backend);
                        println!("Authenticated: {}", if auth { "Yes" } else { "No" });
                        if !auth && !auth_msg.is_empty() {
                            println!("Auth Detail:   {}", auth_msg);
                        }
                        println!("Sync Status:   {}", sync);
                        println!(
                            "FUSE Mounted:  {} ({})",
                            if mounted { "Yes" } else { "No" },
                            mount_point
                        );

                        if let Some(quota) = resp.get("quota") {
                            let used = quota
                                .get("used_bytes")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let total = quota
                                .get("total_bytes")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let pct = quota
                                .get("percent_used")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0);
                            let used_gb = (used as f64) / (1024.0 * 1024.0 * 1024.0);
                            if total == 0 {
                                let used_mb = (used as f64) / (1024.0 * 1024.0);
                                if used_mb >= 1024.0 {
                                    println!(
                                        "Storage Quota: {:.2} GB used (plan limit unavailable)",
                                        used_gb
                                    );
                                } else {
                                    println!(
                                        "Storage Quota: {:.2} MB used (plan limit unavailable)",
                                        used_mb
                                    );
                                }
                            } else {
                                let total_gb = (total as f64) / (1024.0 * 1024.0 * 1024.0);
                                println!(
                                    "Storage Quota: {:.2} GB of {:.2} GB ({:.1}%)",
                                    used_gb, total_gb, pct
                                );
                            }
                        }
                    }
                }
                Err(_) => {
                    println!("{} daemon is not running.", APP_DISPLAY_NAME);
                    println!("Start it using: {} start", APP_NAME);
                }
            }
        }

        Commands::Mount { path } => {
            let ipc = IpcClient::new(None);
            let mp = path.unwrap_or_else(default_mount_point);
            match ipc.send_command(
                "mount",
                serde_json::json!({"mount_point": mp.to_string_lossy()}),
            ) {
                Ok(r) => println!("Mounted: {}", r),
                Err(e) => eprintln!("Failed to mount: {}", e),
            }
        }

        Commands::Unmount => {
            let ipc = IpcClient::new(None);
            match ipc.send_command("unmount", serde_json::json!({})) {
                Ok(_) => println!("Unmounted successfully."),
                Err(e) => eprintln!("Failed to unmount: {}", e),
            }
        }

        Commands::Pause => {
            let ipc = IpcClient::new(None);
            let _ = ipc.send_command("pause", serde_json::json!({}));
            println!("Sync paused.");
        }

        Commands::Resume => {
            let ipc = IpcClient::new(None);
            let _ = ipc.send_command("resume", serde_json::json!({}));
            println!("Sync resumed.");
        }

        Commands::ClearCache => {
            let ipc = IpcClient::new(None);
            match ipc.send_command("clear-cache", serde_json::json!({})) {
                Ok(r) => println!("Cache cleared: {}", r),
                Err(e) => eprintln!("Failed to clear cache: {}", e),
            }
        }

        Commands::RetryErrors => {
            let ipc = IpcClient::new(None);
            match ipc.send_command("retry-errors", serde_json::json!({})) {
                Ok(r) => {
                    let msg = r
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Retry queued");
                    println!("{}", msg);
                }
                Err(e) => {
                    eprintln!("Failed to retry errors: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::ClearErrors => {
            let ipc = IpcClient::new(None);
            match ipc.send_command("clear-errors", serde_json::json!({})) {
                Ok(r) => {
                    let msg = r
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Errors cleared");
                    println!("{}", msg);
                }
                Err(e) => {
                    eprintln!("Failed to clear errors: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Login { browser } => {
            if let Err(e) = run_native_cli_login(browser) {
                eprintln!("Login failed: {}", e);
                std::process::exit(1);
            }
        }

        Commands::Logout => {
            let ipc = IpcClient::new(None);
            let _ = ipc.send_command("logout", serde_json::json!({}));
            println!("Logged out.");
        }

        Commands::Refresh => {
            let ipc = IpcClient::new(None);
            match ipc.send_command("refresh", serde_json::json!({})) {
                Ok(r) => {
                    let msg = r.get("message").and_then(|m| m.as_str()).unwrap_or("ok");
                    println!("Metadata refresh triggered: {}", msg);
                }
                Err(e) => {
                    eprintln!("Failed to refresh: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

fn prompt_line(prompt: &str, hidden: bool) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut buf = String::new();
    #[cfg(unix)]
    let orig_termios = if hidden && unsafe { libc::isatty(libc::STDIN_FILENO) } != 0 {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut t) == 0 {
                let saved = t;
                t.c_lflag &= !libc::ECHO;
                let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t);
                Some(saved)
            } else {
                None
            }
        }
    } else {
        None
    };

    let read_res = io::stdin().read_line(&mut buf);

    #[cfg(unix)]
    if let Some(saved) = orig_termios {
        unsafe {
            let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &saved);
        }
        println!();
    }

    read_res.map_err(|e| e.to_string())?;
    Ok(buf.trim_end_matches(&['\r', '\n'][..]).to_string())
}

fn run_native_browser_login(show_notice: bool) -> Result<(), String> {
    if show_notice {
        println!("{}", THIRD_PARTY_AUTH_NOTICE);
    }
    let ipc = IpcClient::new(None);
    if ipc.is_daemon_running() {
        let start = ipc
            .send_command("start-browser-login", serde_json::json!({}))
            .map_err(|e| e.to_string())?;
        if start.get("status").and_then(|v| v.as_str()) != Some("ok") {
            let msg = start
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed initiating browser SSO");
            return Err(msg.to_string());
        }
        let url = start
            .get("login_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let code = start
            .get("user_code")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!(
            "Open this URL in your browser to sign in to Proton Drive via {}:",
            APP_DISPLAY_NAME
        );
        println!("  {}", url);
        println!("Confirmation code: {}", code);
        let _ = Command::new("xdg-open").arg(url).spawn();

        let deadline = std::time::Instant::now() + Duration::from_secs(300);
        loop {
            let poll = ipc
                .send_command("poll-browser-login", serde_json::json!({}))
                .map_err(|e| e.to_string())?;
            match poll.get("status").and_then(|v| v.as_str()) {
                Some("ok") => {
                    println!(
                        "{}",
                        poll.get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Authenticated")
                    );
                    return Ok(());
                }
                Some("pending") => {
                    if std::time::Instant::now() >= deadline {
                        return Err("Timed out waiting for browser SSO authorization".to_string());
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
                _ => {
                    let msg = poll
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Browser SSO failed");
                    return Err(msg.to_string());
                }
            }
        }
    }

    let db = MetadataDB::new(&db_path()).map_err(|e| e.to_string())?;
    let client = NativeProtonClient::new(db, None)?;
    let msg = client.authenticate_via_browser(Duration::from_secs(300), |url, code| {
        println!(
            "Open this URL in your browser to sign in to Proton Drive via {}:",
            APP_DISPLAY_NAME
        );
        println!("  {}", url);
        println!("Confirmation code: {}", code);
        let _ = Command::new("xdg-open").arg(url).spawn();
    })?;
    println!("{}", msg);
    Ok(())
}

fn run_native_cli_login(browser: bool) -> Result<(), String> {
    if browser || std::env::var_os("PROTON_BROWSER_LOGIN").is_some() {
        return run_native_browser_login(true);
    }

    println!("{}", THIRD_PARTY_AUTH_NOTICE);
    let username = prompt_line(
        "Proton username / email (leave blank for browser SSO): ",
        false,
    )?;
    if username.trim().is_empty() {
        return run_native_browser_login(false);
    }
    let password = prompt_line("Password: ", true)?;

    let ipc = IpcClient::new(None);
    let submit = |totp: Option<&str>| -> Result<(String, String), String> {
        if ipc.is_daemon_running() {
            let mut args = serde_json::json!({
                "username": username,
                "password": password,
            });
            if let Some(code) = totp {
                args["totp"] = serde_json::json!(code);
            }
            let resp = ipc.send_command("login", args).map_err(|e| e.to_string())?;
            let status = resp
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("error")
                .to_string();
            let msg = resp
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok((status, msg))
        } else {
            let db = MetadataDB::new(&db_path()).map_err(|e| e.to_string())?;
            let client = NativeProtonClient::new(db, None)?;
            match client.authenticate(&username, &password, totp) {
                Ok(msg) => Ok(("ok".to_string(), msg)),
                Err(e) if e.starts_with("2FA_REQUIRED") => Ok(("2fa_required".to_string(), e)),
                Err(e) => Ok(("error".to_string(), e)),
            }
        }
    };

    let (status, msg) = submit(None)?;
    if status == "ok" {
        println!("{}", msg);
        return Ok(());
    }
    if status == "2fa_required" {
        let code = prompt_line("2FA TOTP code: ", false)?;
        let (st2, msg2) = submit(Some(&code))?;
        if st2 == "ok" {
            println!("{}", msg2);
            return Ok(());
        }
        return Err(msg2);
    }
    Err(msg)
}
