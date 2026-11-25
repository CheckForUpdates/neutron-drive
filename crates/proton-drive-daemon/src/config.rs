use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "neutron-drive";
pub const APP_DISPLAY_NAME: &str = "Neutron Drive";
pub const APP_VERSION: &str = "3.0.3";
pub const BACKEND_NATIVE: &str = "native";

pub fn validate_backend(backend: &str) -> Result<&str, String> {
    match backend {
        BACKEND_NATIVE => Ok(BACKEND_NATIVE),
        "cli" => Err(
            "Invalid backend 'cli': CLI backend has been retired; only 'native' is supported"
                .to_string(),
        ),
        other => Err(format!(
            "Invalid backend '{}': expected '{}'",
            other, BACKEND_NATIVE
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mount_point: String,
    pub auto_mount_on_start: bool,
    pub cache_max_size_mb: u64,
    pub cache_ttl_hours: u64,
    pub event_poll_interval_sec: u64,
    pub offline_mode: bool,
    pub sync_paused: bool,
    pub start_at_login: bool,
    pub backend: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mount_point: default_mount_point().to_string_lossy().to_string(),
            auto_mount_on_start: true,
            cache_max_size_mb: 5120, // 5 GB
            cache_ttl_hours: 72,
            event_poll_interval_sec: 10,
            offline_mode: false,
            sync_paused: false,
            start_at_login: true,
            backend: BACKEND_NATIVE.to_string(),
        }
    }
}

pub fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

pub fn app_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| home_dir().join(".config"))
        .join(APP_NAME)
}

pub fn app_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| home_dir().join(".local").join("share"))
        .join(APP_NAME)
}

pub fn app_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| home_dir().join(".cache"))
        .join(APP_NAME)
}

pub fn block_cache_dir() -> PathBuf {
    app_cache_dir().join("blocks")
}

pub fn thumbnail_cache_dir() -> PathBuf {
    app_cache_dir().join("thumbnails")
}

pub fn db_path() -> PathBuf {
    app_data_dir().join("metadata.db")
}

pub fn config_file() -> PathBuf {
    app_config_dir().join("config.json")
}

pub fn default_mount_point() -> PathBuf {
    home_dir().join("NeutronDrive")
}

pub fn socket_path() -> PathBuf {
    if let Some(runtime) = dirs::runtime_dir() {
        runtime.join("neutron-drive.sock")
    } else {
        app_data_dir().join("daemon.sock")
    }
}

pub fn ensure_directories() -> std::io::Result<()> {
    std::fs::create_dir_all(app_config_dir())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(app_config_dir(), std::fs::Permissions::from_mode(0o700));
    }
    std::fs::create_dir_all(app_data_dir())?;
    std::fs::create_dir_all(app_cache_dir())?;
    std::fs::create_dir_all(block_cache_dir())?;
    std::fs::create_dir_all(thumbnail_cache_dir())?;
    let mount = default_mount_point();
    if !mount.exists() {
        let _ = std::fs::create_dir_all(&mount);
    }
    Ok(())
}

pub fn load_config_from(path: &Path) -> Config {
    if path.exists() {
        if let Ok(data) = std::fs::read_to_string(path) {
            if let Ok(mut cfg) = serde_json::from_str::<Config>(&data) {
                if cfg.backend == "cli" {
                    log::warn!("Migrating legacy 'cli' backend configuration to 'native'");
                    cfg.backend = BACKEND_NATIVE.to_string();
                }
                return cfg;
            }
        }
    }
    Config::default()
}

pub fn load_config() -> Config {
    load_config_from(&config_file())
}

pub fn save_config_to(cfg: &Config, path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    let data = serde_json::to_string_pretty(cfg).map_err(std::io::Error::other)?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.json");
    let temp_path = parent.join(format!(".{}.tmp.{}", file_name, fastrand::u64(..)));

    std::fs::write(&temp_path, &data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600));
    }

    if let Err(e) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

pub fn save_config(cfg: &Config) -> std::io::Result<()> {
    save_config_to(cfg, &config_file())
}

pub fn autostart_file_for_config(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let config_root = if parent.file_name().and_then(|n| n.to_str()) == Some(APP_NAME) {
        parent.parent().unwrap_or(parent)
    } else {
        parent
    };

    config_root.join("autostart").join("neutron-drive.desktop")
}

pub fn sync_autostart_entry(config_path: &Path, enabled: bool) -> std::io::Result<PathBuf> {
    let desktop_path = autostart_file_for_config(config_path);

    if enabled {
        if let Some(parent) = desktop_path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let content = "[Desktop Entry]\n\
            Type=Application\n\
            Name=Neutron Drive\n\
            Exec=neutron-drive gui\n\
            Icon=neutron-drive\n\
            Terminal=false\n\
            X-GNOME-Autostart-enabled=true\n";
        std::fs::write(&desktop_path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&desktop_path, std::fs::Permissions::from_mode(0o600));
        }
    } else if desktop_path.exists() {
        std::fs::remove_file(&desktop_path)?;
    }

    Ok(desktop_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load_config_to_path() {
        let temp = tempfile::tempdir().unwrap();
        let cfg_path = temp.path().join("subdir").join("test_config.json");

        let cfg = Config {
            mount_point: "/custom/mount".to_string(),
            auto_mount_on_start: false,
            start_at_login: false,
            cache_max_size_mb: 10240,
            ..Default::default()
        };

        save_config_to(&cfg, &cfg_path).expect("Failed to save config");
        assert!(cfg_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_meta = std::fs::metadata(&cfg_path).unwrap();
            assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);

            let parent_meta = std::fs::metadata(cfg_path.parent().unwrap()).unwrap();
            assert_eq!(parent_meta.permissions().mode() & 0o777, 0o700);
        }

        let loaded = load_config_from(&cfg_path);
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn test_load_config_fallback_when_missing_or_corrupt() {
        let temp = tempfile::tempdir().unwrap();
        let missing_path = temp.path().join("missing.json");
        let default_cfg = Config::default();
        assert_eq!(load_config_from(&missing_path), default_cfg);

        let corrupt_path = temp.path().join("corrupt.json");
        std::fs::write(&corrupt_path, b"not valid json").unwrap();
        assert_eq!(load_config_from(&corrupt_path), default_cfg);
    }

    #[test]
    fn test_sync_autostart_entry_creates_and_removes_in_isolated_dir() {
        let temp = tempfile::tempdir().unwrap();

        // Isolated config path directly under temp dir
        let isolated_cfg = temp.path().join("config.json");
        let desktop_path =
            sync_autostart_entry(&isolated_cfg, true).expect("Failed to enable autostart");
        assert_eq!(
            desktop_path,
            temp.path().join("autostart").join("neutron-drive.desktop")
        );
        assert!(desktop_path.exists());
        let contents = std::fs::read_to_string(&desktop_path).unwrap();
        assert!(contents.contains("Name=Neutron Drive"));
        assert!(contents.contains("Exec=neutron-drive gui"));
        assert!(contents.contains("Icon=neutron-drive"));
        assert!(contents.contains("X-GNOME-Autostart-enabled=true"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&desktop_path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        // Disable removes the entry
        let removed_path =
            sync_autostart_entry(&isolated_cfg, false).expect("Failed to disable autostart");
        assert_eq!(removed_path, desktop_path);
        assert!(!desktop_path.exists());

        // Idempotent disable when already absent
        sync_autostart_entry(&isolated_cfg, false).expect("Idempotent disable should succeed");

        // Standard XDG-like layout: <root>/neutron-drive/config.json -> <root>/autostart/neutron-drive.desktop
        let xdg_cfg = temp.path().join("neutron-drive").join("config.json");
        assert_eq!(
            autostart_file_for_config(&xdg_cfg),
            temp.path().join("autostart").join("neutron-drive.desktop")
        );
    }

    #[test]
    fn test_default_backend_is_native_and_missing_field_config_preserves_existing_data() {
        assert_eq!(Config::default().backend, BACKEND_NATIVE);

        let temp = tempfile::tempdir().unwrap();
        let old_cfg_path = temp.path().join("old_config.json");
        std::fs::write(
            &old_cfg_path,
            r#"{
                "mount_point": "/custom/legacy/mount",
                "auto_mount_on_start": false,
                "cache_max_size_mb": 2048
            }"#,
        )
        .unwrap();

        let loaded = load_config_from(&old_cfg_path);
        assert_eq!(loaded.mount_point, "/custom/legacy/mount");
        assert!(!loaded.auto_mount_on_start);
        assert_eq!(loaded.cache_max_size_mb, 2048);
        assert_eq!(loaded.backend, BACKEND_NATIVE);

        let cli_cfg_path = temp.path().join("cli_config.json");
        std::fs::write(
            &cli_cfg_path,
            r#"{
                "mount_point": "/custom/cli/mount",
                "backend": "cli"
            }"#,
        )
        .unwrap();
        let loaded_cli = load_config_from(&cli_cfg_path);
        assert_eq!(loaded_cli.mount_point, "/custom/cli/mount");
        assert_eq!(loaded_cli.backend, BACKEND_NATIVE);

        assert!(validate_backend("cli").is_err());
        assert_eq!(validate_backend("native"), Ok(BACKEND_NATIVE));
        assert!(validate_backend("unknown").is_err());
    }
}
