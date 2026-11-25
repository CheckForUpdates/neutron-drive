use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn write_executable(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Build an isolated copy of the source checkout files needed by `install.sh`
/// so installer tests never touch the real workspace build/target directories.
fn create_isolated_checkout(base: &Path) -> PathBuf {
    let checkout = base.join("checkout");
    let root = repo_root();

    fs::create_dir_all(checkout.join("bin")).unwrap();
    fs::create_dir_all(checkout.join("desktop")).unwrap();
    fs::create_dir_all(checkout.join("assets/icons")).unwrap();
    fs::create_dir_all(checkout.join("crates/proton-drive-daemon/target/release")).unwrap();
    fs::create_dir_all(checkout.join("build")).unwrap();

    fs::copy(root.join("install.sh"), checkout.join("install.sh")).unwrap();
    fs::set_permissions(
        checkout.join("install.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::copy(
        root.join("bin/neutron-drive"),
        checkout.join("bin/neutron-drive"),
    )
    .unwrap();
    fs::set_permissions(
        checkout.join("bin/neutron-drive"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::copy(
        root.join("desktop/neutron-drive.desktop"),
        checkout.join("desktop/neutron-drive.desktop"),
    )
    .unwrap();
    fs::copy(
        root.join("desktop/neutron-drive.service"),
        checkout.join("desktop/neutron-drive.service"),
    )
    .unwrap();

    for size in [16, 24, 32, 48, 64, 128, 256, 512] {
        let name = format!("icon-{size}.png");
        let src = root.join("assets/icons").join(&name);
        if src.exists() {
            fs::copy(&src, checkout.join("assets/icons").join(&name)).unwrap();
        }
    }
    let svg_src = root.join("assets/icons/neutron-drive.svg");
    if svg_src.exists() {
        fs::copy(&svg_src, checkout.join("assets/icons/neutron-drive.svg")).unwrap();
    }

    write_executable(
        &checkout.join("crates/proton-drive-daemon/target/release/neutron-drive-daemon"),
        "#!/usr/bin/env bash\necho daemon-v1\n",
    );
    write_executable(
        &checkout.join("build/neutron-drive-gui"),
        "#!/usr/bin/env bash\necho gui-v1\n",
    );

    checkout
}

/// Populate a minimal fake PATH directory with standard POSIX utilities symlinked
/// from `/usr/bin` / `/bin` so we can precisely control which build/desktop tools exist.
fn create_minimal_bin_dir(base: &Path) -> PathBuf {
    let bin_dir = base.join("fake-bin");
    fs::create_dir_all(&bin_dir).unwrap();

    for tool in [
        "bash", "sh", "dirname", "uname", "id", "mkdir", "cp", "mv", "rm", "chmod", "grep", "cat",
        "test", "env",
    ] {
        for candidate in [format!("/usr/bin/{tool}"), format!("/bin/{tool}")] {
            let path = Path::new(&candidate);
            if path.exists() {
                let target = bin_dir.join(tool);
                if !target.exists() {
                    std::os::unix::fs::symlink(path, &target).unwrap();
                }
                break;
            }
        }
    }

    bin_dir
}

#[test]
fn test_install_sh_check_passes_and_fails_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let checkout = create_isolated_checkout(temp.path());
    let bin_dir = create_minimal_bin_dir(temp.path());
    let prefix = temp.path().join("never-created-prefix");

    for stub in [
        "cargo",
        "rustc",
        "cmake",
        "c++",
        "pkg-config",
        "fusermount3",
    ] {
        write_executable(&bin_dir.join(stub), "#!/usr/bin/env bash\nexit 0\n");
    }

    // 1. All required prerequisites present -> passes without writing prefix, warns about optional tools
    let ok = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", temp.path().join("home"))
        .args(["--check", "--prefix"])
        .arg(&prefix)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "--check should pass when required tools exist; stderr: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let stdout = String::from_utf8_lossy(&ok.stdout);
    let stderr = String::from_utf8_lossy(&ok.stderr);
    assert!(stdout.contains("Preflight passed. No files were written."));
    assert!(stderr.contains("Warning: systemctl not found"));
    assert!(stderr.contains("Warning: update-desktop-database not found"));
    assert!(stderr.contains("Warning: gtk-update-icon-cache not found"));
    assert!(!prefix.exists(), "--check must not create target prefix");

    // 2. Missing FUSE helper -> fails cleanly and still writes nothing
    fs::remove_file(bin_dir.join("fusermount3")).unwrap();
    let fail = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", temp.path().join("home"))
        .args(["--check", "--prefix"])
        .arg(&prefix)
        .output()
        .unwrap();
    assert!(!fail.status.success(), "--check must fail without FUSE");
    assert!(
        String::from_utf8_lossy(&fail.stderr).contains("FUSE mount helper"),
        "failure stderr should identify missing FUSE helper"
    );
    assert!(!prefix.exists(), "failed --check must not create prefix");
}

#[test]
fn test_install_sh_non_default_prefix_and_idempotent_install() {
    let temp = tempfile::tempdir().unwrap();
    let checkout = create_isolated_checkout(temp.path());
    let bin_dir = create_minimal_bin_dir(temp.path());
    let prefix = temp.path().join("custom-prefix");
    let home = temp.path().join("home");

    for run in 1..=2 {
        let out = Command::new(checkout.join("install.sh"))
            .env("PATH", &bin_dir)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", temp.path().join("xdg-config"))
            .env("XDG_DATA_HOME", temp.path().join("xdg-data"))
            .env("XDG_CACHE_HOME", temp.path().join("xdg-cache"))
            .args(["--prefix"])
            .arg(&prefix)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "install run {run} must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("Warning: update-desktop-database not found"));
        assert!(stderr.contains("Warning: gtk-update-icon-cache not found"));
        assert!(stderr.contains("Warning: systemctl not found"));
    }

    assert!(prefix.join("bin/neutron-drive").exists());
    assert!(prefix.join("bin/neutron-drive-daemon").exists());
    assert!(prefix.join("bin/neutron-drive-gui").exists());
    assert!(prefix
        .join("share/applications/neutron-drive.desktop")
        .exists());
    assert!(prefix
        .join("share/systemd/user/neutron-drive.service")
        .exists());
    assert!(prefix
        .join("share/icons/hicolor/32x32/apps/neutron-drive.png")
        .exists());
    assert!(prefix
        .join("share/icons/hicolor/scalable/apps/neutron-drive.svg")
        .exists());
}

#[test]
fn test_install_sh_update_stops_and_restarts_daemon_via_installed_launcher_and_refreshes_caches() {
    let temp = tempfile::tempdir().unwrap();
    let checkout = create_isolated_checkout(temp.path());
    let bin_dir = create_minimal_bin_dir(temp.path());
    let prefix = temp.path().join("opt-neutron");
    let home = temp.path().join("home");
    let log_file = temp.path().join("events.log");

    // Recording shims for build and desktop integration tools
    write_executable(
        &bin_dir.join("cargo"),
        &format!(
            "#!/usr/bin/env bash\necho \"cargo $*\" >> \"{}\"\nprintf '#!/usr/bin/env bash\\necho daemon-v2\\n' > \"{}\"\nchmod 755 \"{}\"\n",
            log_file.display(),
            checkout
                .join("crates/proton-drive-daemon/target/release/neutron-drive-daemon")
                .display(),
            checkout
                .join("crates/proton-drive-daemon/target/release/neutron-drive-daemon")
                .display(),
        ),
    );
    write_executable(
        &bin_dir.join("cmake"),
        &format!(
            "#!/usr/bin/env bash\necho \"cmake $*\" >> \"{}\"\nprintf '#!/usr/bin/env bash\\necho gui-v2\\n' > \"{}\"\nchmod 755 \"{}\"\n",
            log_file.display(),
            checkout.join("build/neutron-drive-gui").display(),
            checkout.join("build/neutron-drive-gui").display(),
        ),
    );
    for tool in [
        "systemctl",
        "update-desktop-database",
        "gtk-update-icon-cache",
    ] {
        write_executable(
            &bin_dir.join(tool),
            &format!(
                "#!/usr/bin/env bash\necho \"{tool} $*\" >> \"{}\"\nexit 0\n",
                log_file.display()
            ),
        );
    }

    // Replace the checkout's launcher with a recording stub so both the pre-update
    // installed launcher and the newly installed launcher record their commands.
    write_executable(
        &checkout.join("bin/neutron-drive"),
        &format!(
            "#!/usr/bin/env bash\necho \"launcher-v2 $*\" >> \"{}\"\nexit 0\n",
            log_file.display()
        ),
    );

    // Pre-populate an existing installation with a running daemon reported by installed launcher
    let installed_launcher = prefix.join("bin/neutron-drive");
    write_executable(
        &installed_launcher,
        &format!(
            "#!/usr/bin/env bash\necho \"launcher-v1 $*\" >> \"{}\"\nif [ \"$1\" = \"status\" ]; then\n  echo '{{\"status\":\"ok\"}}'\nfi\nexit 0\n",
            log_file.display()
        ),
    );
    write_executable(
        &prefix.join("bin/neutron-drive-daemon"),
        "#!/usr/bin/env bash\necho daemon-v1\n",
    );

    let out = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg-config"))
        .env("XDG_DATA_HOME", temp.path().join("xdg-data"))
        .env("XDG_CACHE_HOME", temp.path().join("xdg-cache"))
        .args(["--update", "--prefix"])
        .arg(&prefix)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "--update must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let log = fs::read_to_string(&log_file).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    let stop_idx = lines
        .iter()
        .position(|l| *l == "launcher-v1 stop")
        .expect("update must stop running daemon via installed launcher");
    let start_idx = lines
        .iter()
        .position(|l| *l == "launcher-v2 start")
        .expect("update must restart daemon via newly installed launcher");
    assert!(
        stop_idx < start_idx,
        "daemon must be stopped before restart"
    );
    assert!(lines.iter().any(|l| l.starts_with("cargo build --release")));
    assert!(lines.iter().any(|l| l.starts_with("cmake --build")));
    assert!(lines
        .iter()
        .any(|l| l.starts_with("update-desktop-database ")));
    assert!(lines
        .iter()
        .any(|l| l.starts_with("gtk-update-icon-cache -f -t ")));
    assert!(lines.contains(&"systemctl --user daemon-reload"));

    let daemon_contents = fs::read_to_string(prefix.join("bin/neutron-drive-daemon")).unwrap();
    assert!(
        daemon_contents.contains("daemon-v2"),
        "updated daemon binary must replace previous version"
    );
}

#[test]
fn test_install_sh_uninstall_respects_ownership_boundaries_disables_service_and_preserves_data() {
    let temp = tempfile::tempdir().unwrap();
    let checkout = create_isolated_checkout(temp.path());
    let bin_dir = create_minimal_bin_dir(temp.path());
    let prefix = temp.path().join("prefix");
    let home = temp.path().join("home");
    let xdg_config = temp.path().join("xdg-config");
    let xdg_data = temp.path().join("xdg-data");
    let xdg_cache = temp.path().join("xdg-cache");
    let log_file = temp.path().join("uninstall.log");

    // Recording stubs (systemctl returns non-zero to also verify best-effort handling)
    write_executable(
        &bin_dir.join("systemctl"),
        &format!(
            "#!/usr/bin/env bash\necho \"systemctl $*\" >> \"{}\"\nexit 1\n",
            log_file.display()
        ),
    );
    for tool in ["update-desktop-database", "gtk-update-icon-cache"] {
        write_executable(
            &bin_dir.join(tool),
            &format!(
                "#!/usr/bin/env bash\necho \"{tool} $*\" >> \"{}\"\nexit 0\n",
                log_file.display()
            ),
        );
    }

    // Install first
    let install_out = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["--prefix"])
        .arg(&prefix)
        .output()
        .unwrap();
    assert!(install_out.status.success());

    // Plant Neutron Drive autostart, sibling third-party files, and user data
    let autostart_nd = xdg_config.join("autostart/neutron-drive.desktop");
    let sibling_files = [
        prefix.join("bin/other-app"),
        prefix.join("share/applications/other-app.desktop"),
        prefix.join("share/systemd/user/other-app.service"),
        prefix.join("share/icons/hicolor/32x32/apps/other-app.png"),
        xdg_config.join("autostart/other-app.desktop"),
    ];
    let user_data_files = [
        xdg_config.join("neutron-drive/config.json"),
        xdg_data.join("neutron-drive/metadata.db"),
        xdg_cache.join("neutron-drive/blocks/chunk.dat"),
        home.join("NeutronDrive/important.txt"),
    ];

    for p in std::iter::once(&autostart_nd)
        .chain(sibling_files.iter())
        .chain(user_data_files.iter())
    {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"keep-me").unwrap();
    }

    // Clear log before uninstall
    fs::write(&log_file, "").unwrap();

    let out = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["--uninstall", "--prefix"])
        .arg(&prefix)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "uninstall must succeed even when systemctl returns non-zero; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains("systemctl --user disable --now neutron-drive.service"));
    assert!(log.contains("systemctl --user daemon-reload"));
    assert!(log.contains("update-desktop-database "));
    assert!(log.contains("gtk-update-icon-cache -f -t "));

    // Owned files removed
    assert!(!prefix.join("bin/neutron-drive").exists());
    assert!(!prefix.join("bin/neutron-drive-daemon").exists());
    assert!(!prefix.join("bin/neutron-drive-gui").exists());
    assert!(!prefix
        .join("share/applications/neutron-drive.desktop")
        .exists());
    assert!(!prefix
        .join("share/systemd/user/neutron-drive.service")
        .exists());
    assert!(!prefix
        .join("share/icons/hicolor/32x32/apps/neutron-drive.png")
        .exists());
    assert!(!prefix
        .join("share/icons/hicolor/scalable/apps/neutron-drive.svg")
        .exists());
    assert!(!autostart_nd.exists());

    // Sibling files & user data preserved
    for p in sibling_files.iter().chain(user_data_files.iter()) {
        assert!(p.exists(), "uninstall must preserve {}", p.display());
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&xdg_config.join("neutron-drive").display().to_string()));
    assert!(stdout.contains(&xdg_data.join("neutron-drive").display().to_string()));
    assert!(stdout.contains(&xdg_cache.join("neutron-drive").display().to_string()));
    assert!(stdout.contains(&home.join("NeutronDrive").display().to_string()));
}

#[test]
fn test_install_sh_purge_data_is_separate_confirmed_and_preserves_mount() {
    let temp = tempfile::tempdir().unwrap();
    let checkout = create_isolated_checkout(temp.path());
    let bin_dir = create_minimal_bin_dir(temp.path());
    let home = temp.path().join("home");
    let xdg_config = temp.path().join("xdg-config");
    let xdg_data = temp.path().join("xdg-data");
    let xdg_cache = temp.path().join("xdg-cache");

    let cfg = xdg_config.join("neutron-drive/config.json");
    let db = xdg_data.join("neutron-drive/metadata.db");
    let cache = xdg_cache.join("neutron-drive/blocks/chunk.dat");
    let mount_file = home.join("NeutronDrive/cloud-copy.txt");
    let sibling_cfg = xdg_config.join("other-app/settings.json");

    for p in [&cfg, &db, &cache, &mount_file, &sibling_cfg] {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"data").unwrap();
    }

    // 1. Combining --uninstall and --purge-data must be rejected
    let combined = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["--uninstall", "--purge-data", "--confirm-purge"])
        .output()
        .unwrap();
    assert!(!combined.status.success());
    assert!(cfg.exists() && db.exists() && cache.exists());

    // 2. Non-interactive --purge-data without --confirm-purge must fail and preserve data
    let unconfirmed = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["--purge-data"])
        .output()
        .unwrap();
    assert!(!unconfirmed.status.success());
    assert!(cfg.exists() && db.exists() && cache.exists());

    // 3. --purge-data with DESTDIR must be rejected
    let with_destdir = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", &home)
        .env("DESTDIR", temp.path().join("stage"))
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["--purge-data", "--confirm-purge"])
        .output()
        .unwrap();
    assert!(!with_destdir.status.success());
    assert!(cfg.exists() && db.exists() && cache.exists());

    // 4. Confirmed --purge-data deletes only Neutron Drive XDG state, preserving mount & siblings
    let confirmed = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .args(["--purge-data", "--confirm-purge"])
        .output()
        .unwrap();
    assert!(
        confirmed.status.success(),
        "confirmed --purge-data must succeed; stderr: {}",
        String::from_utf8_lossy(&confirmed.stderr)
    );
    assert!(!xdg_config.join("neutron-drive").exists());
    assert!(!xdg_data.join("neutron-drive").exists());
    assert!(!xdg_cache.join("neutron-drive").exists());
    assert!(
        mount_file.exists(),
        "--purge-data must never delete the FUSE mount folder"
    );
    assert!(
        sibling_cfg.exists(),
        "--purge-data must never delete unrelated XDG directories"
    );
}

#[test]
fn test_install_sh_destdir_staging_does_not_touch_host_session() {
    let temp = tempfile::tempdir().unwrap();
    let checkout = create_isolated_checkout(temp.path());
    let bin_dir = create_minimal_bin_dir(temp.path());
    let stage = temp.path().join("stage");
    let home = temp.path().join("home");
    let xdg_config = temp.path().join("xdg-config");
    let log_file = temp.path().join("host-tools.log");

    for tool in [
        "systemctl",
        "update-desktop-database",
        "gtk-update-icon-cache",
    ] {
        write_executable(
            &bin_dir.join(tool),
            &format!(
                "#!/usr/bin/env bash\necho \"{tool} $*\" >> \"{}\"\nexit 0\n",
                log_file.display()
            ),
        );
    }

    let out = Command::new(checkout.join("install.sh"))
        .env("PATH", &bin_dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("DESTDIR", &stage)
        .args(["--prefix", "/usr"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "DESTDIR staged install must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(stage.join("usr/bin/neutron-drive").exists());
    assert!(stage.join("usr/bin/neutron-drive-daemon").exists());
    assert!(stage.join("usr/bin/neutron-drive-gui").exists());
    assert!(stage
        .join("usr/share/applications/neutron-drive.desktop")
        .exists());
    assert!(stage
        .join("usr/share/systemd/user/neutron-drive.service")
        .exists());
    assert!(stage
        .join("usr/share/icons/hicolor/scalable/apps/neutron-drive.svg")
        .exists());

    assert!(
        !log_file.exists(),
        "DESTDIR staged install must not invoke host systemctl or cache tools"
    );
    assert!(
        !xdg_config.exists(),
        "DESTDIR staged install must not touch XDG_CONFIG_HOME"
    );
}
