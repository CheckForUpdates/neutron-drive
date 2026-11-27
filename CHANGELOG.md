# Changelog

All notable changes to Neutron Drive are documented in this file.

## [3.0.3] - Unreleased (Pre-Release Community Preparation)

### Added
- **Pure-Rust Native Daemon (`crates/proton-drive-daemon`):**
  - Pure-Rust kernel `/dev/fuse` virtual filesystem via `fuser` (`default-features = false`, no C `libfuse` linkage).
  - Native Proton API client, SRP-6a authentication, 2FA TOTP, and Browser SSO session forking (`native/auth.rs`, `native/http.rs`).
  - Pure-Rust OpenPGP key unlocking, signing, and streaming 4 MiB block encryption/decryption (`native/crypto.rs`, `native/transfer.rs` using `pgp 0.21`).
  - Transactional SQLite metadata store in WAL mode with crash recovery and atomic schema migrations (`metadata_db.rs`).
  - Shared `ActivityRegistry` protecting open writers and in-flight transfers from concurrent upload or cache eviction (`fuse_fs.rs`, `sync_engine.rs`).
  - Unix domain socket IPC server authenticated with Linux `SO_PEERCRED` UID checks and bounded 64 KB framing (`ipc.rs`).
  - Encrypted `SessionVault` with Linux Secret Service integration (`zbus`) and encrypted fallback storage.
  - Exponential backoff in `RateLimitGate` for `429` rate limits (when `Retry-After` is absent) and transient `5xx` responses (`native/http.rs`).
- **Native Qt6 System Tray (`src/gui-cpp/`):**
  - Asynchronous, non-blocking `IpcClient` and `TrayCoordinator` with gated status polling, quota bar (`QuotaWidget`), desktop error/auth notifications, and `PreferencesDialog` (native/browser login, error retry/clear recovery, mount point, cache policy).
- **Branding, SDK Compliance & Packaging:**
  - Independent **Neutron Drive** branding, original SVG/PNG icon set (`assets/icons/`), third-party credential handling disclosures in CLI and Qt login prompts, and `external-drive-neutron_drive@3.0.3-alpha+linux` client identification (`x-pm-appversion`).
  - Unified `neutron-drive` launcher, `install.sh` (`--prefix`, `--update`, `DESTDIR`, `--uninstall`), systemd user unit, desktop entry, CPack `.deb`/`.rpm`/`.tar.gz` targets, Arch `PKGBUILD`, and GitHub Actions CI workflow.
- **Offline Pinning (`metadata_db.rs`, `fuse_fs.rs`, `daemon.rs`, `main.rs`, `PreferencesDialog.cpp`):**
  - Schema v3 migration adding `pinned` tracking for files and folders, protecting pinned items (and descendants of pinned folders) from both `clear-cache` and policy-based TTL/max-size eviction.
  - Added `pin`, `unpin`, and `pinned` IPC/CLI commands with on-demand hydration when mounted, `pinned_count` in `status`, and skipped-item feedback in the Qt6 Cache Preferences dialog.
- **Trash Restore & Conflict Resolution (`endpoints.rs`, `metadata_db.rs`, `daemon.rs`, `main.rs`, `PreferencesDialog.cpp`):**
  - Added `DriveEndpoints::restore_trash_links` (`PUT /drive/v2/volumes/{volume_id}/trash/restore_multiple`), `RemoteDrive::restore_from_trash`, and the `restore-trash` IPC/CLI command.
  - Added transactional `MetadataDB::resolve_error_node` (`keep-local`, `keep-remote`, `keep-both`), `list-errors` / `resolve-conflict` IPC/CLI commands, and the **Resolve Conflicts...** workflow in Qt6 Preferences.
- **Distribution & Desktop Integration (`packaging/`, `docs/packaging-and-desktop.md`):**
  - Added Fedora/COPR RPM spec (`packaging/rpm/neutron-drive.spec`), experimental Flatpak manifest (`packaging/flatpak/io.github.CheckForUpdates.NeutronDrive.yml`), KDE Dolphin service menu (`packaging/dolphin/`), and Nautilus pin/unpin scripts (`packaging/nautilus/`).

### Changed
- Retired the legacy external Node/JS CLI bridge (`bin/proton-drive`) and Python prototype; legacy `"backend": "cli"` configs automatically migrate to `"native"`.
- Synchronized `SyncEngine` startup/pause handoff (`wait_until_idle` and pause-aware status/upload guards) so pausing while a background poll is in flight stops pending uploads cleanly and preserves `paused` state.
- Scoped `x-pm-appversion: cli-drive@0.9.0` to `/auth/v4/sessions/forks*` Browser SSO initiation/polling requests and URL-encoded fork selectors (`auth.rs`, `http.rs`), resolving live `422 Invalid selector` poll rejections while keeping `external-drive-neutron_drive@3.0.3-alpha+linux` on all other API requests; verified all three live `native_client` interoperability tests against a disposable Proton Drive account.
- Added atomic cross-parent move + rename (`RemoteDrive::move_and_rename` via Proton Drive's `move-multiple` endpoint in `native/mod.rs` and `fuse_fs.rs`), eliminating intermediate-path `EEXIST` collisions and partial-failure rollback windows on the native backend.

### Known Limitations
- **Pre-Release Status:** Automated tests run against `FakeRemoteDrive` mocks; always validate live FUSE mounts using a disposable Proton account and non-sensitive data.
