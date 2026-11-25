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

### Changed
- Retired the legacy external Node/JS CLI bridge (`bin/proton-drive`) and Python prototype; legacy `"backend": "cli"` configs automatically migrate to `"native"`.
- Synchronized `SyncEngine` startup/pause handoff (`wait_until_idle` and pause-aware status/upload guards) so pausing while a background poll is in flight stops pending uploads cleanly and preserves `paused` state.

### Known Limitations
- **Pre-Release Status:** Automated tests run against `FakeRemoteDrive` mocks; always validate live FUSE mounts using a disposable Proton account and non-sensitive data.
- **Cross-Parent Move + Rename Intermediate Collision (`EEXIST`):** Moving and renaming a remote node across directories in one operation sequences a rename and move (or move and rename); if *both* intermediate paths are already occupied, `rename` returns `EEXIST` and the operations should be performed separately.
