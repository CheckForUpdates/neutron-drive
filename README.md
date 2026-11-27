# Neutron Drive (Unofficial Linux Client for Proton Drive)

An unofficial, native, high-performance desktop client and virtual filesystem for [Proton Drive](https://proton.me/drive) on Linux, architecturally informed by the official macOS client (`ProtonDriveMac` and `ProtonDriveFileProviderMac`).

Unlike web-based or Electron/Tauri wrappers that wrap Proton's web application inside a browser engine, **Neutron Drive** is a **true native desktop client** featuring:
- **Virtual Filesystem (Files-on-Demand):** Mounts your Proton Drive via **FUSE** (`~/NeutronDrive`) with instant metadata browsing and on-demand streaming hydration implemented in pure Rust (`fuser`).
- **No Arbitrary File Caps:** Handles multi-gigabyte files with chunked uploads and streaming decryption without browser memory caps.
- **Low Resource Footprint:** Operates with minimal memory overhead as a native unprivileged background daemon, avoiding full browser rendering engines.
- **Native Qt6 System Tray:** System tray menu with real-time status badges (*Synced*, *Syncing*, *Paused*, *Offline*, *Error*), storage quota indicators, and non-blocking asynchronous IPC controls.
- **Transactional SQLite Engine:** Local caching and indexing with WAL mode and crash recovery.
- **Decoupled Daemon & IPC:** Headless background daemon manageable via authenticated Unix domain sockets (`SO_PEERCRED`), CLI, or `systemd --user`.

> **Pre-Release & Third-Party Notice:** Neutron Drive is an independent, unofficial third-party application and is not affiliated with, endorsed by, or supported by Proton AG. Automated test suites validate filesystem and sync invariants against isolated local mocks (`FakeRemoteDrive`); evaluate live FUSE mounts first with a dedicated, disposable Proton Drive test account and non-sensitive data before using personal files.

---

## Architecture Overview

This project translates the macOS client architecture into native Linux desktop and kernel primitives:

```
┌────────────────────────────────────────────────────────┐
│               macOS Client (Reference)                 │
├──────────────────────────┬─────────────────────────────┤
│ ProtonDriveMac (Status)  │ SwiftUI / AppKit Menu Bar   │
│ ProtonDriveFileProvider  │ NSFileProviderReplicatedExt │
│ PDCore Metadata Store    │ Core Data (SQLite schema)   │
│ PDCore & PDSDKCore       │ OpenPGP / Streaming chunks  │
│ Keychain                 │ macOS Security Framework    │
└──────────────────────────┴─────────────────────────────┘
                            ▼
┌────────────────────────────────────────────────────────┐
│              Neutron Drive (Native Port)               │
├──────────────────────────┬─────────────────────────────┤
│ Qt6 System Tray          │ QSystemTrayIcon & Menus (C++)│
│ FUSE Virtual Filesystem  │ Files-On-Demand (fuser Rust)│
│ Local Metadata Engine    │ SQLite3 (rusqlite bundled)  │
│ Sync & Daemon Engine     │ Async Tokio streaming sync  │
│ Secret Storage / Auth    │ SRP-6a + OpenPGP + Keyring  │
│ Process Control          │ Unix Domain Socket IPC      │
└──────────────────────────┴─────────────────────────────┘
```

### Module Breakdown

```
neutron-drive/
├── CMakeLists.txt                  # CMake build configuration, CTest runner, CPack, and install rules
├── install.sh                      # Shell installer supporting --prefix, DESTDIR, and --uninstall
├── packaging/
│   └── arch/PKGBUILD               # Arch Linux PKGBUILD recipe
├── .github/workflows/
│   └── ci.yml                      # CI verification gates and package builds
├── bin/
│   └── neutron-drive               # Multi-directory launcher resolving native binaries
├── desktop/
│   ├── neutron-drive.desktop       # XDG desktop application entry
│   └── neutron-drive.service       # Systemd user service unit for headless operation
├── assets/icons/                   # Original Neutron Drive SVG and PNG icon set (16px to 512px)
├── crates/
│   └── proton-drive-daemon/        # Native Rust backend daemon & CLI
│       ├── Cargo.toml              # Rust crate manifest (fuser, rusqlite, tokio, clap)
│       ├── src/
│       │   ├── lib.rs              # Library exports and public interfaces
│       │   ├── main.rs             # Daemon and CLI command-line entrypoint
│       │   ├── client.rs           # RemoteDrive trait and FakeRemoteDrive test double
│       │   ├── config.rs           # Atomic configuration management (0700/0600)
│       │   ├── daemon.rs           # Daemon orchestration, session lifecycle, and cached status
│       │   ├── fuse_fs.rs          # FUSE filesystem, inode mapping, and ActivityRegistry
│       │   ├── ipc.rs              # Unix domain socket IPC server/client with SO_PEERCRED
│       │   ├── metadata_db.rs      # SQLite database, schema migrations, and crash recovery
│       │   ├── native/             # Pure-Rust Proton API, SRP-6a, OpenPGP, events, transfers
│       │   └── sync_engine.rs      # Upload coordinator with open-writer protection
│       └── tests/                  # Authoritative Rust integration test suites
│           ├── daemon_control.rs   # Daemon lifecycle, configuration, and graceful stop
│           ├── data_safety.rs      # Open-writer coordination and durability error tests
│           ├── migration.rs        # Transactional schema migrations and path safety
│           ├── namespace.rs        # Move, rename, and subtree atomicity tests
│           ├── native_client.rs    # Native SRP, OpenPGP, transfer, and event recovery tests
│           ├── reconciliation.rs   # Remote reconciliation, refresh, and offline recovery
│           └── security.rs         # IPC peer UID, framing, cache eviction, and installer tests
├── src/
│   └── gui-cpp/                    # Native C++ Qt6 system tray application
│       ├── main.cpp                # GUI application entrypoint
│       ├── IpcClient.hpp / .cpp    # Asynchronous non-blocking Qt IPC client
│       ├── TrayCoordinator.hpp/.cpp # System tray icon, notifications, menu actions, and status polling
│       ├── PreferencesDialog.hpp/.cpp # Preferences, native/SSO login, error recovery, and cache controls
│       ├── OnboardingDialog.hpp/.cpp  # First-run guided onboarding wizard
│       └── QuotaWidget.hpp / .cpp     # Storage quota visual progress widget
└── tests/
    ├── test_ipc_async.cpp             # Qt event-loop non-blocking IPC, notification, and UI tests
    └── test_onboarding.cpp            # Qt guided onboarding wizard tests
```

---

## Prerequisites

Ensure your Linux development environment has the following dependencies:

- **C++17 Compiler:** GCC 10+ or Clang 11+
- **CMake:** 3.22 or newer
- **Qt6:** `Core`, `Gui`, `Widgets`, `Network`, and `Test`
- **Rust & Cargo:** 1.70 or newer
- **FUSE:** `fuse3` or `fuse` (`fusermount3` or `fusermount`)
- **Desktop Environment:** Any standard X11 or Wayland desktop (GNOME, KDE Plasma, XFCE, etc.)

### Package Manager Installation

On Debian / Ubuntu:
```bash
sudo apt update
sudo apt install build-essential cmake qt6-base-dev qt6-base-dev-tools cargo rustc fuse3 libfuse3-dev
```

On Fedora:
```bash
sudo dnf install gcc-c++ cmake qt6-qtbase-devel qt6-qtbase-gui cargo rust fuse3 fuse3-devel
```

On Arch Linux:
```bash
sudo pacman -S base-devel cmake qt6-base cargo rust fuse3
```

---

## Building & Testing

### 1. Configure and Build Native Client
```bash
cmake -B build -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
```

### 2. Run Authoritative Test Suites
```bash
QT_QPA_PLATFORM=offscreen ctest --test-dir build --output-on-failure
```
CTest executes the three authoritative native test suites:
1. `rust_backend_tests` (Rust unit and integration tests)
2. `qt_ipc_async_tests` (Qt non-blocking IPC, login, notification, error recovery, and event loop tests)
3. `qt_onboarding_tests` (Qt guided onboarding wizard tests)

You can also run the Rust test suite directly:
```bash
cargo test --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets
```

---

## Codex on GitHub

Add an OpenAI API key as the repository Actions secret `OPENAI_API_KEY`
under **Settings → Secrets and variables → Actions**. Once the workflow is on
the default branch, maintainers with write access can use it from GitHub.

| Where | Trigger | Result |
| --- | --- | --- |
| Issue | Comment `/codex triage` | Triage notes and a proposed next step on the issue |
| Pull request | Comment `/codex review` | Review findings in a PR conversation comment |
| GitHub Actions | A failed **Release Verification Gates** push run on the default branch | Diagnosis in the **Codex GitHub Assistant** run summary |
| GitHub Actions | Run **Codex GitHub Assistant** from the default branch and provide a failed **Release Verification Gates** run ID | Diagnosis for the selected run, including PR CI runs |

Codex reads selected issue text, PR patches, or failed-step logs through the
OpenAI API. It reports findings with read-only access to repository contents.

## Installation & Packaging

### Automated Installation Script
Run `install.sh` to compile native binaries, install executables to `${HOME}/.local/bin`, install desktop entry and icons, and register the systemd user service:
```bash
./install.sh
```

Supported options:
- `--prefix <dir>`: Specify install prefix (defaults to `~/.local` for unprivileged user, `/usr/local` for root)
- `--check`: Validate the Linux, FUSE, Rust, CMake, C++ compiler, and Qt6 prerequisites without writing files
- `--update`: Rebuild native components, stop any running daemon via the installed launcher, replace binaries atomically, refresh caches, and restart the daemon if active
- `DESTDIR=<dir>`: Support staged package installs (e.g. `DESTDIR=/tmp/pkg ./install.sh`); does not touch host desktop/session state
- `--uninstall`: Remove only Neutron Drive artifacts under the selected prefix, disable its user-service/autostart entry, refresh caches, and preserve credentials, configuration, metadata, cache, and mount data
- `--purge-data`: Separately delete local Neutron Drive configuration, credentials, metadata database, and cache after explicit confirmation (`PURGE` prompt or `--confirm-purge`); never implied by `--uninstall` and never deletes the mount folder or remote cloud files

### Package-Manager Removal
`install.sh --uninstall` is for source-checkout installs only — do **not** run it against a package-manager install. Remove distribution packages with your package manager:
- **Debian / Ubuntu (`.deb`):** `sudo apt remove neutron-drive`
- **Fedora / RHEL (`.rpm`):** `sudo dnf remove neutron-drive`
- **Arch Linux:** `sudo pacman -R neutron-drive`

### CMake Install & Distribution Packages
```bash
cmake --install build --prefix ~/.local
```
Generate `.deb`, `.rpm`, or `.tar.gz` packages with CPack:
```bash
cpack --config build/CPackConfig.cmake -G DEB -B build/packages
cpack --config build/CPackConfig.cmake -G RPM -B build/packages
```
Arch Linux users can build directly using [`packaging/arch/PKGBUILD`](packaging/arch/PKGBUILD). See [`docs/packaging-and-desktop.md`](docs/packaging-and-desktop.md) for Fedora COPR/RPM (`packaging/rpm/neutron-drive.spec`), Flatpak, and Dolphin/Nautilus context-menu integration.

---

## Usage Guide

The unified `neutron-drive` launcher orchestrates daemon, GUI, and CLI management.

### 1. Authenticate
Sign in natively using Proton credentials (+ optional 2FA TOTP) or browser SSO:
```bash
neutron-drive login
# Or launch browser-based SSO sign-in directly:
neutron-drive login --browser
```
*Session secrets are stored via Linux Secret Service / encrypted `SessionVault` storage; passwords are never stored.*

### 2. Launch the System Tray GUI
Start the desktop system tray application and background daemon:
```bash
neutron-drive gui
```
The tray icon appears in your system tray with:
- Live storage quota bar (`X GB of Y GB used`)
- Desktop notifications (`QSystemTrayIcon::showMessage`) for sync/upload errors and session expiration
- Direct folder shortcut to open `~/NeutronDrive` in your default file manager
- Refresh metadata resync trigger
- Pause / Resume syncing toggles
- Preferences dialog (native/browser SSO login, error retry/clear recovery, auto-mount on start, start-at-login, custom mount point, cache clearing)

### 3. Command-Line Operations
For terminal workflows and headless servers:

| Command | Action |
|---|---|
| `neutron-drive start` | Start the background daemon process |
| `neutron-drive stop` | Cleanly unmount and stop the running daemon |
| `neutron-drive status` | Display status (use `--json` for structured output) |
| `neutron-drive mount [path]` | Mount the virtual drive (default: `~/NeutronDrive`) |
| `neutron-drive unmount` | Cleanly unmount the virtual drive |
| `neutron-drive refresh` | Force a metadata resync with cloud |
| `neutron-drive pause` | Temporarily pause background uploads |
| `neutron-drive resume` | Resume background uploads |
| `neutron-drive retry-errors` | Re-queue failed sync uploads for retry |
| `neutron-drive clear-errors` | Safely clear stale sync error diagnostics |
| `neutron-drive clear-cache` | Safely evict clean downloaded blocks (respecting pinned items) |
| `neutron-drive pin <path>` | Pin a file or folder for offline access |
| `neutron-drive unpin <path>` | Unpin a file or folder so it can be evicted from cache |
| `neutron-drive pinned` | List files and folders pinned for offline access |
| `neutron-drive resolve-conflict <path> [--strategy ...]` | Resolve a sync error (`keep-local`, `keep-remote`, `keep-both`) |
| `neutron-drive restore-trash <link_id>` | Restore a trashed file or folder in Proton Drive |
| `neutron-drive update` | Run full native build & install update (`install.sh --update`) |
| `neutron-drive logout` | Sign out and clear stored credentials |

### 4. Background Systemd Service
To keep Neutron Drive running in the background across user login sessions:
```bash
systemctl --user enable --now neutron-drive.service
```

---

## Data Safety & Security Guarantees

### 1. Private Permissions by Default
- The FUSE mount directory and metadata directory are created with mode `0700` (owner-only).
- Files created in the virtual drive have permissions `0600`.
- The Unix domain socket (`$XDG_RUNTIME_DIR/neutron-drive.sock`, or `~/.local/share/neutron-drive/daemon.sock` fallback) is created with mode `0600`. The daemon uses Linux socket peer credentials (`SO_PEERCRED`) to immediately reject any connection from a foreign UID before parsing requests.

### 2. Open-Writer and In-Flight Protection
- The daemon tracks all open file handles and in-flight transfers in a thread-safe `ActivityRegistry`.
- Files with open writable handles or actively hydrating/uploading blocks are strictly excluded from upload synchronization and cache eviction until closed and released.
- Concurrent writes to different offsets honor POSIX semantics without clobbering each other.

### 3. Durability & Crash Recovery
- Content modifications persist dirty intent to the metadata database before file mutation.
- `fsync` and `flush` invoke real filesystem synchronization and SQLite WAL checkpoints, propagating durability errors to applications.
- In the event of a system crash or power interruption during an upload, unacknowledged writes are restored to `modified` status on the next daemon launch, retaining their cache ID and generation for safe retry.

### 4. Recoverable Namespace Operations
- Renaming onto an existing file performs POSIX atomic overwrite validation (`ENOTDIR`/`EISDIR`/`ENOTEMPTY`/`EBUSY`) and trashes the replaced target before moving the source.
- Cross-parent move and rename (`/a/old -> /b/new`) sequences the remote rename and move via a non-colliding intermediate path with best-effort rollback if step 2 fails (returning `EEXIST` if both intermediate paths are occupied).
- Subtree moves in the metadata database execute within atomic SQLite transactions with automatic rollback on error.

### 5. Native Cryptography & Security Guarantees
- Authentication, SRP-6a proofs, OpenPGP key unlocking, and block encryption/decryption are implemented directly in Rust (`neutron-drive-daemon`) with `pgp` and `ring`/`sha2`.
- HTTP requests identify as `external-drive-neutron_drive@3.0.3-alpha+linux` (`x-pm-appversion`) with exponential backoff on `429` rate limits and transient `5xx` responses, following the [`ProtonDriveApps/sdk`](https://github.com/ProtonDriveApps/sdk) usage guidelines.
- See [`docs/third-party-artifacts.md`](docs/third-party-artifacts.md) for dependency provenance, SDK compliance, and upstream cryptographic model migration tracking (late 2026 / early 2027).

### 6. Validation Disclaimer
Unit and integration test suites execute against isolated mock doubles (`FakeRemoteDrive`) with temporary paths. Passing local tests does not establish live Proton server synchronization, live encryption, or kernel filesystem correctness. Live validation requires an isolated Proton account and disposable test data.

---

## Disclaimer & License

This is an independent community open-source project and is not officially affiliated with, endorsed by, or operated by Proton AG. Proton Drive is a registered trademark of Proton AG.

Licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See [LICENSE](LICENSE) for details.
