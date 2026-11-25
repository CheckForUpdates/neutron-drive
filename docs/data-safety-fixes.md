# Linux Data-Safety Remediation and Validation Record

## 1. Scope and Architecture Overview

This document records the architectural decisions, safety invariants, and test verification results for the data-safety and native parity implementation of Proton Drive Linux.

The project implements a native Linux desktop client comprising:
1. **Rust Daemon & Filesystem Backend (`crates/proton-drive-daemon`)**:
   - Files-on-demand virtual filesystem using `fuser` (`default-features = false`, pure-Rust kernel FUSE ABI without C `libfuse` linkage).
   - Pure-Rust Proton Drive client, SRP-6a authentication, Browser SSO session forking, OpenPGP key unlocking/encryption (`pgp 0.21`), encrypted `SessionVault` (`zbus` Linux Secret Service + encrypted fallback), incremental event polling, and 4 MiB streaming block transfers (`src/native/`).
   - Local transactional metadata engine using `rusqlite` (bundled SQLite with WAL mode).
   - Upload coordinator and thread-safe handle/transfer tracking (`ActivityRegistry`).
   - Private Unix domain socket IPC server with Linux `SO_PEERCRED` caller UID enforcement.
2. **C++ Qt6 GUI Frontend (`src/gui-cpp`)**:
   - System tray coordinator (`TrayCoordinator`) with non-blocking asynchronous IPC (`IpcClient`).
   - Gated polling preventing multiple inflight status or refresh requests.
   - Preference dialog (`PreferencesDialog`) with native/SSO login, error retry/clear recovery, and transactional config rollbacks on error.
   - Storage quota bar (`QuotaWidget`).

---

## 2. Core Data Safety Invariants & Decisions

### Invariant 1: Durable Intent & POSIX Semantics
- **Persistent Dirty Intent**: In `fuse_fs::write`, dirty intent (`mark_pending`) is written to SQLite before file mutation. If SQLite recording fails, the write returns an immediate I/O error (`libc::EIO`).
- **Positional I/O**: Multi-handle concurrent writes use positional offsets (`write_all_at`) without handle position clobbering.
- **Real Durability Callbacks**: `flush` and `fsync` invoke explicit OS file synchronization (`sync_data`/`sync_all`) and SQLite WAL checkpoints (`PRAGMA wal_checkpoint(PASSIVE)`), propagating any durability failures directly to the calling application.

### Invariant 2: Shared Activity Tracking & Open-Writer Protection
- **Single Source of Truth**: `ActivityRegistry` is shared via `Arc<ActivityRegistry>` across FUSE file handles, the background `SyncEngine`, and daemon lifecycle management.
- **No Upload of Open Writers**: `SyncEngine` checks `activity.has_writable_handle(&cache_id)` before uploading. Nodes with open writable handles are skipped until all writers release their handles.
- **Concurrent Modification Protection**: If a file is edited while an earlier generation upload is in progress, the newer write generation remains pending in SQLite after the first upload completes.
- **Pause Isolation**: `SyncEngine::pause()` sets the paused flag, preserves `paused` status against concurrent cycle status updates, skips pending uploads, and exposes `wait_until_idle` for deterministic handoff.
- **Safe Eviction Boundary**: Cache eviction (`evict_clean_cache` and policy-driven eviction) skips dirty files, in-flight hydrating/uploading files, open read or write handles, unknown files, and any file outside the designated cache directory.

### Invariant 3: Transactional Schema Migrations & Crash Recovery
- **Safe Path Verification**: Before opening SQLite, parent directories must be `0700` and db files `0600`, owned by the current effective UID, rejecting symbolic links.
- **Atomic Migrations**: Migrations run inside an explicit SQLite transaction (`conn.transaction()`). If any step fails, the transaction rolls back cleanly, leaving the database unchanged.
- **Ambiguous Cache Rejection**: If multiple database rows share identical local cache paths, they are marked with `SyncStatus::ERROR` rather than guessing ownership.
- **Crash Recovery**: Interrupted `syncing` rows are restored to `modified` upon daemon startup, preserving their write generation and stable `cache_id` so work can be safely retried.

### Invariant 4: Recoverable Namespace Operations
- **POSIX Atomic Overwrite Validation**: Renaming onto an existing destination validates type compatibility (`ENOTDIR`/`EISDIR`), non-empty directory constraints (`ENOTEMPTY`), and active subtree locks (`EBUSY`) before trashing the target and replacing the node.
- **Atomic Subtree Moves**: Subtree renames and moves in SQLite execute within transactions, ensuring child paths and parent linkages remain coherent on failure.
- **Sequenced Cross-Parent Move + Rename**: Moving across parents while changing the basename (`/a/old -> /b/new`) pre-validates a non-colliding intermediate path (returning `EEXIST` if both intermediate paths are occupied) and performs best-effort remote rollback if step 2 fails.
- **In-Flight Locking**: In-flight uploads and active descendants return `EBUSY` when namespace mutations are attempted.
- **Open Handle Continuity**: Moving or renaming directories dynamically updates open handle paths in `ActivityRegistry` and FUSE inode-path lookup tables.

### Invariant 5: Private Mount, IPC, and Credential Trust Boundaries
- **Owner-Only Mount**: FUSE mount defaults to owner-only permissions without `AllowOther`. Advertised directory permissions are `0700` and file permissions are `0600`.
- **IPC Peer Credential Authentication**: Accepted Unix stream connections inspect `SO_PEERCRED`. Any peer UID not matching the daemon's effective UID is dropped immediately before parsing payloads.
- **Bounded IPC Framing**: Incoming payloads are capped at 64 KB with read/write timeouts (5 seconds) and concurrent connection limits.
- **Legacy CLI Retirement**: The historical external `bin/proton-drive` CLI bridge has been retired; `install.sh` cleans up legacy binaries on update and legacy `"backend": "cli"` configs migrate automatically to `"native"`.

---

## 3. Test Suite Verification & Coverage Matrix

The test matrix consists of two authoritative native suites registered under CTest:

| Suite Name | Implementation / Scope | Test Count | Status |
|---|---|---|---|
| `rust_backend_tests` | Rust Unit & Integration Tests (`crates/proton-drive-daemon`) | 122 executed (3 `#[ignore]` live tests) | **PASS** |
| `qt_ipc_async_tests` | Qt6 C++ Event Loop, UI & Non-Blocking IPC Tests (`tests/test_ipc_async.cpp`) | 8 | **PASS** |

### 3.1 Rust Test Suites Breakdown (122 Executed + 3 `#[ignore]`)
1. `src/lib.rs` (35 unit tests):
   - Metadata DB CRUD, cascade deletion, subtree moves, error retry/clear preservation; daemon cached status, refresh bounding, and config backend selection; config save/load/autostart/legacy migration; SRP-6a primitives and modulus verification; `SessionVault` secret redaction, keyring locking, fallback, and permissions; OpenPGP armor, key unlock, split packets, signing, and `gpg` interoperability; HTTP rate-limit parsing.
2. `tests/daemon_control.rs` (11 integration tests):
   - Daemon startup, graceful stop via IPC and CLI contract, `SIGTERM` socket cleanup, `get-config` / `update-config` partial persistence, invalid config rejection, legacy `"cli"` config migration, `retry-errors` / `clear-errors` IPC, and `pause` race isolation during active poll.
3. `tests/data_safety.rs` (9 integration tests):
   - Isolated paths preventing real XDG contamination, `FakeRemoteDrive` failure injection, durability error propagation (`fsync`/`flush`), concurrent multi-handle explicit offsets, open-writer upload withholding, generation preservation during active upload, and crash recovery.
4. `tests/migration.rs` (8 integration tests):
   - Path permissions and symlink rejection, fresh schema initialization, pre-cache-ID legacy schema migration, v1-to-v2 native column migration, duplicate legacy cache error marking, interrupted upload recovery, migration rollback, and idempotent reopening.
5. `tests/namespace.rs` (12 integration tests):
   - `ENOENT` on missing source, POSIX atomic overwrite and type/non-empty dir checks, sequenced cross-parent move-rename and rollback, `EBUSY` on inflight subtrees, dirty file cache/handle preservation across rename, descendant persistence across DB restart, and subtree move rollback.
6. `tests/reconciliation.rs` (8 integration tests):
   - Remote create detection, remote update metadata update and clean cache invalidation, remote delete removal of clean files, preservation of dirty/uploading/open/local-only files during refresh, offline-to-online state recovery, tracked subdirectory polling, non-blocking `statfs` + background refresh, and daemon refresh IPC.
7. `tests/security.rs` (15 integration tests):
   - `0700`/`0600` permissions enforcement, `SO_PEERCRED` foreign UID rejection, oversized payload rejection, malformed/partial JSON handling, connection bounding, stalled connection timeouts, cache eviction handle/inflight/dirty/policy exclusion, path traversal/symlink protection, `clear-cache` mount checks, and `install.sh` staged `DESTDIR` + legacy CLI cleanup.
8. `tests/native_client.rs` (23 mocked tests + 3 `#[ignore]` live disposable-account tests):
   - Native OpenPGP packets/xattrs, SRP-6a + 2FA + tampered modulus rejection, Browser SSO session forking, HTTP 429/401 retry & token rotation, paginated directory bootstrap, streaming block range reads, multi-block upload/download integrity, incremental event cursor recovery, `gpg` interoperability, plus 3 `#[ignore]` live disposable-account integration tests.
9. `tests/test_ipc.rs` (1 integration test):
   - IPC ping and round-trip command execution.

### 3.2 Qt C++ Async Test Suite Breakdown (8 Tests)
- `tests/test_ipc_async.cpp`:
  - `testDelayedDaemonDoesNotBlockEventLoop`
  - `testOnlyOneStatusRequestInflight`
  - `testTimeoutDisconnectAndMalformedResponses`
  - `testPreferencesDialogLoadsConfigAndHandlesRollback`
  - `testNativeLoginTwoFactorLogoutAndBrowserSso`
  - `testEnsureDaemonRunningStartsProcessWhenOffline`
  - `testTrayNotificationsForSyncErrorsAndAuthExpiration`
  - `testPreferencesErrorRecoveryRetryAndClear`

---

## 4. Verification and Release Gate Commands

Authoritative release verification commands:

```bash
# 1. Cargo formatting check
cargo fmt --manifest-path crates/proton-drive-daemon/Cargo.toml --all -- --check

# 2. Strict Clippy lint check
cargo clippy --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets --all-features -- -D warnings

# 3. Rust test suite
cargo test --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets

# 4. CMake build and headless CTest runner
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
QT_QPA_PLATFORM=offscreen ctest --test-dir build --output-on-failure
```

---

## 5. Live Environment Limitations & Testing Policy

- **Mock Isolation**: All automated unit and integration tests run against isolated mock doubles (`FakeRemoteDrive`) using temporary directories.
- **Live Proton Caveat**: Passing local tests does not prove live Proton encryption, authentication token renewal, or remote cloud synchronization against live Proton servers.
- **Disposable Testing Protocol**: Live mounting or manual testing must use a dedicated, disposable test Proton account with non-sensitive data. Never test live mounts using critical personal data.
- **Known Limitations**:
  - Cross-parent move and rename operations sequence a rename and move (or move and rename) via a non-colliding intermediate path; if both intermediate paths are occupied, `rename` returns `EEXIST` and the operations should be performed separately.
