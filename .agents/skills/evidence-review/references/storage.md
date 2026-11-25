# Storage, Sync, FUSE, and IPC Review Checks

Apply these checks whenever reviewed code touches `crates/proton-drive-daemon/`,
`src/gui-cpp/`, or legacy `src/core/`. Identify the governing invariant from
`docs/data-safety-fixes.md` first:

- **Durability & POSIX semantics (`fuse_fs.rs`, `metadata_db.rs`)**:
  - Is dirty intent (`mark_pending`) committed to SQLite before mutating the cache file?
    Does a metadata failure abort the write with `libc::EIO`?
  - Do concurrent file handles use positional writes (`write_all_at`) rather than shared
    seek offsets?
  - Do `flush` and `fsync` invoke `sync_data`/`sync_all` and `PRAGMA wal_checkpoint(PASSIVE)`
    and propagate errors to the caller?
- **Open-writer & generation safety (`ActivityRegistry`, `sync_engine.rs`)**:
  - Can `process_uploads` upload a file while `has_writable_handle(&cache_id)` is true?
  - If a file is written while an earlier generation is uploading, does the newer
    write generation remain `modified`/pending after the upload finishes?
  - Does cache eviction (`evict_clean_cache`) exclude dirty rows, in-flight transfers,
    open read/write handles, and paths outside the cache root?
- **Transactional migrations & crash recovery (`metadata_db.rs`)**:
  - Are parent directories (`0700`) and DB files (`0600`) checked for EUID ownership
    and non-symlink status before opening SQLite?
  - Do schema migrations run inside `conn.transaction()` with clean rollback on failure?
  - Are duplicate legacy cache paths marked `SyncStatus::ERROR` rather than guessed, and
    are interrupted `syncing` rows restored to `modified` on startup?
- **Namespace & rename recoverability (`fuse_fs.rs`, `metadata_db.rs`)**:
  - Are destination collisions (`EEXIST`), cross-parent move+rename (`ENOTSUP`), and
    active/inflight subtrees (`EBUSY`) rejected before any remote call is dispatched?
  - Do subtree moves update child paths transactionally and keep `ActivityRegistry` and
    FUSE inode-path tables synchronized?
- **Isolation, IPC auth, and executable trust (`fuse_fs.rs`, `ipc.rs`, `client.rs`)**:
  - Does FUSE mount without `AllowOther` and advertise `0700`/`0600` permissions?
  - Does `ipc.rs` verify `SO_PEERCRED` UID equality before parsing payloads, enforce the
    64 KB frame cap, and bound connection concurrency and read/write timeouts?
  - Does `client.rs` validate `bin/proton-drive` via `validate_executable_safety`
    (absolute path, non-symlink, regular file, EUID/root owner, owner-executable,
    not world-writable)?
- **Qt6 GUI responsiveness (`src/gui-cpp/`)**:
  - Are all `IpcClient` operations asynchronous on the Qt event loop with single-inflight
    polling guards in `TrayCoordinator` and transactional rollback in `PreferencesDialog`?
