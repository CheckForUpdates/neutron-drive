use std::collections::HashSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub struct SyncStatus;

impl SyncStatus {
    pub const CLOUD_ONLY: &'static str = "cloud_only";
    pub const SYNCING: &'static str = "syncing";
    pub const SYNCED: &'static str = "synced";
    pub const MODIFIED: &'static str = "modified";
    pub const ERROR: &'static str = "error";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub path: String,
    pub parent_path: String,
    pub name: String,
    pub node_type: String,
    pub size: i64,
    pub mtime: f64,
    pub local_cache_path: Option<String>,
    pub sync_status: String,
    pub etag: Option<String>,
    pub uid: Option<String>,
    pub last_checked: Option<f64>,
    pub cache_id: String,
    pub generation: i64,
    pub remote_exists: bool,
    pub last_error: Option<String>,
    #[serde(default)]
    pub volume_id: Option<String>,
    #[serde(default)]
    pub share_id: Option<String>,
    #[serde(default)]
    pub link_id: Option<String>,
    #[serde(default)]
    pub parent_link_id: Option<String>,
    #[serde(default)]
    pub revision_id: Option<String>,
    #[serde(default)]
    pub name_hash: Option<String>,
}

const NODE_SELECT_COLUMNS: &str =
    "path, parent_path, name, type, size, mtime, local_cache_path, sync_status,
     etag, uid, last_checked, cache_id, generation, remote_exists, last_error,
     volume_id, share_id, link_id, parent_link_id, revision_id, name_hash";

pub fn now_sec() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub fn generate_uuid() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    format!("{:016x}{:08x}{:08x}", now, pid, fastrand::u32(..))
}

#[cfg(unix)]
fn path_safety_error(msg: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            msg.to_string(),
        )),
    )
}

#[cfg(unix)]
fn validate_path_safety(db_path: &Path) -> Result<(), rusqlite::Error> {
    let current_uid = unsafe { libc::geteuid() };

    let parent = if let Some(p) = db_path.parent() {
        if p.as_os_str().is_empty() {
            Path::new(".")
        } else {
            p
        }
    } else {
        Path::new(".")
    };

    match fs::symlink_metadata(parent) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(path_safety_error("Parent directory is a symlink"));
            }
            if !meta.is_dir() {
                return Err(path_safety_error("Parent path is not a directory"));
            }
            if meta.uid() != current_uid {
                return Err(path_safety_error(
                    "Parent directory is not owned by current user",
                ));
            }
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                path_safety_error(&format!(
                    "Failed to set parent directory permissions: {}",
                    e
                ))
            })?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(parent).map_err(|e| {
                path_safety_error(&format!("Failed to create parent directory: {}", e))
            })?;
            let meta = fs::symlink_metadata(parent).map_err(|e| {
                path_safety_error(&format!("Failed to stat created parent directory: {}", e))
            })?;
            if meta.file_type().is_symlink() {
                return Err(path_safety_error("Parent directory is a symlink"));
            }
            if !meta.is_dir() {
                return Err(path_safety_error("Parent path is not a directory"));
            }
            if meta.uid() != current_uid {
                return Err(path_safety_error(
                    "Parent directory is not owned by current user",
                ));
            }
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                path_safety_error(&format!(
                    "Failed to set parent directory permissions: {}",
                    e
                ))
            })?;
        }
        Err(err) => {
            return Err(path_safety_error(&format!(
                "Failed to stat parent directory: {}",
                err
            )));
        }
    }

    match fs::symlink_metadata(db_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(path_safety_error("Database path is a symlink"));
            }
            if !meta.is_file() {
                return Err(path_safety_error("Database path is not a regular file"));
            }
            if meta.uid() != current_uid {
                return Err(path_safety_error(
                    "Database file is not owned by current user",
                ));
            }
            fs::set_permissions(db_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                path_safety_error(&format!("Failed to set database file permissions: {}", e))
            })?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Database file does not exist yet. Will be created by Connection::open.
        }
        Err(err) => {
            return Err(path_safety_error(&format!(
                "Failed to stat database file: {}",
                err
            )));
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_path_safety(_db_path: &Path) -> Result<(), rusqlite::Error> {
    Ok(())
}

#[derive(Clone)]
pub struct MetadataDB {
    #[allow(dead_code)]
    db_path: PathBuf,
    conn: Arc<Mutex<Connection>>,
    fail_sync_storage: Arc<AtomicBool>,
    fail_move_subtree: Arc<AtomicBool>,
}

impl MetadataDB {
    pub const CURRENT_SCHEMA_VERSION: u32 = 2;

    pub fn new(db_path: &Path) -> Result<Self, rusqlite::Error> {
        if db_path.as_os_str() != ":memory:" {
            validate_path_safety(db_path)?;
        }

        let mut conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=15000;",
        )?;

        #[cfg(unix)]
        if db_path.as_os_str() != ":memory:" {
            let current_uid = unsafe { libc::geteuid() };
            let meta = fs::symlink_metadata(db_path).map_err(|e| {
                path_safety_error(&format!("Failed to stat database file after open: {}", e))
            })?;
            if meta.file_type().is_symlink() {
                return Err(path_safety_error("Database path is a symlink"));
            }
            if !meta.is_file() {
                return Err(path_safety_error("Database path is not a regular file"));
            }
            if meta.uid() != current_uid {
                return Err(path_safety_error(
                    "Database file is not owned by current user",
                ));
            }
            fs::set_permissions(db_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                path_safety_error(&format!("Failed to set database file permissions: {}", e))
            })?;
        }

        Self::migrate(&mut conn)?;

        let db = Self {
            db_path: db_path.to_path_buf(),
            conn: Arc::new(Mutex::new(conn)),
            fail_sync_storage: Arc::new(AtomicBool::new(false)),
            fail_move_subtree: Arc::new(AtomicBool::new(false)),
        };

        Ok(db)
    }

    pub fn set_fail_sync_storage(&self, fail: bool) {
        self.fail_sync_storage.store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_move_subtree(&self, fail: bool) {
        self.fail_move_subtree.store(fail, Ordering::SeqCst);
    }

    pub fn migrate(conn: &mut Connection) -> Result<(), rusqlite::Error> {
        Self::migrate_with_hook(conn, |_| Ok(()))
    }

    pub fn migrate_with_hook<F>(conn: &mut Connection, mut hook: F) -> Result<(), rusqlite::Error>
    where
        F: FnMut(&str) -> Result<(), rusqlite::Error>,
    {
        let tx = conn.transaction()?;
        hook("before_migration")?;

        let current_version: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if current_version < Self::CURRENT_SCHEMA_VERSION {
            Self::run_schema_migration_tx(&tx, &mut hook)?;
        }

        Self::run_crash_recovery_tx(&tx, &mut hook)?;

        hook("before_commit")?;
        tx.commit()?;
        Ok(())
    }

    fn run_schema_migration_tx<F>(
        tx: &rusqlite::Transaction,
        hook: &mut F,
    ) -> Result<(), rusqlite::Error>
    where
        F: FnMut(&str) -> Result<(), rusqlite::Error>,
    {
        tx.execute(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);",
            [],
        )?;
        hook("after_settings_table")?;

        let nodes_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'nodes')",
            [],
            |row| row.get(0),
        )?;

        if !nodes_exists {
            tx.execute(
                "CREATE TABLE nodes (
                    path TEXT PRIMARY KEY COLLATE BINARY,
                    parent_path TEXT,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    size INTEGER DEFAULT 0,
                    mtime REAL NOT NULL,
                    local_cache_path TEXT,
                    sync_status TEXT DEFAULT 'cloud_only',
                    etag TEXT,
                    uid TEXT,
                    last_checked REAL,
                    cache_id TEXT,
                    generation INTEGER NOT NULL DEFAULT 0,
                    remote_exists INTEGER NOT NULL DEFAULT 1,
                    last_error TEXT,
                    volume_id TEXT,
                    share_id TEXT,
                    link_id TEXT,
                    parent_link_id TEXT,
                    revision_id TEXT,
                    name_hash TEXT
                );",
                [],
            )?;
            hook("after_create_nodes_table")?;
        } else {
            let mut existing_columns = HashSet::new();
            {
                let mut stmt = tx.prepare("PRAGMA table_info(nodes)")?;
                let col_names = stmt.query_map([], |row| row.get::<_, String>(1))?;
                for name in col_names {
                    existing_columns.insert(name?.to_lowercase());
                }
            }

            if !existing_columns.contains("cache_id") {
                tx.execute("ALTER TABLE nodes ADD COLUMN cache_id TEXT", [])?;
            }
            if !existing_columns.contains("generation") {
                tx.execute(
                    "ALTER TABLE nodes ADD COLUMN generation INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
            }
            if !existing_columns.contains("remote_exists") {
                tx.execute(
                    "ALTER TABLE nodes ADD COLUMN remote_exists INTEGER NOT NULL DEFAULT 1",
                    [],
                )?;
            }
            if !existing_columns.contains("last_error") {
                tx.execute("ALTER TABLE nodes ADD COLUMN last_error TEXT", [])?;
            }
            if !existing_columns.contains("volume_id") {
                tx.execute("ALTER TABLE nodes ADD COLUMN volume_id TEXT", [])?;
            }
            if !existing_columns.contains("share_id") {
                tx.execute("ALTER TABLE nodes ADD COLUMN share_id TEXT", [])?;
            }
            if !existing_columns.contains("link_id") {
                tx.execute("ALTER TABLE nodes ADD COLUMN link_id TEXT", [])?;
            }
            if !existing_columns.contains("parent_link_id") {
                tx.execute("ALTER TABLE nodes ADD COLUMN parent_link_id TEXT", [])?;
            }
            if !existing_columns.contains("revision_id") {
                tx.execute("ALTER TABLE nodes ADD COLUMN revision_id TEXT", [])?;
            }
            if !existing_columns.contains("name_hash") {
                tx.execute("ALTER TABLE nodes ADD COLUMN name_hash TEXT", [])?;
            }
            hook("after_add_columns")?;
        }

        // Duplicate local_cache_path detection
        tx.execute(
            "UPDATE nodes
             SET sync_status = 'error',
                 last_error = 'ambiguous legacy cache reference'
             WHERE local_cache_path IS NOT NULL
               AND local_cache_path != ''
               AND local_cache_path IN (
                   SELECT local_cache_path
                   FROM nodes
                   WHERE local_cache_path IS NOT NULL AND local_cache_path != ''
                   GROUP BY local_cache_path
                   HAVING COUNT(*) > 1
               )",
            [],
        )?;
        hook("after_detect_duplicate_cache_paths")?;

        // Assign generated UUID to any rows where cache_id IS NULL or empty
        {
            let mut stmt =
                tx.prepare("SELECT path FROM nodes WHERE cache_id IS NULL OR cache_id = ''")?;
            let paths: Vec<String> = stmt
                .query_map([], |row| row.get(0))?
                .filter_map(Result::ok)
                .collect();
            drop(stmt);

            let mut update_stmt = tx.prepare("UPDATE nodes SET cache_id = ?1 WHERE path = ?2")?;
            for p in paths {
                let uuid = generate_uuid();
                update_stmt.execute(params![uuid, p])?;
            }
        }
        hook("after_assign_cache_ids")?;

        // Create indexes
        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_parent_path ON nodes(parent_path);",
            [],
        )?;
        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_sync_status ON nodes(sync_status);",
            [],
        )?;
        tx.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_cache_id ON nodes(cache_id) WHERE cache_id IS NOT NULL;",
            [],
        )?;
        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_link_id ON nodes(volume_id, link_id) WHERE link_id IS NOT NULL;",
            [],
        )?;
        hook("after_create_indexes")?;

        // Versioning
        tx.execute(
            &format!("PRAGMA user_version = {}", Self::CURRENT_SCHEMA_VERSION),
            [],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO settings(key, value) VALUES ('schema_version', ?1)",
            params![Self::CURRENT_SCHEMA_VERSION.to_string()],
        )?;
        hook("after_schema_version")?;

        Ok(())
    }

    fn run_crash_recovery_tx<F>(
        tx: &rusqlite::Transaction,
        hook: &mut F,
    ) -> Result<(), rusqlite::Error>
    where
        F: FnMut(&str) -> Result<(), rusqlite::Error>,
    {
        let nodes_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'nodes')",
            [],
            |row| row.get(0),
        )?;

        if nodes_exists {
            tx.execute(
                "UPDATE nodes SET sync_status = ?1 WHERE sync_status = ?2",
                params![SyncStatus::MODIFIED, SyncStatus::SYNCING],
            )?;
            hook("after_crash_recovery")?;
        }

        Ok(())
    }

    pub fn init_schema(&self) -> Result<(), rusqlite::Error> {
        let mut conn = self.conn.lock().unwrap();
        Self::migrate(&mut conn)
    }

    pub fn schema_version(&self) -> Result<u32, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_node(
        &self,
        path: &str,
        parent_path: &str,
        name: &str,
        node_type: &str,
        size: i64,
        mtime: Option<f64>,
        local_cache_path: Option<&str>,
        sync_status: Option<&str>,
        etag: Option<&str>,
        uid: Option<&str>,
        cache_id: Option<&str>,
        generation: Option<i64>,
        remote_exists: Option<bool>,
        last_error: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = now_sec();
        let mtime_val = mtime.unwrap_or(now);
        let sync_status_val = sync_status.unwrap_or(SyncStatus::CLOUD_ONLY);
        let cache_id_val = cache_id.map(|s| s.to_string()).unwrap_or_else(|| {
            let mut stmt = conn
                .prepare("SELECT cache_id FROM nodes WHERE path = ?")
                .unwrap();
            stmt.query_row([path], |row| row.get::<_, String>(0))
                .unwrap_or_else(|_| generate_uuid())
        });
        let gen_val = generation.unwrap_or(0);
        let remote_val = remote_exists.map(|b| if b { 1 } else { 0 }).unwrap_or(1);

        conn.execute(
            "INSERT INTO nodes(path, parent_path, name, type, size, mtime, local_cache_path,
                sync_status, etag, uid, last_checked, cache_id, generation, remote_exists, last_error)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(path) DO UPDATE SET
                parent_path = excluded.parent_path,
                name = excluded.name,
                type = excluded.type,
                size = excluded.size,
                mtime = excluded.mtime,
                local_cache_path = COALESCE(excluded.local_cache_path, nodes.local_cache_path),
                sync_status = excluded.sync_status,
                etag = COALESCE(excluded.etag, nodes.etag),
                uid = COALESCE(excluded.uid, nodes.uid),
                last_checked = excluded.last_checked,
                cache_id = COALESCE(nodes.cache_id, excluded.cache_id),
                generation = CASE WHEN ?16 IS NULL THEN nodes.generation ELSE excluded.generation END,
                remote_exists = CASE WHEN ?17 IS NULL THEN nodes.remote_exists ELSE excluded.remote_exists END,
                last_error = excluded.last_error",
            params![
                path, parent_path, name, node_type, size, mtime_val, local_cache_path,
                sync_status_val, etag, uid, now, cache_id_val, gen_val, remote_val, last_error,
                generation, remote_exists.map(|b| if b { 1 } else { 0 })
            ],
        )?;
        Ok(())
    }

    fn row_to_node(row: &rusqlite::Row) -> Result<Node, rusqlite::Error> {
        let remote_int: i32 = row.get(13)?;
        Ok(Node {
            path: row.get(0)?,
            parent_path: row.get(1)?,
            name: row.get(2)?,
            node_type: row.get(3)?,
            size: row.get(4)?,
            mtime: row.get(5)?,
            local_cache_path: row.get(6)?,
            sync_status: row.get(7)?,
            etag: row.get(8)?,
            uid: row.get(9)?,
            last_checked: row.get(10)?,
            cache_id: row.get(11)?,
            generation: row.get(12)?,
            remote_exists: remote_int != 0,
            last_error: row.get(14)?,
            volume_id: row.get(15)?,
            share_id: row.get(16)?,
            link_id: row.get(17)?,
            parent_link_id: row.get(18)?,
            revision_id: row.get(19)?,
            name_hash: row.get(20)?,
        })
    }

    pub fn get_node(&self, path: &str) -> Option<Node> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM nodes WHERE path = ? COLLATE BINARY",
            NODE_SELECT_COLUMNS
        );
        conn.query_row(&sql, [path], Self::row_to_node)
            .optional()
            .ok()
            .flatten()
    }

    pub fn get_node_by_cache_id(&self, cache_id: &str) -> Option<Node> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM nodes WHERE cache_id = ?",
            NODE_SELECT_COLUMNS
        );
        conn.query_row(&sql, [cache_id], Self::row_to_node)
            .optional()
            .ok()
            .flatten()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_native_ids(
        &self,
        path: &str,
        volume_id: Option<&str>,
        share_id: Option<&str>,
        link_id: Option<&str>,
        parent_link_id: Option<&str>,
        revision_id: Option<&str>,
        name_hash: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE nodes SET
                volume_id = COALESCE(?1, volume_id),
                share_id = COALESCE(?2, share_id),
                link_id = COALESCE(?3, link_id),
                parent_link_id = COALESCE(?4, parent_link_id),
                revision_id = COALESCE(?5, revision_id),
                name_hash = COALESCE(?6, name_hash)
             WHERE path = ?7 COLLATE BINARY",
            params![
                volume_id,
                share_id,
                link_id,
                parent_link_id,
                revision_id,
                name_hash,
                path
            ],
        )?;
        Ok(())
    }

    pub fn get_node_by_link_id(&self, volume_id: &str, link_id: &str) -> Option<Node> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM nodes WHERE volume_id = ?1 AND link_id = ?2",
            NODE_SELECT_COLUMNS
        );
        conn.query_row(&sql, params![volume_id, link_id], Self::row_to_node)
            .optional()
            .ok()
            .flatten()
    }

    pub fn get_node_by_only_link_id(&self, link_id: &str) -> Option<Node> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM nodes WHERE link_id = ?1 OR uid = ?1 LIMIT 1",
            NODE_SELECT_COLUMNS
        );
        conn.query_row(&sql, params![link_id], Self::row_to_node)
            .optional()
            .ok()
            .flatten()
    }

    pub fn get_children(&self, parent_path: &str) -> Vec<Node> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM nodes WHERE parent_path = ? COLLATE BINARY ORDER BY type DESC, name ASC",
            NODE_SELECT_COLUMNS
        );
        let mut stmt = conn.prepare(&sql).unwrap();
        let rows = stmt.query_map([parent_path], Self::row_to_node).unwrap();
        rows.filter_map(Result::ok).collect()
    }

    pub fn get_pending_nodes(&self) -> Vec<Node> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM nodes WHERE sync_status IN (?1, ?2) ORDER BY mtime, path",
            NODE_SELECT_COLUMNS
        );
        let mut stmt = conn.prepare(&sql).unwrap();
        let rows = stmt
            .query_map([SyncStatus::MODIFIED, SyncStatus::ERROR], Self::row_to_node)
            .unwrap();
        rows.filter_map(Result::ok).collect()
    }

    pub fn get_sync_counts(&self) -> (usize, usize) {
        let conn = self.conn.lock().unwrap();
        let pending_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM nodes WHERE sync_status IN (?1, ?2)",
                [SyncStatus::MODIFIED, SyncStatus::SYNCING],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let error_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM nodes WHERE sync_status = ?1",
                [SyncStatus::ERROR],
                |row| row.get(0),
            )
            .unwrap_or(0);
        (pending_count.max(0) as usize, error_count.max(0) as usize)
    }

    pub fn get_recent_errors(&self, limit: usize) -> Vec<(String, String)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT path, COALESCE(last_error, 'Sync error')
             FROM nodes
             WHERE sync_status = ?1
             ORDER BY mtime DESC, path ASC
             LIMIT ?2",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map(params![SyncStatus::ERROR, limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(Result::ok).collect()
    }

    pub fn get_all_nodes(&self) -> Vec<Node> {
        let conn = self.conn.lock().unwrap();
        let sql = format!("SELECT {} FROM nodes", NODE_SELECT_COLUMNS);
        let mut stmt = conn.prepare(&sql).unwrap();
        let rows = stmt.query_map([], Self::row_to_node).unwrap();
        rows.filter_map(Result::ok).collect()
    }

    pub fn get_subtree_nodes(&self, path: &str) -> Vec<Node> {
        let clean_path = if path == "/" {
            "/"
        } else {
            path.trim_end_matches('/')
        };
        let prefix = if clean_path == "/" {
            "/".to_string()
        } else {
            format!("{}/", clean_path)
        };
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM nodes WHERE path = ?1 COLLATE BINARY OR substr(path, 1, ?2) = ?3 COLLATE BINARY
             ORDER BY length(path)",
            NODE_SELECT_COLUMNS
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows =
            match stmt.query_map(params![clean_path, prefix.len(), prefix], Self::row_to_node) {
                Ok(r) => r,
                Err(_) => return Vec::new(),
            };
        rows.filter_map(Result::ok).collect()
    }

    pub fn mark_pending(
        &self,
        path: &str,
        local_path: &str,
        size: Option<i64>,
    ) -> Result<Node, String> {
        let conn = self.conn.lock().unwrap();
        let now = now_sec();
        let count = if let Some(s) = size {
            conn.execute(
                "UPDATE nodes SET local_cache_path = ?1, sync_status = ?2, generation = generation + 1,
                        size = ?3, mtime = ?4, last_error = NULL WHERE path = ?5 COLLATE BINARY",
                params![local_path, SyncStatus::MODIFIED, s, now, path],
            )
        } else {
            conn.execute(
                "UPDATE nodes SET local_cache_path = ?1, sync_status = ?2, generation = generation + 1,
                        mtime = ?3, last_error = NULL WHERE path = ?4 COLLATE BINARY",
                params![local_path, SyncStatus::MODIFIED, now, path],
            )
        }
        .map_err(|e| e.to_string())?;

        if count == 0 {
            return Err(format!("Node not found: {}", path));
        }

        let sql = format!(
            "SELECT {} FROM nodes WHERE path = ? COLLATE BINARY",
            NODE_SELECT_COLUMNS
        );
        conn.query_row(&sql, [path], Self::row_to_node)
            .map_err(|e| e.to_string())
    }

    pub fn update_local_size(&self, cache_id: &str, size: i64) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE nodes SET size = ?1, mtime = ?2 WHERE cache_id = ?3",
            params![size, now_sec(), cache_id],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub fn mark_uploading(&self, cache_id: &str, generation: i64) -> bool {
        let conn = self.conn.lock().unwrap();
        let count = conn
            .execute(
                "UPDATE nodes SET sync_status = ?1, last_error = NULL
             WHERE cache_id = ?2 AND generation = ?3 AND sync_status IN (?4, ?5)",
                params![
                    SyncStatus::SYNCING,
                    cache_id,
                    generation,
                    SyncStatus::MODIFIED,
                    SyncStatus::ERROR
                ],
            )
            .unwrap_or(0);
        count == 1
    }

    pub fn acknowledge_upload(&self, cache_id: &str, generation: i64) -> bool {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "UPDATE nodes SET remote_exists = 1 WHERE cache_id = ?",
            [cache_id],
        );
        let count = conn
            .execute(
                "UPDATE nodes SET sync_status = ?1, remote_exists = 1, last_error = NULL
             WHERE cache_id = ?2 AND generation = ?3 AND sync_status = ?4",
                params![
                    SyncStatus::SYNCED,
                    cache_id,
                    generation,
                    SyncStatus::SYNCING
                ],
            )
            .unwrap_or(0);
        count == 1
    }

    pub fn mark_upload_error(&self, cache_id: &str, generation: i64, message: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        let count = conn
            .execute(
                "UPDATE nodes SET sync_status = ?1, last_error = ?2
             WHERE cache_id = ?3 AND generation = ?4",
                params![SyncStatus::ERROR, message, cache_id, generation],
            )
            .unwrap_or(0);
        count == 1
    }

    /// Re-queue all nodes in `error` state back to `modified` and clear their diagnostics.
    pub fn retry_errors(&self) -> Result<usize, String> {
        let conn = self.conn.lock().unwrap();
        let count = conn
            .execute(
                "UPDATE nodes SET sync_status = ?1, last_error = NULL WHERE sync_status = ?2",
                params![SyncStatus::MODIFIED, SyncStatus::ERROR],
            )
            .map_err(|e| e.to_string())?;
        Ok(count)
    }

    /// Safely clear error diagnostics without discarding unuploaded local bytes.
    ///
    /// Returns `(cleared, requeued)`:
    /// - Nodes with an existing local cache file are re-queued as `modified` (`requeued`) so local
    ///   changes are never silently lost.
    /// - Nodes without a local file on disk are restored to `cloud_only` if `remote_exists == 1`,
    ///   or removed if neither remote nor local data exists (`cleared`).
    pub fn clear_errors(&self) -> Result<(usize, usize), String> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;

        let rows: Vec<(String, Option<String>, i64)> = {
            let mut stmt = tx
                .prepare(
                    "SELECT path, local_cache_path, remote_exists FROM nodes WHERE sync_status = ?1",
                )
                .map_err(|e| e.to_string())?;
            let mapped = stmt
                .query_map([SyncStatus::ERROR], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(|e| e.to_string())?;
            mapped
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        };

        let mut cleared = 0usize;
        let mut requeued = 0usize;
        for (path, local_cache_path, remote_exists) in rows {
            let has_local_file = local_cache_path
                .as_deref()
                .map(|p| Path::new(p).exists())
                .unwrap_or(false);

            if has_local_file {
                tx.execute(
                    "UPDATE nodes SET sync_status = ?1, last_error = NULL WHERE path = ?2 COLLATE BINARY",
                    params![SyncStatus::MODIFIED, path],
                )
                .map_err(|e| e.to_string())?;
                requeued += 1;
            } else if remote_exists != 0 {
                tx.execute(
                    "UPDATE nodes SET sync_status = ?1, local_cache_path = NULL, last_error = NULL WHERE path = ?2 COLLATE BINARY",
                    params![SyncStatus::CLOUD_ONLY, path],
                )
                .map_err(|e| e.to_string())?;
                cleared += 1;
            } else {
                tx.execute(
                    "DELETE FROM nodes WHERE path = ?1 COLLATE BINARY",
                    params![path],
                )
                .map_err(|e| e.to_string())?;
                cleared += 1;
            }
        }

        tx.commit().map_err(|e| e.to_string())?;
        Ok((cleared, requeued))
    }

    pub fn update_sync_status(
        &self,
        path: &str,
        status: &str,
        local_path: Option<&str>,
        error: Option<&str>,
    ) {
        let conn = self.conn.lock().unwrap();
        if let Some(lp) = local_path {
            let _ = conn.execute(
                "UPDATE nodes SET sync_status = ?1, local_cache_path = ?2, last_error = ?3
                 WHERE path = ?4 COLLATE BINARY",
                params![status, lp, error, path],
            );
        } else {
            let _ = conn.execute(
                "UPDATE nodes SET sync_status = ?1, last_error = ?2
                 WHERE path = ?3 COLLATE BINARY",
                params![status, error, path],
            );
        }
    }

    pub fn clear_local_cache(&self, path: &str) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "UPDATE nodes SET local_cache_path = NULL, sync_status = ?1, last_error = NULL
             WHERE path = ?2 COLLATE BINARY",
            params![SyncStatus::CLOUD_ONLY, path],
        );
    }

    pub fn update_last_checked(&self, path: &str) {
        let conn = self.conn.lock().unwrap();
        let now = now_sec();
        let _ = conn.execute(
            "UPDATE nodes SET last_checked = ?1 WHERE path = ?2 COLLATE BINARY",
            params![now, path],
        );
    }

    pub fn invalidate_node_cache(
        &self,
        path: &str,
        size: i64,
        mtime: Option<f64>,
        uid: Option<&str>,
        node_type: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = now_sec();
        conn.execute(
            "UPDATE nodes SET local_cache_path = NULL, sync_status = ?1, size = ?2, mtime = COALESCE(?3, mtime), uid = COALESCE(?4, uid), type = ?5, last_checked = ?6, last_error = NULL, remote_exists = 1 WHERE path = ?7 COLLATE BINARY",
            params![SyncStatus::CLOUD_ONLY, size, mtime, uid, node_type, now, path],
        )?;
        Ok(())
    }

    pub fn update_clean_remote_metadata(
        &self,
        path: &str,
        size: i64,
        mtime: Option<f64>,
        uid: Option<&str>,
        node_type: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = now_sec();
        conn.execute(
            "UPDATE nodes SET size = ?1, mtime = COALESCE(?2, mtime), uid = COALESCE(?3, uid), type = ?4, last_checked = ?5, remote_exists = 1 WHERE path = ?6 COLLATE BINARY",
            params![size, mtime, uid, node_type, now, path],
        )?;
        Ok(())
    }

    pub fn update_remote_exists(&self, path: &str, exists: bool) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let val = if exists { 1 } else { 0 };
        conn.execute(
            "UPDATE nodes SET remote_exists = ?1 WHERE path = ?2 COLLATE BINARY",
            params![val, path],
        )?;
        Ok(())
    }

    pub fn delete_node(&self, path: &str) {
        let prefix = format!("{}/", path.trim_end_matches('/'));
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "DELETE FROM nodes WHERE path = ?1 COLLATE BINARY OR substr(path, 1, ?2) = ?3 COLLATE BINARY",
            params![path, prefix.len(), prefix],
        );
    }

    pub fn move_subtree(&self, old_path: &str, new_path: &str) -> Result<(), String> {
        if old_path == "/" || new_path == "/" {
            return Err("Cannot move root directory".to_string());
        }

        let clean_old = old_path.trim_end_matches('/');
        let clean_new = new_path.trim_end_matches('/');
        let prefix = format!("{}/", clean_old);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;

        let rows: Vec<String> = {
            let mut stmt = tx
                .prepare(
                    "SELECT path FROM nodes WHERE path = ?1 COLLATE BINARY OR substr(path, 1, ?2) = ?3 COLLATE BINARY
                     ORDER BY length(path)",
                )
                .map_err(|e| e.to_string())?;

            let rows_res: Vec<String> = stmt
                .query_map(params![clean_old, prefix.len(), prefix], |row| row.get(0))
                .map_err(|e| e.to_string())?
                .filter_map(Result::ok)
                .collect();
            rows_res
        };

        if rows.is_empty() {
            return Err(format!("Node not found: {}", old_path));
        }

        let targets: Vec<(String, String)> = rows
            .into_iter()
            .map(|p| {
                let suffix = &p[clean_old.len()..];
                let target = format!("{}{}", clean_new, suffix);
                (p, target)
            })
            .collect();

        let token = format!("/.move-{}", generate_uuid());

        // First pass: rename to temporary unique token paths
        for (src, target) in targets.iter().rev() {
            let temp_target = format!("{}{}", token, target);
            tx.execute(
                "UPDATE nodes SET path = ?1 WHERE path = ?2 COLLATE BINARY",
                params![temp_target, src],
            )
            .map_err(|e| e.to_string())?;
        }

        if self.fail_move_subtree.load(Ordering::SeqCst) {
            return Err("Simulated move_subtree failure midway".to_string());
        }

        // Second pass: set to final target paths
        for (_, target) in &targets {
            let temp_target = format!("{}{}", token, target);
            let parent = Path::new(target)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let name = Path::new(target)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            tx.execute(
                "UPDATE nodes SET path = ?1, parent_path = ?2, name = ?3, mtime = ?4
                 WHERE path = ?5 COLLATE BINARY",
                params![target, parent, name, now_sec(), temp_target],
            )
            .map_err(|e| e.to_string())?;
        }

        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn set_setting(&self, key: &str, value: &str) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO settings(key, value) VALUES(?1, ?2)",
            params![key, value],
        );
    }

    pub fn get_setting(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT value FROM settings WHERE key = ?", [key], |row| {
            row.get(0)
        })
        .optional()
        .ok()
        .flatten()
    }

    pub fn clear(&self) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute("DELETE FROM nodes", []);
    }

    pub fn sync_storage(&self) -> Result<(), rusqlite::Error> {
        if self.fail_sync_storage.load(Ordering::SeqCst) {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(libc::EIO),
                Some("Simulated SQLite checkpoint failure".to_string()),
            ));
        }
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upsert_and_get_node() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = MetadataDB::new(&db_path).unwrap();

        db.upsert_node(
            "/my-files/test.txt",
            "/my-files",
            "test.txt",
            "file",
            1024,
            None,
            None,
            Some(SyncStatus::CLOUD_ONLY),
            None,
            None,
            None,
            None,
            Some(true),
            None,
        )
        .unwrap();

        let node = db
            .get_node("/my-files/test.txt")
            .expect("Node should exist");
        assert_eq!(node.name, "test.txt");
        assert_eq!(node.size, 1024);
        assert_eq!(node.node_type, "file");
        assert_eq!(node.sync_status, SyncStatus::CLOUD_ONLY);
        assert!(node.remote_exists);
    }

    #[test]
    fn test_get_children() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetadataDB::new(&dir.path().join("test.db")).unwrap();

        db.upsert_node(
            "/my-files",
            "/",
            "my-files",
            "folder",
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        db.upsert_node(
            "/my-files/a.txt",
            "/my-files",
            "a.txt",
            "file",
            10,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        db.upsert_node(
            "/my-files/b.txt",
            "/my-files",
            "b.txt",
            "file",
            20,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        db.upsert_node(
            "/my-files/sub",
            "/my-files",
            "sub",
            "folder",
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let children = db.get_children("/my-files");
        assert_eq!(children.len(), 3);
        let names: Vec<String> = children.into_iter().map(|c| c.name).collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));
    }

    #[test]
    fn test_delete_node_cascade() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetadataDB::new(&dir.path().join("test.db")).unwrap();

        db.upsert_node(
            "/folder", "/", "folder", "folder", 0, None, None, None, None, None, None, None, None,
            None,
        )
        .unwrap();
        db.upsert_node(
            "/folder/child.txt",
            "/folder",
            "child.txt",
            "file",
            10,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        db.delete_node("/folder");
        assert!(db.get_node("/folder").is_none());
        assert!(db.get_node("/folder/child.txt").is_none());
    }

    #[test]
    fn test_move_subtree() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetadataDB::new(&dir.path().join("test.db")).unwrap();

        db.upsert_node(
            "/old", "/", "old", "folder", 0, None, None, None, None, None, None, None, None, None,
        )
        .unwrap();
        db.upsert_node(
            "/old/child.txt",
            "/old",
            "child.txt",
            "file",
            10,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        db.move_subtree("/old", "/new").unwrap();
        assert!(db.get_node("/old").is_none());
        assert!(db.get_node("/old/child.txt").is_none());
        assert!(db.get_node("/new").is_some());
        assert!(db.get_node("/new/child.txt").is_some());
    }

    #[test]
    fn test_sync_storage() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetadataDB::new(&dir.path().join("test.db")).unwrap();
        assert!(db.sync_storage().is_ok());

        db.set_fail_sync_storage(true);
        assert!(db.sync_storage().is_err());

        db.set_fail_sync_storage(false);
        assert!(db.sync_storage().is_ok());
    }

    #[test]
    fn test_retry_errors_and_clear_errors_preserve_local_data() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetadataDB::new(&dir.path().join("test.db")).unwrap();

        let existing_local = dir.path().join("dirty.txt");
        std::fs::write(&existing_local, b"unsaved local edits").unwrap();

        // 1. Node with existing local edits on disk
        db.upsert_node(
            "/dirty.txt",
            "/",
            "dirty.txt",
            "file",
            19,
            None,
            Some(existing_local.to_str().unwrap()),
            Some(SyncStatus::ERROR),
            None,
            None,
            None,
            None,
            Some(false),
            Some("network timeout"),
        )
        .unwrap();

        // 2. Remote-only node whose local cache file disappeared
        db.upsert_node(
            "/stale_remote.txt",
            "/",
            "stale_remote.txt",
            "file",
            10,
            None,
            Some("/nonexistent/stale_remote.txt"),
            Some(SyncStatus::ERROR),
            None,
            None,
            None,
            None,
            Some(true),
            Some("cache missing"),
        )
        .unwrap();

        // 3. Orphaned non-remote node whose local file disappeared
        db.upsert_node(
            "/orphan.txt",
            "/",
            "orphan.txt",
            "file",
            0,
            None,
            Some("/nonexistent/orphan.txt"),
            Some(SyncStatus::ERROR),
            None,
            None,
            None,
            None,
            Some(false),
            Some("local file missing"),
        )
        .unwrap();

        assert_eq!(db.get_sync_counts(), (0, 3));

        // clear_errors preserves local edits by re-queuing them, restores remote-only, drops orphan
        let (cleared, requeued) = db.clear_errors().unwrap();
        assert_eq!(cleared, 2);
        assert_eq!(requeued, 1);
        assert_eq!(db.get_sync_counts(), (1, 0));

        let dirty = db.get_node("/dirty.txt").unwrap();
        assert_eq!(dirty.sync_status, SyncStatus::MODIFIED);
        assert!(dirty.last_error.is_none());

        let stale = db.get_node("/stale_remote.txt").unwrap();
        assert_eq!(stale.sync_status, SyncStatus::CLOUD_ONLY);
        assert!(stale.local_cache_path.is_none());
        assert!(stale.last_error.is_none());

        assert!(db.get_node("/orphan.txt").is_none());

        // retry_errors moves error rows back to modified and clears last_error
        db.update_sync_status("/dirty.txt", SyncStatus::ERROR, None, Some("503"));
        assert_eq!(db.get_sync_counts(), (0, 1));
        assert_eq!(db.retry_errors().unwrap(), 1);
        assert_eq!(db.get_sync_counts(), (1, 0));
        assert!(db.get_node("/dirty.txt").unwrap().last_error.is_none());
    }
}
