mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rusqlite::Connection;
use support::{MetadataDB, SyncStatus};

#[test]
fn test_fresh_schema_initialization_and_private_permissions() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_parent = temp_dir.path().join("secure_db_dir");
    let db_path = db_parent.join("fresh_metadata.db");

    let db = MetadataDB::new(&db_path).expect("Fresh database should initialize successfully");

    // Verify parent directory permissions (0700)
    let parent_meta = fs::symlink_metadata(&db_parent).unwrap();
    assert_eq!(
        parent_meta.permissions().mode() & 0o777,
        0o700,
        "Parent directory permissions must be 0700"
    );

    // Verify database file permissions (0600)
    let db_meta = fs::symlink_metadata(&db_path).unwrap();
    assert_eq!(
        db_meta.permissions().mode() & 0o777,
        0o600,
        "Database file permissions must be 0600"
    );

    // Verify schema version
    assert_eq!(
        db.schema_version().unwrap(),
        MetadataDB::CURRENT_SCHEMA_VERSION,
        "Schema version must be current"
    );
    assert_eq!(
        db.get_setting("schema_version"),
        Some(MetadataDB::CURRENT_SCHEMA_VERSION.to_string()),
        "Settings table must record current schema_version"
    );

    // Verify nodes table columns and indexes via raw connection
    let conn = Connection::open(&db_path).unwrap();

    let mut stmt = conn.prepare("PRAGMA table_info(nodes)").unwrap();
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    let required_columns = [
        "path",
        "parent_path",
        "name",
        "type",
        "size",
        "mtime",
        "local_cache_path",
        "sync_status",
        "etag",
        "uid",
        "last_checked",
        "cache_id",
        "generation",
        "remote_exists",
        "last_error",
        "volume_id",
        "share_id",
        "link_id",
        "parent_link_id",
        "revision_id",
        "name_hash",
    ];
    for col in &required_columns {
        assert!(
            cols.iter().any(|c| c.eq_ignore_ascii_case(col)),
            "Column {} must exist in nodes table",
            col
        );
    }

    let mut index_stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index'")
        .unwrap();
    let indexes: Vec<String> = index_stmt
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert!(indexes.contains(&"idx_parent_path".to_string()));
    assert!(indexes.contains(&"idx_sync_status".to_string()));
    assert!(indexes.contains(&"idx_cache_id".to_string()));
    assert!(indexes.contains(&"idx_link_id".to_string()));
}

#[test]
fn test_pre_cache_id_legacy_schema_migration() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("legacy.db");

    // Create a pre-cache-id legacy database missing cache_id, generation, remote_exists, last_error
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
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
                last_checked REAL
            );
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status, etag, uid, last_checked)
            VALUES ('/file1.txt', '/', 'file1.txt', 'file', 1234, 1000.0, '/cache/file1', 'synced', 'etag1', 'uid1', 1000.0);
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status, etag, uid, last_checked)
            VALUES ('/file2.txt', '/', 'file2.txt', 'file', 5678, 2000.0, NULL, 'cloud_only', 'etag2', 'uid2', 2000.0);",
        )
        .unwrap();
    }

    // Open via MetadataDB::new, which executes transactional migration
    let db = MetadataDB::new(&db_path).expect("Legacy database should migrate successfully");

    // Verify row 1 was preserved and updated
    let node1 = db.get_node("/file1.txt").expect("Node 1 must exist");
    assert_eq!(node1.name, "file1.txt");
    assert_eq!(node1.size, 1234);
    assert_eq!(node1.sync_status, SyncStatus::SYNCED);
    assert_eq!(node1.etag.as_deref(), Some("etag1"));
    assert_eq!(node1.uid.as_deref(), Some("uid1"));
    assert!(!node1.cache_id.is_empty(), "cache_id must be assigned");
    assert_eq!(node1.generation, 0, "default generation must be 0");
    assert!(node1.remote_exists, "default remote_exists must be true");
    assert_eq!(node1.last_error, None);

    // Verify row 2 was preserved and assigned a distinct cache_id
    let node2 = db.get_node("/file2.txt").expect("Node 2 must exist");
    assert_eq!(node2.name, "file2.txt");
    assert_eq!(node2.size, 5678);
    assert_eq!(node2.sync_status, SyncStatus::CLOUD_ONLY);
    assert!(!node2.cache_id.is_empty(), "cache_id must be assigned");
    assert_ne!(
        node1.cache_id, node2.cache_id,
        "Distinct rows must receive distinct UUIDs"
    );

    // Verify unique index on cache_id was created and works
    let conn = Connection::open(&db_path).unwrap();
    let has_index: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_cache_id')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(has_index, "idx_cache_id must be created");

    // Verify schema version is bumped
    assert_eq!(
        db.schema_version().unwrap(),
        MetadataDB::CURRENT_SCHEMA_VERSION
    );
}

#[test]
fn test_ambiguous_legacy_cache_paths_marked_error() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("duplicate_paths.db");

    // Create legacy table with duplicate local_cache_path references
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
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
                last_checked REAL
            );
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status)
            VALUES ('/dup1.txt', '/', 'dup1.txt', 'file', 100, 1000.0, '/cache/conflict.dat', 'synced');
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status)
            VALUES ('/dup2.txt', '/', 'dup2.txt', 'file', 200, 1000.0, '/cache/conflict.dat', 'synced');
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status)
            VALUES ('/unique.txt', '/', 'unique.txt', 'file', 300, 1000.0, '/cache/unique.dat', 'synced');
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status)
            VALUES ('/no_cache.txt', '/', 'no_cache.txt', 'file', 400, 1000.0, NULL, 'cloud_only');",
        )
        .unwrap();
    }

    let db = MetadataDB::new(&db_path).expect("Database should migrate successfully");

    // Both nodes sharing /cache/conflict.dat should be marked with error
    let dup1 = db.get_node("/dup1.txt").unwrap();
    assert_eq!(dup1.sync_status, SyncStatus::ERROR);
    assert_eq!(
        dup1.last_error.as_deref(),
        Some("ambiguous legacy cache reference")
    );

    let dup2 = db.get_node("/dup2.txt").unwrap();
    assert_eq!(dup2.sync_status, SyncStatus::ERROR);
    assert_eq!(
        dup2.last_error.as_deref(),
        Some("ambiguous legacy cache reference")
    );

    // Unique local_cache_path should remain unaffected
    let unique = db.get_node("/unique.txt").unwrap();
    assert_eq!(unique.sync_status, SyncStatus::SYNCED);
    assert_eq!(unique.last_error, None);

    // Node without local_cache_path should remain unaffected
    let no_cache = db.get_node("/no_cache.txt").unwrap();
    assert_eq!(no_cache.sync_status, SyncStatus::CLOUD_ONLY);
    assert_eq!(no_cache.last_error, None);
}

#[test]
fn test_interrupted_syncing_row_recovered_to_modified() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("crash_recovery.db");

    // Populate a database with nodes in various sync statuses, including interrupted 'syncing'
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
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
                last_error TEXT
            );
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status, cache_id, generation, remote_exists)
            VALUES ('/interrupted_upload.bin', '/', 'interrupted_upload.bin', 'file', 4096, 5000.0, '/cache/upload.bin', 'syncing', 'cache-uuid-xyz-42', 42, 1);
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status, cache_id, generation, remote_exists)
            VALUES ('/normal_synced.txt', '/', 'normal_synced.txt', 'file', 512, 5000.0, '/cache/normal.txt', 'synced', 'cache-uuid-abc-10', 10, 1);
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status, cache_id, generation, remote_exists)
            VALUES ('/cloud_file.txt', '/', 'cloud_file.txt', 'file', 1024, 5000.0, NULL, 'cloud_only', 'cache-uuid-cld-1', 0, 1);",
        )
        .unwrap();
    }

    // Startup MetadataDB - crash recovery must run
    let db = MetadataDB::new(&db_path).expect("MetadataDB should open and run crash recovery");

    // The interrupted upload must be transitioned from 'syncing' to 'modified'
    let interrupted = db.get_node("/interrupted_upload.bin").unwrap();
    assert_eq!(
        interrupted.sync_status,
        SyncStatus::MODIFIED,
        "Interrupted syncing node must be recovered to modified"
    );
    assert_eq!(
        interrupted.generation, 42,
        "Interrupted upload must retain its original generation"
    );
    assert_eq!(
        interrupted.cache_id, "cache-uuid-xyz-42",
        "Interrupted upload must retain its original cache_id"
    );
    assert!(interrupted.remote_exists);

    // Other nodes should remain untouched
    let synced = db.get_node("/normal_synced.txt").unwrap();
    assert_eq!(synced.sync_status, SyncStatus::SYNCED);
    assert_eq!(synced.generation, 10);

    let cloud = db.get_node("/cloud_file.txt").unwrap();
    assert_eq!(cloud.sync_status, SyncStatus::CLOUD_ONLY);
}

#[test]
fn test_migration_rollback_on_failure() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("failing_migration.db");

    // Step 1: Create legacy database with sample rows and install an abort trigger
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
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
                last_checked REAL
            );
            INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status)
            VALUES ('/preserved.txt', '/', 'preserved.txt', 'file', 999, 123.0, '/cache/p.dat', 'synced');
            
            -- Trigger that forces an abort when UPDATE runs during migration (e.g. cache_id assignment)
            CREATE TRIGGER fail_migration BEFORE UPDATE ON nodes BEGIN
                SELECT RAISE(ABORT, 'forced test failure in migration step');
            END;",
        )
        .unwrap();
    }

    // Opening with MetadataDB::new should fail because of the trigger
    let result = MetadataDB::new(&db_path);
    assert!(
        result.is_err(),
        "MetadataDB::new should return Err when migration fails"
    );

    // Verify original database is intact and changes were rolled back
    let conn = Connection::open(&db_path).unwrap();

    let user_version: u32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(user_version, 0, "Schema version must not have been bumped");

    let mut stmt = conn.prepare("PRAGMA table_info(nodes)").unwrap();
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert!(
        !cols.contains(&"cache_id".to_string()),
        "cache_id column must not exist after rollback"
    );
    assert!(
        !cols.contains(&"generation".to_string()),
        "generation column must not exist after rollback"
    );
    assert!(
        !cols.contains(&"remote_exists".to_string()),
        "remote_exists column must not exist after rollback"
    );
    assert!(
        !cols.contains(&"last_error".to_string()),
        "last_error column must not exist after rollback"
    );

    let preserved_name: String = conn
        .query_row(
            "SELECT name FROM nodes WHERE path = '/preserved.txt'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        preserved_name, "preserved.txt",
        "Original data must be intact"
    );

    // Step 2: Also verify programmatic rollback via migrate_with_hook
    let hook_db_path = temp_dir.path().join("hook_migration.db");
    let mut hook_conn = Connection::open(&hook_db_path).unwrap();
    hook_conn
        .execute_batch(
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
                last_checked REAL
            );
            INSERT INTO nodes (path, parent_path, name, type, size, mtime)
            VALUES ('/data.txt', '/', 'data.txt', 'file', 42, 10.0);",
        )
        .unwrap();

    let hook_result = MetadataDB::migrate_with_hook(&mut hook_conn, |step| {
        if step == "after_add_columns" {
            Err(rusqlite::Error::ExecuteReturnedResults)
        } else {
            Ok(())
        }
    });
    assert!(hook_result.is_err(), "Hook failure must return Err");

    let hook_version: u32 = hook_conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        hook_version, 0,
        "Version must remain 0 after hook failure rollback"
    );

    let mut stmt2 = hook_conn.prepare("PRAGMA table_info(nodes)").unwrap();
    let cols2: Vec<String> = stmt2
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        !cols2.contains(&"cache_id".to_string()),
        "Columns added before failure must be rolled back"
    );
}

#[test]
fn test_symlink_and_unowned_path_rejection() {
    let temp_dir = tempfile::tempdir().unwrap();

    // 1. Database file is a symlink to an existing file
    let real_db = temp_dir.path().join("real.db");
    fs::write(&real_db, b"").unwrap();
    let symlink_db = temp_dir.path().join("symlink.db");
    std::os::unix::fs::symlink(&real_db, &symlink_db).unwrap();

    let err = MetadataDB::new(&symlink_db);
    assert!(
        err.is_err(),
        "MetadataDB::new must reject a symlinked database file"
    );

    // 2. Database file is a broken symlink
    let broken_db = temp_dir.path().join("broken_link.db");
    std::os::unix::fs::symlink(temp_dir.path().join("nonexistent_target.db"), &broken_db).unwrap();

    let err_broken = MetadataDB::new(&broken_db);
    assert!(
        err_broken.is_err(),
        "MetadataDB::new must reject a broken symlink database file"
    );

    // 3. Parent directory is a symlink
    let real_dir = temp_dir.path().join("real_parent_dir");
    fs::create_dir(&real_dir).unwrap();
    let symlink_dir = temp_dir.path().join("symlink_parent_dir");
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

    let db_in_symlink_parent = symlink_dir.join("test.db");
    let err_parent = MetadataDB::new(&db_in_symlink_parent);
    assert!(
        err_parent.is_err(),
        "MetadataDB::new must reject a database inside a symlinked parent directory"
    );

    // 4. Unowned directory rejection: /proc/1 is owned by root (UID 0 != 1000)
    let proc_path = Path::new("/proc/1/metadata.db");
    let err_unowned = MetadataDB::new(proc_path);
    assert!(
        err_unowned.is_err(),
        "MetadataDB::new must reject paths inside unowned parent directories"
    );

    // 5. Database path is an existing directory instead of a regular file
    let dir_as_db = temp_dir.path().join("directory_as_db");
    fs::create_dir(&dir_as_db).unwrap();
    let err_dir = MetadataDB::new(&dir_as_db);
    assert!(
        err_dir.is_err(),
        "MetadataDB::new must reject a directory passed as db_path"
    );
}

#[test]
fn test_reopening_already_migrated_database() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("reopen.db");

    // First open initializes the database
    {
        let db = MetadataDB::new(&db_path).unwrap();
        db.upsert_node(
            "/test.txt",
            "/",
            "test.txt",
            "file",
            100,
            None,
            Some("/cache/test.txt"),
            Some(SyncStatus::SYNCING),
            None,
            None,
            None,
            Some(5),
            Some(true),
            None,
        )
        .unwrap();
    }

    // Reopen the database - should not fail, should preserve version, and should recover 'syncing' node
    let db2 = MetadataDB::new(&db_path).expect("Reopening already migrated DB must succeed");
    assert_eq!(
        db2.schema_version().unwrap(),
        MetadataDB::CURRENT_SCHEMA_VERSION
    );

    let node = db2.get_node("/test.txt").unwrap();
    assert_eq!(
        node.sync_status,
        SyncStatus::MODIFIED,
        "Interrupted node must be recovered to modified on reopen"
    );
    assert_eq!(node.generation, 5);
}

#[test]
fn test_v1_to_v2_native_columns_migration() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("v1_native.db");

    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO settings (key, value) VALUES ('schema_version', '1');
             CREATE TABLE nodes (
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
                 last_error TEXT
             );
             INSERT INTO nodes (path, parent_path, name, type, size, mtime, local_cache_path, sync_status, cache_id, generation, remote_exists)
             VALUES ('/doc.txt', '/', 'doc.txt', 'file', 42, 1234.0, NULL, 'cloud_only', 'cid-v1-1', 3, 1);
             PRAGMA user_version = 1;",
        )
        .unwrap();
    }

    let db = MetadataDB::new(&db_path).expect("v1 -> v3 migration must succeed");
    assert_eq!(
        db.schema_version().unwrap(),
        MetadataDB::CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        db.get_setting("schema_version").as_deref(),
        Some(MetadataDB::CURRENT_SCHEMA_VERSION.to_string().as_str())
    );

    let migrated = db.get_node("/doc.txt").expect("Migrated row must exist");
    assert_eq!(migrated.cache_id, "cid-v1-1");
    assert_eq!(migrated.generation, 3);
    assert_eq!(migrated.volume_id, None);
    assert_eq!(migrated.link_id, None);

    db.upsert_native_ids(
        "/doc.txt",
        Some("vol-1"),
        Some("share-1"),
        Some("link-1"),
        Some("root-link"),
        Some("rev-1"),
        Some("hash-1"),
    )
    .expect("upsert_native_ids must succeed");

    let by_vol = db
        .get_node_by_link_id("vol-1", "link-1")
        .expect("get_node_by_link_id must find node");
    assert_eq!(by_vol.path, "/doc.txt");
    assert_eq!(by_vol.share_id.as_deref(), Some("share-1"));
    assert_eq!(by_vol.revision_id.as_deref(), Some("rev-1"));
    assert_eq!(by_vol.name_hash.as_deref(), Some("hash-1"));

    let by_only = db
        .get_node_by_only_link_id("link-1")
        .expect("get_node_by_only_link_id must find node");
    assert_eq!(by_only.path, "/doc.txt");
}

#[test]
fn test_migration_v2_to_v3_adds_pinned_column_with_default_false() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("v2.db");

    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
             CREATE TABLE nodes (
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
             );
             INSERT INTO nodes (
                 path, parent_path, name, type, size, mtime, local_cache_path,
                 sync_status, cache_id, generation, remote_exists, volume_id, link_id
             ) VALUES (
                 '/v2-file.txt', '/', 'v2-file.txt', 'file', 99, 1000.0, NULL,
                 'cloud_only', 'cid-v2-1', 2, 1, 'vol-2', 'link-2'
             );
             PRAGMA user_version = 2;",
        )
        .unwrap();
    }

    let db = MetadataDB::new(&db_path).expect("v2 -> v3 migration must succeed");
    assert_eq!(db.schema_version().unwrap(), 3);
    assert_eq!(db.get_setting("schema_version").as_deref(), Some("3"));

    let migrated = db
        .get_node("/v2-file.txt")
        .expect("Migrated v2 row must exist");
    assert_eq!(migrated.cache_id, "cid-v2-1");
    assert_eq!(migrated.link_id.as_deref(), Some("link-2"));
    assert!(!migrated.pinned, "Existing rows must default pinned=false");
    assert!(db.list_pinned_paths().is_empty());

    assert_eq!(db.set_pinned("/v2-file.txt", true), Ok(true));
    assert!(db.get_node("/v2-file.txt").unwrap().pinned);
    assert_eq!(db.list_pinned_paths(), vec!["/v2-file.txt".to_string()]);
}
