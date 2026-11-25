mod support;

use support::{MetadataDB, SyncStatus, TestFixture};

#[test]
fn test_cross_parent_rename_succeeds_with_sequenced_remote_calls() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let _ = fuse.create_dir("/", "a").expect("create /a");
    let _ = fuse.create_dir("/", "b").expect("create /b");

    fixture
        .db
        .upsert_node(
            "/a/old",
            "/a",
            "old",
            "file",
            100,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("old-cache-id"),
            Some(1),
            Some(true), // remote_exists = true
            None,
        )
        .expect("upsert /a/old");

    let old_ino = fuse.get_or_create_inode("/a/old");
    fixture.fake_remote.clear_recorded_calls();

    // Cross-parent rename: parent changes (/a -> /b) AND name changes (old -> new)
    let res = fuse.rename_node("/a", "old", "/b", "new");
    assert_eq!(res, Ok(()));

    // Verify remote calls: rename in /a to new, then move /a/new to /b
    let rename_calls = fixture.fake_remote.rename_calls();
    assert_eq!(rename_calls.len(), 1);
    assert_eq!(rename_calls[0].remote_path, "/my-files/a/old");
    assert_eq!(rename_calls[0].new_name, "new");

    let move_calls = fixture.fake_remote.move_node_calls();
    assert_eq!(move_calls.len(), 1);
    assert_eq!(move_calls[0].source_path, "/my-files/a/new");
    assert_eq!(move_calls[0].target_parent_path, "/my-files/b");

    // Verify local DB updated and cache_id preserved
    assert!(fixture.db.get_node("/a/old").is_none());
    let moved = fixture
        .db
        .get_node("/b/new")
        .expect("node exists at /b/new");
    assert_eq!(moved.parent_path, "/b");
    assert_eq!(moved.name, "new");
    assert_eq!(moved.cache_id, "old-cache-id");
    assert_eq!(fuse.get_path_for_inode(old_ino), Some("/b/new".to_string()));
}

#[test]
fn test_separate_move_and_rename_succeed_with_remote_calls() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let _ = fuse.create_dir("/", "a").expect("create /a");
    let _ = fuse.create_dir("/", "b").expect("create /b");

    // File for moving: /a/file -> /b/file
    fixture
        .db
        .upsert_node(
            "/a/file",
            "/a",
            "file",
            "file",
            100,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("move-file-id"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert /a/file");

    let file_ino = fuse.get_or_create_inode("/a/file");

    fixture.fake_remote.clear_recorded_calls();
    let move_res = fuse.rename_node("/a", "file", "/b", "file");
    assert_eq!(move_res, Ok(()));

    // Verify remote move call recorded
    let move_calls = fixture.fake_remote.move_node_calls();
    assert_eq!(move_calls.len(), 1);
    assert_eq!(move_calls[0].source_path, "/my-files/a/file");
    assert_eq!(move_calls[0].target_parent_path, "/my-files/b");

    // Verify local DB
    assert!(fixture.db.get_node("/a/file").is_none());
    let moved_node = fixture
        .db
        .get_node("/b/file")
        .expect("node exists at /b/file");
    assert_eq!(moved_node.parent_path, "/b");
    assert_eq!(moved_node.name, "file");
    assert_eq!(moved_node.cache_id, "move-file-id");

    // Verify inode mapping updated
    assert_eq!(
        fuse.get_path_for_inode(file_ino),
        Some("/b/file".to_string())
    );
    assert_eq!(fuse.get_inode_for_path("/b/file"), Some(file_ino));
    assert_eq!(fuse.get_inode_for_path("/a/file"), None);

    // File for renaming: /a/file1 -> /a/file2
    fixture
        .db
        .upsert_node(
            "/a/file1",
            "/a",
            "file1",
            "file",
            200,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("rename-file-id"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert /a/file1");

    let rename_ino = fuse.get_or_create_inode("/a/file1");

    fixture.fake_remote.clear_recorded_calls();
    let rename_res = fuse.rename_node("/a", "file1", "/a", "file2");
    assert_eq!(rename_res, Ok(()));

    // Verify remote rename call recorded
    let rename_calls = fixture.fake_remote.rename_calls();
    assert_eq!(rename_calls.len(), 1);
    assert_eq!(rename_calls[0].remote_path, "/my-files/a/file1");
    assert_eq!(rename_calls[0].new_name, "file2");

    // Verify local DB
    assert!(fixture.db.get_node("/a/file1").is_none());
    let renamed_node = fixture
        .db
        .get_node("/a/file2")
        .expect("node exists at /a/file2");
    assert_eq!(renamed_node.parent_path, "/a");
    assert_eq!(renamed_node.name, "file2");
    assert_eq!(renamed_node.cache_id, "rename-file-id");

    // Verify inode mapping updated
    assert_eq!(
        fuse.get_path_for_inode(rename_ino),
        Some("/a/file2".to_string())
    );
    assert_eq!(fuse.get_inode_for_path("/a/file2"), Some(rename_ino));
    assert_eq!(fuse.get_inode_for_path("/a/file1"), None);
}

#[test]
fn test_atomic_overwrite_trashes_target_and_replaces_node() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    fixture
        .db
        .upsert_node(
            "/file1.txt",
            "/",
            "file1.txt",
            "file",
            50,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("file1-id"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert /file1.txt");

    fixture
        .db
        .upsert_node(
            "/file2.txt",
            "/",
            "file2.txt",
            "file",
            50,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("file2-id"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert /file2.txt");

    let file1_ino = fuse.get_or_create_inode("/file1.txt");
    let _file2_ino = fuse.get_or_create_inode("/file2.txt");
    fixture.fake_remote.clear_recorded_calls();

    let res = fuse.rename_node("/", "file1.txt", "/", "file2.txt");
    assert_eq!(res, Ok(()));

    // Verify target was trashed and source renamed
    let trash_calls = fixture.fake_remote.trash_calls();
    assert_eq!(trash_calls.len(), 1);
    assert_eq!(trash_calls[0].remote_path, "/my-files/file2.txt");

    let rename_calls = fixture.fake_remote.rename_calls();
    assert_eq!(rename_calls.len(), 1);
    assert_eq!(rename_calls[0].remote_path, "/my-files/file1.txt");
    assert_eq!(rename_calls[0].new_name, "file2.txt");

    // Verify local DB and inode mappings
    assert!(fixture.db.get_node("/file1.txt").is_none());
    let replaced = fixture
        .db
        .get_node("/file2.txt")
        .expect("/file2.txt exists");
    assert_eq!(replaced.cache_id, "file1-id");
    assert_eq!(
        fuse.get_path_for_inode(file1_ino),
        Some("/file2.txt".to_string())
    );
}

#[test]
fn test_atomic_overwrite_rejects_type_mismatch_and_nonempty_dir() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let _ = fuse
        .create_dir("/", "dir_target")
        .expect("create /dir_target");
    fixture
        .db
        .upsert_node(
            "/dir_target/child.txt",
            "/dir_target",
            "child.txt",
            "file",
            10,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("child-id"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert /dir_target/child.txt");
    fixture
        .db
        .upsert_node(
            "/src.txt",
            "/",
            "src.txt",
            "file",
            10,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("src-id"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert /src.txt");
    let _ = fuse.create_dir("/", "src_dir").expect("create /src_dir");

    // File overwriting directory -> EISDIR
    assert_eq!(
        fuse.rename_node("/", "src.txt", "/", "dir_target"),
        Err(libc::EISDIR)
    );
    // Directory overwriting file -> ENOTDIR
    assert_eq!(
        fuse.rename_node("/", "src_dir", "/", "src.txt"),
        Err(libc::ENOTDIR)
    );

    // Non-empty directory overwrite -> ENOTEMPTY
    let _ = fuse
        .create_dir("/", "empty_src")
        .expect("create /empty_src");
    assert_eq!(
        fuse.rename_node("/", "empty_src", "/", "dir_target"),
        Err(libc::ENOTEMPTY)
    );
}

#[test]
fn test_cross_parent_rename_rolls_back_first_step_when_second_step_fails() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let _ = fuse.create_dir("/", "a").expect("create /a");
    let _ = fuse.create_dir("/", "b").expect("create /b");

    fixture
        .db
        .upsert_node(
            "/a/old",
            "/a",
            "old",
            "file",
            100,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("rollback-id"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert /a/old");

    fixture.fake_remote.clear_recorded_calls();
    fixture.fake_remote.set_move_node_result(false);

    let res = fuse.rename_node("/a", "old", "/b", "new");
    assert_eq!(res, Err(libc::EIO));

    // Rename forward + move (failed) + rename rollback
    let rename_calls = fixture.fake_remote.rename_calls();
    assert_eq!(rename_calls.len(), 2);
    assert_eq!(rename_calls[0].remote_path, "/my-files/a/old");
    assert_eq!(rename_calls[0].new_name, "new");
    assert_eq!(rename_calls[1].remote_path, "/my-files/a/new");
    assert_eq!(rename_calls[1].new_name, "old");

    // Local DB remains intact
    assert!(fixture.db.get_node("/a/old").is_some());
    assert!(fixture.db.get_node("/b/new").is_none());
}

#[test]
fn test_inflight_file_and_descendant_fail_with_ebusy() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    // 1. Inflight single file
    fixture
        .db
        .upsert_node(
            "/busy_file.txt",
            "/",
            "busy_file.txt",
            "file",
            100,
            None,
            None,
            Some(SyncStatus::SYNCING),
            None,
            None,
            Some("busy-file-id"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert /busy_file.txt");

    fixture.activity.mark_inflight("busy-file-id");
    fixture.fake_remote.clear_recorded_calls();

    let res = fuse.rename_node("/", "busy_file.txt", "/", "busy_file_renamed.txt");
    assert_eq!(res, Err(libc::EBUSY));
    assert_eq!(fixture.fake_remote.recorded_calls().len(), 0);
    assert!(fixture.db.get_node("/busy_file.txt").is_some());
    assert!(fixture.db.get_node("/busy_file_renamed.txt").is_none());

    fixture.activity.remove_inflight("busy-file-id");

    // 2. Inflight descendant in folder
    let _ = fuse
        .create_dir("/", "parent_dir")
        .expect("create parent_dir");
    let _ = fuse
        .create_dir("/parent_dir", "sub_dir")
        .expect("create sub_dir");

    fixture
        .db
        .upsert_node(
            "/parent_dir/sub_dir/child.txt",
            "/parent_dir/sub_dir",
            "child.txt",
            "file",
            200,
            None,
            None,
            Some(SyncStatus::SYNCING),
            None,
            None,
            Some("child-cache-id"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert child.txt");

    fixture.activity.mark_inflight("child-cache-id");
    fixture.fake_remote.clear_recorded_calls();

    // Try renaming the root parent folder
    let res_dir = fuse.rename_node("/", "parent_dir", "/", "new_parent_dir");
    assert_eq!(res_dir, Err(libc::EBUSY));
    assert_eq!(fixture.fake_remote.recorded_calls().len(), 0);
    assert!(fixture.db.get_node("/parent_dir").is_some());
    assert!(fixture.db.get_node("/new_parent_dir").is_none());
    assert!(fixture
        .db
        .get_node("/parent_dir/sub_dir/child.txt")
        .is_some());

    fixture.activity.remove_inflight("child-cache-id");
}

#[test]
fn test_local_dirty_file_rename_preserves_cache_status_and_handle() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    // Create file via FUSE handle
    let fh = fuse
        .create_file_handle("/", "dirty_doc.txt")
        .expect("create handle");
    fuse.write_to_handle(fh, 0, b"dirty initial content")
        .expect("write to handle");

    let initial_node = fixture.db.get_node("/dirty_doc.txt").expect("node exists");
    let initial_cache_id = initial_node.cache_id.clone();
    let initial_gen = initial_node.generation;
    assert_eq!(initial_node.sync_status, SyncStatus::MODIFIED);
    let cache_file_path = fixture.cache_dir.join(format!("{}.dat", initial_cache_id));
    assert!(cache_file_path.exists());

    let ino = fuse.get_or_create_inode("/dirty_doc.txt");

    // Rename the dirty file
    let rename_res = fuse.rename_node("/", "dirty_doc.txt", "/", "renamed_doc.txt");
    assert_eq!(rename_res, Ok(()));

    // Verify local DB
    assert!(fixture.db.get_node("/dirty_doc.txt").is_none());
    let renamed_node = fixture
        .db
        .get_node("/renamed_doc.txt")
        .expect("renamed node exists");
    assert_eq!(renamed_node.sync_status, SyncStatus::MODIFIED);
    assert_eq!(renamed_node.cache_id, initial_cache_id);
    assert_eq!(renamed_node.generation, initial_gen);
    assert_eq!(renamed_node.name, "renamed_doc.txt");
    assert_eq!(renamed_node.parent_path, "/");

    // Local cache file must still exist
    assert!(cache_file_path.exists());
    let on_disk_content = std::fs::read(&cache_file_path).expect("read cache file");
    assert_eq!(on_disk_content, b"dirty initial content");

    // Open handle in ActivityRegistry must be updated
    {
        let handles = fixture.activity.open_handles.lock().unwrap();
        let handle = handles.get(&fh).expect("handle still exists");
        assert_eq!(handle.path, "/renamed_doc.txt");
        assert_eq!(handle.cache_id, initial_cache_id);
    }

    // Inode mapping must be updated
    assert_eq!(
        fuse.get_path_for_inode(ino),
        Some("/renamed_doc.txt".to_string())
    );
    assert_eq!(fuse.get_inode_for_path("/renamed_doc.txt"), Some(ino));

    // Can still write via the handle after rename
    fuse.write_to_handle(fh, 21, b" appended")
        .expect("write after rename");
    let content_after = std::fs::read(&cache_file_path).expect("read after append");
    assert_eq!(content_after, b"dirty initial content appended");

    // Close handle cleanly
    fuse.release_handle(fh).expect("release handle");
}

#[test]
fn test_folder_rename_preserves_descendants_across_db_restart() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let _ = fuse.create_dir("/", "work").expect("create /work");
    let _ = fuse
        .create_dir("/work", "projects")
        .expect("create /work/projects");

    let cache_id_f1 = "descendant-f1-uuid";
    let cache_id_f2 = "descendant-f2-uuid";

    fixture
        .db
        .upsert_node(
            "/work/notes.txt",
            "/work",
            "notes.txt",
            "file",
            123,
            None,
            Some(
                &fixture
                    .cache_dir
                    .join(format!("{}.dat", cache_id_f1))
                    .to_string_lossy(),
            ),
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some(cache_id_f1),
            Some(3),
            Some(true),
            None,
        )
        .expect("upsert notes.txt");

    fixture
        .db
        .upsert_node(
            "/work/projects/spec.md",
            "/work/projects",
            "spec.md",
            "file",
            456,
            None,
            Some(
                &fixture
                    .cache_dir
                    .join(format!("{}.dat", cache_id_f2))
                    .to_string_lossy(),
            ),
            Some(SyncStatus::MODIFIED),
            None,
            None,
            Some(cache_id_f2),
            Some(7),
            Some(false),
            None,
        )
        .expect("upsert spec.md");

    let ino_work = fuse.get_or_create_inode("/work");
    let ino_sub = fuse.get_or_create_inode("/work/projects");
    let ino_f1 = fuse.get_or_create_inode("/work/notes.txt");
    let ino_f2 = fuse.get_or_create_inode("/work/projects/spec.md");

    // Rename folder /work -> /archive
    let rename_res = fuse.rename_node("/", "work", "/", "archive");
    assert_eq!(rename_res, Ok(()));

    // Verify inodes in FUSE
    assert_eq!(
        fuse.get_path_for_inode(ino_work),
        Some("/archive".to_string())
    );
    assert_eq!(
        fuse.get_path_for_inode(ino_sub),
        Some("/archive/projects".to_string())
    );
    assert_eq!(
        fuse.get_path_for_inode(ino_f1),
        Some("/archive/notes.txt".to_string())
    );
    assert_eq!(
        fuse.get_path_for_inode(ino_f2),
        Some("/archive/projects/spec.md".to_string())
    );

    // Verify local DB state before restart
    assert!(fixture.db.get_node("/work").is_none());
    assert!(fixture.db.get_node("/work/projects").is_none());
    assert!(fixture.db.get_node("/work/notes.txt").is_none());
    assert!(fixture.db.get_node("/work/projects/spec.md").is_none());

    assert!(fixture.db.get_node("/archive").is_some());
    assert!(fixture.db.get_node("/archive/projects").is_some());

    let f1 = fixture
        .db
        .get_node("/archive/notes.txt")
        .expect("f1 exists");
    assert_eq!(f1.parent_path, "/archive");
    assert_eq!(f1.name, "notes.txt");
    assert_eq!(f1.cache_id, cache_id_f1);
    assert_eq!(f1.generation, 3);
    assert_eq!(f1.sync_status, SyncStatus::SYNCED);

    let f2 = fixture
        .db
        .get_node("/archive/projects/spec.md")
        .expect("f2 exists");
    assert_eq!(f2.parent_path, "/archive/projects");
    assert_eq!(f2.name, "spec.md");
    assert_eq!(f2.cache_id, cache_id_f2);
    assert_eq!(f2.generation, 7);
    assert_eq!(f2.sync_status, SyncStatus::MODIFIED);

    // Simulate database restart: reopen DB from db_path
    let restarted_db = MetadataDB::new(&fixture.db_path).expect("reopen database");

    // Check that all nodes, descendants, cache_ids, generations, and pending work survived restart
    assert!(restarted_db.get_node("/work").is_none());
    assert!(restarted_db.get_node("/archive").is_some());
    assert!(restarted_db.get_node("/archive/projects").is_some());

    let restarted_f1 = restarted_db
        .get_node("/archive/notes.txt")
        .expect("f1 after restart");
    assert_eq!(restarted_f1.parent_path, "/archive");
    assert_eq!(restarted_f1.cache_id, cache_id_f1);
    assert_eq!(restarted_f1.generation, 3);
    assert_eq!(restarted_f1.sync_status, SyncStatus::SYNCED);

    let restarted_f2 = restarted_db
        .get_node("/archive/projects/spec.md")
        .expect("f2 after restart");
    assert_eq!(restarted_f2.parent_path, "/archive/projects");
    assert_eq!(restarted_f2.cache_id, cache_id_f2);
    assert_eq!(restarted_f2.generation, 7);
    assert_eq!(restarted_f2.sync_status, SyncStatus::MODIFIED);

    // Pending work verification
    let pending = restarted_db.get_pending_nodes();
    assert!(pending
        .iter()
        .any(|n| n.path == "/archive/projects/spec.md" && n.sync_status == SyncStatus::MODIFIED));
}

#[test]
fn test_subtree_move_failure_injection_rolls_back_cleanly() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let _ = fuse.create_dir("/", "dir_to_fail").expect("create dir");
    let _ = fuse
        .create_dir("/dir_to_fail", "nested")
        .expect("create nested");

    fixture
        .db
        .upsert_node(
            "/dir_to_fail/item.txt",
            "/dir_to_fail",
            "item.txt",
            "file",
            50,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("item-uuid"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert item.txt");

    fixture
        .db
        .upsert_node(
            "/dir_to_fail/nested/deep.txt",
            "/dir_to_fail/nested",
            "deep.txt",
            "file",
            75,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("deep-uuid"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert deep.txt");

    let ino_dir = fuse.get_or_create_inode("/dir_to_fail");
    let ino_item = fuse.get_or_create_inode("/dir_to_fail/item.txt");

    // Inject failure into SQLite move_subtree
    fixture.db.set_fail_move_subtree(true);

    let res = fuse.rename_node("/", "dir_to_fail", "/", "dir_failed");
    assert_eq!(res, Err(libc::EIO));

    // Verify rollback in DB: original rows exist exactly as before
    assert!(fixture.db.get_node("/dir_to_fail").is_some());
    assert!(fixture.db.get_node("/dir_to_fail/nested").is_some());
    assert!(fixture.db.get_node("/dir_to_fail/item.txt").is_some());
    assert!(fixture
        .db
        .get_node("/dir_to_fail/nested/deep.txt")
        .is_some());

    // Target rows do NOT exist
    assert!(fixture.db.get_node("/dir_failed").is_none());
    assert!(fixture.db.get_node("/dir_failed/nested").is_none());
    assert!(fixture.db.get_node("/dir_failed/item.txt").is_none());

    // No temporary tokens stranded in DB!
    let all_nodes = fixture.db.get_all_nodes();
    assert!(!all_nodes.iter().any(|n| n.path.contains(".move-")));

    // Inodes must NOT have been changed
    assert_eq!(
        fuse.get_path_for_inode(ino_dir),
        Some("/dir_to_fail".to_string())
    );
    assert_eq!(
        fuse.get_path_for_inode(ino_item),
        Some("/dir_to_fail/item.txt".to_string())
    );

    // Disable failure injection and retry: should succeed
    fixture.db.set_fail_move_subtree(false);
    let retry_res = fuse.rename_node("/", "dir_to_fail", "/", "dir_failed");
    assert_eq!(retry_res, Ok(()));
    assert!(fixture.db.get_node("/dir_to_fail").is_none());
    assert!(fixture.db.get_node("/dir_failed").is_some());
    assert!(fixture.db.get_node("/dir_failed/item.txt").is_some());
    assert_eq!(
        fuse.get_path_for_inode(ino_dir),
        Some("/dir_failed".to_string())
    );
    assert_eq!(
        fuse.get_path_for_inode(ino_item),
        Some("/dir_failed/item.txt".to_string())
    );
}

#[test]
fn test_local_only_file_cross_parent_rename_succeeds_without_remote() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let _ = fuse.create_dir("/", "dir_a").expect("create dir_a");
    let _ = fuse.create_dir("/", "dir_b").expect("create dir_b");

    // Local-only node: remote_exists = false
    fixture
        .db
        .upsert_node(
            "/dir_a/local_old.txt",
            "/dir_a",
            "local_old.txt",
            "file",
            30,
            None,
            None,
            Some(SyncStatus::MODIFIED),
            None,
            None,
            Some("local-uuid"),
            Some(1),
            Some(false), // remote_exists = false
            None,
        )
        .expect("upsert local_old.txt");

    fixture.fake_remote.clear_recorded_calls();

    // Cross-parent rename on a local-only node
    let res = fuse.rename_node("/dir_a", "local_old.txt", "/dir_b", "local_new.txt");
    assert_eq!(res, Ok(()));

    // Zero remote calls
    assert_eq!(fixture.fake_remote.recorded_calls().len(), 0);

    // Verify DB updated
    assert!(fixture.db.get_node("/dir_a/local_old.txt").is_none());
    let new_node = fixture
        .db
        .get_node("/dir_b/local_new.txt")
        .expect("new node exists");
    assert_eq!(new_node.parent_path, "/dir_b");
    assert_eq!(new_node.name, "local_new.txt");
    assert_eq!(new_node.cache_id, "local-uuid");
    assert!(!new_node.remote_exists);
}

#[test]
fn test_rename_nonexistent_node_fails_with_enoent() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    let res = fuse.rename_node("/", "does_not_exist.txt", "/", "renamed.txt");
    assert_eq!(res, Err(libc::ENOENT));
    assert_eq!(fixture.fake_remote.recorded_calls().len(), 0);
}

#[test]
fn test_remote_failure_aborts_without_local_mutation() {
    let fixture = TestFixture::new();
    let fuse = fixture.create_fuse();

    fixture
        .db
        .upsert_node(
            "/remote_fail.txt",
            "/",
            "remote_fail.txt",
            "file",
            100,
            None,
            None,
            Some(SyncStatus::SYNCED),
            None,
            None,
            Some("fail-uuid"),
            Some(1),
            Some(true),
            None,
        )
        .expect("upsert /remote_fail.txt");

    fixture.fake_remote.set_rename_result(false);

    let res = fuse.rename_node("/", "remote_fail.txt", "/", "remote_fail2.txt");
    assert_eq!(res, Err(libc::EIO));

    // Local DB was not mutated
    assert!(fixture.db.get_node("/remote_fail.txt").is_some());
    assert!(fixture.db.get_node("/remote_fail2.txt").is_none());
}
