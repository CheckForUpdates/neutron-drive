#![allow(unused_imports, dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

pub use neutron_drive_daemon::client::{
    CreateFolderCall, DeleteCall, DownloadCall, FakeRemoteDrive, MoveNodeCall, RemoteCall,
    RemoteDrive, RemoteNode, RenameCall, StorageQuota, TrashCall, UploadCall,
};
pub use neutron_drive_daemon::config::{load_config_from, save_config_to, Config};
pub use neutron_drive_daemon::daemon::ProtonDriveDaemon;
pub use neutron_drive_daemon::fuse_fs::{
    reconcile_directory, ActivityRegistry, OpenHandle, ProtonDriveFUSE,
};
pub use neutron_drive_daemon::ipc::{IpcClient, IpcServer};
pub use neutron_drive_daemon::metadata_db::{generate_uuid, MetadataDB, Node, SyncStatus};
pub use neutron_drive_daemon::sync_engine::{AppSyncStatus, SyncEngine};

pub struct TestFixture {
    pub temp_dir: TempDir,
    pub db: MetadataDB,
    pub db_path: PathBuf,
    pub cache_dir: PathBuf,
    pub mount_dir: PathBuf,
    pub socket_path: PathBuf,
    pub config_path: PathBuf,
    pub fake_remote: FakeRemoteDrive,
    pub activity: Arc<ActivityRegistry>,
}

impl TestFixture {
    pub fn new() -> Self {
        let temp_dir = tempfile::Builder::new()
            .prefix("proton-test-")
            .tempdir()
            .expect("Failed to create temporary directory for test");
        let root = temp_dir.path();
        let db_path = root.join("test_metadata.db");
        let cache_dir = root.join("blocks");
        let mount_dir = root.join("mount");
        let socket_path = root.join("test.sock");
        let config_path = root.join("config.json");

        std::fs::create_dir_all(&cache_dir).expect("Failed to create isolated cache dir");
        std::fs::create_dir_all(&mount_dir).expect("Failed to create isolated mount dir");

        let db = MetadataDB::new(&db_path).expect("Failed to initialize test MetadataDB");
        let fake_remote = FakeRemoteDrive::new();
        let activity = Arc::new(ActivityRegistry::new());

        Self {
            temp_dir,
            db,
            db_path,
            cache_dir,
            mount_dir,
            socket_path,
            config_path,
            fake_remote,
            activity,
        }
    }

    pub fn remote_client(&self) -> Arc<dyn RemoteDrive> {
        Arc::new(self.fake_remote.clone())
    }

    pub fn create_fuse(&self) -> ProtonDriveFUSE {
        ProtonDriveFUSE::new(
            self.remote_client(),
            self.db.clone(),
            self.cache_dir.clone(),
            Some("/my-files"),
            Arc::clone(&self.activity),
        )
    }

    pub fn create_sync_engine(&self, poll_interval_sec: u64) -> SyncEngine {
        SyncEngine::new(
            self.remote_client(),
            self.db.clone(),
            self.cache_dir.clone(),
            poll_interval_sec,
            Arc::clone(&self.activity),
        )
    }

    pub fn create_daemon(&self) -> ProtonDriveDaemon {
        let config = if self.config_path.exists() {
            load_config_from(&self.config_path)
        } else {
            Config {
                mount_point: self.mount_dir.to_string_lossy().to_string(),
                auto_mount_on_start: false,
                ..Default::default()
            }
        };

        ProtonDriveDaemon::new_with_deps_and_activity(
            self.remote_client(),
            self.db.clone(),
            config,
            self.cache_dir.clone(),
            self.socket_path.clone(),
            self.config_path.clone(),
            Arc::clone(&self.activity),
        )
        .expect("Failed to create test daemon")
    }

    pub fn create_daemon_with_config(&self, config: Config) -> ProtonDriveDaemon {
        ProtonDriveDaemon::new_with_deps_and_activity(
            self.remote_client(),
            self.db.clone(),
            config,
            self.cache_dir.clone(),
            self.socket_path.clone(),
            self.config_path.clone(),
            Arc::clone(&self.activity),
        )
        .expect("Failed to create test daemon")
    }

    pub fn create_ipc_client(&self) -> IpcClient {
        IpcClient::new(Some(self.socket_path.clone()))
    }

    pub fn root_path(&self) -> &Path {
        self.temp_dir.path()
    }

    pub fn reconcile_dir(&self, path: &str) -> Result<(), String> {
        reconcile_directory(
            &*self.remote_client(),
            &self.db,
            &self.cache_dir,
            &self.activity,
            "/my-files",
            path,
        )
    }
}
