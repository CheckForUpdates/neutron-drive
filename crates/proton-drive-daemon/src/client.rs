use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub trait RemoteDrive: Send + Sync {
    fn check_auth_status(&self) -> (bool, String);
    fn start_login(&self) -> Result<String, String> {
        Ok("Login initiated".to_string())
    }
    fn logout(&self) -> bool;
    fn list_path(&self, remote_path: &str) -> Result<Vec<RemoteNode>, String>;
    fn download_file(
        &self,
        remote_path: &str,
        local_target_dir: &Path,
        conflict_strategy: &str,
    ) -> bool;
    fn upload_file(
        &self,
        local_file: &Path,
        remote_parent_path: &str,
        conflict_strategy: &str,
    ) -> bool;
    fn create_folder(&self, remote_parent: &str, folder_name: &str) -> bool;
    fn rename(&self, remote_path: &str, new_name: &str) -> bool;
    fn move_node(&self, source_path: &str, target_parent_path: &str) -> bool;
    fn trash(&self, remote_path: &str) -> bool;
    fn delete(&self, remote_path: &str) -> bool;
    fn get_storage_quota(&self) -> StorageQuota;
    fn backend_name(&self) -> &'static str {
        "native"
    }
    fn supports_block_range_reads(&self) -> bool {
        false
    }
    fn authenticate(
        &self,
        _username: &str,
        _password: &str,
        _totp: Option<&str>,
    ) -> Result<String, String> {
        self.start_login()
    }
    fn start_browser_login(&self) -> Result<(String, String), String> {
        Err("Browser SSO is only supported by the native backend".to_string())
    }
    fn poll_browser_login(&self) -> Result<Option<String>, String> {
        Err("Browser SSO is only supported by the native backend".to_string())
    }
    fn poll_events(
        &self,
        _db: &crate::metadata_db::MetadataDB,
        _cache_dir: &Path,
        _activity: &crate::fuse_fs::ActivityRegistry,
    ) -> Option<Result<usize, String>> {
        None
    }
    fn backfill_native_ids(&self, _db: &crate::metadata_db::MetadataDB) {}
    fn read_block_range(
        &self,
        _remote_path: &str,
        _offset: u64,
        _size: usize,
    ) -> Option<Result<Vec<u8>, String>> {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteNode {
    pub name: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(default)]
    pub size: i64,
    #[serde(rename = "modifyTime", default)]
    pub modify_time: Option<f64>,
    pub uid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageQuota {
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub percent_used: f64,
}

impl Default for StorageQuota {
    fn default() -> Self {
        Self {
            used_bytes: 0,
            total_bytes: 0,
            percent_used: 0.0,
        }
    }
}

pub(crate) fn parse_iso8601_utc_seconds(ts: &str) -> Option<f64> {
    let ts = ts.trim();
    let (date_part, time_part) = ts.split_once('T')?;
    let mut date_iter = date_part.split('-');
    let year: i64 = date_iter.next()?.parse().ok()?;
    let month: u32 = date_iter.next()?.parse().ok()?;
    let day: u32 = date_iter.next()?.parse().ok()?;
    if date_iter.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let time_no_tz = time_part.strip_suffix('Z')?;
    let (hms, frac_str) = match time_no_tz.split_once('.') {
        Some((h, f)) => (h, Some(f)),
        None => (time_no_tz, None),
    };
    let mut time_iter = hms.split(':');
    let hour: u64 = time_iter.next()?.parse().ok()?;
    let min: u64 = time_iter.next()?.parse().ok()?;
    let sec: u64 = time_iter.next()?.parse().ok()?;
    if time_iter.next().is_some() || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let frac: f64 = match frac_str {
        Some(f) if !f.is_empty() => format!("0.{}", f).parse().ok()?,
        _ => 0.0,
    };

    // Howard Hinnant's civil-from-days / days-from-civil algorithm (days since 1970-01-01).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + (doe as i64) - 719_468;

    Some((days as f64) * 86_400.0 + (hour * 3600 + min * 60 + sec) as f64 + frac)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadCall {
    pub remote_path: String,
    pub local_target_dir: PathBuf,
    pub conflict_strategy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadCall {
    pub local_file: PathBuf,
    pub remote_parent_path: String,
    pub conflict_strategy: String,
    pub file_content: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFolderCall {
    pub remote_parent: String,
    pub folder_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameCall {
    pub remote_path: String,
    pub new_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveNodeCall {
    pub source_path: String,
    pub target_parent_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashCall {
    pub remote_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteCall {
    pub remote_path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RemoteCall {
    CheckAuthStatus,
    Logout,
    ListPath(String),
    DownloadFile(DownloadCall),
    UploadFile(UploadCall),
    CreateFolder(CreateFolderCall),
    Rename(RenameCall),
    MoveNode(MoveNodeCall),
    Trash(TrashCall),
    Delete(DeleteCall),
    GetStorageQuota,
}

#[derive(Debug)]
struct FakeRemoteDriveInner {
    auth_status: (bool, String),
    logout_success: bool,
    list_responses: HashMap<String, Result<Vec<RemoteNode>, String>>,
    default_list_response: Result<Vec<RemoteNode>, String>,
    download_success: bool,
    download_contents: HashMap<String, Vec<u8>>,
    upload_success: bool,
    create_folder_success: bool,
    rename_success: bool,
    move_node_success: bool,
    trash_success: bool,
    delete_success: bool,
    quota: StorageQuota,
    calls: Vec<RemoteCall>,
}

impl Default for FakeRemoteDriveInner {
    fn default() -> Self {
        Self {
            auth_status: (true, "Authenticated".to_string()),
            logout_success: true,
            list_responses: HashMap::new(),
            default_list_response: Ok(Vec::new()),
            download_success: true,
            download_contents: HashMap::new(),
            upload_success: true,
            create_folder_success: true,
            rename_success: true,
            move_node_success: true,
            trash_success: true,
            delete_success: true,
            quota: StorageQuota::default(),
            calls: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeRemoteDrive {
    inner: Arc<Mutex<FakeRemoteDriveInner>>,
}

impl FakeRemoteDrive {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_auth_status(&self, authenticated: bool, message: impl Into<String>) {
        let mut inner = self.inner.lock().unwrap();
        inner.auth_status = (authenticated, message.into());
    }

    pub fn set_logout_result(&self, success: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.logout_success = success;
    }

    pub fn set_list_result(
        &self,
        remote_path: impl Into<String>,
        result: Result<Vec<RemoteNode>, String>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.list_responses.insert(remote_path.into(), result);
    }

    pub fn set_default_list_result(&self, result: Result<Vec<RemoteNode>, String>) {
        let mut inner = self.inner.lock().unwrap();
        inner.default_list_response = result;
    }

    pub fn set_download_result(&self, success: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.download_success = success;
    }

    pub fn set_download_content(&self, remote_path: impl Into<String>, content: Vec<u8>) {
        let mut inner = self.inner.lock().unwrap();
        inner.download_contents.insert(remote_path.into(), content);
    }

    pub fn set_upload_result(&self, success: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.upload_success = success;
    }

    pub fn set_create_folder_result(&self, success: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.create_folder_success = success;
    }

    pub fn set_rename_result(&self, success: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.rename_success = success;
    }

    pub fn set_move_node_result(&self, success: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.move_node_success = success;
    }

    pub fn set_trash_result(&self, success: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.trash_success = success;
    }

    pub fn set_delete_result(&self, success: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.delete_success = success;
    }

    pub fn set_storage_quota(&self, quota: StorageQuota) {
        let mut inner = self.inner.lock().unwrap();
        inner.quota = quota;
    }

    pub fn recorded_calls(&self) -> Vec<RemoteCall> {
        let inner = self.inner.lock().unwrap();
        inner.calls.clone()
    }

    pub fn clear_recorded_calls(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.clear();
    }

    pub fn upload_calls(&self) -> Vec<UploadCall> {
        let inner = self.inner.lock().unwrap();
        inner
            .calls
            .iter()
            .filter_map(|c| match c {
                RemoteCall::UploadFile(u) => Some(u.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn download_calls(&self) -> Vec<DownloadCall> {
        let inner = self.inner.lock().unwrap();
        inner
            .calls
            .iter()
            .filter_map(|c| match c {
                RemoteCall::DownloadFile(d) => Some(d.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn create_folder_calls(&self) -> Vec<CreateFolderCall> {
        let inner = self.inner.lock().unwrap();
        inner
            .calls
            .iter()
            .filter_map(|c| match c {
                RemoteCall::CreateFolder(cf) => Some(cf.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn rename_calls(&self) -> Vec<RenameCall> {
        let inner = self.inner.lock().unwrap();
        inner
            .calls
            .iter()
            .filter_map(|c| match c {
                RemoteCall::Rename(r) => Some(r.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn move_node_calls(&self) -> Vec<MoveNodeCall> {
        let inner = self.inner.lock().unwrap();
        inner
            .calls
            .iter()
            .filter_map(|c| match c {
                RemoteCall::MoveNode(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn trash_calls(&self) -> Vec<TrashCall> {
        let inner = self.inner.lock().unwrap();
        inner
            .calls
            .iter()
            .filter_map(|c| match c {
                RemoteCall::Trash(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn delete_calls(&self) -> Vec<DeleteCall> {
        let inner = self.inner.lock().unwrap();
        inner
            .calls
            .iter()
            .filter_map(|c| match c {
                RemoteCall::Delete(d) => Some(d.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn list_calls(&self) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner
            .calls
            .iter()
            .filter_map(|c| match c {
                RemoteCall::ListPath(p) => Some(p.clone()),
                _ => None,
            })
            .collect()
    }
}

impl RemoteDrive for FakeRemoteDrive {
    fn check_auth_status(&self) -> (bool, String) {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::CheckAuthStatus);
        inner.auth_status.clone()
    }

    fn start_login(&self) -> Result<String, String> {
        let mut inner = self.inner.lock().unwrap();
        inner.auth_status = (true, "Authenticated".to_string());
        Ok("Login initiated".to_string())
    }

    fn logout(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::Logout);
        inner.logout_success
    }

    fn list_path(&self, remote_path: &str) -> Result<Vec<RemoteNode>, String> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .calls
            .push(RemoteCall::ListPath(remote_path.to_string()));
        if let Some(res) = inner.list_responses.get(remote_path) {
            res.clone()
        } else {
            inner.default_list_response.clone()
        }
    }

    fn download_file(
        &self,
        remote_path: &str,
        local_target_dir: &Path,
        conflict_strategy: &str,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::DownloadFile(DownloadCall {
            remote_path: remote_path.to_string(),
            local_target_dir: local_target_dir.to_path_buf(),
            conflict_strategy: conflict_strategy.to_string(),
        }));
        if !inner.download_success {
            return false;
        }
        let _ = std::fs::create_dir_all(local_target_dir);
        let file_name = Path::new(remote_path).file_name().unwrap_or_default();
        let target_file = local_target_dir.join(file_name);
        let content = inner
            .download_contents
            .get(remote_path)
            .cloned()
            .unwrap_or_default();
        let _ = std::fs::write(&target_file, content);
        true
    }

    fn upload_file(
        &self,
        local_file: &Path,
        remote_parent_path: &str,
        conflict_strategy: &str,
    ) -> bool {
        let file_content = std::fs::read(local_file).ok();
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::UploadFile(UploadCall {
            local_file: local_file.to_path_buf(),
            remote_parent_path: remote_parent_path.to_string(),
            conflict_strategy: conflict_strategy.to_string(),
            file_content,
        }));
        inner.upload_success
    }

    fn create_folder(&self, remote_parent: &str, folder_name: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::CreateFolder(CreateFolderCall {
            remote_parent: remote_parent.to_string(),
            folder_name: folder_name.to_string(),
        }));
        inner.create_folder_success
    }

    fn rename(&self, remote_path: &str, new_name: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::Rename(RenameCall {
            remote_path: remote_path.to_string(),
            new_name: new_name.to_string(),
        }));
        inner.rename_success
    }

    fn move_node(&self, source_path: &str, target_parent_path: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::MoveNode(MoveNodeCall {
            source_path: source_path.to_string(),
            target_parent_path: target_parent_path.to_string(),
        }));
        inner.move_node_success
    }

    fn trash(&self, remote_path: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::Trash(TrashCall {
            remote_path: remote_path.to_string(),
        }));
        inner.trash_success
    }

    fn delete(&self, remote_path: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::Delete(DeleteCall {
            remote_path: remote_path.to_string(),
        }));
        inner.delete_success
    }

    fn get_storage_quota(&self) -> StorageQuota {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(RemoteCall::GetStorageQuota);
        inner.quota.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iso8601_utc_seconds() {
        let ts = parse_iso8601_utc_seconds("2026-11-15T23:58:21.500Z").unwrap();
        assert!((ts - 1_794_787_101.5).abs() < 0.001);
        assert!(parse_iso8601_utc_seconds("invalid").is_none());
    }
}
