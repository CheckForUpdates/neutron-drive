pub mod auth;
pub mod crypto;
pub mod endpoints;
pub mod events;
pub mod http;
pub mod transfer;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use log::{error, warn};

use crate::client::{RemoteDrive, RemoteNode, StorageQuota};
use crate::fuse_fs::ActivityRegistry;
use crate::metadata_db::{MetadataDB, SyncStatus};

use self::auth::{AuthManager, BrowserLoginChallenge, SessionVault};
use self::crypto::{CachedNodeKeys, Decryptor, DriveKey, Encryptor, NameHasher, NodeKeyCache};
use self::endpoints::{
    DriveEndpoints, LinkMetadata, MoveMultipleLinkItem, MoveMultipleParameters,
    NewFolderParameters, RenameNodeParameters,
};
use self::events::{decrypt_link_with_parent, EventProcessor};
use self::http::PdHttpClient;

#[derive(Debug, Clone)]
struct VolumeContext {
    volume_id: String,
    share_id: String,
    root_link_id: String,
}

#[derive(Clone)]
pub(crate) struct CachedRemoteLink {
    pub(crate) link_id: String,
    pub(crate) parent_link_id: Option<String>,
    pub(crate) share_id: String,
    pub(crate) link_type: i32,
    pub(crate) name: String,
    pub(crate) name_hash: String,
    pub(crate) revision_id: Option<String>,
    pub(crate) content_key_packet: Option<String>,
    pub(crate) content_key_packet_signature: Option<String>,
    pub(crate) raw_node_passphrase_armored: Option<String>,
}

pub fn normalize_virtual_path(remote_path: &str) -> String {
    let trimmed = remote_path.trim();
    if trimmed.is_empty() || trimmed == "/" || trimmed == "/my-files" || trimmed == "/my-files/" {
        return "/".to_string();
    }
    let without_section = trimmed
        .strip_prefix("/my-files/")
        .map(|s| format!("/{}", s))
        .unwrap_or_else(|| {
            if trimmed.starts_with('/') {
                trimmed.to_string()
            } else {
                format!("/{}", trimmed)
            }
        });
    let clean = without_section.trim_end_matches('/');
    if clean.is_empty() {
        "/".to_string()
    } else {
        clean.to_string()
    }
}

pub struct NativeProtonClient {
    db: MetadataDB,
    http: Arc<PdHttpClient>,
    vault: Arc<SessionVault>,
    auth: AuthManager,
    node_cache: Arc<NodeKeyCache>,
    volume_ctx: Mutex<Option<VolumeContext>>,
    links_by_path: Mutex<HashMap<String, CachedRemoteLink>>,
    recently_trashed_by_path: Mutex<HashMap<String, (String, String)>>,
    active_browser_challenge: Mutex<Option<BrowserLoginChallenge>>,
}

impl NativeProtonClient {
    pub fn new(db: MetadataDB, base_url: Option<String>) -> Result<Self, String> {
        Self::new_with_paths(db, None, base_url)
    }

    pub fn new_with_paths(
        db: MetadataDB,
        vault_path: Option<PathBuf>,
        base_url: Option<String>,
    ) -> Result<Self, String> {
        let vault = Arc::new(SessionVault::new(vault_path)?);
        Self::new_with_vault(db, vault, base_url)
    }

    pub fn new_with_vault(
        db: MetadataDB,
        vault: Arc<SessionVault>,
        base_url: Option<String>,
    ) -> Result<Self, String> {
        let http = Arc::new(PdHttpClient::new(base_url, None)?);
        let auth = AuthManager::new(Arc::clone(&http), Arc::clone(&vault));
        Ok(Self {
            db,
            http,
            vault,
            auth,
            node_cache: Arc::new(NodeKeyCache::new(4096)),
            volume_ctx: Mutex::new(None),
            links_by_path: Mutex::new(HashMap::new()),
            recently_trashed_by_path: Mutex::new(HashMap::new()),
            active_browser_challenge: Mutex::new(None),
        })
    }

    pub fn with_trusted_srp_keys(mut self, keys: Vec<String>) -> Self {
        self.auth.set_trusted_srp_keys(keys);
        self
    }

    pub fn http(&self) -> &Arc<PdHttpClient> {
        &self.http
    }

    pub fn vault(&self) -> &Arc<SessionVault> {
        &self.vault
    }

    pub fn node_cache(&self) -> &Arc<NodeKeyCache> {
        &self.node_cache
    }

    pub fn start_browser_login(
        &self,
        account_base_url: Option<&str>,
    ) -> Result<BrowserLoginChallenge, String> {
        self.auth.start_browser_login(account_base_url)
    }

    pub fn poll_browser_login_once(
        &self,
        challenge: &BrowserLoginChallenge,
    ) -> Result<Option<String>, String> {
        let res = self.auth.poll_browser_login_once(challenge)?;
        if res.is_some() {
            self.reset_caches();
        }
        Ok(res)
    }

    pub fn authenticate_via_browser<F>(
        &self,
        timeout: std::time::Duration,
        on_url: F,
    ) -> Result<String, String>
    where
        F: FnOnce(&str, &str),
    {
        let msg = self.auth.authenticate_via_browser(timeout, on_url)?;
        self.reset_caches();
        Ok(msg)
    }

    pub fn download_file_checked(
        &self,
        remote_path: &str,
        local_target_dir: &Path,
        conflict_strategy: &str,
    ) -> Result<std::path::PathBuf, String> {
        let (ctx, mut link) = self.resolve_path(remote_path)?;
        self.resolve_single_link_metadata(&ctx, &mut link)?;
        let revision_id = link
            .revision_id
            .as_deref()
            .ok_or_else(|| format!("File {} has no active revision", remote_path))?;
        let kp = link
            .content_key_packet
            .as_deref()
            .ok_or_else(|| format!("File {} has no ContentKeyPacket", remote_path))?;
        let cached_keys = self
            .node_cache
            .get(&link.link_id)
            .ok_or_else(|| format!("Unlocked node key missing for {}", link.link_id))?;
        let verif = self.vault.address_public_keys(None);
        transfer::download_file_blocks(
            &self.http,
            &link.share_id,
            &link.link_id,
            revision_id,
            kp,
            link.content_key_packet_signature.as_deref(),
            &cached_keys.unlocked_key,
            &verif,
            &link.name,
            local_target_dir,
            conflict_strategy,
        )
    }

    fn reset_caches(&self) {
        *self.volume_ctx.lock().unwrap() = None;
        self.node_cache.clear();
        self.links_by_path.lock().unwrap().clear();
        self.recently_trashed_by_path.lock().unwrap().clear();
        *self.active_browser_challenge.lock().unwrap() = None;
    }

    #[allow(clippy::too_many_arguments)]
    fn relocate_cached_subtree(
        &self,
        old_vpath: &str,
        new_vpath: &str,
        link_id: &str,
        new_name: Option<&str>,
        new_hash: &str,
        new_parent_link_id: Option<&str>,
        new_passphrase: Option<&str>,
    ) {
        let prefix = format!("{}/", old_vpath);
        let new_prefix = format!("{}/", new_vpath);
        {
            let mut map = self.links_by_path.lock().unwrap();
            let descendants: Vec<(String, CachedRemoteLink)> = map
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (k, _) in &descendants {
                map.remove(k);
            }
            if let Some(mut entry) = map.remove(old_vpath) {
                if let Some(name) = new_name {
                    entry.name = name.to_string();
                }
                entry.name_hash = new_hash.to_string();
                if let Some(pid) = new_parent_link_id {
                    entry.parent_link_id = Some(pid.to_string());
                }
                if let Some(pp) = new_passphrase {
                    entry.raw_node_passphrase_armored = Some(pp.to_string());
                }
                map.insert(new_vpath.to_string(), entry);
            }
            for (k, v) in descendants {
                if let Some(suffix) = k.strip_prefix(&prefix) {
                    map.insert(format!("{}{}", new_prefix, suffix), v);
                }
            }
        }
        self.recently_trashed_by_path
            .lock()
            .unwrap()
            .remove(new_vpath);
        if let Some(mut ck) = self.node_cache.get(link_id) {
            if let Some(name) = new_name {
                ck.name = name.to_string();
            }
            if let Some(pid) = new_parent_link_id {
                ck.parent_link_id = Some(pid.to_string());
            }
            self.node_cache.insert(link_id.to_string(), ck);
        }
        if self.db.get_node(new_vpath).is_some() {
            let _ = self.db.upsert_native_ids(
                new_vpath,
                None,
                None,
                None,
                new_parent_link_id,
                None,
                Some(new_hash),
            );
        }
    }

    fn evict_cached_subtree(&self, vpath: &str, target_link_id: &str) {
        let prefix = format!("{}/", vpath);
        let evicted_ids: Vec<String> = {
            let mut map = self.links_by_path.lock().unwrap();
            let mut ids = Vec::new();
            let to_remove: Vec<String> = map
                .keys()
                .filter(|k| *k == vpath || k.starts_with(&prefix))
                .cloned()
                .collect();
            for k in to_remove {
                if let Some(entry) = map.remove(&k) {
                    ids.push(entry.link_id);
                }
            }
            ids
        };
        self.node_cache.invalidate(target_link_id);
        for id in evicted_ids {
            self.node_cache.invalidate(&id);
        }
    }

    fn sync_cached_ids_to_db(&self, db: &MetadataDB, volume_id: &str) {
        let cached_links: Vec<(String, CachedRemoteLink)> = {
            let map = self.links_by_path.lock().unwrap();
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (vpath, cached) in &cached_links {
            if db.get_node(vpath).is_some() {
                let _ = db.upsert_native_ids(
                    vpath,
                    Some(volume_id),
                    Some(&cached.share_id),
                    Some(&cached.link_id),
                    cached.parent_link_id.as_deref(),
                    cached.revision_id.as_deref(),
                    Some(&cached.name_hash),
                );
            }
        }
    }

    fn ensure_bootstrapped(&self) -> Result<VolumeContext, String> {
        if !self.vault.is_authenticated() {
            return Err("Not authenticated".to_string());
        }

        if let Some(ctx) = self.volume_ctx.lock().unwrap().clone() {
            if self.node_cache.get(&ctx.root_link_id).is_some() {
                return Ok(ctx);
            }
        }

        let vols = DriveEndpoints::list_volumes(&self.http)
            .map_err(|e| format!("Failed listing volumes: {}", e))?;
        if vols.code != 1000 && vols.code != 1001 {
            return Err(format!("Volumes request rejected with code {}", vols.code));
        }

        let vol = vols
            .volumes
            .iter()
            .find(|v| v.volume_type == 1 && v.state.unwrap_or(1) == 1)
            .or_else(|| {
                vols.volumes
                    .iter()
                    .find(|v| v.volume_type == 1 && v.state == Some(4))
            })
            .or_else(|| {
                vols.volumes
                    .iter()
                    .find(|v| v.volume_type == 1 && !matches!(v.state, Some(2) | Some(3)))
            })
            .or_else(|| vols.volumes.iter().find(|v| v.state.unwrap_or(1) == 1))
            .or_else(|| vols.volumes.first())
            .ok_or_else(|| "No Drive volume available for account".to_string())?
            .clone();

        let share_resp = DriveEndpoints::get_share_bootstrap(&self.http, &vol.share.share_id)
            .map_err(|e| format!("Failed bootstrapping share {}: {}", vol.share.share_id, e))?;
        if share_resp.code != 1000 && share_resp.code != 1001 {
            return Err(format!(
                "Share bootstrap rejected with code {}",
                share_resp.code
            ));
        }
        if share_resp.locked == Some(true) {
            return Err(format!("Share {} is locked", share_resp.share_id));
        }
        if share_resp.state == 2 {
            return Err(format!("Share {} is deleted", share_resp.share_id));
        }

        let target_address_id = share_resp
            .address_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                share_resp
                    .memberships
                    .first()
                    .map(|m| m.address_id.as_str())
                    .filter(|s| !s.is_empty())
            });
        let all_addr_keys = self.vault.address_keys();
        let mut dec_keys = Vec::new();
        if let Some(addr_id) = target_address_id {
            for ak in &all_addr_keys {
                if ak.address_id == addr_id {
                    dec_keys.push(ak.unlocked.clone());
                }
            }
        }
        for ak in all_addr_keys {
            if target_address_id.is_none_or(|id| ak.address_id != id) {
                dec_keys.push(ak.unlocked);
            }
        }
        if let Some(uk) = self.vault.user_key() {
            dec_keys.push(uk);
        }
        if dec_keys.is_empty() {
            return Err("No unlocked user/address keys available in SessionVault".to_string());
        }

        let verif_keys = self.vault.address_public_keys(None);

        let share_pass = Decryptor::decrypt_and_verify_share_passphrase(
            &share_resp.passphrase,
            &share_resp.passphrase_signature,
            &verif_keys,
            &dec_keys,
        )?;
        let share_unlocked = DriveKey::unlock(&share_resp.key, share_pass.value())?;

        let root_meta_resp = DriveEndpoints::fetch_links_metadata(
            &self.http,
            &vol.volume_id,
            std::slice::from_ref(&vol.share.link_id),
        )
        .map_err(|e| format!("Failed fetching root link metadata: {}", e))?;
        if root_meta_resp.code != 1000 && root_meta_resp.code != 1001 {
            return Err(format!(
                "Root link metadata rejected with code {}",
                root_meta_resp.code
            ));
        }
        let root_link = root_meta_resp
            .links
            .into_iter()
            .next()
            .ok_or_else(|| "Root link metadata response was empty".to_string())?;

        // Decrypt root folder using share key (or fall back to address keys)
        let root_dec = match decrypt_link_with_parent(
            &root_link,
            &vol.share.share_id,
            &share_unlocked,
            &verif_keys,
        ) {
            Ok(d) => d,
            Err(_) => {
                let mut res = None;
                for dk in &dec_keys {
                    if let Ok(d) =
                        decrypt_link_with_parent(&root_link, &vol.share.share_id, dk, &verif_keys)
                    {
                        res = Some(d);
                        break;
                    }
                }
                res.ok_or_else(|| "Failed decrypting root folder node key".to_string())?
            }
        };

        self.node_cache.insert(
            vol.share.link_id.clone(),
            CachedNodeKeys {
                unlocked_key: root_dec.unlocked_key,
                node_hash_key: root_dec.node_hash_key,
                share_id: vol.share.share_id.clone(),
                parent_link_id: None,
                name: String::new(),
                node_passphrase_raw: root_dec.node_passphrase_raw,
            },
        );

        self.links_by_path.lock().unwrap().insert(
            "/".to_string(),
            CachedRemoteLink {
                link_id: vol.share.link_id.clone(),
                parent_link_id: None,
                share_id: vol.share.share_id.clone(),
                link_type: 1,
                name: String::new(),
                name_hash: root_link.hash,
                revision_id: None,
                content_key_packet: None,
                content_key_packet_signature: None,
                raw_node_passphrase_armored: Some(root_link.node_passphrase),
            },
        );

        if self.db.get_node("/").is_none() {
            let _ = self.db.upsert_node(
                "/",
                "",
                "",
                "folder",
                0,
                None,
                None,
                Some(SyncStatus::SYNCED),
                None,
                Some(&vol.share.link_id),
                None,
                None,
                Some(true),
                None,
            );
        }
        let _ = self.db.upsert_native_ids(
            "/",
            Some(&vol.volume_id),
            Some(&vol.share.share_id),
            Some(&vol.share.link_id),
            None,
            None,
            None,
        );

        let ctx = VolumeContext {
            volume_id: vol.volume_id,
            share_id: vol.share.share_id,
            root_link_id: vol.share.link_id,
        };
        *self.volume_ctx.lock().unwrap() = Some(ctx.clone());
        Ok(ctx)
    }

    fn resolve_path(&self, remote_path: &str) -> Result<(VolumeContext, CachedRemoteLink), String> {
        let ctx = self.ensure_bootstrapped()?;
        let vpath = normalize_virtual_path(remote_path);

        if vpath == "/" {
            let cached = self
                .links_by_path
                .lock()
                .unwrap()
                .get("/")
                .cloned()
                .ok_or_else(|| "Root node missing after bootstrap".to_string())?;
            return Ok((ctx, cached));
        }

        if let Some(cached) = self.links_by_path.lock().unwrap().get(&vpath).cloned() {
            if self.node_cache.get(&cached.link_id).is_some() {
                return Ok((ctx, cached));
            }
        }

        // Walk components from "/" calling list_path to populate caches & unlock ancestor keys
        let segments: Vec<&str> = vpath.trim_start_matches('/').split('/').collect();
        let mut cur_path = "/".to_string();
        for seg in segments {
            let _ = self.list_path_internal(&cur_path)?;
            cur_path = if cur_path == "/" {
                format!("/{}", seg)
            } else {
                format!("{}/{}", cur_path, seg)
            };
        }

        let cached = self
            .links_by_path
            .lock()
            .unwrap()
            .get(&vpath)
            .cloned()
            .ok_or_else(|| format!("Remote path not found: {}", vpath))?;
        Ok((ctx, cached))
    }

    fn fetch_all_children_metadata(
        &self,
        volume_id: &str,
        folder_link_id: &str,
    ) -> Result<Vec<LinkMetadata>, String> {
        let mut all_ids = Vec::new();
        let mut seen_ids = HashSet::new();
        let mut seen_anchors = HashSet::new();
        let mut anchor: Option<String> = None;

        loop {
            let page = DriveEndpoints::list_folder_children_v2(
                &self.http,
                volume_id,
                folder_link_id,
                anchor.as_deref(),
                false,
            )
            .map_err(|e| format!("Failed listing folder children: {}", e))?;
            if page.code != 1000 && page.code != 1001 {
                return Err(format!("Folder children rejected with code {}", page.code));
            }
            for id in page.link_ids {
                if !id.is_empty() && seen_ids.insert(id.clone()) {
                    all_ids.push(id);
                }
            }
            if !page.more {
                break;
            }
            let Some(next_anchor) = page.anchor_id.filter(|a| !a.is_empty()) else {
                return Err(
                    "Folder children pagination indicated more pages without an AnchorID"
                        .to_string(),
                );
            };
            if !seen_anchors.insert(next_anchor.clone()) {
                return Err(format!(
                    "Folder children pagination anchor did not advance: {}",
                    next_anchor
                ));
            }
            anchor = Some(next_anchor);
        }

        if all_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut links = Vec::with_capacity(all_ids.len());
        for chunk in all_ids.chunks(150) {
            let resp = DriveEndpoints::fetch_links_metadata(&self.http, volume_id, chunk)
                .map_err(|e| format!("Failed fetching batch link metadata: {}", e))?;
            if resp.code != 1000 && resp.code != 1001 {
                return Err(format!(
                    "Fetch link metadata rejected with code {}",
                    resp.code
                ));
            }
            links.extend(resp.links);
        }

        Ok(links)
    }

    fn list_path_internal(&self, remote_path: &str) -> Result<Vec<RemoteNode>, String> {
        let vpath = normalize_virtual_path(remote_path);
        let (ctx, folder_link) = if vpath == "/" {
            let ctx = self.ensure_bootstrapped()?;
            let cached = self
                .links_by_path
                .lock()
                .unwrap()
                .get("/")
                .cloned()
                .ok_or_else(|| "Root node missing".to_string())?;
            (ctx, cached)
        } else {
            self.resolve_path(&vpath)?
        };

        let parent_keys = self
            .node_cache
            .get(&folder_link.link_id)
            .ok_or_else(|| format!("Folder key not unlocked for {}", vpath))?;

        let raw_links = self.fetch_all_children_metadata(&ctx.volume_id, &folder_link.link_id)?;
        let verif_keys = self.vault.address_public_keys(None);
        let mut out = Vec::new();
        let mut cache_updates = Vec::new();

        for link in raw_links {
            if link.state != 1 || link.trashed.is_some() {
                continue;
            }

            let dec = decrypt_link_with_parent(
                &link,
                &ctx.share_id,
                &parent_keys.unlocked_key,
                &verif_keys,
            )?;
            if dec.name.is_empty() || dec.name == "." || dec.name == ".." || dec.name.contains('/')
            {
                continue;
            }

            let child_vpath = if vpath == "/" {
                format!("/{}", dec.name)
            } else {
                format!("{}/{}", vpath.trim_end_matches('/'), dec.name)
            };

            self.node_cache.insert(
                dec.link_id.clone(),
                CachedNodeKeys {
                    unlocked_key: dec.unlocked_key.clone(),
                    node_hash_key: dec.node_hash_key.clone(),
                    share_id: ctx.share_id.clone(),
                    parent_link_id: Some(folder_link.link_id.clone()),
                    name: dec.name.clone(),
                    node_passphrase_raw: dec.node_passphrase_raw.clone(),
                },
            );

            cache_updates.push((
                child_vpath.clone(),
                CachedRemoteLink {
                    link_id: dec.link_id.clone(),
                    parent_link_id: Some(folder_link.link_id.clone()),
                    share_id: ctx.share_id.clone(),
                    link_type: link.link_type,
                    name: dec.name.clone(),
                    name_hash: dec.name_hash.clone(),
                    revision_id: dec.revision_id.clone(),
                    content_key_packet: dec.content_key_packet.clone(),
                    content_key_packet_signature: dec.content_key_packet_signature.clone(),
                    raw_node_passphrase_armored: Some(dec.raw_node_passphrase_armored.clone()),
                },
            ));

            if self.db.get_node(&child_vpath).is_some() {
                let _ = self.db.upsert_native_ids(
                    &child_vpath,
                    Some(&ctx.volume_id),
                    Some(&ctx.share_id),
                    Some(&dec.link_id),
                    Some(&folder_link.link_id),
                    dec.revision_id.as_deref(),
                    Some(&dec.name_hash),
                );
            }

            out.push(RemoteNode {
                name: dec.name,
                node_type: dec.node_type,
                size: dec.size,
                modify_time: Some(dec.mtime),
                uid: Some(dec.link_id),
            });
        }

        {
            let mut map = self.links_by_path.lock().unwrap();
            let active_child_paths: HashSet<String> =
                cache_updates.iter().map(|(k, _)| k.clone()).collect();
            let stale_keys: Vec<String> = map
                .keys()
                .filter(|k| {
                    if *k == "/" || active_child_paths.contains(*k) {
                        return false;
                    }
                    let parent = Path::new(k.as_str())
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "/".to_string());
                    parent == vpath
                })
                .cloned()
                .collect();
            for stale in stale_keys {
                map.remove(&stale);
            }
            for (k, v) in cache_updates {
                map.insert(k, v);
            }
        }

        Ok(out)
    }

    fn resolve_single_link_metadata(
        &self,
        ctx: &VolumeContext,
        link: &mut CachedRemoteLink,
    ) -> Result<(), String> {
        if link.revision_id.is_some() && link.content_key_packet.is_some() {
            return Ok(());
        }
        let resp = DriveEndpoints::fetch_links_metadata(
            &self.http,
            &ctx.volume_id,
            std::slice::from_ref(&link.link_id),
        )
        .map_err(|e| format!("Failed fetching metadata for {}: {}", link.link_id, e))?;
        if resp.code != 1000 && resp.code != 1001 {
            return Err(format!(
                "Fetch link metadata rejected with code {}",
                resp.code
            ));
        }
        if let Some(meta) = resp.links.into_iter().next() {
            link.link_type = meta.link_type;
            if let Some(fp) = meta.file_properties {
                link.content_key_packet = Some(fp.content_key_packet);
                link.content_key_packet_signature = fp.content_key_packet_signature;
                if let Some(rev) = fp.active_revision {
                    link.revision_id = Some(rev.id);
                }
            }
        }
        Ok(())
    }

    fn move_node_internal(
        &self,
        source_path: &str,
        target_parent_path: &str,
        new_name: Option<&str>,
    ) -> bool {
        let res = (|| -> Result<(), String> {
            if let Some(name) = new_name {
                if name.trim().is_empty() || name == "." || name == ".." || name.contains('/') {
                    return Err(format!(
                        "Invalid target name for move_and_rename: {:?}",
                        name
                    ));
                }
            }
            let src_vpath = normalize_virtual_path(source_path);
            let dst_parent_vpath = normalize_virtual_path(target_parent_path);
            if src_vpath == "/" {
                return Err("Cannot move root link".to_string());
            }
            if dst_parent_vpath == src_vpath
                || dst_parent_vpath.starts_with(&format!("{}/", src_vpath))
            {
                return Err(format!(
                    "Cannot move '{}' inside itself or descendant '{}'",
                    src_vpath, dst_parent_vpath
                ));
            }

            let (ctx, src_link) = self.resolve_path(&src_vpath)?;
            let (_, dst_parent_link) = self.resolve_path(&dst_parent_vpath)?;

            let old_parent_id = src_link
                .parent_link_id
                .as_deref()
                .ok_or_else(|| "Cannot move root link".to_string())?;
            let target_name = new_name.unwrap_or(&src_link.name);
            if old_parent_id == dst_parent_link.link_id {
                if target_name == src_link.name {
                    return Ok(());
                }
                if self.rename(source_path, target_name) {
                    return Ok(());
                }
                return Err(format!(
                    "Rename failed for '{}' -> '{}'",
                    source_path, target_name
                ));
            }
            let old_parent_keys = self
                .node_cache
                .get(old_parent_id)
                .ok_or_else(|| "Source parent folder key not unlocked".to_string())?;
            let dst_parent_keys = self
                .node_cache
                .get(&dst_parent_link.link_id)
                .ok_or_else(|| "Destination parent folder key not unlocked".to_string())?;
            let dst_hash_key = dst_parent_keys
                .node_hash_key
                .as_ref()
                .ok_or_else(|| "Destination parent hash key missing".to_string())?;

            let addr = self
                .vault
                .primary_address_key()
                .ok_or_else(|| "No unlocked address key".to_string())?;

            let child_keys = self.node_cache.get(&src_link.link_id);
            let new_passphrase = if let Some(ref armored_pp) = src_link.raw_node_passphrase_armored
            {
                Encryptor::reencrypt_key_packet(
                    armored_pp,
                    &old_parent_keys.unlocked_key.armored_private,
                    old_parent_keys.node_passphrase_raw.as_str(),
                    &dst_parent_keys.unlocked_key.armored_public,
                )?
            } else if let Some(ref ck) = child_keys {
                Encryptor::encrypt_text(
                    ck.node_passphrase_raw.as_str(),
                    &dst_parent_keys.unlocked_key.armored_public,
                )?
            } else {
                return Err("Missing node passphrase material for move".to_string());
            };

            let enc_name = Encryptor::encrypt_and_sign_text(
                target_name,
                &dst_parent_keys.unlocked_key.armored_public,
                &addr.passphrase,
                &addr.unlocked.armored_private,
            )?;
            let new_hash = NameHasher::hash(target_name, dst_hash_key)?;

            let params = MoveMultipleParameters {
                parent_link_id: dst_parent_link.link_id.clone(),
                links: vec![MoveMultipleLinkItem {
                    link_id: src_link.link_id.clone(),
                    name: enc_name,
                    node_passphrase: new_passphrase.clone(),
                    hash: new_hash.clone(),
                    original_hash: src_link.name_hash.clone(),
                    content_hash: None,
                    node_passphrase_signature: None,
                }],
                name_signature_email: addr.email,
                signature_email: None,
                new_share_id: None,
            };

            let resp = DriveEndpoints::move_multiple(&self.http, &ctx.volume_id, &params)
                .map_err(|e| format!("Move HTTP failed: {}", e))?;
            if resp.code != 1000 && resp.code != 1001 {
                return Err(format!("Move rejected with code {}", resp.code));
            }
            for item in &resp.responses {
                item.response.ensure_ok("Move link item")?;
            }

            let new_vpath = if dst_parent_vpath == "/" {
                format!("/{}", target_name)
            } else {
                format!("{}/{}", dst_parent_vpath, target_name)
            };

            self.relocate_cached_subtree(
                &src_vpath,
                &new_vpath,
                &src_link.link_id,
                new_name,
                &new_hash,
                Some(&dst_parent_link.link_id),
                Some(&new_passphrase),
            );
            Ok(())
        })();

        if let Err(ref e) = res {
            error!(
                "Native move_node failed for {} -> {} (new_name={:?}): {}",
                source_path, target_parent_path, new_name, e
            );
        }
        res.is_ok()
    }
}

impl RemoteDrive for NativeProtonClient {
    fn check_auth_status(&self) -> (bool, String) {
        if self.vault.is_authenticated() {
            let email = self
                .vault
                .snapshot()
                .map(|s| s.user_email)
                .unwrap_or_default();
            if email.is_empty() {
                (true, "Authenticated".to_string())
            } else {
                (true, format!("Authenticated ({})", email))
            }
        } else {
            (false, "Not authenticated".to_string())
        }
    }

    fn start_login(&self) -> Result<String, String> {
        if self.vault.is_authenticated() {
            Ok("Already authenticated".to_string())
        } else {
            Err("Native login requires username and password credentials".to_string())
        }
    }

    fn authenticate(
        &self,
        username: &str,
        password: &str,
        totp: Option<&str>,
    ) -> Result<String, String> {
        let msg = self.auth.authenticate(username, password, totp)?;
        self.reset_caches();
        Ok(msg)
    }

    fn start_browser_login(&self) -> Result<(String, String), String> {
        let challenge = self.auth.start_browser_login(None)?;
        let out = (challenge.login_url.clone(), challenge.user_code.clone());
        *self.active_browser_challenge.lock().unwrap() = Some(challenge);
        Ok(out)
    }

    fn poll_browser_login(&self) -> Result<Option<String>, String> {
        let challenge = self
            .active_browser_challenge
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "No active browser SSO login challenge".to_string())?;
        let res = self.auth.poll_browser_login_once(&challenge)?;
        if res.is_some() {
            self.reset_caches();
        }
        Ok(res)
    }

    fn logout(&self) -> bool {
        self.reset_caches();
        self.auth.logout()
    }

    fn list_path(&self, remote_path: &str) -> Result<Vec<RemoteNode>, String> {
        self.list_path_internal(remote_path)
    }

    fn download_file(
        &self,
        remote_path: &str,
        local_target_dir: &Path,
        conflict_strategy: &str,
    ) -> bool {
        match self.download_file_checked(remote_path, local_target_dir, conflict_strategy) {
            Ok(_) => true,
            Err(e) => {
                error!("Native download_file failed for {}: {}", remote_path, e);
                false
            }
        }
    }

    fn upload_file(
        &self,
        local_file: &Path,
        remote_parent_path: &str,
        conflict_strategy: &str,
    ) -> bool {
        let res = (|| -> Result<(), String> {
            let file_name = local_file
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| format!("Invalid local file name: {:?}", local_file))?;
            let parent_vpath = normalize_virtual_path(remote_parent_path);
            let (ctx, parent_link) = self.resolve_path(&parent_vpath)?;
            let parent_keys = self
                .node_cache
                .get(&parent_link.link_id)
                .ok_or_else(|| format!("Parent key not unlocked for {}", parent_vpath))?;
            let parent_hash_key = parent_keys
                .node_hash_key
                .as_ref()
                .ok_or_else(|| format!("Parent folder hash key missing for {}", parent_vpath))?;

            // Refresh parent listing so overwrite/new-revision and conflict detection are authoritative
            self.list_path_internal(&parent_vpath)?;

            let target_vpath = if parent_vpath == "/" {
                format!("/{}", file_name)
            } else {
                format!("{}/{}", parent_vpath, file_name)
            };

            let existing = self
                .links_by_path
                .lock()
                .unwrap()
                .get(&target_vpath)
                .cloned();
            let (effective_name, existing_opt, existing_unlocked) = match existing {
                Some(mut ex) => {
                    if conflict_strategy == "skip" {
                        return Ok(());
                    }
                    if conflict_strategy == "rename" {
                        let stem = Path::new(file_name)
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or(file_name);
                        let ext = Path::new(file_name)
                            .extension()
                            .and_then(|s| s.to_str())
                            .map(|e| format!(".{}", e))
                            .unwrap_or_default();
                        let map = self.links_by_path.lock().unwrap();
                        let mut chosen = None;
                        for idx in 1..1000 {
                            let candidate_name = format!("{} ({}){}", stem, idx, ext);
                            let candidate_vpath = if parent_vpath == "/" {
                                format!("/{}", candidate_name)
                            } else {
                                format!("{}/{}", parent_vpath, candidate_name)
                            };
                            if !map.contains_key(&candidate_vpath) {
                                chosen = Some(candidate_name);
                                break;
                            }
                        }
                        let alt = chosen.ok_or_else(|| {
                            "Unable to find non-colliding upload filename".to_string()
                        })?;
                        (alt, None, None)
                    } else {
                        if ex.link_type == 1 {
                            return Err(format!(
                                "Cannot overwrite remote folder '{}' with a file",
                                target_vpath
                            ));
                        }
                        self.resolve_single_link_metadata(&ctx, &mut ex)?;
                        let ex_key = self
                            .node_cache
                            .get(&ex.link_id)
                            .map(|c| c.unlocked_key)
                            .ok_or_else(|| {
                                format!(
                                    "Unlocked node key missing for existing file {}",
                                    ex.link_id
                                )
                            })?;
                        let kp = ex.content_key_packet.clone().ok_or_else(|| {
                            format!("ContentKeyPacket missing for existing file {}", ex.link_id)
                        })?;
                        (file_name.to_string(), Some((ex.link_id, kp)), Some(ex_key))
                    }
                }
                None => (file_name.to_string(), None, None),
            };

            let existing_ref = existing_opt
                .as_ref()
                .map(|(lid, kp)| (lid.as_str(), kp.as_str()));

            let uploaded = transfer::upload_file_blocks(
                &self.http,
                &self.vault,
                &ctx.volume_id,
                &parent_link.share_id,
                &parent_link.link_id,
                &parent_keys.unlocked_key.armored_public,
                parent_hash_key,
                existing_ref,
                existing_unlocked.as_ref(),
                local_file,
                &effective_name,
            )?;

            let final_vpath = if parent_vpath == "/" {
                format!("/{}", effective_name)
            } else {
                format!("{}/{}", parent_vpath, effective_name)
            };

            self.recently_trashed_by_path
                .lock()
                .unwrap()
                .remove(&final_vpath);

            if let Some(entry) = self.links_by_path.lock().unwrap().get_mut(&final_vpath) {
                entry.revision_id = Some(uploaded.revision_id.clone());
            }

            if self.db.get_node(&final_vpath).is_some() {
                let _ = self.db.upsert_native_ids(
                    &final_vpath,
                    Some(&ctx.volume_id),
                    Some(&parent_link.share_id),
                    Some(&uploaded.link_id),
                    Some(&parent_link.link_id),
                    Some(&uploaded.revision_id),
                    uploaded.name_hash.as_deref(),
                );
            }

            let _ = self.list_path_internal(&parent_vpath);
            Ok(())
        })();

        if let Err(ref e) = res {
            error!(
                "Native upload_file failed for {:?} -> {}: {}",
                local_file, remote_parent_path, e
            );
        }
        res.is_ok()
    }

    fn create_folder(&self, remote_parent: &str, folder_name: &str) -> bool {
        let res = (|| -> Result<(), String> {
            let parent_vpath = normalize_virtual_path(remote_parent);
            let (ctx, parent_link) = self.resolve_path(&parent_vpath)?;
            let parent_keys = self
                .node_cache
                .get(&parent_link.link_id)
                .ok_or_else(|| format!("Parent key not unlocked for {}", parent_vpath))?;
            let parent_hash_key = parent_keys
                .node_hash_key
                .as_ref()
                .ok_or_else(|| format!("Parent hash key missing for {}", parent_vpath))?;

            let addr = self
                .vault
                .primary_address_key()
                .ok_or_else(|| "No unlocked address key in SessionVault".to_string())?;

            let folder_creds = Encryptor::generate_node_keys(
                &addr.passphrase,
                &addr.unlocked.armored_private,
                &parent_keys.unlocked_key.armored_public,
            )?;
            let folder_hash_key =
                Encryptor::generate_node_hash_key(&folder_creds.key, &folder_creds.passphrase_raw)?;
            let enc_name = Encryptor::encrypt_and_sign_text(
                folder_name,
                &parent_keys.unlocked_key.armored_public,
                &addr.passphrase,
                &addr.unlocked.armored_private,
            )?;
            let name_hash = NameHasher::hash(folder_name, parent_hash_key)?;

            let resp = DriveEndpoints::create_folder(
                &self.http,
                &parent_link.share_id,
                &NewFolderParameters {
                    name: enc_name,
                    hash: name_hash.clone(),
                    parent_link_id: parent_link.link_id.clone(),
                    node_key: folder_creds.key.clone(),
                    node_hash_key: folder_hash_key,
                    node_passphrase: folder_creds.passphrase.clone(),
                    node_passphrase_signature: folder_creds.signature,
                    signature_address: addr.email,
                },
            )
            .map_err(|e| format!("Create folder HTTP failed: {}", e))?;
            if resp.code != 1000 && resp.code != 1001 {
                return Err(format!("Create folder rejected with code {}", resp.code));
            }

            let child_vpath = if parent_vpath == "/" {
                format!("/{}", folder_name)
            } else {
                format!("{}/{}", parent_vpath, folder_name)
            };

            self.recently_trashed_by_path
                .lock()
                .unwrap()
                .remove(&child_vpath);

            if self.db.get_node(&child_vpath).is_some() {
                let _ = self.db.upsert_native_ids(
                    &child_vpath,
                    Some(&ctx.volume_id),
                    Some(&parent_link.share_id),
                    Some(&resp.folder.id),
                    Some(&parent_link.link_id),
                    None,
                    Some(&name_hash),
                );
            }
            let _ = self.list_path_internal(&parent_vpath);
            Ok(())
        })();

        if let Err(ref e) = res {
            error!(
                "Native create_folder failed for {}/{}: {}",
                remote_parent, folder_name, e
            );
        }
        res.is_ok()
    }

    fn rename(&self, remote_path: &str, new_name: &str) -> bool {
        let res = (|| -> Result<(), String> {
            if new_name.trim().is_empty()
                || new_name == "."
                || new_name == ".."
                || new_name.contains('/')
            {
                return Err(format!("Invalid target name for rename: {:?}", new_name));
            }
            let vpath = normalize_virtual_path(remote_path);
            let (_ctx, link) = self.resolve_path(&vpath)?;
            let parent_link_id = link
                .parent_link_id
                .as_deref()
                .ok_or_else(|| "Cannot rename root link".to_string())?;
            let parent_keys = self
                .node_cache
                .get(parent_link_id)
                .ok_or_else(|| "Parent folder key not unlocked for rename".to_string())?;
            let parent_hash_key = parent_keys
                .node_hash_key
                .as_ref()
                .ok_or_else(|| "Parent folder hash key missing for rename".to_string())?;
            let addr = self
                .vault
                .primary_address_key()
                .ok_or_else(|| "No unlocked address key".to_string())?;

            let enc_name = Encryptor::encrypt_and_sign_text(
                new_name,
                &parent_keys.unlocked_key.armored_public,
                &addr.passphrase,
                &addr.unlocked.armored_private,
            )?;
            let new_hash = NameHasher::hash(new_name, parent_hash_key)?;

            let resp = DriveEndpoints::rename_node(
                &self.http,
                &link.share_id,
                &link.link_id,
                &RenameNodeParameters {
                    name: enc_name,
                    hash: Some(new_hash.clone()),
                    mime_type: None,
                    signature_address: addr.email,
                    original_hash: Some(link.name_hash.clone()),
                },
            )
            .map_err(|e| format!("Rename failed: {}", e))?;
            resp.ensure_ok("Rename node")?;

            let parent_vpath = Path::new(&vpath)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".to_string());
            let new_vpath = if parent_vpath == "/" {
                format!("/{}", new_name)
            } else {
                format!("{}/{}", parent_vpath.trim_end_matches('/'), new_name)
            };

            self.relocate_cached_subtree(
                &vpath,
                &new_vpath,
                &link.link_id,
                Some(new_name),
                &new_hash,
                None,
                None,
            );
            Ok(())
        })();

        if let Err(ref e) = res {
            error!(
                "Native rename failed for {} -> {}: {}",
                remote_path, new_name, e
            );
        }
        res.is_ok()
    }

    fn move_node(&self, source_path: &str, target_parent_path: &str) -> bool {
        self.move_node_internal(source_path, target_parent_path, None)
    }

    fn supports_atomic_move_and_rename(&self) -> bool {
        true
    }

    fn move_and_rename(&self, source_path: &str, target_parent_path: &str, new_name: &str) -> bool {
        self.move_node_internal(source_path, target_parent_path, Some(new_name))
    }

    fn trash(&self, remote_path: &str) -> bool {
        let res = (|| -> Result<(), String> {
            let vpath = normalize_virtual_path(remote_path);
            let (ctx, link) = self.resolve_path(&vpath)?;
            let parent_link_id = link
                .parent_link_id
                .as_deref()
                .ok_or_else(|| "Cannot trash root link".to_string())?;
            let resp = DriveEndpoints::trash_links(
                &self.http,
                &link.share_id,
                parent_link_id,
                std::slice::from_ref(&link.link_id),
            )
            .map_err(|e| format!("Trash HTTP failed: {}", e))?;
            if resp.code != 1000 && resp.code != 1001 {
                return Err(format!("Trash rejected with code {}", resp.code));
            }
            for item in &resp.responses {
                item.response.ensure_ok("Trash link item")?;
            }
            self.evict_cached_subtree(&vpath, &link.link_id);
            self.recently_trashed_by_path
                .lock()
                .unwrap()
                .insert(vpath, (ctx.volume_id, link.link_id));
            Ok(())
        })();

        if let Err(ref e) = res {
            error!("Native trash failed for {}: {}", remote_path, e);
        }
        res.is_ok()
    }

    fn restore_from_trash(&self, link_id: &str) -> bool {
        let res = (|| -> Result<(), String> {
            let trimmed = link_id.trim();
            if trimmed.is_empty() {
                return Err("LinkID cannot be empty".to_string());
            }
            let ctx = self.ensure_bootstrapped()?;
            let resp = DriveEndpoints::restore_trash_links(
                &self.http,
                &ctx.volume_id,
                &[trimmed.to_string()],
            )
            .map_err(|e| format!("Restore trash HTTP failed: {}", e))?;
            if resp.code != 1000 && resp.code != 1001 {
                return Err(format!("Restore trash rejected with code {}", resp.code));
            }
            for item in &resp.responses {
                item.response.ensure_ok("Restore trashed link")?;
            }
            self.recently_trashed_by_path
                .lock()
                .unwrap()
                .retain(|_, (_, lid)| lid != trimmed);
            Ok(())
        })();

        if let Err(ref e) = res {
            error!("Native restore_from_trash failed for {}: {}", link_id, e);
        }
        res.is_ok()
    }

    fn delete(&self, remote_path: &str) -> bool {
        let res = (|| -> Result<(), String> {
            let vpath = normalize_virtual_path(remote_path);
            let (volume_id, link_id, from_recent_trash) = match self.resolve_path(&vpath) {
                Ok((ctx, link)) => (ctx.volume_id, link.link_id, false),
                Err(resolve_err) => {
                    if let Some((vol_id, lid)) = self
                        .recently_trashed_by_path
                        .lock()
                        .unwrap()
                        .get(&vpath)
                        .cloned()
                    {
                        (vol_id, lid, true)
                    } else {
                        return Err(resolve_err);
                    }
                }
            };
            let resp = DriveEndpoints::delete_multiple(
                &self.http,
                &volume_id,
                std::slice::from_ref(&link_id),
            )
            .map_err(|e| format!("Delete HTTP failed: {}", e))?;
            if resp.code != 1000 && resp.code != 1001 {
                return Err(format!("Delete rejected with code {}", resp.code));
            }
            for item in &resp.responses {
                item.response.ensure_ok("Delete link item")?;
            }
            self.evict_cached_subtree(&vpath, &link_id);
            if from_recent_trash {
                self.recently_trashed_by_path.lock().unwrap().remove(&vpath);
            }
            Ok(())
        })();

        if let Err(ref e) = res {
            error!("Native delete failed for {}: {}", remote_path, e);
        }
        res.is_ok()
    }

    fn get_storage_quota(&self) -> StorageQuota {
        match self.auth.refresh_quota() {
            Ok(q) => q,
            Err(e) => {
                warn!("Failed refreshing native storage quota: {}", e);
                self.vault.storage_quota()
            }
        }
    }

    fn backend_name(&self) -> &'static str {
        "native"
    }

    fn supports_block_range_reads(&self) -> bool {
        true
    }

    fn backfill_native_ids(&self, db: &MetadataDB) {
        if let Some(ctx) = self.volume_ctx.lock().unwrap().clone() {
            self.sync_cached_ids_to_db(db, &ctx.volume_id);
        }
    }

    fn poll_events(
        &self,
        db: &MetadataDB,
        cache_dir: &Path,
        activity: &ActivityRegistry,
    ) -> Option<Result<usize, String>> {
        if !self.vault.is_authenticated() {
            return Some(Err("Not authenticated".to_string()));
        }
        let res = (|| -> Result<usize, String> {
            let ctx = self.ensure_bootstrapped()?;
            self.sync_cached_ids_to_db(db, &ctx.volume_id);
            EventProcessor::poll_volume_events(
                &self.http,
                &self.vault,
                db,
                cache_dir,
                activity,
                &self.node_cache,
                &self.links_by_path,
                &ctx.volume_id,
                &ctx.share_id,
            )
        })();
        Some(res)
    }

    fn read_block_range(
        &self,
        remote_path: &str,
        offset: u64,
        size: usize,
    ) -> Option<Result<Vec<u8>, String>> {
        let res = (|| -> Result<Vec<u8>, String> {
            let (ctx, mut link) = self.resolve_path(remote_path)?;
            self.resolve_single_link_metadata(&ctx, &mut link)?;
            let revision_id = link
                .revision_id
                .as_deref()
                .ok_or_else(|| format!("File {} has no active revision", remote_path))?;
            let kp = link
                .content_key_packet
                .as_deref()
                .ok_or_else(|| format!("File {} has no ContentKeyPacket", remote_path))?;
            let cached_keys = self
                .node_cache
                .get(&link.link_id)
                .ok_or_else(|| format!("Unlocked node key missing for {}", link.link_id))?;
            transfer::read_block_range(
                &self.http,
                &link.share_id,
                &link.link_id,
                revision_id,
                kp,
                &cached_keys.unlocked_key,
                offset,
                size,
            )
        })();
        Some(res)
    }
}
