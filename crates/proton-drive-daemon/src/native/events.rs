use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::client::parse_iso8601_utc_seconds;
use crate::fuse_fs::{is_safe_cache_file_path, ActivityRegistry};
use crate::metadata_db::{MetadataDB, SyncStatus};

use super::auth::SessionVault;
use super::crypto::{
    CachedNodeKeys, Decryptor, DriveKey, ExtendedAttributes, NodeKeyCache, UnlockedKey,
};
use super::endpoints::{DriveEndpoints, LinkMetadata};
use super::http::PdHttpClient;
use super::CachedRemoteLink;

pub const EVENT_DELETE: i32 = 0;
pub const EVENT_CREATE: i32 = 1;
pub const EVENT_UPDATE_CONTENT: i32 = 2;
pub const EVENT_UPDATE_METADATA: i32 = 3;

#[derive(Clone)]
pub struct DecryptedLinkInfo {
    pub link_id: String,
    pub parent_link_id: Option<String>,
    pub name: String,
    pub node_type: String,
    pub size: i64,
    pub mtime: f64,
    pub name_hash: String,
    pub revision_id: Option<String>,
    pub content_key_packet: Option<String>,
    pub content_key_packet_signature: Option<String>,
    pub unlocked_key: UnlockedKey,
    pub node_passphrase_raw: Zeroizing<String>,
    pub node_hash_key: Option<Zeroizing<Vec<u8>>>,
    pub raw_node_passphrase_armored: String,
}

fn decode_hash_key_bytes(raw: &[u8]) -> Zeroizing<Vec<u8>> {
    // Proton Drive computes HMAC-SHA256 using the decrypted NodeHashKey bytes directly
    // (never base64-decoded; see PDCore `Encryptor.hmac(filename:parentHashKey:)`).
    Zeroizing::new(raw.to_vec())
}

pub fn decrypt_link_with_parent(
    link: &LinkMetadata,
    _share_id: &str,
    parent_key: &UnlockedKey,
    verification_keys: &[String],
) -> Result<DecryptedLinkInfo, String> {
    let mut base_verif = verification_keys.to_vec();
    if base_verif.is_empty() {
        base_verif.push(parent_key.armored_public.clone());
    }

    let name_sig_empty = link
        .name_signature_email
        .as_deref()
        .unwrap_or(&link.signature_email)
        .trim()
        .is_empty();
    let mut name_verif = base_verif.clone();
    if name_sig_empty && !name_verif.contains(&parent_key.armored_public) {
        name_verif.push(parent_key.armored_public.clone());
    }

    let name_ver = Decryptor::decrypt_and_verify_node_name(&link.name, parent_key, &name_verif)?;
    let name = name_ver.into_value();

    let pass_sig_empty = link.signature_email.trim().is_empty();
    let mut pass_verif = base_verif.clone();
    if pass_sig_empty && !pass_verif.contains(&parent_key.armored_public) {
        pass_verif.push(parent_key.armored_public.clone());
    }

    let pass_ver = Decryptor::decrypt_and_verify_node_passphrase(
        &link.node_passphrase,
        &link.node_passphrase_signature,
        &pass_verif,
        std::slice::from_ref(parent_key),
    )?;
    let node_passphrase_raw = Zeroizing::new(pass_ver.into_value());

    let unlocked_key = DriveKey::unlock(&link.node_key, &node_passphrase_raw)?;

    let node_hash_key = if let Some(ref fp) = link.folder_properties {
        let mut hk_verif = base_verif.clone();
        if !hk_verif.contains(&unlocked_key.armored_public) {
            hk_verif.push(unlocked_key.armored_public.clone());
        }
        let dec = Decryptor::decrypt_and_verify_node_hash_key(
            &fp.node_hash_key,
            std::slice::from_ref(&unlocked_key),
            &hk_verif,
        )?;
        Some(decode_hash_key_bytes(dec.value()))
    } else {
        None
    };

    let mut size = link
        .file_properties
        .as_ref()
        .and_then(|fp| fp.active_revision.as_ref())
        .map(|r| r.size)
        .unwrap_or(link.size);
    let mut mtime = if link.modify_time > 0.0 {
        link.modify_time
    } else {
        link.create_time
    };

    if let Some(ref enc_xattr) = link.xattr {
        if let Ok(dec_xattr) =
            Decryptor::decrypt_and_verify_xattributes(enc_xattr, &unlocked_key, &base_verif)
        {
            if let Ok(parsed) = ExtendedAttributes::decode(dec_xattr.value()) {
                if let Some(common) = parsed.common {
                    if let Some(s) = common.size {
                        size = s;
                    }
                    if let Some(ref mt) = common.modification_time {
                        if let Some(secs) = parse_iso8601_utc_seconds(mt) {
                            mtime = secs;
                        }
                    }
                }
            }
        }
    }

    let node_type = match link.link_type {
        1 => "folder".to_string(),
        3 => "album".to_string(),
        _ => "file".to_string(),
    };
    if node_type == "folder" || node_type == "album" {
        size = 0;
    }

    let revision_id = link
        .file_properties
        .as_ref()
        .and_then(|fp| fp.active_revision.as_ref())
        .map(|r| r.id.clone());
    let content_key_packet = link
        .file_properties
        .as_ref()
        .map(|fp| fp.content_key_packet.clone());
    let content_key_packet_signature = link
        .file_properties
        .as_ref()
        .and_then(|fp| fp.content_key_packet_signature.clone());

    Ok(DecryptedLinkInfo {
        link_id: link.link_id.clone(),
        parent_link_id: link.parent_link_id.clone(),
        name,
        node_type,
        size,
        mtime,
        name_hash: link.hash.clone(),
        revision_id,
        content_key_packet,
        content_key_packet_signature,
        unlocked_key,
        node_passphrase_raw,
        node_hash_key,
        raw_node_passphrase_armored: link.node_passphrase.clone(),
    })
}

pub struct EventProcessor;

impl EventProcessor {
    pub fn event_cursor_key(volume_id: &str) -> String {
        format!("native_latest_event_id_{}", volume_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn poll_volume_events(
        http: &PdHttpClient,
        vault: &SessionVault,
        db: &MetadataDB,
        cache_dir: &Path,
        activity: &ActivityRegistry,
        node_cache: &NodeKeyCache,
        links_by_path: &Mutex<HashMap<String, CachedRemoteLink>>,
        volume_id: &str,
        share_id: &str,
    ) -> Result<usize, String> {
        let cursor_key = Self::event_cursor_key(volume_id);
        let mut cursor = match db.get_setting(&cursor_key) {
            Some(c) if !c.is_empty() => c,
            _ => {
                let latest = DriveEndpoints::get_latest_event_id(http, volume_id)
                    .map_err(|e| format!("Failed getting latest event ID: {}", e))?;
                if latest.code != 1000 && latest.code != 1001 {
                    return Err(format!(
                        "Latest event ID rejected with API code {}",
                        latest.code
                    ));
                }
                db.set_setting(&cursor_key, &latest.event_id);
                return Ok(0);
            }
        };

        let verif_keys = vault.address_public_keys(None);
        let mut applied = 0usize;
        let mut seen_cursors = HashSet::new();
        seen_cursors.insert(cursor.clone());

        loop {
            let resp = DriveEndpoints::get_events(http, volume_id, &cursor)
                .map_err(|e| format!("Failed fetching volume events: {}", e))?;
            if resp.code != 1000 && resp.code != 1001 {
                return Err(format!("Get events rejected with API code {}", resp.code));
            }

            if resp.refresh != 0 {
                // Full resync requested by server; retain only "/", reset cursor, and bump refresh epoch
                {
                    let mut map = links_by_path.lock().unwrap();
                    map.retain(|k, _| k == "/");
                }
                if !resp.event_id.is_empty() {
                    db.set_setting(&cursor_key, &resp.event_id);
                }
                let next_epoch = db
                    .get_setting("native_refresh_epoch")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0)
                    + 1;
                db.set_setting("native_refresh_epoch", &next_epoch.to_string());
                return Ok(applied);
            }

            for ev in &resp.events {
                let effective_share_id = if ev.context_share_id.is_empty() {
                    share_id
                } else {
                    ev.context_share_id.as_str()
                };
                match ev.event_type {
                    EVENT_DELETE => {
                        if Self::apply_delete_event(
                            db,
                            cache_dir,
                            activity,
                            node_cache,
                            links_by_path,
                            volume_id,
                            &ev.link.link_id,
                        ) {
                            applied += 1;
                        }
                    }
                    EVENT_CREATE | EVENT_UPDATE_CONTENT | EVENT_UPDATE_METADATA => {
                        if ev.link.state != 1 || ev.link.trashed.is_some() {
                            if Self::apply_delete_event(
                                db,
                                cache_dir,
                                activity,
                                node_cache,
                                links_by_path,
                                volume_id,
                                &ev.link.link_id,
                            ) {
                                applied += 1;
                            }
                            continue;
                        }

                        if Self::apply_upsert_event(
                            http,
                            db,
                            cache_dir,
                            activity,
                            node_cache,
                            links_by_path,
                            &verif_keys,
                            volume_id,
                            effective_share_id,
                            ev.event_type,
                            &ev.link,
                        )? {
                            applied += 1;
                        }
                    }
                    _ => {}
                }
            }

            if resp.event_id != cursor && !resp.event_id.is_empty() {
                cursor = resp.event_id.clone();
                db.set_setting(&cursor_key, &cursor);
            }
            if resp.more == 0 {
                break;
            }
            if resp.event_id.is_empty() || !seen_cursors.insert(resp.event_id.clone()) {
                return Err(format!(
                    "Event pagination cursor did not advance while More=1: {}",
                    resp.event_id
                ));
            }
        }

        Ok(applied)
    }

    fn is_node_protected(
        node: &crate::metadata_db::Node,
        db: &MetadataDB,
        activity: &ActivityRegistry,
    ) -> bool {
        if !node.remote_exists
            || node.sync_status == SyncStatus::MODIFIED
            || node.sync_status == SyncStatus::SYNCING
            || node.sync_status == SyncStatus::ERROR
            || activity.is_inflight(&node.cache_id)
            || activity.is_inflight(&node.path)
            || activity.has_open_handle(&node.cache_id)
        {
            return true;
        }
        if node.node_type == "folder" || node.node_type == "album" {
            let subtree = db.get_subtree_nodes(&node.path);
            return subtree.iter().any(|n| {
                !n.remote_exists
                    || n.sync_status == SyncStatus::MODIFIED
                    || n.sync_status == SyncStatus::SYNCING
                    || n.sync_status == SyncStatus::ERROR
                    || activity.is_inflight(&n.cache_id)
                    || activity.is_inflight(&n.path)
                    || activity.has_open_handle(&n.cache_id)
            });
        }
        false
    }

    fn evict_path_cache_entries(
        links_by_path: &Mutex<HashMap<String, CachedRemoteLink>>,
        node_cache: &NodeKeyCache,
        link_id: &str,
        path_hint: Option<&str>,
    ) {
        let evicted_ids: Vec<String> = {
            let mut map = links_by_path.lock().unwrap();
            let prefix = path_hint.map(|p| format!("{}/", p.trim_end_matches('/')));
            let keys_to_remove: Vec<String> = map
                .iter()
                .filter(|(k, v)| {
                    *k != "/"
                        && (v.link_id == link_id
                            || path_hint == Some(k.as_str())
                            || prefix.as_ref().is_some_and(|pref| k.starts_with(pref)))
                })
                .map(|(k, _)| k.clone())
                .collect();
            let mut ids = Vec::with_capacity(keys_to_remove.len());
            for k in keys_to_remove {
                if let Some(entry) = map.remove(&k) {
                    ids.push(entry.link_id);
                }
            }
            ids
        };
        node_cache.invalidate(link_id);
        for id in evicted_ids {
            node_cache.invalidate(&id);
        }
    }

    fn relocate_path_cache_subtree(
        links_by_path: &Mutex<HashMap<String, CachedRemoteLink>>,
        old_path: &str,
        new_path: &str,
    ) {
        if old_path == new_path {
            return;
        }
        let old_prefix = format!("{}/", old_path.trim_end_matches('/'));
        let new_prefix = format!("{}/", new_path.trim_end_matches('/'));
        let mut map = links_by_path.lock().unwrap();
        let descendants: Vec<(String, CachedRemoteLink)> = map
            .iter()
            .filter(|(k, _)| k.starts_with(&old_prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, _) in &descendants {
            map.remove(k);
        }
        if let Some(entry) = map.remove(old_path) {
            map.insert(new_path.to_string(), entry);
        }
        for (k, v) in descendants {
            if let Some(suffix) = k.strip_prefix(&old_prefix) {
                map.insert(format!("{}{}", new_prefix, suffix), v);
            }
        }
    }

    fn resolve_folder_path(
        db: &MetadataDB,
        links_by_path: &Mutex<HashMap<String, CachedRemoteLink>>,
        volume_id: &str,
        folder_link_id: &str,
    ) -> Option<String> {
        if let Some(node) = db
            .get_node_by_link_id(volume_id, folder_link_id)
            .or_else(|| db.get_node_by_only_link_id(folder_link_id))
        {
            return Some(node.path);
        }
        links_by_path
            .lock()
            .unwrap()
            .iter()
            .find(|(_, v)| v.link_id == folder_link_id)
            .map(|(k, _)| k.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_folder_key_unlocked(
        http: &PdHttpClient,
        db: &MetadataDB,
        node_cache: &NodeKeyCache,
        links_by_path: &Mutex<HashMap<String, CachedRemoteLink>>,
        verif_keys: &[String],
        volume_id: &str,
        share_id: &str,
        folder_link_id: &str,
    ) -> Result<Option<(CachedNodeKeys, String)>, String> {
        if let Some(cached) = node_cache.get(folder_link_id) {
            if let Some(path) =
                Self::resolve_folder_path(db, links_by_path, volume_id, folder_link_id)
            {
                return Ok(Some((cached, path)));
            }
        }

        // Walk upward to the closest unlocked ancestor (typically root "/" after restart)
        let mut chain: Vec<LinkMetadata> = Vec::new();
        let mut cur_id = folder_link_id.to_string();
        let mut seen = HashSet::new();
        const MAX_DEPTH: usize = 64;

        while !(node_cache.get(&cur_id).is_some()
            && Self::resolve_folder_path(db, links_by_path, volume_id, &cur_id).is_some())
        {
            if chain.len() >= MAX_DEPTH || !seen.insert(cur_id.clone()) {
                return Ok(None);
            }
            let resp = DriveEndpoints::fetch_links_metadata(
                http,
                volume_id,
                std::slice::from_ref(&cur_id),
            )
            .map_err(|e| format!("Failed fetching ancestor metadata for {}: {}", cur_id, e))?;
            if resp.code != 1000 && resp.code != 1001 {
                return Err(format!(
                    "Fetch ancestor metadata rejected with code {}",
                    resp.code
                ));
            }
            let Some(meta) = resp.links.into_iter().next() else {
                return Ok(None);
            };
            if meta.state != 1 || meta.trashed.is_some() {
                return Ok(None);
            }
            let Some(parent_id) = meta.parent_link_id.clone() else {
                return Ok(None);
            };
            chain.push(meta);
            cur_id = parent_id;
        }

        let Some(mut cur_path) = Self::resolve_folder_path(db, links_by_path, volume_id, &cur_id)
        else {
            return Ok(None);
        };

        for meta in chain.iter().rev() {
            let Some(parent_keys) = node_cache.get(&cur_id) else {
                return Ok(None);
            };
            let dec =
                decrypt_link_with_parent(meta, share_id, &parent_keys.unlocked_key, verif_keys)?;
            if dec.name.is_empty() || dec.name == "." || dec.name == ".." || dec.name.contains('/')
            {
                return Ok(None);
            }
            let next_path = if cur_path == "/" {
                format!("/{}", dec.name)
            } else {
                format!("{}/{}", cur_path.trim_end_matches('/'), dec.name)
            };

            node_cache.insert(
                dec.link_id.clone(),
                CachedNodeKeys {
                    unlocked_key: dec.unlocked_key.clone(),
                    node_hash_key: dec.node_hash_key.clone(),
                    share_id: share_id.to_string(),
                    parent_link_id: dec.parent_link_id.clone(),
                    name: dec.name.clone(),
                    node_passphrase_raw: dec.node_passphrase_raw.clone(),
                },
            );
            links_by_path.lock().unwrap().insert(
                next_path.clone(),
                CachedRemoteLink {
                    link_id: dec.link_id.clone(),
                    parent_link_id: dec.parent_link_id.clone(),
                    share_id: share_id.to_string(),
                    link_type: meta.link_type,
                    name: dec.name.clone(),
                    name_hash: dec.name_hash.clone(),
                    revision_id: dec.revision_id.clone(),
                    content_key_packet: dec.content_key_packet.clone(),
                    content_key_packet_signature: dec.content_key_packet_signature.clone(),
                    raw_node_passphrase_armored: Some(dec.raw_node_passphrase_armored.clone()),
                },
            );

            if db.get_node(&next_path).is_none() {
                let _ = db.upsert_node(
                    &next_path,
                    &cur_path,
                    &dec.name,
                    &dec.node_type,
                    dec.size,
                    Some(dec.mtime),
                    None,
                    Some(SyncStatus::CLOUD_ONLY),
                    None,
                    Some(&dec.link_id),
                    None,
                    None,
                    Some(true),
                    None,
                );
            }
            let _ = db.upsert_native_ids(
                &next_path,
                Some(volume_id),
                Some(share_id),
                Some(&dec.link_id),
                Some(&cur_id),
                dec.revision_id.as_deref(),
                Some(&dec.name_hash),
            );

            cur_id = dec.link_id;
            cur_path = next_path;
        }

        Ok(node_cache.get(folder_link_id).map(|k| (k, cur_path)))
    }

    fn apply_delete_event(
        db: &MetadataDB,
        cache_dir: &Path,
        activity: &ActivityRegistry,
        node_cache: &NodeKeyCache,
        links_by_path: &Mutex<HashMap<String, CachedRemoteLink>>,
        volume_id: &str,
        link_id: &str,
    ) -> bool {
        let Some(node) = db
            .get_node_by_link_id(volume_id, link_id)
            .or_else(|| db.get_node_by_only_link_id(link_id))
        else {
            Self::evict_path_cache_entries(links_by_path, node_cache, link_id, None);
            return false;
        };

        if node.path == "/" || Self::is_node_protected(&node, db, activity) {
            return false;
        }

        let subtree = if node.node_type == "folder" || node.node_type == "album" {
            db.get_subtree_nodes(&node.path)
        } else {
            vec![node.clone()]
        };

        db.delete_node(&node.path);
        if node.node_type == "folder" || node.node_type == "album" {
            activity.untrack_dir(&node.path);
        }
        Self::evict_path_cache_entries(links_by_path, node_cache, link_id, Some(&node.path));

        for n in subtree {
            if let Some(ref lid) = n.link_id {
                node_cache.invalidate(lid);
            }
            if let Some(ref lp) = n.local_cache_path {
                let p = PathBuf::from(lp);
                if is_safe_cache_file_path(cache_dir, &p) {
                    let _ = fs::remove_file(&p);
                }
            }
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_upsert_event(
        http: &PdHttpClient,
        db: &MetadataDB,
        cache_dir: &Path,
        activity: &ActivityRegistry,
        node_cache: &NodeKeyCache,
        links_by_path: &Mutex<HashMap<String, CachedRemoteLink>>,
        verif_keys: &[String],
        volume_id: &str,
        share_id: &str,
        event_type: i32,
        link: &LinkMetadata,
    ) -> Result<bool, String> {
        let Some(ref parent_link_id) = link.parent_link_id else {
            return Ok(false);
        };
        let Some((parent_cached, parent_path)) = Self::ensure_folder_key_unlocked(
            http,
            db,
            node_cache,
            links_by_path,
            verif_keys,
            volume_id,
            share_id,
            parent_link_id,
        )?
        else {
            return Ok(false);
        };

        let dec =
            decrypt_link_with_parent(link, share_id, &parent_cached.unlocked_key, verif_keys)?;
        if dec.name.is_empty() || dec.name == "." || dec.name == ".." || dec.name.contains('/') {
            return Ok(false);
        }

        let target_path = if parent_path == "/" {
            format!("/{}", dec.name)
        } else {
            format!("{}/{}", parent_path.trim_end_matches('/'), dec.name)
        };

        node_cache.insert(
            dec.link_id.clone(),
            CachedNodeKeys {
                unlocked_key: dec.unlocked_key.clone(),
                node_hash_key: dec.node_hash_key.clone(),
                share_id: share_id.to_string(),
                parent_link_id: dec.parent_link_id.clone(),
                name: dec.name.clone(),
                node_passphrase_raw: dec.node_passphrase_raw.clone(),
            },
        );
        let updated_cached_link = CachedRemoteLink {
            link_id: dec.link_id.clone(),
            parent_link_id: dec.parent_link_id.clone(),
            share_id: share_id.to_string(),
            link_type: link.link_type,
            name: dec.name.clone(),
            name_hash: dec.name_hash.clone(),
            revision_id: dec.revision_id.clone(),
            content_key_packet: dec.content_key_packet.clone(),
            content_key_packet_signature: dec.content_key_packet_signature.clone(),
            raw_node_passphrase_armored: Some(dec.raw_node_passphrase_armored.clone()),
        };

        let existing_by_id = db
            .get_node_by_link_id(volume_id, &dec.link_id)
            .or_else(|| db.get_node_by_only_link_id(&dec.link_id));

        if let Some(ex) = existing_by_id {
            if Self::is_node_protected(&ex, db, activity) {
                return Ok(false);
            }

            let mut current_path = ex.path.clone();
            if ex.path != target_path {
                if let Some(dest) = db.get_node(&target_path) {
                    if Self::is_node_protected(&dest, db, activity) {
                        return Ok(false);
                    }
                    if dest.link_id.as_deref() != Some(dec.link_id.as_str()) {
                        let dest_subtree =
                            if dest.node_type == "folder" || dest.node_type == "album" {
                                db.get_subtree_nodes(&dest.path)
                            } else {
                                vec![dest.clone()]
                            };
                        db.delete_node(&dest.path);
                        if dest.node_type == "folder" || dest.node_type == "album" {
                            activity.untrack_dir(&dest.path);
                        }
                        if let Some(ref dlid) = dest.link_id {
                            Self::evict_path_cache_entries(
                                links_by_path,
                                node_cache,
                                dlid,
                                Some(&dest.path),
                            );
                        }
                        for n in dest_subtree {
                            if let Some(ref lp) = n.local_cache_path {
                                let p = PathBuf::from(lp);
                                if is_safe_cache_file_path(cache_dir, &p) {
                                    let _ = fs::remove_file(&p);
                                }
                            }
                        }
                    }
                }
                if db.get_node(&target_path).is_none()
                    && db.move_subtree(&ex.path, &target_path).is_ok()
                {
                    activity.rename_handle_paths(&ex.path, &target_path);
                    if ex.node_type == "folder" || ex.node_type == "album" {
                        activity.rename_tracked_dirs(&ex.path, &target_path);
                    }
                    Self::relocate_path_cache_subtree(links_by_path, &ex.path, &target_path);
                    current_path = target_path.clone();
                }
            }

            let rev_changed = dec.node_type == "file"
                && dec.revision_id.is_some()
                && ex.revision_id.as_deref() != dec.revision_id.as_deref();
            let content_changed = (event_type == EVENT_UPDATE_CONTENT || rev_changed)
                && (rev_changed
                    || dec.size != ex.size
                    || dec.node_type != ex.node_type
                    || ex.revision_id.is_none());

            if ex.node_type != dec.node_type {
                let subtree = db.get_subtree_nodes(&current_path);
                for n in subtree {
                    if let Some(ref lp) = n.local_cache_path {
                        let p = PathBuf::from(lp);
                        if is_safe_cache_file_path(cache_dir, &p) {
                            let _ = fs::remove_file(&p);
                        }
                    }
                }
                db.delete_node(&current_path);
                if ex.node_type == "folder" || ex.node_type == "album" {
                    activity.untrack_dir(&current_path);
                }
                let _ = db.upsert_node(
                    &current_path,
                    &parent_path,
                    &dec.name,
                    &dec.node_type,
                    dec.size,
                    Some(dec.mtime),
                    None,
                    Some(SyncStatus::CLOUD_ONLY),
                    None,
                    Some(&dec.link_id),
                    None,
                    None,
                    Some(true),
                    None,
                );
            } else if content_changed && ex.sync_status == SyncStatus::SYNCED {
                if let Some(ref lp) = ex.local_cache_path {
                    let p = PathBuf::from(lp);
                    if is_safe_cache_file_path(cache_dir, &p) {
                        let _ = fs::remove_file(&p);
                    }
                }
                let _ = db.invalidate_node_cache(
                    &current_path,
                    dec.size,
                    Some(dec.mtime),
                    Some(&dec.link_id),
                    &dec.node_type,
                );
            } else {
                let _ = db.update_clean_remote_metadata(
                    &current_path,
                    dec.size,
                    Some(dec.mtime),
                    Some(&dec.link_id),
                    &dec.node_type,
                );
            }

            let _ = db.upsert_native_ids(
                &current_path,
                Some(volume_id),
                Some(share_id),
                Some(&dec.link_id),
                Some(parent_link_id),
                dec.revision_id.as_deref(),
                Some(&dec.name_hash),
            );
            links_by_path
                .lock()
                .unwrap()
                .insert(current_path, updated_cached_link);
            return Ok(true);
        }

        if let Some(dest_existing) = db.get_node(&target_path) {
            if Self::is_node_protected(&dest_existing, db, activity) {
                return Ok(false);
            }
            if dest_existing.node_type != dec.node_type {
                let subtree = db.get_subtree_nodes(&dest_existing.path);
                for n in subtree {
                    if let Some(ref lp) = n.local_cache_path {
                        let p = PathBuf::from(lp);
                        if is_safe_cache_file_path(cache_dir, &p) {
                            let _ = fs::remove_file(&p);
                        }
                    }
                }
                db.delete_node(&dest_existing.path);
                if dest_existing.node_type == "folder" || dest_existing.node_type == "album" {
                    activity.untrack_dir(&dest_existing.path);
                }
            } else if dest_existing.sync_status == SyncStatus::SYNCED {
                if let Some(ref lp) = dest_existing.local_cache_path {
                    let p = PathBuf::from(lp);
                    if is_safe_cache_file_path(cache_dir, &p) {
                        let _ = fs::remove_file(&p);
                    }
                }
            }
        }

        let _ = db.upsert_node(
            &target_path,
            &parent_path,
            &dec.name,
            &dec.node_type,
            dec.size,
            Some(dec.mtime),
            None,
            Some(SyncStatus::CLOUD_ONLY),
            None,
            Some(&dec.link_id),
            None,
            None,
            Some(true),
            None,
        );
        let _ = db.upsert_native_ids(
            &target_path,
            Some(volume_id),
            Some(share_id),
            Some(&dec.link_id),
            Some(parent_link_id),
            dec.revision_id.as_deref(),
            Some(&dec.name_hash),
        );
        links_by_path
            .lock()
            .unwrap()
            .insert(target_path, updated_cached_link);

        Ok(true)
    }
}
