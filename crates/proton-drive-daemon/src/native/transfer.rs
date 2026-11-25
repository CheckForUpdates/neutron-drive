use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use super::auth::SessionVault;
use super::crypto::{
    format_iso8601_utc, sha256_bytes, Decryptor, DriveCrypto, DriveKey, Encryptor,
    ExtendedAttributes, NameHasher, SessionKey, Sha1Hasher, UnlockedKey,
};
use super::endpoints::{
    BlockMetadata, CodeResponse, ContentUploadLink, DriveEndpoints, NewBlockItem,
    NewBlocksParameters, NewFileParameters, UpdateRevisionParameters, VerifierInfo,
};
use super::http::{PdHttpClient, RateLimitFamily};

pub const BLOCK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

#[derive(Debug, Clone)]
pub struct UploadResult {
    pub link_id: String,
    pub revision_id: String,
    pub name_hash: Option<String>,
}

fn verify_block_digest(
    enc_bytes: &[u8],
    expected_hash: &str,
    block_index: usize,
) -> Result<[u8; 32], String> {
    let trimmed = expected_hash.trim();
    if trimmed.is_empty() {
        return Err(format!("Block {} missing SHA-256 hash", block_index));
    }
    let digest = sha256_bytes(enc_bytes);
    let b64_actual = BASE64.encode(digest);
    let hex_actual = hex::encode(digest);
    if trimmed != b64_actual && !trimmed.eq_ignore_ascii_case(&hex_actual) {
        return Err(format!(
            "Block {} SHA-256 mismatch: expected {}, got {} (hex {})",
            block_index, trimmed, b64_actual, hex_actual
        ));
    }
    Ok(digest)
}

fn sort_and_validate_blocks(blocks: &mut [BlockMetadata]) -> Result<(), String> {
    blocks.sort_by_key(|b| b.index);
    for pair in blocks.windows(2) {
        if pair[0].index == pair[1].index {
            return Err(format!("Duplicate block index {}", pair[0].index));
        }
    }
    Ok(())
}

fn block_upload_target(link: &ContentUploadLink) -> Result<(&str, Option<&str>), String> {
    if let Some(ref bare) = link.bare_url {
        if !bare.trim().is_empty() {
            let tok = (!link.token.is_empty()).then_some(link.token.as_str());
            return Ok((bare.as_str(), tok));
        }
    }
    if !link.url.trim().is_empty() {
        let tok = (!link.token.is_empty()).then_some(link.token.as_str());
        return Ok((link.url.as_str(), tok));
    }
    Err("Upload link missing URL".to_string())
}

fn compute_verifier_token(verification_code: &[u8], enc_block: &[u8]) -> Result<String, String> {
    if verification_code.is_empty() {
        return Err("Empty revision verification code".to_string());
    }
    let xored: Vec<u8> = verification_code
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ enc_block.get(i).copied().unwrap_or(0))
        .collect();
    Ok(BASE64.encode(xored))
}

fn revision_verification_keys(
    signature_address: Option<&str>,
    file_node_key: &UnlockedKey,
    verification_keys: &[String],
) -> Vec<String> {
    let mut keys = Vec::new();
    if signature_address.is_none_or(|s| s.trim().is_empty()) {
        keys.push(file_node_key.armored_public.clone());
    }
    for k in verification_keys {
        if !keys.contains(k) {
            keys.push(k.clone());
        }
    }
    keys
}

fn block_download_target(block: &BlockMetadata) -> Result<(&str, Option<&str>), String> {
    if let Some(ref bare) = block.bare_url {
        if !bare.trim().is_empty() {
            let tok = block.token.as_deref().filter(|t| !t.is_empty());
            return Ok((bare.as_str(), tok));
        }
    }
    if !block.url.trim().is_empty() {
        let tok = block.token.as_deref().filter(|t| !t.is_empty());
        return Ok((block.url.as_str(), tok));
    }
    Err(format!("Block {} missing download URL", block.index))
}

fn download_and_verify_block(
    http: &PdHttpClient,
    block: &BlockMetadata,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let (download_url, download_tok) = block_download_target(block)?;
    let headers: Vec<(&str, &str)> = match download_tok {
        Some(tok) => vec![("pm-storage-token", tok)],
        None => Vec::new(),
    };
    let enc_bytes = http
        .download_bytes_with_headers(RateLimitFamily::Transfer, download_url, &headers, true)
        .map_err(|e| format!("Failed downloading block {}: {}", block.index, e))?;
    let digest = verify_block_digest(&enc_bytes, &block.hash, block.index)?;
    Ok((enc_bytes, digest))
}

fn resolve_download_target(
    local_target_dir: &Path,
    file_name: &str,
    conflict_strategy: &str,
) -> Result<Option<PathBuf>, String> {
    fs::create_dir_all(local_target_dir)
        .map_err(|e| format!("Failed creating download dir {:?}: {}", local_target_dir, e))?;
    let candidate = local_target_dir.join(file_name);
    if !candidate.exists() {
        return Ok(Some(candidate));
    }
    match conflict_strategy {
        "skip" => Ok(None),
        "rename" => {
            let stem = Path::new(file_name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(file_name);
            let ext = Path::new(file_name)
                .extension()
                .and_then(|s| s.to_str())
                .map(|e| format!(".{}", e))
                .unwrap_or_default();
            for idx in 1..1000 {
                let alt = local_target_dir.join(format!("{} ({}){}", stem, idx, ext));
                if !alt.exists() {
                    return Ok(Some(alt));
                }
            }
            Err("Unable to find non-colliding download filename".to_string())
        }
        _ => Ok(Some(candidate)),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn download_file_blocks(
    http: &PdHttpClient,
    share_id: &str,
    file_id: &str,
    revision_id: &str,
    content_key_packet_b64: &str,
    content_key_packet_sig: Option<&str>,
    file_node_key: &UnlockedKey,
    verification_keys: &[String],
    file_name: &str,
    local_target_dir: &Path,
    conflict_strategy: &str,
) -> Result<PathBuf, String> {
    let Some(target_path) =
        resolve_download_target(local_target_dir, file_name, conflict_strategy)?
    else {
        return Ok(local_target_dir.join(file_name));
    };

    let rev_resp = DriveEndpoints::get_revision(http, share_id, file_id, revision_id)
        .map_err(|e| format!("Failed fetching revision {}: {}", revision_id, e))?;
    if rev_resp.code != 1000 && rev_resp.code != 1001 {
        return Err(format!("Get revision rejected with code {}", rev_resp.code));
    }

    let kp_bytes = BASE64
        .decode(content_key_packet_b64.trim())
        .map_err(|e| format!("Invalid ContentKeyPacket base64: {}", e))?;

    let mut kp_verif_keys = vec![file_node_key.armored_public.clone()];
    for k in verification_keys {
        if !kp_verif_keys.contains(k) {
            kp_verif_keys.push(k.clone());
        }
    }

    let session_key = if let Some(sig) = content_key_packet_sig {
        let verified = Decryptor::decrypt_and_verify_content_key_packet(
            &kp_bytes,
            file_node_key,
            Some(sig),
            &kp_verif_keys,
        )?;
        let sk_bytes = verified.require_verified("ContentKeyPacket")?;
        SessionKey::from_bytes(&sk_bytes)?
    } else {
        Decryptor::decrypt_content_key_packet(&kp_bytes, file_node_key)?
    };

    let mut blocks = rev_resp.revision.blocks;
    sort_and_validate_blocks(&mut blocks)?;

    let stage_tmp = tempfile::NamedTempFile::new_in(local_target_dir)
        .map_err(|e| format!("Failed creating staging file: {}", e))?;
    let mut thumbnails = rev_resp.revision.thumbnails;
    thumbnails.sort_by_key(|t| t.thumb_type);
    let mut manifest_hashes = Vec::with_capacity((thumbnails.len() + blocks.len()) * 32);
    if !thumbnails.is_empty() {
        for thumb in &thumbnails {
            if let Ok(raw) = BASE64.decode(thumb.hash.trim()) {
                manifest_hashes.extend_from_slice(&raw);
            } else if let Ok(raw) = hex::decode(thumb.hash.trim()) {
                manifest_hashes.extend_from_slice(&raw);
            }
        }
    } else if let Some(ref thumb_hash) = rev_resp.revision.thumbnail_hash {
        let trimmed = thumb_hash.trim();
        if !trimmed.is_empty() {
            if let Ok(raw) = BASE64.decode(trimmed) {
                manifest_hashes.extend_from_slice(&raw);
            } else if let Ok(raw) = hex::decode(trimmed) {
                manifest_hashes.extend_from_slice(&raw);
            }
        }
    }

    let mut sha1_hasher = Sha1Hasher::new();
    let mut total_written: u64 = 0;
    for block in &blocks {
        let (enc_bytes, digest) = download_and_verify_block(http, block)?;
        manifest_hashes.extend_from_slice(&digest);

        let plain = if let Some(ref enc_sig) = block.enc_signature {
            let mut block_verif_keys = verification_keys.to_vec();
            if block
                .signature_email
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
                && !block_verif_keys.contains(&file_node_key.armored_public)
            {
                block_verif_keys.push(file_node_key.armored_public.clone());
            }
            if !block_verif_keys.is_empty() {
                let armored_sig = Decryptor::decrypt_block_signature(enc_sig, file_node_key)?;
                Decryptor::decrypt_and_verify_block(
                    &enc_bytes,
                    &session_key,
                    &armored_sig,
                    &block_verif_keys,
                )?
                .require_verified(&format!("Block {}", block.index))?
            } else {
                Decryptor::decrypt_block_with_session_key(&enc_bytes, &session_key)?
            }
        } else {
            Decryptor::decrypt_block_with_session_key(&enc_bytes, &session_key)?
        };

        sha1_hasher.update(&plain);
        total_written = total_written
            .checked_add(plain.len() as u64)
            .ok_or_else(|| "Downloaded file size overflow".to_string())?;
        stage_tmp
            .as_file()
            .write_all(&plain)
            .map_err(|e| format!("Failed writing decrypted block {}: {}", block.index, e))?;
    }

    let rev_verif_keys = revision_verification_keys(
        rev_resp.revision.signature_address.as_deref(),
        file_node_key,
        verification_keys,
    );

    if let Some(ref manifest_sig) = rev_resp.revision.manifest_signature {
        if rev_verif_keys.is_empty() {
            return Err("No verification keys available for manifest signature".to_string());
        }
        Decryptor::verify_manifest_signature(&manifest_hashes, manifest_sig, &rev_verif_keys)?;
    }

    let actual_sha1 = sha1_hasher.finish_hex();
    if let Some(ref enc_xattr) = rev_resp.revision.xattr {
        if !enc_xattr.trim().is_empty() {
            let verified_xattr = Decryptor::decrypt_and_verify_xattributes(
                enc_xattr,
                file_node_key,
                &rev_verif_keys,
            )?;
            let xattr_bytes = if !rev_verif_keys.is_empty() {
                verified_xattr.require_verified("Revision XAttr")?
            } else {
                verified_xattr.into_value()
            };
            let parsed = ExtendedAttributes::decode(&xattr_bytes)?;
            if let Some(common) = parsed.common {
                if let Some(expected_size) = common.size {
                    if expected_size >= 0 && total_written != expected_size as u64 {
                        return Err(format!(
                            "Downloaded size mismatch: expected {} bytes from XAttr, got {}",
                            expected_size, total_written
                        ));
                    }
                }
                if let Some(expected_sha1) = common.digests.and_then(|d| d.sha1) {
                    let trimmed = expected_sha1.trim();
                    if !trimmed.is_empty() && !actual_sha1.eq_ignore_ascii_case(trimmed) {
                        return Err(format!(
                            "Downloaded plaintext SHA-1 mismatch: expected {}, got {}",
                            trimmed, actual_sha1
                        ));
                    }
                }
            }
        }
    }

    stage_tmp
        .as_file()
        .sync_all()
        .map_err(|e| format!("Failed syncing downloaded file: {}", e))?;
    #[cfg(unix)]
    fs::set_permissions(stage_tmp.path(), fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed setting 0600 on downloaded file: {}", e))?;

    stage_tmp.persist(&target_path).map_err(|e| {
        format!(
            "Failed persisting downloaded file {:?}: {}",
            target_path, e.error
        )
    })?;

    Ok(target_path)
}

#[allow(clippy::too_many_arguments)]
pub fn read_block_range(
    http: &PdHttpClient,
    share_id: &str,
    file_id: &str,
    revision_id: &str,
    content_key_packet_b64: &str,
    file_node_key: &UnlockedKey,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>, String> {
    if size == 0 {
        return Ok(Vec::new());
    }

    let rev_resp = DriveEndpoints::get_revision(http, share_id, file_id, revision_id)
        .map_err(|e| format!("Failed fetching revision {}: {}", revision_id, e))?;
    if rev_resp.code != 1000 && rev_resp.code != 1001 {
        return Err(format!("Get revision rejected with code {}", rev_resp.code));
    }

    let kp_bytes = BASE64
        .decode(content_key_packet_b64.trim())
        .map_err(|e| format!("Invalid ContentKeyPacket base64: {}", e))?;
    let session_key = Decryptor::decrypt_content_key_packet(&kp_bytes, file_node_key)?;

    let mut blocks = rev_resp.revision.blocks;
    sort_and_validate_blocks(&mut blocks)?;
    if blocks.is_empty() {
        return Ok(Vec::new());
    }

    let start_offset = offset as usize;
    let end_offset = start_offset.saturating_add(size);
    let start_block_pos = start_offset / BLOCK_SIZE;
    let end_block_pos = end_offset.saturating_sub(1) / BLOCK_SIZE;

    let mut result = Vec::with_capacity(size);
    for (pos, block) in blocks.iter().enumerate() {
        if pos < start_block_pos || pos > end_block_pos {
            continue;
        }
        let (enc_bytes, _) = download_and_verify_block(http, block)?;
        let plain = Decryptor::decrypt_block_with_session_key(&enc_bytes, &session_key)?;

        let block_global_start = pos * BLOCK_SIZE;
        let slice_start = start_offset.saturating_sub(block_global_start);
        if slice_start >= plain.len() {
            break;
        }
        let slice_end = end_offset
            .saturating_sub(block_global_start)
            .min(plain.len());
        result.extend_from_slice(&plain[slice_start..slice_end]);
    }

    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub fn upload_file_blocks(
    http: &PdHttpClient,
    vault: &SessionVault,
    volume_id: &str,
    share_id: &str,
    parent_link_id: &str,
    parent_pub_key: &str,
    parent_hash_key: &[u8],
    existing_link: Option<(&str, &str)>,
    existing_file_node_key: Option<&UnlockedKey>,
    local_file: &Path,
    target_name: &str,
) -> Result<UploadResult, String> {
    let addr = vault
        .primary_address_key()
        .ok_or_else(|| "No unlocked address key in SessionVault".to_string())?;

    let mut file = File::open(local_file)
        .map_err(|e| format!("Failed opening local file {:?}: {}", local_file, e))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("Failed stating local file {:?}: {}", local_file, e))?;
    let total_size = meta.len() as i64;
    let mtime_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // 1. Resolve/create file link, revision, node key, and content session key
    let is_new_revision = existing_link.is_some();
    let (link_id, revision_id, file_unlocked, session_key, name_hash_opt) =
        if let Some((ex_link_id, kp_b64)) = existing_link {
            let ex_unlocked = existing_file_node_key
                .cloned()
                .ok_or_else(|| "Existing file node key not unlocked".to_string())?;
            let kp_bytes = BASE64
                .decode(kp_b64.trim())
                .map_err(|e| format!("Invalid existing ContentKeyPacket base64: {}", e))?;
            let sk = Decryptor::decrypt_content_key_packet(&kp_bytes, &ex_unlocked)?;
            let new_rev = DriveEndpoints::create_revision(http, share_id, ex_link_id)
                .map_err(|e| format!("Failed creating new revision: {}", e))?;
            if new_rev.code != 1000 && new_rev.code != 1001 {
                return Err(format!(
                    "Create revision rejected with code {}",
                    new_rev.code
                ));
            }
            (
                ex_link_id.to_string(),
                new_rev.revision.id,
                ex_unlocked,
                sk,
                None,
            )
        } else {
            let file_creds = Encryptor::generate_node_keys(
                &addr.passphrase,
                &addr.unlocked.armored_private,
                parent_pub_key,
            )?;
            let file_unlocked = DriveKey::unlock(&file_creds.key, &file_creds.passphrase_raw)?;
            let (sk, _kp, kp_b64, kp_sig) = Encryptor::generate_content_session_key(
                &file_unlocked.armored_public,
                &file_creds.key,
                &file_creds.passphrase_raw,
            )?;
            let enc_name = Encryptor::encrypt_and_sign_text(
                target_name,
                parent_pub_key,
                &addr.passphrase,
                &addr.unlocked.armored_private,
            )?;
            let name_hash = NameHasher::hash(target_name, parent_hash_key)?;
            let params = NewFileParameters {
                name: enc_name,
                hash: name_hash.clone(),
                parent_link_id: parent_link_id.to_string(),
                node_key: file_creds.key,
                node_passphrase: file_creds.passphrase,
                node_passphrase_signature: file_creds.signature,
                signature_address: addr.email.clone(),
                content_key_packet: kp_b64,
                content_key_packet_signature: kp_sig,
                mime_type: "application/octet-stream".to_string(),
                client_uid: vault
                    .snapshot()
                    .map(|s| s.uid)
                    .unwrap_or_else(|| "linux-drive".to_string()),
            };
            let created = DriveEndpoints::create_file(http, share_id, &params)
                .map_err(|e| format!("Failed creating remote file: {}", e))?;
            if created.code != 1000 && created.code != 1001 {
                return Err(format!("Create file rejected with code {}", created.code));
            }
            (
                created.file.id,
                created.file.revision_id,
                file_unlocked,
                sk,
                Some(name_hash),
            )
        };

    let upload_body_res = (|| -> Result<(), String> {
        // 2. Chunk into 4 MiB blocks, encrypt, hash, and prepare block metadata
        let mut sha1_hasher = Sha1Hasher::new();
        let mut block_sizes = Vec::new();
        let mut prepared_blocks: Vec<(usize, String, String, Vec<u8>)> = Vec::new();
        let mut manifest_hashes = Vec::new();

        let mut buf = vec![0u8; BLOCK_SIZE];
        let mut index = 1usize;
        loop {
            let mut read_total = 0usize;
            while read_total < BLOCK_SIZE {
                let n = file
                    .read(&mut buf[read_total..])
                    .map_err(|e| format!("Failed reading local file {:?}: {}", local_file, e))?;
                if n == 0 {
                    break;
                }
                read_total += n;
            }
            if read_total == 0 {
                break;
            }
            let plain_chunk = &buf[..read_total];
            sha1_hasher.update(plain_chunk);
            block_sizes.push(read_total);

            let (enc_block, enc_sig) = Encryptor::encrypt_block_with_session_key(
                plain_chunk,
                &session_key,
                &addr.unlocked,
                &file_unlocked.armored_public,
            )?;
            let digest = sha256_bytes(&enc_block);
            manifest_hashes.extend_from_slice(&digest);
            let hash_b64 = BASE64.encode(digest);

            prepared_blocks.push((index, hash_b64, enc_sig, enc_block));
            index += 1;
        }

        // 3. Fetch revision verification input, compute XOR Verifier.Token, request upload links,
        //    and upload encrypted blocks concurrently with pm-storage-token header.
        if !prepared_blocks.is_empty() {
            let verif_resp =
                DriveEndpoints::get_verification_data(http, volume_id, &link_id, &revision_id)
                    .map_err(|e| format!("Failed fetching revision verification data: {}", e))?;
            if verif_resp.code != 1000 && verif_resp.code != 1001 {
                return Err(format!(
                    "Verification data request rejected with code {}",
                    verif_resp.code
                ));
            }
            let verif_code = BASE64
                .decode(verif_resp.verification_code.trim())
                .map_err(|e| format!("Invalid VerificationCode base64: {}", e))?;
            if !verif_resp.content_key_packet.trim().is_empty() {
                let kp_bytes = BASE64
                    .decode(verif_resp.content_key_packet.trim())
                    .map_err(|e| format!("Invalid verification ContentKeyPacket base64: {}", e))?;
                let _ = Decryptor::decrypt_content_key_packet(&kp_bytes, &file_unlocked)?;
            }

            let mut block_items = Vec::with_capacity(prepared_blocks.len());
            let mut encrypted_blocks = Vec::with_capacity(prepared_blocks.len());
            for (blk_idx, hash_b64, enc_sig, enc_block) in prepared_blocks {
                let verifier_tok = compute_verifier_token(&verif_code, &enc_block)?;
                block_items.push(NewBlockItem {
                    size: enc_block.len(),
                    index: blk_idx,
                    enc_signature: enc_sig,
                    hash: hash_b64,
                    verifier: VerifierInfo {
                        token: verifier_tok,
                    },
                });
                encrypted_blocks.push((blk_idx, enc_block));
            }

            let req_blocks = NewBlocksParameters {
                address_id: addr.address_id.clone(),
                share_id: share_id.to_string(),
                link_id: link_id.clone(),
                revision_id: revision_id.clone(),
                block_list: block_items,
                thumbnail_list: Vec::new(),
            };
            let links_resp = DriveEndpoints::request_block_upload_links(http, &req_blocks)
                .map_err(|e| format!("Failed requesting block upload links: {}", e))?;
            if links_resp.code != 1000 && links_resp.code != 1001 {
                return Err(format!(
                    "New blocks request rejected with code {}",
                    links_resp.code
                ));
            }
            if links_resp.upload_links.len() != encrypted_blocks.len() {
                return Err(format!(
                    "Upload link count mismatch: expected {}, got {}",
                    encrypted_blocks.len(),
                    links_resp.upload_links.len()
                ));
            }

            let mut upload_targets: Vec<(&str, Option<&str>, &[u8])> =
                Vec::with_capacity(links_resp.upload_links.len());
            let all_have_index = links_resp.upload_links.iter().all(|l| l.index.is_some());
            if all_have_index {
                for link in &links_resp.upload_links {
                    let target_idx = link.index.unwrap();
                    let (_, enc_data) = encrypted_blocks
                        .iter()
                        .find(|(idx, _)| *idx == target_idx)
                        .ok_or_else(|| {
                            format!("Upload link returned unknown block index {}", target_idx)
                        })?;
                    let (url, token) = block_upload_target(link)?;
                    upload_targets.push((url, token, enc_data.as_slice()));
                }
            } else {
                for (link, (_, enc_data)) in
                    links_resp.upload_links.iter().zip(encrypted_blocks.iter())
                {
                    let (url, token) = block_upload_target(link)?;
                    upload_targets.push((url, token, enc_data.as_slice()));
                }
            }

            thread::scope(|s| -> Result<(), String> {
                let mut handles = Vec::with_capacity(upload_targets.len());
                for (url, token, enc_data) in upload_targets {
                    let handle = s.spawn(move || {
                        let resp_bytes = http
                            .upload_multipart_block_with_token(
                                RateLimitFamily::Transfer,
                                url,
                                token,
                                enc_data,
                                true,
                            )
                            .map_err(|e| format!("Block upload failed: {}", e))?;
                        if let Ok(code_resp) = serde_json::from_slice::<CodeResponse>(&resp_bytes) {
                            code_resp.ensure_ok("Block upload")?;
                        }
                        Ok::<(), String>(())
                    });
                    handles.push(handle);
                }
                for h in handles {
                    h.join()
                        .map_err(|_| "Block upload thread panicked".to_string())??;
                }
                Ok(())
            })?;
        }

        // 4. Commit revision with manifest signature & encrypted ExtendedAttributes
        let manifest_sig = DriveCrypto::sign_bytes_armored(
            &manifest_hashes,
            None,
            &addr.unlocked.armored_private,
            &addr.passphrase,
        )?;

        let xattr = ExtendedAttributes::new(
            Some(format_iso8601_utc(mtime_secs)),
            Some(total_size),
            Some(block_sizes),
            Some(sha1_hasher.finish_hex()),
        );
        let xattr_json = xattr.encoded()?;
        let enc_xattr = Encryptor::encrypt_and_sign_bytes(
            &xattr_json,
            &file_unlocked.armored_public,
            &addr.passphrase,
            &addr.unlocked.armored_private,
            true,
        )?;

        let commit_resp = DriveEndpoints::update_revision(
            http,
            share_id,
            &link_id,
            &revision_id,
            &UpdateRevisionParameters {
                manifest_signature: manifest_sig,
                signature_address: addr.email,
                xattr: Some(enc_xattr),
            },
        )
        .map_err(|e| format!("Failed committing revision: {}", e))?;
        commit_resp.ensure_ok("Commit revision")?;
        Ok(())
    })();

    if let Err(err) = upload_body_res {
        if is_new_revision {
            let _ = DriveEndpoints::delete_revision(http, share_id, &link_id, &revision_id);
        } else {
            let _ =
                DriveEndpoints::delete_draft_links(http, volume_id, std::slice::from_ref(&link_id));
        }
        return Err(err);
    }

    Ok(UploadResult {
        link_id,
        revision_id,
        name_hash: name_hash_opt,
    })
}
