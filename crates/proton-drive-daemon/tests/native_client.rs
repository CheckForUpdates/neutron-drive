mod support;

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::json;

use neutron_drive_daemon::client::RemoteDrive;
use neutron_drive_daemon::config::Config;
use neutron_drive_daemon::daemon::ProtonDriveDaemon;
use neutron_drive_daemon::fuse_fs::ProtonDriveFUSE;
use neutron_drive_daemon::metadata_db::SyncStatus;
use neutron_drive_daemon::native::auth::{
    derive_key_passphrase, expand_hash, hash_password_v4, BigUint, InMemorySecretStore,
    NoFallbackKeyProvider, SessionVault,
};
use neutron_drive_daemon::native::crypto::{
    dearmor, decode_packets, sha1_hex, sha256_bytes, Decryptor, DriveCrypto, DriveKey, Encryptor,
    ExtendedAttributes, NameHasher, PACKET_PKESK, PACKET_SEIPD,
};
use neutron_drive_daemon::native::endpoints::DriveEndpoints;
use neutron_drive_daemon::native::http::{
    HttpError, RateLimitFamily, RateLimitGate, DEFAULT_APP_VERSION, DEFAULT_LOCALE,
    DEFAULT_USER_AGENT, PROTON_ACCEPT_HEADER,
};
use neutron_drive_daemon::native::transfer::BLOCK_SIZE;
use neutron_drive_daemon::native::NativeProtonClient;
use neutron_drive_daemon::sync_engine::SyncEngine;
use support::TestFixture;

// ============================================================================
// Stateful Mock Proton Drive HTTP API Server
// ============================================================================

#[derive(Clone)]
struct ServerLink {
    link_id: String,
    parent_link_id: Option<String>,
    link_type: i32, // 1 = folder, 2 = file
    name_enc: String,
    hash: String,
    state: i32,
    size: i64,
    node_key: String,
    node_passphrase: String,
    node_passphrase_sig: String,
    signature_email: String,
    node_hash_key: Option<String>,
    content_key_packet: Option<String>,
    content_key_packet_sig: Option<String>,
    active_revision_id: Option<String>,
    manifest_signature: Option<String>,
    xattr: Option<String>,
    modify_time: f64,
    trashed: Option<f64>,
}

#[derive(Clone)]
struct ServerBlock {
    index: usize,
    hash: String,
    enc_signature: String,
    data: Vec<u8>,
}

struct MockServerState {
    // Auth & Keys
    username: String,
    totp_required: bool,
    totp_code: String,
    srp_modulus: Vec<u8>,
    srp_salt: [u8; 10],
    srp_b_sec: BigUint,
    srp_v: BigUint,
    srp_b_pub: BigUint,
    srp_signing_key_armored: String,
    srp_signing_passphrase: String,
    srp_signing_pub: String,
    srp_modulus_override: Option<String>,
    key_salt_b64: String,
    user_key_armored: String,
    address_id: String,
    address_email: String,
    address_key_id: String,
    address_key_armored: String,
    address_token_armored: String,
    address_key_passphrase: String,
    address_unlocked_pub: String,

    uid: String,
    access_token: String,
    refresh_token: String,
    require_2fa_pending: bool,
    used_drive_space: u64,
    max_drive_space: u64,

    // Fault injection / call counters
    fork_selector: String,
    fork_user_code: String,
    fork_encrypted_payload: Option<String>,
    fork_poll_pending_remaining: usize,
    force_429_once: bool,
    force_429_remaining: usize,
    force_429_retry_after: Option<String>,
    force_503_remaining: usize,
    force_401_once: bool,
    force_401_always: bool,
    refresh_override_status: Option<u16>,
    null_drive_quota_fields: bool,
    used_space: u64,
    max_space: u64,
    children_page_size: usize,
    force_repeated_anchor: bool,
    force_missing_anchor: bool,
    overlap_pagination: bool,
    emit_null_link_fields: bool,
    emit_bare_upload_urls: bool,
    corrupt_verification_code_once: bool,
    fail_block_upload_index: Option<usize>,
    fail_block_download_index: Option<usize>,
    fail_update_revision: bool,
    auth_v4_calls: usize,
    refresh_calls: usize,
    authed_request_calls: usize,
    block_download_calls: usize,
    list_children_calls: usize,
    create_file_calls: usize,
    create_revision_calls: usize,
    new_blocks_calls: usize,
    delete_revision_calls: usize,
    deleted_revisions: Vec<(String, String)>,
    delete_calls: usize,
    trash_calls: usize,
    captured_headers: Vec<(String, String, HashMap<String, String>)>,
    fetch_metadata_batch_sizes: Vec<usize>,

    // Drive hierarchy
    volume_id: String,
    share_id: String,
    root_link_id: String,
    share_key_armored: String,
    share_passphrase_enc: String,
    share_passphrase_sig: String,
    links: HashMap<String, ServerLink>,
    children: HashMap<String, Vec<String>>,
    revision_blocks: HashMap<String, Vec<ServerBlock>>,
    revision_verification_codes: HashMap<String, (String, Vec<u8>)>, // rev_id -> (file_id, 32-byte code)
    pending_upload_blocks: HashMap<String, (String, usize, String)>, // token -> (rev_id, index, verifier_token)
    next_id_seq: usize,

    // Events
    latest_event_id: String,
    events: Vec<serde_json::Value>,
    events_refresh_once: bool,
    events_more_repeated_once: bool,
    events_fail_remaining: usize,
}

impl MockServerState {
    fn new(username: &str, password: &str, totp_required: bool) -> Self {
        let address_key_passphrase = "addr-token-passphrase-xyz".to_string();
        let address_key_armored =
            DriveKey::generate("Test User", username, &address_key_passphrase).unwrap();
        Self::new_with_address_key(
            username,
            password,
            totp_required,
            address_key_armored,
            address_key_passphrase,
        )
    }

    fn new_with_address_key(
        username: &str,
        password: &str,
        totp_required: bool,
        address_key_armored: String,
        address_key_passphrase: String,
    ) -> Self {
        let mut srp_modulus = vec![0x85u8; 256];
        srp_modulus[0] = 0xFB;
        srp_modulus[255] = 0xC3;
        let srp_salt = [0x22u8; 10];
        let srp_b_sec = BigUint::from_le_bytes(&[0x37; 32]);
        let srp_n = BigUint::from_le_bytes(&srp_modulus);
        let srp_x_bytes = hash_password_v4(password, &srp_salt, &srp_modulus).unwrap();
        let srp_x = BigUint::from_le_bytes(&srp_x_bytes);
        let srp_g = BigUint::from_u64(2);
        let srp_v = srp_g.mod_pow(&srp_x, &srp_n);
        let srp_g_padded = srp_g.to_le_bytes_padded(256);
        let mut srp_k_in = Vec::with_capacity(512);
        srp_k_in.extend_from_slice(&srp_g_padded);
        srp_k_in.extend_from_slice(&srp_modulus);
        let srp_k = BigUint::from_le_bytes(&expand_hash(&srp_k_in)).rem(&srp_n);
        let srp_gb = srp_g.mod_pow(&srp_b_sec, &srp_n);
        let srp_b_pub = srp_k.mul_mod(&srp_v, &srp_n).add(&srp_gb).rem(&srp_n);
        let srp_signing_passphrase = "mock-srp-server-pass".to_string();
        let srp_signing_key_armored = DriveKey::generate(
            "Mock SRP Server",
            "srp@mock.proton.me",
            &srp_signing_passphrase,
        )
        .unwrap();
        let srp_signing_pub = DriveKey::public_key_armored(&srp_signing_key_armored).unwrap();

        let key_salt = [0x44u8; 16];
        let key_salt_b64 = BASE64.encode(key_salt);
        let key_pass = derive_key_passphrase(password, &key_salt_b64).unwrap();
        let user_key_armored = DriveKey::generate("Test User", username, &key_pass).unwrap();
        let user_pub = DriveKey::public_key_armored(&user_key_armored).unwrap();

        let address_token_armored =
            Encryptor::encrypt_text(&address_key_passphrase, &user_pub).unwrap();
        let address_unlocked_pub = DriveKey::public_key_armored(&address_key_armored).unwrap();

        let volume_id = "vol-main-1".to_string();
        let share_id = "share-main-1".to_string();
        let root_link_id = "link-root-1".to_string();

        let share_creds = Encryptor::generate_node_keys(
            &address_key_passphrase,
            &address_key_armored,
            &address_unlocked_pub,
        )
        .unwrap();
        let share_unlocked =
            DriveKey::unlock(&share_creds.key, &share_creds.passphrase_raw).unwrap();

        let root_creds = Encryptor::generate_node_keys(
            &address_key_passphrase,
            &address_key_armored,
            &share_unlocked.armored_public,
        )
        .unwrap();
        let root_hash_key_enc =
            Encryptor::generate_node_hash_key(&root_creds.key, &root_creds.passphrase_raw).unwrap();
        let root_name_enc = Encryptor::encrypt_and_sign_text(
            "root",
            &share_unlocked.armored_public,
            &address_key_passphrase,
            &address_key_armored,
        )
        .unwrap();

        let root_link = ServerLink {
            link_id: root_link_id.clone(),
            parent_link_id: None,
            link_type: 1,
            name_enc: root_name_enc,
            hash: "root-hash".to_string(),
            state: 1,
            size: 0,
            node_key: root_creds.key,
            node_passphrase: root_creds.passphrase,
            node_passphrase_sig: root_creds.signature,
            signature_email: username.to_string(),
            node_hash_key: Some(root_hash_key_enc),
            content_key_packet: None,
            content_key_packet_sig: None,
            active_revision_id: None,
            manifest_signature: None,
            xattr: None,
            modify_time: 1_700_000_000.0,
            trashed: None,
        };

        let mut links = HashMap::new();
        links.insert(root_link_id.clone(), root_link);
        let mut children = HashMap::new();
        children.insert(root_link_id.clone(), Vec::new());

        Self {
            username: username.to_string(),
            totp_required,
            totp_code: "123456".to_string(),
            srp_modulus,
            srp_salt,
            srp_b_sec,
            srp_v,
            srp_b_pub,
            srp_signing_key_armored,
            srp_signing_passphrase,
            srp_signing_pub,
            srp_modulus_override: None,
            key_salt_b64,
            user_key_armored,
            address_id: "addr-1".to_string(),
            address_email: username.to_string(),
            address_key_id: "addr-key-1".to_string(),
            address_key_armored,
            address_token_armored,
            address_key_passphrase,
            address_unlocked_pub,
            uid: "uid-native-1".to_string(),
            access_token: "access-token-initial".to_string(),
            refresh_token: "refresh-token-initial".to_string(),
            require_2fa_pending: false,
            used_drive_space: 1_073_741_824,
            max_drive_space: 536_870_912_000,
            fork_selector: "sel-mock-fork-1".to_string(),
            fork_user_code: "ABCD2345".to_string(),
            fork_encrypted_payload: None,
            fork_poll_pending_remaining: 0,
            force_429_once: false,
            force_429_remaining: 0,
            force_429_retry_after: None,
            force_503_remaining: 0,
            force_401_once: false,
            force_401_always: false,
            refresh_override_status: None,
            null_drive_quota_fields: false,
            used_space: 100,
            max_space: 200,
            children_page_size: 2,
            force_repeated_anchor: false,
            force_missing_anchor: false,
            overlap_pagination: false,
            emit_null_link_fields: false,
            emit_bare_upload_urls: false,
            corrupt_verification_code_once: false,
            fail_block_upload_index: None,
            fail_block_download_index: None,
            fail_update_revision: false,
            auth_v4_calls: 0,
            refresh_calls: 0,
            authed_request_calls: 0,
            block_download_calls: 0,
            list_children_calls: 0,
            create_file_calls: 0,
            create_revision_calls: 0,
            new_blocks_calls: 0,
            delete_revision_calls: 0,
            deleted_revisions: Vec::new(),
            delete_calls: 0,
            trash_calls: 0,
            captured_headers: Vec::new(),
            fetch_metadata_batch_sizes: Vec::new(),
            volume_id,
            share_id,
            root_link_id,
            share_key_armored: share_creds.key,
            share_passphrase_enc: share_creds.passphrase,
            share_passphrase_sig: share_creds.signature,
            links,
            children,
            revision_blocks: HashMap::new(),
            revision_verification_codes: HashMap::new(),
            pending_upload_blocks: HashMap::new(),
            next_id_seq: 100,
            latest_event_id: "ev-0".to_string(),
            events: Vec::new(),
            events_refresh_once: false,
            events_more_repeated_once: false,
            events_fail_remaining: 0,
        }
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.next_id_seq += 1;
        format!("{}-{}", prefix, self.next_id_seq)
    }

    fn unlock_folder(&self, folder_link_id: &str) -> (DriveKeyHandle, Vec<u8>) {
        let share_pass = Decryptor::decrypt_and_verify_share_passphrase(
            &self.share_passphrase_enc,
            &self.share_passphrase_sig,
            std::slice::from_ref(&self.address_unlocked_pub),
            &[DriveKey::unlock(&self.address_key_armored, &self.address_key_passphrase).unwrap()],
        )
        .unwrap();
        let share_unlocked = DriveKey::unlock(&self.share_key_armored, share_pass.value()).unwrap();

        // Walk chain from root to target
        let mut chain = Vec::new();
        let mut cur = folder_link_id.to_string();
        while let Some(l) = self.links.get(&cur) {
            chain.push(l.clone());
            match l.parent_link_id {
                Some(ref p) => cur = p.clone(),
                None => break,
            }
        }
        chain.reverse();

        let mut parent_unlocked = share_unlocked;
        let mut last_hk = Vec::new();
        for link in chain {
            let pp = Decryptor::decrypt_and_verify_node_passphrase(
                &link.node_passphrase,
                &link.node_passphrase_sig,
                std::slice::from_ref(&self.address_unlocked_pub),
                std::slice::from_ref(&parent_unlocked),
            )
            .unwrap();
            let uk = DriveKey::unlock(&link.node_key, pp.value()).unwrap();
            if let Some(ref hk_armored) = link.node_hash_key {
                let dec_hk = Decryptor::decrypt_and_verify_node_hash_key(
                    hk_armored,
                    std::slice::from_ref(&uk),
                    &[uk.armored_public.clone(), self.address_unlocked_pub.clone()],
                )
                .unwrap();
                last_hk = dec_hk.value().to_vec();
            }
            parent_unlocked = uk;
        }
        (parent_unlocked, last_hk)
    }

    fn add_remote_folder(&mut self, parent_link_id: &str, name: &str) -> String {
        let (parent_uk, parent_hk) = self.unlock_folder(parent_link_id);
        let creds = Encryptor::generate_node_keys(
            &self.address_key_passphrase,
            &self.address_key_armored,
            &parent_uk.armored_public,
        )
        .unwrap();
        let hk_enc = Encryptor::generate_node_hash_key(&creds.key, &creds.passphrase_raw).unwrap();
        let name_enc = Encryptor::encrypt_and_sign_text(
            name,
            &parent_uk.armored_public,
            &self.address_key_passphrase,
            &self.address_key_armored,
        )
        .unwrap();
        let hash = NameHasher::hash(name, &parent_hk).unwrap();
        let lid = self.next_id("folder");
        let link = ServerLink {
            link_id: lid.clone(),
            parent_link_id: Some(parent_link_id.to_string()),
            link_type: 1,
            name_enc,
            hash,
            state: 1,
            size: 0,
            node_key: creds.key,
            node_passphrase: creds.passphrase,
            node_passphrase_sig: creds.signature,
            signature_email: self.address_email.clone(),
            node_hash_key: Some(hk_enc),
            content_key_packet: None,
            content_key_packet_sig: None,
            active_revision_id: None,
            manifest_signature: None,
            xattr: None,
            modify_time: 1_700_000_100.0,
            trashed: None,
        };
        self.links.insert(lid.clone(), link);
        self.children.entry(lid.clone()).or_default();
        self.children
            .entry(parent_link_id.to_string())
            .or_default()
            .push(lid.clone());
        lid
    }

    fn add_remote_file(&mut self, parent_link_id: &str, name: &str, content: &[u8]) -> String {
        let (parent_uk, parent_hk) = self.unlock_folder(parent_link_id);
        let creds = Encryptor::generate_node_keys(
            &self.address_key_passphrase,
            &self.address_key_armored,
            &parent_uk.armored_public,
        )
        .unwrap();
        let file_uk = DriveKey::unlock(&creds.key, &creds.passphrase_raw).unwrap();
        let (sk, _kp, kp_b64, kp_sig) = Encryptor::generate_content_session_key(
            &file_uk.armored_public,
            &self.address_key_armored,
            &self.address_key_passphrase,
        )
        .unwrap();
        let name_enc = Encryptor::encrypt_and_sign_text(
            name,
            &parent_uk.armored_public,
            &self.address_key_passphrase,
            &self.address_key_armored,
        )
        .unwrap();
        let hash = NameHasher::hash(name, &parent_hk).unwrap();
        let lid = self.next_id("file");
        let rev_id = self.next_id("rev");

        let addr_uk =
            DriveKey::unlock(&self.address_key_armored, &self.address_key_passphrase).unwrap();
        let (enc_block, enc_sig) = Encryptor::encrypt_block_with_session_key(
            content,
            &sk,
            &addr_uk,
            &file_uk.armored_public,
        )
        .unwrap();
        let digest = sha256_bytes(&enc_block);
        let block_hash_b64 = BASE64.encode(digest);
        let manifest_sig = neutron_drive_daemon::native::crypto::DriveCrypto::sign_bytes_armored(
            &digest,
            None,
            &self.address_key_armored,
            &self.address_key_passphrase,
        )
        .unwrap();

        let xattr = ExtendedAttributes::new(
            Some("2026-11-15T12:00:00Z".to_string()),
            Some(content.len() as i64),
            Some(vec![content.len()]),
            None,
        );
        let xattr_enc = Encryptor::encrypt_and_sign_bytes(
            &xattr.encoded().unwrap(),
            &file_uk.armored_public,
            &self.address_key_passphrase,
            &self.address_key_armored,
            true,
        )
        .unwrap();

        self.revision_blocks.insert(
            rev_id.clone(),
            vec![ServerBlock {
                index: 1,
                hash: block_hash_b64,
                enc_signature: enc_sig,
                data: enc_block,
            }],
        );

        let link = ServerLink {
            link_id: lid.clone(),
            parent_link_id: Some(parent_link_id.to_string()),
            link_type: 2,
            name_enc,
            hash,
            state: 1,
            size: content.len() as i64,
            node_key: creds.key,
            node_passphrase: creds.passphrase,
            node_passphrase_sig: creds.signature,
            signature_email: self.address_email.clone(),
            node_hash_key: None,
            content_key_packet: Some(kp_b64),
            content_key_packet_sig: Some(kp_sig),
            active_revision_id: Some(rev_id),
            manifest_signature: Some(manifest_sig),
            xattr: Some(xattr_enc),
            modify_time: 1_700_000_200.0,
            trashed: None,
        };
        self.links.insert(lid.clone(), link);
        self.children
            .entry(parent_link_id.to_string())
            .or_default()
            .push(lid.clone());
        lid
    }

    /// Creates a remote file using official macOS/Web client semantics:
    /// - `ContentKeyPacketSignature` is signed by the file's `NodeKey`
    /// - 0-byte files have 0 blocks and `ManifestSignature` over `&[]`
    /// - Multi-block files are chunked at `BLOCK_SIZE` (4 MiB)
    /// - `XAttr` includes `BlockSizes`, `Size`, and plaintext `SHA1`
    fn add_remote_file_official_style(
        &mut self,
        parent_link_id: &str,
        name: &str,
        content: &[u8],
    ) -> String {
        let (parent_uk, parent_hk) = self.unlock_folder(parent_link_id);
        let creds = Encryptor::generate_node_keys(
            &self.address_key_passphrase,
            &self.address_key_armored,
            &parent_uk.armored_public,
        )
        .unwrap();
        let file_uk = DriveKey::unlock(&creds.key, &creds.passphrase_raw).unwrap();
        let (sk, _kp, kp_b64, kp_sig) = Encryptor::generate_content_session_key(
            &file_uk.armored_public,
            &creds.key,
            &creds.passphrase_raw,
        )
        .unwrap();
        let name_enc = Encryptor::encrypt_and_sign_text(
            name,
            &parent_uk.armored_public,
            &self.address_key_passphrase,
            &self.address_key_armored,
        )
        .unwrap();
        let hash = NameHasher::hash(name, &parent_hk).unwrap();
        let lid = self.next_id("file");
        let rev_id = self.next_id("rev");

        let addr_uk =
            DriveKey::unlock(&self.address_key_armored, &self.address_key_passphrase).unwrap();
        let mut server_blocks = Vec::new();
        let mut manifest_hashes = Vec::new();
        let mut block_sizes = Vec::new();
        let mut total_enc_size: i64 = 0;

        if !content.is_empty() {
            for (i, chunk) in content.chunks(BLOCK_SIZE).enumerate() {
                block_sizes.push(chunk.len());
                let (enc_block, enc_sig) = Encryptor::encrypt_block_with_session_key(
                    chunk,
                    &sk,
                    &addr_uk,
                    &file_uk.armored_public,
                )
                .unwrap();
                total_enc_size += enc_block.len() as i64;
                let digest = sha256_bytes(&enc_block);
                manifest_hashes.extend_from_slice(&digest);
                server_blocks.push(ServerBlock {
                    index: i + 1,
                    hash: BASE64.encode(digest),
                    enc_signature: enc_sig,
                    data: enc_block,
                });
            }
        }

        let manifest_sig = DriveCrypto::sign_bytes_armored(
            &manifest_hashes,
            None,
            &self.address_key_armored,
            &self.address_key_passphrase,
        )
        .unwrap();

        let xattr = ExtendedAttributes::new(
            Some("2026-11-16T12:00:00Z".to_string()),
            Some(content.len() as i64),
            Some(block_sizes),
            Some(sha1_hex(content)),
        );
        let xattr_enc = Encryptor::encrypt_and_sign_bytes(
            &xattr.encoded().unwrap(),
            &file_uk.armored_public,
            &self.address_key_passphrase,
            &self.address_key_armored,
            true,
        )
        .unwrap();

        self.revision_blocks.insert(rev_id.clone(), server_blocks);

        let link = ServerLink {
            link_id: lid.clone(),
            parent_link_id: Some(parent_link_id.to_string()),
            link_type: 2,
            name_enc,
            hash,
            state: 1,
            size: total_enc_size,
            node_key: creds.key,
            node_passphrase: creds.passphrase,
            node_passphrase_sig: creds.signature,
            signature_email: self.address_email.clone(),
            node_hash_key: None,
            content_key_packet: Some(kp_b64),
            content_key_packet_sig: Some(kp_sig),
            active_revision_id: Some(rev_id),
            manifest_signature: Some(manifest_sig),
            xattr: Some(xattr_enc),
            modify_time: 1_700_000_200.0,
            trashed: None,
        };
        self.links.insert(lid.clone(), link);
        self.children
            .entry(parent_link_id.to_string())
            .or_default()
            .push(lid.clone());
        lid
    }

    fn link_to_json(&self, l: &ServerLink) -> serde_json::Value {
        let mut obj = if self.emit_null_link_fields {
            json!({
                "LinkID": l.link_id,
                "ParentLinkID": l.parent_link_id,
                "Type": l.link_type,
                "Name": l.name_enc,
                "NameSignatureEmail": null,
                "Hash": l.hash,
                "State": l.state,
                "Size": l.size,
                "MIMEType": null,
                "NodeKey": l.node_key,
                "NodePassphrase": l.node_passphrase,
                "NodePassphraseSignature": l.node_passphrase_sig,
                "SignatureEmail": null,
                "CreateTime": 1_700_000_000.0,
                "ModifyTime": l.modify_time,
                "Trashed": l.trashed,
                "XAttr": l.xattr,
            })
        } else {
            json!({
                "LinkID": l.link_id,
                "ParentLinkID": l.parent_link_id,
                "Type": l.link_type,
                "Name": l.name_enc,
                "NameSignatureEmail": l.signature_email,
                "Hash": l.hash,
                "State": l.state,
                "Size": l.size,
                "MIMEType": if l.link_type == 1 { "Folder" } else { "application/octet-stream" },
                "NodeKey": l.node_key,
                "NodePassphrase": l.node_passphrase,
                "NodePassphraseSignature": l.node_passphrase_sig,
                "SignatureEmail": l.signature_email,
                "CreateTime": 1_700_000_000.0,
                "ModifyTime": l.modify_time,
                "Trashed": l.trashed,
                "XAttr": l.xattr,
            })
        };
        if l.link_type == 1 {
            if let Some(ref hk) = l.node_hash_key {
                obj["FolderProperties"] = json!({ "NodeHashKey": hk });
            }
        } else if let Some(ref kp) = l.content_key_packet {
            let active_rev = l.active_revision_id.as_ref().map(|rid| {
                json!({
                    "ID": rid,
                    "CreateTime": 1_700_000_000.0,
                    "Size": l.size,
                    "ManifestSignature": l.manifest_signature,
                    "SignatureAddress": l.signature_email,
                    "State": 1,
                })
            });
            obj["FileProperties"] = json!({
                "ContentKeyPacket": kp,
                "ContentKeyPacketSignature": l.content_key_packet_sig,
                "ActiveRevision": active_rev,
            });
        }
        obj
    }
}

type DriveKeyHandle = neutron_drive_daemon::native::crypto::UnlockedKey;

struct MockHttpServer {
    base_url: String,
    state: Arc<Mutex<MockServerState>>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockHttpServer {
    fn start(state: MockServerState) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind mock server");
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://127.0.0.1:{}", addr.port());
        let state_arc = Arc::new(Mutex::new(state));
        let stop_flag = Arc::new(AtomicBool::new(false));

        let state_bg = Arc::clone(&state_arc);
        let stop_bg = Arc::clone(&stop_flag);
        let base_bg = base_url.clone();

        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            while !stop_bg.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let s = Arc::clone(&state_bg);
                        let b = base_bg.clone();
                        thread::spawn(move || {
                            let _ = handle_http_connection(stream, &s, &b);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url,
            state: state_arc,
            stop_flag,
            handle: Some(handle),
        }
    }

    fn srp_public_key(&self) -> String {
        self.state.lock().unwrap().srp_signing_pub.clone()
    }

    fn auth_v4_calls(&self) -> usize {
        self.state.lock().unwrap().auth_v4_calls
    }

    fn set_srp_modulus_override(&self, raw_modulus: Option<String>) {
        self.state.lock().unwrap().srp_modulus_override = raw_modulus;
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

type ParsedHttpRequest = (String, String, HashMap<String, String>, Vec<u8>);

fn read_http_request(stream: &mut TcpStream) -> Option<ParsedHttpRequest> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = pos + 4;
                    break;
                }
            }
            Err(_) => return None,
        }
    }

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.split("\r\n");
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut headers = HashMap::new();
    let mut content_len = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let vl = v.trim().to_string();
            if kl == "content-length" {
                content_len = vl.parse().unwrap_or(0);
            }
            headers.insert(kl, vl);
        }
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_len {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    body.truncate(content_len);
    Some((method, target, headers, body))
}

fn send_http_response(
    stream: &mut TcpStream,
    status: u16,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let mut hdr = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        status,
        reason,
        body.len()
    );
    for (k, v) in extra_headers {
        hdr.push_str(&format!("{}: {}\r\n", k, v));
    }
    hdr.push_str("\r\n");
    let _ = stream.write_all(hdr.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn extract_multipart_block(content_type: &str, body: &[u8]) -> Option<Vec<u8>> {
    let boundary = content_type.split("boundary=").nth(1)?.trim();
    let marker = format!("--{}", boundary);
    let start_hdr = body
        .windows(b"\r\n\r\n".len())
        .position(|w| w == b"\r\n\r\n")?
        + 4;
    let end_marker = format!("\r\n{}--", marker);
    let end_pos = body[start_hdr..]
        .windows(end_marker.len())
        .position(|w| w == end_marker.as_bytes())
        .map(|p| start_hdr + p)?;
    Some(body[start_hdr..end_pos].to_vec())
}

fn handle_http_connection(
    mut stream: TcpStream,
    state_arc: &Arc<Mutex<MockServerState>>,
    base_url: &str,
) -> Result<(), ()> {
    let _ = stream.set_nonblocking(false);
    let (method, target, headers, body) = read_http_request(&mut stream).ok_or(())?;
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };

    let mut st = state_arc.lock().unwrap();
    st.captured_headers
        .push((method.clone(), path.clone(), headers.clone()));

    // Global fault injection for authenticated non-refresh endpoints
    let is_auth_public = path == "/auth/v4/sessions"
        || path == "/auth/v4/sessions/forks"
        || path.starts_with("/auth/v4/sessions/forks/")
        || path == "/auth/v4/info"
        || path == "/auth/v4"
        || path == "/auth/v4/refresh";
    if !is_auth_public {
        st.authed_request_calls += 1;
        if st.force_429_once || st.force_429_remaining > 0 {
            st.force_429_once = false;
            if st.force_429_remaining > 0 {
                st.force_429_remaining -= 1;
            }
            let retry_val = st
                .force_429_retry_after
                .clone()
                .unwrap_or_else(|| "0".to_string());
            send_http_response(
                &mut stream,
                429,
                &[("Retry-After", &retry_val)],
                br#"{"Code":429,"Error":"Rate limited"}"#,
            );
            return Ok(());
        }
        if st.force_503_remaining > 0 {
            st.force_503_remaining -= 1;
            send_http_response(
                &mut stream,
                503,
                &[],
                br#"{"Code":503,"Error":"Simulated transient service unavailable"}"#,
            );
            return Ok(());
        }
        if st.force_401_once || st.force_401_always {
            st.force_401_once = false;
            send_http_response(
                &mut stream,
                401,
                &[],
                br#"{"Code":401,"Error":"Access token expired"}"#,
            );
            return Ok(());
        }
        let expected_auth = format!("Bearer {}", st.access_token);
        if headers.get("authorization").map(String::as_str) != Some(expected_auth.as_str()) {
            send_http_response(
                &mut stream,
                401,
                &[],
                br#"{"Code":401,"Error":"Invalid bearer token"}"#,
            );
            return Ok(());
        }
    }

    let reply_json = |s: &mut TcpStream, code: u16, v: serde_json::Value| {
        let bytes = serde_json::to_vec(&v).unwrap();
        send_http_response(s, code, &[], &bytes);
    };

    match (method.as_str(), path.as_str()) {
        ("POST", "/auth/v4/sessions") => {
            assert_eq!(
                headers.get("x-enforce-unauthsession").map(String::as_str),
                Some("true")
            );
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "UID": "unauth-uid-1",
                    "AccessToken": "unauth-access-1",
                    "RefreshToken": "unauth-refresh-1"
                }),
            );
        }
        ("GET", "/auth/v4/sessions/forks") => {
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "Selector": st.fork_selector,
                    "UserCode": st.fork_user_code,
                }),
            );
        }
        ("GET", p) if p == format!("/auth/v4/sessions/forks/{}", st.fork_selector) => {
            if st.fork_poll_pending_remaining > 0 {
                st.fork_poll_pending_remaining -= 1;
                reply_json(
                    &mut stream,
                    422,
                    json!({"Code": 2001, "Error": "Invalid selector"}),
                );
                return Ok(());
            }
            let payload = st.fork_encrypted_payload.clone().unwrap_or_default();
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "Payload": payload,
                    "UID": st.uid,
                    "UserID": "user-1",
                    "AccessToken": st.access_token,
                    "RefreshToken": st.refresh_token,
                    "Scopes": ["full", "self"]
                }),
            );
        }
        ("POST", "/auth/v4/info") => {
            let clearsigned_mod = if let Some(ref custom) = st.srp_modulus_override {
                custom.clone()
            } else {
                let mod_b64 = BASE64.encode(&st.srp_modulus);
                neutron_drive_daemon::native::crypto::DriveCrypto::sign_cleartext(
                    &mod_b64,
                    &st.srp_signing_key_armored,
                    &st.srp_signing_passphrase,
                )
                .unwrap()
            };
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "Modulus": clearsigned_mod,
                    "ServerEphemeral": BASE64.encode(st.srp_b_pub.to_le_bytes_padded(256)),
                    "Version": 4,
                    "Salt": BASE64.encode(st.srp_salt),
                    "SRPSession": "srp-sess-1"
                }),
            );
        }
        ("POST", "/auth/v4") => {
            st.auth_v4_calls += 1;
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let user = req["Username"].as_str().unwrap_or("");
            if user != st.username {
                reply_json(
                    &mut stream,
                    401,
                    json!({"Code": 8002, "Error": "Incorrect user"}),
                );
                return Ok(());
            }
            let a_bytes = BASE64
                .decode(req["ClientEphemeral"].as_str().unwrap())
                .unwrap();
            let client_proof = BASE64.decode(req["ClientProof"].as_str().unwrap()).unwrap();

            let n = BigUint::from_le_bytes(&st.srp_modulus);
            let b_bytes = st.srp_b_pub.to_le_bytes_padded(256);

            let a_pub = BigUint::from_le_bytes(&a_bytes);
            let mut u_in = Vec::new();
            u_in.extend_from_slice(&a_bytes);
            u_in.extend_from_slice(&b_bytes);
            let u = BigUint::from_le_bytes(&expand_hash(&u_in));
            let vu = st.srp_v.mod_pow(&u, &n);
            let s_srv = a_pub.mul_mod(&vu, &n).mod_pow(&st.srp_b_sec, &n);
            let s_bytes = s_srv.to_le_bytes_padded(256);

            let mut m1_in = Vec::new();
            m1_in.extend_from_slice(&a_bytes);
            m1_in.extend_from_slice(&b_bytes);
            m1_in.extend_from_slice(&s_bytes);
            let expected_m1 = expand_hash(&m1_in);
            if client_proof != expected_m1 {
                reply_json(
                    &mut stream,
                    401,
                    json!({"Code": 8002, "Error": "Invalid SRP proof"}),
                );
                return Ok(());
            }

            let mut m2_in = Vec::new();
            m2_in.extend_from_slice(&a_bytes);
            m2_in.extend_from_slice(&expected_m1);
            m2_in.extend_from_slice(&s_bytes);
            let m2 = BASE64.encode(expand_hash(&m2_in));

            st.require_2fa_pending = st.totp_required;
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "UID": st.uid,
                    "AccessToken": st.access_token,
                    "RefreshToken": st.refresh_token,
                    "ServerProof": m2,
                    "2FA": { "Enabled": if st.totp_required { 1 } else { 0 } }
                }),
            );
        }
        ("POST", "/auth/v4/2fa") => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let code = req["TwoFactorCode"].as_str().unwrap_or("");
            if code == st.totp_code {
                st.require_2fa_pending = false;
                reply_json(&mut stream, 200, json!({"Code": 1000}));
            } else {
                reply_json(
                    &mut stream,
                    401,
                    json!({"Code": 8002, "Error": "Invalid 2FA code"}),
                );
            }
        }
        ("POST", "/auth/v4/refresh") => {
            st.refresh_calls += 1;
            if let Some(code) = st.refresh_override_status {
                if code == 429 {
                    send_http_response(
                        &mut stream,
                        429,
                        &[("Retry-After", "0")],
                        br#"{"Code":429,"Error":"Refresh rate limited"}"#,
                    );
                } else {
                    reply_json(
                        &mut stream,
                        code,
                        json!({"Code": code, "Error": "Refresh rejected by mock"}),
                    );
                }
                return Ok(());
            }
            st.access_token = format!("access-token-refreshed-{}", st.refresh_calls);
            st.refresh_token = format!("refresh-token-refreshed-{}", st.refresh_calls);
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "UID": st.uid,
                    "AccessToken": st.access_token,
                    "RefreshToken": st.refresh_token
                }),
            );
        }
        ("DELETE", "/auth/v4") => {
            reply_json(&mut stream, 200, json!({"Code": 1000}));
        }
        ("GET", "/core/v4/users") => {
            let used_drive = if st.null_drive_quota_fields {
                serde_json::Value::Null
            } else {
                json!(st.used_drive_space)
            };
            let max_drive = if st.null_drive_quota_fields {
                serde_json::Value::Null
            } else {
                json!(st.max_drive_space)
            };
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "User": {
                        "ID": "user-1",
                        "Email": st.address_email,
                        "Name": st.username,
                        "UsedSpace": st.used_space,
                        "MaxSpace": st.max_space,
                        "UsedDriveSpace": used_drive,
                        "MaxDriveSpace": max_drive,
                        "Keys": [{
                            "ID": "ukey-1",
                            "PrivateKey": st.user_key_armored,
                            "Primary": 1
                        }]
                    }
                }),
            );
        }
        ("GET", "/core/v4/keys/salts") => {
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "KeySalts": [{
                        "ID": "ukey-1",
                        "KeySalt": st.key_salt_b64
                    }]
                }),
            );
        }
        ("GET", "/core/v4/addresses") => {
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "Addresses": [{
                        "ID": st.address_id,
                        "Email": st.address_email,
                        "Status": 1,
                        "Keys": [{
                            "ID": st.address_key_id,
                            "PrivateKey": st.address_key_armored,
                            "Primary": 1,
                            "Active": 1,
                            "Token": st.address_token_armored
                        }]
                    }]
                }),
            );
        }
        ("GET", "/drive/volumes") => {
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "Volumes": [{
                        "VolumeID": st.volume_id,
                        "State": 1,
                        "Type": 1,
                        "Share": {
                            "ShareID": st.share_id,
                            "LinkID": st.root_link_id
                        }
                    }]
                }),
            );
        }
        ("GET", p) if p == format!("/drive/shares/{}", st.share_id) => {
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "ShareID": st.share_id,
                    "VolumeID": st.volume_id,
                    "Type": 1,
                    "State": 1,
                    "Creator": st.address_email,
                    "LinkID": st.root_link_id,
                    "Key": st.share_key_armored,
                    "Passphrase": st.share_passphrase_enc,
                    "PassphraseSignature": st.share_passphrase_sig,
                    "AddressID": st.address_id,
                    "AddressKeyID": st.address_key_id,
                    "Memberships": []
                }),
            );
        }
        ("GET", p)
            if p.starts_with(&format!("/drive/v2/volumes/{}/folders/", st.volume_id))
                && p.ends_with("/children") =>
        {
            st.list_children_calls += 1;
            let trimmed = p
                .trim_start_matches(&format!("/drive/v2/volumes/{}/folders/", st.volume_id))
                .trim_end_matches("/children");
            let all_kids = st.children.get(trimmed).cloned().unwrap_or_default();
            let anchor = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("AnchorID="))
                .unwrap_or("");
            let offset: usize = anchor
                .strip_prefix("page-")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let page_size = st.children_page_size.max(1);
            let start = if st.overlap_pagination && offset > 0 {
                offset - 1
            } else {
                offset
            };
            let end = (offset + page_size).min(all_kids.len());
            let slice = if start < all_kids.len() {
                all_kids[start..end].to_vec()
            } else {
                Vec::new()
            };
            let more = end < all_kids.len() || st.force_repeated_anchor || st.force_missing_anchor;
            let next_anchor = if st.force_missing_anchor {
                None
            } else if st.force_repeated_anchor {
                Some("page-stuck".to_string())
            } else if more {
                Some(format!("page-{}", end))
            } else {
                None
            };
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "LinkIDs": slice,
                    "AnchorID": next_anchor,
                    "More": more
                }),
            );
        }
        ("POST", p) if p == format!("/drive/volumes/{}/links/fetch_metadata", st.volume_id) => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let ids = req["LinkIDs"].as_array().cloned().unwrap_or_default();
            st.fetch_metadata_batch_sizes.push(ids.len());
            let links: Vec<serde_json::Value> = ids
                .iter()
                .filter_map(|v| v.as_str())
                .filter_map(|id| st.links.get(id))
                .map(|l| st.link_to_json(l))
                .collect();
            reply_json(&mut stream, 200, json!({"Code": 1000, "Links": links}));
        }
        ("POST", p) if p == format!("/drive/shares/{}/folders", st.share_id) => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let lid = st.next_id("folder");
            let parent = req["ParentLinkID"].as_str().unwrap().to_string();
            let link = ServerLink {
                link_id: lid.clone(),
                parent_link_id: Some(parent.clone()),
                link_type: 1,
                name_enc: req["Name"].as_str().unwrap().to_string(),
                hash: req["Hash"].as_str().unwrap().to_string(),
                state: 1,
                size: 0,
                node_key: req["NodeKey"].as_str().unwrap().to_string(),
                node_passphrase: req["NodePassphrase"].as_str().unwrap().to_string(),
                node_passphrase_sig: req["NodePassphraseSignature"].as_str().unwrap().to_string(),
                signature_email: req["SignatureAddress"].as_str().unwrap().to_string(),
                node_hash_key: Some(req["NodeHashKey"].as_str().unwrap().to_string()),
                content_key_packet: None,
                content_key_packet_sig: None,
                active_revision_id: None,
                manifest_signature: None,
                xattr: None,
                modify_time: 1_700_000_300.0,
                trashed: None,
            };
            st.links.insert(lid.clone(), link);
            st.children.entry(lid.clone()).or_default();
            st.children.entry(parent).or_default().push(lid.clone());
            reply_json(
                &mut stream,
                200,
                json!({"Code": 1000, "Folder": {"ID": lid}}),
            );
        }
        ("POST", p) if p == format!("/drive/shares/{}/files", st.share_id) => {
            st.create_file_calls += 1;
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let lid = st.next_id("file");
            let rev_id = st.next_id("rev");
            let parent = req["ParentLinkID"].as_str().unwrap().to_string();
            let link = ServerLink {
                link_id: lid.clone(),
                parent_link_id: Some(parent.clone()),
                link_type: 2,
                name_enc: req["Name"].as_str().unwrap().to_string(),
                hash: req["Hash"].as_str().unwrap().to_string(),
                state: 1,
                size: 0,
                node_key: req["NodeKey"].as_str().unwrap().to_string(),
                node_passphrase: req["NodePassphrase"].as_str().unwrap().to_string(),
                node_passphrase_sig: req["NodePassphraseSignature"].as_str().unwrap().to_string(),
                signature_email: req["SignatureAddress"].as_str().unwrap().to_string(),
                node_hash_key: None,
                content_key_packet: Some(req["ContentKeyPacket"].as_str().unwrap().to_string()),
                content_key_packet_sig: Some(
                    req["ContentKeyPacketSignature"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                ),
                active_revision_id: Some(rev_id.clone()),
                manifest_signature: None,
                xattr: None,
                modify_time: 1_700_000_300.0,
                trashed: None,
            };
            st.links.insert(lid.clone(), link);
            st.children.entry(parent).or_default().push(lid.clone());
            st.revision_blocks.insert(rev_id.clone(), Vec::new());
            let verif_code: Vec<u8> = (0..32)
                .map(|i| ((i * 37 + st.next_id_seq) & 0xFF) as u8)
                .collect();
            st.revision_verification_codes
                .insert(rev_id.clone(), (lid.clone(), verif_code));
            reply_json(
                &mut stream,
                200,
                json!({"Code": 1000, "File": {"ID": lid, "RevisionID": rev_id}}),
            );
        }
        ("POST", p)
            if p.starts_with(&format!("/drive/shares/{}/files/", st.share_id))
                && p.ends_with("/revisions") =>
        {
            st.create_revision_calls += 1;
            let fid = p
                .trim_start_matches(&format!("/drive/shares/{}/files/", st.share_id))
                .trim_end_matches("/revisions")
                .to_string();
            let rev_id = st.next_id("rev");
            st.revision_blocks.insert(rev_id.clone(), Vec::new());
            let verif_code: Vec<u8> = (0..32)
                .map(|i| ((i * 53 + st.next_id_seq) & 0xFF) as u8)
                .collect();
            st.revision_verification_codes
                .insert(rev_id.clone(), (fid, verif_code));
            reply_json(
                &mut stream,
                200,
                json!({"Code": 1000, "Revision": {"ID": rev_id}}),
            );
        }
        ("GET", p)
            if p.starts_with(&format!("/drive/v2/volumes/{}/links/", st.volume_id))
                && p.ends_with("/verification") =>
        {
            let rest = p
                .trim_start_matches(&format!("/drive/v2/volumes/{}/links/", st.volume_id))
                .trim_end_matches("/verification");
            let (fid, rev_id) = rest.split_once("/revisions/").unwrap();
            let mut code = st
                .revision_verification_codes
                .get(rev_id)
                .filter(|(f, _)| f == fid)
                .map(|(_, c)| c.clone())
                .unwrap_or_else(|| vec![0x5A; 32]);
            if st.corrupt_verification_code_once {
                st.corrupt_verification_code_once = false;
                for b in &mut code {
                    *b ^= 0xFF;
                }
            }
            let kp = st
                .links
                .get(fid)
                .and_then(|l| l.content_key_packet.clone())
                .unwrap_or_default();
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "VerificationCode": BASE64.encode(code),
                    "ContentKeyPacket": kp,
                }),
            );
        }
        ("POST", "/drive/blocks") => {
            st.new_blocks_calls += 1;
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let rev_id = req["RevisionID"].as_str().unwrap().to_string();
            let list = req["BlockList"].as_array().unwrap();
            let mut upload_links = Vec::new();
            let mut new_blocks = Vec::new();
            for item in list {
                let idx = item["Index"].as_u64().unwrap() as usize;
                let tok = format!("tok-{}-{}", rev_id, idx);
                let verifier_tok = item["Verifier"]["Token"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                new_blocks.push(ServerBlock {
                    index: idx,
                    hash: item["Hash"].as_str().unwrap().to_string(),
                    enc_signature: item["EncSignature"].as_str().unwrap().to_string(),
                    data: Vec::new(),
                });
                st.pending_upload_blocks
                    .insert(tok.clone(), (rev_id.clone(), idx, verifier_tok));
                if st.emit_bare_upload_urls {
                    upload_links.push(json!({
                        "Index": idx,
                        "Token": tok,
                        "BareURL": format!("{}/upload-block/{}", base_url, tok)
                    }));
                } else {
                    upload_links.push(json!({
                        "Index": idx,
                        "Token": tok,
                        "URL": format!("{}/upload-block/{}", base_url, tok)
                    }));
                }
            }
            st.revision_blocks
                .entry(rev_id)
                .or_default()
                .extend(new_blocks);
            reply_json(
                &mut stream,
                200,
                json!({"Code": 1000, "UploadLinks": upload_links}),
            );
        }
        ("POST", p) if p.starts_with("/upload-block/") => {
            let tok = p.trim_start_matches("/upload-block/");
            if st.emit_bare_upload_urls {
                assert_eq!(
                    headers.get("pm-storage-token").map(String::as_str),
                    Some(tok),
                    "Expected pm-storage-token header matching BareURL token"
                );
            }
            let ct = headers
                .get("content-type")
                .map(String::as_str)
                .unwrap_or("");
            let block_bytes = extract_multipart_block(ct, &body).unwrap();
            if let Some((rev_id, idx, expected_verifier_tok)) =
                st.pending_upload_blocks.get(tok).cloned()
            {
                if st.fail_block_upload_index == Some(idx) {
                    reply_json(
                        &mut stream,
                        500,
                        json!({"Code": 500, "Error": "Simulated block upload failure"}),
                    );
                    return Ok(());
                }
                if let Some((_, verif_code)) = st.revision_verification_codes.get(&rev_id) {
                    let expected_bytes: Vec<u8> = verif_code
                        .iter()
                        .enumerate()
                        .map(|(i, &b)| b ^ block_bytes.get(i).copied().unwrap_or(0))
                        .collect();
                    if BASE64.encode(expected_bytes) != expected_verifier_tok {
                        reply_json(
                            &mut stream,
                            422,
                            json!({
                                "Code": 200501,
                                "Error": "Operation failed: Make sure you are using the latest version of Proton Drive and retry"
                            }),
                        );
                        return Ok(());
                    }
                }
                if let Some(blocks) = st.revision_blocks.get_mut(&rev_id) {
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == idx) {
                        b.data = block_bytes;
                    }
                }
            }
            reply_json(&mut stream, 200, json!({"Code": 1000}));
        }
        ("PUT", p)
            if p.starts_with(&format!("/drive/shares/{}/files/", st.share_id))
                && p.contains("/revisions/") =>
        {
            if st.fail_update_revision {
                reply_json(
                    &mut stream,
                    500,
                    json!({"Code": 500, "Error": "Simulated revision commit failure"}),
                );
                return Ok(());
            }
            let rest = p.trim_start_matches(&format!("/drive/shares/{}/files/", st.share_id));
            let (fid, rev_id) = rest.split_once("/revisions/").unwrap();
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if let Some(link) = st.links.get_mut(fid) {
                link.active_revision_id = Some(rev_id.to_string());
                link.manifest_signature =
                    req["ManifestSignature"].as_str().map(ToString::to_string);
                link.xattr = req["XAttr"].as_str().map(ToString::to_string);
            }
            reply_json(&mut stream, 200, json!({"Code": 1000}));
        }
        ("DELETE", p)
            if p.starts_with(&format!("/drive/shares/{}/files/", st.share_id))
                && p.contains("/revisions/") =>
        {
            let rest = p.trim_start_matches(&format!("/drive/shares/{}/files/", st.share_id));
            let (fid, rev_id) = rest.split_once("/revisions/").unwrap();
            st.delete_revision_calls += 1;
            st.deleted_revisions
                .push((fid.to_string(), rev_id.to_string()));
            st.revision_blocks.remove(rev_id);
            reply_json(&mut stream, 200, json!({"Code": 1000}));
        }
        ("GET", p)
            if p.starts_with(&format!("/drive/shares/{}/files/", st.share_id))
                && p.contains("/revisions/") =>
        {
            let rest = p.trim_start_matches(&format!("/drive/shares/{}/files/", st.share_id));
            let (fid, rev_id) = rest.split_once("/revisions/").unwrap();
            let link = st.links.get(fid).cloned();
            let blocks = st.revision_blocks.get(rev_id).cloned().unwrap_or_default();
            let blocks_json: Vec<serde_json::Value> = blocks
                .iter()
                .map(|b| {
                    if st.emit_bare_upload_urls {
                        json!({
                            "Index": b.index,
                            "Hash": b.hash,
                            "BareURL": format!("{}/download-block/{}/{}", base_url, rev_id, b.index),
                            "Token": format!("dl-tok-{}-{}", rev_id, b.index),
                            "EncSignature": b.enc_signature,
                            "SignatureEmail": st.address_email
                        })
                    } else {
                        json!({
                            "Index": b.index,
                            "Hash": b.hash,
                            "URL": format!("{}/download-block/{}/{}", base_url, rev_id, b.index),
                            "EncSignature": b.enc_signature,
                            "SignatureEmail": st.address_email
                        })
                    }
                })
                .collect();
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "Revision": {
                        "ID": rev_id,
                        "CreateTime": 1_700_000_000.0,
                        "Size": link.as_ref().map(|l| l.size).unwrap_or(0),
                        "ManifestSignature": link.as_ref().and_then(|l| l.manifest_signature.clone()),
                        "SignatureAddress": st.address_email,
                        "State": 1,
                        "Blocks": blocks_json,
                        "XAttr": link.as_ref().and_then(|l| l.xattr.clone())
                    }
                }),
            );
        }
        ("GET", p) if p.starts_with("/download-block/") => {
            st.block_download_calls += 1;
            let rest = p.trim_start_matches("/download-block/");
            let (rev_id, idx_str) = rest.split_once('/').unwrap();
            let idx: usize = idx_str.parse().unwrap();
            if st.emit_bare_upload_urls {
                let expected_tok = format!("dl-tok-{}-{}", rev_id, idx);
                assert_eq!(
                    headers.get("pm-storage-token").map(String::as_str),
                    Some(expected_tok.as_str()),
                    "Expected pm-storage-token header on BareURL download"
                );
            }
            if st.fail_block_download_index == Some(idx) {
                reply_json(
                    &mut stream,
                    500,
                    json!({"Code": 500, "Error": "Simulated block download failure"}),
                );
                return Ok(());
            }
            let data = st
                .revision_blocks
                .get(rev_id)
                .and_then(|bs| bs.iter().find(|b| b.index == idx))
                .map(|b| b.data.clone())
                .unwrap_or_default();
            send_http_response(&mut stream, 200, &[], &data);
        }
        ("PUT", p)
            if p.starts_with(&format!("/drive/shares/{}/links/", st.share_id))
                && p.ends_with("/rename") =>
        {
            let lid = p
                .trim_start_matches(&format!("/drive/shares/{}/links/", st.share_id))
                .trim_end_matches("/rename");
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if let Some(link) = st.links.get_mut(lid) {
                if let Some(orig) = req["OriginalHash"].as_str() {
                    assert_eq!(orig, link.hash, "OriginalHash mismatch on rename");
                }
                link.name_enc = req["Name"].as_str().unwrap().to_string();
                if let Some(h) = req["Hash"].as_str() {
                    link.hash = h.to_string();
                }
            }
            reply_json(&mut stream, 200, json!({"Code": 1000}));
        }
        ("PUT", p) if p == format!("/drive/volumes/{}/links/move-multiple", st.volume_id) => {
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let new_parent = req["ParentLinkID"].as_str().unwrap().to_string();
            let items = req["Links"].as_array().unwrap();
            let mut resps = Vec::new();
            for item in items {
                let lid = item["LinkID"].as_str().unwrap().to_string();
                let mut old_parent_opt = None;
                if let Some(link) = st.links.get_mut(&lid) {
                    old_parent_opt = link.parent_link_id.take();
                    link.parent_link_id = Some(new_parent.clone());
                    link.name_enc = item["Name"].as_str().unwrap().to_string();
                    link.node_passphrase = item["NodePassphrase"].as_str().unwrap().to_string();
                    link.hash = item["Hash"].as_str().unwrap().to_string();
                }
                if let Some(old_parent) = old_parent_opt {
                    if let Some(kids) = st.children.get_mut(&old_parent) {
                        kids.retain(|k| k != &lid);
                    }
                }
                st.children
                    .entry(new_parent.clone())
                    .or_default()
                    .push(lid.clone());
                resps.push(json!({"LinkID": lid, "Response": {"Code": 1000}}));
            }
            reply_json(&mut stream, 200, json!({"Code": 1000, "Responses": resps}));
        }
        ("POST", p)
            if p.starts_with(&format!("/drive/shares/{}/folders/", st.share_id))
                && p.ends_with("/trash_multiple") =>
        {
            st.trash_calls += 1;
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let ids = req["LinkIDs"].as_array().unwrap();
            let mut resps = Vec::new();
            for v in ids {
                let lid = v.as_str().unwrap().to_string();
                if let Some(link) = st.links.get_mut(&lid) {
                    link.trashed = Some(1_700_000_500.0);
                    link.state = 2;
                }
                resps.push(json!({"LinkID": lid, "Response": {"Code": 1000}}));
            }
            reply_json(&mut stream, 200, json!({"Code": 1000, "Responses": resps}));
        }
        ("POST", p)
            if p == format!("/drive/v2/volumes/{}/trash/delete_multiple", st.volume_id)
                || p == format!("/drive/v2/volumes/{}/delete_multiple", st.volume_id) =>
        {
            st.delete_calls += 1;
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let ids = req["LinkIDs"].as_array().unwrap();
            let mut resps = Vec::new();
            for v in ids {
                let lid = v.as_str().unwrap().to_string();
                if let Some(link) = st.links.remove(&lid) {
                    if let Some(p) = link.parent_link_id {
                        if let Some(kids) = st.children.get_mut(&p) {
                            kids.retain(|k| k != &lid);
                        }
                    }
                }
                resps.push(json!({"LinkID": lid, "Response": {"Code": 1000}}));
            }
            reply_json(&mut stream, 200, json!({"Code": 1000, "Responses": resps}));
        }
        ("GET", p) if p == format!("/drive/volumes/{}/events/latest", st.volume_id) => {
            reply_json(
                &mut stream,
                200,
                json!({"Code": 1000, "EventID": st.latest_event_id}),
            );
        }
        ("GET", p) if p.starts_with(&format!("/drive/volumes/{}/events/", st.volume_id)) => {
            if st.events_fail_remaining > 0 {
                st.events_fail_remaining -= 1;
                reply_json(
                    &mut stream,
                    500,
                    json!({"Code": 500, "Error": "Simulated transient events failure"}),
                );
                return Ok(());
            }
            let since = p.trim_start_matches(&format!("/drive/volumes/{}/events/", st.volume_id));
            if st.events_more_repeated_once {
                st.events_more_repeated_once = false;
                reply_json(
                    &mut stream,
                    200,
                    json!({
                        "Code": 1000,
                        "Events": [],
                        "EventID": since,
                        "More": 1,
                        "Refresh": 0
                    }),
                );
                return Ok(());
            }
            if st.events_refresh_once {
                st.events_refresh_once = false;
                reply_json(
                    &mut stream,
                    200,
                    json!({
                        "Code": 1000,
                        "Events": [],
                        "EventID": st.latest_event_id,
                        "More": 0,
                        "Refresh": 1
                    }),
                );
                return Ok(());
            }
            let evs = if since == st.latest_event_id {
                Vec::new()
            } else {
                st.events.clone()
            };
            reply_json(
                &mut stream,
                200,
                json!({
                    "Code": 1000,
                    "Events": evs,
                    "EventID": st.latest_event_id,
                    "More": 0,
                    "Refresh": 0
                }),
            );
        }
        _ => {
            reply_json(&mut stream, 404, json!({"Code": 404, "Error": "Not found"}));
        }
    }

    Ok(())
}

fn new_client_and_server_with_store(
    fixture: &TestFixture,
    totp_required: bool,
) -> (MockHttpServer, NativeProtonClient, Arc<InMemorySecretStore>) {
    let state = MockServerState::new("alice@proton.me", "super-secret-password", totp_required);
    let server = MockHttpServer::start(state);
    let vault_path = fixture.root_path().join("session_vault.json");
    let store = Arc::new(InMemorySecretStore::new());
    let vault = Arc::new(
        SessionVault::new_with_backend(
            Some(vault_path),
            store.clone(),
            Arc::new(NoFallbackKeyProvider),
        )
        .expect("Create isolated SessionVault"),
    );
    let client = NativeProtonClient::new_with_vault(
        fixture.db.clone(),
        vault,
        Some(server.base_url.clone()),
    )
    .expect("Create NativeProtonClient")
    .with_trusted_srp_keys(vec![server.srp_public_key()]);
    // Keep mock backoff sub-millisecond in unit/integration tests while exercising real retry loops.
    client
        .http()
        .rate_limit_gate()
        .set_default_retry_after(Duration::from_millis(1));
    (server, client, store)
}

fn new_client_and_server(
    fixture: &TestFixture,
    totp_required: bool,
) -> (MockHttpServer, NativeProtonClient) {
    let (server, client, _) = new_client_and_server_with_store(fixture, totp_required);
    (server, client)
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_native_crypto_packets_and_xattr_roundtrip() {
    let key_armored = DriveKey::generate("Alice", "alice@proton.me", "pass-123").unwrap();
    let pub_armored = DriveKey::public_key_armored(&key_armored).unwrap();
    let unlocked = DriveKey::unlock(&key_armored, "pass-123").unwrap();

    let (sk, kp_raw, _kp_b64, kp_sig) =
        Encryptor::generate_content_session_key(&pub_armored, &key_armored, "pass-123").unwrap();
    let dec_sk = Decryptor::decrypt_and_verify_content_key_packet(
        &kp_raw,
        &unlocked,
        Some(&kp_sig),
        std::slice::from_ref(&pub_armored),
    )
    .unwrap();
    assert!(dec_sk.is_verified());
    assert_eq!(dec_sk.value(), sk.as_bytes());

    let xattr = ExtendedAttributes::new(
        Some("2026-11-15T10:00:00Z".to_string()),
        Some(12345),
        Some(vec![12345]),
        Some("abcdef".to_string()),
    );
    let enc_xattr = Encryptor::encrypt_and_sign_bytes(
        &xattr.encoded().unwrap(),
        &pub_armored,
        "pass-123",
        &key_armored,
        true,
    )
    .unwrap();

    let block = dearmor(&enc_xattr).unwrap();
    let pkts = decode_packets(&block.body).unwrap();
    assert!(pkts.iter().any(|(tag, _)| *tag == PACKET_PKESK));
    assert!(pkts.iter().any(|(tag, _)| *tag == PACKET_SEIPD));

    let dec_xattr = Decryptor::decrypt_and_verify_xattributes(
        &enc_xattr,
        &unlocked,
        std::slice::from_ref(&pub_armored),
    )
    .unwrap();
    assert!(dec_xattr.is_verified());
    let decoded_xattr = ExtendedAttributes::decode(dec_xattr.value()).unwrap();
    assert_eq!(decoded_xattr, xattr);
}

#[test]
fn test_native_srp_auth_2fa_vault_persistence_and_quota() {
    let fixture = TestFixture::new();
    let (server, client, store) = new_client_and_server_with_store(&fixture, true);

    // Unauthenticated initially
    assert!(!client.check_auth_status().0);

    // Missing TOTP triggers 2FA_REQUIRED
    let err = client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap_err();
    assert!(
        err.starts_with("2FA_REQUIRED"),
        "Expected 2FA_REQUIRED, got {}",
        err
    );

    // Full SRP-6a + 2FA login succeeds
    let msg = client
        .authenticate("alice@proton.me", "super-secret-password", Some("123456"))
        .expect("Auth with TOTP must succeed");
    assert!(msg.contains("alice@proton.me"));
    assert!(client.check_auth_status().0);

    // Check vault file permissions on disk (0600) and verify secrets are NOT in plaintext on disk
    let vault_path = fixture.root_path().join("session_vault.json");
    assert!(vault_path.exists());
    let meta = fs::metadata(&vault_path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let disk_raw = fs::read_to_string(&vault_path).unwrap();
    assert!(!disk_raw.contains("BEGIN PGP PRIVATE KEY BLOCK"));
    assert!(!disk_raw.contains("access-token-"));
    assert!(!disk_raw.contains("refresh-token-"));
    assert_eq!(store.secret_count(), 1);

    // Check real StorageQuota from /core/v4/users
    let quota = client.get_storage_quota();
    assert_eq!(quota.used_bytes, 1_073_741_824);
    assert_eq!(quota.total_bytes, 536_870_912_000);
    assert!((quota.percent_used - 0.2).abs() < 0.01);

    // Reconstruct client from persisted vault + Secret Service without re-authenticating
    let reloaded_vault = Arc::new(
        SessionVault::new_with_backend(
            Some(vault_path.clone()),
            store.clone(),
            Arc::new(NoFallbackKeyProvider),
        )
        .unwrap(),
    );
    let client_reloaded = NativeProtonClient::new_with_vault(
        fixture.db.clone(),
        reloaded_vault,
        Some(server.base_url.clone()),
    )
    .unwrap();
    assert!(client_reloaded.check_auth_status().0);
    assert_eq!(
        client_reloaded.get_storage_quota().total_bytes,
        536_870_912_000
    );

    // Logout removes vault metadata and Secret Service entry
    assert!(client_reloaded.logout());
    assert!(!vault_path.exists());
    assert_eq!(store.secret_count(), 0);
    assert!(!client_reloaded.check_auth_status().0);
}

#[test]
fn test_native_srp_auth_rejects_unverified_or_tampered_modulus_before_login_proof() {
    let fixture = TestFixture::new();
    let state = MockServerState::new("alice@proton.me", "super-secret-password", false);
    let mod_b64 = BASE64.encode(&state.srp_modulus);
    let valid_signed_mod = neutron_drive_daemon::native::crypto::DriveCrypto::sign_cleartext(
        &mod_b64,
        &state.srp_signing_key_armored,
        &state.srp_signing_passphrase,
    )
    .unwrap();
    let server = MockHttpServer::start(state);
    let vault_path = fixture.root_path().join("session_vault.json");
    let store = Arc::new(InMemorySecretStore::new());

    // 1. Default pinned Proton key rejects mock server's untrusted SRP key before POST /auth/v4
    let default_vault = Arc::new(
        SessionVault::new_with_backend(
            Some(vault_path.clone()),
            store.clone(),
            Arc::new(NoFallbackKeyProvider),
        )
        .unwrap(),
    );
    let default_client = NativeProtonClient::new_with_vault(
        fixture.db.clone(),
        default_vault,
        Some(server.base_url.clone()),
    )
    .expect("Create default NativeProtonClient");
    assert!(default_client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .is_err());
    assert_eq!(server.auth_v4_calls(), 0);

    // Client configured with the mock server's key still rejects unsigned/tampered/malformed moduli
    let vault = Arc::new(
        SessionVault::new_with_backend(Some(vault_path), store, Arc::new(NoFallbackKeyProvider))
            .unwrap(),
    );
    let client = NativeProtonClient::new_with_vault(
        fixture.db.clone(),
        vault,
        Some(server.base_url.clone()),
    )
    .expect("Create NativeProtonClient")
    .with_trusted_srp_keys(vec![server.srp_public_key()]);

    // 2. Unsigned base64 modulus
    server.set_srp_modulus_override(Some(mod_b64.clone()));
    assert!(client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .is_err());
    assert_eq!(server.auth_v4_calls(), 0);

    // 3. Tampered signed modulus payload
    let tampered = valid_signed_mod.replacen(&mod_b64[..8], "ZZZZZZZZ", 1);
    server.set_srp_modulus_override(Some(tampered));
    assert!(client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .is_err());
    assert_eq!(server.auth_v4_calls(), 0);

    // 4. Malformed PGP armor
    server.set_srp_modulus_override(Some(
        valid_signed_mod.replace("-----END PGP SIGNATURE-----", ""),
    ));
    assert!(client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .is_err());
    assert_eq!(server.auth_v4_calls(), 0);
}

#[test]
fn test_native_rate_limit_429_and_401_token_refresh() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // Inject both a 429 rate-limit and a 401 expired-token error
    {
        let mut st = server.state.lock().unwrap();
        st.force_429_once = true;
        st.force_401_once = true;
    }

    let nodes = client
        .list_path("/my-files")
        .expect("Should recover from 429 and 401");
    assert!(nodes.is_empty());

    let st = server.state.lock().unwrap();
    assert_eq!(
        st.refresh_calls, 1,
        "Must transparently refresh token once on 401"
    );
    assert_eq!(
        client.vault().http_tokens().unwrap().access_token.as_str(),
        "access-token-refreshed-1"
    );
}

#[test]
fn test_native_bootstrap_paginated_list_and_metadata_decryption() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // Populate 4 items under root -> mock server paginates at 2 per page -> 2 pages!
    {
        let mut st = server.state.lock().unwrap();
        let root_id = st.root_link_id.clone();
        let docs_id = st.add_remote_folder(&root_id, "Docs");
        st.add_remote_file(&root_id, "a.txt", b"hello a");
        st.add_remote_file(&root_id, "b.txt", b"hello b!");
        st.add_remote_file(&root_id, "c.txt", b"hello c!!");
        st.add_remote_file(&docs_id, "nested.md", b"# Nested");
    }

    let root_nodes = client.list_path("/my-files").expect("list root");
    assert_eq!(root_nodes.len(), 4);
    let names: Vec<&str> = root_nodes.iter().map(|n| n.name.as_str()).collect();
    assert!(names.contains(&"Docs"));
    assert!(names.contains(&"a.txt"));
    assert!(names.contains(&"b.txt"));
    assert!(names.contains(&"c.txt"));
    assert_eq!(
        server.state.lock().unwrap().list_children_calls,
        2,
        "Root listing with 4 items at page size 2 must consume 2 paginated requests"
    );

    let docs_nodes = client.list_path("/my-files/Docs").expect("list Docs");
    assert_eq!(docs_nodes.len(), 1);
    assert_eq!(docs_nodes[0].name, "nested.md");
    assert_eq!(docs_nodes[0].size, 8);
}

#[test]
fn test_native_multiblock_upload_download_and_range_read() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // 4.5 MiB payload spanning 2 blocks (4 MiB + 512 KiB)
    let total_len = 4 * 1024 * 1024 + 512 * 1024;
    let payload: Vec<u8> = (0..total_len).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    let src_dir = fixture.root_path().join("src_files");
    fs::create_dir_all(&src_dir).unwrap();
    let src_file = src_dir.join("large_blob.bin");
    fs::write(&src_file, &payload).unwrap();

    assert!(client.upload_file(&src_file, "/my-files", "create-new-revision"));

    let listed = client.list_path("/my-files").unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "large_blob.bin");
    assert_eq!(listed[0].size as usize, total_len);

    // Download full multi-block file and verify byte-for-byte
    let dl_dir = fixture.root_path().join("downloads");
    assert!(client.download_file("/my-files/large_blob.bin", &dl_dir, "overwrite"));
    let downloaded = fs::read(dl_dir.join("large_blob.bin")).unwrap();
    assert_eq!(downloaded, payload);

    // Verify byte-range read strictly inside block 2 downloads ONLY 1 block!
    server.state.lock().unwrap().block_download_calls = 0;
    let b2_offset = (4 * 1024 * 1024 + 1024) as u64;
    let slice_b2 = client
        .read_block_range("/my-files/large_blob.bin", b2_offset, 256)
        .unwrap()
        .expect("range read inside block 2");
    assert_eq!(
        slice_b2,
        &payload[b2_offset as usize..b2_offset as usize + 256]
    );
    assert_eq!(
        server.state.lock().unwrap().block_download_calls,
        1,
        "Range read inside block 2 must fetch only 1 block"
    );

    // Verify cross-boundary range read across 4 MiB boundary
    let cross_offset = (4 * 1024 * 1024 - 64) as u64;
    let cross_slice = client
        .read_block_range("/my-files/large_blob.bin", cross_offset, 128)
        .unwrap()
        .expect("cross-boundary range read");
    assert_eq!(
        cross_slice,
        &payload[cross_offset as usize..cross_offset as usize + 128]
    );
}

#[test]
fn test_native_namespace_operations_and_reencryption() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    assert!(client.create_folder("/my-files", "SrcDir"));
    assert!(client.create_folder("/my-files", "DstDir"));

    let src_dir = fixture.root_path().join("up");
    fs::create_dir_all(&src_dir).unwrap();
    let sample = src_dir.join("draft.txt");
    fs::write(&sample, b"move-and-rename-secret-data").unwrap();
    assert!(client.upload_file(&sample, "/my-files/SrcDir", "create-new-revision"));

    // Rename draft.txt -> final.txt
    assert!(client.rename("/my-files/SrcDir/draft.txt", "final.txt"));
    let src_items = client.list_path("/my-files/SrcDir").unwrap();
    assert_eq!(src_items.len(), 1);
    assert_eq!(src_items[0].name, "final.txt");

    // Move /my-files/SrcDir/final.txt -> /my-files/DstDir (re-encrypts key packet under DstDir!)
    assert!(client.move_node("/my-files/SrcDir/final.txt", "/my-files/DstDir"));
    assert!(client.list_path("/my-files/SrcDir").unwrap().is_empty());
    let dst_items = client.list_path("/my-files/DstDir").unwrap();
    assert_eq!(dst_items.len(), 1);
    assert_eq!(dst_items[0].name, "final.txt");

    // Verify moved file is still decryptable & downloadable from new parent
    let dl_dir = fixture.root_path().join("dl_moved");
    assert!(client.download_file("/my-files/DstDir/final.txt", &dl_dir, "overwrite"));
    assert_eq!(
        fs::read(dl_dir.join("final.txt")).unwrap(),
        b"move-and-rename-secret-data"
    );

    // Move and rename a non-empty folder (preserving nested descendant key/path caches!)
    assert!(client.create_folder("/my-files/SrcDir", "Nested"));
    assert!(client.create_folder("/my-files/SrcDir/Nested", "Leaf"));
    let nested_file = src_dir.join("inner.txt");
    fs::write(&nested_file, b"nested-subtree-payload").unwrap();
    assert!(client.upload_file(
        &nested_file,
        "/my-files/SrcDir/Nested/Leaf",
        "create-new-revision"
    ));

    // Self / descendant cycle move must be rejected locally without mutating server state
    assert!(!client.move_node("/my-files/SrcDir/Nested", "/my-files/SrcDir/Nested"));
    assert!(!client.move_node("/my-files/SrcDir/Nested", "/my-files/SrcDir/Nested/Leaf"));
    // Invalid rename names must also fail cleanly
    assert!(!client.rename("/my-files/SrcDir/Nested", "bad/name"));
    assert!(!client.rename("/my-files/SrcDir/Nested", ".."));

    // Move non-empty subtree SrcDir/Nested -> DstDir/Nested, then rename Nested -> Archived
    assert!(client.move_node("/my-files/SrcDir/Nested", "/my-files/DstDir"));
    assert!(client.rename("/my-files/DstDir/Nested", "Archived"));

    // Cached descendant under relocated & renamed folder remains directly downloadable
    let dl_nested = fixture.root_path().join("dl_nested");
    assert!(client.download_file(
        "/my-files/DstDir/Archived/Leaf/inner.txt",
        &dl_nested,
        "overwrite"
    ));
    assert_eq!(
        fs::read(dl_nested.join("inner.txt")).unwrap(),
        b"nested-subtree-payload"
    );

    // Trash & permanently delete single file + subtree folder (including trash -> delete sequence!)
    assert!(client.trash("/my-files/DstDir/final.txt"));
    assert!(client.list_path("/my-files/DstDir").unwrap().len() == 1);
    assert!(client.trash("/my-files/DstDir"));
    assert!(client.delete("/my-files/DstDir"));
    assert!(client.delete("/my-files/SrcDir"));
    assert_eq!(server.state.lock().unwrap().trash_calls, 2);
    assert_eq!(server.state.lock().unwrap().delete_calls, 2);
    assert!(client.list_path("/my-files").unwrap().is_empty());
}

#[test]
fn test_native_incremental_event_stream_and_safety_guards() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // Seed remote /clean.txt and /dirty.txt
    let (clean_id, dirty_id, root_id) = {
        let mut st = server.state.lock().unwrap();
        let root_id = st.root_link_id.clone();
        let c = st.add_remote_file(&root_id, "clean.txt", b"v1");
        let d = st.add_remote_file(&root_id, "dirty.txt", b"remote-v1");
        (c, d, root_id)
    };

    let client_arc: Arc<dyn RemoteDrive> = Arc::new(client);
    let engine = SyncEngine::new(
        Arc::clone(&client_arc),
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        10,
        Arc::clone(&fixture.activity),
    );

    // Initial sync: establishes event cursor ev-0 and reconciles "/"
    engine.poll_remote_changes();
    assert_eq!(
        fixture
            .db
            .get_setting("native_latest_event_id_vol-main-1")
            .as_deref(),
        Some("ev-0")
    );
    assert!(fixture.db.get_node("/clean.txt").is_some());
    assert!(fixture.db.get_node("/dirty.txt").is_some());

    // Mark /clean.txt as having a cached clean file, and /dirty.txt as MODIFIED locally
    let clean_cache = fixture.cache_dir.join("clean.dat");
    fs::write(&clean_cache, b"v1").unwrap();
    fixture.db.update_sync_status(
        "/clean.txt",
        SyncStatus::SYNCED,
        Some(clean_cache.to_str().unwrap()),
        None,
    );
    let dirty_cache = fixture.cache_dir.join("dirty.dat");
    fs::write(&dirty_cache, b"unsaved-local-bytes").unwrap();
    fixture
        .db
        .mark_pending("/dirty.txt", dirty_cache.to_str().unwrap(), Some(19))
        .unwrap();

    // Queue remote events:
    // 1) Create new_remote.txt
    // 2) UpdateContent clean.txt (2 bytes -> 7 bytes)
    // 3) Delete dirty.txt (must be ignored by safety guard!)
    {
        let mut st = server.state.lock().unwrap();
        let new_lid = st.add_remote_file(&root_id, "new_remote.txt", b"created!");
        let new_json = st.link_to_json(&st.links[&new_lid]);

        // Update clean.txt size & revision
        let (parent_uk, _) = st.unlock_folder(&root_id);
        let addr_pub = st.address_unlocked_pub.clone();
        let addr_pass = st.address_key_passphrase.clone();
        let addr_key = st.address_key_armored.clone();
        let clean_link_snapshot = st.links.get(&clean_id).unwrap().clone();
        let pp = Decryptor::decrypt_and_verify_node_passphrase(
            &clean_link_snapshot.node_passphrase,
            &clean_link_snapshot.node_passphrase_sig,
            std::slice::from_ref(&addr_pub),
            std::slice::from_ref(&parent_uk),
        )
        .unwrap();
        let clean_uk = DriveKey::unlock(&clean_link_snapshot.node_key, pp.value()).unwrap();
        let new_xattr = ExtendedAttributes::new(
            Some("2026-11-15T12:05:00Z".to_string()),
            Some(7),
            Some(vec![7]),
            None,
        );
        let enc_xattr = Encryptor::encrypt_and_sign_bytes(
            &new_xattr.encoded().unwrap(),
            &clean_uk.armored_public,
            &addr_pass,
            &addr_key,
            true,
        )
        .unwrap();
        {
            let clean_link = st.links.get_mut(&clean_id).unwrap();
            clean_link.xattr = Some(enc_xattr);
            clean_link.size = 7;
            clean_link.active_revision_id = Some("rev-updated-2".to_string());
        }
        let clean_json = st.link_to_json(&st.links[&clean_id]);

        st.latest_event_id = "ev-1".to_string();
        st.events = vec![
            json!({
                "ContextShareID": st.share_id,
                "EventID": "ev-1a",
                "EventType": 1,
                "CreateTime": 1_700_000_900.0,
                "Link": new_json
            }),
            json!({
                "ContextShareID": st.share_id,
                "EventID": "ev-1b",
                "EventType": 2,
                "CreateTime": 1_700_000_901.0,
                "Link": clean_json
            }),
            json!({
                "ContextShareID": st.share_id,
                "EventID": "ev-1c",
                "EventType": 0,
                "CreateTime": 1_700_000_902.0,
                "Link": { "LinkID": dirty_id }
            }),
        ];
        // Note: make sure list_children_calls stays at 1 (no full directory re-listing on next poll!)
        st.list_children_calls = 0;
    }

    // Second sync: consumes incremental events ONLY (0 list_children calls!)
    engine.poll_remote_changes();
    assert_eq!(server.state.lock().unwrap().list_children_calls, 0);
    assert_eq!(
        fixture
            .db
            .get_setting("native_latest_event_id_vol-main-1")
            .as_deref(),
        Some("ev-1")
    );

    // 1. Created file appeared
    let created_node = fixture.db.get_node("/new_remote.txt").unwrap();
    assert_eq!(created_node.size, 8);
    assert_eq!(created_node.sync_status, SyncStatus::CLOUD_ONLY);

    // 2. Updated clean file invalidated stale cache & updated size/revision
    let updated_clean = fixture.db.get_node("/clean.txt").unwrap();
    assert_eq!(updated_clean.size, 7);
    assert_eq!(updated_clean.sync_status, SyncStatus::CLOUD_ONLY);
    assert_eq!(updated_clean.revision_id.as_deref(), Some("rev-updated-2"));
    assert!(!clean_cache.exists());

    // 3. Dirty file survived remote delete event!
    let preserved_dirty = fixture.db.get_node("/dirty.txt").unwrap();
    assert_eq!(preserved_dirty.sync_status, SyncStatus::MODIFIED);
    assert_eq!(fs::read(&dirty_cache).unwrap(), b"unsaved-local-bytes");

    // 4. Now queue a remote Delete event for /clean.txt (now clean) and verify deletion
    {
        let mut st = server.state.lock().unwrap();
        st.latest_event_id = "ev-2".to_string();
        st.events = vec![json!({
            "ContextShareID": st.share_id,
            "EventID": "ev-2a",
            "EventType": 0,
            "CreateTime": 1_700_000_950.0,
            "Link": { "LinkID": clean_id }
        })];
    }
    engine.poll_remote_changes();
    assert!(fixture.db.get_node("/clean.txt").is_none());
}

#[test]
fn test_native_event_cursor_recovery_restart_stale_and_conflicts() {
    let fixture = TestFixture::new();
    let store = Arc::new(InMemorySecretStore::new());
    let vault_path = fixture.root_path().join("restart_vault.json");
    let vault = Arc::new(
        SessionVault::new_with_backend(
            Some(vault_path.clone()),
            store.clone(),
            Arc::new(NoFallbackKeyProvider),
        )
        .unwrap(),
    );
    let mut mock_state = MockServerState::new("alice@proton.me", "super-secret-password", false);
    let root_id = mock_state.root_link_id.clone();
    let docs_id = mock_state.add_remote_folder(&root_id, "docs");
    let spec_id = mock_state.add_remote_file(&docs_id, "spec.txt", b"spec-v1");
    let stale_id = mock_state.add_remote_file(&docs_id, "stale.txt", b"will-disappear");
    let dup_id = mock_state.add_remote_file(&root_id, "dup.txt", b"dup-v1");
    let err_id = mock_state.add_remote_file(&root_id, "err_retry.txt", b"remote-orig");
    let open_id = mock_state.add_remote_file(&root_id, "open_handle.txt", b"open-remote");
    let server = MockHttpServer::start(mock_state);

    let trusted_pub = server.state.lock().unwrap().srp_signing_pub.clone();
    let client1 = NativeProtonClient::new_with_vault(
        fixture.db.clone(),
        vault.clone(),
        Some(server.base_url.clone()),
    )
    .unwrap()
    .with_trusted_srp_keys(vec![trusted_pub.clone()]);
    client1
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    let client1_arc: Arc<dyn RemoteDrive> = Arc::new(client1);
    let fuse1 = ProtonDriveFUSE::new(
        Arc::clone(&client1_arc),
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        Some("/my-files"),
        Arc::clone(&fixture.activity),
    );
    let engine1 = SyncEngine::new(
        Arc::clone(&client1_arc),
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        10,
        Arc::clone(&fixture.activity),
    );

    // 1. Initial sync + FUSE list /docs establishes event cursor ev-0 and reconciled nodes
    engine1.poll_remote_changes();
    fuse1.refresh_dir_if_needed("/docs", 0.0);
    assert!(fixture.db.get_node("/docs/spec.txt").is_some());
    assert!(fixture.db.get_node("/docs/stale.txt").is_some());
    assert_eq!(
        fixture
            .db
            .get_setting("native_latest_event_id_vol-main-1")
            .as_deref(),
        Some("ev-0")
    );

    // Mark dup.txt as clean SYNCED with its exact active revision_id so duplicate events stay replay-safe
    let dup_node = fixture.db.get_node("/dup.txt").unwrap();
    let dup_rev_1 = dup_node.revision_id.clone().unwrap();
    let dup_cache = fixture.cache_dir.join("dup.dat");
    fs::write(&dup_cache, b"dup-v1").unwrap();
    fixture.db.update_sync_status(
        "/dup.txt",
        SyncStatus::SYNCED,
        Some(dup_cache.to_str().unwrap()),
        None,
    );

    // Queue EVENT_UPDATE_CONTENT for dup.txt with SAME revision_id/size (replay/echo) -> must keep cache!
    {
        let mut st = server.state.lock().unwrap();
        let dup_json = st.link_to_json(&st.links[&dup_id]);
        st.latest_event_id = "ev-1".to_string();
        st.events = vec![json!({
            "ContextShareID": st.share_id,
            "EventID": "ev-1a",
            "EventType": 2,
            "CreateTime": 1_700_001_000.0,
            "Link": dup_json
        })];
    }
    engine1.poll_remote_changes();
    let dup_after_replay = fixture.db.get_node("/dup.txt").unwrap();
    assert_eq!(dup_after_replay.sync_status, SyncStatus::SYNCED);
    assert_eq!(
        dup_after_replay.revision_id.as_deref(),
        Some(dup_rev_1.as_str())
    );
    assert!(
        dup_cache.exists(),
        "Duplicate/same-revision event must not invalidate clean cache"
    );

    // 2. Simulate daemon restart: brand new NativeProtonClient + SyncEngine with cold in-memory node_cache!
    drop(engine1);
    drop(fuse1);
    let restarted_vault = Arc::new(
        SessionVault::new_with_backend(Some(vault_path), store, Arc::new(NoFallbackKeyProvider))
            .unwrap(),
    );
    let client2 = Arc::new(
        NativeProtonClient::new_with_vault(
            fixture.db.clone(),
            restarted_vault,
            Some(server.base_url.clone()),
        )
        .unwrap()
        .with_trusted_srp_keys(vec![trusted_pub]),
    );
    client2
        .http()
        .rate_limit_gate()
        .set_default_retry_after(Duration::from_millis(1));

    // Set conflict states BEFORE events arrive:
    // - /err_retry.txt in ERROR state (pending retry upload)
    // - /open_handle.txt SYNCED + open read handle
    let err_cache = fixture.cache_dir.join("err_retry.dat");
    fs::write(&err_cache, b"retry-local-unsynced").unwrap();
    fixture
        .db
        .mark_pending("/err_retry.txt", err_cache.to_str().unwrap(), Some(20))
        .unwrap();
    let err_node_before = fixture.db.get_node("/err_retry.txt").unwrap();
    assert!(fixture
        .db
        .mark_uploading(&err_node_before.cache_id, err_node_before.generation));
    fixture.db.mark_upload_error(
        &err_node_before.cache_id,
        err_node_before.generation,
        "Transient 503",
    );

    let open_cache = fixture.cache_dir.join("open_handle.dat");
    fs::write(&open_cache, b"open-remote").unwrap();
    fixture.db.update_sync_status(
        "/open_handle.txt",
        SyncStatus::SYNCED,
        Some(open_cache.to_str().unwrap()),
        None,
    );
    let open_node = fixture.db.get_node("/open_handle.txt").unwrap();
    let open_f = fs::File::open(&open_cache).unwrap();
    fixture.activity.open_handles.lock().unwrap().insert(
        999,
        support::OpenHandle {
            file: Some(open_f),
            path: "/open_handle.txt".to_string(),
            cache_id: open_node.cache_id.clone(),
            local_cache: open_cache.clone(),
            writable: false,
            wrote: false,
            remote_size: 0,
            stream_block_cache: Arc::new(std::sync::Mutex::new(None)),
        },
    );

    // While restarted (cold node_cache!), queue nested events inside /docs + conflict delete events:
    // - /docs/after_restart.txt created
    // - /docs/spec.txt renamed to /docs/spec-renamed.txt
    // - /err_retry.txt and /open_handle.txt remote delete events (both MUST be ignored!)
    {
        let mut st = server.state.lock().unwrap();
        let after_id = st.add_remote_file(&docs_id, "after_restart.txt", b"nested-after-restart");
        let after_json = st.link_to_json(&st.links[&after_id]);

        let (docs_uk, docs_hk) = st.unlock_folder(&docs_id);
        let addr_pass = st.address_key_passphrase.clone();
        let addr_key = st.address_key_armored.clone();
        let new_name_enc = Encryptor::encrypt_and_sign_text(
            "spec-renamed.txt",
            &docs_uk.armored_public,
            &addr_pass,
            &addr_key,
        )
        .unwrap();
        let new_hash = NameHasher::hash("spec-renamed.txt", &docs_hk).unwrap();
        {
            let spec_link = st.links.get_mut(&spec_id).unwrap();
            spec_link.name_enc = new_name_enc;
            spec_link.hash = new_hash;
        }
        let spec_json = st.link_to_json(&st.links[&spec_id]);

        st.latest_event_id = "ev-2".to_string();
        st.events = vec![
            json!({
                "ContextShareID": st.share_id,
                "EventID": "ev-2a",
                "EventType": 1,
                "CreateTime": 1_700_001_100.0,
                "Link": after_json
            }),
            json!({
                "ContextShareID": st.share_id,
                "EventID": "ev-2b",
                "EventType": 3,
                "CreateTime": 1_700_001_101.0,
                "Link": spec_json
            }),
            json!({
                "ContextShareID": st.share_id,
                "EventID": "ev-2c",
                "EventType": 0,
                "CreateTime": 1_700_001_102.0,
                "Link": { "LinkID": err_id }
            }),
            json!({
                "ContextShareID": st.share_id,
                "EventID": "ev-2d",
                "EventType": 0,
                "CreateTime": 1_700_001_103.0,
                "Link": { "LinkID": open_id }
            }),
        ];
        // Also simulate transient offline/500 failure first -> cursor must stay at ev-1!
        st.events_fail_remaining = 6;
    }

    let client2_dyn: Arc<dyn RemoteDrive> = Arc::clone(&client2) as Arc<dyn RemoteDrive>;
    let engine2 = SyncEngine::new(
        Arc::clone(&client2_dyn),
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        10,
        Arc::clone(&fixture.activity),
    );

    // Offline toggle skips without losing cursor ev-1
    engine2.set_offline_mode(true);
    engine2.poll_remote_changes();
    assert_eq!(engine2.status(), support::AppSyncStatus::OFFLINE);
    assert_eq!(
        fixture
            .db
            .get_setting("native_latest_event_id_vol-main-1")
            .as_deref(),
        Some("ev-1")
    );

    // Come back online -> transient 500 triggers fallback reconcile without advancing cursor past ev-2
    engine2.set_offline_mode(false);
    engine2.poll_remote_changes();
    assert_eq!(
        fixture
            .db
            .get_setting("native_latest_event_id_vol-main-1")
            .as_deref(),
        Some("ev-1")
    );

    // Next online poll applies ev-2 (unlocking /docs ancestor chain from cold node_cache!)
    engine2.poll_remote_changes();
    assert_eq!(
        fixture
            .db
            .get_setting("native_latest_event_id_vol-main-1")
            .as_deref(),
        Some("ev-2")
    );
    assert!(
        fixture.db.get_node("/docs/after_restart.txt").is_some(),
        "Nested subfolder create event must apply after daemon restart with cold node_cache"
    );
    assert!(fixture.db.get_node("/docs/spec.txt").is_none());
    assert!(fixture.db.get_node("/docs/spec-renamed.txt").is_some());
    // ERROR and open-handle nodes survived delete events
    assert_eq!(
        fixture.db.get_node("/err_retry.txt").unwrap().sync_status,
        SyncStatus::ERROR
    );
    assert_eq!(fs::read(&err_cache).unwrap(), b"retry-local-unsynced");
    assert!(fixture.db.get_node("/open_handle.txt").is_some());
    assert!(open_cache.exists());

    // Renamed nested file is directly downloadable through client2 without stale path error
    let dl_restart = fixture.root_path().join("dl_restart");
    assert!(client2.download_file("/my-files/docs/spec-renamed.txt", &dl_restart, "overwrite"));
    assert_eq!(
        fs::read(dl_restart.join("spec-renamed.txt")).unwrap(),
        b"spec-v1"
    );

    // 3. Repeated More=1 cursor must error cleanly (no infinite loop!)
    server.state.lock().unwrap().events_more_repeated_once = true;
    let poll_err = client2
        .poll_events(&fixture.db, &fixture.cache_dir, &fixture.activity)
        .unwrap()
        .unwrap_err();
    assert!(poll_err.contains("did not advance"), "got: {}", poll_err);

    // 4. Server Refresh=1 prunes /docs/stale.txt (removed directly on server) and picks up /docs/fresh.txt!
    {
        let mut st = server.state.lock().unwrap();
        st.links.remove(&stale_id);
        if let Some(kids) = st.children.get_mut(&docs_id) {
            kids.retain(|k| k != &stale_id);
        }
        st.add_remote_file(&docs_id, "fresh.txt", b"fresh-after-refresh");
        st.latest_event_id = "ev-3".to_string();
        st.events_refresh_once = true;
    }
    engine2.poll_remote_changes();
    assert_eq!(
        fixture
            .db
            .get_setting("native_latest_event_id_vol-main-1")
            .as_deref(),
        Some("ev-3")
    );
    assert!(
        fixture.db.get_node("/docs/stale.txt").is_none(),
        "Refresh=1 must re-reconcile previously bootstrapped /docs and remove stale entries"
    );
    assert!(fixture.db.get_node("/docs/fresh.txt").is_some());
}

#[test]
fn test_daemon_ipc_native_login_and_backend_config() {
    let fixture = TestFixture::new();
    let (_server, native_client) = new_client_and_server(&fixture, true);
    let client_arc: Arc<dyn RemoteDrive> = Arc::new(native_client);

    let cfg = Config {
        mount_point: fixture.mount_dir.to_string_lossy().to_string(),
        auto_mount_on_start: false,
        backend: "native".to_string(),
        ..Default::default()
    };

    let daemon = ProtonDriveDaemon::new_with_deps_and_activity(
        client_arc,
        fixture.db.clone(),
        cfg,
        fixture.cache_dir.clone(),
        fixture.socket_path.clone(),
        fixture.config_path.clone(),
        Arc::clone(&fixture.activity),
    )
    .unwrap();
    daemon.start().unwrap();
    let ipc = fixture.create_ipc_client();

    let st0 = ipc.send_command("status", json!({})).unwrap();
    assert_eq!(st0.get("backend").and_then(|v| v.as_str()), Some("native"));

    // Login without TOTP -> 2fa_required
    let r1 = ipc
        .send_command(
            "login",
            json!({"username": "alice@proton.me", "password": "super-secret-password"}),
        )
        .unwrap();
    assert_eq!(
        r1.get("status").and_then(|v| v.as_str()),
        Some("2fa_required")
    );

    // Login with TOTP -> ok
    let r2 = ipc
        .send_command(
            "login",
            json!({
                "username": "alice@proton.me",
                "password": "super-secret-password",
                "totp": "123456"
            }),
        )
        .unwrap();
    assert_eq!(r2.get("status").and_then(|v| v.as_str()), Some("ok"));

    // Wait briefly for trigger_status_refresh to update cached_status
    let mut authed = false;
    for _ in 0..40 {
        let st = ipc.send_command("status", json!({})).unwrap();
        if st.get("authenticated").and_then(|v| v.as_bool()) == Some(true)
            && st["quota"].get("total_bytes").and_then(|v| v.as_u64()) == Some(536_870_912_000)
        {
            authed = true;
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        authed,
        "Daemon status must reflect native authentication and quota"
    );

    // Backend config validation: legacy "cli" is retired, "native" succeeds
    let bad_backend = ipc
        .send_command("update-config", json!({"backend": "cli"}))
        .unwrap();
    assert_eq!(
        bad_backend.get("status").and_then(|v| v.as_str()),
        Some("error")
    );
    let ok_backend = ipc
        .send_command("update-config", json!({"backend": "native"}))
        .unwrap();
    assert_eq!(
        ok_backend.get("status").and_then(|v| v.as_str()),
        Some("ok")
    );
    assert_eq!(
        ok_backend["config"].get("backend").and_then(|v| v.as_str()),
        Some("native")
    );
    assert!(
        ok_backend.get("restart_required").is_none(),
        "Updating backend to active 'native' mode must not require restart"
    );

    daemon.stop();
}

#[test]
fn test_fuse_streaming_block_reads_cloud_only_and_caching() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // Build a deterministic 5.5 MiB payload spanning two 4 MiB blocks
    let total_size = (4 * 1024 * 1024) + (1536 * 1024);
    let mut payload = vec![0u8; total_size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 31 + (i >> 8)) & 0xFF) as u8;
    }

    let up_dir = fixture.root_path().join("up_stream");
    fs::create_dir_all(&up_dir).unwrap();
    let src_file = up_dir.join("big.bin");
    fs::write(&src_file, &payload).unwrap();
    assert!(client.upload_file(&src_file, "/my-files", "create-new-revision"));

    let client_arc: Arc<dyn RemoteDrive> = Arc::new(client);
    assert!(client_arc.supports_block_range_reads());

    let fuse = ProtonDriveFUSE::new(
        Arc::clone(&client_arc),
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        Some("/my-files"),
        Arc::clone(&fixture.activity),
    );
    fuse.reconcile_dir("/").expect("reconcile root directory");

    let node = fixture.db.get_node("/big.bin").unwrap();
    assert_eq!(node.sync_status, SyncStatus::CLOUD_ONLY);
    assert_eq!(node.size, total_size as i64);

    // Reset block download counter before opening read-only via FUSE
    server.state.lock().unwrap().block_download_calls = 0;

    let fh = fuse
        .open_file_handle("/big.bin", false)
        .expect("open_file_handle read-only on CLOUD_ONLY file");

    // 1. Opening read-only MUST NOT hydrate the whole file or download any block
    assert_eq!(
        server.state.lock().unwrap().block_download_calls,
        0,
        "Opening CLOUD_ONLY file read-only must not trigger full hydration"
    );
    let expected_cache_path = {
        let handles = fixture.activity.open_handles.lock().unwrap();
        let h = handles.get(&fh).unwrap();
        assert!(h.file.is_none(), "Streaming handle should not back to disk");
        h.local_cache.clone()
    };
    assert!(
        !expected_cache_path.exists(),
        "Local cache file must not be created on streaming open"
    );

    // 2. Read 64 KiB inside block 1 (past the 4 MiB boundary) -> downloads ONLY block 1
    let off1 = (4 * 1024 * 1024 + 128) as u64;
    let slice1 = fuse.read_from_handle(fh, off1, 64 * 1024).unwrap();
    assert_eq!(slice1, &payload[off1 as usize..off1 as usize + 64 * 1024]);
    assert_eq!(
        server.state.lock().unwrap().block_download_calls,
        1,
        "Streaming read in block 1 must download only block 1"
    );

    // 3. Second sequential read inside the same 4 MiB block hits the handle cache (0 new downloads)
    let off2 = (4 * 1024 * 1024 + 1024 * 1024) as u64;
    let slice2 = fuse.read_from_handle(fh, off2, 32 * 1024).unwrap();
    assert_eq!(slice2, &payload[off2 as usize..off2 as usize + 32 * 1024]);
    assert_eq!(
        server.state.lock().unwrap().block_download_calls,
        1,
        "Subsequent read in cached 4 MiB block must reuse handle cache"
    );

    // 4. Cross-boundary read spanning end of block 0 and start of block 1 returns exact bytes
    let cross_off = (4 * 1024 * 1024 - 2048) as u64;
    let cross_slice = fuse.read_from_handle(fh, cross_off, 4096).unwrap();
    assert_eq!(
        cross_slice,
        &payload[cross_off as usize..cross_off as usize + 4096]
    );
    assert!(
        !expected_cache_path.exists(),
        "Streaming reads must not materialize full local cache file"
    );

    // 5. Read past EOF returns empty Vec cleanly
    assert!(fuse
        .read_from_handle(fh, total_size as u64, 4096)
        .unwrap()
        .is_empty());

    // 6. Renaming the file while streaming handle is open updates handle.path for future reads
    assert!(fuse
        .rename_node("/", "big.bin", "/", "big-renamed.bin")
        .is_ok());
    let post_rename_slice = fuse.read_from_handle(fh, 100, 1024).unwrap();
    assert_eq!(post_rename_slice, &payload[100..1124]);

    // 7. flush, fsync, and release on streaming handle succeed; DB stays CLOUD_ONLY
    fuse.flush_handle(fh).unwrap();
    fuse.fsync_handle(fh, true).unwrap();
    fuse.release_handle(fh).unwrap();
    assert_eq!(
        fixture.db.get_node("/big-renamed.bin").unwrap().sync_status,
        SyncStatus::CLOUD_ONLY
    );
    assert!(!expected_cache_path.exists());

    // 8. Opening the same file writable MUST hydrate to local cache as SYNCED
    let rw_fh = fuse.open_file_handle("/big-renamed.bin", true).unwrap();
    {
        let handles = fixture.activity.open_handles.lock().unwrap();
        let h = handles.get(&rw_fh).unwrap();
        assert!(
            h.file.is_some(),
            "Writable open must hydrate onto local disk"
        );
    }
    assert!(expected_cache_path.exists());
    assert_eq!(
        fixture.db.get_node("/big-renamed.bin").unwrap().sync_status,
        SyncStatus::SYNCED
    );
    fuse.release_handle(rw_fh).unwrap();
}

#[test]
fn test_native_auth_storage_failure_and_locked_keyring_behavior() {
    let fixture = TestFixture::new();
    let (server, client, store) = new_client_and_server_with_store(&fixture, false);

    // Locked keyring blocks authentication persistence without creating disk fallback
    store.set_locked(true);
    let locked_err = client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap_err();
    assert!(
        locked_err.contains("Keyring locked"),
        "Expected locked keyring error, got: {}",
        locked_err
    );
    assert!(!client.check_auth_status().0);
    assert!(!fixture.root_path().join("session_vault.json").exists());

    // Unlocking allows authentication to persist into Secret Service
    store.set_locked(false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();
    assert!(client.check_auth_status().0);
    assert_eq!(store.secret_count(), 1);
    drop(server);
}

#[test]
fn test_native_client_interoperates_with_independent_gpg_keys() {
    const GPG_ECC_PASS: &str = "proton-fixture-pass";
    const GPG_ECC_SEC: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlIYEavuwJBYJKwYBBAHaRw8BAQdAkMzvk0DlcdqzqyD1zmHs03P2MaPVy77OHvRg\nijTzksf+BwMCrWPbfIJS52P/Lw70uiKAkcbT4GkG6QX+WK+PfuxHbr7LwL7dPJi+\nhNa6kMulivDs7JuqINjcshMaz4MkuVgK75tdfsvoAvuk6nouRsrDf7QgRml4dHVy\nZSBVc2VyIDxmaXh0dXJlQHByb3Rvbi5tZT6IkAQTFgoAOBYhBIf/Cp4tDQpE3UMf\nGCmiujd8wOLDBQJq+7AkAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJECmi\nujd8wOLD8bgBALqMKNyM/7KoA6Dp8pMxeG3AW1ZYSbubyDacSx9z8kW7APsF/dZL\nledoVIf9+OifnuiKDw4HvyA3jjPpcJMyNSDCBZyLBGr7sCYSCisGAQQBl1UBBQEB\nB0AgWJjKNHxmMaNubRuJTxegEKobedo6qlhpENi6VupwSAMBCAf+BwMCusvv00gf\nWrD/s6ebeGITazEMJFItx2tEXXF9gIBJGv/7mMNvx4OFii7FyS1woHW0bqTSiqr5\nVgidCXttoxffKhGCad03WtEv3KBinFBoM4h4BBgWCgAgFiEEh/8Kni0NCkTdQx8Y\nKaK6N3zA4sMFAmr7sCYCGwwACgkQKaK6N3zA4sOYegEA+YkLkiQmlz6kPeg1yHyn\new8WR87wyCcOj4JjhvcQgWABAMNiX08cuu0rxwTwefjo4wwLO6AFs0yofSt13Txu\nd0kE\n=hhb+\n-----END PGP PRIVATE KEY BLOCK-----\n";

    let fixture = TestFixture::new();
    let mut state = MockServerState::new_with_address_key(
        "fixture@proton.me",
        "super-secret-password",
        false,
        GPG_ECC_SEC.to_string(),
        GPG_ECC_PASS.to_string(),
    );
    let root_id = state.root_link_id.clone();
    state.add_remote_file(&root_id, "official.txt", b"hello-from-gpg-key-hierarchy");
    let srp_pub = state.srp_signing_pub.clone();
    let server = MockHttpServer::start(state);

    let store = Arc::new(InMemorySecretStore::new());
    let vault = Arc::new(
        SessionVault::new_with_backend(
            Some(fixture.root_path().join("session_vault.json")),
            store,
            Arc::new(NoFallbackKeyProvider),
        )
        .unwrap(),
    );
    let client = NativeProtonClient::new_with_vault(
        fixture.db.clone(),
        vault,
        Some(server.base_url.clone()),
    )
    .unwrap()
    .with_trusted_srp_keys(vec![srp_pub]);

    client
        .authenticate("fixture@proton.me", "super-secret-password", None)
        .unwrap();

    let listed = client.list_path("/").unwrap();
    assert!(listed.iter().any(|n| n.name == "official.txt"));

    let dl_dir = fixture.root_path().join("dl_gpg");
    assert!(client.download_file("/official.txt", &dl_dir, "overwrite"));
    assert_eq!(
        std::fs::read(dl_dir.join("official.txt")).unwrap(),
        b"hello-from-gpg-key-hierarchy"
    );

    let up_file = fixture.root_path().join("uploaded_with_gpg.bin");
    std::fs::write(&up_file, b"uploaded-via-independent-gpg-address-key").unwrap();
    assert!(client.upload_file(&up_file, "/", "overwrite"));

    let listed_after = client.list_path("/").unwrap();
    assert!(listed_after
        .iter()
        .any(|n| n.name == "uploaded_with_gpg.bin"));

    let dl_dir2 = fixture.root_path().join("dl_gpg_2");
    assert!(client.download_file("/uploaded_with_gpg.bin", &dl_dir2, "overwrite"));
    assert_eq!(
        std::fs::read(dl_dir2.join("uploaded_with_gpg.bin")).unwrap(),
        b"uploaded-via-independent-gpg-address-key"
    );
}

// ============================================================================
// Task 5 — Transport Slice Tests (429 Retry-After, 401 Refresh, Bounded Retries)
// ============================================================================

#[test]
fn test_native_transport_429_retry_after_http_date_and_bounded_retries() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // 1. Verify Proton canonical headers & HTTP-date Retry-After recovery within retry budget
    {
        let mut st = server.state.lock().unwrap();
        st.force_429_remaining = 2;
        // Past HTTP-date parses as 0s wait while still exercising HTTP-date header path
        st.force_429_retry_after = Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string());
        st.captured_headers.clear();
        st.authed_request_calls = 0;
    }

    let vols = DriveEndpoints::list_volumes(client.http())
        .expect("Should recover after 2x 429 within default max_retry_count");
    assert_eq!(vols.volumes.len(), 1);
    {
        let st = server.state.lock().unwrap();
        assert_eq!(st.authed_request_calls, 3);
        let (_, _, hdrs) = st.captured_headers.last().unwrap();
        assert_eq!(
            hdrs.get("accept").map(String::as_str),
            Some(PROTON_ACCEPT_HEADER)
        );
        assert_eq!(
            hdrs.get("x-pm-appversion").map(String::as_str),
            Some(DEFAULT_APP_VERSION)
        );
        assert_eq!(
            hdrs.get("x-pm-locale").map(String::as_str),
            Some(DEFAULT_LOCALE)
        );
        assert_eq!(
            hdrs.get("user-agent").map(String::as_str),
            Some(DEFAULT_USER_AGENT)
        );
        assert_eq!(
            hdrs.get("x-pm-uid").map(String::as_str),
            Some("uid-native-1")
        );
    }

    // 2. Verify persistent 429 is strictly bounded by DEFAULT_MAX_RETRY_COUNT (6 attempts)
    {
        let mut st = server.state.lock().unwrap();
        st.force_429_remaining = 20;
        st.force_429_retry_after = Some("0".to_string());
        st.authed_request_calls = 0;
    }

    let err = DriveEndpoints::list_volumes(client.http())
        .expect_err("Persistent 429 must fail after bounded retries");
    assert!(matches!(err, HttpError::Status { status: 429, .. }));
    assert_eq!(server.state.lock().unwrap().authed_request_calls, 6);

    // 3. Verify transient 503 recovery uses exponential backoff and resets streak on success
    assert!(DEFAULT_APP_VERSION.starts_with("external-drive-"));
    {
        let mut st = server.state.lock().unwrap();
        st.force_429_remaining = 0;
        st.force_429_retry_after = None;
        st.force_503_remaining = 2;
        st.authed_request_calls = 0;
    }
    client.http().rate_limit_gate().clear();
    let vols_503 = DriveEndpoints::list_volumes(client.http())
        .expect("Should recover after 2x 503 via exponential backoff");
    assert_eq!(vols_503.volumes.len(), 1);
    assert_eq!(server.state.lock().unwrap().authed_request_calls, 3);
    assert_eq!(
        client
            .http()
            .rate_limit_gate()
            .consecutive_failures(RateLimitFamily::Metadata),
        0
    );

    // 4. Verify RateLimitGate::wait_if_needed rechecks extended deadlines
    let gate = RateLimitGate::new();
    gate.record_rate_limited(
        Some(Duration::from_millis(25)),
        RateLimitFamily::Metadata,
        "test",
    );
    assert!(gate.blocked_until(RateLimitFamily::Metadata).is_some());
    gate.wait_if_needed(RateLimitFamily::Metadata);
    assert!(gate.blocked_until(RateLimitFamily::Metadata).unwrap() <= std::time::Instant::now());
}

#[test]
fn test_native_transport_401_refresh_rotation_and_transient_error_preserves_vault() {
    let fixture = TestFixture::new();
    let (server, client, store) = new_client_and_server_with_store(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // 1. 401 rotates both access & refresh tokens and persists them to SessionVault
    {
        let mut st = server.state.lock().unwrap();
        st.force_401_once = true;
    }
    let quota = client.get_storage_quota();
    assert_eq!(quota.used_bytes, 1_073_741_824);
    assert_eq!(quota.total_bytes, 536_870_912_000);
    let tokens_after_1 = client.vault().http_tokens().unwrap();
    assert_eq!(
        tokens_after_1.access_token.as_str(),
        "access-token-refreshed-1"
    );
    assert_eq!(
        tokens_after_1.refresh_token.as_str(),
        "refresh-token-refreshed-1"
    );

    // Reloading SessionVault from Secret Service must observe the rotated refresh token
    let reloaded = SessionVault::new_with_backend(
        Some(fixture.root_path().join("session_vault.json")),
        store,
        Arc::new(NoFallbackKeyProvider),
    )
    .unwrap();
    assert_eq!(
        reloaded.http_tokens().unwrap().refresh_token.as_str(),
        "refresh-token-refreshed-1"
    );

    // 2. If /auth/v4/refresh hits a transient 500 or 429, SessionVault must NOT be wiped
    {
        let mut st = server.state.lock().unwrap();
        st.force_401_once = true;
        st.refresh_override_status = Some(500);
        st.refresh_calls = 0;
    }
    let err_500 = DriveEndpoints::list_volumes(client.http()).unwrap_err();
    assert!(matches!(err_500, HttpError::Status { status: 500, .. }));
    assert!(
        client.check_auth_status().0,
        "Transient 500 during refresh must preserve stored session"
    );

    // 3. Persistent 401 after successful refresh is bounded to 1 refresh attempt
    {
        let mut st = server.state.lock().unwrap();
        st.refresh_override_status = None;
        st.force_401_always = true;
        st.refresh_calls = 0;
        st.authed_request_calls = 0;
    }
    let err_401 = DriveEndpoints::list_volumes(client.http()).unwrap_err();
    assert!(matches!(err_401, HttpError::Unauthorized(_)));
    {
        let st = server.state.lock().unwrap();
        assert_eq!(st.refresh_calls, 1);
        assert_eq!(st.authed_request_calls, 2);
    }

    // 4. Genuine 401 rejection on /auth/v4/refresh clears dead session during quota refresh
    {
        let mut st = server.state.lock().unwrap();
        st.force_401_always = false;
        st.force_401_once = true;
        st.refresh_override_status = Some(401);
    }
    let fallback_quota = client.get_storage_quota();
    assert_eq!(fallback_quota.used_bytes, 0);
    assert!(!client.check_auth_status().0);
}

// ============================================================================
// Task 5 — Listing & Read Slice Tests (Fixtures, Pagination, Key Hierarchy, Quota)
// ============================================================================

#[test]
fn test_native_read_official_response_fixtures_bootstrap_quota_and_null_fields() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);

    // Simulate real Proton response variations seen in PDClient:
    // - null UsedDriveSpace/MaxDriveSpace falling back to UsedSpace/MaxSpace
    // - null MIMEType, SignatureEmail, NameSignatureEmail on links
    // - nested key hierarchy (Root -> Docs -> official.txt)
    {
        let mut st = server.state.lock().unwrap();
        st.null_drive_quota_fields = true;
        st.used_space = 250_000_000;
        st.max_space = 5_000_000_000;
        st.emit_null_link_fields = true;

        let root_id = st.root_link_id.clone();
        let docs_id = st.add_remote_folder(&root_id, "OfficialDocs");
        st.add_remote_file(
            &docs_id,
            ".aider.conf.yml",
            b"model: gemini-pro\nauto-commits: false\n",
        );
    }

    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    let quota = client.get_storage_quota();
    assert_eq!(quota.used_bytes, 250_000_000);
    assert_eq!(quota.total_bytes, 5_000_000_000);
    assert!((quota.percent_used - 5.0).abs() < 1e-6);

    let root_nodes = client.list_path("/my-files").expect("List root");
    assert_eq!(root_nodes.len(), 1);
    assert_eq!(root_nodes[0].name, "OfficialDocs");
    assert_eq!(root_nodes[0].node_type, "folder");

    let docs_nodes = client
        .list_path("/my-files/OfficialDocs")
        .expect("List OfficialDocs");
    assert_eq!(docs_nodes.len(), 1);
    assert_eq!(docs_nodes[0].name, ".aider.conf.yml");
    assert_eq!(docs_nodes[0].node_type, "file");
    assert_eq!(docs_nodes[0].size, 38);

    let dl_dir = fixture.root_path().join("official_read");
    assert!(client.download_file(
        "/my-files/OfficialDocs/.aider.conf.yml",
        &dl_dir,
        "overwrite"
    ));
    assert_eq!(
        std::fs::read(dl_dir.join(".aider.conf.yml")).unwrap(),
        b"model: gemini-pro\nauto-commits: false\n"
    );
    let range = client
        .read_block_range("/my-files/OfficialDocs/.aider.conf.yml", 7, 10)
        .unwrap()
        .unwrap();
    assert_eq!(range, b"gemini-pro");
}

#[test]
fn test_native_listing_pagination_dedup_anchor_guard_and_stale_child_eviction() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    let trashed_id;
    let draft_id;
    let removable_id;
    {
        let mut st = server.state.lock().unwrap();
        st.children_page_size = 60;
        st.overlap_pagination = true;
        let root_id = st.root_link_id.clone();

        let (parent_uk, parent_hk) = st.unlock_folder(&root_id);
        let template_creds = Encryptor::generate_node_keys(
            &st.address_key_passphrase,
            &st.address_key_armored,
            &parent_uk.armored_public,
        )
        .unwrap();
        let addr_email = st.address_email.clone();
        let addr_pass = st.address_key_passphrase.clone();
        let addr_key = st.address_key_armored.clone();
        for i in 0..155 {
            let name = format!("item-{:03}.txt", i);
            let name_enc = Encryptor::encrypt_and_sign_text(
                &name,
                &parent_uk.armored_public,
                &addr_pass,
                &addr_key,
            )
            .unwrap();
            let hash = NameHasher::hash(&name, &parent_hk).unwrap();
            let lid = st.next_id("file");
            let rev_id = st.next_id("rev");
            let link = ServerLink {
                link_id: lid.clone(),
                parent_link_id: Some(root_id.clone()),
                link_type: 2,
                name_enc,
                hash,
                state: 1,
                size: 1,
                node_key: template_creds.key.clone(),
                node_passphrase: template_creds.passphrase.clone(),
                node_passphrase_sig: template_creds.signature.clone(),
                signature_email: addr_email.clone(),
                node_hash_key: None,
                content_key_packet: None,
                content_key_packet_sig: None,
                active_revision_id: Some(rev_id),
                manifest_signature: None,
                xattr: None,
                modify_time: 1_700_000_200.0,
                trashed: None,
            };
            st.links.insert(lid.clone(), link);
            st.children.entry(root_id.clone()).or_default().push(lid);
        }
        trashed_id = st.add_remote_file(&root_id, "trashed.txt", b"old");
        st.links.get_mut(&trashed_id).unwrap().trashed = Some(1_700_000_123.0);
        draft_id = st.add_remote_file(&root_id, "draft.txt", b"partial");
        st.links.get_mut(&draft_id).unwrap().state = 0;
        removable_id = st.add_remote_file(&root_id, "ephemeral.txt", b"bye");
    }

    let listed = client.list_path("/my-files").expect("Paginated listing");
    assert_eq!(
        listed.len(),
        156,
        "155 numbered + ephemeral.txt (excluding trashed/draft)"
    );
    assert!(!listed
        .iter()
        .any(|n| n.name == "trashed.txt" || n.name == "draft.txt"));
    {
        let st = server.state.lock().unwrap();
        assert_eq!(st.list_children_calls, 3);
        // [1] from root link bootstrap, then [150, 8] for the 158 deduplicated child IDs
        assert_eq!(st.fetch_metadata_batch_sizes, vec![1, 150, 8]);
    }

    // Remove ephemeral.txt remotely and verify stale path is evicted from client cache
    {
        let mut st = server.state.lock().unwrap();
        let root_id = st.root_link_id.clone();
        st.links.remove(&removable_id);
        st.children
            .get_mut(&root_id)
            .unwrap()
            .retain(|id| id != &removable_id);
    }
    let listed_after = client.list_path("/my-files").expect("Re-list after delete");
    assert_eq!(listed_after.len(), 155);
    assert!(!listed_after.iter().any(|n| n.name == "ephemeral.txt"));
    let dl_dir = fixture.root_path().join("evict_check");
    assert!(
        !client.download_file("/my-files/ephemeral.txt", &dl_dir, "overwrite"),
        "Evicted child must not remain resolvable in links_by_path"
    );

    // Repeated anchor with More=true must fail cleanly instead of infinite-looping
    server.state.lock().unwrap().force_repeated_anchor = true;
    let anchor_err = client
        .list_path("/my-files")
        .expect_err("Repeated anchor must fail instead of looping");
    assert!(anchor_err.contains("anchor did not advance"));

    // Missing anchor with More=true must also fail cleanly
    {
        let mut st = server.state.lock().unwrap();
        st.force_repeated_anchor = false;
        st.force_missing_anchor = true;
    }
    let missing_err = client
        .list_path("/my-files")
        .expect_err("Missing anchor with More=true must fail");
    assert!(missing_err.contains("without an AnchorID"));
}

#[test]
fn test_native_browser_sso_session_fork_login_and_vault_persistence() {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

    let fixture = TestFixture::new();
    let (server, client, store) = new_client_and_server_with_store(&fixture, false);
    {
        let mut st = server.state.lock().unwrap();
        let root_id = st.root_link_id.clone();
        st.add_remote_file(&root_id, "sso-file.txt", b"hello-from-browser-sso");
        st.fork_poll_pending_remaining = 1;
    }

    let challenge = client
        .start_browser_login(Some("https://account.proton.me"))
        .expect("Start browser SSO session fork");
    assert_eq!(challenge.user_code, "ABCD2345");
    assert!(challenge
        .login_url
        .starts_with("https://account.proton.me/desktop/login?app=drive&pv=3#payload="));

    // Extract the 32-byte key from the fragment payload (mirrors account.proton.me desktop fork)
    let (_, fragment_payload) = challenge.login_url.split_once("#payload=").unwrap();
    let decoded_payload: String =
        url::form_urlencoded::parse(format!("p={}", fragment_payload).as_bytes())
            .find(|(k, _)| k == "p")
            .map(|(_, v)| v.into_owned())
            .unwrap();
    let parts: Vec<&str> = decoded_payload.split(':').collect();
    assert_eq!(parts[0], "0");
    assert_eq!(parts[1], "ABCD2345");
    assert_eq!(parts[3], "cli-drive");
    let raw_key = BASE64.decode(parts[2]).unwrap();
    assert_eq!(raw_key.len(), 32);

    // First poll returns pending (422 -> Ok(None))
    assert!(
        client
            .poll_browser_login_once(&challenge)
            .unwrap()
            .is_none(),
        "Pending fork poll must return Ok(None)"
    );

    // Derive the account's salted keyPassword and encrypt it using pv=3 AES-256-GCM (12-byte IV, AAD="fork")
    let key_salt = server.state.lock().unwrap().key_salt_b64.clone();
    let key_pass = derive_key_passphrase("super-secret-password", &key_salt).unwrap();
    let json_payload = serde_json::json!({
        "type": "default",
        "keyPassword": key_pass.as_str()
    })
    .to_string();
    let iv = [0x5Au8; 12];
    let unbound = UnboundKey::new(&AES_256_GCM, &raw_key).unwrap();
    let aead_key = LessSafeKey::new(unbound);
    let mut sealed = json_payload.into_bytes();
    aead_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(b"fork"),
            &mut sealed,
        )
        .unwrap();
    let mut blob = iv.to_vec();
    blob.extend_from_slice(&sealed);
    server.state.lock().unwrap().fork_encrypted_payload = Some(BASE64.encode(blob));

    // Second poll completes authentication, unlocks user/address keys, and persists SessionVault
    let msg = client
        .poll_browser_login_once(&challenge)
        .unwrap()
        .expect("Completed browser fork must return auth message");
    assert!(msg.contains("alice@proton.me"));
    assert!(client.check_auth_status().0);
    assert_eq!(store.secret_count(), 1);

    let nodes = client.list_path("/my-files").expect("List via browser SSO");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "sso-file.txt");

    let dl_dir = fixture.root_path().join("sso_dl");
    assert!(client.download_file("/my-files/sso-file.txt", &dl_dir, "overwrite"));
    assert_eq!(
        std::fs::read(dl_dir.join("sso-file.txt")).unwrap(),
        b"hello-from-browser-sso"
    );
}

#[test]
#[ignore = "Requires live disposable Proton Drive account (browser SSO or credentials)"]
fn test_live_disposable_account_authenticated_read() {
    let _ = env_logger::builder().is_test(true).try_init();
    let fixture = TestFixture::new();
    let store = Arc::new(InMemorySecretStore::new());
    let vault = Arc::new(
        SessionVault::new_with_backend(
            Some(fixture.root_path().join("live_session_vault.json")),
            store,
            Arc::new(NoFallbackKeyProvider),
        )
        .unwrap(),
    );
    let client = NativeProtonClient::new_with_vault(fixture.db.clone(), vault, None).unwrap();

    let use_browser = std::env::var("PROTON_TEST_BROWSER_LOGIN").is_ok()
        || std::env::var("PROTON_TEST_USERNAME").is_err();

    let auth_msg = if use_browser {
        client
            .authenticate_via_browser(Duration::from_secs(300), |url, code| {
                println!("LIVE_LOGIN_URL: {}", url);
                println!("LIVE_USER_CODE: {}", code);
                println!("Open the URL above in your browser and confirm sign-in (waiting up to 300s)...");
                let _ = std::process::Command::new("xdg-open").arg(url).spawn();
            })
            .expect("Live browser SSO disposable account authentication")
    } else {
        let username = std::env::var("PROTON_TEST_USERNAME")
            .expect("Set PROTON_TEST_USERNAME for live disposable account check");
        let password = std::env::var("PROTON_TEST_PASSWORD")
            .expect("Set PROTON_TEST_PASSWORD for live disposable account check");
        let totp = std::env::var("PROTON_TEST_TOTP").ok();
        client
            .authenticate(&username, &password, totp.as_deref())
            .expect("Live disposable account authentication")
    };
    println!("LIVE_AUTH: {}", auth_msg);

    let quota = client.get_storage_quota();
    println!(
        "LIVE_QUOTA: used={} total={} percent={:.2}",
        quota.used_bytes, quota.total_bytes, quota.percent_used
    );
    assert!(
        quota.total_bytes > 0,
        "Expected non-zero live storage quota"
    );

    let root_nodes = client
        .list_path("/my-files")
        .expect("Live /my-files listing");
    println!("LIVE_ROOT_COUNT: {}", root_nodes.len());
    for node in &root_nodes {
        println!(
            "LIVE_NODE: name={} type={} size={}",
            node.name, node.node_type, node.size
        );
    }

    let target_name = std::env::var("PROTON_TEST_READ_FILE").ok().or_else(|| {
        root_nodes
            .iter()
            .find(|n| n.node_type == "file")
            .map(|n| n.name.clone())
    });
    if let Some(name) = target_name {
        let dl_dir = fixture.root_path().join("live_download");
        let remote_path = format!("/my-files/{}", name);
        client
            .download_file_checked(&remote_path, &dl_dir, "overwrite")
            .unwrap_or_else(|e| panic!("Failed downloading live file {}: {}", remote_path, e));
        let bytes = std::fs::read(dl_dir.join(&name)).unwrap();
        let sha = hex::encode(sha256_bytes(&bytes));
        println!(
            "LIVE_READ: path={} bytes={} sha256={}",
            remote_path,
            bytes.len(),
            sha
        );
    }
}

// ============================================================================
// Task 6 — Transfer Interoperability, Integrity, Boundaries & Recovery Tests
// ============================================================================

#[test]
fn test_native_transfer_download_integrity_and_signature_validation() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    let payload = b"official-client-file-bytes-0123456789abcdef";
    let file_id = {
        let mut st = server.state.lock().unwrap();
        let root_id = st.root_link_id.clone();
        st.add_remote_file_official_style(&root_id, "official-doc.bin", payload)
    };

    let dl_dir = fixture.root_path().join("dl_integrity");
    fs::create_dir_all(&dl_dir).unwrap();

    // 1. Valid official-style download succeeds and matches plaintext
    client
        .download_file_checked("/my-files/official-doc.bin", &dl_dir, "overwrite")
        .expect("Valid official-style download must succeed");
    assert_eq!(fs::read(dl_dir.join("official-doc.bin")).unwrap(), payload);

    let rev_id = server
        .state
        .lock()
        .unwrap()
        .links
        .get(&file_id)
        .unwrap()
        .active_revision_id
        .clone()
        .unwrap();

    // Helper: write sentinel into target and verify failed downloads preserve it and clean temps
    let target_file = dl_dir.join("official-doc.bin");

    // 2. Tampered block SHA-256 hash rejects download and preserves existing local file
    let orig_hash = {
        let mut st = server.state.lock().unwrap();
        let blk = &mut st.revision_blocks.get_mut(&rev_id).unwrap()[0];
        let h = blk.hash.clone();
        blk.hash = BASE64.encode([0xAAu8; 32]);
        h
    };
    fs::write(&target_file, b"preserve-me").unwrap();
    let err = client
        .download_file_checked("/my-files/official-doc.bin", &dl_dir, "overwrite")
        .unwrap_err();
    assert!(err.contains("SHA-256 mismatch"), "got: {}", err);
    assert_eq!(fs::read(&target_file).unwrap(), b"preserve-me");
    server
        .state
        .lock()
        .unwrap()
        .revision_blocks
        .get_mut(&rev_id)
        .unwrap()[0]
        .hash = orig_hash;

    // 3. Missing (empty) block SHA-256 hash is rejected
    let orig_hash2 = {
        let mut st = server.state.lock().unwrap();
        let blk = &mut st.revision_blocks.get_mut(&rev_id).unwrap()[0];
        let h = blk.hash.clone();
        blk.hash = String::new();
        h
    };
    let err = client
        .download_file_checked("/my-files/official-doc.bin", &dl_dir, "overwrite")
        .unwrap_err();
    assert!(err.contains("missing SHA-256"), "got: {}", err);
    server
        .state
        .lock()
        .unwrap()
        .revision_blocks
        .get_mut(&rev_id)
        .unwrap()[0]
        .hash = orig_hash2;

    // 4. Tampered block EncSignature is rejected
    let other_key = DriveKey::generate("Mallory", "mallory@proton.me", "pass").unwrap();
    let other_unlocked = DriveKey::unlock(&other_key, "pass").unwrap();
    let file_pub = {
        let st = server.state.lock().unwrap();
        DriveKey::public_key_armored(&st.links.get(&file_id).unwrap().node_key).unwrap()
    };
    let (_, forged_enc_sig) = Encryptor::encrypt_block_with_session_key(
        payload,
        &neutron_drive_daemon::native::crypto::SessionKey::generate().unwrap(),
        &other_unlocked,
        &file_pub,
    )
    .unwrap();
    let orig_enc_sig = {
        let mut st = server.state.lock().unwrap();
        let blk = &mut st.revision_blocks.get_mut(&rev_id).unwrap()[0];
        let s = blk.enc_signature.clone();
        blk.enc_signature = forged_enc_sig;
        s
    };
    let err = client
        .download_file_checked("/my-files/official-doc.bin", &dl_dir, "overwrite")
        .unwrap_err();
    assert!(
        err.contains("signature verification failed"),
        "Expected block signature failure, got: {}",
        err
    );
    server
        .state
        .lock()
        .unwrap()
        .revision_blocks
        .get_mut(&rev_id)
        .unwrap()[0]
        .enc_signature = orig_enc_sig;

    // 5. Tampered ManifestSignature is rejected
    let forged_manifest =
        DriveCrypto::sign_bytes_armored(b"wrong-manifest", None, &other_key, "pass").unwrap();
    let orig_manifest = {
        let mut st = server.state.lock().unwrap();
        let link = st.links.get_mut(&file_id).unwrap();
        let m = link.manifest_signature.clone();
        link.manifest_signature = Some(forged_manifest);
        m
    };
    let err = client
        .download_file_checked("/my-files/official-doc.bin", &dl_dir, "overwrite")
        .unwrap_err();
    assert!(
        err.contains("Signature verification failed"),
        "Expected manifest signature failure, got: {}",
        err
    );
    server
        .state
        .lock()
        .unwrap()
        .links
        .get_mut(&file_id)
        .unwrap()
        .manifest_signature = orig_manifest;

    // 6. Tampered XAttr SHA-1 digest is rejected
    let orig_xattr = {
        let mut st = server.state.lock().unwrap();
        let bad_xattr = ExtendedAttributes::new(
            Some("2026-11-16T12:00:00Z".to_string()),
            Some(payload.len() as i64),
            Some(vec![payload.len()]),
            Some("0000000000000000000000000000000000000000".to_string()),
        );
        let bad_xattr_enc = Encryptor::encrypt_and_sign_bytes(
            &bad_xattr.encoded().unwrap(),
            &file_pub,
            &st.address_key_passphrase,
            &st.address_key_armored,
            true,
        )
        .unwrap();
        let link = st.links.get_mut(&file_id).unwrap();
        let x = link.xattr.clone();
        link.xattr = Some(bad_xattr_enc);
        x
    };
    let err = client
        .download_file_checked("/my-files/official-doc.bin", &dl_dir, "overwrite")
        .unwrap_err();
    assert!(err.contains("SHA-1 mismatch"), "got: {}", err);
    server
        .state
        .lock()
        .unwrap()
        .links
        .get_mut(&file_id)
        .unwrap()
        .xattr = orig_xattr;

    // 7. Tampered ContentKeyPacketSignature is rejected (clear cache so metadata re-fetches)
    let forged_kp_sig =
        DriveCrypto::sign_bytes_armored(b"forged-sk", None, &other_key, "pass").unwrap();
    {
        let mut st = server.state.lock().unwrap();
        st.links.get_mut(&file_id).unwrap().content_key_packet_sig = Some(forged_kp_sig);
    }
    client.list_path("/my-files").unwrap();
    let err = client
        .download_file_checked("/my-files/official-doc.bin", &dl_dir, "overwrite")
        .unwrap_err();
    assert!(
        err.contains("ContentKeyPacket signature verification failed"),
        "got: {}",
        err
    );
    assert_eq!(fs::read(&target_file).unwrap(), b"preserve-me");
}

#[test]
fn test_native_transfer_empty_files_and_block_boundaries() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // 1. Official-style 0-byte file (0 blocks) downloads cleanly and supports empty range reads
    {
        let mut st = server.state.lock().unwrap();
        let root_id = st.root_link_id.clone();
        st.add_remote_file_official_style(&root_id, "official-empty.txt", b"");
    }
    let dl_dir = fixture.root_path().join("dl_boundaries");
    fs::create_dir_all(&dl_dir).unwrap();
    client
        .download_file_checked("/my-files/official-empty.txt", &dl_dir, "overwrite")
        .expect("Official empty file download must succeed");
    assert_eq!(fs::read(dl_dir.join("official-empty.txt")).unwrap(), b"");
    assert!(client
        .read_block_range("/my-files/official-empty.txt", 0, 64)
        .unwrap()
        .unwrap()
        .is_empty());

    // 2. Native upload of 0-byte file must NOT call /drive/blocks and must roundtrip cleanly
    let up_dir = fixture.root_path().join("up_boundaries");
    fs::create_dir_all(&up_dir).unwrap();
    let empty_src = up_dir.join("native-empty.bin");
    fs::write(&empty_src, b"").unwrap();
    let blocks_before = server.state.lock().unwrap().new_blocks_calls;
    assert!(client.upload_file(&empty_src, "/my-files", "create-new-revision"));
    assert_eq!(
        server.state.lock().unwrap().new_blocks_calls,
        blocks_before,
        "0-byte upload must not request block upload links"
    );
    client
        .download_file_checked("/my-files/native-empty.bin", &dl_dir, "overwrite")
        .expect("Native empty file download must succeed");
    assert_eq!(fs::read(dl_dir.join("native-empty.bin")).unwrap(), b"");

    // 3. Exact block boundary sizes: BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 1
    let boundary_cases = [
        ("boundary_minus1.bin", BLOCK_SIZE - 1, 1usize),
        ("boundary_exact.bin", BLOCK_SIZE, 1usize),
        ("boundary_plus1.bin", BLOCK_SIZE + 1, 2usize),
    ];
    for (fname, len, expected_blocks) in boundary_cases {
        let data: Vec<u8> = (0..len)
            .map(|i| ((i * 17 + (i >> 12)) & 0xFF) as u8)
            .collect();
        let src = up_dir.join(fname);
        fs::write(&src, &data).unwrap();
        assert!(
            client.upload_file(&src, "/my-files", "create-new-revision"),
            "Upload failed for {}",
            fname
        );

        let rev_id = {
            let listed = client.list_path("/my-files").unwrap();
            let entry = listed.iter().find(|n| n.name == fname).unwrap();
            assert_eq!(entry.size as usize, len);
            let uid = entry.uid.as_ref().unwrap().clone();
            let st = server.state.lock().unwrap();
            st.links
                .get(&uid)
                .unwrap()
                .active_revision_id
                .clone()
                .unwrap()
        };
        assert_eq!(
            server
                .state
                .lock()
                .unwrap()
                .revision_blocks
                .get(&rev_id)
                .unwrap()
                .len(),
            expected_blocks,
            "Unexpected block count for {}",
            fname
        );

        let remote_path = format!("/my-files/{}", fname);
        client
            .download_file_checked(&remote_path, &dl_dir, "overwrite")
            .unwrap_or_else(|e| panic!("Download failed for {}: {}", fname, e));
        let downloaded = fs::read(dl_dir.join(fname)).unwrap();
        assert_eq!(sha256_bytes(&downloaded), sha256_bytes(&data));
    }

    // 4. Cross-boundary range read on BLOCK_SIZE + 1 file reads tail of block 1 + 1 byte of block 2
    let cross = client
        .read_block_range("/my-files/boundary_plus1.bin", (BLOCK_SIZE - 4) as u64, 16)
        .unwrap()
        .unwrap();
    assert_eq!(cross.len(), 5);
}

#[test]
fn test_native_transfer_new_file_upload_and_revision_replacement() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // Exercise BareURL + Token fallback in ContentUploadLink as well
    server.state.lock().unwrap().emit_bare_upload_urls = true;

    let up_dir = fixture.root_path().join("up_rev");
    fs::create_dir_all(&up_dir).unwrap();
    let src = up_dir.join("mutable.bin");

    // 1. Initial upload (multi-block: 4 MiB + 128 KiB)
    let v1: Vec<u8> = (0..(BLOCK_SIZE + 128 * 1024))
        .map(|i| ((i * 7 + 3) & 0xFF) as u8)
        .collect();
    fs::write(&src, &v1).unwrap();
    assert!(client.upload_file(&src, "/my-files", "create-new-revision"));

    let listed_v1 = client.list_path("/my-files").unwrap();
    assert_eq!(listed_v1.len(), 1);
    let file_id = listed_v1[0].uid.clone().unwrap();
    assert_eq!(listed_v1[0].size as usize, v1.len());

    // Independently verify ContentKeyPacketSignature is signed by file's NodeKey (official spec!)
    let rev_v1 = {
        let st = server.state.lock().unwrap();
        let link = st.links.get(&file_id).unwrap();
        let rev_id = link.active_revision_id.clone().unwrap();
        let kp_bytes = BASE64
            .decode(link.content_key_packet.as_deref().unwrap())
            .unwrap();
        let share_pass = Decryptor::decrypt_and_verify_share_passphrase(
            &st.share_passphrase_enc,
            &st.share_passphrase_sig,
            std::slice::from_ref(&st.address_unlocked_pub),
            &[DriveKey::unlock(&st.address_key_armored, &st.address_key_passphrase).unwrap()],
        )
        .unwrap();
        let share_uk = DriveKey::unlock(&st.share_key_armored, share_pass.value()).unwrap();
        let root_link = st.links.get(&st.root_link_id).unwrap();
        let root_pp = Decryptor::decrypt_and_verify_node_passphrase(
            &root_link.node_passphrase,
            &root_link.node_passphrase_sig,
            std::slice::from_ref(&st.address_unlocked_pub),
            std::slice::from_ref(&share_uk),
        )
        .unwrap();
        let root_uk = DriveKey::unlock(&root_link.node_key, root_pp.value()).unwrap();
        let file_pp = Decryptor::decrypt_and_verify_node_passphrase(
            &link.node_passphrase,
            &link.node_passphrase_sig,
            std::slice::from_ref(&st.address_unlocked_pub),
            std::slice::from_ref(&root_uk),
        )
        .unwrap();
        let file_uk = DriveKey::unlock(&link.node_key, file_pp.value()).unwrap();
        let verified_kp = Decryptor::decrypt_and_verify_content_key_packet(
            &kp_bytes,
            &file_uk,
            link.content_key_packet_sig.as_deref(),
            std::slice::from_ref(&file_uk.armored_public),
        )
        .unwrap();
        assert!(
            verified_kp.is_verified(),
            "ContentKeyPacketSignature must verify with file NodeKey"
        );
        rev_id
    };

    // 2. Replace with v2 (smaller payload) using create-new-revision -> must keep same link_id, new revision_id
    let v2 = b"replacement-revision-v2-smaller-content".to_vec();
    fs::write(&src, &v2).unwrap();
    assert!(client.upload_file(&src, "/my-files", "create-new-revision"));

    let st_snap = server.state.lock().unwrap();
    assert_eq!(st_snap.create_file_calls, 1);
    assert_eq!(st_snap.create_revision_calls, 1);
    let rev_v2 = st_snap
        .links
        .get(&file_id)
        .unwrap()
        .active_revision_id
        .clone()
        .unwrap();
    drop(st_snap);
    assert_ne!(rev_v1, rev_v2);

    let dl_dir = fixture.root_path().join("dl_rev");
    fs::create_dir_all(&dl_dir).unwrap();
    client
        .download_file_checked("/my-files/mutable.bin", &dl_dir, "overwrite")
        .unwrap();
    assert_eq!(fs::read(dl_dir.join("mutable.bin")).unwrap(), v2);

    // 3. Conflict strategies: "skip" leaves v2 intact, "rename" creates mutable (1).bin
    let v3 = b"renamed-copy-v3".to_vec();
    fs::write(&src, &v3).unwrap();
    assert!(client.upload_file(&src, "/my-files", "skip"));
    client
        .download_file_checked("/my-files/mutable.bin", &dl_dir, "overwrite")
        .unwrap();
    assert_eq!(fs::read(dl_dir.join("mutable.bin")).unwrap(), v2);

    assert!(client.upload_file(&src, "/my-files", "rename"));
    let listed_final = client.list_path("/my-files").unwrap();
    assert!(listed_final.iter().any(|n| n.name == "mutable (1).bin"));
    client
        .download_file_checked("/my-files/mutable (1).bin", &dl_dir, "overwrite")
        .unwrap();
    assert_eq!(fs::read(dl_dir.join("mutable (1).bin")).unwrap(), v3);
}

#[test]
fn test_native_transfer_interrupted_upload_and_download_cleanup() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    // Seed an existing 2-block file
    let v1: Vec<u8> = (0..(BLOCK_SIZE + 64 * 1024))
        .map(|i| ((i * 13) & 0xFF) as u8)
        .collect();
    let file_id = {
        let mut st = server.state.lock().unwrap();
        let root_id = st.root_link_id.clone();
        st.add_remote_file_official_style(&root_id, "resilient.bin", &v1)
    };
    let orig_rev_id = server
        .state
        .lock()
        .unwrap()
        .links
        .get(&file_id)
        .unwrap()
        .active_revision_id
        .clone()
        .unwrap();

    // 1. Interrupted download on block 2 preserves pre-existing local file and leaves no temp files
    let dl_dir = fixture.root_path().join("dl_interrupt");
    fs::create_dir_all(&dl_dir).unwrap();
    let existing_local = dl_dir.join("resilient.bin");
    fs::write(&existing_local, b"local-intact-copy").unwrap();
    server.state.lock().unwrap().fail_block_download_index = Some(2);
    let dl_err = client
        .download_file_checked("/my-files/resilient.bin", &dl_dir, "overwrite")
        .unwrap_err();
    assert!(
        dl_err.contains("Failed downloading block 2"),
        "got: {}",
        dl_err
    );
    assert_eq!(fs::read(&existing_local).unwrap(), b"local-intact-copy");
    assert_eq!(fs::read_dir(&dl_dir).unwrap().count(), 1);
    server.state.lock().unwrap().fail_block_download_index = None;

    // 2. Interrupted revision replacement (block 2 upload fails) deletes draft revision & preserves v1
    let up_dir = fixture.root_path().join("up_interrupt");
    fs::create_dir_all(&up_dir).unwrap();
    let local_src = up_dir.join("resilient.bin");
    let v2: Vec<u8> = (0..(BLOCK_SIZE + 32 * 1024))
        .map(|i| ((i * 29 + 1) & 0xFF) as u8)
        .collect();
    fs::write(&local_src, &v2).unwrap();

    server.state.lock().unwrap().fail_block_upload_index = Some(2);
    assert!(
        !client.upload_file(&local_src, "/my-files", "create-new-revision"),
        "Interrupted block 2 upload must return false"
    );
    {
        let st = server.state.lock().unwrap();
        assert_eq!(
            st.delete_revision_calls, 1,
            "Failed revision upload must clean up orphaned draft revision"
        );
        assert_eq!(
            st.links
                .get(&file_id)
                .unwrap()
                .active_revision_id
                .as_deref(),
            Some(orig_rev_id.as_str()),
            "Active revision must remain v1 after interrupted upload"
        );
    }

    // 3. Recovery: clearing fault allows upload of v2 to succeed and roundtrip cleanly
    server.state.lock().unwrap().fail_block_upload_index = None;
    assert!(client.upload_file(&local_src, "/my-files", "create-new-revision"));
    client
        .download_file_checked("/my-files/resilient.bin", &dl_dir, "overwrite")
        .unwrap();
    assert_eq!(fs::read(&existing_local).unwrap(), v2);

    // 4. Verification failure (422 / 200501) on new file upload cleans up uncommitted draft link
    let draft_src = up_dir.join("draft_cleanup.bin");
    fs::write(&draft_src, b"draft-cleanup-payload").unwrap();
    server.state.lock().unwrap().corrupt_verification_code_once = true;
    assert!(
        !client.upload_file(&draft_src, "/my-files", "create-new-revision"),
        "422 / 200501 verification mismatch must abort new file upload"
    );
    {
        let st = server.state.lock().unwrap();
        assert_eq!(
            st.delete_calls, 1,
            "Failed new-file upload must delete uncommitted draft link"
        );
    }
    // Retry immediately -> no draft collision, upload & download succeed
    assert!(client.upload_file(&draft_src, "/my-files", "create-new-revision"));
    client
        .download_file_checked("/my-files/draft_cleanup.bin", &dl_dir, "overwrite")
        .unwrap();
    assert_eq!(
        fs::read(dl_dir.join("draft_cleanup.bin")).unwrap(),
        b"draft-cleanup-payload"
    );
}

#[test]
fn test_native_sync_engine_transfer_failure_leaves_local_data_recoverable() {
    let fixture = TestFixture::new();
    let (server, client) = new_client_and_server(&fixture, false);
    client
        .authenticate("alice@proton.me", "super-secret-password", None)
        .unwrap();

    let client_arc: Arc<dyn RemoteDrive> = Arc::new(client);
    let fuse = ProtonDriveFUSE::new(
        Arc::clone(&client_arc),
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        Some("/my-files"),
        Arc::clone(&fixture.activity),
    );
    let sync_engine = SyncEngine::new(
        Arc::clone(&client_arc),
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        5,
        Arc::clone(&fixture.activity),
    );

    // Create and release a local file via FUSE
    let fh = fuse
        .create_file_handle("/", "durable.txt")
        .expect("create_file_handle");
    fuse.write_to_handle(fh, 0, b"important-local-bytes")
        .expect("write_to_handle");
    fuse.release_handle(fh).expect("release_handle");

    // Inject transfer failure on UpdateRevision so remote commit fails
    server.state.lock().unwrap().fail_update_revision = true;
    sync_engine.sync_once();

    let node_err = fixture.db.get_node("/durable.txt").unwrap();
    assert_eq!(node_err.sync_status, SyncStatus::ERROR);
    let cache_path = node_err.local_cache_path.as_ref().unwrap();
    assert_eq!(fs::read(cache_path).unwrap(), b"important-local-bytes");

    // Clear fault and retry -> SyncEngine recovers and commits to native remote
    server.state.lock().unwrap().fail_update_revision = false;
    sync_engine.sync_once();
    let node_ok = fixture.db.get_node("/durable.txt").unwrap();
    assert_eq!(node_ok.sync_status, SyncStatus::SYNCED);

    let dl_dir = fixture.root_path().join("sync_verify");
    assert!(client_arc.download_file("/my-files/durable.txt", &dl_dir, "overwrite"));
    assert_eq!(
        fs::read(dl_dir.join("durable.txt")).unwrap(),
        b"important-local-bytes"
    );
}

fn authenticate_live_disposable_client(
    fixture: &TestFixture,
    vault_file_name: &str,
) -> (
    Arc<NativeProtonClient>,
    Arc<SessionVault>,
    Arc<InMemorySecretStore>,
) {
    let store = Arc::new(InMemorySecretStore::new());
    let vault = Arc::new(
        SessionVault::new_with_backend(
            Some(fixture.root_path().join(vault_file_name)),
            store.clone(),
            Arc::new(NoFallbackKeyProvider),
        )
        .unwrap(),
    );
    let client = Arc::new(
        NativeProtonClient::new_with_vault(fixture.db.clone(), vault.clone(), None).unwrap(),
    );

    let use_browser = std::env::var("PROTON_TEST_BROWSER_LOGIN").is_ok()
        || std::env::var("PROTON_TEST_USERNAME").is_err();
    let auth_msg = if use_browser {
        client
            .authenticate_via_browser(Duration::from_secs(300), |url, code| {
                println!("LIVE_LOGIN_URL: {}", url);
                println!("LIVE_USER_CODE: {}", code);
                let _ = std::process::Command::new("xdg-open").arg(url).spawn();
            })
            .expect("Live browser SSO disposable account authentication")
    } else {
        let username = std::env::var("PROTON_TEST_USERNAME")
            .expect("Set PROTON_TEST_USERNAME for live disposable account check");
        let password = std::env::var("PROTON_TEST_PASSWORD")
            .expect("Set PROTON_TEST_PASSWORD for live disposable account check");
        let totp = std::env::var("PROTON_TEST_TOTP").ok();
        client
            .authenticate(&username, &password, totp.as_deref())
            .expect("Live disposable account authentication")
    };
    println!("LIVE_DISPOSABLE_AUTH: {}", auth_msg);
    (client, vault, store)
}

#[test]
#[ignore = "Requires live disposable Proton Drive account (browser SSO or credentials)"]
fn test_live_disposable_account_transfer_interoperability() {
    let _ = env_logger::builder().is_test(true).try_init();
    let fixture = TestFixture::new();
    let (client, _, _) = authenticate_live_disposable_client(&fixture, "live_transfer_vault.json");

    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let folder_name = format!("native-transfer-e2e-{}", run_id);
    assert!(
        client.create_folder("/my-files", &folder_name),
        "Failed creating live test folder"
    );
    let remote_folder = format!("/my-files/{}", folder_name);

    let up_dir = fixture.root_path().join("live_up");
    let dl_dir = fixture.root_path().join("live_dl");
    fs::create_dir_all(&up_dir).unwrap();
    fs::create_dir_all(&dl_dir).unwrap();

    // 1. Empty file upload + download
    let empty_file = up_dir.join("empty.bin");
    fs::write(&empty_file, b"").unwrap();
    assert!(client.upload_file(&empty_file, &remote_folder, "create-new-revision"));
    client
        .download_file_checked(
            &format!("{}/empty.bin", remote_folder),
            &dl_dir,
            "overwrite",
        )
        .expect("Live empty file download");
    assert_eq!(fs::read(dl_dir.join("empty.bin")).unwrap(), b"");

    // 2. Multi-block boundary upload (4 MiB + 64 bytes) -> download -> revision replacement -> download
    let mut payload_v1 = vec![0u8; BLOCK_SIZE + 64];
    for (i, b) in payload_v1.iter_mut().enumerate() {
        *b = ((i * 31 + 7) & 0xFF) as u8;
    }
    let test_file = up_dir.join("boundary.bin");
    fs::write(&test_file, &payload_v1).unwrap();
    assert!(client.upload_file(&test_file, &remote_folder, "create-new-revision"));
    client
        .download_file_checked(
            &format!("{}/boundary.bin", remote_folder),
            &dl_dir,
            "overwrite",
        )
        .expect("Live boundary v1 download");
    assert_eq!(
        sha256_bytes(&fs::read(dl_dir.join("boundary.bin")).unwrap()),
        sha256_bytes(&payload_v1)
    );

    let payload_v2 = b"live-revision-v2-verified".to_vec();
    fs::write(&test_file, &payload_v2).unwrap();
    assert!(client.upload_file(&test_file, &remote_folder, "create-new-revision"));
    client
        .download_file_checked(
            &format!("{}/boundary.bin", remote_folder),
            &dl_dir,
            "overwrite",
        )
        .expect("Live boundary v2 download");
    assert_eq!(fs::read(dl_dir.join("boundary.bin")).unwrap(), payload_v2);

    // 3. Optional external official CLI cross-verification when PROTON_TEST_OFFICIAL_CLI=1
    if std::env::var("PROTON_TEST_OFFICIAL_CLI").ok().as_deref() == Some("1") {
        let cli_bin =
            std::env::var("PROTON_DRIVE_CLI_BIN").unwrap_or_else(|_| "proton-drive".to_string());
        let cli_dl_dir = fixture.root_path().join("cli_dl");
        fs::create_dir_all(&cli_dl_dir).unwrap();
        let dl_status = std::process::Command::new(&cli_bin)
            .args([
                "filesystem",
                "download",
                "--conflict-strategy",
                "overwrite",
                &format!("{}/boundary.bin", remote_folder),
                cli_dl_dir.to_str().unwrap(),
            ])
            .status()
            .expect("Execute external official CLI for cross-verification");
        assert!(dl_status.success(), "Official CLI download failed");
        assert_eq!(
            fs::read(cli_dl_dir.join("boundary.bin")).unwrap(),
            payload_v2
        );

        let cli_up_file = up_dir.join("from-official-cli.bin");
        let cli_payload = b"uploaded-by-official-cli-for-native-download";
        fs::write(&cli_up_file, cli_payload).unwrap();
        let up_status = std::process::Command::new(&cli_bin)
            .args([
                "filesystem",
                "upload",
                "--conflict-strategy",
                "create-new-revision",
                cli_up_file.to_str().unwrap(),
                &remote_folder,
            ])
            .status()
            .expect("Execute external official CLI upload");
        assert!(up_status.success(), "Official CLI upload failed");
        client.list_path(&remote_folder).unwrap();
        client
            .download_file_checked(
                &format!("{}/from-official-cli.bin", remote_folder),
                &dl_dir,
                "overwrite",
            )
            .expect("Native download of official CLI upload");
        assert_eq!(
            fs::read(dl_dir.join("from-official-cli.bin")).unwrap(),
            cli_payload
        );
        println!("LIVE_OFFICIAL_CLI_CROSS_CHECK: PASSED");
    }

    // Cleanup test folder
    let _ = client.trash(&remote_folder);
    let _ = client.delete(&remote_folder);
}

#[test]
#[ignore = "Requires live disposable Proton Drive account (browser SSO or credentials)"]
fn test_live_disposable_account_namespace_and_events() {
    let _ = env_logger::builder().is_test(true).try_init();
    let fixture = TestFixture::new();
    let (client, vault, _) = authenticate_live_disposable_client(&fixture, "live_ns_vault.json");

    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let folder_name = format!("native-ns-e2e-{}", run_id);
    let root_vpath = format!("/{}", folder_name);
    let remote_root = format!("/my-files/{}", folder_name);
    assert!(client.create_folder("/my-files", &folder_name));
    assert!(client.create_folder(&remote_root, "SrcDir"));
    assert!(client.create_folder(&remote_root, "DstDir"));

    let client_dyn: Arc<dyn RemoteDrive> = Arc::clone(&client) as Arc<dyn RemoteDrive>;
    let fuse = ProtonDriveFUSE::new(
        Arc::clone(&client_dyn),
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        Some("/my-files"),
        Arc::clone(&fixture.activity),
    );
    let engine = SyncEngine::new(
        Arc::clone(&client_dyn),
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        10,
        Arc::clone(&fixture.activity),
    );

    // Initialize event cursor & FUSE directory state
    engine.poll_remote_changes();
    fuse.refresh_dir_if_needed(&root_vpath, 0.0);
    let src_vpath = format!("{}/SrcDir", root_vpath);
    fuse.refresh_dir_if_needed(&src_vpath, 0.0);

    // Create & write via FUSE, then upload via SyncEngine
    let fh = fuse
        .create_file_handle(&src_vpath, "note.txt")
        .expect("create_file_handle");
    fuse.write_to_handle(fh, 0, b"live-fuse-namespace-v1")
        .expect("write_to_handle");
    fuse.release_handle(fh).expect("release_handle");
    engine.sync_once();
    assert_eq!(
        fixture
            .db
            .get_node(&format!("{}/note.txt", src_vpath))
            .unwrap()
            .sync_status,
        SyncStatus::SYNCED
    );

    // Rename & move under DstDir with key re-encryption on live server
    let remote_src_file = format!("{}/SrcDir/note.txt", remote_root);
    let remote_renamed_file = format!("{}/SrcDir/renamed.txt", remote_root);
    let remote_dst_dir = format!("{}/DstDir", remote_root);
    assert!(client.rename(&remote_src_file, "renamed.txt"));
    assert!(client.move_node(&remote_renamed_file, &remote_dst_dir));

    // Simulate client restart & run poll_events + download moved/renamed file
    let restarted =
        Arc::new(NativeProtonClient::new_with_vault(fixture.db.clone(), vault, None).unwrap());
    let restarted_dyn: Arc<dyn RemoteDrive> = Arc::clone(&restarted) as Arc<dyn RemoteDrive>;
    let engine2 = SyncEngine::new(
        restarted_dyn,
        fixture.db.clone(),
        fixture.cache_dir.clone(),
        10,
        Arc::clone(&fixture.activity),
    );
    engine2.poll_remote_changes();

    let dl_dir = fixture.root_path().join("live_ns_dl");
    fs::create_dir_all(&dl_dir).unwrap();
    restarted
        .download_file_checked(
            &format!("{}/DstDir/renamed.txt", remote_root),
            &dl_dir,
            "overwrite",
        )
        .expect("Download renamed + moved file after restart");
    assert_eq!(
        fs::read(dl_dir.join("renamed.txt")).unwrap(),
        b"live-fuse-namespace-v1"
    );

    // Trash & permanently delete test folder
    assert!(restarted.trash(&remote_root));
    assert!(restarted.delete(&remote_root));
}
