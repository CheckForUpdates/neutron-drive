use serde::{Deserialize, Deserializer, Serialize};

use super::http::{HttpError, PdHttpClient, RateLimitFamily};

fn de_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: Deserializer<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn de_null_volume_type<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<i32>::deserialize(deserializer)?.unwrap_or(1))
}

fn de_null_link_type<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<i32>::deserialize(deserializer)?.unwrap_or(2))
}

fn de_null_link_state<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<i32>::deserialize(deserializer)?.unwrap_or(1))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CodeResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "Error", alias = "error", default)]
    pub error: Option<String>,
}

impl CodeResponse {
    pub fn ensure_ok(&self, context: &str) -> Result<(), String> {
        if self.code == 1000 || self.code == 1001 {
            Ok(())
        } else {
            Err(format!(
                "{} failed with API code {}: {}",
                context,
                self.code,
                self.error.as_deref().unwrap_or("unknown error")
            ))
        }
    }
}

// ============================================================================
// Volumes & Share Bootstrap
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VolumeShare {
    #[serde(rename = "ShareID", alias = "shareID")]
    pub share_id: String,
    #[serde(rename = "LinkID", alias = "linkID")]
    pub link_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Volume {
    #[serde(rename = "VolumeID", alias = "volumeID")]
    pub volume_id: String,
    #[serde(rename = "State", alias = "state", default)]
    pub state: Option<i32>,
    #[serde(rename = "Share", alias = "share")]
    pub share: VolumeShare,
    #[serde(
        rename = "Type",
        alias = "type",
        default = "default_volume_type",
        deserialize_with = "de_null_volume_type"
    )]
    pub volume_type: i32,
    #[serde(rename = "UploadedBytes", alias = "uploadedBytes", default)]
    pub uploaded_bytes: Option<i64>,
    #[serde(rename = "MaxSpace", alias = "maxSpace", default)]
    pub max_space: Option<i64>,
    #[serde(rename = "UsedSpace", alias = "usedSpace", default)]
    pub used_space: Option<i64>,
}

fn default_volume_type() -> i32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VolumesResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(
        rename = "Volumes",
        alias = "volumes",
        default,
        deserialize_with = "de_null_default"
    )]
    pub volumes: Vec<Volume>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShareMembership {
    #[serde(
        rename = "MemberID",
        alias = "memberID",
        default,
        deserialize_with = "de_null_default"
    )]
    pub member_id: String,
    #[serde(
        rename = "ShareID",
        alias = "shareID",
        default,
        deserialize_with = "de_null_default"
    )]
    pub share_id: String,
    #[serde(
        rename = "AddressID",
        alias = "addressID",
        default,
        deserialize_with = "de_null_default"
    )]
    pub address_id: String,
    #[serde(
        rename = "AddressKeyID",
        alias = "addressKeyID",
        default,
        deserialize_with = "de_null_default"
    )]
    pub address_key_id: String,
    #[serde(
        rename = "KeyPacket",
        alias = "keyPacket",
        default,
        deserialize_with = "de_null_default"
    )]
    pub key_packet: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShareBootstrapResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "ShareID", alias = "shareID")]
    pub share_id: String,
    #[serde(rename = "VolumeID", alias = "volumeID")]
    pub volume_id: String,
    #[serde(
        rename = "Type",
        alias = "type",
        default,
        deserialize_with = "de_null_default"
    )]
    pub share_type: i32,
    #[serde(
        rename = "State",
        alias = "state",
        default,
        deserialize_with = "de_null_default"
    )]
    pub state: i32,
    #[serde(rename = "Locked", alias = "locked", default)]
    pub locked: Option<bool>,
    #[serde(
        rename = "Creator",
        alias = "creator",
        default,
        deserialize_with = "de_null_default"
    )]
    pub creator: String,
    #[serde(rename = "LinkID", alias = "linkID")]
    pub link_id: String,
    #[serde(
        rename = "Key",
        alias = "key",
        default,
        deserialize_with = "de_null_default"
    )]
    pub key: String,
    #[serde(
        rename = "Passphrase",
        alias = "passphrase",
        default,
        deserialize_with = "de_null_default"
    )]
    pub passphrase: String,
    #[serde(
        rename = "PassphraseSignature",
        alias = "passphraseSignature",
        default,
        deserialize_with = "de_null_default"
    )]
    pub passphrase_signature: String,
    #[serde(rename = "AddressID", alias = "addressID", default)]
    pub address_id: Option<String>,
    #[serde(rename = "AddressKeyID", alias = "addressKeyID", default)]
    pub address_key_id: Option<String>,
    #[serde(
        rename = "Memberships",
        alias = "memberships",
        default,
        deserialize_with = "de_null_default"
    )]
    pub memberships: Vec<ShareMembership>,
}

// ============================================================================
// Folder Children V2 & Link Metadata
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FolderChildrenListV2Response {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(
        rename = "LinkIDs",
        alias = "linkIDs",
        default,
        deserialize_with = "de_null_default"
    )]
    pub link_ids: Vec<String>,
    #[serde(rename = "AnchorID", alias = "anchorID", default)]
    pub anchor_id: Option<String>,
    #[serde(
        rename = "More",
        alias = "more",
        default,
        deserialize_with = "de_null_default"
    )]
    pub more: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinksMetadataByVolumeRequest<'a> {
    #[serde(rename = "LinkIDs")]
    pub link_ids: &'a [String],
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LinksMetadataResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(
        rename = "Links",
        alias = "links",
        default,
        deserialize_with = "de_null_default"
    )]
    pub links: Vec<LinkMetadata>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LinkMetadata {
    #[serde(rename = "LinkID", alias = "linkID")]
    pub link_id: String,
    #[serde(rename = "ParentLinkID", alias = "parentLinkID", default)]
    pub parent_link_id: Option<String>,
    /// 1 = folder, 2 = file, 3 = album
    #[serde(
        rename = "Type",
        alias = "type",
        default = "default_link_type",
        deserialize_with = "de_null_link_type"
    )]
    pub link_type: i32,
    #[serde(
        rename = "Name",
        alias = "name",
        default,
        deserialize_with = "de_null_default"
    )]
    pub name: String,
    #[serde(rename = "NameSignatureEmail", alias = "nameSignatureEmail", default)]
    pub name_signature_email: Option<String>,
    #[serde(
        rename = "Hash",
        alias = "hash",
        default,
        deserialize_with = "de_null_default"
    )]
    pub hash: String,
    /// 0 = draft, 1 = active, 2 = deleted, 3 = deleting
    #[serde(
        rename = "State",
        alias = "state",
        default = "default_link_state",
        deserialize_with = "de_null_link_state"
    )]
    pub state: i32,
    #[serde(
        rename = "Size",
        alias = "size",
        default,
        deserialize_with = "de_null_default"
    )]
    pub size: i64,
    #[serde(
        rename = "MIMEType",
        alias = "MIMEType",
        default,
        deserialize_with = "de_null_default"
    )]
    pub mime_type: String,
    #[serde(
        rename = "NodeKey",
        alias = "nodeKey",
        default,
        deserialize_with = "de_null_default"
    )]
    pub node_key: String,
    #[serde(
        rename = "NodePassphrase",
        alias = "nodePassphrase",
        default,
        deserialize_with = "de_null_default"
    )]
    pub node_passphrase: String,
    #[serde(
        rename = "NodePassphraseSignature",
        alias = "nodePassphraseSignature",
        default,
        deserialize_with = "de_null_default"
    )]
    pub node_passphrase_signature: String,
    #[serde(
        rename = "SignatureEmail",
        alias = "signatureEmail",
        default,
        deserialize_with = "de_null_default"
    )]
    pub signature_email: String,
    #[serde(
        rename = "CreateTime",
        alias = "createTime",
        default,
        deserialize_with = "de_null_default"
    )]
    pub create_time: f64,
    #[serde(
        rename = "ModifyTime",
        alias = "modifyTime",
        default,
        deserialize_with = "de_null_default"
    )]
    pub modify_time: f64,
    #[serde(rename = "Trashed", alias = "trashed", default)]
    pub trashed: Option<f64>,
    #[serde(rename = "XAttr", alias = "XAttr", default)]
    pub xattr: Option<String>,
    #[serde(rename = "FileProperties", alias = "fileProperties", default)]
    pub file_properties: Option<FileProperties>,
    #[serde(rename = "FolderProperties", alias = "folderProperties", default)]
    pub folder_properties: Option<FolderProperties>,
}

fn default_link_type() -> i32 {
    2
}

fn default_link_state() -> i32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileProperties {
    #[serde(
        rename = "ContentKeyPacket",
        alias = "contentKeyPacket",
        default,
        deserialize_with = "de_null_default"
    )]
    pub content_key_packet: String,
    #[serde(
        rename = "ContentKeyPacketSignature",
        alias = "contentKeyPacketSignature",
        default
    )]
    pub content_key_packet_signature: Option<String>,
    #[serde(rename = "ActiveRevision", alias = "activeRevision", default)]
    pub active_revision: Option<RevisionShort>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FolderProperties {
    #[serde(
        rename = "NodeHashKey",
        alias = "nodeHashKey",
        default,
        deserialize_with = "de_null_default"
    )]
    pub node_hash_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevisionShort {
    #[serde(rename = "ID", alias = "ID")]
    pub id: String,
    #[serde(
        rename = "CreateTime",
        alias = "createTime",
        default,
        deserialize_with = "de_null_default"
    )]
    pub create_time: f64,
    #[serde(
        rename = "Size",
        alias = "size",
        default,
        deserialize_with = "de_null_default"
    )]
    pub size: i64,
    #[serde(rename = "ManifestSignature", alias = "manifestSignature", default)]
    pub manifest_signature: Option<String>,
    #[serde(rename = "SignatureAddress", alias = "signatureAddress", default)]
    pub signature_address: Option<String>,
    #[serde(
        rename = "State",
        alias = "state",
        default,
        deserialize_with = "de_null_default"
    )]
    pub state: i32,
}

// ============================================================================
// Revisions, Blocks & File/Folder Creation
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevisionThumbnail {
    #[serde(
        rename = "ThumbnailID",
        alias = "thumbnailID",
        default,
        deserialize_with = "de_null_default"
    )]
    pub thumbnail_id: String,
    #[serde(
        rename = "Type",
        alias = "type",
        default,
        deserialize_with = "de_null_default"
    )]
    pub thumb_type: i32,
    #[serde(
        rename = "Hash",
        alias = "hash",
        default,
        deserialize_with = "de_null_default"
    )]
    pub hash: String,
    #[serde(
        rename = "Size",
        alias = "size",
        default,
        deserialize_with = "de_null_default"
    )]
    pub size: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockMetadata {
    #[serde(
        rename = "Index",
        alias = "index",
        default,
        deserialize_with = "de_null_default"
    )]
    pub index: usize,
    #[serde(
        rename = "Hash",
        alias = "hash",
        default,
        deserialize_with = "de_null_default"
    )]
    pub hash: String,
    #[serde(
        rename = "URL",
        alias = "URL",
        alias = "url",
        default,
        deserialize_with = "de_null_default"
    )]
    pub url: String,
    #[serde(rename = "BareURL", alias = "bareUrl", default)]
    pub bare_url: Option<String>,
    #[serde(rename = "Token", alias = "token", default)]
    pub token: Option<String>,
    #[serde(rename = "EncSignature", alias = "encSignature", default)]
    pub enc_signature: Option<String>,
    #[serde(rename = "SignatureEmail", alias = "signatureEmail", default)]
    pub signature_email: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevisionDetail {
    #[serde(rename = "ID", alias = "id")]
    pub id: String,
    #[serde(
        rename = "CreateTime",
        alias = "createTime",
        default,
        deserialize_with = "de_null_default"
    )]
    pub create_time: f64,
    #[serde(
        rename = "Size",
        alias = "size",
        default,
        deserialize_with = "de_null_default"
    )]
    pub size: i64,
    #[serde(rename = "ManifestSignature", alias = "manifestSignature", default)]
    pub manifest_signature: Option<String>,
    #[serde(rename = "SignatureAddress", alias = "signatureAddress", default)]
    pub signature_address: Option<String>,
    #[serde(
        rename = "State",
        alias = "state",
        default,
        deserialize_with = "de_null_default"
    )]
    pub state: i32,
    #[serde(
        rename = "Blocks",
        alias = "blocks",
        default,
        deserialize_with = "de_null_default"
    )]
    pub blocks: Vec<BlockMetadata>,
    #[serde(
        rename = "Thumbnails",
        alias = "thumbnails",
        default,
        deserialize_with = "de_null_default"
    )]
    pub thumbnails: Vec<RevisionThumbnail>,
    #[serde(rename = "ThumbnailHash", alias = "thumbnailHash", default)]
    pub thumbnail_hash: Option<String>,
    #[serde(rename = "XAttr", alias = "XAttr", default)]
    pub xattr: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevisionResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "Revision", alias = "revision")]
    pub revision: RevisionDetail,
}

#[derive(Debug, Clone, Serialize)]
pub struct NewFileParameters {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Hash")]
    pub hash: String,
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: String,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "NodePassphrase")]
    pub node_passphrase: String,
    #[serde(rename = "NodePassphraseSignature")]
    pub node_passphrase_signature: String,
    #[serde(rename = "SignatureAddress")]
    pub signature_address: String,
    #[serde(rename = "ContentKeyPacket")]
    pub content_key_packet: String,
    #[serde(rename = "ContentKeyPacketSignature")]
    pub content_key_packet_signature: String,
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    #[serde(rename = "ClientUID")]
    pub client_uid: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewFileInfo {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "RevisionID", alias = "revisionID")]
    pub revision_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewFileResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "File", alias = "file")]
    pub file: NewFileInfo,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewRevisionInfo {
    #[serde(rename = "ID")]
    pub id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewRevisionResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "Revision", alias = "revision")]
    pub revision: NewRevisionInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifierInfo {
    #[serde(rename = "Token")]
    pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NewBlockItem {
    #[serde(rename = "Size")]
    pub size: usize,
    #[serde(rename = "Index")]
    pub index: usize,
    #[serde(rename = "EncSignature")]
    pub enc_signature: String,
    #[serde(rename = "Hash")]
    pub hash: String,
    #[serde(rename = "Verifier")]
    pub verifier: VerifierInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct NewBlocksParameters {
    #[serde(rename = "AddressID")]
    pub address_id: String,
    #[serde(rename = "ShareID")]
    pub share_id: String,
    #[serde(rename = "LinkID")]
    pub link_id: String,
    #[serde(rename = "RevisionID")]
    pub revision_id: String,
    #[serde(rename = "BlockList")]
    pub block_list: Vec<NewBlockItem>,
    #[serde(rename = "ThumbnailList")]
    pub thumbnail_list: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContentUploadLink {
    #[serde(rename = "Index", alias = "index", default)]
    pub index: Option<usize>,
    #[serde(rename = "Token", alias = "token", default)]
    pub token: String,
    #[serde(rename = "URL", alias = "URL", alias = "url", default)]
    pub url: String,
    #[serde(rename = "BareURL", alias = "bareUrl", default)]
    pub bare_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationDataResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "VerificationCode", alias = "verificationCode", default)]
    pub verification_code: String,
    #[serde(rename = "ContentKeyPacket", alias = "contentKeyPacket", default)]
    pub content_key_packet: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewBlocksResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "UploadLinks", alias = "uploadLinks", default)]
    pub upload_links: Vec<ContentUploadLink>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateRevisionParameters {
    #[serde(rename = "ManifestSignature")]
    pub manifest_signature: String,
    #[serde(rename = "SignatureAddress")]
    pub signature_address: String,
    #[serde(rename = "XAttr", skip_serializing_if = "Option::is_none")]
    pub xattr: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NewFolderParameters {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Hash")]
    pub hash: String,
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: String,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "NodeHashKey")]
    pub node_hash_key: String,
    #[serde(rename = "NodePassphrase")]
    pub node_passphrase: String,
    #[serde(rename = "NodePassphraseSignature")]
    pub node_passphrase_signature: String,
    #[serde(rename = "SignatureAddress")]
    pub signature_address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewFolderInfo {
    #[serde(rename = "ID")]
    pub id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewFolderResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "Folder", alias = "folder")]
    pub folder: NewFolderInfo,
}

// ============================================================================
// Namespace Mutations (Rename, Move, Trash, Delete)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct RenameNodeParameters {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Hash", skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(rename = "MIMEType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(rename = "SignatureAddress")]
    pub signature_address: String,
    #[serde(rename = "OriginalHash", skip_serializing_if = "Option::is_none")]
    pub original_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MoveMultipleLinkItem {
    #[serde(rename = "LinkID")]
    pub link_id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NodePassphrase")]
    pub node_passphrase: String,
    #[serde(rename = "Hash")]
    pub hash: String,
    #[serde(rename = "OriginalHash")]
    pub original_hash: String,
    #[serde(rename = "ContentHash", skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(
        rename = "NodePassphraseSignature",
        skip_serializing_if = "Option::is_none"
    )]
    pub node_passphrase_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MoveMultipleParameters {
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: String,
    #[serde(rename = "Links")]
    pub links: Vec<MoveMultipleLinkItem>,
    #[serde(rename = "NameSignatureEmail")]
    pub name_signature_email: String,
    #[serde(rename = "SignatureEmail", skip_serializing_if = "Option::is_none")]
    pub signature_email: Option<String>,
    #[serde(rename = "NewShareID", skip_serializing_if = "Option::is_none")]
    pub new_share_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MultipleLinkResponseItem {
    #[serde(rename = "LinkID", alias = "linkID")]
    pub link_id: String,
    #[serde(rename = "Response", alias = "response")]
    pub response: CodeResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MultipleLinkResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "Responses", alias = "responses", default)]
    pub responses: Vec<MultipleLinkResponseItem>,
}

#[derive(Debug, Clone, Serialize)]
struct LinkIdsBody<'a> {
    #[serde(rename = "LinkIDs")]
    link_ids: &'a [String],
}

// ============================================================================
// Events Stream
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LatestEventResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "EventID", alias = "eventID")]
    pub event_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DriveEvent {
    #[serde(rename = "ContextShareID", alias = "contextShareID", default)]
    pub context_share_id: String,
    #[serde(rename = "EventID", alias = "eventID")]
    pub event_id: String,
    /// 0 = delete, 1 = create, 2 = updateContent, 3 = updateMetadata
    #[serde(rename = "EventType", alias = "eventType")]
    pub event_type: i32,
    #[serde(rename = "CreateTime", alias = "createTime", default)]
    pub create_time: f64,
    #[serde(rename = "Link", alias = "link")]
    pub link: LinkMetadata,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventsResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "Events", alias = "events", default)]
    pub events: Vec<DriveEvent>,
    #[serde(rename = "EventID", alias = "eventID")]
    pub event_id: String,
    #[serde(rename = "More", alias = "more", default)]
    pub more: i32,
    #[serde(rename = "Refresh", alias = "refresh", default)]
    pub refresh: i32,
}

// ============================================================================
// Typed Endpoint Helpers
// ============================================================================

pub struct DriveEndpoints;

impl DriveEndpoints {
    pub fn list_volumes(http: &PdHttpClient) -> Result<VolumesResponse, HttpError> {
        http.get_json(RateLimitFamily::Metadata, "/drive/volumes", &[], true)
    }

    pub fn get_share_bootstrap(
        http: &PdHttpClient,
        share_id: &str,
    ) -> Result<ShareBootstrapResponse, HttpError> {
        let path = format!("/drive/shares/{}", share_id);
        http.get_json(RateLimitFamily::Metadata, &path, &[], true)
    }

    pub fn list_folder_children_v2(
        http: &PdHttpClient,
        volume_id: &str,
        folder_id: &str,
        anchor_id: Option<&str>,
        folders_only: bool,
    ) -> Result<FolderChildrenListV2Response, HttpError> {
        let path = format!(
            "/drive/v2/volumes/{}/folders/{}/children",
            volume_id, folder_id
        );
        let folders_flag = if folders_only { "1" } else { "0" };
        let mut query = vec![("FoldersOnly", folders_flag)];
        if let Some(a) = anchor_id {
            query.push(("AnchorID", a));
        }
        http.get_json(RateLimitFamily::Children, &path, &query, true)
    }

    pub fn fetch_links_metadata(
        http: &PdHttpClient,
        volume_id: &str,
        link_ids: &[String],
    ) -> Result<LinksMetadataResponse, HttpError> {
        let path = format!("/drive/volumes/{}/links/fetch_metadata", volume_id);
        let body = LinksMetadataByVolumeRequest { link_ids };
        http.post_json(RateLimitFamily::Metadata, &path, &body, true)
    }

    pub fn get_revision(
        http: &PdHttpClient,
        share_id: &str,
        file_id: &str,
        revision_id: &str,
    ) -> Result<RevisionResponse, HttpError> {
        let path = format!(
            "/drive/shares/{}/files/{}/revisions/{}",
            share_id, file_id, revision_id
        );
        http.get_json(RateLimitFamily::Metadata, &path, &[], true)
    }

    pub fn create_file(
        http: &PdHttpClient,
        share_id: &str,
        params: &NewFileParameters,
    ) -> Result<NewFileResponse, HttpError> {
        let path = format!("/drive/shares/{}/files", share_id);
        http.post_json(RateLimitFamily::Mutation, &path, params, true)
    }

    pub fn create_revision(
        http: &PdHttpClient,
        share_id: &str,
        file_id: &str,
    ) -> Result<NewRevisionResponse, HttpError> {
        let path = format!("/drive/shares/{}/files/{}/revisions", share_id, file_id);
        let empty = serde_json::json!({});
        http.post_json(RateLimitFamily::Mutation, &path, &empty, true)
    }

    pub fn request_block_upload_links(
        http: &PdHttpClient,
        params: &NewBlocksParameters,
    ) -> Result<NewBlocksResponse, HttpError> {
        http.post_json(RateLimitFamily::Transfer, "/drive/blocks", params, true)
    }

    pub fn update_revision(
        http: &PdHttpClient,
        share_id: &str,
        file_id: &str,
        revision_id: &str,
        params: &UpdateRevisionParameters,
    ) -> Result<CodeResponse, HttpError> {
        let path = format!(
            "/drive/shares/{}/files/{}/revisions/{}",
            share_id, file_id, revision_id
        );
        http.put_json(RateLimitFamily::Mutation, &path, params, true)
    }

    pub fn delete_revision(
        http: &PdHttpClient,
        share_id: &str,
        file_id: &str,
        revision_id: &str,
    ) -> Result<CodeResponse, HttpError> {
        let path = format!(
            "/drive/shares/{}/files/{}/revisions/{}",
            share_id, file_id, revision_id
        );
        http.delete_json(RateLimitFamily::Mutation, &path, true)
    }

    pub fn get_verification_data(
        http: &PdHttpClient,
        volume_id: &str,
        link_id: &str,
        revision_id: &str,
    ) -> Result<VerificationDataResponse, HttpError> {
        let path = format!(
            "/drive/v2/volumes/{}/links/{}/revisions/{}/verification",
            volume_id, link_id, revision_id
        );
        http.get_json(RateLimitFamily::Metadata, &path, &[], true)
    }

    pub fn delete_draft_links(
        http: &PdHttpClient,
        volume_id: &str,
        link_ids: &[String],
    ) -> Result<MultipleLinkResponse, HttpError> {
        let path = format!("/drive/v2/volumes/{}/delete_multiple", volume_id);
        let body = LinkIdsBody { link_ids };
        http.post_json(RateLimitFamily::Mutation, &path, &body, true)
    }

    pub fn create_folder(
        http: &PdHttpClient,
        share_id: &str,
        params: &NewFolderParameters,
    ) -> Result<NewFolderResponse, HttpError> {
        let path = format!("/drive/shares/{}/folders", share_id);
        http.post_json(RateLimitFamily::Mutation, &path, params, true)
    }

    pub fn rename_node(
        http: &PdHttpClient,
        share_id: &str,
        link_id: &str,
        params: &RenameNodeParameters,
    ) -> Result<CodeResponse, HttpError> {
        let path = format!("/drive/shares/{}/links/{}/rename", share_id, link_id);
        http.put_json(RateLimitFamily::Mutation, &path, params, true)
    }

    pub fn move_multiple(
        http: &PdHttpClient,
        volume_id: &str,
        params: &MoveMultipleParameters,
    ) -> Result<MultipleLinkResponse, HttpError> {
        let path = format!("/drive/volumes/{}/links/move-multiple", volume_id);
        http.put_json(RateLimitFamily::Mutation, &path, params, true)
    }

    pub fn trash_links(
        http: &PdHttpClient,
        share_id: &str,
        parent_link_id: &str,
        link_ids: &[String],
    ) -> Result<MultipleLinkResponse, HttpError> {
        let path = format!(
            "/drive/shares/{}/folders/{}/trash_multiple",
            share_id, parent_link_id
        );
        let body = LinkIdsBody { link_ids };
        http.post_json(RateLimitFamily::Mutation, &path, &body, true)
    }

    pub fn delete_multiple(
        http: &PdHttpClient,
        volume_id: &str,
        link_ids: &[String],
    ) -> Result<MultipleLinkResponse, HttpError> {
        let path = format!("/drive/v2/volumes/{}/trash/delete_multiple", volume_id);
        let body = LinkIdsBody { link_ids };
        http.post_json(RateLimitFamily::Mutation, &path, &body, true)
    }

    pub fn get_latest_event_id(
        http: &PdHttpClient,
        volume_id: &str,
    ) -> Result<LatestEventResponse, HttpError> {
        let path = format!("/drive/volumes/{}/events/latest", volume_id);
        http.get_json(RateLimitFamily::Events, &path, &[], true)
    }

    pub fn get_events(
        http: &PdHttpClient,
        volume_id: &str,
        since_event_id: &str,
    ) -> Result<EventsResponse, HttpError> {
        let path = format!("/drive/volumes/{}/events/{}", volume_id, since_event_id);
        http.get_json(RateLimitFamily::Events, &path, &[], true)
    }
}
