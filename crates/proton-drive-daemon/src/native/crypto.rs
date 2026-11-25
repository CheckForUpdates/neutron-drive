use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bytes::Bytes;
use pgp::armor::{self, BlockType};
use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, Edata, EncryptionCaps,
    KeyType, Message, MessageBuilder, PlainSessionKey, RawSessionKey, SecretKeyParamsBuilder,
    SignedPublicKey, SignedPublicSubKey, SignedSecretKey, SubkeyParamsBuilder, SubpacketConfig,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{
    Notation, Packet, PacketParser, PacketTrait, ProtectedDataConfig, PublicKey,
    PublicKeyEncryptedSessionKey, SecretKey, SecretSubkey, Signature, Subpacket, SubpacketData,
    SymEncryptedProtectedDataConfig,
};
use pgp::ser::Serialize as PgpSerialize;
use pgp::types::{
    CompressionAlgorithm, DecryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion,
    Password, PkeskVersion, Timestamp,
};
use rand::thread_rng;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smallvec::smallvec;
use zeroize::{Zeroize, Zeroizing};

pub const PACKET_PKESK: u8 = 1;
pub const PACKET_SIGNATURE: u8 = 2;
pub const PACKET_SECRET_KEY: u8 = 5;
pub const PACKET_PUBLIC_KEY: u8 = 6;
pub const PACKET_SECRET_SUBKEY: u8 = 7;
pub const PACKET_COMPRESSED: u8 = 8;
pub const PACKET_LITERAL: u8 = 11;
pub const PACKET_USER_ID: u8 = 13;
pub const PACKET_PUBLIC_SUBKEY: u8 = 14;
pub const PACKET_SEIPD: u8 = 18;

const PROTON_CONTEXT_NOTATION: &[u8] = b"context@proton.ch";

pub fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let mut out = vec![0u8; len];
    rng.fill(&mut out)
        .map_err(|_| "CSPRNG failure generating random bytes".to_string())?;
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmorKind {
    Message,
    PrivateKey,
    PublicKey,
    Signature,
}

impl ArmorKind {
    fn header_label(self) -> &'static str {
        match self {
            ArmorKind::Message => "PGP MESSAGE",
            ArmorKind::PrivateKey => "PGP PRIVATE KEY BLOCK",
            ArmorKind::PublicKey => "PGP PUBLIC KEY BLOCK",
            ArmorKind::Signature => "PGP SIGNATURE",
        }
    }

    fn to_block_type(self) -> BlockType {
        match self {
            ArmorKind::Message => BlockType::Message,
            ArmorKind::PrivateKey => BlockType::PrivateKey,
            ArmorKind::PublicKey => BlockType::PublicKey,
            ArmorKind::Signature => BlockType::Signature,
        }
    }

    fn from_block_type(bt: BlockType) -> Result<Self, String> {
        match bt {
            BlockType::Message | BlockType::MultiPartMessage(_, _) | BlockType::File => {
                Ok(ArmorKind::Message)
            }
            BlockType::PrivateKey => Ok(ArmorKind::PrivateKey),
            BlockType::PublicKey => Ok(ArmorKind::PublicKey),
            BlockType::Signature => Ok(ArmorKind::Signature),
            other => Err(format!("Unsupported PGP armor block type: {:?}", other)),
        }
    }

    fn from_label(label: &str) -> Result<Self, String> {
        match label.trim() {
            "PGP MESSAGE" => Ok(ArmorKind::Message),
            "PGP PRIVATE KEY BLOCK" => Ok(ArmorKind::PrivateKey),
            "PGP PUBLIC KEY BLOCK" => Ok(ArmorKind::PublicKey),
            "PGP SIGNATURE" => Ok(ArmorKind::Signature),
            other => Err(format!("Unsupported PGP armor header: {}", other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmoredBlock {
    pub kind: ArmorKind,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Computes RFC 4880 CRC-24 over `data`.
pub fn crc24(data: &[u8]) -> u32 {
    const CRC24_INIT: u32 = 0xB704CE;
    const CRC24_POLY: u32 = 0x1864CFB;
    let mut crc = CRC24_INIT;
    for &byte in data {
        crc ^= (byte as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if (crc & 0x100_0000) != 0 {
                crc ^= CRC24_POLY;
            }
        }
    }
    crc & 0xFF_FFFF
}

/// Encodes raw OpenPGP packet bytes into an RFC 4880 ASCII-armored block with CRC-24.
pub fn enarmor(kind: ArmorKind, body: &[u8]) -> String {
    struct RawBytes<'a>(&'a [u8]);
    impl PgpSerialize for RawBytes<'_> {
        fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> pgp::errors::Result<()> {
            writer.write_all(self.0)?;
            Ok(())
        }
        fn write_len(&self) -> usize {
            self.0.len()
        }
    }

    let mut out = Vec::new();
    if armor::write(&RawBytes(body), kind.to_block_type(), &mut out, None, true).is_ok() {
        if let Ok(s) = String::from_utf8(out) {
            return s;
        }
    }

    let label = kind.header_label();
    let b64 = BASE64.encode(body);
    let crc = crc24(body);
    let crc_bytes = [
        ((crc >> 16) & 0xFF) as u8,
        ((crc >> 8) & 0xFF) as u8,
        (crc & 0xFF) as u8,
    ];
    let crc_b64 = BASE64.encode(crc_bytes);

    let mut fallback = String::with_capacity(b64.len() + 96);
    fallback.push_str("-----BEGIN ");
    fallback.push_str(label);
    fallback.push_str("-----\n\n");
    for chunk in b64.as_bytes().chunks(64) {
        fallback.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        fallback.push('\n');
    }
    fallback.push('=');
    fallback.push_str(&crc_b64);
    fallback.push('\n');
    fallback.push_str("-----END ");
    fallback.push_str(label);
    fallback.push_str("-----\n");
    fallback
}

/// Decodes and validates an RFC 4880 ASCII-armored OpenPGP block.
pub fn dearmor(armored: &str) -> Result<ArmoredBlock, String> {
    let mut dearmor_reader = armor::Dearmor::new(armored.as_bytes());
    dearmor_reader
        .read_header()
        .map_err(|e| format!("Failed parsing PGP armor header: {}", e))?;

    let bt = dearmor_reader
        .typ
        .ok_or_else(|| "Missing PGP armor BEGIN block type".to_string())?;
    let kind =
        ArmorKind::from_block_type(bt).or_else(|_| ArmorKind::from_label(&bt.to_string()))?;

    let headers: Vec<(String, String)> = dearmor_reader
        .headers
        .iter()
        .flat_map(|(k, vals)| vals.iter().map(move |v| (k.clone(), v.clone())))
        .collect();

    let mut body = Vec::new();
    dearmor_reader
        .read_to_end(&mut body)
        .map_err(|e| format!("Failed reading PGP armor body: {}", e))?;

    // pgp 0.21.1's built-in `crc24_check` option copies its `Crc24Hasher` by value inside
    // `Dearmor::read_body`, leaving the accumulated hash at the initial seed. Check the
    // parsed footer checksum against our computed CRC-24 directly.
    if let Some(expected_crc) = dearmor_reader.checksum {
        if u64::from(crc24(&body)) != expected_crc {
            return Err("OpenPGP armor CRC-24 checksum mismatch".to_string());
        }
    }

    Ok(ArmoredBlock {
        kind,
        headers,
        body,
    })
}

/// Parses an OpenPGP binary packet stream into `(tag, serialized_packet_bytes)` pairs.
pub fn decode_packets(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, String> {
    let parser = PacketParser::new(data);
    let mut packets = Vec::new();
    for res in parser {
        let pkt = res.map_err(|e| format!("Failed parsing OpenPGP packet: {}", e))?;
        let tag: u8 = pkt.tag().into();
        let mut raw = Vec::new();
        pkt.to_writer(&mut raw)
            .map_err(|e| format!("Failed serializing OpenPGP packet: {}", e))?;
        packets.push((tag, raw));
    }
    if packets.is_empty() && !data.is_empty() {
        return Err("No valid OpenPGP packets found in input".to_string());
    }
    Ok(packets)
}

// ============================================================================
// Core Key, SessionKey, Context, and Verification Types
// ============================================================================

#[derive(Clone)]
pub struct SessionKey {
    bytes: Zeroizing<[u8; 32]>,
    sym_alg: SymmetricKeyAlgorithm,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey").finish_non_exhaustive()
    }
}

impl SessionKey {
    pub fn generate() -> Result<Self, String> {
        let raw = random_bytes(32)?;
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&raw);
        Ok(Self {
            bytes: arr,
            sym_alg: SymmetricKeyAlgorithm::AES256,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::from_bytes_with_alg(data, SymmetricKeyAlgorithm::AES256)
    }

    fn from_bytes_with_alg(data: &[u8], sym_alg: SymmetricKeyAlgorithm) -> Result<Self, String> {
        if data.len() != 32 {
            return Err(format!(
                "Expected 32-byte AES-256 session key, got {}",
                data.len()
            ));
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(data);
        Ok(Self {
            bytes: arr,
            sym_alg,
        })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[derive(Clone)]
pub struct UnlockedKey {
    pub key_id: [u8; 8],
    pub subkey_id: [u8; 8],
    pub fingerprint: [u8; 20],
    secret_key: SignedSecretKey,
    passphrase: Zeroizing<String>,
    pub armored_public: String,
    pub armored_private: String,
}

impl std::fmt::Debug for UnlockedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedKey")
            .field("key_id", &hex::encode(self.key_id))
            .field("subkey_id", &hex::encode(self.subkey_id))
            .finish_non_exhaustive()
    }
}

impl UnlockedKey {
    fn pgp_password(&self) -> Password {
        Password::from(self.passphrase.as_str())
    }
}

#[derive(Clone)]
pub struct KeyCredentials {
    pub key: String,
    pub passphrase: String,
    pub signature: String,
    pub passphrase_raw: Zeroizing<String>,
}

#[derive(Debug, Clone)]
pub struct SignContext {
    pub value: String,
    pub is_critical: bool,
}

impl SignContext {
    pub fn critical(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            is_critical: true,
        }
    }

    pub fn non_critical(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            is_critical: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum VerificationRequired {
    NonRequired,
    RequiredAfter(u64),
}

#[derive(Debug, Clone)]
pub struct VerificationContext {
    pub value: String,
    pub required: VerificationRequired,
}

impl VerificationContext {
    pub fn new(value: impl Into<String>, required: VerificationRequired) -> Self {
        Self {
            value: value.into(),
            required,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedText {
    Verified(String),
    Unverified(String, String),
}

impl VerifiedText {
    pub fn value(&self) -> &str {
        match self {
            VerifiedText::Verified(s) | VerifiedText::Unverified(s, _) => s,
        }
    }

    pub fn into_value(self) -> String {
        match self {
            VerifiedText::Verified(s) | VerifiedText::Unverified(s, _) => s,
        }
    }

    pub fn is_verified(&self) -> bool {
        matches!(self, VerifiedText::Verified(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedBinary {
    Verified(Vec<u8>),
    Unverified(Vec<u8>, String),
}

impl VerifiedBinary {
    pub fn value(&self) -> &[u8] {
        match self {
            VerifiedBinary::Verified(b) | VerifiedBinary::Unverified(b, _) => b,
        }
    }

    pub fn into_value(self) -> Vec<u8> {
        match self {
            VerifiedBinary::Verified(b) | VerifiedBinary::Unverified(b, _) => b,
        }
    }

    pub fn is_verified(&self) -> bool {
        matches!(self, VerifiedBinary::Verified(_))
    }

    pub fn require_verified(self, context: &str) -> Result<Vec<u8>, String> {
        match self {
            VerifiedBinary::Verified(b) => Ok(b),
            VerifiedBinary::Unverified(_, err) => Err(format!(
                "{} signature verification failed: {}",
                context, err
            )),
        }
    }
}

// ============================================================================
// OpenPGP Key Parsing, Selection & Subpacket Helpers
// ============================================================================

fn parse_signed_public_key(armored: &str) -> Result<SignedPublicKey, String> {
    if armored.contains("PGP PRIVATE KEY BLOCK") {
        let (sk, _) = SignedSecretKey::from_string(armored)
            .map_err(|e| format!("Failed parsing armored private key: {}", e))?;
        return Ok(sk.to_public_key());
    }
    match SignedPublicKey::from_string(armored) {
        Ok((pk, _)) => Ok(pk),
        Err(pub_err) => {
            if let Ok((sk, _)) = SignedSecretKey::from_string(armored) {
                Ok(sk.to_public_key())
            } else {
                Err(format!("Failed parsing armored OpenPGP key: {}", pub_err))
            }
        }
    }
}

fn can_encrypt_alg(alg: PublicKeyAlgorithm) -> bool {
    matches!(
        alg,
        PublicKeyAlgorithm::ECDH
            | PublicKeyAlgorithm::X25519
            | PublicKeyAlgorithm::X448
            | PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::Elgamal
    )
}

fn can_sign_alg(alg: PublicKeyAlgorithm) -> bool {
    matches!(
        alg,
        PublicKeyAlgorithm::EdDSALegacy
            | PublicKeyAlgorithm::Ed25519
            | PublicKeyAlgorithm::Ed448
            | PublicKeyAlgorithm::ECDSA
            | PublicKeyAlgorithm::DSA
            | PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSASign
    )
}

#[derive(Clone, Copy)]
enum SelectedEncryptionKey<'a> {
    Primary(&'a PublicKey),
    Sub(&'a SignedPublicSubKey),
}

impl<'a> SelectedEncryptionKey<'a> {
    fn to_pkesk_v3<RNG: rand::CryptoRng + rand::Rng>(
        self,
        rng: RNG,
        raw_sk: &RawSessionKey,
        sym_alg: SymmetricKeyAlgorithm,
    ) -> pgp::errors::Result<PublicKeyEncryptedSessionKey> {
        match self {
            Self::Primary(k) => {
                PublicKeyEncryptedSessionKey::from_session_key_v3(rng, raw_sk, sym_alg, k)
            }
            Self::Sub(k) => {
                PublicKeyEncryptedSessionKey::from_session_key_v3(rng, raw_sk, sym_alg, k)
            }
        }
    }
}

#[derive(Clone, Copy)]
enum SelectedSigningKey<'a> {
    Primary(&'a SecretKey),
    Sub(&'a SecretSubkey),
}

impl<'a> SelectedSigningKey<'a> {
    fn fingerprint(self) -> Fingerprint {
        match self {
            Self::Primary(k) => k.fingerprint(),
            Self::Sub(k) => k.fingerprint(),
        }
    }

    fn version(self) -> KeyVersion {
        match self {
            Self::Primary(k) => k.version(),
            Self::Sub(k) => k.version(),
        }
    }

    fn legacy_key_id(self) -> KeyId {
        match self {
            Self::Primary(k) => k.legacy_key_id(),
            Self::Sub(k) => k.legacy_key_id(),
        }
    }

    fn sign_detached_with_subpackets<RNG: rand::CryptoRng + rand::Rng>(
        self,
        rng: RNG,
        pw: &Password,
        hash_alg: HashAlgorithm,
        input: &[u8],
        subpackets: SubpacketConfig,
        is_text: bool,
    ) -> pgp::errors::Result<DetachedSignature> {
        match (self, is_text) {
            (Self::Primary(k), true) => DetachedSignature::sign_text_data_with_subpackets(
                rng, k, pw, hash_alg, input, subpackets,
            ),
            (Self::Sub(k), true) => DetachedSignature::sign_text_data_with_subpackets(
                rng, k, pw, hash_alg, input, subpackets,
            ),
            (Self::Primary(k), false) => DetachedSignature::sign_binary_data_with_subpackets(
                rng, k, pw, hash_alg, input, subpackets,
            ),
            (Self::Sub(k), false) => DetachedSignature::sign_binary_data_with_subpackets(
                rng, k, pw, hash_alg, input, subpackets,
            ),
        }
    }

    fn sign_cleartext<RNG: rand::CryptoRng + rand::Rng>(
        self,
        rng: RNG,
        text: &str,
        pw: &Password,
    ) -> pgp::errors::Result<CleartextSignedMessage> {
        match self {
            Self::Primary(k) => CleartextSignedMessage::sign(rng, text, k, pw),
            Self::Sub(k) => CleartextSignedMessage::sign(rng, text, k, pw),
        }
    }
}

#[derive(Clone, Copy)]
enum SelectedVerifyingKey<'a> {
    Primary(&'a PublicKey),
    Sub(&'a SignedPublicSubKey),
}

impl<'a> SelectedVerifyingKey<'a> {
    fn verify_detached(self, sig: &Signature, clear_data: &[u8]) -> pgp::errors::Result<()> {
        match self {
            Self::Primary(k) => sig.verify(k, clear_data),
            Self::Sub(k) => sig.verify(k, clear_data),
        }
    }

    fn verify_cleartext(self, msg: &CleartextSignedMessage) -> pgp::errors::Result<()> {
        match self {
            Self::Primary(k) => msg.verify(k).map(|_| ()),
            Self::Sub(k) => msg.verify(k).map(|_| ()),
        }
    }
}

fn select_encryption_keys<'a>(pub_key: &'a SignedPublicKey) -> Vec<SelectedEncryptionKey<'a>> {
    let mut keys = Vec::new();
    for sub in &pub_key.public_subkeys {
        if can_encrypt_alg(sub.algorithm()) {
            let flagged = sub
                .signatures
                .iter()
                .any(|s| s.key_flags().encrypt_storage() || s.key_flags().encrypt_comms());
            if flagged {
                keys.push(SelectedEncryptionKey::Sub(sub));
            }
        }
    }
    if keys.is_empty() {
        for sub in &pub_key.public_subkeys {
            if can_encrypt_alg(sub.algorithm()) {
                keys.push(SelectedEncryptionKey::Sub(sub));
            }
        }
    }
    if keys.is_empty() && can_encrypt_alg(pub_key.primary_key.algorithm()) {
        keys.push(SelectedEncryptionKey::Primary(&pub_key.primary_key));
    }
    keys
}

fn select_signing_key<'a>(sec_key: &'a SignedSecretKey) -> Result<SelectedSigningKey<'a>, String> {
    let primary_can_sign = can_sign_alg(sec_key.primary_key.algorithm());
    let primary_flagged_sign = sec_key
        .details
        .direct_signatures
        .iter()
        .any(|s| s.key_flags().sign())
        || sec_key
            .details
            .users
            .iter()
            .any(|u| u.signatures.iter().any(|s| s.key_flags().sign()));

    if primary_can_sign && primary_flagged_sign {
        return Ok(SelectedSigningKey::Primary(&sec_key.primary_key));
    }
    for sub in &sec_key.secret_subkeys {
        if can_sign_alg(sub.algorithm()) && sub.signatures.iter().any(|s| s.key_flags().sign()) {
            return Ok(SelectedSigningKey::Sub(&sub.key));
        }
    }
    if primary_can_sign {
        return Ok(SelectedSigningKey::Primary(&sec_key.primary_key));
    }
    for sub in &sec_key.secret_subkeys {
        if can_sign_alg(sub.algorithm()) {
            return Ok(SelectedSigningKey::Sub(&sub.key));
        }
    }
    Err("No signing-capable key packet found in secret key".to_string())
}

fn collect_verifying_keys<'a>(pub_key: &'a SignedPublicKey) -> Vec<SelectedVerifyingKey<'a>> {
    let mut keys = Vec::new();
    if can_sign_alg(pub_key.primary_key.algorithm()) {
        keys.push(SelectedVerifyingKey::Primary(&pub_key.primary_key));
    }
    for sub in &pub_key.public_subkeys {
        if can_sign_alg(sub.algorithm()) {
            keys.push(SelectedVerifyingKey::Sub(sub));
        }
    }
    if keys.is_empty() {
        keys.push(SelectedVerifyingKey::Primary(&pub_key.primary_key));
    }
    keys
}

fn build_signing_subpackets(
    signer: SelectedSigningKey<'_>,
    context: Option<&SignContext>,
) -> Result<SubpacketConfig, String> {
    let Some(ctx) = context else {
        return Ok(SubpacketConfig::Default);
    };

    let notation = Notation {
        readable: true,
        name: Bytes::from_static(PROTON_CONTEXT_NOTATION),
        value: Bytes::from(ctx.value.as_bytes().to_vec()),
    };
    let notation_sp = if ctx.is_critical {
        Subpacket::critical(SubpacketData::Notation(notation))
    } else {
        Subpacket::regular(SubpacketData::Notation(notation))
    }
    .map_err(|e| format!("Failed creating notation subpacket: {}", e))?;

    let hashed = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))
            .map_err(|e| format!("Failed creating IssuerFingerprint subpacket: {}", e))?,
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
            .map_err(|e| format!("Failed creating SignatureCreationTime subpacket: {}", e))?,
        notation_sp,
    ];

    let mut unhashed = Vec::new();
    if signer.version() <= KeyVersion::V4 {
        unhashed.push(
            Subpacket::regular(SubpacketData::IssuerKeyId(signer.legacy_key_id()))
                .map_err(|e| format!("Failed creating IssuerKeyId subpacket: {}", e))?,
        );
    }

    Ok(SubpacketConfig::UserDefined { hashed, unhashed })
}

fn verify_signature_context(
    sig: &Signature,
    context: Option<&VerificationContext>,
    verify_time: Option<u64>,
) -> Result<(), String> {
    let Some(ctx) = context else {
        return Ok(());
    };
    let Some(config) = sig.config() else {
        return Err("Signature config unavailable for context verification".to_string());
    };

    let mut created_at: u64 = 0;
    let mut found_contexts: Vec<String> = Vec::new();

    for sp in config.hashed_subpackets() {
        match &sp.data {
            SubpacketData::SignatureCreationTime(ts) => {
                created_at = ts.as_secs() as u64;
            }
            SubpacketData::Notation(n) if n.name.as_ref() == PROTON_CONTEXT_NOTATION => {
                let s = String::from_utf8(n.value.to_vec())
                    .map_err(|_| "Invalid UTF-8 in context@proton.ch notation".to_string())?;
                found_contexts.push(s);
            }
            SubpacketData::Notation(_) if sp.is_critical => {
                return Err(
                    "Signature contains unrecognized critical notation subpacket".to_string(),
                );
            }
            _ => {}
        }
    }

    if let Some(vt) = verify_time {
        if created_at > vt {
            return Err(format!(
                "Signature creation time {} is after verify_time {}",
                created_at, vt
            ));
        }
    }

    for actual in &found_contexts {
        if actual != &ctx.value {
            return Err(format!(
                "Signing context mismatch: expected '{}', got '{}'",
                ctx.value, actual
            ));
        }
    }

    if let VerificationRequired::RequiredAfter(since) = ctx.required {
        if created_at >= since && found_contexts.is_empty() {
            return Err(format!(
                "Signature missing required signing context '{}'",
                ctx.value
            ));
        }
    }

    Ok(())
}

// ============================================================================
// DriveKey Serialization / Parsing / Unlocking
// ============================================================================

pub struct DriveKey;

impl DriveKey {
    /// Generates an RFC 4880 v4 Curve25519 OpenPGP key (Ed25519 primary + ECDH X25519 subkey),
    /// matching Proton's `HelperGenerateKey(..., "x25519", 0)` profile.
    pub fn generate(name: &str, email: &str, passphrase: &str) -> Result<String, String> {
        let mut rng = thread_rng();
        let uid_str = if email.is_empty() {
            name.to_string()
        } else {
            format!("{} <{}>", name, email)
        };
        let pw_opt = if passphrase.is_empty() {
            None
        } else {
            Some(passphrase.to_string())
        };

        let subkey = SubkeyParamsBuilder::default()
            .version(KeyVersion::V4)
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_encrypt(EncryptionCaps::All)
            .passphrase(pw_opt.clone())
            .build()
            .map_err(|e| format!("Failed building subkey params: {}", e))?;

        let key_params = SecretKeyParamsBuilder::default()
            .version(KeyVersion::V4)
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(uid_str)
            .passphrase(pw_opt)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha256, HashAlgorithm::Sha512])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkeys(vec![subkey])
            .build()
            .map_err(|e| format!("Failed building OpenPGP secret key params: {}", e))?;

        let signed_key = key_params
            .generate(&mut rng)
            .map_err(|e| format!("Failed generating OpenPGP key: {}", e))?;

        signed_key
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("Failed armoring generated OpenPGP key: {}", e))
    }

    pub fn public_key_armored(armored: &str) -> Result<String, String> {
        let pub_key = parse_signed_public_key(armored)?;
        pub_key
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("Failed armoring OpenPGP public key: {}", e))
    }

    pub fn unlock(armored_private: &str, passphrase: &str) -> Result<UnlockedKey, String> {
        let (secret_key, _) = SignedSecretKey::from_string(armored_private)
            .map_err(|e| format!("Failed parsing OpenPGP private key: {}", e))?;
        let pw = Password::from(passphrase);

        secret_key
            .primary_key
            .unlock(&pw, |_, _| Ok(()))
            .map_err(|e| format!("Wrong passphrase or corrupt primary private key: {}", e))?
            .map_err(|e| format!("Primary private key unlock callback failed: {}", e))?;

        for sub in &secret_key.secret_subkeys {
            sub.key
                .unlock(&pw, |_, _| Ok(()))
                .map_err(|e| format!("Wrong passphrase or corrupt secret subkey: {}", e))?
                .map_err(|e| format!("Secret subkey unlock callback failed: {}", e))?;
        }

        let public_key = secret_key.to_public_key();
        let armored_public = public_key
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("Failed armoring public key: {}", e))?;

        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(secret_key.primary_key.legacy_key_id().as_ref());

        let mut subkey_id = key_id;
        if let Some(sub) = secret_key.secret_subkeys.first() {
            subkey_id.copy_from_slice(sub.legacy_key_id().as_ref());
        }

        let mut fingerprint = [0u8; 20];
        let fp_bytes = secret_key.primary_key.fingerprint();
        let fp_slice = fp_bytes.as_bytes();
        let copy_len = fp_slice.len().min(20);
        fingerprint[..copy_len].copy_from_slice(&fp_slice[..copy_len]);

        Ok(UnlockedKey {
            key_id,
            subkey_id,
            fingerprint,
            secret_key,
            passphrase: Zeroizing::new(passphrase.to_string()),
            armored_public,
            armored_private: armored_private.to_string(),
        })
    }
}

// ============================================================================
// Signatures & Proton Contexts
// ============================================================================

pub struct DriveCrypto;

impl DriveCrypto {
    pub fn key_packets_count(armored_message: &str) -> Result<usize, String> {
        let block = dearmor(armored_message)?;
        let packets = decode_packets(&block.body)?;
        Ok(packets
            .iter()
            .filter(|(tag, _)| *tag == PACKET_PKESK)
            .count())
    }

    pub fn sign_str(
        input: &str,
        context: &SignContext,
        private_key: &str,
        passphrase: &str,
    ) -> Result<Vec<u8>, String> {
        let trimmed = trim_trailing_line_spaces(input);
        let unlocked = DriveKey::unlock(private_key, passphrase)?;
        Self::sign_text_unlocked(&trimmed, Some(context), &unlocked)
    }

    pub fn sign_str_armored(
        input: &str,
        context: &SignContext,
        private_key: &str,
        passphrase: &str,
    ) -> Result<String, String> {
        let trimmed = trim_trailing_line_spaces(input);
        let unlocked = DriveKey::unlock(private_key, passphrase)?;
        let sig = Self::sign_detached_internal(trimmed.as_bytes(), true, Some(context), &unlocked)?;
        sig.to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("Failed armoring signature: {}", e))
    }

    pub fn sign_bytes(
        input: &[u8],
        context: Option<&SignContext>,
        private_key: &str,
        passphrase: &str,
    ) -> Result<Vec<u8>, String> {
        let unlocked = DriveKey::unlock(private_key, passphrase)?;
        Self::sign_bytes_unlocked(input, context, &unlocked)
    }

    pub fn sign_bytes_unlocked(
        input: &[u8],
        context: Option<&SignContext>,
        unlocked: &UnlockedKey,
    ) -> Result<Vec<u8>, String> {
        let sig = Self::sign_detached_internal(input, false, context, unlocked)?;
        sig.to_bytes()
            .map_err(|e| format!("Failed serializing detached signature: {}", e))
    }

    fn sign_text_unlocked(
        input: &str,
        context: Option<&SignContext>,
        unlocked: &UnlockedKey,
    ) -> Result<Vec<u8>, String> {
        let sig = Self::sign_detached_internal(input.as_bytes(), true, context, unlocked)?;
        sig.to_bytes()
            .map_err(|e| format!("Failed serializing detached text signature: {}", e))
    }

    fn sign_detached_internal(
        input: &[u8],
        is_text: bool,
        context: Option<&SignContext>,
        unlocked: &UnlockedKey,
    ) -> Result<DetachedSignature, String> {
        let mut rng = thread_rng();
        let signer = select_signing_key(&unlocked.secret_key)?;
        let pw = unlocked.pgp_password();
        let subpackets = build_signing_subpackets(signer, context)?;
        let hash_alg = HashAlgorithm::Sha256;

        if is_text {
            signer.sign_detached_with_subpackets(&mut rng, &pw, hash_alg, input, subpackets, true)
        } else {
            signer.sign_detached_with_subpackets(&mut rng, &pw, hash_alg, input, subpackets, false)
        }
        .map_err(|e| format!("OpenPGP signing failed: {}", e))
    }

    pub fn sign_bytes_armored(
        input: &[u8],
        context: Option<&SignContext>,
        private_key: &str,
        passphrase: &str,
    ) -> Result<String, String> {
        let unlocked = DriveKey::unlock(private_key, passphrase)?;
        let sig = Self::sign_detached_internal(input, false, context, &unlocked)?;
        sig.to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("Failed armoring OpenPGP signature: {}", e))
    }

    pub fn verify_detached_str(
        armored_signature: &str,
        clear_text: &str,
        verification_keys: &[String],
        context: Option<&VerificationContext>,
        verify_time: Option<u64>,
    ) -> Result<(), String> {
        let trimmed = trim_trailing_line_spaces(clear_text);
        Self::verify_detached_armored(
            armored_signature,
            trimmed.as_bytes(),
            verification_keys,
            context,
            verify_time,
        )
    }

    pub fn verify_detached_armored(
        armored_signature: &str,
        clear_data: &[u8],
        verification_keys: &[String],
        context: Option<&VerificationContext>,
        verify_time: Option<u64>,
    ) -> Result<(), String> {
        let (sig, _) = DetachedSignature::from_string(armored_signature)
            .map_err(|e| format!("Failed parsing armored OpenPGP signature: {}", e))?;
        Self::verify_detached_obj(&sig, clear_data, verification_keys, context, verify_time)
    }

    pub fn verify_detached(
        signature_packet: &[u8],
        clear_data: &[u8],
        verification_keys: &[String],
        context: Option<&VerificationContext>,
        verify_time: Option<u64>,
    ) -> Result<(), String> {
        let sig = DetachedSignature::from_bytes(signature_packet)
            .map_err(|e| format!("Failed parsing binary OpenPGP signature: {}", e))?;
        Self::verify_detached_obj(&sig, clear_data, verification_keys, context, verify_time)
    }

    fn verify_detached_obj(
        sig: &DetachedSignature,
        clear_data: &[u8],
        verification_keys: &[String],
        context: Option<&VerificationContext>,
        verify_time: Option<u64>,
    ) -> Result<(), String> {
        let mut parsed_keys = Vec::new();
        for key_armored in verification_keys {
            if let Ok(pk) = parse_signed_public_key(key_armored) {
                parsed_keys.push(pk);
            }
        }
        if parsed_keys.is_empty() {
            return Err("No valid verification keys provided".to_string());
        }

        let mut last_err = "Signature verification failed".to_string();
        for pk in &parsed_keys {
            for vk in collect_verifying_keys(pk) {
                if let Err(e) = vk.verify_detached(&sig.signature, clear_data) {
                    last_err = e.to_string();
                    continue;
                }
                verify_signature_context(&sig.signature, context, verify_time)?;
                return Ok(());
            }
        }
        Err(format!(
            "Signature verification failed against provided verification keys: {}",
            last_err
        ))
    }

    /// Signs `text` as an RFC 4880 Cleartext Signed Message.
    pub fn sign_cleartext(
        text: &str,
        private_key: &str,
        passphrase: &str,
    ) -> Result<String, String> {
        let unlocked = DriveKey::unlock(private_key, passphrase)?;
        let signer = select_signing_key(&unlocked.secret_key)?;
        let pw = unlocked.pgp_password();
        let mut rng = thread_rng();
        let msg = signer
            .sign_cleartext(&mut rng, text, &pw)
            .map_err(|e| format!("Failed creating cleartext signed message: {}", e))?;
        msg.to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("Failed armoring cleartext signed message: {}", e))
    }

    /// Verifies an OpenPGP Cleartext Signed Message (such as Proton's `/auth/v4/info` modulus)
    /// against `verification_keys` and returns the normalized signed text.
    pub fn verify_cleartext_signed(
        cleartext_msg: &str,
        verification_keys: &[String],
    ) -> Result<String, String> {
        let (msg, _) = CleartextSignedMessage::from_string(cleartext_msg)
            .map_err(|e| format!("Failed parsing OpenPGP cleartext signed message: {}", e))?;

        let mut parsed_keys = Vec::new();
        for key_armored in verification_keys {
            if let Ok(pk) = parse_signed_public_key(key_armored) {
                parsed_keys.push(pk);
            }
        }
        if parsed_keys.is_empty() {
            return Err("No valid verification keys provided".to_string());
        }

        for pk in &parsed_keys {
            for vk in collect_verifying_keys(pk) {
                if vk.verify_cleartext(&msg).is_ok() {
                    return Ok(msg.signed_text());
                }
            }
        }

        Err("Cleartext signature verification failed against provided keys".to_string())
    }
}

fn trim_trailing_line_spaces(s: &str) -> String {
    s.lines()
        .map(|l| l.trim_end_matches(' '))
        .collect::<Vec<_>>()
        .join("\n")
}

// ============================================================================
// Split PKESK + SEIPD Packet Helpers
// ============================================================================

fn decrypt_session_key_from_pkesks(
    pkesks: &[PublicKeyEncryptedSessionKey],
    unlocked: &UnlockedKey,
) -> Result<PlainSessionKey, String> {
    let pw = unlocked.pgp_password();

    for pkesk in pkesks {
        let typ = match pkesk.version() {
            PkeskVersion::V3 => EskType::V3_4,
            PkeskVersion::V6 => EskType::V6,
            PkeskVersion::Other(_) => continue,
        };
        let Ok(values) = pkesk.values() else {
            continue;
        };

        for sub in &unlocked.secret_key.secret_subkeys {
            if pkesk.match_identity(sub.public_key()) {
                if let Ok(Ok(sk)) = sub.key.decrypt(&pw, values, typ) {
                    return Ok(sk);
                }
            }
        }

        if pkesk.match_identity(unlocked.secret_key.primary_key.public_key()) {
            if let Ok(Ok(sk)) = unlocked.secret_key.primary_key.decrypt(&pw, values, typ) {
                return Ok(sk);
            }
        }
    }

    // Fallback: try non-matching key IDs in case of anonymous/wildcard PKESK or rotated subkeys
    for pkesk in pkesks {
        let typ = match pkesk.version() {
            PkeskVersion::V3 => EskType::V3_4,
            PkeskVersion::V6 => EskType::V6,
            PkeskVersion::Other(_) => continue,
        };
        let Ok(values) = pkesk.values() else {
            continue;
        };
        for sub in &unlocked.secret_key.secret_subkeys {
            if let Ok(Ok(sk)) = sub.key.decrypt(&pw, values, typ) {
                return Ok(sk);
            }
        }
        if let Ok(Ok(sk)) = unlocked.secret_key.primary_key.decrypt(&pw, values, typ) {
            return Ok(sk);
        }
    }

    Err("No matching PKESK packet could be decrypted with the provided key".to_string())
}

fn plain_session_key_to_session_key(sk: PlainSessionKey) -> Result<SessionKey, String> {
    match &sk {
        PlainSessionKey::V3_4 { sym_alg, key } => {
            SessionKey::from_bytes_with_alg(key.as_ref(), *sym_alg)
        }
        PlainSessionKey::V5 { key } | PlainSessionKey::V6 { key } => {
            SessionKey::from_bytes_with_alg(key.as_ref(), SymmetricKeyAlgorithm::AES256)
        }
    }
}

fn split_armored_packets(
    armored_message: &str,
) -> Result<(Vec<PublicKeyEncryptedSessionKey>, Vec<Packet>), String> {
    let block = dearmor(armored_message)?;
    let parser = PacketParser::new(&block.body[..]);
    let mut pkesks = Vec::new();
    let mut rest = Vec::new();
    for res in parser {
        let pkt = res.map_err(|e| format!("Failed parsing OpenPGP message packet: {}", e))?;
        match pkt {
            Packet::PublicKeyEncryptedSessionKey(p) => pkesks.push(p),
            other => rest.push(other),
        }
    }
    if rest.is_empty() {
        return Err("Missing encrypted data packet in OpenPGP message".to_string());
    }
    Ok((pkesks, rest))
}

struct PacketSlice<'a>(&'a [Packet]);

impl PgpSerialize for PacketSlice<'_> {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> pgp::errors::Result<()> {
        for pkt in self.0 {
            pkt.to_writer(writer)?;
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.0.iter().map(PgpSerialize::write_len).sum()
    }
}

fn armor_packet_sequence(packets: &[Packet]) -> Result<String, String> {
    let mut out = Vec::new();
    armor::write(
        &PacketSlice(packets),
        BlockType::Message,
        &mut out,
        None,
        true,
    )
    .map_err(|e| format!("Failed armoring OpenPGP message: {}", e))?;
    String::from_utf8(out).map_err(|e| format!("Armored message is not UTF-8: {}", e))
}

// ============================================================================
// Decryptor & Encryptor & NameHasher
// ============================================================================

pub struct Decryptor;

impl Decryptor {
    pub fn decrypt_attached_text_message(
        armored_message: &str,
        decryption_keys: &[UnlockedKey],
    ) -> Result<String, String> {
        let (plain, _) = Self::decrypt_attached_raw(armored_message, decryption_keys, None)?;
        String::from_utf8(plain).map_err(|e| format!("Decrypted message is not UTF-8: {}", e))
    }

    pub fn decrypt_and_verify_share_passphrase(
        armored_passphrase: &str,
        armored_signature: &str,
        verification_keys: &[String],
        decryption_keys: &[UnlockedKey],
    ) -> Result<VerifiedText, String> {
        Self::decrypt_and_verify_detached_text(
            armored_passphrase,
            armored_signature,
            decryption_keys,
            verification_keys,
        )
    }

    pub fn decrypt_and_verify_node_passphrase(
        armored_passphrase: &str,
        armored_signature: &str,
        verification_keys: &[String],
        decryption_keys: &[UnlockedKey],
    ) -> Result<VerifiedText, String> {
        Self::decrypt_and_verify_detached_text(
            armored_passphrase,
            armored_signature,
            decryption_keys,
            verification_keys,
        )
    }

    pub fn decrypt_and_verify_node_name(
        armored_name: &str,
        decryption_key: &UnlockedKey,
        verification_keys: &[String],
    ) -> Result<VerifiedText, String> {
        Self::decrypt_and_verify_attached_text(
            armored_name,
            std::slice::from_ref(decryption_key),
            verification_keys,
        )
    }

    pub fn decrypt_and_verify_node_hash_key(
        armored_hash_key: &str,
        decryption_keys: &[UnlockedKey],
        verification_keys: &[String],
    ) -> Result<VerifiedBinary, String> {
        Self::decrypt_and_verify_attached_binary(
            armored_hash_key,
            decryption_keys,
            verification_keys,
        )
    }

    pub fn decrypt_content_key_packet(
        key_packet: &[u8],
        decryption_key: &UnlockedKey,
    ) -> Result<SessionKey, String> {
        let parser = PacketParser::new(key_packet);
        let mut pkesks = Vec::new();
        for res in parser {
            let pkt = res.map_err(|e| format!("Failed parsing ContentKeyPacket: {}", e))?;
            if let Packet::PublicKeyEncryptedSessionKey(p) = pkt {
                pkesks.push(p);
            }
        }
        let plain_sk = decrypt_session_key_from_pkesks(&pkesks, decryption_key)?;
        plain_session_key_to_session_key(plain_sk)
    }

    pub fn decrypt_and_verify_content_key_packet(
        key_packet: &[u8],
        decryption_key: &UnlockedKey,
        signature: Option<&str>,
        verification_keys: &[String],
    ) -> Result<VerifiedBinary, String> {
        let sk = Self::decrypt_content_key_packet(key_packet, decryption_key)?;
        let sk_bytes = sk.as_bytes().to_vec();
        let Some(sig) = signature else {
            return Ok(VerifiedBinary::Unverified(
                sk_bytes,
                "Missing content key packet signature".to_string(),
            ));
        };
        if DriveCrypto::verify_detached_armored(sig, &sk_bytes, verification_keys, None, None)
            .is_ok()
        {
            return Ok(VerifiedBinary::Verified(sk_bytes));
        }
        match DriveCrypto::verify_detached_armored(sig, key_packet, verification_keys, None, None) {
            Ok(()) => Ok(VerifiedBinary::Verified(sk_bytes)),
            Err(e) => Ok(VerifiedBinary::Unverified(sk_bytes, e)),
        }
    }

    pub fn decrypt_and_verify_xattributes(
        armored_xattr: &str,
        decryption_key: &UnlockedKey,
        verification_keys: &[String],
    ) -> Result<VerifiedBinary, String> {
        Self::decrypt_and_verify_attached_binary(
            armored_xattr,
            std::slice::from_ref(decryption_key),
            verification_keys,
        )
    }

    pub fn decrypt_block_signature(
        encrypted_signature: &str,
        node_key: &UnlockedKey,
    ) -> Result<String, String> {
        let (plain, _) =
            Self::decrypt_attached_raw(encrypted_signature, std::slice::from_ref(node_key), None)?;
        let sig = DetachedSignature::from_bytes(&plain[..])
            .or_else(|bin_err| {
                std::str::from_utf8(&plain)
                    .ok()
                    .and_then(|s| DetachedSignature::from_string(s).ok().map(|(sig, _)| sig))
                    .ok_or(bin_err)
            })
            .map_err(|e| {
                format!(
                    "Decrypted block signature is not valid OpenPGP signature: {}",
                    e
                )
            })?;
        sig.to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("Failed armoring decrypted block signature: {}", e))
    }

    pub fn decrypt_block_with_session_key(
        block_data_packet: &[u8],
        session_key: &SessionKey,
    ) -> Result<Vec<u8>, String> {
        let msg = Message::from_bytes(block_data_packet)
            .map_err(|e| format!("Failed parsing block OpenPGP packet: {}", e))?;
        let raw_sk = RawSessionKey::from(session_key.as_bytes().as_slice());
        // rPGP rejects PlainSessionKey::V3_4 for SEIPD v2 (RFC 9580 AEAD) packets and
        // rejects PlainSessionKey::V6 for SEIPD v1 packets, so match the container version.
        let plain_sk = match &msg {
            Message::Encrypted {
                edata: Edata::SymEncryptedProtectedData { reader },
                ..
            } if matches!(
                reader.config(),
                ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V2 { .. })
            ) =>
            {
                PlainSessionKey::V6 { key: raw_sk }
            }
            _ => PlainSessionKey::V3_4 {
                sym_alg: session_key.sym_alg,
                key: raw_sk,
            },
        };
        let mut decrypted = msg
            .decrypt_with_session_key(plain_sk)
            .map_err(|e| format!("Failed decrypting block with session key: {}", e))?;
        while decrypted.is_compressed() {
            decrypted = decrypted
                .decompress()
                .map_err(|e| format!("Failed decompressing block: {}", e))?;
        }
        decrypted
            .as_data_vec()
            .map_err(|e| format!("Failed reading decrypted block payload: {}", e))
    }

    pub fn decrypt_and_verify_block(
        block_data_packet: &[u8],
        session_key: &SessionKey,
        armored_signature: &str,
        verification_keys: &[String],
    ) -> Result<VerifiedBinary, String> {
        let plain = Self::decrypt_block_with_session_key(block_data_packet, session_key)?;
        match DriveCrypto::verify_detached_armored(
            armored_signature,
            &plain,
            verification_keys,
            None,
            None,
        ) {
            Ok(()) => Ok(VerifiedBinary::Verified(plain)),
            Err(e) => Ok(VerifiedBinary::Unverified(plain, e)),
        }
    }

    pub fn verify_manifest_signature(
        manifest_bytes: &[u8],
        armored_signature: &str,
        verification_keys: &[String],
    ) -> Result<(), String> {
        DriveCrypto::verify_detached_armored(
            armored_signature,
            manifest_bytes,
            verification_keys,
            None,
            None,
        )
    }

    fn decrypt_attached_raw(
        armored_message: &str,
        decryption_keys: &[UnlockedKey],
        verification_keys: Option<&[String]>,
    ) -> Result<(Vec<u8>, Result<(), String>), String> {
        let (msg, _) = Message::from_string(armored_message)
            .map_err(|e| format!("Failed parsing armored OpenPGP message: {}", e))?;

        let secret_keys: Vec<&SignedSecretKey> =
            decryption_keys.iter().map(|k| &k.secret_key).collect();
        let passwords: Vec<Password> = decryption_keys.iter().map(|k| k.pgp_password()).collect();
        let password_refs: Vec<&Password> = passwords.iter().collect();

        let mut current = if msg.is_encrypted() {
            msg.decrypt_with_keys(password_refs, secret_keys)
                .map_err(|e| format!("Failed decrypting OpenPGP message: {}", e))?
        } else {
            msg
        };

        while current.is_compressed() {
            current = current
                .decompress()
                .map_err(|e| format!("Failed decompressing OpenPGP message: {}", e))?;
        }
        if matches!(current, Message::Signed { .. }) {
            current = current
                .decompress()
                .map_err(|e| format!("Failed decompressing signed OpenPGP message: {}", e))?;
        }

        let plain = current
            .as_data_vec()
            .map_err(|e| format!("Failed reading OpenPGP literal payload: {}", e))?;

        let sig_res = match verification_keys {
            None => Ok(()),
            Some(vkeys) => {
                if !current.is_signed() {
                    Err("Message has no attached signature".to_string())
                } else {
                    let mut parsed = Vec::new();
                    for ka in vkeys {
                        if let Ok(pk) = parse_signed_public_key(ka) {
                            parsed.push(pk);
                        }
                    }
                    if parsed.is_empty() {
                        Err("No valid verification keys provided".to_string())
                    } else {
                        let mut verified = false;
                        let mut last_err = "Signature verification failed".to_string();
                        'outer: for pk in &parsed {
                            for vk in collect_verifying_keys(pk) {
                                let res = match vk {
                                    SelectedVerifyingKey::Primary(k) => current.verify(k),
                                    SelectedVerifyingKey::Sub(k) => current.verify(k),
                                };
                                match res {
                                    Ok(_) => {
                                        verified = true;
                                        break 'outer;
                                    }
                                    Err(e) => last_err = e.to_string(),
                                }
                            }
                        }
                        if verified {
                            Ok(())
                        } else {
                            Err(last_err)
                        }
                    }
                }
            }
        };

        Ok((plain, sig_res))
    }

    fn decrypt_and_verify_attached_text(
        armored_message: &str,
        decryption_keys: &[UnlockedKey],
        verification_keys: &[String],
    ) -> Result<VerifiedText, String> {
        let bin = Self::decrypt_and_verify_attached_binary(
            armored_message,
            decryption_keys,
            verification_keys,
        )?;
        match bin {
            VerifiedBinary::Verified(b) => {
                let s = String::from_utf8(b)
                    .map_err(|e| format!("Decrypted text is not UTF-8: {}", e))?;
                Ok(VerifiedText::Verified(s))
            }
            VerifiedBinary::Unverified(b, err) => {
                let s = String::from_utf8(b)
                    .map_err(|e| format!("Decrypted text is not UTF-8: {}", e))?;
                Ok(VerifiedText::Unverified(s, err))
            }
        }
    }

    fn decrypt_and_verify_attached_binary(
        armored_message: &str,
        decryption_keys: &[UnlockedKey],
        verification_keys: &[String],
    ) -> Result<VerifiedBinary, String> {
        let (plain, sig_res) =
            Self::decrypt_attached_raw(armored_message, decryption_keys, Some(verification_keys))?;
        match sig_res {
            Ok(()) => Ok(VerifiedBinary::Verified(plain)),
            Err(e) => Ok(VerifiedBinary::Unverified(plain, e)),
        }
    }

    fn decrypt_and_verify_detached_text(
        armored_message: &str,
        armored_signature: &str,
        decryption_keys: &[UnlockedKey],
        verification_keys: &[String],
    ) -> Result<VerifiedText, String> {
        let text = Self::decrypt_attached_text_message(armored_message, decryption_keys)?;
        match DriveCrypto::verify_detached_armored(
            armored_signature,
            text.as_bytes(),
            verification_keys,
            None,
            None,
        ) {
            Ok(()) => Ok(VerifiedText::Verified(text)),
            Err(e) => Ok(VerifiedText::Unverified(text, e)),
        }
    }
}

pub struct Encryptor;

impl Encryptor {
    pub fn hmac(filename: &str, parent_hash_key: &[u8]) -> Result<String, String> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, parent_hash_key);
        let tag = hmac::sign(&key, filename.as_bytes());
        Ok(hex::encode(tag.as_ref()))
    }

    pub fn encrypt_text(cleartext: &str, recipient_key: &str) -> Result<String, String> {
        Self::encrypt_bytes_internal(cleartext.as_bytes(), recipient_key, None, false)
    }

    pub fn encrypt_and_sign_text(
        cleartext: &str,
        recipient_key: &str,
        address_passphrase: &str,
        address_private_key: &str,
    ) -> Result<String, String> {
        let signer = DriveKey::unlock(address_private_key, address_passphrase)?;
        Self::encrypt_bytes_internal(cleartext.as_bytes(), recipient_key, Some(&signer), false)
    }

    pub fn encrypt_and_sign_bytes(
        plain: &[u8],
        recipient_key: &str,
        address_passphrase: &str,
        address_private_key: &str,
        compress: bool,
    ) -> Result<String, String> {
        let signer = DriveKey::unlock(address_private_key, address_passphrase)?;
        Self::encrypt_bytes_internal(plain, recipient_key, Some(&signer), compress)
    }

    fn encrypt_bytes_internal(
        plain: &[u8],
        recipient_key: &str,
        signer: Option<&UnlockedKey>,
        compress: bool,
    ) -> Result<String, String> {
        let recipient_pub = parse_signed_public_key(recipient_key)?;
        let enc_keys = select_encryption_keys(&recipient_pub);
        if enc_keys.is_empty() {
            return Err("Recipient OpenPGP key has no encryption-capable key".to_string());
        }

        let mut rng = thread_rng();
        let mut builder = MessageBuilder::from_bytes("", Bytes::copy_from_slice(plain));
        if compress {
            builder.compression(CompressionAlgorithm::ZLIB);
        }
        if let Some(s) = signer {
            match select_signing_key(&s.secret_key)? {
                SelectedSigningKey::Primary(k) => {
                    builder.sign(k, s.pgp_password(), HashAlgorithm::Sha256);
                }
                SelectedSigningKey::Sub(k) => {
                    builder.sign(k, s.pgp_password(), HashAlgorithm::Sha256);
                }
            }
        }

        let mut enc_builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        for ek in enc_keys {
            match ek {
                SelectedEncryptionKey::Primary(k) => enc_builder.encrypt_to_key(&mut rng, k),
                SelectedEncryptionKey::Sub(k) => enc_builder.encrypt_to_key(&mut rng, k),
            }
            .map_err(|e| format!("Failed encrypting session key to recipient: {}", e))?;
        }

        enc_builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .map_err(|e| format!("Failed building encrypted OpenPGP message: {}", e))
    }

    pub fn generate_node_keys(
        address_passphrase: &str,
        address_private_key: &str,
        parent_key: &str,
    ) -> Result<KeyCredentials, String> {
        let raw = random_bytes(32)?;
        let passphrase_raw = Zeroizing::new(BASE64.encode(raw));
        let node_key = DriveKey::generate("Drive key", "noreply@protonmail.com", &passphrase_raw)?;
        let (encrypted_passphrase, signature) = Self::update_node_keys(
            &passphrase_raw,
            address_passphrase,
            address_private_key,
            parent_key,
        )?;
        Ok(KeyCredentials {
            key: node_key,
            passphrase: encrypted_passphrase,
            signature,
            passphrase_raw,
        })
    }

    pub fn update_node_keys(
        passphrase_raw: &str,
        address_passphrase: &str,
        address_private_key: &str,
        parent_key: &str,
    ) -> Result<(String, String), String> {
        let encrypted_passphrase = Self::encrypt_text(passphrase_raw, parent_key)?;
        let signature = DriveCrypto::sign_bytes_armored(
            passphrase_raw.as_bytes(),
            None,
            address_private_key,
            address_passphrase,
        )?;
        Ok((encrypted_passphrase, signature))
    }

    pub fn generate_node_hash_key(
        node_private_key: &str,
        node_passphrase: &str,
    ) -> Result<String, String> {
        let raw_hash_key = Zeroizing::new(random_bytes(32)?);
        let b64_hash_key = Zeroizing::new(BASE64.encode(&*raw_hash_key));
        Self::encrypt_and_sign_bytes(
            b64_hash_key.as_bytes(),
            node_private_key,
            node_passphrase,
            node_private_key,
            false,
        )
    }

    pub fn generate_content_session_key(
        node_key: &str,
        signing_private_key: &str,
        signing_passphrase: &str,
    ) -> Result<(SessionKey, Vec<u8>, String, String), String> {
        let sk = SessionKey::generate()?;
        let packet = Self::encrypt_session_key_packet(&sk, node_key)?;
        let packet_b64 = BASE64.encode(&packet);
        let packet_sig = DriveCrypto::sign_bytes_armored(
            sk.as_bytes(),
            None,
            signing_private_key,
            signing_passphrase,
        )?;
        Ok((sk, packet, packet_b64, packet_sig))
    }

    pub fn encrypt_session_key_packet(
        session_key: &SessionKey,
        recipient_key: &str,
    ) -> Result<Vec<u8>, String> {
        let recipient_pub = parse_signed_public_key(recipient_key)?;
        let enc_keys = select_encryption_keys(&recipient_pub);
        if enc_keys.is_empty() {
            return Err("Recipient OpenPGP key has no encryption-capable key".to_string());
        }
        let mut rng = thread_rng();
        let raw_sk = RawSessionKey::from(session_key.as_bytes().as_slice());
        let mut out = Vec::new();
        for ek in enc_keys {
            let pkesk = ek
                .to_pkesk_v3(&mut rng, &raw_sk, session_key.sym_alg)
                .map_err(|e| format!("Failed creating PKESK packet: {}", e))?;
            pkesk
                .to_writer_with_header(&mut out)
                .map_err(|e| format!("Failed serializing PKESK packet: {}", e))?;
        }
        Ok(out)
    }

    pub fn encrypt_block_with_session_key(
        clear_data: &[u8],
        session_key: &SessionKey,
        signing_key: &UnlockedKey,
        node_public_key: &str,
    ) -> Result<(Vec<u8>, String), String> {
        let mut rng = thread_rng();
        let mut builder = MessageBuilder::from_bytes("", Bytes::copy_from_slice(clear_data))
            .seipd_v1(&mut rng, session_key.sym_alg);
        builder
            .set_session_key(RawSessionKey::from(session_key.as_bytes().as_slice()))
            .map_err(|e| format!("Failed setting block session key: {}", e))?;
        let data_packet = builder
            .to_vec(&mut rng)
            .map_err(|e| format!("Failed encrypting block SEIPD packet: {}", e))?;

        let sig_pkt = DriveCrypto::sign_bytes_unlocked(clear_data, None, signing_key)?;
        let encrypted_sig = Self::encrypt_bytes_internal(&sig_pkt, node_public_key, None, false)?;
        Ok((data_packet, encrypted_sig))
    }

    pub fn reencrypt_key_packet(
        armored_message: &str,
        old_parent_key: &str,
        old_parent_passphrase: &str,
        new_parent_key: &str,
    ) -> Result<String, String> {
        let (pkesks, data_packets) = split_armored_packets(armored_message)?;
        let old_unlocked = DriveKey::unlock(old_parent_key, old_parent_passphrase)?;
        let plain_sk = decrypt_session_key_from_pkesks(&pkesks, &old_unlocked)?;
        let session_key = plain_session_key_to_session_key(plain_sk)?;

        let new_pub = parse_signed_public_key(new_parent_key)?;
        let new_enc_keys = select_encryption_keys(&new_pub);
        if new_enc_keys.is_empty() {
            return Err("Target OpenPGP key has no encryption-capable key".to_string());
        }

        let mut rng = thread_rng();
        let raw_sk = RawSessionKey::from(session_key.as_bytes().as_slice());
        let mut combined = Vec::with_capacity(new_enc_keys.len() + data_packets.len());
        for ek in new_enc_keys {
            let pkesk = ek
                .to_pkesk_v3(&mut rng, &raw_sk, session_key.sym_alg)
                .map_err(|e| format!("Failed creating new PKESK: {}", e))?;
            combined.push(Packet::PublicKeyEncryptedSessionKey(pkesk));
        }
        combined.extend(data_packets);
        armor_packet_sequence(&combined)
    }

    pub fn encrypt_pgp_message_to_additional_key(
        armored_message: &str,
        existing_key: &str,
        existing_passphrase: &str,
        additional_key: &str,
    ) -> Result<String, String> {
        let (pkesks, data_packets) = split_armored_packets(armored_message)?;
        let unlocked = DriveKey::unlock(existing_key, existing_passphrase)?;
        let plain_sk = decrypt_session_key_from_pkesks(&pkesks, &unlocked)?;
        let session_key = plain_session_key_to_session_key(plain_sk)?;

        let add_pub = parse_signed_public_key(additional_key)?;
        let add_enc_keys = select_encryption_keys(&add_pub);
        if add_enc_keys.is_empty() {
            return Err("Additional OpenPGP key has no encryption-capable key".to_string());
        }

        let mut rng = thread_rng();
        let raw_sk = RawSessionKey::from(session_key.as_bytes().as_slice());
        let mut combined =
            Vec::with_capacity(add_enc_keys.len() + pkesks.len() + data_packets.len());
        for ek in add_enc_keys {
            let pkesk = ek
                .to_pkesk_v3(&mut rng, &raw_sk, session_key.sym_alg)
                .map_err(|e| format!("Failed creating additional PKESK: {}", e))?;
            combined.push(Packet::PublicKeyEncryptedSessionKey(pkesk));
        }
        for old_p in pkesks {
            combined.push(Packet::PublicKeyEncryptedSessionKey(old_p));
        }
        combined.extend(data_packets);
        armor_packet_sequence(&combined)
    }
}

pub struct NameHasher;

impl NameHasher {
    pub fn hash(clear_name: &str, parent_hash_key: &[u8]) -> Result<String, String> {
        Encryptor::hmac(clear_name, parent_hash_key)
    }
}

// ============================================================================
// Extended Attributes (ExtendedAttributes.swift)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedAttributes {
    #[serde(rename = "Common", skip_serializing_if = "Option::is_none")]
    pub common: Option<ExtendedAttributesCommon>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedAttributesCommon {
    #[serde(rename = "ModificationTime", skip_serializing_if = "Option::is_none")]
    pub modification_time: Option<String>,
    #[serde(rename = "Size", skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(rename = "BlockSizes", skip_serializing_if = "Option::is_none")]
    pub block_sizes: Option<Vec<usize>>,
    #[serde(rename = "Digests", skip_serializing_if = "Option::is_none")]
    pub digests: Option<ExtendedAttributesDigests>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedAttributesDigests {
    #[serde(rename = "SHA1", skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
}

impl ExtendedAttributes {
    pub fn new(
        modification_time: Option<String>,
        size: Option<i64>,
        block_sizes: Option<Vec<usize>>,
        sha1: Option<String>,
    ) -> Self {
        Self {
            common: Some(ExtendedAttributesCommon {
                modification_time,
                size,
                block_sizes,
                digests: sha1.map(|s| ExtendedAttributesDigests { sha1: Some(s) }),
            }),
        }
    }

    pub fn encoded(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("Failed to encode xattr JSON: {}", e))
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("Failed to decode xattr JSON: {}", e))
    }
}

// ============================================================================
// NodeKeyCache (Bounded LRU Cache of Unlocked Node Keys)
// ============================================================================

#[derive(Clone)]
pub struct CachedNodeKeys {
    pub unlocked_key: UnlockedKey,
    pub node_hash_key: Option<Zeroizing<Vec<u8>>>,
    pub share_id: String,
    pub parent_link_id: Option<String>,
    pub name: String,
    pub node_passphrase_raw: Zeroizing<String>,
}

pub struct NodeKeyCache {
    capacity: usize,
    inner: Mutex<NodeKeyCacheInner>,
}

struct NodeKeyCacheInner {
    map: HashMap<String, CachedNodeKeys>,
    order: VecDeque<String>,
}

impl NodeKeyCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(16),
            inner: Mutex::new(NodeKeyCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    pub fn get(&self, link_id: &str) -> Option<CachedNodeKeys> {
        let mut guard = self.inner.lock().unwrap();
        let entry = guard.map.get(link_id).cloned()?;
        guard.order.retain(|id| id != link_id);
        guard.order.push_back(link_id.to_string());
        Some(entry)
    }

    pub fn insert(&self, link_id: impl Into<String>, value: CachedNodeKeys) {
        let id = link_id.into();
        let mut guard = self.inner.lock().unwrap();
        if guard.map.contains_key(&id) {
            guard.order.retain(|x| x != &id);
        } else if guard.map.len() >= self.capacity {
            if let Some(oldest) = guard.order.pop_front() {
                guard.map.remove(&oldest);
            }
        }
        guard.map.insert(id.clone(), value);
        guard.order.push_back(id);
    }

    pub fn invalidate(&self, link_id: &str) {
        let mut guard = self.inner.lock().unwrap();
        guard.map.remove(link_id);
        guard.order.retain(|x| x != link_id);
    }

    pub fn clear(&self) {
        let mut guard = self.inner.lock().unwrap();
        guard.map.clear();
        guard.order.clear();
    }
}

pub fn format_iso8601_utc(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Howard Hinnant's civil-from-days
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hour, min, sec
    )
}

pub fn sha1_hex(data: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    hex::encode(digest.as_ref())
}

/// Incremental SHA-1 hasher for O(1)-memory file transfer digests.
pub struct Sha1Hasher {
    ctx: ring::digest::Context,
}

impl Default for Sha1Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1Hasher {
    pub fn new() -> Self {
        Self {
            ctx: ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
    }

    pub fn finish_hex(self) -> String {
        hex::encode(self.ctx.finish().as_ref())
    }
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn zeroize_string(mut s: String) {
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn current_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[test]
    fn test_armor_crc24_roundtrip_and_corruption_detection() {
        let body = b"proton-drive-openpgp-test-payload";
        let armored = enarmor(ArmorKind::Message, body);
        let parsed = dearmor(&armored).unwrap();
        assert_eq!(parsed.kind, ArmorKind::Message);
        assert_eq!(parsed.body, body);

        let mut lines: Vec<String> = armored.lines().map(ToString::to_string).collect();
        let idx = lines.iter().position(|l| l.starts_with('=')).unwrap();
        lines[idx] = "=AAAA".to_string();
        let bad = lines.join("\n");
        assert!(dearmor(&bad).is_err());
    }

    #[test]
    fn test_real_openpgp_key_unlock_split_packets_reencrypt_and_hmac() {
        let addr_pass = "addr-secret-pass";
        let addr_key = DriveKey::generate("Test", "user@proton.me", addr_pass).unwrap();
        let addr_pub = DriveKey::public_key_armored(&addr_key).unwrap();
        assert!(DriveKey::unlock(&addr_key, "wrong-pass").is_err());

        // Verify generated key parses as a genuine RFC 4880 Curve25519 (EdDSALegacy + ECDH) key
        let (parsed_sec, _) = SignedSecretKey::from_string(&addr_key).unwrap();
        assert_eq!(
            parsed_sec.primary_key.algorithm(),
            PublicKeyAlgorithm::EdDSALegacy
        );
        assert_eq!(
            parsed_sec.secret_subkeys[0].algorithm(),
            PublicKeyAlgorithm::ECDH
        );

        let parent1 = Encryptor::generate_node_keys(addr_pass, &addr_key, &addr_pub).unwrap();
        let parent2 = Encryptor::generate_node_keys(addr_pass, &addr_key, &addr_pub).unwrap();
        let parent1_unlocked = DriveKey::unlock(&parent1.key, &parent1.passphrase_raw).unwrap();
        let parent2_unlocked = DriveKey::unlock(&parent2.key, &parent2.passphrase_raw).unwrap();

        let child_creds =
            Encryptor::generate_node_keys(addr_pass, &addr_key, &parent1_unlocked.armored_public)
                .unwrap();

        let dec_pass = Decryptor::decrypt_and_verify_node_passphrase(
            &child_creds.passphrase,
            &child_creds.signature,
            std::slice::from_ref(&addr_pub),
            std::slice::from_ref(&parent1_unlocked),
        )
        .unwrap();
        assert!(dec_pass.is_verified());
        assert_eq!(dec_pass.value(), child_creds.passphrase_raw.as_str());

        let reencrypted = Encryptor::reencrypt_key_packet(
            &child_creds.passphrase,
            &parent1.key,
            &parent1.passphrase_raw,
            &parent2_unlocked.armored_public,
        )
        .unwrap();
        let dec_pass2 = Decryptor::decrypt_and_verify_node_passphrase(
            &reencrypted,
            &child_creds.signature,
            std::slice::from_ref(&addr_pub),
            std::slice::from_ref(&parent2_unlocked),
        )
        .unwrap();
        assert!(dec_pass2.is_verified());
        assert_eq!(dec_pass2.value(), child_creds.passphrase_raw.as_str());

        // Also verify encrypt_pgp_message_to_additional_key lets both parent1 and parent2 decrypt
        let multi = Encryptor::encrypt_pgp_message_to_additional_key(
            &child_creds.passphrase,
            &parent1.key,
            &parent1.passphrase_raw,
            &parent2_unlocked.armored_public,
        )
        .unwrap();
        assert_eq!(DriveCrypto::key_packets_count(&multi).unwrap(), 2);
        assert_eq!(
            Decryptor::decrypt_attached_text_message(
                &multi,
                std::slice::from_ref(&parent2_unlocked)
            )
            .unwrap(),
            child_creds.passphrase_raw.as_str()
        );

        let hash_key_b64 =
            Encryptor::generate_node_hash_key(&parent1.key, &parent1.passphrase_raw).unwrap();
        let dec_hk = Decryptor::decrypt_and_verify_node_hash_key(
            &hash_key_b64,
            std::slice::from_ref(&parent1_unlocked),
            std::slice::from_ref(&parent1_unlocked.armored_public),
        )
        .unwrap();
        assert!(dec_hk.is_verified());
        let h1 = NameHasher::hash("report.pdf", dec_hk.value()).unwrap();
        let h2 = NameHasher::hash("report.pdf", dec_hk.value()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_proton_signing_context_notation_verification() {
        let pass = "ctx-pass";
        let key = DriveKey::generate("Signer", "signer@proton.me", pass).unwrap();
        let pub_key = DriveKey::public_key_armored(&key).unwrap();

        let ctx = SignContext::critical("drive.share-member.member");
        let sig_armored =
            DriveCrypto::sign_str_armored("member-payload  \nline2 ", &ctx, &key, pass).unwrap();

        // Matching context succeeds
        DriveCrypto::verify_detached_str(
            &sig_armored,
            "member-payload\nline2",
            std::slice::from_ref(&pub_key),
            Some(&VerificationContext::new(
                "drive.share-member.member",
                VerificationRequired::RequiredAfter(0),
            )),
            None,
        )
        .unwrap();

        // Wrong context fails
        assert!(DriveCrypto::verify_detached_str(
            &sig_armored,
            "member-payload\nline2",
            std::slice::from_ref(&pub_key),
            Some(&VerificationContext::new(
                "wrong.context",
                VerificationRequired::RequiredAfter(0),
            )),
            None,
        )
        .is_err());

        // Unsigned-with-context signature rejected when RequiredAfter(0), accepted when RequiredAfter(future)
        let plain_sig = DriveCrypto::sign_bytes_armored(b"hello", None, &key, pass).unwrap();
        assert!(DriveCrypto::verify_detached_armored(
            &plain_sig,
            b"hello",
            std::slice::from_ref(&pub_key),
            Some(&VerificationContext::new(
                "drive.share-member.member",
                VerificationRequired::RequiredAfter(0),
            )),
            None,
        )
        .is_err());

        DriveCrypto::verify_detached_armored(
            &plain_sig,
            b"hello",
            std::slice::from_ref(&pub_key),
            Some(&VerificationContext::new(
                "drive.share-member.member",
                VerificationRequired::RequiredAfter(current_unix_secs() + 3600),
            )),
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_rfc4880_cleartext_signed_message_verification() {
        let pass = "modulus-pass";
        let key = DriveKey::generate("ModulusSigner", "srv@proton.me", pass).unwrap();
        let pub_key = DriveKey::public_key_armored(&key).unwrap();
        let (sk, _) = SignedSecretKey::from_string(&key).unwrap();

        let body = "AAAA1234BBBB5678";
        let mut rng = thread_rng();
        let csf = CleartextSignedMessage::sign(&mut rng, body, &sk.primary_key, &pass.into())
            .unwrap()
            .to_armored_string(ArmorOptions::default())
            .unwrap();

        let verified_text =
            DriveCrypto::verify_cleartext_signed(&csf, std::slice::from_ref(&pub_key)).unwrap();
        assert_eq!(verified_text.trim(), body);

        let tampered = csf.replace("AAAA1234", "ZZZZ9999");
        assert!(
            DriveCrypto::verify_cleartext_signed(&tampered, std::slice::from_ref(&pub_key))
                .is_err()
        );
    }

    // Independently generated GnuPG 2.4.8 Curve25519 (Ed25519 primary + Cv25519 subkey) fixtures.
    const FIXTURE_GPG_ECC_PASS: &str = "proton-fixture-pass";
    const FIXTURE_GPG_ECC_SEC: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlIYEavuwJBYJKwYBBAHaRw8BAQdAkMzvk0DlcdqzqyD1zmHs03P2MaPVy77OHvRg\nijTzksf+BwMCrWPbfIJS52P/Lw70uiKAkcbT4GkG6QX+WK+PfuxHbr7LwL7dPJi+\nhNa6kMulivDs7JuqINjcshMaz4MkuVgK75tdfsvoAvuk6nouRsrDf7QgRml4dHVy\nZSBVc2VyIDxmaXh0dXJlQHByb3Rvbi5tZT6IkAQTFgoAOBYhBIf/Cp4tDQpE3UMf\nGCmiujd8wOLDBQJq+7AkAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJECmi\nujd8wOLD8bgBALqMKNyM/7KoA6Dp8pMxeG3AW1ZYSbubyDacSx9z8kW7APsF/dZL\nledoVIf9+OifnuiKDw4HvyA3jjPpcJMyNSDCBZyLBGr7sCYSCisGAQQBl1UBBQEB\nB0AgWJjKNHxmMaNubRuJTxegEKobedo6qlhpENi6VupwSAMBCAf+BwMCusvv00gf\nWrD/s6ebeGITazEMJFItx2tEXXF9gIBJGv/7mMNvx4OFii7FyS1woHW0bqTSiqr5\nVgidCXttoxffKhGCad03WtEv3KBinFBoM4h4BBgWCgAgFiEEh/8Kni0NCkTdQx8Y\nKaK6N3zA4sMFAmr7sCYCGwwACgkQKaK6N3zA4sOYegEA+YkLkiQmlz6kPeg1yHyn\new8WR87wyCcOj4JjhvcQgWABAMNiX08cuu0rxwTwefjo4wwLO6AFs0yofSt13Txu\nd0kE\n=hhb+\n-----END PGP PRIVATE KEY BLOCK-----\n";
    const FIXTURE_GPG_ECC_PUB: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEavuwJBYJKwYBBAHaRw8BAQdAkMzvk0DlcdqzqyD1zmHs03P2MaPVy77OHvRg\nijTzkse0IEZpeHR1cmUgVXNlciA8Zml4dHVyZUBwcm90b24ubWU+iJAEExYKADgW\nIQSH/wqeLQ0KRN1DHxgporo3fMDiwwUCavuwJAIbAwULCQgHAgYVCgkICwIEFgID\nAQIeAQIXgAAKCRAporo3fMDiw/G4AQC6jCjcjP+yqAOg6fKTMXhtwFtWWEm7m8g2\nnEsfc/JFuwD7Bf3WS5XnaFSH/fjon57oig8OB78gN44z6XCTMjUgwgW4OARq+7Am\nEgorBgEEAZdVAQUBAQdAIFiYyjR8ZjGjbm0biU8XoBCqG3naOqpYaRDYulbqcEgD\nAQgHiHgEGBYKACAWIQSH/wqeLQ0KRN1DHxgporo3fMDiwwUCavuwJgIbDAAKCRAp\noro3fMDiw5h6AQD5iQuSJCaXPqQ96DXIfKd7DxZHzvDIJw6PgmOG9xCBYAEAw2Jf\nTxy67SvHBPB5+OjjDAs7oAWzTKh9K3XdPG53SQQ=\n=tjFG\n-----END PGP PUBLIC KEY BLOCK-----\n";
    const FIXTURE_GPG_ECC_ENC_SIGNED: &str = "-----BEGIN PGP MESSAGE-----\n\nhF4D3GNKJE377VoSAQdAW6IPhjjpjRAug0s4GxUFE29j4zY0a6IdPksW/0JLRh0w\nostPSc+8/onCAgFs4bG1Bi/C6Ahn04KJN+m/F55c7ajUIF5me+1IzVYjWGZFP5ie\n0sABAWhmXCr1+dhq5unYJOTocn/n0FS+q/bzm5xPsf0pOMo+arY5/WHJD6kSHmNR\nUDMj9bhhqhuz+xSAr33ZKPfz/HP1DqJ2j9U8Mkxq+8Bt8p2jbkEQJs1VLpVK8fMA\nASAktgyJjGzh7Z948JhdNB7Jw+mZ4Y+6HQJJ8tCIn03WjhuXmD8PkBlB6zWul3q4\ngiDwL5vCQHwwF1Dqk62Bf0LG7MHtJdXOXb8ZOSMqlDTcCkL46RbY35x+/Rf1n/3j\nw3cZbA==\n=Y1+d\n-----END PGP MESSAGE-----\n";
    const FIXTURE_GPG_ECC_SIG_BIN: &str = "-----BEGIN PGP SIGNATURE-----\n\niHUEABYKAB0WIQSH/wqeLQ0KRN1DHxgporo3fMDiwwUCavuwKAAKCRAporo3fMDi\nw+p1AP9J9ZJgZ2xegx06OfWL/oCmzQCTXj2gu6BDuWx2YjCcqQD+OnkKdzYZb49z\nZZn3SC/EuuWK7EesuQ7LV+VYxbekdwo=\n=l4ga\n-----END PGP SIGNATURE-----\n";
    const FIXTURE_GPG_ECC_SIG_TXT: &str = "-----BEGIN PGP SIGNATURE-----\n\niHUEARYKAB0WIQSH/wqeLQ0KRN1DHxgporo3fMDiwwUCavuwKQAKCRAporo3fMDi\nw7QVAP4i6gmlSdnUb/lBTelyb0LK7znBcmIusKjqoFubBDfy5AD9Fd2yHro+derE\njDOGfDnK61UKkmV5OkB6eRA1Xpqt4gg=\n=bU9Y\n-----END PGP SIGNATURE-----\n";
    const FIXTURE_GPG_ECC_CLEARSIG: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nmodulus-line-1\nmodulus-line-2\n-----BEGIN PGP SIGNATURE-----\n\niHUEARYKAB0WIQSH/wqeLQ0KRN1DHxgporo3fMDiwwUCavuwKQAKCRAporo3fMDi\nwyrtAP9UiPROsh6+g9QSa/x+bZOn1AXx9iKOlbB3k66+TfVuyAEAn9tZPVcm7U++\nuvj7K/58dq+INsvGJH8pQ9wnhsporQc=\n=Fa/D\n-----END PGP SIGNATURE-----\n";
    const FIXTURE_GPG_ECC_SPLIT_B64: &str = "hF4D3GNKJE377VoSAQdAZojqhvCeRU7yG7awpMLY7Zver9IHmCc/cnxTGwF+hlIwc8/v69aUuiB3pelWM4X8dkHjzftI+wvmYgmp0s+cY6kAL5xMfB2mN+4AspmTgiQa0k8BYeWoaBjTGpAPyqHVjoBAz9QabQ76dGrnBNlaMe6AmQUlxYN45EryWCYMuVYyvmXm3osuxANVA6KmARo2M9YDaa1+Erec83Hb4UujKoiI";

    // Independently generated GnuPG 2.4.8 RSA-2048 (certify-only primary + sign subkey + encr subkey) fixtures.
    const FIXTURE_GPG_RSA_PASS: &str = "rsa-fixture-pass";
    const FIXTURE_GPG_RSA_SEC: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n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\n=5wWU\n-----END PGP PRIVATE KEY BLOCK-----\n";
    const FIXTURE_GPG_RSA_PUB: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBGr7sCkBCADF3zFAibefJWDroq/zTJuCPvo36OvT2BzOspMixfi1QK1vxB/0\nkNkfjkkPHo0mhK+E7Zdr6E9IVFD6grFx8ikWXUW9lN/H8Ux29pjaWtf9fQtVdqm7\nOg27PcjOadHyU5LQYwG4LRT3UqzddZVMBEeWYFO6PZ4ZXSX0ZzU502f3wqoIPTkK\nrgL1d3SoFueWfBLrG3POnVyZ1UGcMe3MqSwC4pcmshPI5RxBdBT68GWBRkgFyjNy\n1ua1+lQ8Lhj8KgY+qeS1fMeGiOoQphucIlp+oHqyfhDEsD+pHfNaGJpjbIh+ESiu\nzNG/9hbbuo3CuFvP6mz01iD1Gm4rB6mQ6rdRABEBAAG0GVJTQSBTcGxpdCA8cnNh\nQHByb3Rvbi5tZT6JAU4EEwEKADgWIQTY3aZoidwudjrNTtOJ7iGT1l6xVAUCavuw\nKQIbAQULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRCJ7iGT1l6xVCsFCACJN8sY\nnFKaFt9YHXP5HaygzGSzcxNSaksAFVFNB3n16FqXnCntQTqG2iSloPuezxeLYVMf\nX6RuSTmswgDIxWXGXActqhsgkXK9eR6EZasfKomClIiivRLyZmEoy6AN5UawcRDz\nw53XjBqkOwcKj8ImWuDGVS1RJqFEdmfIy99tQ9BRVD9JlZbnIS5scnyEBJiK0nV8\nffd/doTxll0gfdCyLvpa2APGalRKbUNJglA1kIYGG1gtF3aRUBeCgSW/wEHbirjC\n3FPSLnuWLspBEYRn+RQw+LPgrkZjc1SVVUlpU+upTjsyW2Xhm2/uDaWziziEsmZa\njrNycNUSMrVo3k0duQENBGr7sCoBCADpEMNQAJEeRAc6RPmTtJCLNBMXzKgAFRpt\nU5yi4tOoIwUMKKwpkiWqpWUZ1d5+K/Drzwp7EMoCpAlIdhzl0UiS3oNSawUEl6sV\nuw3dtMMjW/jMTl8/KwnKeXSKPNTArK6lnQAXbWoR4eE22d0LyXvpPOBHlVrCr695\np9OL520fyfDQC5aKp5y0JD5hIImyHpDvLKwhsspi6w63EXqHIN9SRz9JVAgbRX4x\nExNLsLIWTLN8RUdGvnkEVdyaj7DTRyGUIW+byvxQDFsqWhUhLkxoZuWeUeozOiy0\n4V479HTuOIXN6OSBJl6j3X350QIGA2M36jfSSq6Ey9oDbVPE2ZUnABEBAAGJAmwE\nGAEKACAWIQTY3aZoidwudjrNTtOJ7iGT1l6xVAUCavuwKgIbAgFACRCJ7iGT1l6x\nVMB0IAQZAQoAHRYhBF6hD6OaSJ+BdVKc6qMOS083mStkBQJq+7AqAAoJEKMOS083\nmStkmWEH/jMXRFPVF3m1zioJei7wGrm56KpU25OlmkErm2MkOPZJJxodd6XQnLKY\nZRV0BxAQqkRXh4VwDRC21bKruJ5/aLvcEaugLQ3+I9gSPj981ySfIlpV0HrrDRpn\nf2YW0p6Ej6pnIq8PZm/abWmZYpomaZLgHgxY9s8UeolwuAF3HXwAXllME3EcW++s\nLlKnBWJ17UO+wEqux5hWmcVAMrXUQftdFp0Wn1876T3Bd5xKQl0wlDcfeTQE/w9E\nwXwgyTzaHEfM0HO6FUko9ZmKT/zQ4F0Jy7Pxf7EGEZr3wqB9Y+C7LfcVKSCMhCwl\nnQPW95HRz8Eoc7Hx50JXN5Hz+q7lJMSE+QgAs4yFUF2gDcMdsGmihjlDSsflmZQl\nun0tGMFWqrn5wmBiODzocGvxNbZfKABFpvLEOIitFPNFtI4dpmtwu55TOl758xKT\nGSnKBFScM1IcvBy5IR9jBjKftsXP7CfluBF8fmHDErjuSPyO6rmr8elER/mmczUw\nqci2CknQSnHrSxU7KVohLzRReP8ZY2na7U4PqNM9lSZEnioQRmBjCDNEM0kAkVmW\ndz61dcaoo1foZTQ9n/XSd/ReyZIqzXQTrgk5DtPFIakNJeYNw5WAdkbT5iWMaYwc\nGH4Ry2E+li84b56eQuDg2fHSdONQaClwlGFZnr5q+d+7BTrfmkBjGyYo1rkBDQRq\n+7AsAQgAndo8NO6jJlEDcw6kQC5WHTo2PXzHGsnt86vQDGYzrA/ItBq2Xcxmph48\nd5YGv0IGss38F6sAua4UQKEr+um7VH3iRUOADjenHX7puz/yBkMaDl1e3D2MNbvz\n1A/5uVCuXlxdmS1dgipgUMA4VcoQn1ul1bJMLqmYLWnsOnNbgZaHOiYO0cLfydlY\nFdM2BcqYqkdWOonVco3LtSqIn7HpjnHQSn+1XXMXiU5pp7IORZfLuwHXLYct0PQF\nQS2UPDrVTjCvk4bIKLrmUX6edKUOggqLFHXBbmf4gfjkYJjdU2GxWgFb+1gTji0q\nnpld1fdJ3q1OXQZC5t6vUlxzw2Ql4wARAQABiQE2BBgBCgAgFiEE2N2maIncLnY6\nzU7Tie4hk9ZesVQFAmr7sCwCGwwACgkQie4hk9ZesVSbsggArlumHfYxsIJQ49ZI\nWJnhqMIkyYXuaLESPA50SYTzsDrEa6m1HeFt4PmOwohWLGc9RUEgIxdg7C6SAP2M\nmFXgarwNjInvvXW1+uGLVS963vDSkKvo7FdBfh3jEPHffQIvtJp6NikfJ1MOsTTp\nV17H9ys4NQdQsteidZyKcW8tPy8CMYCaUKVpRrO4HfUHJg8aL/UaLf+t5jl0XGlA\nAqj5xoCnJ/lR/nx/9FmhlXOCRyrbZqXX9EyQ7dpJuREffTXbpKsUfG7WvxlPHSCf\ncG9b3eCbO65SHRe9KuWd6fkiLsdgyXL5sZtnmn3STeV2T84XLlPuXhUG/rSbo7cs\nc+/9Bg==\n=2ACN\n-----END PGP PUBLIC KEY BLOCK-----\n";
    const FIXTURE_GPG_RSA_ENC_SIGNED: &str = "-----BEGIN PGP MESSAGE-----\n\nhQEMA+Ajrs5/pqdCAQf/dtlJciiytC2+c0jDMN9P3lg87kNhlnJIZNlTbJsFqTdJ\nCbdeNhtPe5JPNilN+OhV49Clqk2w2NCTqiAITeGY2/VhZ9HKjReFoOx5D8O+vWt9\nd1TQv/UjdzPLBXr1BP9DI5HRGdhu3D72GNIwkC8XX0scqkvXF6pvuBxEapvOlRGF\nQaZJdYvKhiFCxubgd0v8nwQVJH7cmJyvEgECccuYpwUFfFPkNbVJWK3+C7RLS+Is\nYFqHQFTYytNhXCt38oxtazHkNEp2OyR3ON1J/tDV9EA13SO5Ii/JzfJC13b9swe1\nznQbtUTgClQFp1WVYInttGh0sU7qsWDmZz9zTt3jBNLA0AEqmi5cgcDWroeZMIH/\nxw/et0uWGMaOEIPIVgoz8tRiIzoU8RNEuvl/A6w/k26TWZZ7aK1GsJWnVsMCk8YM\n5qb5RNF0/73DZ8wxRcWydcGI5WSxk8DnKkd5Aoj8SzlhcPfreL95MD/ntGWBmOjx\n79B5xdjmFHp3OTU/uhg3BgOhdnE7i8LJYibIbuOAoDHrPOJ2VnNZn0yIIdfwgvkj\nvuj7kKqXJzbBh75YxBcZPj+U7jA9e6aF+SKHvaKwQQJ5NYwjvrK6YIpRnDQJPl6T\nGn3U2HYpsR7RdF0Kvhar4VIrVxE6viYhGfZeXEdHxricQ4EBXJtLDyApRaZjk6Hs\nx+Wz4JDsS0XH/XmH5B7lyTIfI+gHtdfSSntoLyAhDfzr4YDV/GMqAYFxc2f7xQG7\nmMSmtpCJdco9sns+uX2wB0NNrpE016iWoBi3YZVQNXNAIZo8V6UXzfpin1Bwa1Dq\nCqxoAZFztzZJBlPFI1kVJoQ8AK5Y7FyNKtl5ctqD5L5pWrqbWbRMH+9Hh5hMlJ7w\nzT4=\n=FHR2\n-----END PGP MESSAGE-----\n";
    const FIXTURE_GPG_RSA_SPLIT_B64: &str = "hQEMA+Ajrs5/pqdCAQf/fEWKo1XLVZpXYZ8G/V/pJC+Kmt9mB38GyMZyijVWyoD6isDJousPnG2WzoxeaSNNzLbYEHl3LDLOHkxZC048YAiUj9h+/rF+9D7aHmuxK7U6rn7bLwmWV4unIV7Cw+GIyFisCJjxIKRvL6iz9dqbxQ3To9weMYfdv5NV0ylrhFbyj+739NKml5zcI73WEvJiphoDyeqZe0cTCx3hlPzEi1QeNljdziz4qkWmRl0r+5DmIpFxQpUsH9zTGiZ8MKZv9k9QIdxo73k4AcWZaEEhzi8GG0SPXzOAUVFyTMahWH9OuhRu6w53rZA2ZunXTEXklMDQsZvIGaeD/lg+tzd7VdJGAWRUCaMX+0jr5Ez8Zjh1ntVsds5AhD1XmwmhXgE0d3uFk36f+VznR8kXno+CVEo8aRt+08ek2RGuy0OCp6UjllVSIXP4Dw==";

    #[test]
    fn test_gpg_independent_key_unlock_and_metadata_decryption() {
        // 1. Key unlock on independent GPG Curve25519 and RSA multi-subkey keys
        assert!(DriveKey::unlock(FIXTURE_GPG_ECC_SEC, "wrong-pass").is_err());
        assert!(DriveKey::unlock(FIXTURE_GPG_RSA_SEC, "wrong-pass").is_err());

        let ecc_unlocked = DriveKey::unlock(FIXTURE_GPG_ECC_SEC, FIXTURE_GPG_ECC_PASS).unwrap();
        let rsa_unlocked = DriveKey::unlock(FIXTURE_GPG_RSA_SEC, FIXTURE_GPG_RSA_PASS).unwrap();
        let other_key = DriveKey::generate("Other", "other@proton.me", "other-pass").unwrap();
        let other_pub = DriveKey::public_key_armored(&other_key).unwrap();

        // 2. Decrypt & verify attached compressed+signed messages produced by GnuPG
        let ecc_dec = Decryptor::decrypt_and_verify_node_name(
            FIXTURE_GPG_ECC_ENC_SIGNED,
            &ecc_unlocked,
            &[FIXTURE_GPG_ECC_PUB.to_string()],
        )
        .unwrap();
        assert!(
            ecc_dec.is_verified(),
            "ECC GPG attached message must verify"
        );
        assert_eq!(ecc_dec.value(), "report.pdf");

        let ecc_wrong_signer = Decryptor::decrypt_and_verify_node_name(
            FIXTURE_GPG_ECC_ENC_SIGNED,
            &ecc_unlocked,
            std::slice::from_ref(&other_pub),
        )
        .unwrap();
        assert!(!ecc_wrong_signer.is_verified());

        let rsa_dec = Decryptor::decrypt_and_verify_node_name(
            FIXTURE_GPG_RSA_ENC_SIGNED,
            &rsa_unlocked,
            &[FIXTURE_GPG_RSA_PUB.to_string()],
        )
        .unwrap();
        assert!(
            rsa_dec.is_verified(),
            "RSA GPG attached message must verify"
        );
        assert_eq!(rsa_dec.value(), "rsa-secret-node");

        // 3. Verify independent GnuPG detached binary, detached text, and cleartext signatures
        DriveCrypto::verify_detached_armored(
            FIXTURE_GPG_ECC_SIG_BIN,
            b"binary-payload-\x00\xff",
            &[FIXTURE_GPG_ECC_PUB.to_string()],
            None,
            None,
        )
        .unwrap();
        assert!(DriveCrypto::verify_detached_armored(
            FIXTURE_GPG_ECC_SIG_BIN,
            b"tampered-payload",
            &[FIXTURE_GPG_ECC_PUB.to_string()],
            None,
            None,
        )
        .is_err());
        assert!(DriveCrypto::verify_detached_armored(
            FIXTURE_GPG_ECC_SIG_BIN,
            b"binary-payload-\x00\xff",
            std::slice::from_ref(&other_pub),
            None,
            None,
        )
        .is_err());

        DriveCrypto::verify_detached_str(
            FIXTURE_GPG_ECC_SIG_TXT,
            "line1\nline2",
            &[FIXTURE_GPG_ECC_PUB.to_string()],
            None,
            None,
        )
        .unwrap();
        DriveCrypto::verify_detached_str(
            FIXTURE_GPG_ECC_SIG_TXT,
            "line1\r\nline2",
            &[FIXTURE_GPG_ECC_PUB.to_string()],
            None,
            None,
        )
        .unwrap();

        let cs_text = DriveCrypto::verify_cleartext_signed(
            FIXTURE_GPG_ECC_CLEARSIG,
            &[FIXTURE_GPG_ECC_PUB.to_string()],
        )
        .unwrap();
        assert_eq!(
            cs_text.replace("\r\n", "\n").trim(),
            "modulus-line-1\nmodulus-line-2"
        );
        assert!(DriveCrypto::verify_cleartext_signed(
            &FIXTURE_GPG_ECC_CLEARSIG.replace("modulus-line-1", "modulus-tampered"),
            &[FIXTURE_GPG_ECC_PUB.to_string()],
        )
        .is_err());

        // 4. Signing with RSA certify-only primary + signing subkey selects the signing subkey
        let rsa_sig = DriveCrypto::sign_str_armored(
            "subkey-signed-metadata",
            &SignContext::critical("drive.share-member.member"),
            FIXTURE_GPG_RSA_SEC,
            FIXTURE_GPG_RSA_PASS,
        )
        .unwrap();
        DriveCrypto::verify_detached_str(
            &rsa_sig,
            "subkey-signed-metadata",
            &[FIXTURE_GPG_RSA_PUB.to_string()],
            Some(&VerificationContext::new(
                "drive.share-member.member",
                VerificationRequired::RequiredAfter(0),
            )),
            None,
        )
        .unwrap();

        // 5. Reject unknown critical notation subpacket
        let mut rng = thread_rng();
        let signer = select_signing_key(&ecc_unlocked.secret_key).unwrap();
        let unknown_crit = Subpacket::critical(SubpacketData::Notation(Notation {
            readable: true,
            name: Bytes::from_static(b"unknown@example.com"),
            value: Bytes::from_static(b"val"),
        }))
        .unwrap();
        let sp_cfg = SubpacketConfig::UserDefined {
            hashed: vec![
                Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint())).unwrap(),
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
                unknown_crit,
            ],
            unhashed: vec![],
        };
        let bad_sig = signer
            .sign_detached_with_subpackets(
                &mut rng,
                &ecc_unlocked.pgp_password(),
                HashAlgorithm::Sha256,
                b"payload",
                sp_cfg,
                false,
            )
            .unwrap()
            .to_armored_string(ArmorOptions::default())
            .unwrap();
        assert!(DriveCrypto::verify_detached_armored(
            &bad_sig,
            b"payload",
            &[FIXTURE_GPG_ECC_PUB.to_string()],
            Some(&VerificationContext::new(
                "drive.share-member.member",
                VerificationRequired::NonRequired,
            )),
            None,
        )
        .is_err());
    }

    #[test]
    fn test_gpg_independent_split_content_key_packet_and_block() {
        let ecc_unlocked = DriveKey::unlock(FIXTURE_GPG_ECC_SEC, FIXTURE_GPG_ECC_PASS).unwrap();
        let rsa_unlocked = DriveKey::unlock(FIXTURE_GPG_RSA_SEC, FIXTURE_GPG_RSA_PASS).unwrap();

        for (raw_b64, unlocked, expected_plain) in [
            (
                FIXTURE_GPG_ECC_SPLIT_B64,
                &ecc_unlocked,
                b"block-payload-0123456789abcdef".as_slice(),
            ),
            (
                FIXTURE_GPG_RSA_SPLIT_B64,
                &rsa_unlocked,
                b"rsa-block-payload-xyz".as_slice(),
            ),
        ] {
            let msg_bytes = BASE64.decode(raw_b64).unwrap();
            let mut key_packet = Vec::new();
            let mut data_packet = Vec::new();
            for (tag, raw) in decode_packets(&msg_bytes).unwrap() {
                if tag == PACKET_PKESK {
                    key_packet.extend_from_slice(&raw);
                } else {
                    data_packet.extend_from_slice(&raw);
                }
            }
            assert!(!key_packet.is_empty());
            assert!(!data_packet.is_empty());

            let sk = Decryptor::decrypt_content_key_packet(&key_packet, unlocked).unwrap();
            let plain = Decryptor::decrypt_block_with_session_key(&data_packet, &sk).unwrap();
            assert_eq!(plain, expected_plain);
        }

        // Wrong key rejects ContentKeyPacket
        let ecc_bytes = BASE64.decode(FIXTURE_GPG_ECC_SPLIT_B64).unwrap();
        assert!(Decryptor::decrypt_content_key_packet(&ecc_bytes, &rsa_unlocked).is_err());
    }

    #[test]
    fn test_output_accepted_by_independent_gpg() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};

        if Command::new("gpg").arg("--version").output().is_err() {
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let agent_available = Command::new("gpg-connect-agent")
            .env("GNUPGHOME", tmp.path())
            .arg("/bye")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if !agent_available {
            eprintln!("skipping GPG interoperability test: gpg-agent is unavailable");
            return;
        }
        let run_gpg = |args: &[&str], input: &[u8]| -> std::process::Output {
            let mut child = Command::new("gpg")
                .env("GNUPGHOME", tmp.path())
                .args(["--batch", "--yes", "--pinentry-mode", "loopback"])
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed spawning gpg");
            child.stdin.as_mut().unwrap().write_all(input).unwrap();
            child.wait_with_output().unwrap()
        };

        // 1. Import DriveKey::generate key + independent GPG ECC key into GNUPGHOME
        let gen_pass = "native-gen-pass";
        let gen_sec = DriveKey::generate("Native", "native@proton.me", gen_pass).unwrap();
        let gen_pub = DriveKey::public_key_armored(&gen_sec).unwrap();

        let imp1 = run_gpg(&["--passphrase", gen_pass, "--import"], gen_sec.as_bytes());
        assert!(
            imp1.status.success(),
            "gpg failed importing DriveKey::generate secret key: {}",
            String::from_utf8_lossy(&imp1.stderr)
        );
        let imp2 = run_gpg(
            &["--passphrase", FIXTURE_GPG_ECC_PASS, "--import"],
            FIXTURE_GPG_ECC_SEC.as_bytes(),
        );
        assert!(imp2.status.success());

        // Some headless environments can launch gpg-agent but cannot unlock a
        // passphrase-protected key through loopback pinentry. Verify that external
        // prerequisite against an independently generated fixture before judging
        // Neutron Drive output.
        let fixture_probe = run_gpg(
            &["--passphrase", FIXTURE_GPG_ECC_PASS, "--decrypt"],
            FIXTURE_GPG_ECC_ENC_SIGNED.as_bytes(),
        );
        if !fixture_probe.status.success() {
            eprintln!(
                "skipping GPG interoperability test: gpg-agent cannot decrypt the fixture: {}",
                String::from_utf8_lossy(&fixture_probe.stderr)
            );
            return;
        }

        // 2. GPG decrypts and verifies attached messages (compressed and uncompressed)
        for compress in [false, true] {
            let payload = b"proton-drive-xattr-{\"Size\":42}".as_slice();
            let enc = Encryptor::encrypt_and_sign_bytes(
                payload,
                FIXTURE_GPG_ECC_PUB,
                gen_pass,
                &gen_sec,
                compress,
            )
            .unwrap();
            let dec = run_gpg(
                &["--passphrase", FIXTURE_GPG_ECC_PASS, "--decrypt"],
                enc.as_bytes(),
            );
            assert!(
                dec.status.success(),
                "gpg failed decrypting encrypt_and_sign_bytes(compress={}): {}",
                compress,
                String::from_utf8_lossy(&dec.stderr)
            );
            assert_eq!(dec.stdout, payload);
            let stderr = String::from_utf8_lossy(&dec.stderr);
            assert!(
                stderr.contains("Good signature"),
                "gpg did not report Good signature: {}",
                stderr
            );
        }

        // 3. GPG verifies detached binary signature, non-critical context text signature, and cleartext signature
        let sig_path = tmp.path().join("bin.sig");
        let data_path = tmp.path().join("bin.dat");
        let bin_data = b"block-bytes-for-gpg";
        let bin_sig = DriveCrypto::sign_bytes_armored(bin_data, None, &gen_sec, gen_pass).unwrap();
        std::fs::write(&sig_path, &bin_sig).unwrap();
        std::fs::write(&data_path, bin_data).unwrap();
        let ver_bin = run_gpg(
            &[
                "--verify",
                sig_path.to_str().unwrap(),
                data_path.to_str().unwrap(),
            ],
            b"",
        );
        assert!(
            ver_bin.status.success(),
            "gpg failed verifying binary signature: {}",
            String::from_utf8_lossy(&ver_bin.stderr)
        );

        let txt_sig_path = tmp.path().join("txt.sig");
        let txt_data_path = tmp.path().join("txt.dat");
        let txt_sig = DriveCrypto::sign_str_armored(
            "hello\nworld",
            &SignContext::non_critical("drive.test.noncrit"),
            &gen_sec,
            gen_pass,
        )
        .unwrap();
        std::fs::write(&txt_sig_path, &txt_sig).unwrap();
        std::fs::write(&txt_data_path, b"hello\nworld").unwrap();
        let ver_txt = run_gpg(
            &[
                "--verify",
                txt_sig_path.to_str().unwrap(),
                txt_data_path.to_str().unwrap(),
            ],
            b"",
        );
        assert!(
            ver_txt.status.success(),
            "gpg failed verifying text signature: {}",
            String::from_utf8_lossy(&ver_txt.stderr)
        );

        let crit_sig = DriveCrypto::sign_str_armored(
            "member",
            &SignContext::critical("drive.share-member.member"),
            &gen_sec,
            gen_pass,
        )
        .unwrap();
        let pkts_out = run_gpg(&["--list-packets"], crit_sig.as_bytes());
        assert!(pkts_out.status.success());
        let pkts_text = String::from_utf8_lossy(&pkts_out.stdout);
        assert!(
            pkts_text.contains("context@proton.ch") && pkts_text.contains("critical"),
            "Critical context@proton.ch notation missing in gpg --list-packets: {}",
            pkts_text
        );

        let cs = DriveCrypto::sign_cleartext("modulus-body", &gen_sec, gen_pass).unwrap();
        let ver_cs = run_gpg(&["--verify"], cs.as_bytes());
        assert!(
            ver_cs.status.success(),
            "gpg failed verifying cleartext signature: {}",
            String::from_utf8_lossy(&ver_cs.stderr)
        );

        // 4. GPG decrypts concatenated ContentKeyPacket + block SEIPD, and re-encrypted node passphrase
        let gen_unlocked = DriveKey::unlock(&gen_sec, gen_pass).unwrap();
        let (sk, kp, _, _) =
            Encryptor::generate_content_session_key(FIXTURE_GPG_ECC_PUB, &gen_sec, gen_pass)
                .unwrap();
        let block_plain = b"4MiB-aligned-block-content-for-gpg";
        let (block_pkt, enc_block_sig) =
            Encryptor::encrypt_block_with_session_key(block_plain, &sk, &gen_unlocked, &gen_pub)
                .unwrap();
        let mut combined_msg = Vec::with_capacity(kp.len() + block_pkt.len());
        combined_msg.extend_from_slice(&kp);
        combined_msg.extend_from_slice(&block_pkt);
        let dec_block = run_gpg(
            &["--passphrase", FIXTURE_GPG_ECC_PASS, "--decrypt"],
            &combined_msg,
        );
        assert!(
            dec_block.status.success(),
            "gpg failed decrypting PKESK+SEIPD block: {}",
            String::from_utf8_lossy(&dec_block.stderr)
        );
        assert_eq!(dec_block.stdout, block_plain);

        // Verify Decryptor::decrypt_block_signature accepts both binary and armored encrypted signatures
        let dec_sig = Decryptor::decrypt_block_signature(&enc_block_sig, &gen_unlocked).unwrap();
        DriveCrypto::verify_detached_armored(
            &dec_sig,
            block_plain,
            std::slice::from_ref(&gen_pub),
            None,
            None,
        )
        .unwrap();
        let armored_wrapped = Encryptor::encrypt_text(&dec_sig, &gen_pub).unwrap();
        let dec_sig_from_armored =
            Decryptor::decrypt_block_signature(&armored_wrapped, &gen_unlocked).unwrap();
        DriveCrypto::verify_detached_armored(
            &dec_sig_from_armored,
            block_plain,
            std::slice::from_ref(&gen_pub),
            None,
            None,
        )
        .unwrap();

        // 5. Re-encrypt key packet to independent GPG key and decrypt with gpg
        let orig_creds = Encryptor::generate_node_keys(gen_pass, &gen_sec, &gen_pub).unwrap();
        let reenc = Encryptor::reencrypt_key_packet(
            &orig_creds.passphrase,
            &gen_sec,
            gen_pass,
            FIXTURE_GPG_ECC_PUB,
        )
        .unwrap();
        let dec_reenc = run_gpg(
            &["--passphrase", FIXTURE_GPG_ECC_PASS, "--decrypt"],
            reenc.as_bytes(),
        );
        assert!(
            dec_reenc.status.success(),
            "gpg failed decrypting re-encrypted node passphrase: {}",
            String::from_utf8_lossy(&dec_reenc.stderr)
        );
        assert_eq!(
            String::from_utf8(dec_reenc.stdout).unwrap(),
            orig_creds.passphrase_raw.as_str()
        );
    }

    #[test]
    fn test_decrypt_block_seipd_v2_with_session_key() {
        let pass = "seipd-v2-pass";
        let key_armored = DriveKey::generate("SeipdV2User", "v2@proton.me", pass).unwrap();
        let pub_armored = DriveKey::public_key_armored(&key_armored).unwrap();
        let unlocked = DriveKey::unlock(&key_armored, pass).unwrap();
        let pub_key = parse_signed_public_key(&pub_armored).unwrap();
        let enc_keys = select_encryption_keys(&pub_key);
        assert!(!enc_keys.is_empty());

        let payload = b"seipd-v2-block-payload-0123456789abcdef";
        for aead in [
            pgp::crypto::aead::AeadAlgorithm::Gcm,
            pgp::crypto::aead::AeadAlgorithm::Ocb,
        ] {
            let sk = SessionKey::generate().unwrap();
            let mut rng = thread_rng();
            let mut builder = MessageBuilder::from_bytes("", Bytes::from_static(payload)).seipd_v2(
                &mut rng,
                SymmetricKeyAlgorithm::AES256,
                aead,
                Default::default(),
            );
            builder
                .set_session_key(RawSessionKey::from(sk.as_bytes().as_slice()))
                .unwrap();
            match enc_keys[0] {
                SelectedEncryptionKey::Primary(k) => {
                    builder.encrypt_to_key(&mut rng, k).unwrap();
                }
                SelectedEncryptionKey::Sub(k) => {
                    builder.encrypt_to_key(&mut rng, k).unwrap();
                }
            }
            let full_msg = builder.to_vec(&mut rng).unwrap();

            let mut key_packet = Vec::new();
            let mut data_packet = Vec::new();
            for (tag, raw) in decode_packets(&full_msg).unwrap() {
                if tag == PACKET_PKESK {
                    key_packet.extend_from_slice(&raw);
                } else {
                    data_packet.extend_from_slice(&raw);
                }
            }
            assert!(!key_packet.is_empty());
            assert!(!data_packet.is_empty());

            // Both the PKESK-derived SessionKey and a raw SessionKey::from_bytes() (as used
            // after signature verification in transfer::download_file_blocks) must decrypt SEIPD v2.
            let dec_sk = Decryptor::decrypt_content_key_packet(&key_packet, &unlocked).unwrap();
            assert_eq!(dec_sk.as_bytes(), sk.as_bytes());
            assert_eq!(
                Decryptor::decrypt_block_with_session_key(&data_packet, &dec_sk).unwrap(),
                payload
            );
            let raw_reconstructed = SessionKey::from_bytes(dec_sk.as_bytes()).unwrap();
            assert_eq!(
                Decryptor::decrypt_block_with_session_key(&data_packet, &raw_reconstructed)
                    .unwrap(),
                payload
            );
        }
    }
}
