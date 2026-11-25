use std::collections::HashMap;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zbus::blocking::{Connection as DbusConnection, Proxy as DbusProxy};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::client::StorageQuota;

use super::crypto::{random_bytes, Decryptor, DriveCrypto, DriveKey, UnlockedKey};
use super::http::{HttpAuthTokens, HttpError, PdHttpClient, RateLimitFamily};

// ============================================================================
// Pure-Rust 2048-bit BigUint for Proton SRP-6a
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    /// Little-endian base-2^32 limbs (no trailing zero limbs).
    limbs: Vec<u32>,
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn from_u64(v: u64) -> Self {
        let mut limbs = Vec::new();
        if v != 0 {
            limbs.push(v as u32);
            let hi = (v >> 32) as u32;
            if hi != 0 {
                limbs.push(hi);
            }
        }
        Self { limbs }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(4));
        for chunk in bytes.rchunks(4) {
            let mut val = 0u32;
            for &b in chunk {
                val = (val << 8) | (b as u32);
            }
            limbs.push(val);
        }
        let mut out = Self { limbs };
        out.trim();
        out
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(4));
        for chunk in bytes.chunks(4) {
            let mut val = 0u32;
            for (i, &b) in chunk.iter().enumerate() {
                val |= (b as u32) << (8 * i);
            }
            limbs.push(val);
        }
        let mut out = Self { limbs };
        out.trim();
        out
    }

    pub fn to_le_bytes_padded(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for (i, &limb) in self.limbs.iter().enumerate() {
            let le = limb.to_le_bytes();
            let base = i * 4;
            for j in 0..4 {
                if base + j < len {
                    out[base + j] = le[j];
                }
            }
        }
        out
    }

    pub fn to_be_bytes_padded(&self, len: usize) -> Vec<u8> {
        let mut out = self.to_le_bytes_padded(len);
        out.reverse();
        out
    }

    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn bit_len(&self) -> usize {
        if let Some(&top) = self.limbs.last() {
            (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize)
        } else {
            0
        }
    }

    fn bit(&self, idx: usize) -> bool {
        let word = idx / 32;
        if word >= self.limbs.len() {
            return false;
        }
        ((self.limbs[word] >> (idx % 32)) & 1) != 0
    }

    fn shl_bits(&self, shift: u32) -> Self {
        if self.is_zero() || shift == 0 {
            return self.clone();
        }
        let word_shift = (shift / 32) as usize;
        let bit_shift = shift % 32;
        let mut out = vec![0u32; word_shift + self.limbs.len() + 1];
        if bit_shift == 0 {
            out[word_shift..word_shift + self.limbs.len()].copy_from_slice(&self.limbs);
        } else {
            let mut carry = 0u32;
            for (i, &limb) in self.limbs.iter().enumerate() {
                out[word_shift + i] = (limb << bit_shift) | carry;
                carry = limb >> (32 - bit_shift);
            }
            if carry != 0 {
                out[word_shift + self.limbs.len()] = carry;
            }
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    fn shr_bits(&self, shift: u32) -> Self {
        if self.is_zero() || shift == 0 {
            return self.clone();
        }
        let word_shift = (shift / 32) as usize;
        let bit_shift = shift % 32;
        if word_shift >= self.limbs.len() {
            return Self::zero();
        }
        let rem_len = self.limbs.len() - word_shift;
        let mut out = vec![0u32; rem_len];
        if bit_shift == 0 {
            out.copy_from_slice(&self.limbs[word_shift..]);
        } else {
            let mut carry = 0u32;
            for i in (0..rem_len).rev() {
                let limb = self.limbs[word_shift + i];
                out[i] = (limb >> bit_shift) | carry;
                carry = limb << (32 - bit_shift);
            }
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    pub fn cmp_ref(&self, other: &Self) -> std::cmp::Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for (&a, &b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            if a != b {
                return a.cmp(&b);
            }
        }
        std::cmp::Ordering::Equal
    }

    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;
        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0) as u64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as u64;
            let sum = a + b + carry;
            out.push(sum as u32);
            carry = sum >> 32;
        }
        if carry != 0 {
            out.push(carry as u32);
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    pub fn sub_checked(&self, other: &Self) -> Option<Self> {
        if self.cmp_ref(other) == std::cmp::Ordering::Less {
            return None;
        }
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for (i, &limb) in self.limbs.iter().enumerate() {
            let a = limb as i64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i64;
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1i64 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(diff as u32);
        }
        let mut res = Self { limbs: out };
        res.trim();
        Some(res)
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut out = vec![0u32; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            let a64 = a as u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let acc = (out[i + j] as u64) + a64 * (b as u64) + carry;
                out[i + j] = acc as u32;
                carry = acc >> 32;
            }
            out[i + other.limbs.len()] += carry as u32;
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    pub fn rem(&self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            panic!("Division by zero in BigUint::rem");
        }
        if self.cmp_ref(modulus) == std::cmp::Ordering::Less {
            return self.clone();
        }
        let n = modulus.limbs.len();
        if n == 1 {
            let d = modulus.limbs[0] as u64;
            let mut r = 0u64;
            for &limb in self.limbs.iter().rev() {
                r = ((r << 32) | (limb as u64)) % d;
            }
            return Self::from_u64(r);
        }

        // Knuth Algorithm D (base 2^32)
        let shift = modulus.limbs[n - 1].leading_zeros();
        let vn = modulus.shl_bits(shift);
        let mut un_vec = self.shl_bits(shift).limbs;
        let m = un_vec.len().saturating_sub(n);
        un_vec.resize(m + n + 1, 0);

        let vn1 = vn.limbs[n - 1] as u64;
        let vn2 = vn.limbs[n - 2] as u64;
        const BASE: u64 = 1u64 << 32;

        for j in (0..=m).rev() {
            let hi = ((un_vec[j + n] as u64) << 32) | (un_vec[j + n - 1] as u64);
            let mut qhat = hi / vn1;
            let mut rhat = hi % vn1;
            loop {
                if qhat >= BASE || (qhat * vn2) > ((rhat << 32) | (un_vec[j + n - 2] as u64)) {
                    qhat -= 1;
                    rhat += vn1;
                    if rhat >= BASE {
                        break;
                    }
                } else {
                    break;
                }
            }

            let mut borrow: i64 = 0;
            for i in 0..n {
                let p = qhat * (vn.limbs[i] as u64);
                let p_lo = (p & 0xFFFF_FFFF) as i64;
                let p_hi = (p >> 32) as i64;
                let diff = (un_vec[j + i] as i64) - p_lo - borrow;
                un_vec[j + i] = diff.rem_euclid(BASE as i64) as u32;
                borrow = p_hi - diff.div_euclid(BASE as i64);
            }
            let diff = (un_vec[j + n] as i64) - borrow;
            un_vec[j + n] = diff.rem_euclid(BASE as i64) as u32;

            if diff < 0 {
                let mut carry = 0u64;
                for i in 0..n {
                    let sum = (un_vec[j + i] as u64) + (vn.limbs[i] as u64) + carry;
                    un_vec[j + i] = sum as u32;
                    carry = sum >> 32;
                }
                un_vec[j + n] = un_vec[j + n].wrapping_add(carry as u32);
            }
        }

        let mut r = Self {
            limbs: un_vec[..n].to_vec(),
        };
        r.trim();
        r.shr_bits(shift)
    }

    pub fn mul_mod(&self, other: &Self, modulus: &Self) -> Self {
        self.mul(other).rem(modulus)
    }

    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        let mut result = Self::from_u64(1).rem(modulus);
        let mut base = self.rem(modulus);
        let bits = exp.bit_len();
        for i in 0..bits {
            if exp.bit(i) {
                result = result.mul_mod(&base, modulus);
            }
            if i + 1 < bits {
                base = base.mul_mod(&base, modulus);
            }
        }
        result
    }
}

// ============================================================================
// Pure-Rust OpenBSD Eksblowfish / Bcrypt ($2y$10$)
// ============================================================================

const BCRYPT_ALPHABET: &[u8; 64] =
    b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const BLOWFISH_P_INIT: [u32; 18] = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
    0x9216d5d9, 0x8979fb1b,
];

const BLOWFISH_S_INIT: [[u32; 256]; 4] = [
    [
        0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96, 0xba7c9045,
        0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
        0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d,
        0xc25a59b5, 0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
        0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda,
        0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
        0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a, 0x2ba9c55d,
        0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
        0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991, 0x487cac60,
        0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
        0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842,
        0xf6e96c9a, 0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
        0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176, 0x66ca593e,
        0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073,
        0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d, 0x37d0d724,
        0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
        0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2,
        0x196a2463, 0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c,
        0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3, 0xc0cba857,
        0x45c8740f, 0xd20b5f39, 0xb9d3fbdb, 0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
        0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8, 0x3c7516df, 0xfd616b15, 0x2f501ec8,
        0xad0552ab, 0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0,
        0x1a87562e, 0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573, 0x695b27b0,
        0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
        0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341,
        0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4, 0x95dbda4d, 0xae909198,
        0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb,
        0xf2122b64, 0x8888b812, 0x900df01c, 0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
        0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1, 0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6,
        0xce89e299, 0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705,
        0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf, 0xebcdaf0c,
        0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
        0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f, 0x207d5ba2,
        0x02e5b9c5, 0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a,
        0x1b510052, 0x9a532915, 0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5,
        0x571be91f, 0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
        0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a,
    ],
    [
        0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8,
        0x8fedb266, 0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29,
        0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07,
        0xefe830f5, 0x4d2d38e6, 0xf0255dc1, 0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
        0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1, 0x687f3584, 0x52a0e286, 0xb79c5305,
        0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8, 0xb03ada37, 0xf0500c0d,
        0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd, 0xd19113f9,
        0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
        0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f, 0x3280bba1,
        0x183eb331, 0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79,
        0x5679b072, 0xbcaf89af, 0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f,
        0x2e6b7124, 0x501adde6, 0x9f84cd87, 0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
        0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2, 0xef1c1847, 0x3215d908, 0xdd433b37,
        0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd, 0x71dff89e, 0x10314e55,
        0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509, 0xf28fe6ed,
        0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
        0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978,
        0x9c10b36a, 0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d,
        0x1939260f, 0x19c27960, 0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595,
        0xa67bc883, 0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
        0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84, 0x1521b628, 0x29076170, 0xecdd4775,
        0x619f1510, 0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf, 0xb5735c90, 0x4c70a239,
        0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e, 0x648b1eaf,
        0x19bdf0ca, 0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
        0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f,
        0x16681281, 0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263,
        0x9b83c3ff, 0x1ac24696, 0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef,
        0x34c6ffea, 0xfe28ed61, 0xee7c3c73, 0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
        0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0, 0xc742f442, 0xef6abbb5, 0x654f3b1d,
        0x41cd2105, 0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250, 0xcf62a1f2, 0x5b8d2646,
        0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285, 0x095bbf00,
        0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
        0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460, 0x4085f2a7,
        0xce77326e, 0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2,
        0x5a04abfc, 0x800bcadc, 0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3,
        0x105588cd, 0x675fda79, 0xe3674340, 0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
        0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7,
    ],
    [
        0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e,
        0xd4a20068, 0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546,
        0x14214f74, 0xbf8b8840, 0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec,
        0x03bd9785, 0x7fac6dd0, 0x31cb8504, 0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
        0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb, 0x68dc1462, 0xd7486900, 0x680ec0a4,
        0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6, 0xaace1e7c, 0xd3375fec,
        0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b, 0x1dc9faf7,
        0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
        0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7,
        0xd096954b, 0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9,
        0x5ef47e1c, 0x9029317c, 0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548,
        0xe4c66d22, 0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
        0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564, 0x257b7834, 0x602a9c60, 0xdff8e8a3,
        0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115, 0x6b2395e0, 0x333e92e1,
        0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728, 0xd0127845,
        0x95b794fd, 0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
        0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c,
        0xdb6e6b0d, 0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3,
        0xb5390f92, 0x690fed0b, 0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88,
        0x515bad24, 0x7b9479bf, 0x763bd6eb, 0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
        0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c, 0x6a124237, 0xb79251e7, 0x06a1bbe6,
        0x4bfb6350, 0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9, 0x44421659, 0x0a121386,
        0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe, 0x9dbc8057,
        0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
        0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24, 0x55464299,
        0xbf582e61, 0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74,
        0xb475f255, 0x46fcd9b9, 0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e,
        0x20b45770, 0x8cd55591, 0xc902de4c, 0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
        0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c, 0x4a99a025,
        0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169, 0xdcb7da83, 0x573906fe,
        0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027, 0x9af88c27,
        0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
        0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de, 0xebfc7da1,
        0xce591d76, 0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9,
        0x1ac15bb4, 0xd39eb8fc, 0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e,
        0xb161e6f8, 0xa28514d9, 0x6c51133c, 0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
        0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0,
    ],
    [
        0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740,
        0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b, 0xb78c1b6b, 0x21a19045,
        0xb26eb1be, 0x6a366eb4, 0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee,
        0x468dde7d, 0xd5730a1d, 0x4cd04dc6, 0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
        0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22, 0xc089c2b8, 0x43242ef6, 0xa51e03aa,
        0x9cf2d0a4, 0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1,
        0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59, 0x80e4a915,
        0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
        0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b, 0x5ad6b472,
        0x5a88f54c, 0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc,
        0xf8d56629, 0x79132e28, 0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4,
        0x88f46dba, 0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
        0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319, 0x7533d928, 0xb155fdf5, 0x03563482,
        0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f, 0x4de81751, 0x3830dc8e,
        0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32, 0xa8b6e37e,
        0xc3293d46, 0x48de5369, 0x6413e680, 0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
        0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f,
        0x6bb4e3bb, 0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb,
        0x8d6612ae, 0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370, 0x740e0d8d,
        0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
        0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048, 0x6f3f3b82, 0x3520ab82, 0x011a1d4b,
        0x277227f8, 0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd, 0xa08839e1, 0x51ce794b,
        0x2f32c9b7, 0xa01fbac9, 0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7, 0x1a908749,
        0xd44fbd9a, 0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
        0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a, 0x0f91fc71,
        0x9b941525, 0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c,
        0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964, 0x9f1f9532,
        0xe0d392df, 0xd3a0342b, 0x8971f21e, 0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
        0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891, 0xce6279cf,
        0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299, 0xf523f357, 0xa6327623,
        0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc, 0xde966292,
        0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
        0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 0x71126905, 0xb2040222, 0xb6cbcf7c,
        0xcd769c2b, 0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76,
        0x77afa1c5, 0x20756060, 0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c,
        0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
        0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6,
    ],
];

struct BlowfishState {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl BlowfishState {
    fn new() -> Self {
        Self {
            p: BLOWFISH_P_INIT,
            s: BLOWFISH_S_INIT,
        }
    }

    #[inline]
    fn feistel(&self, x: u32) -> u32 {
        let a = self.s[0][((x >> 24) & 0xFF) as usize];
        let b = self.s[1][((x >> 16) & 0xFF) as usize];
        let c = self.s[2][((x >> 8) & 0xFF) as usize];
        let d = self.s[3][(x & 0xFF) as usize];
        ((a.wrapping_add(b)) ^ c).wrapping_add(d)
    }

    fn encipher(&self, mut xl: u32, mut xr: u32) -> (u32, u32) {
        for i in (0..16).step_by(2) {
            xl ^= self.p[i];
            xr ^= self.feistel(xl);
            xr ^= self.p[i + 1];
            xl ^= self.feistel(xr);
        }
        xl ^= self.p[16];
        xr ^= self.p[17];
        (xr, xl)
    }

    fn expand_key(&mut self, data: &[u8], key: &[u8]) {
        let mut key_pos = 0usize;
        for p_entry in &mut self.p {
            let mut val = 0u32;
            for _ in 0..4 {
                val = (val << 8) | (key[key_pos] as u32);
                key_pos = (key_pos + 1) % key.len();
            }
            *p_entry ^= val;
        }

        let mut data_pos = 0usize;
        let next_word = |pos: &mut usize| -> u32 {
            if data.is_empty() {
                return 0;
            }
            let mut v = 0u32;
            for _ in 0..4 {
                v = (v << 8) | (data[*pos] as u32);
                *pos = (*pos + 1) % data.len();
            }
            v
        };

        let mut l = 0u32;
        let mut r = 0u32;
        for i in (0..18).step_by(2) {
            l ^= next_word(&mut data_pos);
            r ^= next_word(&mut data_pos);
            let (nl, nr) = self.encipher(l, r);
            l = nl;
            r = nr;
            self.p[i] = l;
            self.p[i + 1] = r;
        }
        for s_box in 0..4 {
            for i in (0..256).step_by(2) {
                l ^= next_word(&mut data_pos);
                r ^= next_word(&mut data_pos);
                let (nl, nr) = self.encipher(l, r);
                l = nl;
                r = nr;
                self.s[s_box][i] = l;
                self.s[s_box][i + 1] = r;
            }
        }
    }

    fn expand_0_state(&mut self, key: &[u8]) {
        let mut key_pos = 0usize;
        for p_entry in &mut self.p {
            let mut val = 0u32;
            for _ in 0..4 {
                val = (val << 8) | (key[key_pos] as u32);
                key_pos = (key_pos + 1) % key.len();
            }
            *p_entry ^= val;
        }
        let mut l = 0u32;
        let mut r = 0u32;
        for i in (0..18).step_by(2) {
            let (nl, nr) = self.encipher(l, r);
            l = nl;
            r = nr;
            self.p[i] = l;
            self.p[i + 1] = r;
        }
        for s_box in 0..4 {
            for i in (0..256).step_by(2) {
                let (nl, nr) = self.encipher(l, r);
                l = nl;
                r = nr;
                self.s[s_box][i] = l;
                self.s[s_box][i + 1] = r;
            }
        }
    }
}

pub fn bcrypt_encode_base64(input: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let mut c1 = input[i] as usize;
        i += 1;
        out.push(BCRYPT_ALPHABET[(c1 >> 2) & 0x3F] as char);
        c1 = (c1 & 0x03) << 4;
        if i >= input.len() {
            out.push(BCRYPT_ALPHABET[c1] as char);
            break;
        }
        let mut c2 = input[i] as usize;
        i += 1;
        c1 |= (c2 >> 4) & 0x0F;
        out.push(BCRYPT_ALPHABET[c1] as char);
        c1 = (c2 & 0x0F) << 2;
        if i >= input.len() {
            out.push(BCRYPT_ALPHABET[c1] as char);
            break;
        }
        c2 = input[i] as usize;
        i += 1;
        c1 |= (c2 >> 6) & 0x03;
        out.push(BCRYPT_ALPHABET[c1] as char);
        out.push(BCRYPT_ALPHABET[c2 & 0x3F] as char);
    }
    out
}

pub fn bcrypt_hash_2y(
    password: &[u8],
    cost: u32,
    salt16: &[u8; 16],
) -> Result<Zeroizing<String>, String> {
    if !(4..=31).contains(&cost) {
        return Err(format!("Unsupported bcrypt cost: {}", cost));
    }
    let mut pw_buf = Zeroizing::new(password[..password.len().min(72)].to_vec());
    if pw_buf.len() < 72 {
        pw_buf.push(0); // OpenBSD NUL terminator included up to 72 bytes
    }

    let mut state = BlowfishState::new();
    state.expand_key(salt16, &pw_buf);
    let rounds = 1u32 << cost;
    for _ in 0..rounds {
        state.expand_0_state(&pw_buf);
        state.expand_0_state(salt16);
    }

    let mut cdata: [u32; 6] = [
        0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274,
    ];
    for _ in 0..64 {
        for j in (0..6).step_by(2) {
            let (nl, nr) = state.encipher(cdata[j], cdata[j + 1]);
            cdata[j] = nl;
            cdata[j + 1] = nr;
        }
    }

    let mut hash_bytes = [0u8; 23];
    for (i, word) in cdata.iter().enumerate() {
        let be = word.to_be_bytes();
        let base = i * 4;
        for (j, byte) in be.iter().enumerate() {
            if base + j < 23 {
                hash_bytes[base + j] = *byte;
            }
        }
    }

    let salt_b64 = bcrypt_encode_base64(salt16);
    let hash_b64 = bcrypt_encode_base64(&hash_bytes);
    Ok(Zeroizing::new(format!(
        "$2y${:02}${}{}",
        cost, salt_b64, hash_b64
    )))
}

// ============================================================================
// Proton SRP-6a Client
// ============================================================================

pub fn expand_hash(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    for round in 0u8..=3u8 {
        let mut h = Sha512::new();
        h.update(data);
        h.update([round]);
        out.extend_from_slice(&h.finalize());
    }
    out
}

pub fn hash_password_v4(
    password: &str,
    salt_10: &[u8],
    modulus_le: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if salt_10.len() < 10 {
        return Err("SRP v4 salt must be at least 10 bytes".to_string());
    }
    let mut salt16 = [0u8; 16];
    salt16[..10].copy_from_slice(&salt_10[..10]);
    salt16[10..16].copy_from_slice(b"proton");
    let bcrypt_out = bcrypt_hash_2y(password.as_bytes(), 10, &salt16)?;
    let mut combined = Zeroizing::new(Vec::with_capacity(bcrypt_out.len() + modulus_le.len()));
    combined.extend_from_slice(bcrypt_out.as_bytes());
    combined.extend_from_slice(modulus_le);
    Ok(Zeroizing::new(expand_hash(&combined)))
}

pub fn derive_key_passphrase(password: &str, salt_b64: &str) -> Result<Zeroizing<String>, String> {
    let salt_raw = BASE64
        .decode(salt_b64.trim())
        .map_err(|e| format!("Invalid key salt base64: {}", e))?;
    if salt_raw.len() < 16 {
        return Err(format!("Expected 16-byte key salt, got {}", salt_raw.len()));
    }
    let mut salt16 = [0u8; 16];
    salt16.copy_from_slice(&salt_raw[..16]);
    let full = bcrypt_hash_2y(password.as_bytes(), 10, &salt16)?;
    if full.len() < 29 {
        return Err("Unexpected bcrypt output length".to_string());
    }
    Ok(Zeroizing::new(full[29..].to_string()))
}

/// Pinned Proton SRP modulus verification public key (`proton@srp.modulus`, key ID `350585C4E9518F26`).
pub const PROTON_SRP_MODULUS_PUBLIC_KEY: &str = "\
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----";

/// Returns the default pinned Proton SRP modulus verification keys.
pub fn default_trusted_srp_keys() -> Vec<String> {
    vec![PROTON_SRP_MODULUS_PUBLIC_KEY.to_string()]
}

/// Parses and cryptographically verifies a cleartext-signed SRP modulus against trusted server keys.
pub fn extract_and_verify_modulus_bytes(
    raw_modulus: &str,
    trusted_server_keys: &[String],
) -> Result<Vec<u8>, String> {
    let signed_text =
        DriveCrypto::verify_cleartext_signed(raw_modulus.trim(), trusted_server_keys)?;
    let joined: String = signed_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    BASE64
        .decode(joined.as_bytes())
        .map_err(|e| format!("Failed decoding verified SRP modulus: {}", e))
}

pub struct SrpProof {
    pub client_ephemeral_b64: String,
    pub client_proof_b64: String,
    pub expected_server_proof: Vec<u8>,
}

impl std::fmt::Debug for SrpProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpProof")
            .field("client_ephemeral_len", &self.client_ephemeral_b64.len())
            .finish_non_exhaustive()
    }
}

pub struct SrpClient;

impl SrpClient {
    pub fn generate_proof(
        password: &str,
        salt_b64: &str,
        modulus_armored: &str,
        server_ephemeral_b64: &str,
        version: i32,
        trusted_server_keys: &[String],
    ) -> Result<SrpProof, String> {
        let modulus_bytes = extract_and_verify_modulus_bytes(modulus_armored, trusted_server_keys)?;
        if modulus_bytes.len() < 32 {
            return Err("SRP modulus too short".to_string());
        }
        let byte_len = modulus_bytes.len();
        let n = BigUint::from_le_bytes(&modulus_bytes);

        let server_ephemeral_bytes = BASE64
            .decode(server_ephemeral_b64.trim())
            .map_err(|e| format!("Invalid server ephemeral base64: {}", e))?;
        let b_big = BigUint::from_le_bytes(&server_ephemeral_bytes);
        if b_big.rem(&n).is_zero() {
            return Err("Invalid SRP server ephemeral B == 0 mod N".to_string());
        }

        let salt_bytes = BASE64
            .decode(salt_b64.trim())
            .map_err(|e| format!("Invalid SRP salt base64: {}", e))?;

        let x_bytes = if version >= 4 {
            hash_password_v4(password, &salt_bytes, &modulus_bytes)?
        } else {
            // Legacy fallback using expand_hash(password || salt)
            let mut buf = Zeroizing::new(password.as_bytes().to_vec());
            buf.extend_from_slice(&salt_bytes);
            Zeroizing::new(expand_hash(&buf))
        };
        let x = BigUint::from_le_bytes(&x_bytes);

        let g = BigUint::from_u64(2);
        let g_padded = g.to_le_bytes_padded(byte_len);
        let mut k_input = Vec::with_capacity(byte_len * 2);
        k_input.extend_from_slice(&g_padded);
        k_input.extend_from_slice(&modulus_bytes);
        let k_bytes = expand_hash(&k_input);
        let k = BigUint::from_le_bytes(&k_bytes).rem(&n);

        // Client ephemeral secret a (256-bit random)
        let a_rand = Zeroizing::new(random_bytes(32)?);
        let a = BigUint::from_le_bytes(&a_rand);
        let a_pub = g.mod_pow(&a, &n);
        let a_pub_bytes = a_pub.to_le_bytes_padded(byte_len);
        let b_padded = b_big.to_le_bytes_padded(byte_len);

        // u = H_expand(A || B)
        let mut u_input = Vec::with_capacity(byte_len * 2);
        u_input.extend_from_slice(&a_pub_bytes);
        u_input.extend_from_slice(&b_padded);
        let u_bytes = expand_hash(&u_input);
        let u = BigUint::from_le_bytes(&u_bytes);
        if u.is_zero() {
            return Err("Invalid SRP scrambling parameter u == 0".to_string());
        }

        // S = (B - k * g^x mod N)^(a + u * x) mod N
        let gx = g.mod_pow(&x, &n);
        let kgx = k.mul_mod(&gx, &n);
        let b_mod = b_big.rem(&n);
        let base = if b_mod.cmp_ref(&kgx) != std::cmp::Ordering::Less {
            b_mod.sub_checked(&kgx).unwrap()
        } else {
            b_mod.add(&n).sub_checked(&kgx).unwrap()
        };
        let exp = a.add(&u.mul(&x));
        let s = base.mod_pow(&exp, &n);
        let s_bytes = Zeroizing::new(s.to_le_bytes_padded(byte_len));

        // M1 = H_expand(A || B || S)
        let mut m1_input = Zeroizing::new(Vec::with_capacity(byte_len * 3));
        m1_input.extend_from_slice(&a_pub_bytes);
        m1_input.extend_from_slice(&b_padded);
        m1_input.extend_from_slice(&s_bytes);
        let m1 = expand_hash(&m1_input);

        // M2 = H_expand(A || M1 || S)
        let mut m2_input = Zeroizing::new(Vec::with_capacity(byte_len * 2 + m1.len()));
        m2_input.extend_from_slice(&a_pub_bytes);
        m2_input.extend_from_slice(&m1);
        m2_input.extend_from_slice(&s_bytes);
        let m2 = expand_hash(&m2_input);

        Ok(SrpProof {
            client_ephemeral_b64: BASE64.encode(&a_pub_bytes),
            client_proof_b64: BASE64.encode(&m1),
            expected_server_proof: m2,
        })
    }

    pub fn verify_server_proof(expected: &[u8], server_proof_b64: &str) -> Result<(), String> {
        let actual = BASE64
            .decode(server_proof_b64.trim())
            .map_err(|e| format!("Invalid server proof base64: {}", e))?;
        if actual.len() != expected.len() {
            return Err("SRP server proof length mismatch".to_string());
        }
        let diff = actual
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err("SRP server proof verification failed".to_string());
        }
        Ok(())
    }
}

// ============================================================================
// Auth Endpoint Wire Models
// ============================================================================

#[derive(Deserialize)]
struct UnauthSessionResponse {
    #[serde(rename = "Code", alias = "code")]
    code: i64,
    #[serde(rename = "UID", alias = "uid", default)]
    uid: String,
    #[serde(rename = "AccessToken", alias = "accessToken", default)]
    access_token: String,
    #[serde(rename = "RefreshToken", alias = "refreshToken", default)]
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct AuthInfoRequest<'a> {
    #[serde(rename = "Username")]
    username: &'a str,
    #[serde(rename = "Intent")]
    intent: &'a str,
}

#[derive(Debug, Deserialize)]
struct AuthInfoResponse {
    #[serde(rename = "Code", alias = "code")]
    code: i64,
    #[serde(rename = "Modulus", alias = "modulus")]
    modulus: String,
    #[serde(rename = "ServerEphemeral", alias = "serverEphemeral")]
    server_ephemeral: String,
    #[serde(rename = "Version", alias = "version", default = "default_srp_version")]
    version: i32,
    #[serde(rename = "Salt", alias = "salt")]
    salt: String,
    #[serde(rename = "SRPSession", alias = "srpSession")]
    srp_session: String,
}

fn default_srp_version() -> i32 {
    4
}

#[derive(Debug, Serialize)]
struct AuthRequest<'a> {
    #[serde(rename = "Username")]
    username: &'a str,
    #[serde(rename = "ClientEphemeral")]
    client_ephemeral: &'a str,
    #[serde(rename = "ClientProof")]
    client_proof: &'a str,
    #[serde(rename = "SRPSession")]
    srp_session: &'a str,
}

#[derive(Debug, Deserialize, Default)]
struct TwoFactorInfo {
    #[serde(rename = "Enabled", alias = "enabled", default)]
    enabled: i32,
}

#[derive(Deserialize)]
struct AuthResponse {
    #[serde(rename = "Code", alias = "code")]
    code: i64,
    #[serde(rename = "UID", alias = "uid")]
    uid: String,
    #[serde(rename = "AccessToken", alias = "accessToken")]
    access_token: String,
    #[serde(rename = "RefreshToken", alias = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "ServerProof", alias = "serverProof", default)]
    server_proof: Option<String>,
    #[serde(rename = "2FA", alias = "TwoFactor", default)]
    two_factor: TwoFactorInfo,
}

impl std::fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthResponse")
            .field("code", &self.code)
            .field("uid", &self.uid)
            .field("has_server_proof", &self.server_proof.is_some())
            .field("two_factor", &self.two_factor)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
struct TwoFactorRequest<'a> {
    #[serde(rename = "TwoFactorCode")]
    two_factor_code: &'a str,
}

#[derive(Deserialize)]
struct UserKeyInfo {
    #[serde(rename = "ID", alias = "id")]
    pub id: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    pub private_key: String,
    #[serde(rename = "Primary", alias = "primary", default)]
    pub primary: i32,
}

impl std::fmt::Debug for UserKeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserKeyInfo")
            .field("id", &self.id)
            .field("primary", &self.primary)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct UserPayload {
    #[serde(rename = "ID", alias = "id", default)]
    pub id: String,
    #[serde(rename = "Email", alias = "email", default)]
    pub email: Option<String>,
    #[serde(rename = "Name", alias = "name", default)]
    pub name: Option<String>,
    #[serde(rename = "UsedSpace", alias = "usedSpace", default)]
    pub used_space: Option<u64>,
    #[serde(rename = "MaxSpace", alias = "maxSpace", default)]
    pub max_space: Option<u64>,
    #[serde(rename = "UsedDriveSpace", alias = "usedDriveSpace", default)]
    pub used_drive_space: Option<u64>,
    #[serde(rename = "MaxDriveSpace", alias = "maxDriveSpace", default)]
    pub max_drive_space: Option<u64>,
    #[serde(rename = "Keys", alias = "keys", default)]
    pub keys: Vec<UserKeyInfo>,
}

#[derive(Debug, Deserialize)]
struct UsersResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "User", alias = "user")]
    pub user: UserPayload,
}

#[derive(Debug, Deserialize)]
struct KeySaltItem {
    #[serde(rename = "ID", alias = "id")]
    pub id: String,
    #[serde(rename = "KeySalt", alias = "keySalt", default)]
    pub key_salt: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KeySaltsResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "KeySalts", alias = "keySalts", default)]
    pub key_salts: Vec<KeySaltItem>,
}

#[derive(Deserialize)]
struct AddressKeyItem {
    #[serde(rename = "ID", alias = "id")]
    pub id: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    pub private_key: String,
    #[serde(rename = "Primary", alias = "primary", default)]
    pub primary: i32,
    #[serde(rename = "Active", alias = "active", default)]
    pub active: i32,
    #[serde(rename = "Token", alias = "token", default)]
    pub token: Option<String>,
}

impl std::fmt::Debug for AddressKeyItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressKeyItem")
            .field("id", &self.id)
            .field("primary", &self.primary)
            .field("active", &self.active)
            .field("has_token", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct AddressItem {
    #[serde(rename = "ID", alias = "id")]
    pub id: String,
    #[serde(rename = "Email", alias = "email")]
    pub email: String,
    #[serde(rename = "Keys", alias = "keys", default)]
    pub keys: Vec<AddressKeyItem>,
}

#[derive(Debug, Deserialize)]
struct AddressesResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "Addresses", alias = "addresses", default)]
    pub addresses: Vec<AddressItem>,
}

const DEFAULT_ACCOUNT_WEB_URL: &str = "https://account.proton.me";
// Browser SSO session forking (`/desktop/login?app=drive&pv=3`) requires a
// server-recognized child client ID registered on account.proton.me. Keep
// `cli-drive` until live SSO verification confirms an alternate external ID.
const FORK_CHILD_CLIENT_ID: &str = "cli-drive";
const FORK_AAD: &[u8] = b"fork";

#[derive(Debug, Deserialize)]
struct ForkInitResponse {
    #[serde(rename = "Code", alias = "code")]
    pub code: i64,
    #[serde(rename = "Selector", alias = "selector")]
    pub selector: String,
    #[serde(rename = "UserCode", alias = "userCode")]
    pub user_code: String,
}

#[derive(Deserialize)]
struct ForkPollResponse {
    #[serde(rename = "Code", alias = "code", default)]
    pub code: Option<i64>,
    #[serde(rename = "Payload", alias = "payload", default)]
    pub payload: Option<String>,
    #[serde(rename = "UID", alias = "uid")]
    pub uid: String,
    #[serde(rename = "AccessToken", alias = "accessToken")]
    pub access_token: String,
    #[serde(rename = "RefreshToken", alias = "refreshToken")]
    pub refresh_token: String,
}

#[derive(Deserialize, Zeroize)]
struct ForkDecryptedPayload {
    #[serde(rename = "keyPassword", default)]
    pub key_password: String,
}

#[derive(Clone)]
pub struct BrowserLoginChallenge {
    pub selector: String,
    pub user_code: String,
    pub login_url: String,
    encryption_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for BrowserLoginChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserLoginChallenge")
            .field("selector", &self.selector)
            .field("user_code", &self.user_code)
            .finish_non_exhaustive()
    }
}

pub fn decrypt_fork_payload(
    encryption_key: &[u8],
    payload_b64: &str,
) -> Result<Zeroizing<String>, String> {
    if encryption_key.len() != 32 {
        return Err("Invalid fork encryption key length".to_string());
    }
    let blob = BASE64
        .decode(payload_b64.trim())
        .map_err(|e| format!("Invalid fork payload base64: {}", e))?;
    if blob.len() < 12 + 16 {
        return Err("Invalid fork payload blob length".to_string());
    }
    let (iv_bytes, ct_and_tag) = blob.split_at(12);
    let iv: [u8; 12] = iv_bytes
        .try_into()
        .map_err(|_| "Invalid fork IV length".to_string())?;

    let unbound = UnboundKey::new(&AES_256_GCM, encryption_key)
        .map_err(|_| "Failed initializing AES-256-GCM key for fork payload".to_string())?;
    let key = LessSafeKey::new(unbound);
    let mut work = Zeroizing::new(ct_and_tag.to_vec());
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(FORK_AAD),
            &mut work,
        )
        .map_err(|_| "Failed decrypting browser login fork payload".to_string())?;
    let parsed: ForkDecryptedPayload = serde_json::from_slice(plain)
        .map_err(|e| format!("Failed parsing decrypted browser login fork payload: {}", e))?;
    Ok(Zeroizing::new(parsed.key_password))
}

// ============================================================================
// SessionVault (Linux Secret Service + Independently-Keyed Fallback)
// ============================================================================

const VAULT_FORMAT_VERSION: u32 = 2;
const STORAGE_SECRET_SERVICE: &str = "secret-service";
const STORAGE_ENCRYPTED_FALLBACK: &str = "encrypted-fallback";
const SECRET_SERVICE_APP: &str = "neutron-drive";
const SECRET_SERVICE_TYPE: &str = "neutron-drive-native";
const SECRET_SERVICE_LABEL: &str = "Neutron Drive Session";
const VAULT_ENV_KEY: &str = "PROTON_DRIVE_VAULT_KEY";
const VAULT_ENV_KEY_FILE: &str = "PROTON_DRIVE_VAULT_KEY_FILE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultStorageError {
    KeyringLocked(String),
    KeyringUnavailable(String),
    StorageFailure(String),
    CryptoFailure(String),
    InvalidFormat(String),
}

impl std::fmt::Display for VaultStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultStorageError::KeyringLocked(m) => write!(f, "Keyring locked: {}", m),
            VaultStorageError::KeyringUnavailable(m) => write!(f, "Keyring unavailable: {}", m),
            VaultStorageError::StorageFailure(m) => write!(f, "Session storage failure: {}", m),
            VaultStorageError::CryptoFailure(m) => write!(f, "Session crypto failure: {}", m),
            VaultStorageError::InvalidFormat(m) => write!(f, "Invalid session vault format: {}", m),
        }
    }
}

impl std::error::Error for VaultStorageError {}

pub trait SecretStore: Send + Sync {
    fn store_secret(&self, account: &str, secret_bytes: &[u8]) -> Result<(), VaultStorageError>;
    fn load_secret(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStorageError>;
    fn delete_secret(&self, account: &str) -> Result<(), VaultStorageError>;
}

pub trait FallbackKeyProvider: Send + Sync {
    fn resolve_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStorageError>;
}

#[derive(Debug, Default)]
pub struct EnvFallbackKeyProvider;

impl FallbackKeyProvider for EnvFallbackKeyProvider {
    fn resolve_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStorageError> {
        if let Some(raw) = std::env::var_os(VAULT_ENV_KEY) {
            let s = raw.to_string_lossy();
            if !s.is_empty() {
                return Ok(Some(Zeroizing::new(s.as_bytes().to_vec())));
            }
        }
        if let Some(path_os) = std::env::var_os(VAULT_ENV_KEY_FILE) {
            if !path_os.is_empty() {
                let key_path = PathBuf::from(path_os);
                #[cfg(unix)]
                {
                    let euid = unsafe { libc::geteuid() };
                    let meta = fs::symlink_metadata(&key_path).map_err(|e| {
                        VaultStorageError::StorageFailure(format!(
                            "Failed inspecting fallback key file {:?}: {}",
                            key_path, e
                        ))
                    })?;
                    if meta.file_type().is_symlink() || !meta.is_file() || meta.uid() != euid {
                        return Err(VaultStorageError::StorageFailure(format!(
                            "Unsafe fallback key file {:?}: must be regular file owned by current user",
                            key_path
                        )));
                    }
                    if (meta.permissions().mode() & 0o077) != 0 {
                        return Err(VaultStorageError::StorageFailure(format!(
                            "Unsafe fallback key file {:?}: permissions must be 0600 or stricter",
                            key_path
                        )));
                    }
                }
                let bytes = Zeroizing::new(fs::read(&key_path).map_err(|e| {
                    VaultStorageError::StorageFailure(format!(
                        "Failed reading fallback key file {:?}: {}",
                        key_path, e
                    ))
                })?);
                if bytes.is_empty() {
                    return Err(VaultStorageError::StorageFailure(format!(
                        "Fallback key file {:?} must not be empty",
                        key_path
                    )));
                }
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }
}

pub struct StaticFallbackKeyProvider(Zeroizing<Vec<u8>>);

impl StaticFallbackKeyProvider {
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(key.into()))
    }
}

impl FallbackKeyProvider for StaticFallbackKeyProvider {
    fn resolve_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStorageError> {
        if self.0.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.0.clone()))
        }
    }
}

#[derive(Debug, Default)]
pub struct NoFallbackKeyProvider;

impl FallbackKeyProvider for NoFallbackKeyProvider {
    fn resolve_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStorageError> {
        Ok(None)
    }
}

#[derive(Default)]
struct InMemorySecretStoreInner {
    secrets: HashMap<String, Zeroizing<Vec<u8>>>,
    locked: bool,
    unavailable: bool,
    fail_writes: bool,
    fail_reads: bool,
    fail_deletes: bool,
}

#[derive(Clone, Default)]
pub struct InMemorySecretStore {
    inner: Arc<Mutex<InMemorySecretStoreInner>>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_locked(&self, locked: bool) {
        self.inner.lock().unwrap().locked = locked;
    }

    pub fn set_unavailable(&self, unavailable: bool) {
        self.inner.lock().unwrap().unavailable = unavailable;
    }

    pub fn set_fail_writes(&self, fail: bool) {
        self.inner.lock().unwrap().fail_writes = fail;
    }

    pub fn set_fail_reads(&self, fail: bool) {
        self.inner.lock().unwrap().fail_reads = fail;
    }

    pub fn set_fail_deletes(&self, fail: bool) {
        self.inner.lock().unwrap().fail_deletes = fail;
    }

    pub fn has_secret(&self, account: &str) -> bool {
        self.inner.lock().unwrap().secrets.contains_key(account)
    }

    pub fn secret_count(&self) -> usize {
        self.inner.lock().unwrap().secrets.len()
    }
}

impl SecretStore for InMemorySecretStore {
    fn store_secret(&self, account: &str, secret_bytes: &[u8]) -> Result<(), VaultStorageError> {
        let mut g = self.inner.lock().unwrap();
        if g.unavailable {
            return Err(VaultStorageError::KeyringUnavailable(
                "Mock Secret Service unavailable".to_string(),
            ));
        }
        if g.locked {
            return Err(VaultStorageError::KeyringLocked(
                "Mock Secret Service collection is locked".to_string(),
            ));
        }
        if g.fail_writes {
            return Err(VaultStorageError::StorageFailure(
                "Mock Secret Service write failure".to_string(),
            ));
        }
        g.secrets
            .insert(account.to_string(), Zeroizing::new(secret_bytes.to_vec()));
        Ok(())
    }

    fn load_secret(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStorageError> {
        let g = self.inner.lock().unwrap();
        if g.unavailable {
            return Err(VaultStorageError::KeyringUnavailable(
                "Mock Secret Service unavailable".to_string(),
            ));
        }
        if g.locked {
            return Err(VaultStorageError::KeyringLocked(
                "Mock Secret Service collection is locked".to_string(),
            ));
        }
        if g.fail_reads {
            return Err(VaultStorageError::StorageFailure(
                "Mock Secret Service read failure".to_string(),
            ));
        }
        Ok(g.secrets.get(account).cloned())
    }

    fn delete_secret(&self, account: &str) -> Result<(), VaultStorageError> {
        let mut g = self.inner.lock().unwrap();
        if g.unavailable {
            return Err(VaultStorageError::KeyringUnavailable(
                "Mock Secret Service unavailable".to_string(),
            ));
        }
        if g.locked {
            return Err(VaultStorageError::KeyringLocked(
                "Mock Secret Service collection is locked".to_string(),
            ));
        }
        if g.fail_deletes {
            return Err(VaultStorageError::StorageFailure(
                "Mock Secret Service delete failure".to_string(),
            ));
        }
        g.secrets.remove(account);
        Ok(())
    }
}

#[derive(zbus::zvariant::Type, serde::Serialize, serde::Deserialize)]
struct DbusSecret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

#[derive(Debug, Default)]
pub struct LinuxSecretServiceStore;

impl LinuxSecretServiceStore {
    fn map_dbus_err(context: &str, err: zbus::Error) -> VaultStorageError {
        let msg = err.to_string();
        if let zbus::Error::MethodError(ref name, ref detail, _) = err {
            let name_str = name.as_str();
            if name_str.contains("ServiceUnknown")
                || name_str.contains("NameHasNoOwner")
                || name_str.contains("Spawn")
            {
                return VaultStorageError::KeyringUnavailable(format!("{}: {}", context, msg));
            }
            if name_str.contains("IsLocked")
                || detail
                    .as_deref()
                    .is_some_and(|d| d.to_ascii_lowercase().contains("locked"))
            {
                return VaultStorageError::KeyringLocked(format!("{}: {}", context, msg));
            }
        }
        if matches!(err, zbus::Error::Address(_) | zbus::Error::InputOutput(_))
            || msg.contains("DBUS_SESSION_BUS_ADDRESS")
            || msg.contains("ServiceUnknown")
            || msg.contains("NameHasNoOwner")
        {
            return VaultStorageError::KeyringUnavailable(format!("{}: {}", context, msg));
        }
        VaultStorageError::StorageFailure(format!("{}: {}", context, msg))
    }

    fn run_prompt(
        conn: &DbusConnection,
        prompt_path: &OwnedObjectPath,
    ) -> Result<(), VaultStorageError> {
        if prompt_path.as_str() == "/" || prompt_path.as_str().is_empty() {
            return Ok(());
        }
        let prompt_proxy = DbusProxy::new(
            conn,
            "org.freedesktop.secrets",
            prompt_path.as_ref(),
            "org.freedesktop.Secret.Prompt",
        )
        .map_err(|e| Self::map_dbus_err("Prompt proxy creation failed", e))?;

        let signals = prompt_proxy
            .receive_signal("Completed")
            .map_err(|e| Self::map_dbus_err("Subscribing to Secret Service prompt failed", e))?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut iter = signals;
            if let Some(msg) = iter.next() {
                let parsed = msg.body().deserialize::<(bool, OwnedValue)>().ok();
                let _ = tx.send(parsed);
            }
        });

        prompt_proxy
            .call::<_, _, ()>("Prompt", &("",))
            .map_err(|e| Self::map_dbus_err("Triggering Secret Service unlock prompt failed", e))?;

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Some((false, _))) => Ok(()),
            Ok(Some((true, _))) => Err(VaultStorageError::KeyringLocked(
                "Secret Service unlock prompt was dismissed".to_string(),
            )),
            _ => {
                let _ = prompt_proxy.call::<_, _, ()>("Dismiss", &());
                Err(VaultStorageError::KeyringLocked(
                    "Secret Service unlock prompt timed out or remained locked".to_string(),
                ))
            }
        }
    }

    fn open_session(
        conn: &DbusConnection,
        service: &DbusProxy<'_>,
    ) -> Result<OwnedObjectPath, VaultStorageError> {
        let (_out, session_path): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::from("")))
            .map_err(|e| Self::map_dbus_err("Secret Service OpenSession failed", e))?;
        let _ = conn;
        Ok(session_path)
    }

    fn close_session(conn: &DbusConnection, session_path: &OwnedObjectPath) {
        if let Ok(sess_proxy) = DbusProxy::new(
            conn,
            "org.freedesktop.secrets",
            session_path.as_ref(),
            "org.freedesktop.Secret.Session",
        ) {
            let _: Result<(), _> = sess_proxy.call("Close", &());
        }
    }

    fn unlock_objects(
        conn: &DbusConnection,
        service: &DbusProxy<'_>,
        objs: &[ObjectPath<'_>],
    ) -> Result<Vec<OwnedObjectPath>, VaultStorageError> {
        let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
            .call("Unlock", &(objs,))
            .map_err(|e| Self::map_dbus_err("Secret Service Unlock failed", e))?;
        if prompt.as_str() != "/" && !prompt.as_str().is_empty() {
            Self::run_prompt(conn, &prompt)?;
            // Re-run Unlock once or return unlocked objects; if prompt succeeded, unlocked items may be in Completed result or unlocked now.
            let (unlocked_after, _): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
                .call("Unlock", &(objs,))
                .map_err(|e| Self::map_dbus_err("Secret Service Unlock verification failed", e))?;
            return Ok(unlocked_after);
        }
        Ok(unlocked)
    }

    fn default_collection<'a>(
        conn: &'a DbusConnection,
        service: &DbusProxy<'a>,
    ) -> Result<OwnedObjectPath, VaultStorageError> {
        let mut coll: OwnedObjectPath = service
            .call("ReadAlias", &("default",))
            .map_err(|e| Self::map_dbus_err("Secret Service ReadAlias(default) failed", e))?;
        if coll.as_str() == "/" || coll.as_str().is_empty() {
            let login_path = ObjectPath::try_from("/org/freedesktop/secrets/collection/login")
                .map_err(|e| VaultStorageError::StorageFailure(e.to_string()))?;
            let probe = DbusProxy::new(
                conn,
                "org.freedesktop.secrets",
                login_path.clone(),
                "org.freedesktop.Secret.Collection",
            );
            if probe.and_then(|p| p.get_property::<bool>("Locked")).is_ok() {
                coll = login_path.into();
            } else {
                return Err(VaultStorageError::KeyringUnavailable(
                    "No default Secret Service collection is available".to_string(),
                ));
            }
        }
        Ok(coll)
    }

    fn item_attributes(account: &str) -> HashMap<&'static str, &str> {
        let mut attrs = HashMap::new();
        attrs.insert("application", SECRET_SERVICE_APP);
        attrs.insert("service", SECRET_SERVICE_TYPE);
        attrs.insert("account", account);
        attrs
    }
}

impl SecretStore for LinuxSecretServiceStore {
    fn store_secret(&self, account: &str, secret_bytes: &[u8]) -> Result<(), VaultStorageError> {
        let conn = DbusConnection::session()
            .map_err(|e| Self::map_dbus_err("D-Bus session connection unavailable", e))?;
        let service = DbusProxy::new(
            &conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .map_err(|e| Self::map_dbus_err("Secret Service proxy unavailable", e))?;

        let session_path = Self::open_session(&conn, &service)?;
        let res = (|| -> Result<(), VaultStorageError> {
            let coll_path = Self::default_collection(&conn, &service)?;
            let coll_proxy = DbusProxy::new(
                &conn,
                "org.freedesktop.secrets",
                coll_path.as_ref(),
                "org.freedesktop.Secret.Collection",
            )
            .map_err(|e| Self::map_dbus_err("Secret Service collection unavailable", e))?;

            let is_locked: bool = coll_proxy
                .get_property("Locked")
                .map_err(|e| Self::map_dbus_err("Reading collection Locked property failed", e))?;
            if is_locked {
                let unlocked = Self::unlock_objects(&conn, &service, &[coll_path.as_ref()])?;
                let still_locked: bool = coll_proxy.get_property("Locked").unwrap_or(true);
                if still_locked || unlocked.is_empty() {
                    return Err(VaultStorageError::KeyringLocked(
                        "Secret Service default collection is locked".to_string(),
                    ));
                }
            }

            let mut attrs: HashMap<String, String> = HashMap::new();
            attrs.insert("application".to_string(), SECRET_SERVICE_APP.to_string());
            attrs.insert("service".to_string(), SECRET_SERVICE_TYPE.to_string());
            attrs.insert("account".to_string(), account.to_string());

            let mut props: HashMap<&str, Value<'_>> = HashMap::new();
            props.insert(
                "org.freedesktop.Secret.Item.Label",
                Value::from(SECRET_SERVICE_LABEL),
            );
            props.insert("org.freedesktop.Secret.Item.Attributes", Value::from(attrs));

            let secret = DbusSecret {
                session: session_path.clone(),
                parameters: Vec::new(),
                value: secret_bytes.to_vec(),
                content_type: "application/json".to_string(),
            };
            let (item_path, prompt): (OwnedObjectPath, OwnedObjectPath) = coll_proxy
                .call("CreateItem", &(props, secret, true))
                .map_err(|e| Self::map_dbus_err("Secret Service CreateItem failed", e))?;
            Self::run_prompt(&conn, &prompt)?;
            if item_path.as_str() == "/" && prompt.as_str() == "/" {
                return Err(VaultStorageError::StorageFailure(
                    "Secret Service CreateItem returned no item".to_string(),
                ));
            }
            Ok(())
        })();

        Self::close_session(&conn, &session_path);
        res
    }

    fn load_secret(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStorageError> {
        let conn = DbusConnection::session()
            .map_err(|e| Self::map_dbus_err("D-Bus session connection unavailable", e))?;
        let service = DbusProxy::new(
            &conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .map_err(|e| Self::map_dbus_err("Secret Service proxy unavailable", e))?;

        let session_path = Self::open_session(&conn, &service)?;
        let res = (|| -> Result<Option<Zeroizing<Vec<u8>>>, VaultStorageError> {
            let attrs = Self::item_attributes(account);
            let (mut unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
                .call("SearchItems", &(attrs,))
                .map_err(|e| Self::map_dbus_err("Secret Service SearchItems failed", e))?;

            if unlocked.is_empty() && !locked.is_empty() {
                let locked_refs: Vec<ObjectPath<'_>> = locked.iter().map(|p| p.as_ref()).collect();
                unlocked = Self::unlock_objects(&conn, &service, &locked_refs)?;
                if unlocked.is_empty() {
                    return Err(VaultStorageError::KeyringLocked(
                        "Secret Service session item is locked".to_string(),
                    ));
                }
            }

            let Some(item_path) = unlocked.first() else {
                return Ok(None);
            };
            let item_proxy = DbusProxy::new(
                &conn,
                "org.freedesktop.secrets",
                item_path.as_ref(),
                "org.freedesktop.Secret.Item",
            )
            .map_err(|e| Self::map_dbus_err("Secret Service item proxy failed", e))?;

            let mut secret: DbusSecret = item_proxy
                .call("GetSecret", &(session_path.as_ref(),))
                .map_err(|e| Self::map_dbus_err("Secret Service GetSecret failed", e))?;
            let out = Zeroizing::new(std::mem::take(&mut secret.value));
            Ok(Some(out))
        })();

        Self::close_session(&conn, &session_path);
        res
    }

    fn delete_secret(&self, account: &str) -> Result<(), VaultStorageError> {
        let conn = DbusConnection::session()
            .map_err(|e| Self::map_dbus_err("D-Bus session connection unavailable", e))?;
        let service = DbusProxy::new(
            &conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .map_err(|e| Self::map_dbus_err("Secret Service proxy unavailable", e))?;

        let attrs = Self::item_attributes(account);
        let (mut unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &(attrs,))
            .map_err(|e| Self::map_dbus_err("Secret Service SearchItems failed", e))?;

        if !locked.is_empty() {
            let locked_refs: Vec<ObjectPath<'_>> = locked.iter().map(|p| p.as_ref()).collect();
            let newly_unlocked = Self::unlock_objects(&conn, &service, &locked_refs)?;
            if newly_unlocked.is_empty() {
                return Err(VaultStorageError::KeyringLocked(
                    "Cannot delete locked Secret Service session item".to_string(),
                ));
            }
            unlocked.extend(newly_unlocked);
        }

        for item_path in unlocked {
            let item_proxy = DbusProxy::new(
                &conn,
                "org.freedesktop.secrets",
                item_path.as_ref(),
                "org.freedesktop.Secret.Item",
            )
            .map_err(|e| Self::map_dbus_err("Secret Service item proxy failed", e))?;
            let prompt: OwnedObjectPath = item_proxy
                .call("Delete", &())
                .map_err(|e| Self::map_dbus_err("Secret Service item Delete failed", e))?;
            Self::run_prompt(&conn, &prompt)?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultAddressKeyRecord {
    pub address_id: String,
    pub email: String,
    pub key_id: String,
    pub private_key_armored: String,
    pub token: Option<String>,
    pub primary: bool,
}

impl std::fmt::Debug for VaultAddressKeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultAddressKeyRecord")
            .field("address_id", &self.address_id)
            .field("email", &self.email)
            .field("key_id", &self.key_id)
            .field("primary", &self.primary)
            .field("has_token", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SessionVaultData {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
    pub user_email: String,
    pub used_space: u64,
    pub max_space: u64,
    pub primary_user_key_armored: Option<String>,
    pub key_passphrase: Option<String>,
    pub address_keys: Vec<VaultAddressKeyRecord>,
}

impl std::fmt::Debug for SessionVaultData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionVaultData")
            .field("uid", &self.uid)
            .field("user_id", &self.user_id)
            .field("user_email", &self.user_email)
            .field("used_space", &self.used_space)
            .field("max_space", &self.max_space)
            .field(
                "has_primary_user_key",
                &self.primary_user_key_armored.is_some(),
            )
            .field("has_key_passphrase", &self.key_passphrase.is_some())
            .field("address_key_count", &self.address_keys.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultSecrets {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    primary_user_key_armored: Option<String>,
    #[serde(default)]
    key_passphrase: Option<String>,
    #[serde(default)]
    address_keys: Vec<VaultAddressKeyRecord>,
}

impl Drop for VaultSecrets {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        if let Some(ref mut k) = self.primary_user_key_armored {
            k.zeroize();
        }
        if let Some(ref mut p) = self.key_passphrase {
            p.zeroize();
        }
        for rec in &mut self.address_keys {
            rec.private_key_armored.zeroize();
            if let Some(ref mut t) = rec.token {
                t.zeroize();
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultPublicMetadata {
    uid: String,
    user_id: String,
    user_email: String,
    used_space: u64,
    max_space: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultDiskV2 {
    version: u32,
    storage: String,
    secret_account: String,
    metadata: VaultPublicMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext_b64: Option<String>,
}

struct Aes256KeyType;

impl KeyType for Aes256KeyType {
    fn len(&self) -> usize {
        32
    }
}

fn derive_fallback_aead_key(
    master_secret: &[u8],
    salt: &[u8],
    account: &str,
) -> Result<Zeroizing<[u8; 32]>, VaultStorageError> {
    let prk = Salt::new(HKDF_SHA256, salt).extract(master_secret);
    let context = format!("neutron-drive-session-vault-v2:{}", account);
    let info = [context.as_bytes()];
    let okm = prk
        .expand(&info, Aes256KeyType)
        .map_err(|_| VaultStorageError::CryptoFailure("HKDF expand failed".to_string()))?;
    let mut out = Zeroizing::new([0u8; 32]);
    okm.fill(&mut *out)
        .map_err(|_| VaultStorageError::CryptoFailure("HKDF fill failed".to_string()))?;
    Ok(out)
}

fn encrypt_vault_secrets(
    master_secret: &[u8],
    account: &str,
    secrets_json: &[u8],
) -> Result<(String, String, String), VaultStorageError> {
    let salt = random_bytes(32).map_err(VaultStorageError::CryptoFailure)?;
    let nonce_bytes = random_bytes(12).map_err(VaultStorageError::CryptoFailure)?;
    let key_bytes = derive_fallback_aead_key(master_secret, &salt, account)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &*key_bytes)
        .map_err(|_| VaultStorageError::CryptoFailure("Invalid AES-256-GCM key".to_string()))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| VaultStorageError::CryptoFailure("Invalid AES-GCM nonce".to_string()))?;
    let aad_str = format!("neutron-drive-session-vault-v2:{}", account);
    let mut in_out = Zeroizing::new(secrets_json.to_vec());
    key.seal_in_place_append_tag(nonce, Aad::from(aad_str.as_bytes()), &mut *in_out)
        .map_err(|_| {
            VaultStorageError::CryptoFailure("Failed encrypting vault payload".to_string())
        })?;
    Ok((
        BASE64.encode(&salt),
        BASE64.encode(&nonce_bytes),
        BASE64.encode(&*in_out),
    ))
}

fn decrypt_vault_secrets(
    master_secret: &[u8],
    account: &str,
    salt_b64: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<Zeroizing<Vec<u8>>, VaultStorageError> {
    let salt = BASE64.decode(salt_b64.trim()).map_err(|e| {
        VaultStorageError::InvalidFormat(format!("Invalid fallback vault salt base64: {}", e))
    })?;
    let nonce_bytes = BASE64.decode(nonce_b64.trim()).map_err(|e| {
        VaultStorageError::InvalidFormat(format!("Invalid fallback vault nonce base64: {}", e))
    })?;
    let mut ciphertext = BASE64.decode(ciphertext_b64.trim()).map_err(|e| {
        VaultStorageError::InvalidFormat(format!("Invalid fallback vault ciphertext base64: {}", e))
    })?;
    if nonce_bytes.len() != 12 {
        return Err(VaultStorageError::InvalidFormat(
            "Invalid fallback vault nonce length".to_string(),
        ));
    }
    let key_bytes = derive_fallback_aead_key(master_secret, &salt, account)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &*key_bytes)
        .map_err(|_| VaultStorageError::CryptoFailure("Invalid AES-256-GCM key".to_string()))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| VaultStorageError::CryptoFailure("Invalid AES-GCM nonce".to_string()))?;
    let aad_str = format!("neutron-drive-session-vault-v2:{}", account);
    let plain = key
        .open_in_place(nonce, Aad::from(aad_str.as_bytes()), &mut ciphertext)
        .map_err(|_| {
            VaultStorageError::CryptoFailure(
                "Failed decrypting fallback vault (wrong key or tampered ciphertext)".to_string(),
            )
        })?;
    Ok(Zeroizing::new(plain.to_vec()))
}

#[derive(Clone)]
pub struct UnlockedAddressKey {
    pub address_id: String,
    pub email: String,
    pub key_id: String,
    pub unlocked: UnlockedKey,
    pub passphrase: Zeroizing<String>,
}

#[derive(Clone, Default)]
struct UnlockedSessionState {
    user_key: Option<UnlockedKey>,
    address_keys: Vec<UnlockedAddressKey>,
}

pub struct SessionVault {
    vault_path: PathBuf,
    secret_store: Arc<dyn SecretStore>,
    fallback_key: Arc<dyn FallbackKeyProvider>,
    data: Mutex<Option<SessionVaultData>>,
    unlocked: Mutex<UnlockedSessionState>,
}

impl SessionVault {
    pub fn default_path() -> PathBuf {
        crate::config::app_data_dir().join("session_vault.json")
    }

    pub fn secret_account_for_path(path: &Path) -> String {
        if path == Self::default_path() {
            "default".to_string()
        } else {
            let digest = super::crypto::sha256_bytes(path.to_string_lossy().as_bytes());
            format!("vault-{}", hex::encode(&digest[..12]))
        }
    }

    pub fn new(vault_path: Option<PathBuf>) -> Result<Self, String> {
        Self::new_with_backend(
            vault_path,
            Arc::new(LinuxSecretServiceStore),
            Arc::new(EnvFallbackKeyProvider),
        )
        .map_err(|e| e.to_string())
    }

    pub fn new_with_backend(
        vault_path: Option<PathBuf>,
        secret_store: Arc<dyn SecretStore>,
        fallback_key: Arc<dyn FallbackKeyProvider>,
    ) -> Result<Self, VaultStorageError> {
        let path = vault_path.unwrap_or_else(Self::default_path);
        let data = Self::load_or_migrate(&path, &*secret_store, &*fallback_key)?;
        let vault = Self {
            vault_path: path,
            secret_store,
            fallback_key,
            data: Mutex::new(data),
            unlocked: Mutex::new(UnlockedSessionState::default()),
        };
        let _ = vault.try_unlock_in_memory();
        Ok(vault)
    }

    pub fn path(&self) -> &Path {
        &self.vault_path
    }

    #[cfg(unix)]
    fn validate_vault_path(path: &Path) -> Result<(), VaultStorageError> {
        let euid = unsafe { libc::geteuid() };
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        match fs::symlink_metadata(parent) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != euid {
                    return Err(VaultStorageError::StorageFailure(format!(
                        "Unsafe vault parent directory permissions or ownership: {:?}",
                        parent
                    )));
                }
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(parent).map_err(|err| {
                    VaultStorageError::StorageFailure(format!(
                        "Failed to create vault dir: {}",
                        err
                    ))
                })?;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
            Err(e) => {
                return Err(VaultStorageError::StorageFailure(format!(
                    "Failed checking vault dir {:?}: {}",
                    parent, e
                )));
            }
        }

        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() || meta.uid() != euid {
                    return Err(VaultStorageError::StorageFailure(format!(
                        "Unsafe vault file {:?}: must be regular file owned by current user",
                        path
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(VaultStorageError::StorageFailure(format!(
                    "Failed checking vault file {:?}: {}",
                    path, e
                )));
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn validate_vault_path(_path: &Path) -> Result<(), VaultStorageError> {
        Ok(())
    }

    fn write_private_file_atomic(target: &Path, bytes: &[u8]) -> Result<(), VaultStorageError> {
        Self::validate_vault_path(target)?;
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        let mut last_exists_err = None;
        for _ in 0..8 {
            let tmp_name = format!(".session_vault.tmp.{}", fastrand::u64(..));
            let tmp_path = parent.join(tmp_name);

            #[cfg(unix)]
            let open_res = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path);
            #[cfg(not(unix))]
            let open_res = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path);

            let mut file = match open_res {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    last_exists_err = Some(e);
                    continue;
                }
                Err(e) => {
                    return Err(VaultStorageError::StorageFailure(format!(
                        "Failed creating private temp vault {:?}: {}",
                        tmp_path, e
                    )));
                }
            };

            let write_res = (|| -> std::io::Result<()> {
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            })();
            drop(file);
            if let Err(e) = write_res {
                let _ = fs::remove_file(&tmp_path);
                return Err(VaultStorageError::StorageFailure(format!(
                    "Failed writing private temp vault {:?}: {}",
                    tmp_path, e
                )));
            }

            if let Err(e) = fs::rename(&tmp_path, target) {
                let _ = fs::remove_file(&tmp_path);
                return Err(VaultStorageError::StorageFailure(format!(
                    "Failed persisting session vault {:?}: {}",
                    target, e
                )));
            }
            #[cfg(unix)]
            let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
            return Ok(());
        }

        Err(VaultStorageError::StorageFailure(format!(
            "Failed allocating unique temp vault file: {:?}",
            last_exists_err
        )))
    }

    fn split_data(data: &SessionVaultData) -> (VaultPublicMetadata, VaultSecrets) {
        let meta = VaultPublicMetadata {
            uid: data.uid.clone(),
            user_id: data.user_id.clone(),
            user_email: data.user_email.clone(),
            used_space: data.used_space,
            max_space: data.max_space,
        };
        let secrets = VaultSecrets {
            access_token: data.access_token.clone(),
            refresh_token: data.refresh_token.clone(),
            primary_user_key_armored: data.primary_user_key_armored.clone(),
            key_passphrase: data.key_passphrase.clone(),
            address_keys: data.address_keys.clone(),
        };
        (meta, secrets)
    }

    fn combine_data(meta: VaultPublicMetadata, secrets: VaultSecrets) -> SessionVaultData {
        SessionVaultData {
            uid: meta.uid,
            access_token: secrets.access_token.clone(),
            refresh_token: secrets.refresh_token.clone(),
            user_id: meta.user_id,
            user_email: meta.user_email,
            used_space: meta.used_space,
            max_space: meta.max_space,
            primary_user_key_armored: secrets.primary_user_key_armored.clone(),
            key_passphrase: secrets.key_passphrase.clone(),
            address_keys: secrets.address_keys.clone(),
        }
    }

    fn persist_to_secure_storage(
        path: &Path,
        secret_store: &dyn SecretStore,
        fallback_key: &dyn FallbackKeyProvider,
        data: &SessionVaultData,
    ) -> Result<(), VaultStorageError> {
        Self::validate_vault_path(path)?;
        let account = Self::secret_account_for_path(path);
        let (meta, secrets) = Self::split_data(data);
        let secrets_json = Zeroizing::new(serde_json::to_vec(&secrets).map_err(|e| {
            VaultStorageError::StorageFailure(format!("Failed serializing vault secrets: {}", e))
        })?);

        let disk_envelope = match secret_store.store_secret(&account, &secrets_json) {
            Ok(()) => VaultDiskV2 {
                version: VAULT_FORMAT_VERSION,
                storage: STORAGE_SECRET_SERVICE.to_string(),
                secret_account: account,
                metadata: meta,
                salt_b64: None,
                nonce_b64: None,
                ciphertext_b64: None,
            },
            Err(VaultStorageError::KeyringLocked(msg)) => {
                // Locked keyring must surface explicitly without downgrading to disk.
                return Err(VaultStorageError::KeyringLocked(msg));
            }
            Err(VaultStorageError::KeyringUnavailable(unavail_msg)) => {
                let Some(master_key) = fallback_key.resolve_key()? else {
                    return Err(VaultStorageError::KeyringUnavailable(format!(
                        "{}; configure {} or {} for an independently protected encrypted fallback",
                        unavail_msg, VAULT_ENV_KEY, VAULT_ENV_KEY_FILE
                    )));
                };
                let (salt_b64, nonce_b64, ciphertext_b64) =
                    encrypt_vault_secrets(&master_key, &account, &secrets_json)?;
                VaultDiskV2 {
                    version: VAULT_FORMAT_VERSION,
                    storage: STORAGE_ENCRYPTED_FALLBACK.to_string(),
                    secret_account: account,
                    metadata: meta,
                    salt_b64: Some(salt_b64),
                    nonce_b64: Some(nonce_b64),
                    ciphertext_b64: Some(ciphertext_b64),
                }
            }
            Err(other) => return Err(other),
        };

        let envelope_json = serde_json::to_string_pretty(&disk_envelope).map_err(|e| {
            VaultStorageError::StorageFailure(format!("Failed serializing vault envelope: {}", e))
        })?;
        Self::write_private_file_atomic(path, envelope_json.as_bytes())
    }

    fn load_or_migrate(
        path: &Path,
        secret_store: &dyn SecretStore,
        fallback_key: &dyn FallbackKeyProvider,
    ) -> Result<Option<SessionVaultData>, VaultStorageError> {
        Self::validate_vault_path(path)?;
        if !path.exists() {
            return Ok(None);
        }
        let raw = Zeroizing::new(fs::read_to_string(path).map_err(|e| {
            VaultStorageError::StorageFailure(format!(
                "Failed reading session vault {:?}: {}",
                path, e
            ))
        })?);

        let val: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            VaultStorageError::InvalidFormat(format!(
                "Failed parsing session vault {:?}: {}",
                path, e
            ))
        })?;

        if val.get("version").is_some() {
            let v2: VaultDiskV2 = serde_json::from_value(val).map_err(|e| {
                VaultStorageError::InvalidFormat(format!(
                    "Malformed v2 session vault {:?}: {}",
                    path, e
                ))
            })?;
            if v2.version != VAULT_FORMAT_VERSION {
                return Err(VaultStorageError::InvalidFormat(format!(
                    "Unsupported session vault version {}",
                    v2.version
                )));
            }
            match v2.storage.as_str() {
                STORAGE_SECRET_SERVICE => {
                    let Some(secret_bytes) = secret_store.load_secret(&v2.secret_account)? else {
                        return Ok(None);
                    };
                    let secrets: VaultSecrets =
                        serde_json::from_slice(&secret_bytes).map_err(|e| {
                            VaultStorageError::InvalidFormat(format!(
                                "Malformed secret payload in Secret Service: {}",
                                e
                            ))
                        })?;
                    let combined = Self::combine_data(v2.metadata, secrets);
                    if combined.uid.is_empty() || combined.access_token.is_empty() {
                        return Ok(None);
                    }
                    Ok(Some(combined))
                }
                STORAGE_ENCRYPTED_FALLBACK => {
                    let salt_b64 = v2.salt_b64.as_deref().ok_or_else(|| {
                        VaultStorageError::InvalidFormat("Missing fallback vault salt".to_string())
                    })?;
                    let nonce_b64 = v2.nonce_b64.as_deref().ok_or_else(|| {
                        VaultStorageError::InvalidFormat("Missing fallback vault nonce".to_string())
                    })?;
                    let ciphertext_b64 = v2.ciphertext_b64.as_deref().ok_or_else(|| {
                        VaultStorageError::InvalidFormat(
                            "Missing fallback vault ciphertext".to_string(),
                        )
                    })?;
                    let Some(master_key) = fallback_key.resolve_key()? else {
                        return Err(VaultStorageError::KeyringUnavailable(format!(
                            "Encrypted fallback vault exists at {:?} but no fallback key is configured ({} or {})",
                            path, VAULT_ENV_KEY, VAULT_ENV_KEY_FILE
                        )));
                    };
                    let secret_bytes = decrypt_vault_secrets(
                        &master_key,
                        &v2.secret_account,
                        salt_b64,
                        nonce_b64,
                        ciphertext_b64,
                    )?;
                    let secrets: VaultSecrets =
                        serde_json::from_slice(&secret_bytes).map_err(|e| {
                            VaultStorageError::InvalidFormat(format!(
                                "Malformed decrypted fallback vault secrets: {}",
                                e
                            ))
                        })?;
                    let combined = Self::combine_data(v2.metadata, secrets);
                    if combined.uid.is_empty() || combined.access_token.is_empty() {
                        return Ok(None);
                    }
                    Ok(Some(combined))
                }
                other => Err(VaultStorageError::InvalidFormat(format!(
                    "Unsupported vault storage backend '{}'",
                    other
                ))),
            }
        } else {
            // Legacy plaintext JSON v1: migrate ONLY after secure storage succeeds.
            let parsed: SessionVaultData = serde_json::from_value(val).map_err(|e| {
                VaultStorageError::InvalidFormat(format!(
                    "Failed parsing legacy session vault {:?}: {}",
                    path, e
                ))
            })?;
            if parsed.uid.is_empty() || parsed.access_token.is_empty() {
                return Ok(None);
            }
            Self::persist_to_secure_storage(path, secret_store, fallback_key, &parsed)?;
            Ok(Some(parsed))
        }
    }

    fn write_vault_data(&self, data: SessionVaultData) -> Result<(), VaultStorageError> {
        Self::persist_to_secure_storage(
            &self.vault_path,
            &*self.secret_store,
            &*self.fallback_key,
            &data,
        )?;
        *self.data.lock().unwrap() = Some(data);
        Ok(())
    }

    pub fn save_checked(&self, data: SessionVaultData) -> Result<(), VaultStorageError> {
        self.write_vault_data(data)?;
        self.try_unlock_in_memory()
            .map_err(VaultStorageError::CryptoFailure)?;
        Ok(())
    }

    pub fn save(&self, data: SessionVaultData) -> Result<(), String> {
        self.save_checked(data).map_err(|e| e.to_string())
    }

    pub fn update_tokens(&self, tokens: &HttpAuthTokens) -> Result<(), String> {
        let current = {
            let guard = self.data.lock().unwrap();
            guard.clone()
        };
        if let Some(mut d) = current {
            d.uid = tokens.uid.clone();
            d.access_token = tokens.access_token.as_str().to_string();
            d.refresh_token = tokens.refresh_token.as_str().to_string();
            self.write_vault_data(d).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn update_quota(&self, used_space: u64, max_space: u64) -> Result<(), String> {
        let current = {
            let guard = self.data.lock().unwrap();
            guard.clone()
        };
        if let Some(mut d) = current {
            d.used_space = used_space;
            d.max_space = max_space;
            self.write_vault_data(d).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn clear_checked(&self) -> Result<(), VaultStorageError> {
        let mut disk_secret_account = None;
        let mut uses_secret_service = false;
        if self.vault_path.exists() {
            if let Ok(raw) = fs::read_to_string(&self.vault_path) {
                if let Ok(v2) = serde_json::from_str::<VaultDiskV2>(&raw) {
                    if v2.version == VAULT_FORMAT_VERSION && v2.storage == STORAGE_SECRET_SERVICE {
                        uses_secret_service = true;
                        disk_secret_account = Some(v2.secret_account);
                    }
                }
            }
        }

        if uses_secret_service {
            let account = disk_secret_account
                .unwrap_or_else(|| Self::secret_account_for_path(&self.vault_path));
            self.secret_store.delete_secret(&account)?;
        }

        *self.data.lock().unwrap() = None;
        *self.unlocked.lock().unwrap() = UnlockedSessionState::default();
        if self.vault_path.exists() {
            fs::remove_file(&self.vault_path).map_err(|e| {
                VaultStorageError::StorageFailure(format!("Failed removing session vault: {}", e))
            })?;
        }
        Ok(())
    }

    pub fn clear(&self) -> Result<(), String> {
        self.clear_checked().map_err(|e| e.to_string())
    }

    pub fn is_authenticated(&self) -> bool {
        self.data
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|d| !d.uid.is_empty() && !d.access_token.is_empty())
    }

    pub fn snapshot(&self) -> Option<SessionVaultData> {
        self.data.lock().unwrap().clone()
    }

    pub fn http_tokens(&self) -> Option<HttpAuthTokens> {
        self.data.lock().unwrap().as_ref().map(|d| HttpAuthTokens {
            uid: d.uid.clone(),
            access_token: Zeroizing::new(d.access_token.clone()),
            refresh_token: Zeroizing::new(d.refresh_token.clone()),
        })
    }

    pub fn storage_quota(&self) -> StorageQuota {
        let guard = self.data.lock().unwrap();
        let Some(ref d) = *guard else {
            return StorageQuota::default();
        };
        let percent_used = if d.max_space > 0 {
            ((d.used_space as f64) / (d.max_space as f64)) * 100.0
        } else {
            0.0
        };
        StorageQuota {
            used_bytes: d.used_space,
            total_bytes: d.max_space,
            percent_used,
        }
    }

    pub fn primary_address_key(&self) -> Option<UnlockedAddressKey> {
        self.unlocked.lock().unwrap().address_keys.first().cloned()
    }

    pub fn address_keys(&self) -> Vec<UnlockedAddressKey> {
        self.unlocked.lock().unwrap().address_keys.clone()
    }

    pub fn address_public_keys(&self, email: Option<&str>) -> Vec<String> {
        let guard = self.unlocked.lock().unwrap();
        let filtered: Vec<String> = guard
            .address_keys
            .iter()
            .filter(|ak| email.is_none_or(|e| ak.email == e))
            .map(|ak| ak.unlocked.armored_public.clone())
            .collect();
        if filtered.is_empty() {
            guard
                .address_keys
                .iter()
                .map(|ak| ak.unlocked.armored_public.clone())
                .collect()
        } else {
            filtered
        }
    }

    pub fn try_unlock_in_memory(&self) -> Result<(), String> {
        let Some(data) = self.snapshot() else {
            *self.unlocked.lock().unwrap() = UnlockedSessionState::default();
            return Ok(());
        };
        let Some(ref pass) = data.key_passphrase else {
            return Ok(());
        };

        let user_key = match data.primary_user_key_armored {
            Some(ref armored) => Some(DriveKey::unlock(armored, pass)?),
            None => None,
        };

        let mut unlocked_addr_keys = Vec::new();
        for rec in &data.address_keys {
            let addr_pass = if let Some(ref token_armored) = rec.token {
                if let Some(ref uk) = user_key {
                    Zeroizing::new(Decryptor::decrypt_attached_text_message(
                        token_armored,
                        std::slice::from_ref(uk),
                    )?)
                } else {
                    Zeroizing::new(pass.clone())
                }
            } else {
                Zeroizing::new(pass.clone())
            };

            let unlocked = DriveKey::unlock(&rec.private_key_armored, &addr_pass)?;
            unlocked_addr_keys.push(UnlockedAddressKey {
                address_id: rec.address_id.clone(),
                email: rec.email.clone(),
                key_id: rec.key_id.clone(),
                unlocked,
                passphrase: addr_pass,
            });
        }

        *self.unlocked.lock().unwrap() = UnlockedSessionState {
            user_key,
            address_keys: unlocked_addr_keys,
        };
        Ok(())
    }

    pub fn user_key(&self) -> Option<UnlockedKey> {
        self.unlocked.lock().unwrap().user_key.clone()
    }
}

// ============================================================================
// AuthManager (SRP-6a Login, Key Salting, Quota Sync, Logout)
// ============================================================================

pub struct AuthManager {
    http: Arc<PdHttpClient>,
    vault: Arc<SessionVault>,
    trusted_srp_keys: Vec<String>,
}

impl AuthManager {
    pub fn new(http: Arc<PdHttpClient>, vault: Arc<SessionVault>) -> Self {
        Self::new_with_trusted_srp_keys(http, vault, default_trusted_srp_keys())
    }

    /// Creates an `AuthManager` with explicit trusted SRP modulus verification keys.
    pub fn new_with_trusted_srp_keys(
        http: Arc<PdHttpClient>,
        vault: Arc<SessionVault>,
        trusted_srp_keys: Vec<String>,
    ) -> Self {
        if let Some(tokens) = vault.http_tokens() {
            http.set_tokens(Some(tokens));
        }
        let vault_cb = Arc::clone(&vault);
        http.set_on_token_refresh(Arc::new(move |new_tokens| {
            if let Err(err) = vault_cb.update_tokens(new_tokens) {
                log::warn!("Failed persisting rotated auth tokens to vault: {}", err);
            }
        }));
        Self {
            http,
            vault,
            trusted_srp_keys,
        }
    }

    /// Overrides the trusted SRP modulus verification keys (primarily for tests).
    pub fn set_trusted_srp_keys(&mut self, trusted_srp_keys: Vec<String>) {
        self.trusted_srp_keys = trusted_srp_keys;
    }

    pub fn vault(&self) -> &Arc<SessionVault> {
        &self.vault
    }

    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
        totp: Option<&str>,
    ) -> Result<String, String> {
        if username.trim().is_empty() || password.is_empty() {
            return Err("Username and password must not be empty".to_string());
        }

        // 0. Acquire an unauthenticated session if supported by the server (mirrors Proton SDK)
        let had_unauth_session = match self
            .http
            .post_json_with_options::<serde_json::Value, UnauthSessionResponse>(
                RateLimitFamily::Auth,
                "/auth/v4/sessions",
                &serde_json::json!({}),
                &[("x-enforce-unauthsession", "true")],
                false,
                false,
            ) {
            Ok(sess)
                if (sess.code == 1000 || sess.code == 1001)
                    && !sess.uid.is_empty()
                    && !sess.access_token.is_empty() =>
            {
                self.http.set_tokens(Some(HttpAuthTokens {
                    uid: sess.uid,
                    access_token: Zeroizing::new(sess.access_token),
                    refresh_token: Zeroizing::new(sess.refresh_token),
                }));
                true
            }
            _ => false,
        };

        // 1. POST /auth/v4/info
        let info: AuthInfoResponse = self
            .http
            .post_json_with_options(
                RateLimitFamily::Auth,
                "/auth/v4/info",
                &AuthInfoRequest {
                    username,
                    intent: "Proton",
                },
                &[],
                had_unauth_session,
                false,
            )
            .map_err(|e| {
                if had_unauth_session {
                    self.http.set_tokens(None);
                }
                format!("Auth info request failed: {}", e)
            })?;
        if info.code != 1000 && info.code != 1001 {
            if had_unauth_session {
                self.http.set_tokens(None);
            }
            return Err(format!("Auth info rejected with API code {}", info.code));
        }

        // 2. SRP-6a proof computation (verifies Proton's signed SRP modulus first)
        let proof = match SrpClient::generate_proof(
            password,
            &info.salt,
            &info.modulus,
            &info.server_ephemeral,
            info.version,
            &self.trusted_srp_keys,
        ) {
            Ok(p) => p,
            Err(e) => {
                if had_unauth_session {
                    self.http.set_tokens(None);
                }
                return Err(e);
            }
        };

        // 3. POST /auth/v4
        let auth_resp: AuthResponse = self
            .http
            .post_json_with_options(
                RateLimitFamily::Auth,
                "/auth/v4",
                &AuthRequest {
                    username,
                    client_ephemeral: &proof.client_ephemeral_b64,
                    client_proof: &proof.client_proof_b64,
                    srp_session: &info.srp_session,
                },
                &[],
                had_unauth_session,
                false,
            )
            .map_err(|e| {
                if had_unauth_session {
                    self.http.set_tokens(None);
                }
                match &e {
                    HttpError::Status {
                        code: Some(2028), ..
                    } => format!(
                        "Authentication failed: {} — Proton anti-abuse blocked headless password login on /auth/v4 (whereas the official CLI uses browser SSO session forking /auth/v4/sessions/forks).",
                        e
                    ),
                    HttpError::Status {
                        code: Some(9001), ..
                    } => format!(
                        "Authentication failed: {} — Proton requires human verification / CAPTCHA for headless login.",
                        e
                    ),
                    _ => format!("Authentication failed: {}", e),
                }
            })?;
        if auth_resp.code != 1000 && auth_resp.code != 1001 {
            return Err(format!(
                "Authentication rejected with API code {}",
                auth_resp.code
            ));
        }
        if let Some(ref srv_proof) = auth_resp.server_proof {
            SrpClient::verify_server_proof(&proof.expected_server_proof, srv_proof)?;
        }

        let tokens = HttpAuthTokens {
            uid: auth_resp.uid.clone(),
            access_token: Zeroizing::new(auth_resp.access_token.clone()),
            refresh_token: Zeroizing::new(auth_resp.refresh_token.clone()),
        };
        self.http.set_tokens(Some(tokens));

        // 4. Optional 2FA/TOTP
        if auth_resp.two_factor.enabled != 0 {
            let Some(code) = totp.map(str::trim).filter(|c| !c.is_empty()) else {
                self.http.set_tokens(None);
                return Err("2FA_REQUIRED: Two-factor TOTP code required".to_string());
            };
            let tfa: super::endpoints::CodeResponse = self
                .http
                .post_json(
                    RateLimitFamily::Auth,
                    "/auth/v4/2fa",
                    &TwoFactorRequest {
                        two_factor_code: code,
                    },
                    true,
                )
                .map_err(|e| format!("2FA verification failed: {}", e))?;
            tfa.ensure_ok("2FA verification")?;
        }

        // 5. Fetch user, key salts, and addresses, unlock keys, and save SessionVault
        let users_resp: UsersResponse = self
            .http
            .get_json(RateLimitFamily::Auth, "/core/v4/users", &[], true)
            .map_err(|e| format!("Failed fetching user profile: {}", e))?;
        if users_resp.code != 1000 && users_resp.code != 1001 {
            return Err(format!(
                "Users request rejected with code {}",
                users_resp.code
            ));
        }
        let salts_resp: KeySaltsResponse = self
            .http
            .get_json(RateLimitFamily::Auth, "/core/v4/keys/salts", &[], true)
            .map_err(|e| format!("Failed fetching key salts: {}", e))?;
        if salts_resp.code != 1000 && salts_resp.code != 1001 {
            return Err(format!(
                "Key salts request rejected with code {}",
                salts_resp.code
            ));
        }

        let primary_user_key = users_resp
            .user
            .keys
            .iter()
            .find(|k| k.primary == 1)
            .or_else(|| users_resp.user.keys.first());

        let key_passphrase = if let Some(uk) = primary_user_key {
            if let Some(salt_entry) = salts_resp
                .key_salts
                .iter()
                .find(|s| s.id == uk.id && s.key_salt.is_some())
                .or_else(|| salts_resp.key_salts.iter().find(|s| s.key_salt.is_some()))
            {
                derive_key_passphrase(password, salt_entry.key_salt.as_deref().unwrap_or_default())?
            } else {
                Zeroizing::new(password.to_string())
            }
        } else {
            Zeroizing::new(password.to_string())
        };

        self.finalize_authenticated_session(
            auth_resp.uid,
            auth_resp.access_token,
            auth_resp.refresh_token,
            Some(users_resp),
            key_passphrase,
            Some(username),
        )
    }

    pub fn start_browser_login(
        &self,
        account_base_url: Option<&str>,
    ) -> Result<BrowserLoginChallenge, String> {
        let resp: ForkInitResponse = self
            .http
            .get_json(RateLimitFamily::Auth, "/auth/v4/sessions/forks", &[], false)
            .map_err(|e| format!("Failed initiating browser SSO session fork: {}", e))?;
        if resp.code != 1000 && resp.code != 1001 {
            return Err(format!(
                "Session fork initiation rejected with API code {}",
                resp.code
            ));
        }
        if resp.selector.is_empty() || resp.user_code.is_empty() {
            return Err("Session fork response missing Selector or UserCode".to_string());
        }

        let encryption_key = Zeroizing::new(random_bytes(32)?);
        let encoded_key = BASE64.encode(&*encryption_key);
        let raw_payload = format!(
            "0:{}:{}:{}",
            resp.user_code, encoded_key, FORK_CHILD_CLIENT_ID
        );
        let encoded_payload: String =
            url::form_urlencoded::byte_serialize(raw_payload.as_bytes()).collect();
        let base = account_base_url
            .unwrap_or(DEFAULT_ACCOUNT_WEB_URL)
            .trim_end_matches('/');
        let login_url = format!(
            "{}/desktop/login?app=drive&pv=3#payload={}",
            base, encoded_payload
        );

        Ok(BrowserLoginChallenge {
            selector: resp.selector,
            user_code: resp.user_code,
            login_url,
            encryption_key,
        })
    }

    pub fn poll_browser_login_once(
        &self,
        challenge: &BrowserLoginChallenge,
    ) -> Result<Option<String>, String> {
        let path = format!("/auth/v4/sessions/forks/{}", challenge.selector);
        let fork_resp: ForkPollResponse =
            match self.http.get_json(RateLimitFamily::Auth, &path, &[], false) {
                Ok(r) => r,
                Err(HttpError::Status {
                    status: 404 | 422, ..
                }) => return Ok(None),
                Err(e) => return Err(format!("Failed polling browser SSO session fork: {}", e)),
            };

        if let Some(code) = fork_resp.code {
            if code != 1000 && code != 1001 {
                return Err(format!(
                    "Browser SSO session fork rejected with API code {}",
                    code
                ));
            }
        }
        if fork_resp.uid.is_empty() || fork_resp.access_token.is_empty() {
            return Err("Browser SSO session fork missing UID or AccessToken".to_string());
        }

        let key_password = match fork_resp.payload.as_deref() {
            Some(p) if !p.is_empty() => decrypt_fork_payload(&challenge.encryption_key, p)?,
            _ => {
                return Err(
                    "Browser SSO session fork response did not include an encrypted keyPassword payload"
                        .to_string(),
                )
            }
        };
        if key_password.is_empty() {
            return Err("Browser SSO session fork returned an empty keyPassword".to_string());
        }

        let tokens = HttpAuthTokens {
            uid: fork_resp.uid.clone(),
            access_token: Zeroizing::new(fork_resp.access_token.clone()),
            refresh_token: Zeroizing::new(fork_resp.refresh_token.clone()),
        };
        self.http.set_tokens(Some(tokens));

        let msg = self.finalize_authenticated_session(
            fork_resp.uid,
            fork_resp.access_token,
            fork_resp.refresh_token,
            None,
            key_password,
            None,
        )?;
        Ok(Some(msg))
    }

    pub fn authenticate_via_browser<F>(
        &self,
        timeout: Duration,
        on_url: F,
    ) -> Result<String, String>
    where
        F: FnOnce(&str, &str),
    {
        let challenge = self.start_browser_login(None)?;
        on_url(&challenge.login_url, &challenge.user_code);

        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(msg) = self.poll_browser_login_once(&challenge)? {
                return Ok(msg);
            }
            if std::time::Instant::now() >= deadline {
                return Err("Timed out waiting for browser SSO sign-in confirmation".to_string());
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    fn finalize_authenticated_session(
        &self,
        uid: String,
        access_token: String,
        refresh_token: String,
        prefetched_users: Option<UsersResponse>,
        key_passphrase: Zeroizing<String>,
        fallback_username: Option<&str>,
    ) -> Result<String, String> {
        let users_resp = match prefetched_users {
            Some(u) => u,
            None => {
                let u: UsersResponse = self
                    .http
                    .get_json(RateLimitFamily::Auth, "/core/v4/users", &[], true)
                    .map_err(|e| format!("Failed fetching user profile: {}", e))?;
                if u.code != 1000 && u.code != 1001 {
                    return Err(format!("Users request rejected with code {}", u.code));
                }
                u
            }
        };

        let addrs_resp: AddressesResponse = self
            .http
            .get_json(RateLimitFamily::Auth, "/core/v4/addresses", &[], true)
            .map_err(|e| format!("Failed fetching addresses: {}", e))?;
        if addrs_resp.code != 1000 && addrs_resp.code != 1001 {
            return Err(format!(
                "Addresses request rejected with code {}",
                addrs_resp.code
            ));
        }

        let primary_user_key = users_resp
            .user
            .keys
            .iter()
            .find(|k| k.primary == 1)
            .or_else(|| users_resp.user.keys.first());

        let mut address_records = Vec::new();
        for addr in &addrs_resp.addresses {
            for ak in &addr.keys {
                if ak.active == 0 && !addr.keys.iter().any(|k| k.active != 0) {
                    continue;
                }
                address_records.push(VaultAddressKeyRecord {
                    address_id: addr.id.clone(),
                    email: addr.email.clone(),
                    key_id: ak.id.clone(),
                    private_key_armored: ak.private_key.clone(),
                    token: ak.token.clone(),
                    primary: ak.primary != 0,
                });
            }
        }
        // Sort primary address keys first
        address_records.sort_by_key(|r| !r.primary);

        let used_space = users_resp
            .user
            .used_drive_space
            .or(users_resp.user.used_space)
            .unwrap_or(0);
        let max_space = users_resp
            .user
            .max_drive_space
            .filter(|&v| v > 0)
            .or(users_resp.user.max_space)
            .unwrap_or(0);
        let user_email = users_resp
            .user
            .email
            .or(users_resp.user.name)
            .or_else(|| addrs_resp.addresses.first().map(|a| a.email.clone()))
            .or_else(|| fallback_username.map(ToString::to_string))
            .unwrap_or_default();

        let vault_data = SessionVaultData {
            uid,
            access_token,
            refresh_token,
            user_id: users_resp.user.id,
            user_email: user_email.clone(),
            used_space,
            max_space,
            primary_user_key_armored: primary_user_key.map(|k| k.private_key.clone()),
            key_passphrase: Some(key_passphrase.to_string()),
            address_keys: address_records,
        };
        self.vault.save(vault_data)?;

        Ok(format!("Authenticated as {}", user_email))
    }

    pub fn refresh_quota(&self) -> Result<StorageQuota, String> {
        if !self.vault.is_authenticated() {
            return Ok(StorageQuota::default());
        }
        let users_resp: UsersResponse = self
            .http
            .get_json(RateLimitFamily::Auth, "/core/v4/users", &[], true)
            .map_err(|e| match e {
                HttpError::Unauthorized(m) => {
                    let _ = self.vault.clear();
                    self.http.set_tokens(None);
                    m
                }
                other => other.to_string(),
            })?;
        if users_resp.code != 1000 && users_resp.code != 1001 {
            return Err(format!(
                "Users quota request rejected with code {}",
                users_resp.code
            ));
        }
        let used = users_resp
            .user
            .used_drive_space
            .or(users_resp.user.used_space)
            .unwrap_or(0);
        let max = users_resp
            .user
            .max_drive_space
            .filter(|&v| v > 0)
            .or(users_resp.user.max_space)
            .unwrap_or(0);
        if let Err(err) = self.vault.update_quota(used, max) {
            log::warn!("Failed persisting refreshed quota to vault: {}", err);
        }
        let percent_used = if max > 0 {
            ((used as f64) / (max as f64)) * 100.0
        } else {
            0.0
        };
        Ok(StorageQuota {
            used_bytes: used,
            total_bytes: max,
            percent_used,
        })
    }

    pub fn logout(&self) -> bool {
        if self.vault.is_authenticated() {
            let _: Result<serde_json::Value, _> =
                self.http
                    .delete_json(RateLimitFamily::Auth, "/auth/v4", true);
        }
        self.http.set_tokens(None);
        self.vault.clear().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biguint_arithmetic_and_modpow() {
        let a = BigUint::from_u64(2);
        let e = BigUint::from_u64(10);
        let m = BigUint::from_u64(1000);
        assert_eq!(a.mod_pow(&e, &m), BigUint::from_u64(24));

        // 2048-bit Fermat / DH property: (g^x)^y mod p == (g^y)^x mod p
        let mut prime_bytes = vec![0xFFu8; 256];
        prime_bytes[255] = 0xFD; // odd 2048-bit modulus
        let p = BigUint::from_be_bytes(&prime_bytes);
        let g = BigUint::from_u64(2);
        let x = BigUint::from_be_bytes(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF1]);
        let y = BigUint::from_be_bytes(&[0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11]);
        let gx = g.mod_pow(&x, &p);
        let gy = g.mod_pow(&y, &p);
        assert_eq!(gx.mod_pow(&y, &p), gy.mod_pow(&x, &p));
    }

    #[test]
    fn test_bcrypt_standard_vector() {
        let zero_salt = [0u8; 16];
        let h = bcrypt_hash_2y(b"", 4, &zero_salt).unwrap();
        assert_eq!(
            h.as_str(),
            "$2y$04$......................w74bL5gU7LSJClZClCa.Pkz14aTv/XO"
        );

        let salt_abc = [
            0x71, 0xda, 0x35, 0x87, 0xfe, 0xeb, 0x99, 0x4e, 0x62, 0xb6, 0xa8, 0x26, 0x16, 0x9e,
            0xea, 0x2f,
        ];
        // Direct bcrypt vector for password "abc" with 16-byte salt encoding to "abcdefghijklmnopqrstuu"
        // Let's also verify derive_key_passphrase returns the 31-char suffix.
        let salt_b64 = BASE64.encode(salt_abc);
        let derived = derive_key_passphrase("abc", &salt_b64).unwrap();
        assert_eq!(derived.len(), 31);
        assert_eq!(derived, derive_key_passphrase("abc", &salt_b64).unwrap());
    }

    #[test]
    fn test_srp6a_server_verification_handshake() {
        // Construct a 2048-bit safe-prime-like modulus (256 bytes, MSB=1, LSB=1)
        let mut n_bytes = vec![0x85u8; 256];
        n_bytes[0] = 0xFB; // odd in LE
        n_bytes[255] = 0xC3;
        let n_b64 = BASE64.encode(&n_bytes);
        let n = BigUint::from_le_bytes(&n_bytes);

        let salt = [0x11u8; 10];
        let salt_b64 = BASE64.encode(salt);
        let password = "correct-horse-battery-staple";

        // Server precomputes v = g^x mod N
        let x_bytes = hash_password_v4(password, &salt, &n_bytes).unwrap();
        let x = BigUint::from_le_bytes(&x_bytes);
        let g = BigUint::from_u64(2);
        let v = g.mod_pow(&x, &n);

        let g_padded = g.to_le_bytes_padded(256);
        let mut k_in = Vec::new();
        k_in.extend_from_slice(&g_padded);
        k_in.extend_from_slice(&n_bytes);
        let k = BigUint::from_le_bytes(&expand_hash(&k_in)).rem(&n);

        // Server chooses b and computes B = (k*v + g^b) mod N
        let b_sec = BigUint::from_le_bytes(&[0x42; 32]);
        let gb = g.mod_pow(&b_sec, &n);
        let b_pub = k.mul_mod(&v, &n).add(&gb).rem(&n);
        let b_b64 = BASE64.encode(b_pub.to_le_bytes_padded(256));

        let srv_key = DriveKey::generate("Server", "srv@proton.me", "srv-pass").unwrap();
        let srv_pub = DriveKey::public_key_armored(&srv_key).unwrap();
        let signed_modulus = DriveCrypto::sign_cleartext(&n_b64, &srv_key, "srv-pass").unwrap();

        let proof = SrpClient::generate_proof(
            password,
            &salt_b64,
            &signed_modulus,
            &b_b64,
            4,
            std::slice::from_ref(&srv_pub),
        )
        .unwrap();

        // Server reconstructs S = (A * v^u)^b mod N
        let a_bytes = BASE64.decode(&proof.client_ephemeral_b64).unwrap();
        let a_pub = BigUint::from_le_bytes(&a_bytes);
        let b_bytes = b_pub.to_le_bytes_padded(256);
        let mut u_in = Vec::new();
        u_in.extend_from_slice(&a_bytes);
        u_in.extend_from_slice(&b_bytes);
        let u = BigUint::from_le_bytes(&expand_hash(&u_in));
        let vu = v.mod_pow(&u, &n);
        let s_srv = a_pub.mul_mod(&vu, &n).mod_pow(&b_sec, &n);
        let s_bytes = s_srv.to_le_bytes_padded(256);

        let mut m1_in = Vec::new();
        m1_in.extend_from_slice(&a_bytes);
        m1_in.extend_from_slice(&b_bytes);
        m1_in.extend_from_slice(&s_bytes);
        let expected_m1 = expand_hash(&m1_in);
        assert_eq!(BASE64.decode(&proof.client_proof_b64).unwrap(), expected_m1);

        let mut m2_in = Vec::new();
        m2_in.extend_from_slice(&a_bytes);
        m2_in.extend_from_slice(&expected_m1);
        m2_in.extend_from_slice(&s_bytes);
        let srv_m2 = BASE64.encode(expand_hash(&m2_in));
        SrpClient::verify_server_proof(&proof.expected_server_proof, &srv_m2).unwrap();
    }

    #[test]
    fn test_extract_and_verify_modulus_bytes() {
        let srv_key = DriveKey::generate("Server", "srv@proton.me", "srv-pass").unwrap();
        let srv_pub = DriveKey::public_key_armored(&srv_key).unwrap();
        let other_key = DriveKey::generate("Other", "other@proton.me", "other-pass").unwrap();
        let other_pub = DriveKey::public_key_armored(&other_key).unwrap();

        let raw_mod = vec![0xA5u8; 256];
        let raw_b64 = BASE64.encode(&raw_mod);
        let signed = DriveCrypto::sign_cleartext(&raw_b64, &srv_key, "srv-pass").unwrap();

        let verified =
            extract_and_verify_modulus_bytes(&signed, std::slice::from_ref(&srv_pub)).unwrap();
        assert_eq!(verified, raw_mod);

        // Wrong verification key fails
        assert!(
            extract_and_verify_modulus_bytes(&signed, std::slice::from_ref(&other_pub)).is_err()
        );

        // Empty verification keys fail
        assert!(extract_and_verify_modulus_bytes(&signed, &[]).is_err());

        // Unsigned base64 input fails
        assert!(
            extract_and_verify_modulus_bytes(&raw_b64, std::slice::from_ref(&srv_pub)).is_err()
        );

        // Tampered modulus payload fails
        let tampered = signed.replacen(&raw_b64[..8], "ZZZZZZZZ", 1);
        assert!(
            extract_and_verify_modulus_bytes(&tampered, std::slice::from_ref(&srv_pub)).is_err()
        );

        // Malformed armor fails
        let malformed = signed.replace("-----END PGP SIGNATURE-----", "");
        assert!(
            extract_and_verify_modulus_bytes(&malformed, std::slice::from_ref(&srv_pub)).is_err()
        );

        // Invalid signature armor fails
        let bad_sig =
            if let Some((head, _tail)) = signed.split_once("-----BEGIN PGP SIGNATURE-----") {
                format!(
                    "{}-----BEGIN PGP SIGNATURE-----\n\nAAAA\n=AAAA\n-----END PGP SIGNATURE-----",
                    head
                )
            } else {
                panic!("Missing PGP signature header");
            };
        assert!(
            extract_and_verify_modulus_bytes(&bad_sig, std::slice::from_ref(&srv_pub)).is_err()
        );

        // SrpClient::generate_proof enforces modulus verification before computing proofs
        let salt_b64 = BASE64.encode([0x11u8; 10]);
        let b_b64 = BASE64.encode([0x22u8; 256]);
        assert!(SrpClient::generate_proof(
            "pw",
            &salt_b64,
            &raw_b64,
            &b_b64,
            4,
            std::slice::from_ref(&srv_pub),
        )
        .is_err());
        assert!(SrpClient::generate_proof(
            "pw",
            &salt_b64,
            &signed,
            &b_b64,
            4,
            std::slice::from_ref(&other_pub),
        )
        .is_err());
    }

    #[test]
    fn test_verify_official_proton_modulus_fixture() {
        // Official Proton `/auth/v4/info` Modulus fixture from ProtonCoreLogin (`ModulusOK.json`).
        let official_modulus = concat!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n",
            "Hash: SHA256\n\n",
            "829Ys3DDLyEpVxLJOxuxVRP3ljSliB7d+5YCaH3Da0j+ncoFPGlYtgitmj9se2Zt3tulWH9VbZjOPhNh9gPg6fW3kDK5sP/JaskygFfgs8Qeoks/o9e8/KslJJZU6ztEiCY04Z/eZIX+6oZXRm/EFYxtR9QBDsgDP11FlEVxQvVeCLOTvCX7pgHTYREUYrUdDAXsljYVpUMtjxu5WE2DXcd+0SDls9dCELZSaTkvAA62FdrzJH45bD6+JUubBPBHCmW1JMVns76Y7jBNU3W41e5ZI40oaCVMAbyY8QPdWexGDHiP+paDJa5webjXjNvd6n4j6FTb95rGI4UuPp/e5A==\n",
            "-----BEGIN PGP SIGNATURE-----\n",
            "Version: ProtonMail\n",
            "Comment: https://protonmail.com\n\n",
            "wl4EARYIABAFAlwB1j8JEDUFhcTpUY8mAAA96gEAkB/m4iCzMsXQZai8uZW+\n",
            "aXzdtrkuKGhQ/ohKo6AU5ywBAMI5I6t8y4ysgmBF5gskshJNCcuW5YH8tf4w\n",
            "HrdszBUD\n",
            "=VCB1\n",
            "-----END PGP SIGNATURE-----\n",
        );

        let verified =
            extract_and_verify_modulus_bytes(official_modulus, &default_trusted_srp_keys())
                .expect("Official Proton SRP modulus must verify against pinned key");
        assert_eq!(verified.len(), 256);

        let tampered = official_modulus.replacen("829Ys3DD", "929Ys3DD", 1);
        assert!(extract_and_verify_modulus_bytes(&tampered, &default_trusted_srp_keys()).is_err());
    }

    fn sample_vault_data() -> SessionVaultData {
        let user_pass = "vault-user-pass-secret";
        let user_key = DriveKey::generate("Alice", "alice@proton.me", user_pass).unwrap();
        let addr_key = DriveKey::generate("Alice Addr", "alice@proton.me", user_pass).unwrap();
        SessionVaultData {
            uid: "uid-session-123".to_string(),
            access_token: "access-secret-token-xyz".to_string(),
            refresh_token: "refresh-secret-token-abc".to_string(),
            user_id: "user-id-456".to_string(),
            user_email: "alice@proton.me".to_string(),
            used_space: 1024,
            max_space: 1024 * 1024,
            primary_user_key_armored: Some(user_key),
            key_passphrase: Some(user_pass.to_string()),
            address_keys: vec![VaultAddressKeyRecord {
                address_id: "addr-1".to_string(),
                email: "alice@proton.me".to_string(),
                key_id: "key-1".to_string(),
                private_key_armored: addr_key,
                token: None,
                primary: true,
            }],
        }
    }

    #[test]
    fn test_session_vault_secret_service_restart_and_logout() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault_dir").join("session_vault.json");
        let store = Arc::new(InMemorySecretStore::new());
        let fallback = Arc::new(NoFallbackKeyProvider);
        let sample = sample_vault_data();

        let vault = SessionVault::new_with_backend(
            Some(vault_path.clone()),
            store.clone(),
            fallback.clone(),
        )
        .unwrap();
        assert!(!vault.is_authenticated());
        vault.save_checked(sample.clone()).unwrap();
        assert!(vault.is_authenticated());
        assert_eq!(store.secret_count(), 1);

        #[cfg(unix)]
        {
            let file_meta = fs::metadata(&vault_path).unwrap();
            assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
            let dir_meta = fs::metadata(vault_path.parent().unwrap()).unwrap();
            assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
        }

        // Disk file must NOT contain secrets
        let disk_raw = fs::read_to_string(&vault_path).unwrap();
        assert!(!disk_raw.contains(&sample.access_token));
        assert!(!disk_raw.contains(&sample.refresh_token));
        assert!(!disk_raw.contains(sample.key_passphrase.as_deref().unwrap()));
        assert!(!disk_raw.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(disk_raw.contains("secret-service"));

        // Restart from disk + Secret Service
        let reloaded =
            SessionVault::new_with_backend(Some(vault_path.clone()), store.clone(), fallback)
                .unwrap();
        assert!(reloaded.is_authenticated());
        assert_eq!(
            reloaded.http_tokens().unwrap().access_token.as_str(),
            sample.access_token
        );
        assert!(reloaded.user_key().is_some());
        assert!(reloaded.primary_address_key().is_some());

        // Logout clears both Secret Service and disk metadata
        reloaded.clear_checked().unwrap();
        assert_eq!(store.secret_count(), 0);
        assert!(!vault_path.exists());
        assert!(!reloaded.is_authenticated());
    }

    #[test]
    fn test_session_vault_debug_redacts_secrets() {
        let sample = sample_vault_data();
        let dbg_vault = format!("{:?}", sample);
        assert!(!dbg_vault.contains(&sample.access_token));
        assert!(!dbg_vault.contains(&sample.refresh_token));
        assert!(!dbg_vault.contains(sample.key_passphrase.as_deref().unwrap()));
        assert!(!dbg_vault.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(dbg_vault.contains("alice@proton.me"));

        let dbg_addr = format!("{:?}", sample.address_keys[0]);
        assert!(!dbg_addr.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(dbg_addr.contains("addr-1"));
    }

    #[test]
    fn test_session_vault_locked_keyring_refuses_downgrade_and_preserves_state() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("session_vault.json");
        let store = Arc::new(InMemorySecretStore::new());
        let fallback = Arc::new(StaticFallbackKeyProvider::new(b"independent-key".to_vec()));
        let sample = sample_vault_data();

        // Locked keyring must fail save without downgrading to fallback file
        store.set_locked(true);
        let vault = SessionVault::new_with_backend(
            Some(vault_path.clone()),
            store.clone(),
            fallback.clone(),
        )
        .unwrap();
        let err = vault.save_checked(sample.clone()).unwrap_err();
        assert!(matches!(err, VaultStorageError::KeyringLocked(_)));
        assert!(!vault_path.exists());

        // Save while unlocked, then lock keyring
        store.set_locked(false);
        vault.save_checked(sample).unwrap();
        store.set_locked(true);

        // Reload while locked must fail with KeyringLocked
        let reload_err = SessionVault::new_with_backend(
            Some(vault_path.clone()),
            store.clone(),
            fallback.clone(),
        )
        .err()
        .unwrap();
        assert!(matches!(reload_err, VaultStorageError::KeyringLocked(_)));

        // Logout while locked must fail without stranding the secret
        let clear_err = vault.clear_checked().unwrap_err();
        assert!(matches!(clear_err, VaultStorageError::KeyringLocked(_)));
        assert!(vault_path.exists());
        assert_eq!(store.secret_count(), 1);

        // Unlocking allows reload and logout
        store.set_locked(false);
        let ok = SessionVault::new_with_backend(Some(vault_path.clone()), store.clone(), fallback)
            .unwrap();
        assert!(ok.is_authenticated());
        ok.clear_checked().unwrap();
        assert_eq!(store.secret_count(), 0);
        assert!(!vault_path.exists());
    }

    #[test]
    fn test_session_vault_unavailable_keyring_and_encrypted_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("session_vault.json");
        let store = Arc::new(InMemorySecretStore::new());
        store.set_unavailable(true);
        let sample = sample_vault_data();

        // Unavailable keyring without independent fallback key fails explicitly
        let vault_no_fb = SessionVault::new_with_backend(
            Some(vault_path.clone()),
            store.clone(),
            Arc::new(NoFallbackKeyProvider),
        )
        .unwrap();
        let err = vault_no_fb.save_checked(sample.clone()).unwrap_err();
        assert!(matches!(err, VaultStorageError::KeyringUnavailable(_)));
        assert!(!vault_path.exists());

        // With an independently protected fallback key, encrypted fallback succeeds at 0600
        let fb = Arc::new(StaticFallbackKeyProvider::new(
            b"external-key-material".to_vec(),
        ));
        let vault_fb =
            SessionVault::new_with_backend(Some(vault_path.clone()), store.clone(), fb.clone())
                .unwrap();
        vault_fb.save_checked(sample.clone()).unwrap();

        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&vault_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let disk_raw = fs::read_to_string(&vault_path).unwrap();
        assert!(!disk_raw.contains(&sample.access_token));
        assert!(!disk_raw.contains(&sample.refresh_token));
        assert!(!disk_raw.contains(sample.key_passphrase.as_deref().unwrap()));
        assert!(!disk_raw.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(disk_raw.contains("encrypted-fallback"));

        // Reload with correct key succeeds
        let reloaded =
            SessionVault::new_with_backend(Some(vault_path.clone()), store.clone(), fb).unwrap();
        assert_eq!(
            reloaded.http_tokens().unwrap().access_token.as_str(),
            sample.access_token
        );

        // Wrong key fails with CryptoFailure
        let wrong_fb = Arc::new(StaticFallbackKeyProvider::new(b"wrong-key".to_vec()));
        let wrong_err =
            SessionVault::new_with_backend(Some(vault_path.clone()), store.clone(), wrong_fb)
                .err()
                .unwrap();
        assert!(matches!(wrong_err, VaultStorageError::CryptoFailure(_)));

        // Missing fallback key fails with KeyringUnavailable
        let missing_err = SessionVault::new_with_backend(
            Some(vault_path),
            store,
            Arc::new(NoFallbackKeyProvider),
        )
        .err()
        .unwrap();
        assert!(matches!(
            missing_err,
            VaultStorageError::KeyringUnavailable(_)
        ));
    }

    #[test]
    fn test_session_vault_legacy_migration_preserves_file_on_storage_failure() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("session_vault.json");
        let sample = sample_vault_data();
        let legacy_json = serde_json::to_string_pretty(&sample).unwrap();
        fs::write(&vault_path, &legacy_json).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&vault_path, fs::Permissions::from_mode(0o600)).unwrap();

        let store = Arc::new(InMemorySecretStore::new());
        let no_fb = Arc::new(NoFallbackKeyProvider);

        // 1. Locked keyring must fail migration and keep legacy JSON untouched
        store.set_locked(true);
        let err1 =
            SessionVault::new_with_backend(Some(vault_path.clone()), store.clone(), no_fb.clone())
                .err()
                .unwrap();
        assert!(matches!(err1, VaultStorageError::KeyringLocked(_)));
        assert_eq!(fs::read_to_string(&vault_path).unwrap(), legacy_json);
        assert_eq!(store.secret_count(), 0);

        // 2. Storage failure must fail migration and keep legacy JSON untouched
        store.set_locked(false);
        store.set_fail_writes(true);
        let err2 =
            SessionVault::new_with_backend(Some(vault_path.clone()), store.clone(), no_fb.clone())
                .err()
                .unwrap();
        assert!(matches!(err2, VaultStorageError::StorageFailure(_)));
        assert_eq!(fs::read_to_string(&vault_path).unwrap(), legacy_json);
        assert_eq!(store.secret_count(), 0);

        // 3. Unavailable keyring without fallback key must keep legacy JSON untouched
        store.set_fail_writes(false);
        store.set_unavailable(true);
        let err3 =
            SessionVault::new_with_backend(Some(vault_path.clone()), store.clone(), no_fb.clone())
                .err()
                .unwrap();
        assert!(matches!(err3, VaultStorageError::KeyringUnavailable(_)));
        assert_eq!(fs::read_to_string(&vault_path).unwrap(), legacy_json);
        assert_eq!(store.secret_count(), 0);

        // 4. Once Secret Service succeeds, migration replaces legacy JSON atomically with non-secret v2
        store.set_unavailable(false);
        let migrated =
            SessionVault::new_with_backend(Some(vault_path.clone()), store.clone(), no_fb).unwrap();
        assert!(migrated.is_authenticated());
        assert_eq!(
            migrated.http_tokens().unwrap().access_token.as_str(),
            sample.access_token
        );
        assert_eq!(store.secret_count(), 1);
        let new_disk = fs::read_to_string(&vault_path).unwrap();
        assert!(!new_disk.contains(&sample.access_token));
        assert!(!new_disk.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(new_disk.contains("secret-service"));
    }

    #[test]
    fn test_session_vault_permissions_symlink_and_env_keyfile_validation() {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        fs::write(&target, "{}").unwrap();
        let link_vault = dir.path().join("symlink_vault.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link_vault).unwrap();

        let store = Arc::new(InMemorySecretStore::new());
        let err = SessionVault::new_with_backend(
            Some(link_vault),
            store,
            Arc::new(NoFallbackKeyProvider),
        )
        .err()
        .unwrap();
        assert!(matches!(err, VaultStorageError::StorageFailure(_)));

        // Keyfile with 0644 permissions must be rejected
        let keyfile = dir.path().join("vault.key");
        fs::write(&keyfile, b"super-secret-fallback-key").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&keyfile, fs::Permissions::from_mode(0o644)).unwrap();

        std::env::remove_var(VAULT_ENV_KEY);
        std::env::set_var(VAULT_ENV_KEY_FILE, &keyfile);
        let bad_res = EnvFallbackKeyProvider.resolve_key();
        assert!(matches!(bad_res, Err(VaultStorageError::StorageFailure(_))));

        // Tightening to 0600 allows loading
        #[cfg(unix)]
        fs::set_permissions(&keyfile, fs::Permissions::from_mode(0o600)).unwrap();
        let ok_res = EnvFallbackKeyProvider.resolve_key().unwrap();
        assert_eq!(
            ok_res.as_deref().map(|v| v.as_slice()),
            Some(b"super-secret-fallback-key".as_slice())
        );
        std::env::remove_var(VAULT_ENV_KEY_FILE);
    }
}
