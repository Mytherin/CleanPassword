//! The encryption everything is stored with.
//!
//! - **Master password → master key:** Argon2id (46 MiB, 3 passes, 1 lane by
//!   default: above OWASP's recommendation, and small enough for iOS's
//!   AutoFill extensions, which get little memory). The costs and the random
//!   salt are stored with the vault, so they can be raised later.
//! - **Vault key:** 32 random bytes that encrypt every item. It's stored
//!   only wrapped (encrypted) by the master key, so changing the master
//!   password re-wraps one key instead of re-encrypting the vault.
//! - **Sealing:** XChaCha20-Poly1305 with a random 24-byte nonce
//!   (`nonce ‖ ciphertext ‖ tag`). Every sealed thing carries associated
//!   data naming what it is (the vault, the item id), so ciphertexts can't
//!   be swapped between items or vaults without failing to open.
//! - Keys are wiped from memory when dropped ([`Zeroizing`]).

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// A 256-bit key, wiped when dropped.
pub type Key = Zeroizing<[u8; 32]>;

pub const DEFAULT_MEMORY_KIB: u32 = 46 * 1024;
pub const DEFAULT_PASSES: u32 = 3;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// The least a vault may ask for: below this a stolen vault would be too
/// cheap to attack (OWASP's minimum is 19 MiB with 2 passes). Tests use
/// tiny costs to run fast.
const MIN_MEMORY_KIB: u32 = if cfg!(test) { 8 } else { 19 * 1024 };
/// The most a vault may ask for, so a damaged or hostile `vault.json`
/// can't make a device allocate gigabytes.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// How the master key is made from the master password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Always `argon2id` for now.
    pub alg: String,
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
    /// 16 random bytes, base64.
    pub salt: String,
}

impl KdfParams {
    /// The default costs with a new random salt.
    pub fn new() -> KdfParams {
        if cfg!(test) {
            KdfParams::with_cost(64, 1)
        } else {
            KdfParams::with_cost(DEFAULT_MEMORY_KIB, DEFAULT_PASSES)
        }
    }

    pub fn with_cost(memory_kib: u32, passes: u32) -> KdfParams {
        KdfParams { alg: "argon2id".into(), memory_kib, passes, lanes: 1, salt: b64(&random_bytes::<16>()) }
    }

    fn check(&self) -> Result<()> {
        if self.alg != "argon2id" {
            return Err(Error::invalid(format!("this vault uses {}, which this version of CleanPassword doesn't know", self.alg)));
        }
        let ok = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) && (1..=32).contains(&self.passes) && (1..=16).contains(&self.lanes);
        if !ok {
            return Err(Error::invalid("the vault's key derivation settings are out of the allowed range"));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::new()
    }
}

/// The master key for `password`.
pub fn derive_key(password: &str, p: &KdfParams) -> Result<Key> {
    p.check()?;
    let salt = unb64(&p.salt)?;
    if salt.len() < 16 {
        return Err(Error::invalid("the vault's salt is too short"));
    }
    let params = Params::new(p.memory_kib, p.passes, p.lanes, Some(32)).map_err(|e| Error::invalid(format!("argon2: {e}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, key.as_mut())
        .map_err(|e| Error::invalid(format!("argon2: {e}")))?;
    Ok(key)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn random_key() -> Key {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key
}

/// `nonce ‖ ciphertext ‖ tag` of `plain`, bound to `aad`.
pub fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce = random_bytes::<NONCE_LEN>();
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad })
        .expect("XChaCha20-Poly1305 encryption can't fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend(ct);
    out
}

/// The plaintext of [`seal`]'s output, or `None` if it wasn't sealed with
/// this key and `aad`, or was changed.
pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.into()).decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad }).ok().map(Zeroizing::new)
}

/// Pads `data` with spaces (JSON ignores them) to a multiple of `block`
/// bytes, so stored sizes don't give away how long passwords and notes are.
pub fn pad(mut data: Vec<u8>, block: usize) -> Vec<u8> {
    let len = data.len().div_ceil(block).max(1) * block;
    data.resize(len, b' ');
    data
}

pub fn b64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s.trim()).map_err(|_| Error::invalid("damaged data (bad base64)"))
}

/// A key from base64 (as kept in a keychain).
pub fn key_from_b64(s: &str) -> Result<Key> {
    let bytes = Zeroizing::new(unb64(s)?);
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::invalid("a key must be 32 bytes"))?;
    Ok(Zeroizing::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_per_salt() {
        let p = KdfParams::new();
        assert_eq!(*derive_key("pw", &p).unwrap(), *derive_key("pw", &p).unwrap());
        assert_ne!(*derive_key("pw", &p).unwrap(), *derive_key("pw2", &p).unwrap());
        assert_ne!(*derive_key("pw", &p).unwrap(), *derive_key("pw", &KdfParams::new()).unwrap());
    }

    #[test]
    fn hostile_params_are_refused() {
        let mut p = KdfParams::new();
        p.memory_kib = 4 * 1024 * 1024;
        assert!(derive_key("pw", &p).is_err());
        let mut p = KdfParams::new();
        p.alg = "pbkdf2".into();
        assert!(derive_key("pw", &p).is_err());
        let mut p = KdfParams::new();
        p.salt = b64(b"short");
        assert!(derive_key("pw", &p).is_err());
    }

    #[test]
    fn seal_and_open() {
        let key = random_key();
        let sealed = seal(&key, b"item:1", b"secret");
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(open(&key, b"item:1", &sealed).unwrap().as_slice(), b"secret");
        assert!(open(&key, b"item:2", &sealed).is_none(), "bound to its aad");
        assert!(open(&random_key(), b"item:1", &sealed).is_none());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"item:1", &tampered).is_none());
        assert!(open(&key, b"item:1", &sealed[..10]).is_none());
        assert_ne!(seal(&key, b"a", b"x"), seal(&key, b"a", b"x"), "random nonces");
    }

    #[test]
    fn padding() {
        assert_eq!(pad(vec![b'x'; 10], 256).len(), 256);
        assert_eq!(pad(vec![b'x'; 256], 256).len(), 256);
        assert_eq!(pad(vec![b'x'; 257], 256).len(), 512);
        assert_eq!(pad(vec![], 256).len(), 256);
    }
}
