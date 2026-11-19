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

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cleanbucket::kdf::{self, Cost};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Sealing, random keys and padding: the ones CleanNotes uses too (the
/// `cleanbucket` crate), byte for byte what this vault has always stored.
pub use cleanbucket::seal::{open, pad, random_bytes, random_key, seal, Key};

pub const DEFAULT_MEMORY_KIB: u32 = Cost::DEFAULT.memory_kib;
pub const DEFAULT_PASSES: u32 = Cost::DEFAULT.passes;

/// The least a vault may ask for: below this a stolen vault would be too
/// cheap to attack (OWASP's minimum is 19 MiB with 2 passes). Tests use
/// tiny costs to run fast.
const MIN_MEMORY_KIB: u32 = if cfg!(test) { 8 } else { kdf::MIN_MEMORY_KIB };

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

    fn cost(&self) -> Result<Cost> {
        if self.alg != "argon2id" {
            return Err(Error::invalid(format!("this vault uses {}, which this version of CleanPassword doesn't know", self.alg)));
        }
        // A damaged or hostile vault.json can't make a device allocate
        // gigabytes, nor make a stolen vault cheap to attack.
        let cost = Cost { memory_kib: self.memory_kib, passes: self.passes, lanes: self.lanes };
        cost.check(MIN_MEMORY_KIB).map_err(|_| Error::invalid("the vault's key derivation settings are out of the allowed range"))?;
        Ok(cost)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::new()
    }
}

/// The master key for `password` (Argon2id).
pub fn derive_key(password: &str, p: &KdfParams) -> Result<Key> {
    let cost = p.cost()?;
    let salt = unb64(&p.salt)?;
    if salt.len() < 16 {
        return Err(Error::invalid("the vault's salt is too short"));
    }
    Ok(kdf::derive(password.as_bytes(), &salt, cost)?)
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
