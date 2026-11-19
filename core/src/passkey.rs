//! Passkeys: CleanPassword as a WebAuthn authenticator, the way Apple's,
//! Google's and Bitwarden's password managers are.
//!
//! - **Creating** one (a site's `navigator.credentials.create`, or iOS's
//!   passkey registration): a new P-256 key pair, the private key kept on a
//!   login item (encrypted and synced with it), and an attestation of
//!   format `none` for the site: authenticator data with the credential id
//!   and the public key (COSE).
//! - **Signing in** (`navigator.credentials.get`, or iOS's passkey
//!   assertion): authenticator data and an ES256 signature over it and the
//!   hash of the client data.
//! - Flags: user present and verified (the vault was unlocked with the
//!   master password or Face ID, and the user picked the passkey), and
//!   backup eligible and backed up (synced passkeys).
//! - Counters stay 0 for passkeys made here, as synced passkeys' do;
//!   imported ones that already counted keep counting.
//!
//! Keys are stored as Bitwarden exports them (PKCS#8, base64url), so
//! passkeys import from Bitwarden and export back to it.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::item::{Item, ItemData, ItemKind, ItemUri, Passkey};
use crate::vault::Vault;
use crate::{matching, Error, Result};

/// CleanPassword's authenticator model id (random, fixed).
pub const AAGUID: [u8; 16] = [0x5c, 0x1e, 0xa9, 0x0d, 0x3b, 0x77, 0x4f, 0x2e, 0x9a, 0x61, 0x0c, 0x4e, 0x2d, 0x8b, 0x17, 0xf3];
/// COSE algorithm ES256 (ECDSA P-256 with SHA-256), the only one made.
pub const ES256: i64 = -7;

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// base64url or standard base64, with or without padding.
pub fn unb64(s: &str) -> Result<Vec<u8>> {
    let t = s.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(t))
        .or_else(|_| STANDARD.decode(s.trim()))
        .map_err(|_| Error::invalid("damaged passkey data (bad base64)"))
}

/// A credential id as Bitwarden writes it: `b64.<base64url>` for ones it
/// imported, a GUID for ones it made (the GUID's 16 bytes are the id), or
/// base64url (ours).
pub fn parse_credential_id(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("b64.") {
        return unb64(rest).ok();
    }
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if s.len() == 36 && s.matches('-').count() == 4 && hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return (0..16).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()).collect();
    }
    unb64(s).ok().filter(|b| !b.is_empty())
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// The COSE_Key of a public key: `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
fn cose_key(vk: &VerifyingKey) -> Vec<u8> {
    let point = vk.to_encoded_point(false);
    let (x, y) = (point.x().expect("uncompressed"), point.y().expect("uncompressed"));
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    out.extend_from_slice(x);
    out.extend_from_slice(&[0x22, 0x58, 0x20]);
    out.extend_from_slice(y);
    out
}

/// A public key as SubjectPublicKeyInfo DER (`getPublicKey()` in browsers).
pub fn spki(vk: &VerifyingKey) -> Vec<u8> {
    const PREFIX: [u8; 26] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];
    let mut out = PREFIX.to_vec();
    out.extend_from_slice(vk.to_encoded_point(false).as_bytes());
    out
}

fn cbor_bytes_header(len: usize, out: &mut Vec<u8>) {
    match len {
        0..=23 => out.push(0x40 | len as u8),
        24..=255 => out.extend_from_slice(&[0x58, len as u8]),
        _ => {
            out.push(0x59);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
    }
}

/// `{"fmt": "none", "attStmt": {}, "authData": …}`, in CBOR's canonical
/// key order.
fn attestation_none(auth_data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa3, 0x63];
    out.extend_from_slice(b"fmt");
    out.push(0x64);
    out.extend_from_slice(b"none");
    out.push(0x67);
    out.extend_from_slice(b"attStmt");
    out.push(0xa0);
    out.push(0x68);
    out.extend_from_slice(b"authData");
    cbor_bytes_header(auth_data.len(), &mut out);
    out.extend_from_slice(auth_data);
    out
}

fn auth_data(rp_id: &str, flags: u8, counter: u32, attested: Option<(&[u8], &VerifyingKey)>) -> Vec<u8> {
    let mut out = rp_id_hash(rp_id).to_vec();
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    if let Some((id, vk)) = attested {
        out.extend_from_slice(&AAGUID);
        out.extend_from_slice(&(id.len() as u16).to_be_bytes());
        out.extend_from_slice(id);
        out.extend(cose_key(vk));
    }
    out
}

fn signing_key(p: &Passkey) -> Result<SigningKey> {
    let der = unb64(&p.key)?;
    SigningKey::from_pkcs8_der(&der).map_err(|_| Error::invalid("this passkey's key is damaged or isn't a P-256 key"))
}

/// The client data browsers make for a request (the Chrome extension makes
/// it itself; on iOS the system does and hands over its hash).
pub fn client_data_json(kind: &str, challenge: &[u8], origin: &str, cross_origin: bool) -> String {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":{},"crossOrigin":{cross_origin}}}"#,
        b64url(challenge),
        serde_json::to_string(origin).expect("a string serializes")
    )
}

/// Whether a page at `origin` may use passkeys for `rp_id`: https (or
/// localhost), and the relying party is the page's host or a domain above
/// it, but not a public suffix (`com`, `github.io`).
pub fn rp_id_allowed(rp_id: &str, origin: &str) -> bool {
    let Ok(url) = url::Url::parse(origin) else { return false };
    let Some(host) = url.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()) else { return false };
    let local = host == "localhost" || host.ends_with(".localhost");
    if url.scheme() != "https" && !(url.scheme() == "http" && local) {
        return false;
    }
    let rp = rp_id.trim_end_matches('.').to_ascii_lowercase();
    if rp.is_empty() || !(host == rp || host.ends_with(&format!(".{rp}"))) {
        return false;
    }
    local || host == rp && rp.parse::<std::net::IpAddr>().is_ok() || psl::domain_str(&rp).is_some()
}

/// A passkey offered for signing in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyChoice {
    pub item_id: String,
    pub item_name: String,
    /// base64url.
    pub credential_id: String,
    pub user_name: String,
    pub user_display_name: String,
}

/// What a site asks to create.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewPasskey {
    pub rp_id: String,
    #[serde(default)]
    pub rp_name: String,
    pub user_handle: Vec<u8>,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub user_display_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// The login the passkey was saved on.
    pub item_id: String,
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// SubjectPublicKeyInfo DER.
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ECDSA signature.
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

impl Vault {
    /// The passkeys for a relying party, limited to `allow` (credential
    /// ids) if the site gave any.
    pub fn passkeys_for(&self, rp_id: &str, allow: &[Vec<u8>]) -> Vec<PasskeyChoice> {
        let rp = rp_id.to_ascii_lowercase();
        let mut out = Vec::new();
        for i in self.items() {
            for p in i.passkeys.iter().filter(|p| p.rp_id.eq_ignore_ascii_case(&rp)) {
                if !allow.is_empty() && !allow.iter().any(|a| unb64(&p.credential_id).is_ok_and(|id| &id == a)) {
                    continue;
                }
                out.push(PasskeyChoice {
                    item_id: i.id.clone(),
                    item_name: i.name.clone(),
                    credential_id: p.credential_id.clone(),
                    user_name: p.user_name.clone(),
                    user_display_name: p.user_display_name.clone(),
                });
            }
        }
        out
    }

    /// Whether one of `exclude` (a site's existing credentials for the
    /// account) is already here: the site doesn't want a second one.
    pub fn passkey_excluded(&self, rp_id: &str, exclude: &[Vec<u8>]) -> bool {
        !exclude.is_empty() && !self.passkeys_for(rp_id, exclude).is_empty()
    }

    /// Creates a passkey and saves it on a login: `item_id` if given (the
    /// user chose it), else the one already holding a passkey for this
    /// account (which is replaced), else a login for the site with the same
    /// user name (or none), else a new login.
    pub fn create_passkey(&mut self, req: &NewPasskey, item_id: Option<&str>) -> Result<Registration> {
        let rp_id = req.rp_id.trim().to_ascii_lowercase();
        if rp_id.is_empty() || req.user_handle.is_empty() || req.user_handle.len() > 64 {
            return Err(Error::invalid("the site's passkey request is invalid"));
        }
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        let id = crate::crypto::random_bytes::<16>();
        let key = sk.to_pkcs8_der().map_err(|_| Error::invalid("couldn't store the key"))?;
        let passkey = Passkey {
            credential_id: b64url(&id),
            rp_id: rp_id.clone(),
            rp_name: req.rp_name.clone(),
            user_handle: b64url(&req.user_handle),
            user_name: req.user_name.clone(),
            user_display_name: req.user_display_name.clone(),
            key: b64url(key.as_bytes()),
            counter: 0,
            created: Utc::now(),
        };
        let handle = b64url(&req.user_handle);
        let target = match item_id {
            Some(id) => Some(self.get(id).ok_or(Error::NotFound)?.id.clone()),
            None => self
                .items()
                .into_iter()
                .find(|i| i.passkeys.iter().any(|p| p.rp_id == rp_id && p.user_handle == handle))
                .or_else(|| {
                    let page = matching::parse_page(&format!("https://{rp_id}"))?;
                    self.items().into_iter().find(|i| {
                        i.kind == ItemKind::Login
                            && i.uris.iter().any(|u| matching::match_uri(u, &page).is_some_and(|q| q >= matching::Quality::Domain))
                            && (i.username.is_empty() || i.username.eq_ignore_ascii_case(&req.user_name))
                    })
                })
                .map(|i| i.id.clone()),
        };
        let now = Utc::now();
        let item_id = match target {
            Some(id) => {
                let item = self.s.items.get_mut(&id).expect("found above");
                // One passkey per account and site: a new one replaces it.
                item.passkeys.retain(|p| !(p.rp_id == rp_id && p.user_handle == handle));
                item.passkeys.push(passkey);
                if item.username.is_empty() {
                    item.username = req.user_name.clone();
                }
                item.modified = now;
                id
            }
            None => {
                let name = if req.rp_name.trim().is_empty() { matching::registrable_domain(&rp_id) } else { req.rp_name.trim().to_owned() };
                let data = ItemData { kind: ItemKind::Login, name, username: req.user_name.clone(), uris: vec![ItemUri::new(format!("https://{rp_id}"))], ..Default::default() };
                let mut item = Item::new(data, now);
                item.passkeys.push(passkey);
                let id = item.id.clone();
                self.s.items.insert(id.clone(), item);
                id
            }
        };
        let authenticator_data = auth_data(&rp_id, UP | UV | BE | BS | AT, 0, Some((&id, &vk)));
        Ok(Registration { item_id, credential_id: id.to_vec(), attestation_object: attestation_none(&authenticator_data), authenticator_data, public_key: spki(&vk) })
    }

    /// Signs in with a passkey: `client_data_hash` is SHA-256 of the
    /// client data.
    pub fn assert_passkey(&mut self, item_id: &str, credential_id: &[u8], rp_id: &str, client_data_hash: &[u8]) -> Result<Assertion> {
        if client_data_hash.len() != 32 {
            return Err(Error::invalid("the client data hash must be 32 bytes"));
        }
        let item = self.s.items.get_mut(item_id).ok_or(Error::NotFound)?;
        let p = item
            .passkeys
            .iter_mut()
            .find(|p| unb64(&p.credential_id).is_ok_and(|id| id == credential_id))
            .ok_or(Error::NotFound)?;
        if !p.rp_id.eq_ignore_ascii_case(rp_id) {
            return Err(Error::invalid("this passkey belongs to another site"));
        }
        let sk = signing_key(p)?;
        if p.counter > 0 {
            p.counter += 1;
        }
        let data = auth_data(&p.rp_id, UP | UV | BE | BS, p.counter, None);
        let mut signed = data.clone();
        signed.extend_from_slice(client_data_hash);
        let sig: Signature = sk.sign(&signed);
        Ok(Assertion { credential_id: credential_id.to_vec(), authenticator_data: data, signature: sig.to_der().as_bytes().to_vec(), user_handle: unb64(&p.user_handle)? })
    }

    /// Removes a passkey from an item (the site keeps its public key until
    /// removed there too).
    pub fn delete_passkey(&mut self, item_id: &str, credential_id: &str) -> Result<()> {
        let item = self.s.items.get_mut(item_id).ok_or(Error::NotFound)?;
        let before = item.passkeys.len();
        item.passkeys.retain(|p| p.credential_id != credential_id);
        if item.passkeys.len() == before {
            return Err(Error::NotFound);
        }
        item.modified = Utc::now();
        Ok(())
    }
}

/// A passkey from Bitwarden's export (`fido2Credentials`), if it's one this
/// can use (ECDSA P-256).
pub fn from_bitwarden(v: &serde_json::Value) -> Option<Passkey> {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_owned();
    let alg = s("keyAlgorithm");
    let curve = s("keyCurve");
    if !(alg.is_empty() || alg.eq_ignore_ascii_case("ECDSA")) || !(curve.is_empty() || curve.eq_ignore_ascii_case("P-256")) {
        return None;
    }
    let key = unb64(&s("keyValue")).ok()?;
    SigningKey::from_pkcs8_der(&key).ok()?;
    let id = parse_credential_id(&s("credentialId"))?;
    let handle = unb64(&s("userHandle")).ok()?;
    let rp_id = s("rpId").to_ascii_lowercase();
    if rp_id.is_empty() {
        return None;
    }
    Some(Passkey {
        credential_id: b64url(&id),
        rp_id,
        rp_name: s("rpName"),
        user_handle: b64url(&handle),
        user_name: s("userName"),
        user_display_name: s("userDisplayName"),
        key: b64url(&key),
        counter: s("counter").parse().ok().or_else(|| v.get("counter").and_then(|c| c.as_u64()).map(|c| c as u32)).unwrap_or(0),
        created: s("creationDate").parse().unwrap_or_else(|_| Utc::now()),
    })
}

/// A passkey as Bitwarden's export writes it.
pub fn to_bitwarden(p: &Passkey) -> serde_json::Value {
    serde_json::json!({
        "credentialId": format!("b64.{}", p.credential_id),
        "keyType": "public-key",
        "keyAlgorithm": "ECDSA",
        "keyCurve": "P-256",
        "keyValue": p.key,
        "rpId": p.rp_id,
        "userHandle": p.user_handle,
        "userName": p.user_name,
        "counter": p.counter.to_string(),
        "rpName": p.rp_name,
        "userDisplayName": p.user_display_name,
        "discoverable": "true",
        "creationDate": p.created,
    })
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;

    use super::*;
    use crate::vault::tests::{config, creds, login, PW};

    fn request(user: &str) -> NewPasskey {
        NewPasskey { rp_id: "example.com".into(), rp_name: "Example".into(), user_handle: user.as_bytes().to_vec(), user_name: format!("{user}@example.com"), user_display_name: user.into() }
    }

    #[test]
    fn create_then_sign_in() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        let r = v.create_passkey(&request("alice"), None).unwrap();
        // A new login for the site, with the passkey on it.
        let item = v.get(&r.item_id).unwrap();
        assert_eq!((item.name.as_str(), item.username.as_str()), ("Example", "alice@example.com"));
        assert_eq!(item.passkeys.len(), 1);
        assert!(v.matches("https://example.com/login").iter().any(|m| m.id == r.item_id));

        // The attestation: fmt none, and authenticator data with flags,
        // counter 0, our AAGUID, the id and a COSE ES256 key.
        let a = &r.attestation_object;
        assert_eq!(&a[..5], &[0xa3, 0x63, b'f', b'm', b't']);
        assert!(a.ends_with(&r.authenticator_data));
        let ad = &r.authenticator_data;
        assert_eq!(&ad[..32], &rp_id_hash("example.com"));
        assert_eq!(ad[32], UP | UV | BE | BS | AT);
        assert_eq!(&ad[33..37], &[0, 0, 0, 0]);
        assert_eq!(&ad[37..53], &AAGUID);
        assert_eq!(&ad[53..55], &[0, 16]);
        assert_eq!(&ad[55..71], &r.credential_id[..]);
        assert_eq!(&ad[71..76], &[0xa5, 0x01, 0x02, 0x03, 0x26]);
        let vk = VerifyingKey::from_public_key_der(&r.public_key).unwrap();
        assert_eq!(&ad[71..], &cose_key(&vk)[..]);

        // Signing in: offered for the site, and the signature verifies.
        let choices = v.passkeys_for("example.com", &[]);
        assert_eq!(choices.len(), 1);
        assert!(v.passkeys_for("other.com", &[]).is_empty());
        assert!(v.passkeys_for("example.com", &[vec![1, 2, 3]]).is_empty(), "not among the allowed");
        let cdh: [u8; 32] = Sha256::digest(client_data_json("webauthn.get", b"challenge", "https://example.com", false)).into();
        let s = v.assert_passkey(&r.item_id, &r.credential_id, "example.com", &cdh).unwrap();
        assert_eq!(s.user_handle, b"alice");
        assert_eq!(s.authenticator_data[32], UP | UV | BE | BS);
        let mut signed = s.authenticator_data.clone();
        signed.extend_from_slice(&cdh);
        let sig = Signature::from_der(&s.signature).unwrap();
        vk.verify(&signed, &sig).unwrap();
        assert!(v.assert_passkey(&r.item_id, &r.credential_id, "evil.com", &cdh).is_err());

        // Kept through saving and unlocking.
        let saved = v.save();
        let again = Vault::unlock(&saved, PW).unwrap();
        assert_eq!(again.get(&r.item_id).unwrap().passkeys, item_clone(&v, &r.item_id));
    }

    fn item_clone(v: &Vault, id: &str) -> Vec<Passkey> {
        v.get(id).unwrap().passkeys.clone()
    }

    #[test]
    fn saved_on_the_matching_login_and_replaced_per_account() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        let existing = v.add(login("Example", "https://www.example.com", "alice@example.com", "pw")).unwrap();
        let other = v.add(login("Example 2", "https://example.com", "bob@example.com", "pw")).unwrap();
        let r1 = v.create_passkey(&request("alice"), None).unwrap();
        assert_eq!(r1.item_id, existing, "the login with that user name");
        let r2 = v.create_passkey(&request("alice"), None).unwrap();
        assert_eq!(r2.item_id, existing);
        assert_eq!(v.get(&existing).unwrap().passkeys.len(), 1, "replaced, not added");
        assert_ne!(r1.credential_id, r2.credential_id);
        assert!(v.passkey_excluded("example.com", std::slice::from_ref(&r2.credential_id)));
        assert!(!v.passkey_excluded("example.com", std::slice::from_ref(&r1.credential_id)));
        let r3 = v.create_passkey(&request("carol"), Some(&other)).unwrap();
        assert_eq!(r3.item_id, other, "where the user chose");
        v.delete_passkey(&other, &b64url(&r3.credential_id)).unwrap();
        assert!(v.get(&other).unwrap().passkeys.is_empty());
    }

    #[test]
    fn counters_count_only_if_they_did() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        let r = v.create_passkey(&request("alice"), None).unwrap();
        let cdh = [7u8; 32];
        let s = v.assert_passkey(&r.item_id, &r.credential_id, "example.com", &cdh).unwrap();
        assert_eq!(&s.authenticator_data[33..37], &[0, 0, 0, 0]);
        v.s.items.get_mut(&r.item_id).unwrap().passkeys[0].counter = 41;
        let s = v.assert_passkey(&r.item_id, &r.credential_id, "example.com", &cdh).unwrap();
        assert_eq!(&s.authenticator_data[33..37], &[0, 0, 0, 42]);
    }

    #[test]
    fn relying_party_ids() {
        assert!(rp_id_allowed("example.com", "https://example.com"));
        assert!(rp_id_allowed("example.com", "https://login.example.com"));
        assert!(rp_id_allowed("login.example.com", "https://login.example.com:8443"));
        assert!(!rp_id_allowed("example.com", "http://example.com"), "not on http");
        assert!(!rp_id_allowed("login.example.com", "https://example.com"), "not below the page");
        assert!(!rp_id_allowed("other.com", "https://example.com"));
        assert!(!rp_id_allowed("ample.com", "https://example.com"));
        assert!(!rp_id_allowed("com", "https://example.com"), "a public suffix");
        assert!(!rp_id_allowed("github.io", "https://alice.github.io"), "a public suffix");
        assert!(rp_id_allowed("alice.github.io", "https://alice.github.io"));
        assert!(rp_id_allowed("localhost", "http://localhost:3000"));
    }

    #[test]
    fn credential_ids_as_bitwarden_writes_them() {
        assert_eq!(parse_credential_id("b64.AQID"), Some(vec![1, 2, 3]));
        assert_eq!(parse_credential_id("00112233-4455-6677-8899-aabbccddeeff").unwrap(), (0..16).map(|i| i * 0x11).collect::<Vec<u8>>());
        assert_eq!(parse_credential_id("AQID"), Some(vec![1, 2, 3]));
    }

    #[test]
    fn bitwarden_format_round_trip() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        let r = v.create_passkey(&request("alice"), None).unwrap();
        let p = v.get(&r.item_id).unwrap().passkeys[0].clone();
        let back = from_bitwarden(&to_bitwarden(&p)).unwrap();
        assert_eq!(back, p);
        // Bitwarden's own: GUID ids, standard base64 keys.
        let mut bw = to_bitwarden(&p);
        bw["credentialId"] = "00112233-4455-6677-8899-aabbccddeeff".into();
        bw["keyValue"] = STANDARD.encode(unb64(&p.key).unwrap()).into();
        let q = from_bitwarden(&bw).unwrap();
        assert_eq!(unb64(&q.credential_id).unwrap().len(), 16);
        assert_eq!(q.key, p.key);
        bw["keyCurve"] = "P-384".into();
        assert!(from_bitwarden(&bw).is_none());
    }

    /// Imported first without passkeys (as earlier versions did), then the
    /// same export again: the passkeys join the logins already there, and
    /// they sign in.
    #[test]
    fn reimporting_brings_passkeys_to_existing_logins() {
        let mut a = Vault::create(config(), creds(), PW).unwrap();
        let r = a.create_passkey(&request("alice"), None).unwrap();
        a.add(login("Other", "https://other.com", "me", "pw")).unwrap();
        let export = crate::import::export_bitwarden_json(&a.items());
        let mut without: serde_json::Value = serde_json::from_str(&export).unwrap();
        for i in without["items"].as_array_mut().unwrap() {
            i["login"]["fido2Credentials"] = serde_json::json!([]);
        }

        let mut b = Vault::create(config(), creds(), PW).unwrap();
        let first = b.import(crate::import::import_file(&without.to_string(), None).unwrap().items);
        assert_eq!((first.added, first.passkeys), (2, 0));
        let again = b.import(crate::import::import_file(&export, None).unwrap().items);
        assert_eq!((again.added, again.skipped, again.passkeys), (0, 2, 1));
        assert_eq!(b.items().len(), 2);
        let third = b.import(crate::import::import_file(&export, None).unwrap().items);
        assert_eq!(third.passkeys, 0, "not twice");

        let choice = &b.passkeys_for("example.com", &[])[0];
        let s = b.assert_passkey(&choice.item_id.clone(), &unb64(&choice.credential_id).unwrap(), "example.com", &[1; 32]).unwrap();
        let vk = VerifyingKey::from_public_key_der(&r.public_key).unwrap();
        let mut signed = s.authenticator_data.clone();
        signed.extend_from_slice(&[1; 32]);
        vk.verify(&signed, &Signature::from_der(&s.signature).unwrap()).unwrap();
    }

    #[test]
    fn passkeys_merge_from_both_devices() {
        use crate::item::merge;
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        let id = v.add(login("Example", "https://example.com", "", "pw")).unwrap();
        let base = v.get(&id).unwrap().clone();
        let mut a = base.clone();
        let mut b = base.clone();
        let mut va = Vault::create(config(), creds(), PW).unwrap();
        let ra = va.create_passkey(&request("a"), None).unwrap();
        a.passkeys = va.get(&ra.item_id).unwrap().passkeys.clone();
        let rb = va.create_passkey(&request("b"), None).unwrap();
        b.passkeys = va.get(&rb.item_id).unwrap().passkeys.iter().filter(|p| p.user_handle == b64url(b"b")).cloned().collect();
        let m = merge(Some(&base), &a, &b);
        assert_eq!(m.passkeys.len(), 2, "both kept");
        // Deleted on one side since the base: gone.
        let base2 = m.clone();
        let mut c = m.clone();
        c.passkeys.remove(0);
        assert_eq!(merge(Some(&base2), &c, &m).passkeys.len(), 1);
    }
}
