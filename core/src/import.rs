//! Importing from other password managers, and exporting.
//!
//! - **Bitwarden JSON** (Tools → Export vault → `.json`), unencrypted or
//!   **password-protected** ("Encrypted" with "Password protected"): the
//!   latter is decrypted here with the export's password (PBKDF2-SHA256 or
//!   Argon2id, then AES-256-CBC with HMAC-SHA256, as Bitwarden makes it),
//!   so no unencrypted copy of the vault ever needs to be written to disk.
//!   "Account restricted" exports can only be opened by Bitwarden itself.
//! - **CSV**: Bitwarden's, and those of Chrome, Edge, Safari / Apple
//!   Passwords, Firefox, 1Password and LastPass (columns are recognised by
//!   their names).
//! - **Export**: Bitwarden's unencrypted JSON format, which Bitwarden and
//!   most other password managers import.
//!
//! Cards, identities and SSH keys become secure notes with their details as
//! fields (numbers and codes hidden). **Passkeys** come along with their
//! logins (Bitwarden exports their private keys), and go back out in exports;
//! only ones of a kind CleanPassword can't use (not P-256) are left out,
//! and counted in the warnings.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::item::{Field, HistoryEntry, Item, ItemData, ItemKind, ItemUri, Passkey, UriMatch};
use crate::passkey;
use crate::{Error, Result};

/// The hidden field a Wi-Fi network's password goes in when exported to
/// Bitwarden's format (which has no Wi-Fi type), and comes back from.
const WIFI_PASSWORD_FIELD: &str = "Wi-Fi Password";

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ImportedItem {
    pub data: ItemData,
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
    #[serde(default)]
    pub passkeys: Vec<Passkey>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Imported {
    pub items: Vec<ImportedItem>,
    /// Things that couldn't be brought over, to tell the user.
    pub warnings: Vec<String>,
}

/// Imports a file, recognising its format. `password` is for a
/// password-protected Bitwarden export.
pub fn import_file(text: &str, password: Option<&str>) -> Result<Imported> {
    let t = text.trim_start_matches('\u{feff}').trim_start();
    if t.starts_with('{') {
        bitwarden_json(t, password)
    } else {
        csv(t)
    }
}

/// Whether a Bitwarden JSON export needs its password.
pub fn needs_password(text: &str) -> bool {
    serde_json::from_str::<BwExport>(text.trim_start_matches('\u{feff}')).map(|e| e.encrypted && e.password_protected).unwrap_or(false)
}

// ---- Bitwarden JSON ---------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct BwExport {
    encrypted: bool,
    password_protected: bool,
    salt: Option<String>,
    kdf_type: Option<u32>,
    kdf_iterations: Option<u32>,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: Option<String>,
    data: Option<String>,
    folders: Vec<BwFolder>,
    items: Vec<BwItem>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwFolder {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct BwItem {
    #[serde(rename = "type")]
    kind: u32,
    name: Option<String>,
    notes: Option<String>,
    favorite: bool,
    folder_id: Option<String>,
    fields: Option<Vec<BwField>>,
    login: Option<BwLogin>,
    card: Option<Map<String, Value>>,
    identity: Option<Map<String, Value>>,
    ssh_key: Option<Map<String, Value>>,
    password_history: Option<Vec<BwHistory>>,
    deleted_date: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type")]
    kind: u32,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
    fido2_credentials: Option<Vec<Value>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwUri {
    uri: Option<String>,
    #[serde(rename = "match")]
    match_mode: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct BwHistory {
    password: Option<String>,
    last_used_date: Option<DateTime<Utc>>,
}

fn uri_match(n: Option<u32>) -> Option<UriMatch> {
    match n? {
        0 => Some(UriMatch::Domain),
        1 => Some(UriMatch::Host),
        2 => Some(UriMatch::StartsWith),
        3 => Some(UriMatch::Exact),
        4 => Some(UriMatch::Regex),
        5 => Some(UriMatch::Never),
        _ => None,
    }
}

fn match_number(m: Option<UriMatch>) -> Value {
    match m {
        None => Value::Null,
        Some(UriMatch::Domain) => 0.into(),
        Some(UriMatch::Host) => 1.into(),
        Some(UriMatch::StartsWith) => 2.into(),
        Some(UriMatch::Exact) => 3.into(),
        Some(UriMatch::Regex) => 4.into(),
        Some(UriMatch::Never) => 5.into(),
    }
}

pub fn bitwarden_json(text: &str, password: Option<&str>) -> Result<Imported> {
    let bad = |e: serde_json::Error| Error::Import(format!("this isn't a Bitwarden JSON export ({e})"));
    // Account-restricted exports have encrypted strings where items' fields
    // go: recognise them before reading the items.
    let raw: Value = serde_json::from_str(text).map_err(bad)?;
    if raw["encrypted"] == Value::Bool(true) && raw["passwordProtected"] != Value::Bool(true) {
        return Err(Error::Import(
            "this export is encrypted with your Bitwarden account key, which only Bitwarden can open. Export again choosing \"Password protected\" (or an unencrypted .json)".into(),
        ));
    }
    let export: BwExport = serde_json::from_value(raw).map_err(bad)?;
    if export.encrypted {
        let password = password.ok_or_else(|| Error::Import("this export is password-protected: enter its password".into()))?;
        let plain = decrypt_bitwarden_export(&export, password)?;
        let inner: BwExport = serde_json::from_str(&plain).map_err(bad)?;
        return Ok(convert(inner));
    }
    Ok(convert(export))
}

fn convert(export: BwExport) -> Imported {
    let folders: HashMap<String, String> = export.folders.into_iter().filter_map(|f| Some((f.id?, f.name.unwrap_or_default()))).collect();
    let mut out = Imported::default();
    let mut unusable = 0;
    for bw in export.items {
        if bw.deleted_date.is_some() {
            continue;
        }
        let mut d = ItemData {
            name: bw.name.unwrap_or_default(),
            notes: bw.notes.unwrap_or_default(),
            favorite: bw.favorite,
            folder: bw.folder_id.and_then(|id| folders.get(&id).cloned()).unwrap_or_default(),
            ..Default::default()
        };
        for f in bw.fields.unwrap_or_default() {
            // 3 = "linked" fields: they point at other fields, no value.
            if f.kind == 3 {
                continue;
            }
            d.fields.push(Field { name: f.name.unwrap_or_default(), value: f.value.unwrap_or_default(), hidden: f.kind == 1 });
        }
        let mut passkeys = Vec::new();
        match bw.kind {
            1 => {
                let l = bw.login.unwrap_or_default();
                d.kind = ItemKind::Login;
                d.username = l.username.unwrap_or_default();
                d.password = l.password.unwrap_or_default();
                d.totp = l.totp.unwrap_or_default();
                d.uris = l.uris.unwrap_or_default().into_iter().filter_map(|u| Some(ItemUri { uri: u.uri.filter(|s| !s.trim().is_empty())?, match_mode: uri_match(u.match_mode) })).collect();
                for c in l.fido2_credentials.unwrap_or_default() {
                    match passkey::from_bitwarden(&c) {
                        Some(p) => passkeys.push(p),
                        None => unusable += 1,
                    }
                }
            }
            3..=5 => {
                d.kind = ItemKind::Note;
                let (details, hidden): (Option<Map<String, Value>>, &[&str]) = match bw.kind {
                    3 => (bw.card, &["number", "code"]),
                    4 => (bw.identity, &["ssn", "passportNumber", "licenseNumber"]),
                    _ => (bw.ssh_key, &["privateKey"]),
                };
                for (k, v) in details.unwrap_or_default() {
                    let value = match v {
                        Value::String(s) if !s.is_empty() => s,
                        Value::Number(n) => n.to_string(),
                        _ => continue,
                    };
                    d.fields.push(Field { name: label(&k), value, hidden: hidden.contains(&k.as_str()) });
                }
            }
            _ => d.kind = ItemKind::Note,
        }
        // A Wi-Fi network, as CleanPassword exports one (Bitwarden has no
        // such type): a note with its password in a hidden field.
        if d.kind == ItemKind::Note {
            if let Some(n) = d.fields.iter().position(|f| f.hidden && f.name == WIFI_PASSWORD_FIELD) {
                d.kind = ItemKind::Wifi;
                d.password = d.fields.remove(n).value;
            }
        }
        let history = bw
            .password_history
            .unwrap_or_default()
            .into_iter()
            .filter_map(|h| Some(HistoryEntry { password: h.password.filter(|p| !p.is_empty())?, retired: h.last_used_date.unwrap_or_else(Utc::now) }))
            .collect();
        out.items.push(ImportedItem { data: d, history, passkeys });
    }
    if unusable > 0 {
        out.warnings.push(format!("{unusable} passkey(s) weren't imported: they use a kind of key CleanPassword doesn't support yet (only P-256). Keep using them in Bitwarden, or add a new passkey on those sites."));
    }
    out
}

/// `cardholderName` → `Cardholder name`.
fn label(key: &str) -> String {
    let mut out = String::new();
    for (i, c) in key.chars().enumerate() {
        if i == 0 {
            out.extend(c.to_uppercase());
        } else if c.is_uppercase() {
            out.push(' ');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The plaintext JSON of a password-protected Bitwarden export.
fn decrypt_bitwarden_export(e: &BwExport, password: &str) -> Result<String> {
    let damaged = || Error::Import("the export file is damaged".into());
    let salt = e.salt.as_deref().ok_or_else(damaged)?;
    let iterations = e.kdf_iterations.ok_or_else(damaged)?;
    let mut key = Zeroizing::new([0u8; 32]);
    match e.kdf_type.unwrap_or(0) {
        0 => {
            if !(1..=10_000_000).contains(&iterations) {
                return Err(damaged());
            }
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt.as_bytes(), iterations, key.as_mut());
        }
        1 => {
            use sha2::Digest;
            let memory_mib = e.kdf_memory.ok_or_else(damaged)?;
            let lanes = e.kdf_parallelism.ok_or_else(damaged)?;
            if !(1..=1024).contains(&memory_mib) || !(1..=32).contains(&iterations) || !(1..=16).contains(&lanes) {
                return Err(damaged());
            }
            let salt_hash = sha2::Sha256::digest(salt.as_bytes());
            let params = argon2::Params::new(memory_mib * 1024, iterations, lanes, Some(32)).map_err(|_| damaged())?;
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt_hash, key.as_mut())
                .map_err(|_| damaged())?;
        }
        _ => return Err(Error::Import("this export uses a key derivation this version doesn't know".into())),
    }
    let (enc, mac) = stretch(&key);
    let validation = e.enc_key_validation.as_deref().ok_or_else(damaged)?;
    if decrypt_enc_string(validation, &enc, &mac).is_none() {
        return Err(Error::WrongPassword);
    }
    let data = decrypt_enc_string(e.data.as_deref().ok_or_else(damaged)?, &enc, &mac).ok_or_else(damaged)?;
    String::from_utf8(data.to_vec()).map_err(|_| damaged())
}

/// Bitwarden's key stretching: HKDF-Expand (SHA-256) to an encryption and
/// a MAC key.
fn stretch(key: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(key).expect("32 bytes is a valid PRK");
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    hk.expand(b"enc", enc.as_mut()).expect("32 bytes");
    hk.expand(b"mac", mac.as_mut()).expect("32 bytes");
    (enc, mac)
}

/// Opens a Bitwarden "EncString" of type 2: `2.<iv>|<ciphertext>|<mac>`
/// (base64), AES-256-CBC with an HMAC-SHA256 over iv ‖ ciphertext.
fn decrypt_enc_string(s: &str, enc: &[u8; 32], mac_key: &[u8; 32]) -> Option<Zeroizing<Vec<u8>>> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use hmac::Mac;
    let rest = s.trim().strip_prefix("2.")?;
    let mut parts = rest.split('|');
    let (iv, ct, mac) = (crate::crypto::unb64(parts.next()?).ok()?, crate::crypto::unb64(parts.next()?).ok()?, crate::crypto::unb64(parts.next()?).ok()?);
    if iv.len() != 16 {
        return None;
    }
    let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(mac_key).ok()?;
    m.update(&iv);
    m.update(&ct);
    m.verify_slice(&mac).ok()?;
    let plain = cbc::Decryptor::<aes::Aes256>::new(enc.into(), iv.as_slice().into()).decrypt_padded_vec_mut::<Pkcs7>(&ct).ok()?;
    Some(Zeroizing::new(plain))
}

// ---- CSV ------------------------------------------------------------------

/// Column names other password managers use, by what they hold.
const COLUMNS: &[(&str, &[&str])] = &[
    ("name", &["name", "title"]),
    ("url", &["login_uri", "url", "uri", "website", "web site", "login url", "urls"]),
    ("username", &["login_username", "username", "user name", "login", "user", "email"]),
    ("password", &["login_password", "password"]),
    ("totp", &["login_totp", "totp", "otpauth", "otp", "one-time password"]),
    ("notes", &["notes", "note", "extra", "comments", "comment"]),
    ("folder", &["folder", "grouping", "group", "category", "vault"]),
    ("favorite", &["favorite", "fav", "favourite"]),
    ("type", &["type"]),
    ("fields", &["fields"]),
];

pub fn csv(text: &str) -> Result<Imported> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let headers: Vec<String> = reader.headers().map_err(|e| Error::Import(format!("couldn't read the CSV file ({e})")))?.iter().map(|h| h.trim().to_lowercase()).collect();
    let mut col: HashMap<&str, usize> = HashMap::new();
    for (what, names) in COLUMNS {
        if let Some(i) = names.iter().find_map(|n| headers.iter().position(|h| h == n)) {
            col.insert(what, i);
        }
    }
    if !col.contains_key("password") && !col.contains_key("notes") {
        return Err(Error::Import("this CSV file has no password column: export it from your password manager as CSV".into()));
    }
    let bitwarden = headers.iter().any(|h| h == "login_uri");
    let mut out = Imported::default();
    for (n, record) in reader.records().enumerate() {
        let record = record.map_err(|e| Error::Import(format!("line {} of the CSV file is damaged ({e})", n + 2)))?;
        let get = |what: &str| col.get(what).and_then(|i| record.get(*i)).unwrap_or("").to_owned();
        let url = get("url");
        // LastPass writes its secure notes with the address `http://sn`.
        let lastpass_note = url.trim().eq_ignore_ascii_case("http://sn");
        let uris: Vec<ItemUri> = if bitwarden {
            url.split(',').map(str::trim).filter(|u| !u.is_empty()).map(ItemUri::new).collect()
        } else if url.trim().is_empty() || lastpass_note {
            vec![]
        } else {
            vec![ItemUri::new(url.trim())]
        };
        let kind = if get("type").eq_ignore_ascii_case("note") || lastpass_note { ItemKind::Note } else { ItemKind::Login };
        let mut fields = Vec::new();
        for line in get("fields").lines() {
            if let Some((k, v)) = line.split_once(": ") {
                fields.push(Field { name: k.to_owned(), value: v.to_owned(), hidden: false });
            }
        }
        let fav = get("favorite");
        let d = ItemData {
            kind,
            name: get("name"),
            username: get("username"),
            password: get("password"),
            uris,
            totp: get("totp"),
            notes: get("notes"),
            folder: get("folder").replace('\\', "/"),
            favorite: matches!(fav.trim().to_lowercase().as_str(), "1" | "true" | "yes"),
            fields,
        };
        if d.name.is_empty() && d.username.is_empty() && d.password.is_empty() && d.uris.is_empty() && d.notes.is_empty() {
            continue;
        }
        out.items.push(ImportedItem { data: d, history: vec![], passkeys: vec![] });
    }
    Ok(out)
}

// ---- Export -----------------------------------------------------------------

/// The items as an unencrypted Bitwarden JSON export. It holds every
/// password in plain text: tell the user to delete it once imported.
pub fn export_bitwarden_json(items: &[&Item]) -> String {
    let mut folders: Vec<String> = items.iter().map(|i| i.folder.clone()).filter(|f| !f.is_empty()).collect();
    folders.sort();
    folders.dedup();
    let folder_ids: HashMap<&str, String> = folders.iter().map(|f| (f.as_str(), uuid::Uuid::new_v4().to_string())).collect();
    let items: Vec<Value> = items
        .iter()
        .map(|i| {
            let mut fields: Vec<Value> = i.fields.iter().map(|f| json!({"name": f.name, "value": f.value, "type": if f.hidden { 1 } else { 0 }, "linkedId": null})).collect();
            if i.kind == ItemKind::Wifi {
                fields.push(json!({"name": WIFI_PASSWORD_FIELD, "value": i.password, "type": 1, "linkedId": null}));
            }
            let history: Vec<Value> = i.history.iter().map(|h| json!({"lastUsedDate": h.retired, "password": h.password})).collect();
            let mut v = json!({
                "id": i.id,
                "organizationId": null,
                "folderId": folder_ids.get(i.folder.as_str()),
                "type": if i.kind == ItemKind::Login { 1 } else { 2 },
                "reprompt": 0,
                "name": i.name,
                "notes": if i.notes.is_empty() { Value::Null } else { i.notes.clone().into() },
                "favorite": i.favorite,
                "fields": fields,
                "passwordHistory": if history.is_empty() { Value::Null } else { history.into() },
                "revisionDate": i.modified,
                "creationDate": i.created,
                "deletedDate": null,
                "collectionIds": null,
            });
            if i.kind == ItemKind::Login {
                let uris: Vec<Value> = i.uris.iter().map(|u| json!({"match": match_number(u.match_mode), "uri": u.uri})).collect();
                let passkeys: Vec<Value> = i.passkeys.iter().map(passkey::to_bitwarden).collect();
                v["login"] = json!({"uris": uris, "username": i.username, "password": i.password, "totp": if i.totp.is_empty() { Value::Null } else { i.totp.clone().into() }, "fido2Credentials": passkeys});
            } else {
                v["secureNote"] = json!({"type": 0});
            }
            v
        })
        .collect();
    let folders: Vec<Value> = folders.iter().map(|f| json!({"id": folder_ids[f.as_str()], "name": f})).collect();
    serde_json::to_string_pretty(&json!({"encrypted": false, "folders": folders, "items": items})).expect("export serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BW_JSON: &str = r#"{
      "encrypted": false,
      "folders": [{"id": "f1", "name": "Work"}],
      "items": [
        {"id": "a", "type": 1, "name": "GitHub", "notes": null, "favorite": true, "folderId": "f1",
         "fields": [{"name": "PIN", "value": "1234", "type": 1}, {"name": "linked", "value": null, "type": 3, "linkedId": 100}],
         "login": {"uris": [{"match": null, "uri": "https://github.com"}, {"match": 1, "uri": "https://gist.github.com"}],
                   "username": "octo", "password": "pw", "totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
                   "fido2Credentials": [{"credentialId": "x"}]},
         "passwordHistory": [{"lastUsedDate": "2024-01-01T00:00:00.000Z", "password": "older"}]},
        {"id": "b", "type": 2, "name": "Wifi", "notes": "the code is 1234", "secureNote": {"type": 0}},
        {"id": "c", "type": 3, "name": "Visa", "card": {"cardholderName": "A B", "number": "4111111111111111", "code": "123", "expMonth": "1"}},
        {"id": "d", "type": 1, "name": "Gone", "login": {}, "deletedDate": "2024-01-01T00:00:00.000Z"}
      ]
    }"#;

    #[test]
    fn bitwarden_plain_json() {
        let r = import_file(BW_JSON, None).unwrap();
        assert_eq!(r.items.len(), 3, "deleted items are skipped");
        let gh = &r.items[0];
        assert_eq!(gh.data.username, "octo");
        assert_eq!(gh.data.folder, "Work");
        assert!(gh.data.favorite);
        assert_eq!(gh.data.uris[1].match_mode, Some(UriMatch::Host));
        assert_eq!(gh.data.fields, vec![Field { name: "PIN".into(), value: "1234".into(), hidden: true }]);
        assert_eq!(gh.history[0].password, "older");
        assert_eq!(r.items[1].data.kind, ItemKind::Note);
        let card = &r.items[2].data;
        assert!(card.fields.iter().any(|f| f.name == "Cardholder name" && !f.hidden));
        assert!(card.fields.iter().any(|f| f.name == "Number" && f.hidden));
        assert_eq!(r.warnings.len(), 1, "passkey warning");
    }

    /// Makes a password-protected export the way Bitwarden does.
    fn encrypt_like_bitwarden(plain: &str, password: &str, kdf: u32) -> String {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        use hmac::Mac;
        let salt = "c2FsdHNhbHRzYWx0c2FsdA==";
        let mut key = [0u8; 32];
        let (iterations, extra) = if kdf == 0 {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt.as_bytes(), 1000, &mut key);
            (1000, json!({}))
        } else {
            use sha2::Digest;
            let params = argon2::Params::new(1024, 2, 1, Some(32)).unwrap();
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params).hash_password_into(password.as_bytes(), &sha2::Sha256::digest(salt.as_bytes()), &mut key).unwrap();
            (2, json!({"kdfMemory": 1, "kdfParallelism": 1}))
        };
        let (enc, mac) = stretch(&key);
        let seal = |p: &str| {
            let iv = [7u8; 16];
            let ct = cbc::Encryptor::<aes::Aes256>::new(enc.as_ref().into(), (&iv).into()).encrypt_padded_vec_mut::<Pkcs7>(p.as_bytes());
            let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(mac.as_ref()).unwrap();
            m.update(&iv);
            m.update(&ct);
            let tag = m.finalize().into_bytes();
            format!("2.{}|{}|{}", crate::crypto::b64(&iv), crate::crypto::b64(&ct), crate::crypto::b64(&tag))
        };
        let mut v = json!({
            "encrypted": true, "passwordProtected": true, "salt": salt, "kdfType": kdf, "kdfIterations": iterations,
            "encKeyValidation_DO_NOT_EDIT": seal("4f1a8d4e-validation"), "data": seal(plain)
        });
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        v.to_string()
    }

    #[test]
    fn bitwarden_password_protected_json() {
        for kdf in [0, 1] {
            let file = encrypt_like_bitwarden(BW_JSON, "export pw", kdf);
            assert!(needs_password(&file));
            assert!(matches!(import_file(&file, None), Err(Error::Import(_))));
            assert!(matches!(import_file(&file, Some("wrong")), Err(Error::WrongPassword)));
            assert_eq!(import_file(&file, Some("export pw")).unwrap().items.len(), 3);
        }
        let mut tampered: Value = serde_json::from_str(&encrypt_like_bitwarden(BW_JSON, "pw", 0)).unwrap();
        let data = tampered["data"].as_str().unwrap().to_owned();
        tampered["data"] = data.replacen('|', "|AAAA", 1).into();
        assert!(import_file(&tampered.to_string(), Some("pw")).is_err());
    }

    #[test]
    fn account_restricted_exports_explain_themselves() {
        let e = import_file(r#"{"encrypted": true, "passwordProtected": false, "items": "2.x|y|z"}"#, None);
        assert!(matches!(e, Err(Error::Import(m)) if m.contains("Password protected")));
    }

    #[test]
    fn bitwarden_csv() {
        let text = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                    Work,1,login,GitHub,,\"PIN: 1234\",0,\"https://github.com,https://gist.github.com\",octo,pw,\n\
                    ,,note,Wifi,\"line1\nline2\",,0,,,,\n";
        let r = import_file(text, None).unwrap();
        assert_eq!(r.items.len(), 2);
        let gh = &r.items[0].data;
        assert_eq!((gh.name.as_str(), gh.folder.as_str(), gh.favorite), ("GitHub", "Work", true));
        assert_eq!(gh.uris.len(), 2);
        assert_eq!(gh.fields[0].name, "PIN");
        assert_eq!(r.items[1].data.kind, ItemKind::Note);
        assert_eq!(r.items[1].data.notes, "line1\nline2");
    }

    #[test]
    fn other_csvs() {
        let chrome = "name,url,username,password,note\nexample.com,https://example.com/login,me,pw,hi\n";
        let r = import_file(chrome, None).unwrap();
        assert_eq!(r.items[0].data.uris[0].uri, "https://example.com/login");
        assert_eq!(r.items[0].data.notes, "hi");
        let apple = "\u{feff}Title,URL,Username,Password,Notes,OTPAuth\nSite,https://s.com,u,p,,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n";
        let r = import_file(apple, None).unwrap();
        assert!(r.items[0].data.totp.starts_with("otpauth://"));
        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\"\n\"https://f.com\",\"u\",\"p\",,\"\",\"{x}\"\n";
        assert_eq!(import_file(firefox, None).unwrap().items[0].data.password, "p");
        assert!(import_file("a,b\n1,2\n", None).is_err());
    }

    #[test]
    fn lastpass_secure_notes_are_notes() {
        let lastpass = "url,username,password,totp,extra,name,grouping,fav\n\
                        https://l.com,u,p,,,Site,Work,1\n\
                        http://sn,,,,\"NoteType:Wifi\nSSID:home\",Router,,0\n";
        let r = import_file(lastpass, None).unwrap();
        assert_eq!((r.items[0].data.kind, r.items[0].data.uris.len(), r.items[0].data.favorite), (ItemKind::Login, 1, true));
        let note = &r.items[1].data;
        assert_eq!((note.kind, note.name.as_str()), (ItemKind::Note, "Router"));
        assert!(note.uris.is_empty());
        assert!(note.notes.contains("SSID:home"));
    }

    #[test]
    fn export_round_trips_through_import() {
        let r = import_file(BW_JSON, None).unwrap();
        let now = Utc::now();
        let items: Vec<Item> = r.items.into_iter().map(|i| Item::new(i.data, now)).collect();
        let refs: Vec<&Item> = items.iter().collect();
        let exported = export_bitwarden_json(&refs);
        let back = import_file(&exported, None).unwrap();
        assert_eq!(back.items.len(), 3);
        for (a, b) in items.iter().zip(&back.items) {
            assert_eq!(a.data(), b.data);
        }
    }

    /// Bitwarden has no Wi-Fi type: a network goes out as a note with its
    /// password in a hidden field, and comes back as a network.
    #[test]
    fn wifi_round_trips_through_export() {
        let data = ItemData {
            kind: ItemKind::Wifi,
            name: "Home".into(),
            password: "correct horse".into(),
            notes: "router in the hall".into(),
            fields: vec![Field { name: "Band".into(), value: "5 GHz".into(), hidden: false }],
            ..Default::default()
        };
        let item = Item::new(data.clone(), Utc::now());
        let exported = export_bitwarden_json(&[&item]);
        assert!(exported.contains("\"type\": 2") || exported.contains("\"type\":2"), "a secure note in Bitwarden's terms");
        let back = import_file(&exported, None).unwrap();
        assert_eq!(back.items[0].data, data);
    }
}
