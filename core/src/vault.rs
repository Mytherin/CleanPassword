//! The vault: its items, its keys, and what each device keeps.
//!
//! **In the S3 folder** (see [`crate::sync`]):
//!
//! ```text
//! <folder>/vault.json         the vault's id, Argon2id settings and salt, and
//!                             the vault key wrapped by the master key
//! <folder>/items/<id>.bin     one item, sealed with the vault key
//! ```
//!
//! S3 (and anyone who can read the bucket) sees only the number of items,
//! their padded sizes and when they changed: never names, websites, user
//! names or passwords.
//!
//! **On each device** the app keeps one string ([`Vault::save`]): the S3
//! settings (bucket, region, folder), the vault's header, and everything
//! else sealed with the vault key: the AWS access key, the items, and sync
//! state. So nothing readable is stored on the device either; the access
//! key is only usable once the vault is unlocked.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, Key, KdfParams};
use crate::item::{Item, ItemData, ItemKind};
use crate::matching::{self, Quality};
use crate::{Error, Result};

/// The shortest master password allowed (as in Bitwarden).
pub const MIN_MASTER_PASSWORD: usize = 12;
/// Items stay in the trash this long.
pub const TRASH_DAYS: i64 = 30;

const VAULT_FORMAT: &str = "cleanpassword-vault";
const DEVICE_FORMAT: &str = "cleanpassword-device";

/// Where the vault lives.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    /// The folder in the bucket (e.g. `CleanPassword`); empty for the top.
    #[serde(default)]
    pub prefix: String,
    /// An S3-compatible service's address (Cloudflare R2, MinIO, …), used
    /// with path-style URLs. `None` for Amazon S3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

pub const DEFAULT_PREFIX: &str = "CleanPassword";

impl S3Config {
    pub fn check(&self) -> Result<()> {
        let b = self.bucket.trim();
        if b.is_empty() || b.contains('/') || b.contains(' ') {
            return Err(Error::invalid("enter the bucket's name (without s3:// or slashes)"));
        }
        let r = self.region.trim();
        if r.is_empty() || !r.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::invalid("enter the bucket's region, such as us-east-1"));
        }
        if let Some(e) = self.endpoint.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
            let u = url::Url::parse(e).map_err(|_| Error::invalid("the endpoint must be a URL such as https://…"))?;
            let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            if u.scheme() != "https" && !(u.scheme() == "http" && local) {
                return Err(Error::invalid("the endpoint must use https"));
            }
        }
        Ok(())
    }
}

/// An IAM access key. Wiped from memory when dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// For temporary credentials (STS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredentials").field("access_key_id", &self.access_key_id).field("secret_access_key", &"…").finish()
    }
}

impl AwsCredentials {
    pub fn check(&self) -> Result<()> {
        if self.access_key_id.trim().is_empty() || self.secret_access_key.trim().is_empty() {
            return Err(Error::invalid("enter the access key ID and secret access key"));
        }
        Ok(())
    }
}

/// `vault.json`: everything needed to unlock the vault with the master
/// password. Not secret on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    pub format: String,
    pub version: u32,
    pub vault_id: String,
    pub kdf: KdfParams,
    /// The vault key sealed with the master key (base64).
    pub wrapped_key: String,
    pub created: DateTime<Utc>,
}

impl VaultHeader {
    fn new(vault_id: String, password: &str, key: &[u8; 32], created: DateTime<Utc>) -> Result<VaultHeader> {
        let kdf = KdfParams::new();
        let master = crypto::derive_key(password, &kdf)?;
        let mut h = VaultHeader { format: VAULT_FORMAT.into(), version: 1, vault_id, kdf, wrapped_key: String::new(), created };
        h.wrapped_key = crypto::b64(&crypto::seal(&master, &h.wrap_aad(), key));
        Ok(h)
    }

    fn wrap_aad(&self) -> Vec<u8> {
        format!("cleanpassword/vault-key/v1/{}", self.vault_id).into_bytes()
    }

    pub fn check(&self) -> Result<()> {
        if self.format != VAULT_FORMAT {
            return Err(Error::invalid("this folder's vault.json isn't a CleanPassword vault"));
        }
        if self.version != 1 {
            return Err(Error::invalid("this vault was made by a newer version of CleanPassword; update the app"));
        }
        Ok(())
    }

    /// The vault key, if `password` is the master password.
    pub fn unwrap_key(&self, password: &str) -> Result<Key> {
        self.check()?;
        let master = crypto::derive_key(password, &self.kdf)?;
        let wrapped = crypto::unb64(&self.wrapped_key)?;
        let key = crypto::open(&master, &self.wrap_aad(), &wrapped).ok_or(Error::WrongPassword)?;
        let arr: [u8; 32] = key.as_slice().try_into().map_err(|_| Error::invalid("the vault key is damaged"))?;
        Ok(Zeroizing::new(arr))
    }
}

/// An item and its sync state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ItemState {
    pub item: Item,
    /// The version last synced (what merges start from).
    #[serde(default)]
    pub base: Option<Item>,
    /// Its S3 ETag; `None` if it was never uploaded.
    #[serde(default)]
    pub etag: Option<String>,
    /// Changed here since the last sync.
    #[serde(default)]
    pub dirty: bool,
}

/// An item deleted for good, waiting for its tombstone to be uploaded, or a
/// tombstone seen in S3 (cleaned up after [`TRASH_DAYS`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Gone {
    pub etag: Option<String>,
    pub at: DateTime<Utc>,
}

/// Everything sealed on the device.
#[derive(Serialize, Deserialize)]
pub(crate) struct Secrets {
    pub credentials: AwsCredentials,
    #[serde(default)]
    pub items: BTreeMap<String, ItemState>,
    #[serde(default)]
    pub purges: BTreeMap<String, Gone>,
    #[serde(default)]
    pub tombstones: BTreeMap<String, Gone>,
    /// `vault.json`'s ETag; `None` until it's uploaded.
    #[serde(default)]
    pub header_etag: Option<String>,
    /// The master password was changed here and `vault.json` needs
    /// uploading.
    #[serde(default)]
    pub header_dirty: bool,
}

#[derive(Serialize, Deserialize)]
struct Saved {
    format: String,
    version: u32,
    config: S3Config,
    header: VaultHeader,
    /// [`Secrets`], sealed (base64).
    data: String,
    #[serde(default)]
    last_sync: Option<DateTime<Utc>>,
}

/// What can be shown about a saved vault while it's locked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedInfo {
    pub config: S3Config,
    pub vault_id: String,
    pub last_sync: Option<DateTime<Utc>>,
}

/// An item matching a web page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    pub id: String,
    pub name: String,
    pub username: String,
    pub quality: Quality,
}

/// A password worth changing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub name: String,
    pub weak: bool,
    /// How many other items use the same password.
    pub reused: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub added: usize,
    /// Already in the vault (same name, user name, password and website).
    pub skipped: usize,
}

/// An unlocked vault.
pub struct Vault {
    pub(crate) config: S3Config,
    pub(crate) header: VaultHeader,
    pub(crate) key: Key,
    pub(crate) s: Secrets,
    pub(crate) last_sync: Option<DateTime<Utc>>,
}

fn device_aad(vault_id: &str) -> Vec<u8> {
    format!("cleanpassword/device/v1/{vault_id}").into_bytes()
}

pub fn check_master_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_MASTER_PASSWORD {
        return Err(Error::invalid(format!("the master password needs at least {MIN_MASTER_PASSWORD} characters")));
    }
    Ok(())
}

impl Vault {
    /// A new, empty vault. The next sync uploads it (and fails if the S3
    /// folder already holds a vault: check with
    /// [`crate::sync::fetch_header`] first).
    pub fn create(config: S3Config, credentials: AwsCredentials, password: &str) -> Result<Vault> {
        config.check()?;
        credentials.check()?;
        check_master_password(password)?;
        let key = crypto::random_key();
        let header = VaultHeader::new(uuid::Uuid::new_v4().to_string(), password, &key, Utc::now())?;
        Ok(Vault { config, header, key, s: Secrets::new(credentials), last_sync: None })
    }

    /// Joins the vault already in an S3 folder (`header` and its ETag from
    /// [`crate::sync::fetch_header`]). Sync to download its items.
    pub fn join(config: S3Config, credentials: AwsCredentials, header: VaultHeader, header_etag: String, password: &str) -> Result<Vault> {
        config.check()?;
        credentials.check()?;
        let key = header.unwrap_key(password)?;
        let mut s = Secrets::new(credentials);
        s.header_etag = Some(header_etag);
        Ok(Vault { config, header, key, s, last_sync: None })
    }

    /// Opens what [`Vault::save`] made with the master password.
    pub fn unlock(saved: &str, password: &str) -> Result<Vault> {
        let saved = parse_saved(saved)?;
        let key = saved.header.unwrap_key(password)?;
        Self::open_saved(saved, key)
    }

    /// Opens what [`Vault::save`] made with the vault key itself (from
    /// [`Vault::key_b64`], kept in the iOS keychain behind Face ID, or in
    /// the browser's session storage while unlocked).
    pub fn unlock_with_key(saved: &str, key_b64: &str) -> Result<Vault> {
        let saved = parse_saved(saved)?;
        let key = crypto::key_from_b64(key_b64)?;
        Self::open_saved(saved, key)
    }

    fn open_saved(saved: Saved, key: Key) -> Result<Vault> {
        let header = saved.header;
        let sealed = crypto::unb64(&saved.data)?;
        let plain = crypto::open(&key, &device_aad(&header.vault_id), &sealed).ok_or(Error::WrongPassword)?;
        let s: Secrets = serde_json::from_slice(&plain).map_err(|e| Error::invalid(format!("the saved vault is damaged ({e})")))?;
        Ok(Vault { config: saved.config, header, key, s, last_sync: saved.last_sync })
    }

    /// What the device keeps: everything but the S3 settings sealed.
    pub fn save(&self) -> String {
        let plain = Zeroizing::new(serde_json::to_vec(&self.s).expect("secrets serialize"));
        let data = crypto::b64(&crypto::seal(&self.key, &device_aad(&self.header.vault_id), &plain));
        let saved = Saved {
            format: DEVICE_FORMAT.into(),
            version: 1,
            config: self.config.clone(),
            header: self.header.clone(),
            data,
            last_sync: self.last_sync,
        };
        serde_json::to_string(&saved).expect("saved vault serializes")
    }

    /// The vault key, base64, for unlocking without the master password
    /// ([`Vault::unlock_with_key`]). Keep it only somewhere protected.
    pub fn key_b64(&self) -> Zeroizing<String> {
        Zeroizing::new(crypto::b64(self.key.as_ref()))
    }

    pub fn vault_id(&self) -> &str {
        &self.header.vault_id
    }

    pub fn config(&self) -> &S3Config {
        &self.config
    }

    pub fn credentials(&self) -> &AwsCredentials {
        &self.s.credentials
    }

    /// New AWS keys (for example after rotating them).
    pub fn set_credentials(&mut self, credentials: AwsCredentials) -> Result<()> {
        credentials.check()?;
        self.s.credentials = credentials;
        Ok(())
    }

    pub fn last_sync(&self) -> Option<DateTime<Utc>> {
        self.last_sync
    }

    /// Whether anything here hasn't been uploaded yet.
    pub fn has_unsynced_changes(&self) -> bool {
        self.s.header_dirty || !self.s.purges.is_empty() || self.s.items.values().any(|s| s.dirty) || self.s.header_etag.is_none()
    }

    // ---- Items -----------------------------------------------------------

    /// Items not in the trash, by name.
    pub fn items(&self) -> Vec<&Item> {
        let mut v: Vec<&Item> = self.s.items.values().map(|s| &s.item).filter(|i| i.deleted.is_none()).collect();
        v.sort_by_cached_key(|i| (i.name.to_lowercase(), i.username.to_lowercase(), i.id.clone()));
        v
    }

    /// Items in the trash, most recently deleted first.
    pub fn trash(&self) -> Vec<&Item> {
        let mut v: Vec<&Item> = self.s.items.values().map(|s| &s.item).filter(|i| i.deleted.is_some()).collect();
        v.sort_by_key(|i| std::cmp::Reverse(i.deleted));
        v
    }

    pub fn get(&self, id: &str) -> Option<&Item> {
        self.s.items.get(id).map(|s| &s.item)
    }

    /// Folder names in use, sorted.
    pub fn folders(&self) -> Vec<String> {
        let mut f: Vec<String> = self.items().iter().map(|i| i.folder.clone()).filter(|f| !f.is_empty()).collect();
        f.sort_by_key(|s| s.to_lowercase());
        f.dedup();
        f
    }

    /// Adds an item; returns its id.
    pub fn add(&mut self, data: ItemData) -> Result<String> {
        if data.name.trim().is_empty() && data.uris.is_empty() && data.username.is_empty() {
            return Err(Error::invalid("give the item a name"));
        }
        let mut data = data;
        if data.name.trim().is_empty() {
            data.name = data.uris.first().and_then(|u| matching::parse_page(&u.uri)).map(|p| p.domain).unwrap_or_else(|| data.username.clone());
        }
        let item = Item::new(data, Utc::now());
        let id = item.id.clone();
        self.s.items.insert(id.clone(), ItemState { item, base: None, etag: None, dirty: true });
        Ok(id)
    }

    /// Changes an item; returns whether anything changed.
    pub fn update(&mut self, id: &str, data: ItemData) -> Result<bool> {
        let st = self.s.items.get_mut(id).ok_or(Error::NotFound)?;
        let changed = st.item.apply(data, Utc::now());
        st.dirty |= changed;
        Ok(changed)
    }

    /// Moves an item to the trash.
    pub fn delete(&mut self, id: &str) -> Result<()> {
        let st = self.s.items.get_mut(id).ok_or(Error::NotFound)?;
        if st.item.deleted.is_none() {
            let now = Utc::now();
            st.item.deleted = Some(now);
            st.item.modified = now;
            st.dirty = true;
        }
        Ok(())
    }

    pub fn restore(&mut self, id: &str) -> Result<()> {
        let st = self.s.items.get_mut(id).ok_or(Error::NotFound)?;
        if st.item.deleted.is_some() {
            st.item.deleted = None;
            st.item.modified = Utc::now();
            st.dirty = true;
        }
        Ok(())
    }

    /// Deletes an item for good (from every device, at the next sync).
    pub fn purge(&mut self, id: &str) -> Result<()> {
        let st = self.s.items.remove(id).ok_or(Error::NotFound)?;
        if st.etag.is_some() {
            self.s.purges.insert(id.to_owned(), Gone { etag: st.etag, at: Utc::now() });
        }
        Ok(())
    }

    /// Purges items that have been in the trash for [`TRASH_DAYS`].
    pub fn empty_old_trash(&mut self, now: DateTime<Utc>) {
        let old: Vec<String> = self
            .s
            .items
            .iter()
            .filter(|(_, s)| s.item.deleted.is_some_and(|d| now - d > Duration::days(TRASH_DAYS)) && !s.dirty)
            .map(|(id, _)| id.clone())
            .collect();
        for id in old {
            let _ = self.purge(&id);
        }
    }

    /// Items whose name, user name, websites, folder or notes contain every
    /// word of `query` (ignoring case).
    pub fn search(&self, query: &str) -> Vec<&Item> {
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        self.items()
            .into_iter()
            .filter(|i| {
                let hay = format!("{}\n{}\n{}\n{}\n{}", i.name, i.username, i.uris.iter().map(|u| u.uri.as_str()).collect::<Vec<_>>().join("\n"), i.folder, i.notes)
                    .to_lowercase();
                words.iter().all(|w| hay.contains(w))
            })
            .collect()
    }

    /// Logins for a web page, best first: those saved for this very host,
    /// then the rest of its domain, then sites sharing its sign-ins;
    /// favorites first within each.
    pub fn matches(&self, url: &str) -> Vec<Match> {
        let Some(page) = matching::parse_page(url) else { return Vec::new() };
        let mut out: Vec<(Quality, bool, &Item)> = Vec::new();
        for i in self.items() {
            if i.kind != ItemKind::Login {
                continue;
            }
            if let Some(q) = i.uris.iter().filter_map(|u| matching::match_uri(u, &page)).max() {
                out.push((q, i.favorite, i));
            }
        }
        out.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
        out.into_iter().map(|(q, _, i)| Match { id: i.id.clone(), name: i.name.clone(), username: i.username.clone(), quality: q }).collect()
    }

    /// Weak and reused passwords, worst first.
    pub fn audit(&self) -> Vec<AuditEntry> {
        let items: Vec<&Item> = self.items().into_iter().filter(|i| i.kind == ItemKind::Login && !i.password.is_empty()).collect();
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for i in &items {
            *counts.entry(i.password.as_str()).or_default() += 1;
        }
        let mut out: Vec<AuditEntry> = items
            .iter()
            .map(|i| AuditEntry {
                id: i.id.clone(),
                name: i.name.clone(),
                weak: crate::generator::strength(&i.password).score < 3,
                reused: counts[i.password.as_str()] - 1,
            })
            .filter(|e| e.weak || e.reused > 0)
            .collect();
        out.sort_by(|a, b| b.reused.cmp(&a.reused).then(b.weak.cmp(&a.weak)).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        out
    }

    /// Adds imported items (with their password history), skipping ones
    /// already here.
    pub fn import(&mut self, items: Vec<crate::import::ImportedItem>) -> ImportSummary {
        let fingerprint = |d: &ItemData| (d.name.trim().to_lowercase(), d.username.clone(), d.password.clone(), d.uris.first().map(|u| u.uri.clone()), d.notes.clone());
        let mut seen: std::collections::HashSet<_> = self.items().iter().map(|i| fingerprint(&i.data())).collect();
        let mut summary = ImportSummary::default();
        for imported in items {
            if !seen.insert(fingerprint(&imported.data)) {
                summary.skipped += 1;
                continue;
            }
            match self.add(imported.data) {
                Ok(id) => {
                    let st = self.s.items.get_mut(&id).expect("just added");
                    st.item.history = imported.history;
                    st.item.history.truncate(crate::item::HISTORY_LIMIT);
                    summary.added += 1;
                }
                Err(_) => summary.skipped += 1,
            }
        }
        summary
    }

    // ---- Master password -----------------------------------------------------

    /// Changes the master password (and makes a new salt). Other devices
    /// need the new one from their next sync on.
    pub fn change_master_password(&mut self, current: &str, new: &str) -> Result<()> {
        check_master_password(new)?;
        let key = self.header.unwrap_key(current)?;
        if *key != *self.key {
            return Err(Error::WrongPassword);
        }
        self.header = VaultHeader::new(self.header.vault_id.clone(), new, &self.key, self.header.created)?;
        self.s.header_dirty = true;
        Ok(())
    }
}

impl Secrets {
    fn new(credentials: AwsCredentials) -> Secrets {
        Secrets { credentials, items: BTreeMap::new(), purges: BTreeMap::new(), tombstones: BTreeMap::new(), header_etag: None, header_dirty: false }
    }
}

fn parse_saved(saved: &str) -> Result<Saved> {
    let s: Saved = serde_json::from_str(saved).map_err(|_| Error::invalid("the saved vault is damaged"))?;
    if s.format != DEVICE_FORMAT || s.version != 1 {
        return Err(Error::invalid("the saved vault was made by another version of CleanPassword"));
    }
    Ok(s)
}

/// The S3 settings of a saved vault, without unlocking it.
pub fn locked_info(saved: &str) -> Result<LockedInfo> {
    let s = parse_saved(saved)?;
    Ok(LockedInfo { config: s.config, vault_id: s.header.vault_id, last_sync: s.last_sync })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::item::ItemUri;

    pub fn config() -> S3Config {
        S3Config { bucket: "bucket".into(), region: "us-east-1".into(), prefix: "Vault".into(), endpoint: None }
    }

    pub fn creds() -> AwsCredentials {
        AwsCredentials { access_key_id: "AKIA".into(), secret_access_key: "secret".into(), session_token: None }
    }

    pub const PW: &str = "correct horse battery";

    pub fn login(name: &str, url: &str, user: &str, pw: &str) -> ItemData {
        ItemData { name: name.into(), username: user.into(), password: pw.into(), uris: vec![ItemUri::new(url)], ..Default::default() }
    }

    #[test]
    fn create_save_unlock() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        let id = v.add(login("Example", "https://example.com", "me", "hunter2-hunter2")).unwrap();
        let saved = v.save();
        assert!(!saved.contains("hunter2") && !saved.contains("Example") && !saved.contains("secret"), "nothing readable is saved");
        assert!(saved.contains("bucket"), "the S3 settings are");
        assert!(matches!(Vault::unlock(&saved, "wrong password!"), Err(Error::WrongPassword)));
        let v2 = Vault::unlock(&saved, PW).unwrap();
        assert_eq!(v2.get(&id).unwrap().password, "hunter2-hunter2");
        assert_eq!(v2.credentials().secret_access_key, "secret");
        let v3 = Vault::unlock_with_key(&saved, &v.key_b64()).unwrap();
        assert_eq!(v3.items().len(), 1);
        assert!(Vault::unlock_with_key(&saved, &crypto::b64(&[0u8; 32])).is_err());
        let info = locked_info(&saved).unwrap();
        assert_eq!(info.config.bucket, "bucket");
    }

    #[test]
    fn master_password_rules() {
        assert!(Vault::create(config(), creds(), "short").is_err());
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        assert!(matches!(v.change_master_password("not the password", "another long password"), Err(Error::WrongPassword)));
        v.change_master_password(PW, "another long password").unwrap();
        let saved = v.save();
        assert!(Vault::unlock(&saved, PW).is_err());
        assert!(Vault::unlock(&saved, "another long password").is_ok());
    }

    #[test]
    fn items_trash_and_search() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        let a = v.add(login("Bank", "https://bank.example", "alice", "pw-one-1234567")).unwrap();
        let b = v.add(login("", "https://www.mail.example.org/login", "bob", "pw")).unwrap();
        assert_eq!(v.get(&b).unwrap().name, "example.org", "named after the site");
        assert_eq!(v.items().iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["Bank", "example.org"]);
        assert_eq!(v.search("ALICE bank").len(), 1);
        assert_eq!(v.search("mail.example").len(), 1);
        v.delete(&a).unwrap();
        assert_eq!(v.items().len(), 1);
        assert_eq!(v.trash().len(), 1);
        v.restore(&a).unwrap();
        assert_eq!(v.items().len(), 2);
        v.purge(&a).unwrap();
        assert!(v.get(&a).is_none());
        assert!(v.update("nope", ItemData::default()).is_err());
        assert!(v.add(ItemData::default()).is_err());
    }

    #[test]
    fn matches_rank_host_first() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        v.add(login("Other", "https://other.com", "x", "p")).unwrap();
        let domain = v.add(login("Example", "https://example.com", "domain", "p")).unwrap();
        let host = v.add(login("Accounts", "https://accounts.example.com", "host", "p")).unwrap();
        let m = v.matches("https://accounts.example.com/signin");
        assert_eq!(m.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), [host.as_str(), domain.as_str()]);
        assert!(v.matches("http://accounts.example.com/").is_empty(), "never on http");
        assert!(v.matches("not a url").is_empty());
    }

    #[test]
    fn audit_finds_weak_and_reused() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        v.add(login("A", "https://a.com", "x", "password1")).unwrap();
        v.add(login("B", "https://b.com", "x", "Tq8#xk2!Lm9@vR4z")).unwrap();
        v.add(login("C", "https://c.com", "x", "Tq8#xk2!Lm9@vR4z")).unwrap();
        v.add(login("D", "https://d.com", "x", "Zp3$wq7&Hn5^cY1e")).unwrap();
        let a = v.audit();
        assert_eq!(a.len(), 3);
        assert_eq!(a[0].reused, 1);
        assert!(a.iter().any(|e| e.name == "A" && e.weak));
    }

    #[test]
    fn import_skips_duplicates() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        let wrap = |d: ItemData| crate::import::ImportedItem { data: d, history: vec![] };
        let items: Vec<_> = [login("A", "https://a.com", "x", "1"), login("A", "https://a.com", "x", "1"), login("B", "https://b.com", "x", "2")].into_iter().map(wrap).collect();
        assert_eq!(v.import(items.clone()), ImportSummary { added: 2, skipped: 1 });
        assert_eq!(v.import(items), ImportSummary { added: 0, skipped: 3 });
    }

    #[test]
    fn old_trash_is_purged() {
        let mut v = Vault::create(config(), creds(), PW).unwrap();
        let id = v.add(login("A", "https://a.com", "x", "1")).unwrap();
        v.delete(&id).unwrap();
        v.s.items.get_mut(&id).unwrap().dirty = false;
        v.empty_old_trash(Utc::now() + Duration::days(10));
        assert!(v.get(&id).is_some());
        v.empty_old_trash(Utc::now() + Duration::days(31));
        assert!(v.get(&id).is_none());
    }
}
