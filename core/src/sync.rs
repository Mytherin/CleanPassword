//! Syncing a vault with its S3 folder.
//!
//! The folder holds two objects: `vault.json` (the header: what unlocking
//! needs) and `vault.bin` (every item, sealed in one object; a vault of a
//! thousand passwords is a megabyte or two).
//!
//! - `vault.json` comes first: if it's another vault's, nothing happens
//!   ([`Error::DifferentVault`]); if another device changed the master
//!   password, this device adopts the new header (the vault key stays the
//!   same, so items stay readable) and the new password unlocks from then
//!   on.
//! - A `HEAD` of `vault.bin` tells whether another device saved since this
//!   one last synced. If so it's downloaded and merged with what changed
//!   here, item by item, starting from the copy this device last synced
//!   ([`merge_vault`]): an item changed on one side takes that side's
//!   version; changed on both, it's merged field by field
//!   ([`crate::item::merge`]), so no password is lost; deleted on one side
//!   and edited on the other, the edit wins.
//! - The result is uploaded with `If-Match` (`If-None-Match: *` for the
//!   first upload). If S3 refuses because another device saved meanwhile,
//!   the merge is done again on top of that.
//! - A `vault.bin` that can't be decrypted stops the sync (it's never
//!   overwritten); one that's missing is put back, never taken to mean
//!   every item was deleted.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto;
use crate::item::{merge, Item};
use crate::s3::{Client, Cond, Put, Transport};
use crate::vault::{AwsCredentials, S3Config, Vault, VaultHeader};
use crate::{Error, Result};

pub const HEADER_OBJECT: &str = "vault.json";
pub const VAULT_OBJECT: &str = "vault.bin";
/// The sealed vault starts with this, then `nonce ‖ ciphertext ‖ tag`.
const MAGIC: &[u8] = b"CPV2";
/// The vault's plaintext is padded to a multiple of this many bytes, or of
/// an eighth of its size rounded up to a power of two if that's more: S3
/// sees roughly how big the vault is, not how many items it holds.
const PAD: usize = 16 * 1024;
/// Uploads retried after merging with another device's save.
const RETRIES: usize = 4;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    /// Items added or changed here because they were elsewhere.
    pub downloaded: usize,
    /// Items changed here (or deleted here for good) that were uploaded.
    pub uploaded: usize,
    /// Deleted here because they were deleted elsewhere.
    pub removed: usize,
    /// Changed both here and elsewhere, and merged.
    pub merged: usize,
    /// Changes that couldn't be uploaded this time (tried again next sync).
    pub pending: usize,
    /// The master password was changed on another device.
    pub password_changed_elsewhere: bool,
}

/// What `vault.bin` holds.
#[derive(Serialize, Deserialize)]
struct Stored {
    items: Vec<Item>,
}

fn vault_aad(vault_id: &str) -> Vec<u8> {
    format!("cleanpassword/vault/v2/{vault_id}").into_bytes()
}

fn pad_block(len: usize) -> usize {
    PAD.max(len.next_power_of_two() / 8)
}

fn seal_vault(key: &[u8; 32], vault_id: &str, items: &BTreeMap<String, Item>) -> Vec<u8> {
    let stored = Stored { items: items.values().cloned().collect() };
    let json = Zeroizing::new(serde_json::to_vec(&stored).expect("items serialize"));
    let plain = Zeroizing::new(crypto::pad(json.to_vec(), pad_block(json.len())));
    let mut out = MAGIC.to_vec();
    out.extend(crypto::seal(key, &vault_aad(vault_id), &plain));
    out
}

fn open_vault(key: &[u8; 32], vault_id: &str, data: &[u8]) -> Result<BTreeMap<String, Item>> {
    let unreadable = || Error::invalid("the vault in S3 (vault.bin) can't be decrypted: it's damaged, or was written with another key");
    let plain = crypto::open(key, &vault_aad(vault_id), data.strip_prefix(MAGIC).ok_or_else(unreadable)?).ok_or_else(unreadable)?;
    let stored: Stored = serde_json::from_slice(&plain).map_err(|_| unreadable())?;
    Ok(stored.items.into_iter().map(|i| (i.id.clone(), i)).collect())
}

/// Three-way merge of the vault, item by item: `base` is what this device
/// last synced, `local` what it has now, `remote` what's in S3. Adds the ids
/// merged from both sides to `merged`.
fn merge_vault(
    base: &BTreeMap<String, Item>,
    local: &BTreeMap<String, Item>,
    remote: &BTreeMap<String, Item>,
    merged: &mut BTreeSet<String>,
) -> BTreeMap<String, Item> {
    let ids: BTreeSet<&String> = base.keys().chain(local.keys()).chain(remote.keys()).collect();
    let mut out = BTreeMap::new();
    for id in ids {
        let (b, l, r) = (base.get(id), local.get(id), remote.get(id));
        let pick = if l == r || r == b {
            // The same on both sides, or changed only here.
            l.cloned()
        } else if l == b {
            // Changed (or deleted) only there.
            r.cloned()
        } else {
            match (l, r) {
                (Some(l), Some(r)) => {
                    merged.insert(id.clone());
                    Some(merge(b, l, r))
                }
                // Deleted on one side, edited on the other: the edit wins.
                (l, r) => l.or(r).cloned(),
            }
        };
        if let Some(item) = pick {
            out.insert(id.clone(), item);
        }
    }
    out
}

/// How many items differ between two versions of the vault.
fn changed(a: &BTreeMap<String, Item>, b: &BTreeMap<String, Item>) -> usize {
    a.keys().chain(b.keys()).collect::<BTreeSet<_>>().into_iter().filter(|id| a.get(*id) != b.get(*id)).count()
}

/// `vault.json` and its ETag, if the folder holds a vault.
pub async fn fetch_header<T: Transport>(transport: &T, config: &S3Config, credentials: &AwsCredentials) -> Result<Option<(VaultHeader, String)>> {
    config.check()?;
    credentials.check()?;
    let (location, creds) = (config.location(), credentials.for_client());
    let client = Client::new(&location, &creds, transport);
    let Some(obj) = client.get(HEADER_OBJECT).await? else { return Ok(None) };
    let header: VaultHeader = serde_json::from_slice(&obj.data).map_err(|_| Error::invalid("this folder's vault.json is damaged"))?;
    header.check()?;
    Ok(Some((header, obj.etag)))
}

impl Vault {
    /// Syncs with the S3 folder. Safe to call any time; a failed sync
    /// leaves everything to be tried again next time.
    pub async fn sync<T: Transport>(&mut self, transport: &T) -> Result<SyncReport> {
        self.sync_with_progress(transport, &mut |_, _| {}).await
    }

    /// [`Vault::sync`], telling `progress(done, total)` how the download
    /// of another device's save is going (`(0, 1)` before, `(1, 1)` after;
    /// nothing if there's none to download).
    pub async fn sync_with_progress<T: Transport>(&mut self, transport: &T, progress: &mut dyn FnMut(usize, usize)) -> Result<SyncReport> {
        let location = self.config.location();
        let credentials = self.s.credentials.for_client();
        let client = Client::new(&location, &credentials, transport);
        let mut report = SyncReport::default();

        self.sync_header(&client, &mut report).await?;
        self.empty_old_trash(Utc::now());
        self.sync_items(&client, &mut report, progress).await?;

        self.last_sync = Some(Utc::now());
        Ok(report)
    }

    async fn sync_header<T: Transport>(&mut self, client: &Client<'_, T>, report: &mut SyncReport) -> Result<()> {
        let remote = client.get(HEADER_OBJECT).await?;
        match remote {
            None => {
                if self.s.header_etag.is_some() {
                    // The folder was emptied: put everything back.
                    self.s.etag = None;
                }
                let body = serde_json::to_vec_pretty(&self.header).expect("header serializes");
                match client.put(HEADER_OBJECT, body, Cond::Absent).await? {
                    Put::Stored { etag } => {
                        self.s.header_etag = Some(etag);
                        self.s.header_dirty = false;
                    }
                    // Another device made a vault here at the same moment.
                    Put::Conflict => return Err(Error::DifferentVault),
                }
            }
            Some(obj) => {
                let header: VaultHeader = serde_json::from_slice(&obj.data).map_err(|_| Error::invalid("this folder's vault.json is damaged"))?;
                header.check()?;
                if header.vault_id != self.header.vault_id {
                    return Err(Error::DifferentVault);
                }
                if self.s.header_etag.as_deref() != Some(obj.etag.as_str()) {
                    if header.wrapped_key != self.header.wrapped_key {
                        // A new master password, set on another device (it
                        // wins over one set here at the same time).
                        self.header = header;
                        self.s.header_dirty = false;
                        report.password_changed_elsewhere = true;
                    }
                    self.s.header_etag = Some(obj.etag.clone());
                }
                if self.s.header_dirty {
                    let body = serde_json::to_vec_pretty(&self.header).expect("header serializes");
                    if let Put::Stored { etag } = client.put(HEADER_OBJECT, body, Cond::Match(&obj.etag)).await? {
                        self.s.header_etag = Some(etag);
                        self.s.header_dirty = false;
                    }
                }
            }
        }
        Ok(())
    }

    async fn sync_items<T: Transport>(&mut self, client: &Client<'_, T>, report: &mut SyncReport, progress: &mut dyn FnMut(usize, usize)) -> Result<()> {
        let before = self.s.items.clone();
        let mut merged = BTreeSet::new();
        let mut done = false;
        for _ in 0..RETRIES {
            // What's in S3 now, and its ETag (`None`: there's no vault.bin).
            // Unchanged since the last sync, it's the synced copy.
            let (remote, etag) = match client.head(VAULT_OBJECT).await? {
                Some(e) if self.s.etag.as_ref() == Some(&e) => (self.s.base.clone(), Some(e)),
                Some(_) => {
                    progress(0, 1);
                    let obj = client.get(VAULT_OBJECT).await?;
                    progress(1, 1);
                    match obj {
                        Some(obj) => (open_vault(&self.key, &self.header.vault_id, &obj.data)?, Some(obj.etag)),
                        None => (self.s.base.clone(), None),
                    }
                }
                None => (self.s.base.clone(), None),
            };
            self.s.items = merge_vault(&self.s.base, &self.s.items, &remote, &mut merged);
            self.s.base = remote;
            self.s.etag = etag.clone();
            if etag.is_some() && self.s.items == self.s.base {
                done = true;
                break;
            }
            let body = seal_vault(&self.key, &self.header.vault_id, &self.s.items);
            let cond = etag.as_deref().map_or(Cond::Absent, Cond::Match);
            match client.put(VAULT_OBJECT, body, cond).await? {
                Put::Stored { etag } => {
                    report.uploaded += changed(&self.s.base, &self.s.items);
                    self.s.base = self.s.items.clone();
                    self.s.etag = Some(etag);
                    done = true;
                    break;
                }
                // Another device saved meanwhile: merge with that.
                Put::Conflict => {}
            }
        }
        if !done {
            report.pending = changed(&self.s.base, &self.s.items);
        }
        report.merged = merged.len();
        for id in before.keys().chain(self.s.items.keys()).collect::<BTreeSet<_>>() {
            match (before.get(id), self.s.items.get(id)) {
                (Some(_), None) => report.removed += 1,
                (b, Some(i)) if b != Some(i) && !merged.contains(id) => report.downloaded += 1,
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use pollster::block_on;

    use super::*;
    use crate::item::ItemData;
    use crate::s3::{HttpRequest, HttpResponse};
    use crate::vault::tests::{config, creds, login, PW};
    use cleanbucket::fake::FakeS3;

    fn join(s3: &FakeS3) -> Vault {
        let (h, etag) = block_on(fetch_header(s3, &config(), &creds())).unwrap().expect("a vault");
        let mut v = Vault::join(config(), creds(), h, etag, PW).unwrap();
        block_on(v.sync(s3)).unwrap();
        v
    }

    fn setup() -> (FakeS3, Vault, Vault) {
        let s3 = FakeS3::new();
        assert!(block_on(fetch_header(&s3, &config(), &creds())).unwrap().is_none());
        let mut a = Vault::create(config(), creds(), PW).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let b = join(&s3);
        (s3, a, b)
    }

    fn vault_bin(s3: &FakeS3) -> Vec<u8> {
        s3.objects.borrow()[&format!("Vault/{VAULT_OBJECT}")].0.clone()
    }

    #[test]
    fn two_devices_share_items() {
        let (s3, mut a, mut b) = setup();
        let id = a.add(login("Example", "https://example.com", "me", "pw1")).unwrap();
        a.add(login("Other", "https://other.com", "me", "pw2")).unwrap();
        a.add(login("Third", "https://third.com", "me", "pw3")).unwrap();
        let r = block_on(a.sync(&s3)).unwrap();
        assert_eq!(r.uploaded, 3);
        assert!(!a.has_unsynced_changes());
        let r = block_on(b.sync(&s3)).unwrap();
        assert_eq!(r.downloaded, 3);
        assert_eq!(b.get(&id).unwrap().password, "pw1");

        // Nothing changed: nothing downloaded or uploaded.
        s3.requests.borrow_mut().clear();
        assert_eq!(block_on(b.sync(&s3)).unwrap(), SyncReport::default());
        let requests = s3.requests.borrow().clone();
        assert!(requests.iter().all(|r| !r.starts_with("PUT") && *r != format!("GET Vault/{VAULT_OBJECT}")), "{requests:?}");

        // A device joining now hears of the download; then there's none.
        let mut c = {
            let (h, etag) = block_on(fetch_header(&s3, &config(), &creds())).unwrap().unwrap();
            Vault::join(config(), creds(), h, etag, PW).unwrap()
        };
        let mut seen = Vec::new();
        block_on(c.sync_with_progress(&s3, &mut |done, total| seen.push((done, total)))).unwrap();
        assert_eq!(seen, [(0, 1), (1, 1)]);
        assert_eq!(c.items().len(), 3);
        let mut seen = Vec::new();
        block_on(c.sync_with_progress(&s3, &mut |done, total| seen.push((done, total)))).unwrap();
        assert!(seen.is_empty(), "nothing to download: no progress");

        // Nothing readable in the bucket, and just the two objects.
        let objects = s3.objects.borrow();
        assert_eq!(objects.keys().collect::<Vec<_>>(), ["Vault/vault.bin", "Vault/vault.json"]);
        for (k, (data, _)) in objects.iter() {
            let text = String::from_utf8_lossy(data);
            assert!(!text.contains("Example") && !text.contains("pw1") && !text.contains("example.com"), "{k}");
        }
    }

    #[test]
    fn the_vault_is_padded() {
        let (s3, mut a, _) = setup();
        let overhead = MAGIC.len() + 24 + 16;
        assert_eq!(vault_bin(&s3).len() - overhead, PAD, "an empty vault");
        for i in 0..20 {
            a.add(login(&format!("Site {i}"), &format!("https://site{i}.com"), "me", "pw")).unwrap();
        }
        block_on(a.sync(&s3)).unwrap();
        assert_eq!(vault_bin(&s3).len() - overhead, PAD, "twenty items look the same");
        assert_eq!(pad_block(1 << 20), 128 * 1024, "a large vault grows in eighths");
    }

    #[test]
    fn concurrent_edits_merge() {
        let (s3, mut a, mut b) = setup();
        let id = a.add(login("Example", "https://example.com", "me", "pw1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();

        a.update(&id, ItemData { notes: "from a".into(), ..a.get(&id).unwrap().data() }).unwrap();
        b.update(&id, ItemData { username: "me@b".into(), ..b.get(&id).unwrap().data() }).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let r = block_on(b.sync(&s3)).unwrap();
        assert_eq!(r.merged, 1);
        assert_eq!(r.uploaded, 1);
        block_on(a.sync(&s3)).unwrap();
        for v in [&a, &b] {
            let i = v.get(&id).unwrap();
            assert_eq!((i.notes.as_str(), i.username.as_str()), ("from a", "me@b"));
        }
    }

    #[test]
    fn edits_to_different_items_both_arrive() {
        let (s3, mut a, mut b) = setup();
        let x = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        a.update(&x, ItemData { notes: "a".into(), ..a.get(&x).unwrap().data() }).unwrap();
        let y = b.add(login("Y", "https://y.com", "me", "2")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let r = block_on(b.sync(&s3)).unwrap();
        assert_eq!((r.downloaded, r.uploaded, r.merged), (1, 1, 0));
        block_on(a.sync(&s3)).unwrap();
        for v in [&a, &b] {
            assert_eq!(v.get(&x).unwrap().notes, "a");
            assert!(v.get(&y).is_some());
        }
    }

    #[test]
    fn conflicting_passwords_keep_both() {
        let (s3, mut a, mut b) = setup();
        let id = a.add(login("Example", "https://example.com", "me", "old")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        a.update(&id, ItemData { password: "from-a".into(), ..a.get(&id).unwrap().data() }).unwrap();
        block_on(a.sync(&s3)).unwrap();
        b.update(&id, ItemData { password: "from-b".into(), ..b.get(&id).unwrap().data() }).unwrap();
        block_on(b.sync(&s3)).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let (ia, ib) = (a.get(&id).unwrap(), b.get(&id).unwrap());
        assert_eq!(ia.password, ib.password);
        let all: Vec<&str> = std::iter::once(ia.password.as_str()).chain(ia.history.iter().map(|h| h.password.as_str())).collect();
        for p in ["old", "from-a", "from-b"] {
            assert!(all.contains(&p), "{p} kept: {all:?}");
        }
    }

    #[test]
    fn deletes_reach_other_devices_but_lose_to_edits() {
        let (s3, mut a, mut b) = setup();
        let x = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        let y = a.add(login("Y", "https://y.com", "me", "2")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();

        // Trash syncs as an edit.
        a.delete(&x).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        assert!(b.get(&x).unwrap().deleted.is_some());

        // Deleted for good: gone on b too.
        a.purge(&x).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let r = block_on(b.sync(&s3)).unwrap();
        assert_eq!(r.removed, 1);
        assert!(b.get(&x).is_none());

        // b edits y while a purges it: the edit wins.
        a.purge(&y).unwrap();
        b.update(&y, ItemData { notes: "keep me".into(), ..b.get(&y).unwrap().data() }).unwrap();
        block_on(b.sync(&s3)).unwrap();
        block_on(a.sync(&s3)).unwrap();
        assert_eq!(a.get(&y).unwrap().notes, "keep me");
    }

    #[test]
    fn edit_beats_a_purge_already_uploaded() {
        let (s3, mut a, mut b) = setup();
        let y = a.add(login("Y", "https://y.com", "me", "2")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        a.purge(&y).unwrap();
        block_on(a.sync(&s3)).unwrap();
        b.update(&y, ItemData { notes: "edited offline".into(), ..b.get(&y).unwrap().data() }).unwrap();
        block_on(b.sync(&s3)).unwrap();
        assert_eq!(b.get(&y).unwrap().notes, "edited offline");
        block_on(a.sync(&s3)).unwrap();
        assert_eq!(a.get(&y).unwrap().notes, "edited offline");
    }

    /// A transport that lets another device sync just before this one's
    /// first upload of `vault.bin`, as if both saved at the same moment.
    struct Racing<'a> {
        s3: &'a FakeS3,
        other: RefCell<Option<Vault>>,
    }

    impl Transport for Racing<'_> {
        async fn send(&self, req: HttpRequest) -> std::result::Result<HttpResponse, String> {
            if req.method == "PUT" && req.url.ends_with(VAULT_OBJECT) {
                let other = self.other.borrow_mut().take();
                if let Some(mut other) = other {
                    block_on(other.sync(self.s3)).unwrap();
                }
            }
            self.s3.send(req).await
        }
    }

    #[test]
    fn a_save_refused_as_outdated_is_merged_and_retried() {
        let (s3, mut a, mut b) = setup();
        let x = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        a.update(&x, ItemData { notes: "from a".into(), ..a.get(&x).unwrap().data() }).unwrap();
        let y = b.add(login("Y", "https://y.com", "me", "2")).unwrap();
        let racing = Racing { s3: &s3, other: RefCell::new(Some(b)) };
        let r = block_on(a.sync(&racing)).unwrap();
        assert_eq!((r.uploaded, r.downloaded, r.pending), (1, 1, 0));
        assert!(a.get(&y).is_some());
        let c = join(&s3);
        assert_eq!(c.get(&x).unwrap().notes, "from a");
        assert!(c.get(&y).is_some());
    }

    #[test]
    fn password_change_reaches_other_devices() {
        let (s3, mut a, mut b) = setup();
        a.add(login("X", "https://x.com", "me", "1")).unwrap();
        a.change_master_password(PW, "a brand new master pw").unwrap();
        block_on(a.sync(&s3)).unwrap();
        let r = block_on(b.sync(&s3)).unwrap();
        assert!(r.password_changed_elsewhere);
        assert_eq!(b.items().len(), 1, "items still readable");
        let saved = b.save();
        assert!(Vault::unlock(&saved, PW).is_err());
        assert!(Vault::unlock(&saved, "a brand new master pw").is_ok());
        // A new device joins with the new password.
        let (h, etag) = block_on(fetch_header(&s3, &config(), &creds())).unwrap().unwrap();
        assert!(Vault::join(config(), creds(), h.clone(), etag.clone(), PW).is_err());
        assert!(Vault::join(config(), creds(), h, etag, "a brand new master pw").is_ok());
    }

    #[test]
    fn another_vault_in_the_folder_is_refused() {
        let (s3, mut a, _) = setup();
        let mut other = Vault::create(config(), creds(), PW).unwrap();
        assert!(matches!(block_on(other.sync(&s3)), Err(Error::DifferentVault)));
        assert!(block_on(a.sync(&s3)).is_ok());
    }

    #[test]
    fn a_vault_from_an_older_version_is_refused() {
        let s3 = FakeS3::new();
        let mut a = Vault::create(config(), creds(), PW).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let key = "Vault/vault.json".to_owned();
        let mut header: serde_json::Value = serde_json::from_slice(&s3.objects.borrow()[&key].0).unwrap();
        header["version"] = 1.into();
        s3.insert(&key, serde_json::to_vec(&header).unwrap());
        let e = block_on(fetch_header(&s3, &config(), &creds())).unwrap_err();
        assert!(e.to_string().contains("older version"), "{e}");
        assert!(block_on(a.sync(&s3)).is_err());
    }

    #[test]
    fn an_unreadable_vault_is_never_overwritten() {
        let (s3, mut a, _) = setup();
        let x = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let garbage = b"CPV2garbage-garbage-garbage-garbage-garbage".to_vec();
        s3.insert(&format!("Vault/{VAULT_OBJECT}"), garbage.clone());
        a.update(&x, ItemData { notes: "here".into(), ..a.get(&x).unwrap().data() }).unwrap();
        assert!(block_on(a.sync(&s3)).is_err());
        assert_eq!(vault_bin(&s3), garbage);
        assert_eq!(a.get(&x).unwrap().notes, "here", "kept here");
        assert!(a.has_unsynced_changes());
    }

    #[test]
    fn offline_changes_wait() {
        let (s3, mut a, mut b) = setup();
        let id = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        *s3.fail.borrow_mut() = true;
        assert!(matches!(block_on(a.sync(&s3)), Err(Error::Network(_))));
        assert!(a.has_unsynced_changes());
        // Saved and unlocked again while offline: the change is still there.
        let mut a = Vault::unlock(&a.save(), PW).unwrap();
        *s3.fail.borrow_mut() = false;
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        assert!(b.get(&id).is_some());
    }

    #[test]
    fn emptied_folder_is_restored() {
        let (s3, mut a, mut b) = setup();
        a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        // Only vault.bin gone: not taken to mean every item was deleted.
        s3.objects.borrow_mut().remove(&format!("Vault/{VAULT_OBJECT}"));
        block_on(b.sync(&s3)).unwrap();
        assert_eq!(b.items().len(), 1);
        // Everything gone.
        s3.objects.borrow_mut().clear();
        block_on(a.sync(&s3)).unwrap();
        let c = join(&s3);
        assert_eq!(c.items().len(), 1);
    }

    /// CleanNotes can use the same folder: its objects (head, notes/,
    /// folders/, attachments/, encryption.json) are neither read nor
    /// touched; and CleanPassword's own stay out of CleanNotes' way
    /// (vault.json and vault.bin are names it doesn't use).
    #[test]
    fn shares_a_folder_with_cleannotes() {
        let s3 = FakeS3::new();
        let notes = ["Vault/head", "Vault/encryption.json", "Vault/notes/abc.md", "Vault/folders/f1.json", "Vault/attachments/0123abcd.png"];
        for k in notes {
            s3.objects.borrow_mut().insert(k.into(), (b"CleanNotes data".to_vec(), format!("\"{k}\"")));
        }
        let mut a = Vault::create(config(), creds(), PW).unwrap();
        let x = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        assert_eq!(block_on(a.sync(&s3)).unwrap().uploaded, 1);
        let b = join(&s3);
        assert_eq!(b.items().len(), 1);
        a.purge(&x).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let objects = s3.objects.borrow();
        for k in notes {
            assert_eq!(objects[k], (b"CleanNotes data".to_vec(), format!("\"{k}\"")), "{k} untouched");
        }
        assert!(objects.keys().all(|k| notes.contains(&k.as_str()) || k == "Vault/vault.json" || k == "Vault/vault.bin"));
    }

    #[test]
    fn merging_the_vault() {
        let item = |id: &str, notes: &str| {
            let mut i = Item::new(ItemData { notes: notes.into(), ..login(id, "https://x.com", "me", "1") }, Utc::now());
            i.id = id.into();
            i
        };
        let (kept, gone_there, gone_here, both, new_here, new_there) =
            (item("kept", ""), item("gone-there", ""), item("gone-here", ""), item("both", ""), item("new-here", ""), item("new-there", ""));
        let edited = Item { notes: "edited here".into(), ..gone_there.clone() };
        let map = |items: &[&Item]| items.iter().map(|i| (i.id.clone(), (*i).clone())).collect::<BTreeMap<_, _>>();
        let base = map(&[&kept, &gone_there, &gone_here, &both]);
        let local = map(&[&kept, &edited, &both, &new_here]);
        let remote = map(&[&kept, &gone_here, &both, &new_there]);
        let mut merged = BTreeSet::new();
        let out = merge_vault(&base, &local, &remote, &mut merged);
        assert_eq!(out.keys().map(String::as_str).collect::<Vec<_>>(), ["both", "gone-there", "kept", "new-here", "new-there"]);
        assert_eq!(out["gone-there"].notes, "edited here", "an edit beats a delete");
        assert!(merged.is_empty());
    }
}
