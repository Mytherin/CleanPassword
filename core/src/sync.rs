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
    /// One more with every save, so a device can tell an older copy put
    /// back in S3 (which would read as every item added since having been
    /// deleted) from a newer one. `None` in vaults saved by versions before
    /// it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
}

fn vault_aad(vault_id: &str) -> Vec<u8> {
    format!("cleanpassword/vault/v2/{vault_id}").into_bytes()
}

fn pad_block(len: usize) -> usize {
    PAD.max(len.next_power_of_two() / 8)
}

fn seal_vault(key: &[u8; 32], vault_id: &str, items: &BTreeMap<String, Item>, seq: u64) -> Vec<u8> {
    let stored = Stored { items: items.values().cloned().collect(), seq: Some(seq) };
    let json = Zeroizing::new(serde_json::to_vec(&stored).expect("items serialize"));
    let plain = Zeroizing::new(crypto::pad(json.to_vec(), pad_block(json.len())));
    let mut out = MAGIC.to_vec();
    out.extend(crypto::seal(key, &vault_aad(vault_id), &plain));
    out
}

/// Opens `vault.bin` with the vault key, or one before it (a device that
/// changed the master password seals it again with the new key just after
/// uploading vault.json, so another device can find it sealed with either).
fn open_vault(keys: &[crypto::Key], vault_id: &str, data: &[u8]) -> Result<(BTreeMap<String, Item>, Option<u64>)> {
    let unreadable = || Error::invalid("the vault in S3 (vault.bin) can't be decrypted: it's damaged, or was written with another key");
    let sealed = data.strip_prefix(MAGIC).ok_or_else(unreadable)?;
    let plain = keys.iter().find_map(|k| crypto::open(k, &vault_aad(vault_id), sealed)).ok_or_else(unreadable)?;
    let stored: Stored = serde_json::from_slice(&plain).map_err(|_| unreadable())?;
    Ok((stored.items.into_iter().map(|i| (i.id.clone(), i)).collect(), stored.seq))
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

    /// The vault key, then the ones before it.
    fn keys(&self) -> Vec<crypto::Key> {
        let mut keys = vec![self.key.clone()];
        keys.extend(self.header.previous(&self.key));
        keys
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
                if header.wrapped_key == self.header.wrapped_key {
                    self.pending = None;
                }
                if self.s.header_etag.as_deref() != Some(obj.etag.as_str()) {
                    if header.wrapped_key != self.header.wrapped_key {
                        // A new master password, set on another device (it
                        // wins over one set here at the same time). Adopted
                        // only if it's signed with the vault key and isn't an
                        // older header put back: anything else could lock
                        // every device out.
                        if header.generation < self.header.generation {
                            return Err(Error::invalid(
                                "vault.json in S3 was put back to an older master password, so it was ignored (change the master password again to replace it)",
                            ));
                        }
                        if header.signed_by(&self.key) {
                            self.header = header;
                            self.s.header_dirty = false;
                            report.password_changed_elsewhere = true;
                        } else if header.generation > self.header.generation && !header.previous_keys.is_empty() {
                            // A new vault key with it, which only the new
                            // password opens: kept for unlocking with it
                            // ([`Vault::unlock`]), which proves it genuine. A
                            // forgery never unlocks, and the old password
                            // still does.
                            self.pending = Some((header, obj.etag.clone()));
                            return Err(Error::PasswordChangedElsewhere);
                        } else {
                            return Err(Error::invalid(
                                "vault.json in S3 was replaced by someone without the vault key, so it was ignored (if you changed the master password with an older version of CleanPassword, update it there)",
                            ));
                        }
                    }
                    self.s.header_etag = Some(obj.etag.clone());
                }
                if !self.header.signed_by(&self.key) {
                    // A vault made before vault.json was signed: sign it now.
                    self.header.sign(&self.key);
                    self.s.header_dirty = true;
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
        if self.s.header_dirty && self.s.reseal {
            // vault.bin can't be sealed with a new vault key before the
            // vault.json that holds it is there.
            return Err(Error::invalid("couldn't save the new master password to S3 yet; try syncing again"));
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
            // An older copy than the one last synced, put back by someone
            // who can write to the bucket, is ignored and replaced.
            let (remote, etag, rolled_back) = match client.head(VAULT_OBJECT).await? {
                Some(e) if self.s.etag.as_ref() == Some(&e) => (self.s.base.clone(), Some(e), false),
                Some(_) => {
                    progress(0, 1);
                    let obj = client.get(VAULT_OBJECT).await?;
                    progress(1, 1);
                    match obj {
                        Some(obj) => match open_vault(std::slice::from_ref(&self.key), &self.header.vault_id, &obj.data).or_else(|_| {
                            // Still sealed with an earlier key: seal it again.
                            let opened = open_vault(&self.keys()[1..], &self.header.vault_id, &obj.data)?;
                            self.s.reseal = true;
                            Ok::<_, Error>(opened)
                        })? {
                            (_, Some(seq)) if seq < self.s.seq => (self.s.base.clone(), Some(obj.etag), true),
                            (items, seq) => {
                                self.s.seq = seq.unwrap_or(self.s.seq);
                                (items, Some(obj.etag), false)
                            }
                        },
                        None => (self.s.base.clone(), None, false),
                    }
                }
                None => (self.s.base.clone(), None, false),
            };
            self.s.items = merge_vault(&self.s.base, &self.s.items, &remote, &mut merged);
            self.s.base = remote;
            self.s.etag = etag.clone();
            if etag.is_some() && !rolled_back && !self.s.reseal && self.s.items == self.s.base {
                done = true;
                break;
            }
            let seq = self.s.seq + 1;
            let body = seal_vault(&self.key, &self.header.vault_id, &self.s.items, seq);
            let cond = etag.as_deref().map_or(Cond::Absent, Cond::Match);
            match client.put(VAULT_OBJECT, body, cond).await? {
                Put::Stored { etag } => {
                    report.uploaded += changed(&self.s.base, &self.s.items);
                    self.s.base = self.s.items.clone();
                    self.s.etag = Some(etag);
                    self.s.seq = seq;
                    self.s.reseal = false;
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

    /// Takes in what another process saved of this same vault since this
    /// one last read or saved it (the iPhone app and its AutoFill extension
    /// share one saved copy), so neither overwrites the other's changes.
    ///
    /// `ancestor` is the copy this process last read or saved, which both
    /// sides started from. Items, the access key, the S3 settings and the
    /// header changed here since then are kept; changed only on the other
    /// side, they take its version; items changed on both are merged as in
    /// a sync. Without an ancestor (or one that can't be opened), the older
    /// of the two synced copies stands in for it, and settings come from the
    /// side that synced last (but a master password changed here and not
    /// uploaded yet is kept). What was last synced (the synced copy, the
    /// ETags, when) always comes from the side that synced more recently.
    /// Returns how many items changed here.
    pub fn absorb(&mut self, saved: &str, ancestor: Option<&str>) -> Result<usize> {
        let key = self.key_b64();
        let other = Vault::unlock_with_key(saved, &key)?;
        if other.header.vault_id != self.header.vault_id {
            return Err(Error::DifferentVault);
        }
        let anc = ancestor.and_then(|a| Vault::unlock_with_key(a, &key).ok()).filter(|a| a.header.vault_id == self.header.vault_id);
        let theirs_newer = other.last_sync >= self.last_sync;

        let before = std::mem::take(&mut self.s.items);
        let mut merged = BTreeSet::new();
        let base = match &anc {
            Some(a) => &a.s.items,
            None if theirs_newer => &self.s.base,
            None => &other.s.base,
        };
        let items = merge_vault(base, &before, &other.s.items, &mut merged);

        let (keep_credentials, keep_config, keep_header) = match &anc {
            Some(a) => (self.s.credentials != a.s.credentials, self.config != a.config, self.header != a.header),
            None => (!theirs_newer, !theirs_newer, !theirs_newer || (self.s.header_dirty && !other.s.header_dirty)),
        };
        let Vault { config, header, s: theirs, last_sync, .. } = other;
        if theirs_newer {
            self.s.base = theirs.base;
            self.s.etag = theirs.etag;
            self.s.header_etag = theirs.header_etag;
            self.last_sync = last_sync;
        }
        if !keep_credentials {
            self.s.credentials = theirs.credentials;
        }
        if !keep_config {
            self.config = config;
        }
        if !keep_header {
            self.header = header;
            self.s.header_dirty = theirs.header_dirty;
        }
        self.s.items = items;
        Ok(changed(&before, &self.s.items))
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

    /// The iPhone app and its AutoFill extension share one saved copy: each
    /// takes in the other's before saving.
    #[test]
    fn absorb_keeps_both_processes_changes() {
        let (s3, mut app, _) = setup();
        let shared = app.add(login("Shared", "https://shared.com", "me", "pw0")).unwrap();
        block_on(app.sync(&s3)).unwrap();
        let mut ext = Vault::unlock_with_key(&app.save(), &app.key_b64()).unwrap();

        // The extension saves a passkey's login and syncs; the app edits
        // another login meanwhile, without seeing that.
        let from_ext = ext.add(login("Ext", "https://ext.com", "me", "pw1")).unwrap();
        block_on(ext.sync(&s3)).unwrap();
        let mut d = app.get(&shared).unwrap().data();
        d.notes = "edited in the app".into();
        app.update(&shared, d).unwrap();

        assert_eq!(app.absorb(&ext.save(), None).unwrap(), 1);
        assert!(app.get(&from_ext).is_some(), "the extension's item is kept");
        assert_eq!(app.get(&shared).unwrap().notes, "edited in the app", "and so is the app's edit");
        assert_eq!(app.last_sync(), ext.last_sync(), "the newer sync is adopted");
        let r = block_on(app.sync(&s3)).unwrap();
        assert_eq!((r.uploaded, r.downloaded), (1, 0), "only the app's edit is new to S3");

        // The other way round: the extension, synced earlier, takes in the
        // app's newer copy, and a delete made there.
        app.delete(&from_ext).unwrap();
        app.purge(&from_ext).unwrap();
        assert!(ext.absorb(&app.save(), None).unwrap() >= 2);
        assert!(ext.get(&from_ext).is_none());
        assert_eq!(ext.get(&shared).unwrap().notes, "edited in the app");

        // An identical copy changes nothing.
        let same = app.save();
        assert_eq!(app.absorb(&same, None).unwrap(), 0);
        assert!(app.has_unsynced_changes());

        // Another vault's copy is refused.
        let other = Vault::create(config(), creds(), PW).unwrap();
        assert!(app.absorb(&other.save(), None).is_err());
    }

    /// With the copy both started from, what changed on each side is known:
    /// a new access key isn't lost to a copy that synced later, and an item
    /// purged here doesn't come back from the other side.
    #[test]
    fn absorb_with_ancestor() {
        let (s3, mut app, _) = setup();
        let start = app.save();
        let mut ext = Vault::unlock_with_key(&start, &app.key_b64()).unwrap();

        // The app gets a new access key (its sync fails meanwhile); the
        // extension, with the old key, syncs a new login.
        let rotated = AwsCredentials { access_key_id: "AKIANEW".into(), secret_access_key: "new".into(), session_token: None };
        app.set_credentials(rotated.clone()).unwrap();
        let from_ext = ext.add(login("Ext", "https://ext.com", "me", "pw1")).unwrap();
        block_on(ext.sync(&s3)).unwrap();

        assert_eq!(app.absorb(&ext.save(), Some(&start)).unwrap(), 1);
        assert_eq!(app.credentials().access_key_id, "AKIANEW", "the new key is kept");
        assert_eq!(app.last_sync(), ext.last_sync());
        assert!(app.get(&from_ext).is_some());

        // The extension takes in the app's key, as it didn't change its own.
        let app_saved = app.save();
        ext.absorb(&app_saved, Some(&ext.save())).unwrap();
        assert_eq!(ext.credentials().access_key_id, "AKIANEW");

        // An item made and saved, then purged here while the other side
        // (which has it) saves something else: it stays purged.
        let tmp = app.add(login("Tmp", "https://tmp.com", "me", "pw2")).unwrap();
        let shared = app.save();
        let mut ext = Vault::unlock_with_key(&shared, &app.key_b64()).unwrap();
        app.delete(&tmp).unwrap();
        app.purge(&tmp).unwrap();
        ext.add(login("Other", "https://other.com", "me", "pw3")).unwrap();
        app.absorb(&ext.save(), Some(&shared)).unwrap();
        assert!(app.get(&tmp).is_none(), "a purged item doesn't come back");
        assert!(app.items().iter().any(|i| i.name == "Other"));
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

    const NEW_PW: &str = "a brand new master pw";

    #[test]
    fn password_change_reaches_other_devices() {
        let (s3, mut a, mut b) = setup();
        let x = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        let old_key = b.key_b64();
        a.change_master_password(PW, NEW_PW).unwrap();
        assert!(a.key_changed());
        block_on(a.sync(&s3)).unwrap();
        assert!(!a.has_unsynced_changes());
        // The vault key changed with it: the old one doesn't read the vault.
        assert!(open_vault(&[b.key.clone()], b.vault_id(), &vault_bin(&s3)).is_err());
        assert!(open_vault(&[a.key.clone()], a.vault_id(), &vault_bin(&s3)).is_ok());

        // b made a change meanwhile, then hears of the new password.
        let y = b.add(login("Y", "https://y.com", "me", "2")).unwrap();
        assert!(matches!(block_on(b.sync(&s3)), Err(Error::PasswordChangedElsewhere)));
        assert!(b.password_changed_elsewhere());
        let saved = b.save();
        // The old password still opens what b kept (and syncing says why
        // it can't), the new one moves b to the new key.
        let mut old = Vault::unlock(&saved, PW).unwrap();
        assert!(matches!(block_on(old.sync(&s3)), Err(Error::PasswordChangedElsewhere)));
        let mut b = Vault::unlock(&saved, NEW_PW).unwrap();
        assert!(b.key_changed() && !b.password_changed_elsewhere());
        assert_eq!(*b.key, *a.key);
        // b's key as kept for Face ID or a PIN no longer opens it.
        assert!(matches!(Vault::unlock_with_key(&b.save(), &old_key), Err(Error::StaleKey)));
        assert!(Vault::unlock(&b.save(), PW).is_err());
        block_on(b.sync(&s3)).unwrap();
        assert!(b.get(&x).is_some() && b.get(&y).is_some(), "b's change survived");
        block_on(a.sync(&s3)).unwrap();
        assert!(a.get(&y).is_some());

        // A new device joins with the new password.
        let (h, etag) = block_on(fetch_header(&s3, &config(), &creds())).unwrap().unwrap();
        assert!(Vault::join(config(), creds(), h.clone(), etag.clone(), PW).is_err());
        assert!(Vault::join(config(), creds(), h, etag, NEW_PW).is_ok());
    }

    #[test]
    fn a_device_reads_vault_bin_sealed_with_the_key_before() {
        // a uploaded vault.json with the new password, but not yet vault.bin.
        let (s3, mut a, mut b) = setup();
        let x = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let before = vault_bin(&s3);
        a.change_master_password(PW, NEW_PW).unwrap();
        block_on(a.sync(&s3)).unwrap();
        s3.insert(&format!("Vault/{VAULT_OBJECT}"), before);
        assert!(matches!(block_on(b.sync(&s3)), Err(Error::PasswordChangedElsewhere)));
        let mut b = Vault::unlock(&b.save(), NEW_PW).unwrap();
        block_on(b.sync(&s3)).unwrap();
        assert!(b.get(&x).is_some());
        assert!(open_vault(&[b.key.clone()], b.vault_id(), &vault_bin(&s3)).is_ok(), "sealed again with the new key");
    }

    #[test]
    fn two_password_changes_while_a_device_is_away() {
        let (s3, mut a, b) = setup();
        a.change_master_password(PW, NEW_PW).unwrap();
        block_on(a.sync(&s3)).unwrap();
        a.change_master_password(NEW_PW, "and another master pw").unwrap();
        block_on(a.sync(&s3)).unwrap();
        // CleanNotes unlocks with vault.json as it is in S3 now.
        let (h, etag) = block_on(fetch_header(&s3, &config(), &creds())).unwrap().unwrap();
        let saved = b.save();
        let mut b = Vault::unlock_with_header(&saved, h.clone(), etag.clone(), "and another master pw").unwrap();
        assert!(b.key_changed());
        block_on(b.sync(&s3)).unwrap();
        // The password b knew still opens what it kept, and says it changed.
        let mut old = Vault::unlock_with_header(&saved, h, etag, PW).unwrap();
        assert!(!old.key_changed() && old.password_changed_elsewhere());
        assert!(matches!(block_on(old.sync(&s3)), Err(Error::PasswordChangedElsewhere)));
    }

    #[test]
    fn a_forged_password_change_never_unlocks() {
        // Someone who can write to the bucket puts in a vault.json that
        // looks like a password change.
        let (s3, mut a, _) = setup();
        let real = header_json(&s3);
        let forged = VaultHeader::new(a.vault_id().to_owned(), "the attacker's other pw", &crypto::random_key(), Utc::now(), 5, &[crypto::random_key()]).unwrap();
        s3.insert("Vault/vault.json", serde_json::to_vec(&forged).unwrap());
        assert!(matches!(block_on(a.sync(&s3)), Err(Error::PasswordChangedElsewhere)));
        let saved = a.save();
        assert!(Vault::unlock(&saved, "the attacker's other pw").is_err());
        let mut a = Vault::unlock(&saved, PW).unwrap();
        assert!(!a.key_changed());
        // Put right, syncing works again and the forgery is forgotten.
        s3.insert("Vault/vault.json", serde_json::to_vec(&real).unwrap());
        block_on(a.sync(&s3)).unwrap();
        assert!(!a.password_changed_elsewhere());
    }

    fn header_json(s3: &FakeS3) -> serde_json::Value {
        serde_json::from_slice(&s3.objects.borrow()["Vault/vault.json"].0).unwrap()
    }

    #[test]
    fn a_header_written_without_the_vault_key_is_refused() {
        // Someone who can write to the bucket, but has neither the master
        // password nor the vault key, puts in a vault.json of their own
        // (with or without a MAC of their own) under this vault's id.
        let (s3, mut a, _) = setup();
        a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let real = header_json(&s3);
        let mut forged = serde_json::to_value(&Vault::create(config(), creds(), "the attacker's password").unwrap().header).unwrap();
        forged["vault_id"] = real["vault_id"].clone();
        for mac in [forged["key_mac"].clone(), serde_json::Value::Null] {
            forged["key_mac"] = mac;
            s3.insert("Vault/vault.json", serde_json::to_vec(&forged).unwrap());
            let e = block_on(a.sync(&s3)).unwrap_err();
            assert!(e.to_string().contains("without the vault key"), "{e}");
            assert!(Vault::unlock(&a.save(), PW).is_ok(), "still unlocks with the master password");
            assert_eq!(header_json(&s3), forged, "left alone");
        }
        // Put right, syncing works again.
        s3.insert("Vault/vault.json", serde_json::to_vec(&real).unwrap());
        block_on(a.sync(&s3)).unwrap();
        assert_eq!(a.items().len(), 1);
    }

    #[test]
    fn an_older_header_put_back_is_refused() {
        let (s3, mut a, mut b) = setup();
        let old = header_json(&s3);
        a.change_master_password(PW, NEW_PW).unwrap();
        block_on(a.sync(&s3)).unwrap();
        assert!(matches!(block_on(b.sync(&s3)), Err(Error::PasswordChangedElsewhere)));
        let mut b = Vault::unlock(&b.save(), NEW_PW).unwrap();
        block_on(b.sync(&s3)).unwrap();
        s3.insert("Vault/vault.json", serde_json::to_vec(&old).unwrap());
        for v in [&mut a, &mut b] {
            let e = block_on(v.sync(&s3)).unwrap_err();
            assert!(e.to_string().contains("older master password"), "{e}");
            let saved = v.save();
            assert!(Vault::unlock(&saved, PW).is_err());
            assert!(Vault::unlock(&saved, NEW_PW).is_ok());
        }
    }

    #[test]
    fn an_older_vault_put_back_is_replaced_not_merged() {
        // Someone who can write to the bucket puts back an older vault.bin
        // (sealed with the right key): it must not read as every item
        // added since having been deleted.
        let (s3, mut a, mut b) = setup();
        a.add(login("Old", "https://old.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let old = vault_bin(&s3);
        let new = a.add(login("New", "https://new.com", "me", "2")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        s3.insert(&format!("Vault/{VAULT_OBJECT}"), old);
        for v in [&mut b, &mut a] {
            let r = block_on(v.sync(&s3)).unwrap();
            assert_eq!(r.removed, 0);
            assert!(v.get(&new).is_some());
        }
        // The latest copy was put back for everyone.
        let mut c = join(&s3);
        assert!(block_on(c.sync(&s3)).is_ok());
        assert_eq!(c.items().len(), 2);
    }

    #[test]
    fn a_vault_saved_without_a_counter_still_merges() {
        // vault.bin as versions before the save counter wrote it.
        let (s3, mut a, mut b) = setup();
        a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        block_on(b.sync(&s3)).unwrap();
        b.add(login("Y", "https://y.com", "me", "2")).unwrap();
        let items: BTreeMap<String, Item> = b.s.items.clone();
        let stored = serde_json::to_vec(&serde_json::json!({ "items": items.values().collect::<Vec<_>>() })).unwrap();
        let mut legacy = MAGIC.to_vec();
        legacy.extend(crypto::seal(&b.key, &vault_aad(b.vault_id()), &stored));
        s3.insert(&format!("Vault/{VAULT_OBJECT}"), legacy);
        let r = block_on(a.sync(&s3)).unwrap();
        assert_eq!(r.downloaded, 1);
        assert_eq!(a.items().len(), 2);
    }

    #[test]
    fn an_unsigned_header_gets_signed() {
        // A vault from before vault.json carried a MAC.
        let s3 = FakeS3::new();
        let mut a = Vault::create(config(), creds(), PW).unwrap();
        a.header.key_mac = None;
        block_on(a.sync(&s3)).unwrap();
        block_on(a.sync(&s3)).unwrap();
        assert!(header_json(&s3)["key_mac"].is_string());
        let (h, _) = block_on(fetch_header(&s3, &config(), &creds())).unwrap().unwrap();
        assert!(h.signed_by(&a.key));
        assert!(Vault::unlock(&a.save(), PW).is_ok());
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
