//! Syncing a vault with its S3 folder.
//!
//! - `vault.json` comes first: if it's another vault's, nothing happens
//!   ([`Error::DifferentVault`]); if another device changed the master
//!   password, this device adopts the new header (the vault key stays the
//!   same, so items stay readable) and the new password unlocks from then
//!   on.
//! - The folder is listed, and only items whose ETag changed are
//!   downloaded. An item changed here and elsewhere is merged field by
//!   field ([`crate::item::merge`]); no password is lost.
//! - Items changed here are uploaded with `If-Match` (or `If-None-Match: *`
//!   if new). If S3 refuses because the item changed meanwhile, it's
//!   downloaded, merged and tried again.
//! - Deleting for good leaves a *tombstone* (an encrypted marker) so other
//!   devices delete it too; an edit made elsewhere beats a delete. Tombstones
//!   are removed after 30 days.
//! - Objects that can't be decrypted (another key, damaged) are left alone
//!   and counted, never deleted.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto;
use crate::item::{merge, Item};
use crate::s3::{Client, Cond, Put, Transport};
use crate::vault::{AwsCredentials, Gone, ItemState, S3Config, Vault, VaultHeader, TRASH_DAYS};
use crate::{Error, Result};

pub const HEADER_OBJECT: &str = "vault.json";
pub const ITEMS_PREFIX: &str = "items/";
/// Sealed objects start with this, then `nonce ‖ ciphertext ‖ tag`.
const MAGIC: &[u8] = b"CPV1";
/// Item plaintexts are padded to a multiple of this many bytes.
const PAD: usize = 512;
/// Uploads retried after merging with a concurrent change.
const RETRIES: usize = 3;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    pub downloaded: usize,
    pub uploaded: usize,
    /// Deleted here because they were deleted elsewhere.
    pub removed: usize,
    /// Changed both here and elsewhere, and merged.
    pub merged: usize,
    /// Objects in the folder that couldn't be decrypted (left alone).
    pub unreadable: usize,
    /// Changes that couldn't be uploaded this time (tried again next sync).
    pub pending: usize,
    /// The master password was changed on another device.
    pub password_changed_elsewhere: bool,
}

/// What an item object holds.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Stored {
    Item(Box<Item>),
    Tombstone { id: String, at: DateTime<Utc> },
}

fn item_name(id: &str) -> String {
    format!("{ITEMS_PREFIX}{id}.bin")
}

/// The id from an item object's name, if it's one of ours.
fn item_id(name: &str) -> Option<&str> {
    let id = name.strip_prefix(ITEMS_PREFIX)?.strip_suffix(".bin")?;
    (!id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')).then_some(id)
}

fn item_aad(vault_id: &str, id: &str) -> Vec<u8> {
    format!("cleanpassword/item/v1/{vault_id}/{id}").into_bytes()
}

fn seal_object(key: &[u8; 32], vault_id: &str, id: &str, stored: &Stored) -> Vec<u8> {
    let plain = Zeroizing::new(crypto::pad(serde_json::to_vec(stored).expect("items serialize"), PAD));
    let mut out = MAGIC.to_vec();
    out.extend(crypto::seal(key, &item_aad(vault_id, id), &plain));
    out
}

fn open_object(key: &[u8; 32], vault_id: &str, id: &str, data: &[u8]) -> Option<Stored> {
    let plain = crypto::open(key, &item_aad(vault_id, id), data.strip_prefix(MAGIC)?)?;
    let stored: Stored = serde_json::from_slice(&plain).ok()?;
    // The id inside must be the one in the name (the AAD binds them too).
    let inner = match &stored {
        Stored::Item(i) => &i.id,
        Stored::Tombstone { id, .. } => id,
    };
    (inner == id).then_some(stored)
}

/// `vault.json` and its ETag, if the folder holds a vault.
pub async fn fetch_header<T: Transport>(transport: &T, config: &S3Config, credentials: &AwsCredentials) -> Result<Option<(VaultHeader, String)>> {
    config.check()?;
    credentials.check()?;
    let client = Client::new(config, credentials, transport);
    let Some(obj) = client.get(HEADER_OBJECT).await? else { return Ok(None) };
    let header: VaultHeader = serde_json::from_slice(&obj.data).map_err(|_| Error::invalid("this folder's vault.json is damaged"))?;
    header.check()?;
    Ok(Some((header, obj.etag)))
}

impl Vault {
    /// Syncs with the S3 folder. Safe to call any time; a failed sync
    /// leaves everything to be tried again next time.
    pub async fn sync<T: Transport>(&mut self, transport: &T) -> Result<SyncReport> {
        let config = self.config.clone();
        let credentials = self.s.credentials.clone();
        let client = Client::new(&config, &credentials, transport);
        let mut report = SyncReport::default();

        self.sync_header(&client, &mut report).await?;
        self.empty_old_trash(Utc::now());
        self.pull(&client, &mut report).await?;
        self.push(&client, &mut report).await?;
        self.clean_tombstones(&client).await;

        self.last_sync = Some(Utc::now());
        Ok(report)
    }

    async fn sync_header<T: Transport>(&mut self, client: &Client<'_, T>, report: &mut SyncReport) -> Result<()> {
        let remote = client.get(HEADER_OBJECT).await?;
        match remote {
            None => {
                if self.s.header_etag.is_some() {
                    // The folder was emptied: put everything back.
                    for st in self.s.items.values_mut() {
                        st.etag = None;
                        st.dirty = true;
                    }
                    self.s.purges.clear();
                    self.s.tombstones.clear();
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

    async fn pull<T: Transport>(&mut self, client: &Client<'_, T>, report: &mut SyncReport) -> Result<()> {
        let listed = client.list(ITEMS_PREFIX).await?;
        let mut present = std::collections::HashSet::new();
        for l in &listed {
            let Some(id) = item_id(&l.name) else { continue };
            present.insert(id.to_owned());
            let known = self.s.items.get(id).and_then(|s| s.etag.as_deref()) == Some(l.etag.as_str())
                || self.s.tombstones.get(id).and_then(|g| g.etag.as_deref()) == Some(l.etag.as_str())
                || self.s.purges.contains_key(id);
            if known {
                continue;
            }
            let Some(obj) = client.get(&l.name).await? else { continue };
            match open_object(&self.key, &self.header.vault_id, id, &obj.data) {
                None => report.unreadable += 1,
                Some(stored) => self.take_remote(id, stored, obj.etag, report),
            }
        }
        // Gone from S3 altogether (a tombstone cleaned up, or deleted by
        // hand): delete here too, unless changed here.
        let vanished: Vec<String> = self.s.items.iter().filter(|(id, s)| s.etag.is_some() && !present.contains(*id)).map(|(id, _)| id.clone()).collect();
        for id in vanished {
            let st = self.s.items.get_mut(&id).expect("listed above");
            if st.dirty {
                st.etag = None;
            } else {
                self.s.items.remove(&id);
                report.removed += 1;
            }
        }
        self.s.tombstones.retain(|id, _| present.contains(id));
        Ok(())
    }

    /// Takes in what another device saved.
    fn take_remote(&mut self, id: &str, stored: Stored, etag: String, report: &mut SyncReport) {
        match stored {
            Stored::Item(remote) => {
                let remote = *remote;
                match self.s.items.get_mut(id) {
                    None => {
                        self.s.items.insert(id.to_owned(), ItemState { item: remote.clone(), base: Some(remote), etag: Some(etag), dirty: false });
                        report.downloaded += 1;
                    }
                    Some(st) if !st.dirty => {
                        st.item = remote.clone();
                        st.base = Some(remote);
                        st.etag = Some(etag);
                        report.downloaded += 1;
                    }
                    Some(st) => {
                        st.item = merge(st.base.as_ref(), &st.item, &remote);
                        st.dirty = st.item != remote;
                        st.base = Some(remote);
                        st.etag = Some(etag);
                        report.merged += 1;
                    }
                }
            }
            Stored::Tombstone { at, .. } => {
                self.s.tombstones.insert(id.to_owned(), Gone { etag: Some(etag.clone()), at });
                match self.s.items.get_mut(id) {
                    // Edited here: the edit wins, overwriting the tombstone.
                    Some(st) if st.dirty => st.etag = Some(etag),
                    Some(_) => {
                        self.s.items.remove(id);
                        report.removed += 1;
                    }
                    None => {}
                }
            }
        }
    }

    async fn push<T: Transport>(&mut self, client: &Client<'_, T>, report: &mut SyncReport) -> Result<()> {
        let vault_id = self.header.vault_id.clone();
        let dirty: Vec<String> = self.s.items.iter().filter(|(_, s)| s.dirty).map(|(id, _)| id.clone()).collect();
        for id in dirty {
            let mut done = false;
            for _ in 0..RETRIES {
                let Some(st) = self.s.items.get(&id) else { break };
                let body = seal_object(&self.key, &vault_id, &id, &Stored::Item(Box::new(st.item.clone())));
                let etag = st.etag.clone();
                let cond = etag.as_deref().map(Cond::Match).unwrap_or(Cond::Absent);
                match client.put(&item_name(&id), body, cond).await? {
                    Put::Stored { etag } => {
                        let st = self.s.items.get_mut(&id).expect("still there");
                        st.etag = Some(etag);
                        st.base = Some(st.item.clone());
                        st.dirty = false;
                        self.s.tombstones.remove(&id);
                        report.uploaded += 1;
                        done = true;
                        break;
                    }
                    Put::Conflict => match client.get(&item_name(&id)).await? {
                        None => self.s.items.get_mut(&id).expect("still there").etag = None,
                        Some(obj) => match open_object(&self.key, &vault_id, &id, &obj.data) {
                            Some(stored) => self.take_remote(&id, stored, obj.etag, report),
                            None => break,
                        },
                    },
                }
                if self.s.items.get(&id).is_none_or(|s| !s.dirty) {
                    done = true;
                    break;
                }
            }
            if !done {
                report.pending += 1;
            }
        }

        let purges: Vec<(String, Gone)> = self.s.purges.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (id, gone) in purges {
            let Some(etag) = gone.etag.as_deref() else {
                self.s.purges.remove(&id);
                continue;
            };
            let body = seal_object(&self.key, &vault_id, &id, &Stored::Tombstone { id: id.clone(), at: gone.at });
            match client.put(&item_name(&id), body, Cond::Match(etag)).await? {
                Put::Stored { etag } => {
                    self.s.purges.remove(&id);
                    self.s.tombstones.insert(id, Gone { etag: Some(etag), at: gone.at });
                }
                Put::Conflict => {
                    // Changed elsewhere since: that edit beats the delete.
                    self.s.purges.remove(&id);
                    if let Some(obj) = client.get(&item_name(&id)).await? {
                        if let Some(stored) = open_object(&self.key, &vault_id, &id, &obj.data) {
                            self.take_remote(&id, stored, obj.etag, report);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Removes tombstones every device has had [`TRASH_DAYS`] to see.
    async fn clean_tombstones<T: Transport>(&mut self, client: &Client<'_, T>) {
        let cutoff = Utc::now() - Duration::days(TRASH_DAYS);
        let old: Vec<String> = self.s.tombstones.iter().filter(|(_, g)| g.at < cutoff).map(|(id, _)| id.clone()).collect();
        for id in old {
            if client.delete(&item_name(&id)).await.is_ok() {
                self.s.tombstones.remove(&id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use pollster::block_on;

    use super::*;
    use crate::item::ItemData;
    use crate::s3::fake::FakeS3;
    use crate::vault::tests::{config, creds, login, PW};

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
        assert_eq!(r.downloaded, 3, "paged listing included");
        assert_eq!(b.get(&id).unwrap().password, "pw1");
        // Nothing changed: nothing downloaded again.
        assert_eq!(block_on(b.sync(&s3)).unwrap(), SyncReport::default());

        // Nothing readable in the bucket.
        for (k, (data, _)) in s3.objects.borrow().iter() {
            let text = String::from_utf8_lossy(data);
            assert!(!text.contains("Example") && !text.contains("pw1") && !text.contains("example.com"), "{k}");
            if k.starts_with("Vault/items/") {
                assert_eq!((data.len() - MAGIC.len() - 24 - 16) % PAD, 0, "padded");
            }
        }
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

        // Purge: a tombstone; b deletes it too.
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
    fn edit_beats_a_tombstone_already_uploaded() {
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
    fn unreadable_objects_are_left_alone() {
        let (s3, mut a, _) = setup();
        s3.objects.borrow_mut().insert("Vault/items/abc.bin".into(), (b"CPV1garbage-garbage-garbage-garbage-garbage".to_vec(), "\"x\"".into()));
        let r = block_on(a.sync(&s3)).unwrap();
        assert_eq!(r.unreadable, 1);
        assert!(s3.objects.borrow().contains_key("Vault/items/abc.bin"));
        // An object copied under another item's name doesn't open either.
        let id = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        let data = s3.objects.borrow()[&format!("Vault/items/{id}.bin")].0.clone();
        s3.objects.borrow_mut().insert("Vault/items/other.bin".into(), (data, "\"y\"".into()));
        assert_eq!(block_on(a.sync(&s3)).unwrap().unreadable, 2);
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
        let (s3, mut a, _) = setup();
        a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        s3.objects.borrow_mut().clear();
        block_on(a.sync(&s3)).unwrap();
        let b = join(&s3);
        assert_eq!(b.items().len(), 1);
    }

    #[test]
    fn old_tombstones_are_cleaned_up() {
        let (s3, mut a, _) = setup();
        let x = a.add(login("X", "https://x.com", "me", "1")).unwrap();
        block_on(a.sync(&s3)).unwrap();
        a.purge(&x).unwrap();
        block_on(a.sync(&s3)).unwrap();
        assert!(s3.objects.borrow().contains_key(&format!("Vault/items/{x}.bin")));
        a.s.tombstones.get_mut(&x).unwrap().at = Utc::now() - Duration::days(31);
        block_on(a.sync(&s3)).unwrap();
        assert!(!s3.objects.borrow().contains_key(&format!("Vault/items/{x}.bin")));
    }
}
