//! Vault items: logins and secure notes.
//!
//! An item is stored (encrypted) as JSON. Fields this version doesn't know,
//! written by a newer version, are kept as they are in [`Item::extra`], so an
//! older device editing an item doesn't drop them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    #[default]
    Login,
    /// A secure note (also what cards, identities and SSH keys from other
    /// password managers become, with their details as fields).
    Note,
}

/// How a saved website address is matched against a page (Bitwarden's
/// options; `None` on an [`ItemUri`] means the default, [`UriMatch::Domain`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UriMatch {
    /// Same registrable domain (`accounts.example.com` ~ `example.com`).
    Domain,
    /// Same host name and port.
    Host,
    /// The page's URL starts with the saved one.
    StartsWith,
    /// The same URL.
    Exact,
    /// The page's URL matches a regular expression.
    Regex,
    /// Never offered automatically.
    Never,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemUri {
    pub uri: String,
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_mode: Option<UriMatch>,
}

impl ItemUri {
    pub fn new(uri: impl Into<String>) -> ItemUri {
        ItemUri { uri: uri.into(), match_mode: None }
    }
}

/// A custom field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: String,
    /// Shown as dots until revealed (a PIN, a security answer).
    #[serde(default)]
    pub hidden: bool,
}

/// A password the item had before.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub password: String,
    /// When it stopped being the password.
    pub retired: DateTime<Utc>,
}

/// The parts of an item people edit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ItemData {
    pub kind: ItemKind,
    pub name: String,
    pub username: String,
    pub password: String,
    pub uris: Vec<ItemUri>,
    /// A TOTP secret: base32, an `otpauth://` URI, or `steam://…`.
    pub totp: String,
    pub notes: String,
    /// A folder name; nested folders are written `Work/Email`.
    pub folder: String,
    pub favorite: bool,
    pub fields: Vec<Field>,
}

/// A passkey (a WebAuthn discoverable credential): a P-256 key pair a site
/// knows the public half of. Stored as Bitwarden exports them, so they move
/// both ways.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Passkey {
    /// The credential id, base64url.
    pub credential_id: String,
    /// The site's relying party id (a domain, e.g. `github.com`).
    pub rp_id: String,
    #[serde(default)]
    pub rp_name: String,
    /// The site's id for the account, base64url.
    pub user_handle: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub user_display_name: String,
    /// The private key: PKCS#8 DER, base64url.
    pub key: String,
    /// The signature counter. Passkeys made here keep 0 (they're synced, as
    /// Apple's and Google's are); imported ones that counted keep counting.
    #[serde(default)]
    pub counter: u32,
    pub created: DateTime<Utc>,
}

/// How many old passwords an item remembers.
pub const HISTORY_LIMIT: usize = 20;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    #[serde(default)]
    pub kind: ItemKind,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub uris: Vec<ItemUri>,
    #[serde(default)]
    pub totp: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
    /// The item's passkeys (see [`crate::passkey`]). Made by sites, not
    /// edited, so not in [`ItemData`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<Passkey>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_modified: Option<DateTime<Utc>>,
    /// In the trash since then; purged for good after 30 days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<DateTime<Utc>>,
    /// Fields of newer versions, kept as they were.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Item {
    pub fn new(data: ItemData, now: DateTime<Utc>) -> Item {
        let mut item = Item {
            id: uuid::Uuid::new_v4().to_string(),
            kind: ItemKind::Login,
            name: String::new(),
            username: String::new(),
            password: String::new(),
            uris: Vec::new(),
            totp: String::new(),
            notes: String::new(),
            folder: String::new(),
            favorite: false,
            fields: Vec::new(),
            history: Vec::new(),
            passkeys: Vec::new(),
            created: now,
            modified: now,
            password_modified: None,
            deleted: None,
            extra: Map::new(),
        };
        item.apply(data, now);
        item.password_modified = (!item.password.is_empty()).then_some(now);
        item
    }

    pub fn data(&self) -> ItemData {
        ItemData {
            kind: self.kind,
            name: self.name.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            uris: self.uris.clone(),
            totp: self.totp.clone(),
            notes: self.notes.clone(),
            folder: self.folder.clone(),
            favorite: self.favorite,
            fields: self.fields.clone(),
        }
    }

    /// Sets the editable parts; a changed password goes into the history.
    /// Returns whether anything changed.
    pub fn apply(&mut self, data: ItemData, now: DateTime<Utc>) -> bool {
        let data = ItemData { name: data.name.trim().to_owned(), folder: normalize_folder(&data.folder), ..data };
        if data == self.data() {
            return false;
        }
        if data.password != self.password && !self.password.is_empty() {
            self.retire_password(self.password.clone(), now);
        }
        if data.password != self.password {
            self.password_modified = Some(now);
        }
        let ItemData { kind, name, username, password, uris, totp, notes, folder, favorite, fields } = data;
        (self.kind, self.name, self.username, self.password, self.uris) = (kind, name, username, password, uris);
        (self.totp, self.notes, self.folder, self.favorite, self.fields) = (totp, notes, folder, favorite, fields);
        self.modified = now;
        true
    }

    fn retire_password(&mut self, password: String, now: DateTime<Utc>) {
        if password.is_empty() || self.history.iter().any(|h| h.password == password) {
            return;
        }
        self.history.insert(0, HistoryEntry { password, retired: now });
        self.history.truncate(HISTORY_LIMIT);
    }

    /// The host of the first website, for showing next to the name.
    pub fn first_host(&self) -> Option<String> {
        self.uris.iter().find_map(|u| crate::matching::parse_page(&u.uri).map(|p| p.host))
    }
}

/// `" Work / Email/ "` → `"Work/Email"`.
pub fn normalize_folder(folder: &str) -> String {
    folder.split('/').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>().join("/")
}

/// Merges an item edited on this device (`local`) with the version another
/// device saved (`remote`), both made from `base` (the last version this
/// device synced; `None` if both were made independently).
///
/// Field by field: a field changed on one side only takes that change; one
/// changed on both takes the more recently modified side's, and if that
/// loses a password, the losing password goes into the history, so no
/// password is ever lost.
pub fn merge(base: Option<&Item>, local: &Item, remote: &Item) -> Item {
    let to_map = |i: &Item| match serde_json::to_value(i) {
        Ok(Value::Object(m)) => m,
        _ => unreachable!("an item serializes to an object"),
    };
    let (l, r) = (to_map(local), to_map(remote));
    let b = base.map(to_map).unwrap_or_default();
    let local_newer = local.modified >= remote.modified;
    let mut out = Map::new();
    let keys: std::collections::BTreeSet<&String> = l.keys().chain(r.keys()).collect();
    for k in keys {
        if matches!(k.as_str(), "history" | "modified" | "created") {
            continue;
        }
        let (lv, rv, bv) = (l.get(k), r.get(k), b.get(k));
        let pick = if lv == rv {
            lv
        } else if lv == bv {
            rv
        } else if rv == bv || local_newer {
            // Changed only here, or on both sides and here more recently.
            lv
        } else {
            rv
        };
        if let Some(v) = pick {
            out.insert(k.clone(), v.clone());
        }
    }
    // Required to read the item back; set properly below.
    for k in ["created", "modified"] {
        out.insert(k.into(), l[k].clone());
    }
    let mut merged: Item = serde_json::from_value(Value::Object(out)).unwrap_or_else(|_| if local_newer { local.clone() } else { remote.clone() });
    merged.created = local.created.min(remote.created);
    merged.modified = local.modified.max(remote.modified);
    // Both histories, plus whichever password lost.
    let mut history: Vec<HistoryEntry> = local.history.iter().chain(&remote.history).cloned().collect();
    history.sort_by_key(|h| std::cmp::Reverse(h.retired));
    merged.history.clear();
    for h in history {
        if !merged.history.iter().any(|x| x.password == h.password) {
            merged.history.push(h);
        }
    }
    for lost in [&local.password, &remote.password] {
        if *lost != merged.password {
            merged.retire_password(lost.clone(), merged.modified);
        }
    }
    merged.history.retain(|h| h.password != merged.password);
    merged.history.truncate(HISTORY_LIMIT);
    // Passkeys: those on both sides, plus those added on one side since the
    // base (one deleted on a side stays deleted); the higher counter wins.
    let in_base = |id: &str| base.is_some_and(|b| b.passkeys.iter().any(|p| p.credential_id == id));
    let mut passkeys: Vec<Passkey> = Vec::new();
    for p in local.passkeys.iter().chain(&remote.passkeys) {
        if passkeys.iter().any(|q| q.credential_id == p.credential_id) {
            continue;
        }
        let on_l = local.passkeys.iter().find(|q| q.credential_id == p.credential_id);
        let on_r = remote.passkeys.iter().find(|q| q.credential_id == p.credential_id);
        let keep = match (on_l, on_r) {
            (Some(_), Some(_)) => true,
            _ => !in_base(&p.credential_id),
        };
        if keep {
            let mut p = p.clone();
            p.counter = on_l.map_or(0, |q| q.counter).max(on_r.map_or(0, |q| q.counter));
            passkeys.push(p);
        }
    }
    merged.passkeys = passkeys;
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(s: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + s, 0).unwrap()
    }

    fn login(name: &str, user: &str, pw: &str) -> ItemData {
        ItemData { name: name.into(), username: user.into(), password: pw.into(), uris: vec![ItemUri::new("https://example.com")], ..Default::default() }
    }

    #[test]
    fn changing_the_password_keeps_the_old_one() {
        let mut i = Item::new(login("Example", "me", "one"), t(0));
        assert!(!i.apply(i.data(), t(1)), "no change");
        assert!(i.apply(login("Example", "me", "two"), t(2)));
        assert_eq!(i.history.len(), 1);
        assert_eq!(i.history[0].password, "one");
        assert_eq!(i.password_modified, Some(t(2)));
        i.apply(login("Example", "me", "one"), t(3));
        assert_eq!(i.history.iter().map(|h| h.password.as_str()).collect::<Vec<_>>(), ["two", "one"]);
    }

    #[test]
    fn unknown_fields_survive() {
        let json = r#"{"id":"x","name":"A","created":"2024-01-01T00:00:00Z","modified":"2024-01-01T00:00:00Z","sharing":[{"group":"family"}]}"#;
        let item: Item = serde_json::from_str(json).unwrap();
        assert_eq!(item.name, "A");
        let back = serde_json::to_string(&item).unwrap();
        assert!(back.contains(r#""sharing":[{"group":"family"}]"#));
    }

    #[test]
    fn merge_takes_each_sides_changes() {
        let base = Item::new(login("Example", "me", "pw"), t(0));
        let mut local = base.clone();
        local.apply(ItemData { notes: "local note".into(), ..base.data() }, t(10));
        let mut remote = base.clone();
        remote.apply(ItemData { username: "me@example.com".into(), ..base.data() }, t(5));
        let m = merge(Some(&base), &local, &remote);
        assert_eq!(m.notes, "local note");
        assert_eq!(m.username, "me@example.com");
        assert_eq!(m.modified, t(10));
    }

    #[test]
    fn merge_conflict_keeps_newer_and_remembers_losing_password() {
        let base = Item::new(login("Example", "me", "old"), t(0));
        let mut local = base.clone();
        local.apply(login("Example", "me", "local-pw"), t(10));
        let mut remote = base.clone();
        remote.apply(login("Example", "me", "remote-pw"), t(20));
        let m = merge(Some(&base), &local, &remote);
        assert_eq!(m.password, "remote-pw");
        let hist: Vec<&str> = m.history.iter().map(|h| h.password.as_str()).collect();
        assert!(hist.contains(&"local-pw") && hist.contains(&"old"), "{hist:?}");
        assert!(!hist.contains(&"remote-pw"));
    }

    #[test]
    fn folders_are_normalized() {
        assert_eq!(normalize_folder(" Work / Email/ "), "Work/Email");
        assert_eq!(normalize_folder("/"), "");
    }
}
