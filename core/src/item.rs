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
    /// A secure note (also what types from other password managers that
    /// have no kind here become, with their details as fields).
    Note,
    /// A Wi-Fi network, as in Apple's Passwords: `name` is the network's
    /// name and `password` its password. Never offered on websites, nor
    /// audited.
    Wifi,
    /// A payment card: its details are fields named as in [`CARD_DETAILS`].
    Card,
    /// An identity (name, address, contact, documents): fields named as in
    /// [`IDENTITY_DETAILS`].
    Identity,
    /// An SSH key: fields named as in [`SSH_KEY_DETAILS`]. Its public key
    /// and fingerprint are worked out from its private key when they can be
    /// (see [`crate::ssh`]).
    #[serde(rename = "sshkey")]
    SshKey,
}

/// One detail of a card, an identity or an SSH key: its key in Bitwarden's
/// format, the label of the item field it's kept in, whether it's shown as
/// dots, and whether the core works it out (not typed in the editors).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Detail {
    pub key: &'static str,
    pub label: &'static str,
    pub hidden: bool,
    pub computed: bool,
}

const fn detail(key: &'static str, label: &'static str, hidden: bool) -> Detail {
    Detail { key, label, hidden, computed: false }
}

pub const CARD_DETAILS: &[Detail] = &[
    detail("cardholderName", "Cardholder name", false),
    detail("brand", "Brand", false),
    detail("number", "Number", true),
    detail("expMonth", "Expiry month", false),
    detail("expYear", "Expiry year", false),
    detail("code", "Security code", true),
];

pub const IDENTITY_DETAILS: &[Detail] = &[
    detail("title", "Title", false),
    detail("firstName", "First name", false),
    detail("middleName", "Middle name", false),
    detail("lastName", "Last name", false),
    detail("company", "Company", false),
    detail("email", "Email", false),
    detail("phone", "Phone", false),
    detail("address1", "Address line 1", false),
    detail("address2", "Address line 2", false),
    detail("address3", "Address line 3", false),
    detail("city", "City", false),
    detail("state", "State or province", false),
    detail("postalCode", "Postal code", false),
    detail("country", "Country", false),
    detail("username", "User name", false),
    detail("ssn", "Social security number", true),
    detail("passportNumber", "Passport number", true),
    detail("licenseNumber", "License number", true),
];

pub const SSH_KEY_DETAILS: &[Detail] = &[
    detail("privateKey", crate::ssh::PRIVATE_KEY, true),
    detail("publicKey", crate::ssh::PUBLIC_KEY, false),
    Detail { key: "keyFingerprint", label: crate::ssh::FINGERPRINT, hidden: false, computed: true },
];

impl ItemKind {
    /// The details items of this kind have (none but for cards, identities
    /// and SSH keys).
    pub fn details(self) -> &'static [Detail] {
        match self {
            ItemKind::Card => CARD_DETAILS,
            ItemKind::Identity => IDENTITY_DETAILS,
            ItemKind::SshKey => SSH_KEY_DETAILS,
            _ => &[],
        }
    }
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
    /// Asks for Face ID (or the master password) again before its secrets
    /// are shown, copied or filled: Bitwarden's "master password re-prompt".
    pub reprompt: bool,
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
    pub reprompt: bool,
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
            reprompt: false,
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
            reprompt: self.reprompt,
            fields: self.fields.clone(),
        }
    }

    /// Sets the editable parts; a changed password goes into the history.
    /// Returns whether anything changed.
    pub fn apply(&mut self, data: ItemData, now: DateTime<Utc>) -> bool {
        let mut data = ItemData { name: data.name.trim().to_owned(), folder: normalize_folder(&data.folder), ..data };
        if data.kind == ItemKind::SshKey {
            data.fields = crate::ssh::complete(std::mem::take(&mut data.fields));
        }
        if data == self.data() {
            return false;
        }
        if data.password != self.password && !self.password.is_empty() {
            self.retire_password(self.password.clone(), now);
        }
        if data.password != self.password {
            self.password_modified = Some(now);
        }
        let ItemData { kind, name, username, password, uris, totp, notes, folder, favorite, reprompt, fields } = data;
        (self.kind, self.name, self.username, self.password, self.uris) = (kind, name, username, password, uris);
        (self.totp, self.notes, self.folder, self.favorite, self.fields) = (totp, notes, folder, favorite, fields);
        self.reprompt = reprompt;
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

    /// The registrable domains of the item's websites.
    fn domains(&self) -> std::collections::BTreeSet<String> {
        self.uris.iter().filter_map(|u| crate::matching::parse_page(&u.uri)).map(|p| p.domain).collect()
    }

    /// Whether `other` is the same login saved again, as browsers export a
    /// login once per host (`marktplaats.nl`, `www.marktplaats.nl`): a login
    /// with the same user name and password on the same site, and nothing
    /// that would be lost by merging it into this one (a different TOTP
    /// secret, notes, folder or custom fields).
    pub fn same_login(&self, other: &Item) -> bool {
        fn fits(a: &str, b: &str) -> bool {
            a.is_empty() || b.is_empty() || a == b
        }
        self.kind == ItemKind::Login
            && other.kind == ItemKind::Login
            && !self.password.is_empty()
            && self.password == other.password
            && self.username.trim().to_lowercase() == other.username.trim().to_lowercase()
            && !self.domains().is_disjoint(&other.domains())
            && fits(&self.totp, &other.totp)
            && fits(self.notes.trim(), other.notes.trim())
            && fits(&self.folder, &other.folder)
            && (self.fields.is_empty() || other.fields.is_empty() || self.fields == other.fields)
    }

    /// Merges in a [`same_login`](Self::same_login) item: its websites,
    /// passkeys and old passwords, and what this one lacks. Returns whether
    /// anything changed.
    pub fn absorb(&mut self, other: &Item, now: DateTime<Utc>) -> bool {
        let before = (self.data(), self.history.len(), self.passkeys.len());
        let key = |u: &ItemUri| (crate::matching::parse_page(&u.uri).map(|p| p.url).unwrap_or_else(|| u.uri.trim().to_owned()), u.match_mode);
        for u in &other.uris {
            if !self.uris.iter().any(|v| key(v) == key(u)) {
                self.uris.push(u.clone());
            }
        }
        // Keep a name someone gave it over one made from a host.
        let hosts: Vec<String> = self.uris.iter().filter_map(|u| crate::matching::parse_page(&u.uri)).flat_map(|p| [p.host, p.domain]).collect();
        let generated = |n: &str| n.trim().is_empty() || hosts.iter().any(|h| h.eq_ignore_ascii_case(n.trim()));
        if generated(&self.name) && !generated(&other.name) {
            self.name = other.name.trim().to_owned();
        }
        for (mine, theirs) in [(&mut self.totp, &other.totp), (&mut self.notes, &other.notes), (&mut self.folder, &other.folder)] {
            if mine.trim().is_empty() {
                mine.clone_from(theirs);
            }
        }
        if self.fields.is_empty() {
            self.fields.clone_from(&other.fields);
        }
        self.favorite |= other.favorite;
        self.reprompt |= other.reprompt;
        for p in &other.passkeys {
            if !self.passkeys.iter().any(|q| q.credential_id == p.credential_id) {
                self.passkeys.push(p.clone());
            }
        }
        for h in &other.history {
            if h.password != self.password && !self.history.iter().any(|g| g.password == h.password) {
                self.history.push(h.clone());
            }
        }
        self.history.sort_by_key(|h| std::cmp::Reverse(h.retired));
        self.history.truncate(HISTORY_LIMIT);
        let changed = before != (self.data(), self.history.len(), self.passkeys.len());
        if changed {
            self.modified = now;
        }
        changed
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
