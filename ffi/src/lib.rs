//! CleanPassword's core for Swift: the iPhone app and its AutoFill
//! extension use the same vault, encryption, sync, generator and matching
//! as the Chrome extension, through these bindings (UniFFI;
//! `ios/build-rust.sh` builds the library and generates the Swift).
//!
//! - [`VaultSession`]: an unlocked vault. Its methods are quick except
//!   [`VaultSession::sync`], which blocks on the network: call it off the
//!   main thread.
//! - Free functions: checking an S3 folder for a vault, the generator,
//!   strength, one-time codes, and what can be known of a locked vault.
//!
//! Dates cross as Unix seconds.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use chrono::{DateTime, Utc};
use cleanpassword_core::generator::{self, Recipe};
use cleanpassword_core::import;
use cleanpassword_core::item::{Field, ItemData, ItemKind, ItemUri, UriMatch};
use cleanpassword_core::matching::Quality;
use cleanpassword_core::passkey::{self, NewPasskey, PasskeyTarget};
use cleanpassword_core::s3::{HttpRequest, HttpResponse, Transport};
use cleanpassword_core::sync::{self, SyncReport};
use cleanpassword_core::vault::{self, VaultHeader};
use cleanpassword_core::{totp, AwsCredentials, Error, Item, S3Config, Vault};

uniffi::setup_scaffolding!();

// ---- Errors -----------------------------------------------------------------------

#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    WrongPassword,
    /// The S3 folder holds another vault.
    DifferentVault,
    Failed { message: String },
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::WrongPassword => f.write_str("wrong master password"),
            CoreError::DifferentVault => f.write_str("this S3 folder holds a different vault"),
            CoreError::Failed { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<Error> for CoreError {
    fn from(e: Error) -> Self {
        match e {
            Error::WrongPassword => CoreError::WrongPassword,
            Error::DifferentVault => CoreError::DifferentVault,
            e => CoreError::Failed { message: e.to_string() },
        }
    }
}

type R<T> = Result<T, CoreError>;

// ---- Records ------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct S3Settings {
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub endpoint: Option<String>,
}

impl From<S3Settings> for S3Config {
    fn from(s: S3Settings) -> Self {
        S3Config { bucket: s.bucket, region: s.region, prefix: s.prefix, endpoint: s.endpoint.filter(|e| !e.trim().is_empty()) }
    }
}

impl From<&S3Config> for S3Settings {
    fn from(c: &S3Config) -> Self {
        S3Settings { bucket: c.bucket.clone(), region: c.region.clone(), prefix: c.prefix.clone(), endpoint: c.endpoint.clone() }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct AwsKeys {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl From<AwsKeys> for AwsCredentials {
    fn from(k: AwsKeys) -> Self {
        AwsCredentials { access_key_id: k.access_key_id, secret_access_key: k.secret_access_key, session_token: k.session_token }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Kind {
    Login,
    Note,
}

/// How a website is matched (Bitwarden's options).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Matching {
    Default,
    Domain,
    Host,
    StartsWith,
    Exact,
    Regex,
    Never,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct Website {
    pub uri: String,
    pub matching: Matching,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}

/// What people edit in an item.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ItemFields {
    pub kind: Kind,
    pub name: String,
    pub username: String,
    pub password: String,
    pub websites: Vec<Website>,
    pub totp: String,
    pub notes: String,
    pub folder: String,
    pub favorite: bool,
    pub fields: Vec<CustomField>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct OldPassword {
    pub password: String,
    pub retired: i64,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct VaultItem {
    pub id: String,
    pub fields: ItemFields,
    pub history: Vec<OldPassword>,
    pub created: i64,
    pub modified: i64,
    pub deleted: Option<i64>,
    pub passkeys: Vec<PasskeyInfo>,
}

/// A passkey on an item (without its private key).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PasskeyInfo {
    /// base64url, as the core keeps it (to delete it by).
    pub id: String,
    /// The raw credential id, as iOS wants it.
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    pub created: i64,
}

/// A passkey offered for signing in.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PasskeyOption {
    pub item_id: String,
    pub item_name: String,
    pub credential_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
}

/// A new passkey, for iOS's registration answer.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PasskeyRegistration {
    pub item_id: String,
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// A passkey sign-in, for iOS's assertion answer.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PasskeySignature {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct SuggestedLogin {
    pub id: String,
    pub name: String,
    pub username: String,
    /// Saved for this very host (rather than elsewhere on its domain, or
    /// a site sharing its sign-ins).
    pub exact: bool,
    /// A different site that shares sign-ins with this one.
    pub related: bool,
}

#[derive(Clone, Debug, Default, PartialEq, uniffi::Record)]
pub struct SyncResult {
    pub downloaded: u64,
    pub uploaded: u64,
    pub removed: u64,
    pub merged: u64,
    pub pending: u64,
    pub password_changed_elsewhere: bool,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct OneTimeCode {
    pub code: String,
    pub period: u64,
    pub remaining: u64,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ImportOutcome {
    pub added: u64,
    pub skipped: u64,
    /// Logins merged into one already here for another host of the site.
    pub merged: u64,
    /// Passkeys brought in.
    pub passkeys: u64,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct AuditFinding {
    pub id: String,
    pub name: String,
    pub weak: bool,
    pub reused: u64,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct Strength {
    pub bits: f64,
    /// 0 (very weak) to 4 (very strong).
    pub score: u8,
}

/// `vault.json` found in an S3 folder.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct RemoteVault {
    pub header_json: String,
    pub etag: String,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct LockedVault {
    pub settings: S3Settings,
    pub vault_id: String,
    pub last_sync: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum PasswordRecipe {
    /// `xxxxxx-xxxxxx-xxxxxx`, as Safari suggests.
    Apple,
    Random { length: u32, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, avoid_ambiguous: bool },
    Passphrase { words: u32, separator: String, capitalize: bool, number: bool },
}

// ---- Conversions ----------------------------------------------------------------------

fn secs(t: DateTime<Utc>) -> i64 {
    t.timestamp()
}

fn matching_of(m: Option<UriMatch>) -> Matching {
    match m {
        None => Matching::Default,
        Some(UriMatch::Domain) => Matching::Domain,
        Some(UriMatch::Host) => Matching::Host,
        Some(UriMatch::StartsWith) => Matching::StartsWith,
        Some(UriMatch::Exact) => Matching::Exact,
        Some(UriMatch::Regex) => Matching::Regex,
        Some(UriMatch::Never) => Matching::Never,
    }
}

fn uri_match(m: Matching) -> Option<UriMatch> {
    match m {
        Matching::Default => None,
        Matching::Domain => Some(UriMatch::Domain),
        Matching::Host => Some(UriMatch::Host),
        Matching::StartsWith => Some(UriMatch::StartsWith),
        Matching::Exact => Some(UriMatch::Exact),
        Matching::Regex => Some(UriMatch::Regex),
        Matching::Never => Some(UriMatch::Never),
    }
}

impl From<ItemFields> for ItemData {
    fn from(f: ItemFields) -> Self {
        ItemData {
            kind: if f.kind == Kind::Note { ItemKind::Note } else { ItemKind::Login },
            name: f.name,
            username: f.username,
            password: f.password,
            uris: f.websites.into_iter().map(|w| ItemUri { uri: w.uri, match_mode: uri_match(w.matching) }).collect(),
            totp: f.totp,
            notes: f.notes,
            folder: f.folder,
            favorite: f.favorite,
            fields: f.fields.into_iter().map(|c| Field { name: c.name, value: c.value, hidden: c.hidden }).collect(),
        }
    }
}

fn item_record(i: &Item) -> VaultItem {
    VaultItem {
        id: i.id.clone(),
        fields: ItemFields {
            kind: if i.kind == ItemKind::Note { Kind::Note } else { Kind::Login },
            name: i.name.clone(),
            username: i.username.clone(),
            password: i.password.clone(),
            websites: i.uris.iter().map(|u| Website { uri: u.uri.clone(), matching: matching_of(u.match_mode) }).collect(),
            totp: i.totp.clone(),
            notes: i.notes.clone(),
            folder: i.folder.clone(),
            favorite: i.favorite,
            fields: i.fields.iter().map(|f| CustomField { name: f.name.clone(), value: f.value.clone(), hidden: f.hidden }).collect(),
        },
        history: i.history.iter().map(|h| OldPassword { password: h.password.clone(), retired: secs(h.retired) }).collect(),
        created: secs(i.created),
        modified: secs(i.modified),
        deleted: i.deleted.map(secs),
        passkeys: i
            .passkeys
            .iter()
            .map(|p| PasskeyInfo {
                id: p.credential_id.clone(),
                credential_id: passkey::unb64(&p.credential_id).unwrap_or_default(),
                rp_id: p.rp_id.clone(),
                rp_name: p.rp_name.clone(),
                user_name: p.user_name.clone(),
                user_handle: passkey::unb64(&p.user_handle).unwrap_or_default(),
                created: secs(p.created),
            })
            .collect(),
    }
}

impl From<SyncReport> for SyncResult {
    fn from(r: SyncReport) -> Self {
        SyncResult {
            downloaded: r.downloaded as u64,
            uploaded: r.uploaded as u64,
            removed: r.removed as u64,
            merged: r.merged as u64,
            pending: r.pending as u64,
            password_changed_elsewhere: r.password_changed_elsewhere,
        }
    }
}

fn code_record(c: totp::Code) -> OneTimeCode {
    OneTimeCode { code: c.code, period: c.period, remaining: c.remaining }
}

fn suggested(m: vault::Match) -> SuggestedLogin {
    SuggestedLogin { id: m.id, name: m.name, username: m.username, exact: m.quality == Quality::Host, related: m.quality == Quality::Related }
}

fn now() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

// ---- HTTP -------------------------------------------------------------------------------

fn client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("CleanPassword/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client")
    })
}

struct Http;

impl Transport for Http {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes()).map_err(|e| e.to_string())?;
        let mut b = client().request(method, &req.url);
        for (k, v) in &req.headers {
            b = b.header(k, v);
        }
        if req.method != "GET" && req.method != "HEAD" {
            b = b.body(req.body);
        }
        let resp = b.send().map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let headers = resp.headers().iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_owned())).collect();
        let body = resp.bytes().map_err(|e| e.to_string())?.to_vec();
        Ok(HttpResponse { status, headers, body })
    }
}

// ---- The vault -----------------------------------------------------------------------------

/// An unlocked vault.
#[derive(uniffi::Object)]
pub struct VaultSession {
    vault: Mutex<Vault>,
}

impl VaultSession {
    fn new(v: Vault) -> Arc<Self> {
        Arc::new(VaultSession { vault: Mutex::new(v) })
    }

    fn v(&self) -> MutexGuard<'_, Vault> {
        self.vault.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[uniffi::export]
impl VaultSession {
    /// A new, empty vault; the first sync uploads it.
    #[uniffi::constructor]
    pub fn create(settings: S3Settings, keys: AwsKeys, password: String) -> R<Arc<Self>> {
        Ok(Self::new(Vault::create(settings.into(), keys.into(), &password)?))
    }

    /// Joins the vault found in a folder ([`fetch_remote_vault`]); sync to
    /// download its items.
    #[uniffi::constructor]
    pub fn join(settings: S3Settings, keys: AwsKeys, remote: RemoteVault, password: String) -> R<Arc<Self>> {
        let header: VaultHeader = serde_json::from_str(&remote.header_json).map_err(|e| CoreError::Failed { message: e.to_string() })?;
        Ok(Self::new(Vault::join(settings.into(), keys.into(), header, remote.etag, &password)?))
    }

    #[uniffi::constructor]
    pub fn unlock(saved: String, password: String) -> R<Arc<Self>> {
        Ok(Self::new(Vault::unlock(&saved, &password)?))
    }

    /// With the vault key from the keychain (Face ID).
    #[uniffi::constructor]
    pub fn unlock_with_key(saved: String, key: String) -> R<Arc<Self>> {
        Ok(Self::new(Vault::unlock_with_key(&saved, &key)?))
    }

    /// What to keep on the device (everything secret is sealed).
    pub fn save(&self) -> String {
        self.v().save()
    }

    /// Takes in what the other process (the app, or its AutoFill
    /// extension) saved since this one last read or saved the vault, so
    /// neither overwrites the other's changes. Returns how many items
    /// changed.
    pub fn absorb(&self, saved: String) -> R<u64> {
        Ok(self.v().absorb(&saved)? as u64)
    }

    /// The vault key, for the keychain (behind Face ID).
    pub fn key(&self) -> String {
        self.v().key_b64().to_string()
    }

    pub fn items(&self) -> Vec<VaultItem> {
        self.v().items().into_iter().map(item_record).collect()
    }

    pub fn trash(&self) -> Vec<VaultItem> {
        self.v().trash().into_iter().map(item_record).collect()
    }

    pub fn get(&self, id: String) -> Option<VaultItem> {
        self.v().get(&id).map(item_record)
    }

    pub fn folders(&self) -> Vec<String> {
        self.v().folders()
    }

    pub fn search(&self, query: String) -> Vec<VaultItem> {
        self.v().search(&query).into_iter().map(item_record).collect()
    }

    /// Logins to fill for a website (a URL or a domain, as AutoFill gives
    /// them), best first; not those that are only a passkey.
    pub fn matches(&self, url: String) -> Vec<SuggestedLogin> {
        self.v().matches(&url).into_iter().map(suggested).collect()
    }

    /// Every login for a website, passkey-only ones too: those a new
    /// passkey can go on.
    pub fn site_logins(&self, url: String) -> Vec<SuggestedLogin> {
        self.v().site_logins(&url).into_iter().map(suggested).collect()
    }

    pub fn add(&self, fields: ItemFields) -> R<String> {
        Ok(self.v().add(fields.into())?)
    }

    pub fn update(&self, id: String, fields: ItemFields) -> R<bool> {
        Ok(self.v().update(&id, fields.into())?)
    }

    pub fn delete(&self, id: String) -> R<()> {
        Ok(self.v().delete(&id)?)
    }

    pub fn restore(&self, id: String) -> R<()> {
        Ok(self.v().restore(&id)?)
    }

    pub fn purge(&self, id: String) -> R<()> {
        Ok(self.v().purge(&id)?)
    }

    pub fn totp(&self, id: String) -> Option<OneTimeCode> {
        let secret = self.v().get(&id).map(|i| i.totp.clone()).filter(|t| !t.is_empty())?;
        totp::code(&secret, now()).ok().map(code_record)
    }

    pub fn audit(&self) -> Vec<AuditFinding> {
        self.v().audit().into_iter().map(|a| AuditFinding { id: a.id, name: a.name, weak: a.weak, reused: a.reused as u64 }).collect()
    }

    /// How many logins `merge_duplicates` would merge into others.
    pub fn duplicates(&self) -> u64 {
        self.v().duplicates() as u64
    }

    /// Merges logins saved more than once for one site (once per host, as
    /// browsers export them); the others go to the trash. Returns how many.
    pub fn merge_duplicates(&self) -> u64 {
        self.v().merge_duplicates() as u64
    }

    /// Imports a Bitwarden (JSON, password-protected JSON, CSV) or other CSV
    /// export.
    pub fn import_file(&self, text: String, password: Option<String>) -> R<ImportOutcome> {
        let imported = import::import_file(&text, password.as_deref())?;
        let s = self.v().import(imported.items);
        Ok(ImportOutcome { added: s.added as u64, skipped: s.skipped as u64, merged: s.merged as u64, passkeys: s.passkeys as u64, warnings: imported.warnings })
    }

    /// Everything as an unencrypted Bitwarden JSON export.
    pub fn export_json(&self) -> String {
        import::export_bitwarden_json(&self.v().items())
    }

    pub fn change_master_password(&self, current: String, new_password: String) -> R<()> {
        Ok(self.v().change_master_password(&current, &new_password)?)
    }

    pub fn set_keys(&self, keys: AwsKeys) -> R<()> {
        Ok(self.v().set_credentials(keys.into())?)
    }

    pub fn settings(&self) -> S3Settings {
        self.v().config().into()
    }

    pub fn access_key_id(&self) -> String {
        self.v().credentials().access_key_id.clone()
    }

    pub fn has_unsynced_changes(&self) -> bool {
        self.v().has_unsynced_changes()
    }

    pub fn last_sync(&self) -> Option<i64> {
        self.v().last_sync().map(secs)
    }

    // ---- Passkeys (for the AutoFill extension) ------------------------------

    /// The passkeys for a relying party, limited to `allowed` credential ids
    /// if not empty.
    pub fn passkeys_for(&self, rp_id: String, allowed: Vec<Vec<u8>>) -> Vec<PasskeyOption> {
        self.v()
            .passkeys_for(&rp_id, &allowed)
            .into_iter()
            .map(|c| PasskeyOption {
                item_id: c.item_id,
                item_name: c.item_name,
                credential_id: passkey::unb64(&c.credential_id).unwrap_or_default(),
                user_name: c.user_name,
                user_display_name: c.user_display_name,
            })
            .collect()
    }

    /// Whether one of the site's credentials for the account is here already.
    pub fn passkey_excluded(&self, rp_id: String, excluded: Vec<Vec<u8>>) -> bool {
        self.v().passkey_excluded(&rp_id, &excluded)
    }

    /// Creates a passkey and saves it on a login: `item_id`, the one the
    /// user chose, or `None` for a new login ("A New Login").
    pub fn create_passkey(&self, rp_id: String, rp_name: String, user_handle: Vec<u8>, user_name: String, user_display_name: String, item_id: Option<String>) -> R<PasskeyRegistration> {
        let req = NewPasskey { rp_id, rp_name, user_handle, user_name, user_display_name };
        let r = self.v().create_passkey_on(&req, item_id.as_deref().map_or(PasskeyTarget::New, PasskeyTarget::Item))?;
        Ok(PasskeyRegistration { item_id: r.item_id, credential_id: r.credential_id, attestation_object: r.attestation_object })
    }

    /// Signs in with a passkey; `client_data_hash` is what iOS hands over.
    pub fn assert_passkey(&self, item_id: String, credential_id: Vec<u8>, rp_id: String, client_data_hash: Vec<u8>) -> R<PasskeySignature> {
        let a = self.v().assert_passkey(&item_id, &credential_id, &rp_id, &client_data_hash)?;
        Ok(PasskeySignature { credential_id: a.credential_id, authenticator_data: a.authenticator_data, signature: a.signature, user_handle: a.user_handle })
    }

    /// Removes a passkey (`id` as in [`PasskeyInfo::id`]).
    pub fn delete_passkey(&self, item_id: String, id: String) -> R<()> {
        Ok(self.v().delete_passkey(&item_id, &id)?)
    }

    /// Syncs with S3. Blocks on the network: call it off the main thread.
    pub fn sync(&self) -> R<SyncResult> {
        let mut v = self.v();
        Ok(pollster::block_on(v.sync(&Http))?.into())
    }
}

// ---- Free functions -----------------------------------------------------------------------

/// The vault in an S3 folder, if there's one. Blocks on the network.
#[uniffi::export]
pub fn fetch_remote_vault(settings: S3Settings, keys: AwsKeys) -> R<Option<RemoteVault>> {
    let found = pollster::block_on(sync::fetch_header(&Http, &settings.into(), &keys.into()))?;
    Ok(found.map(|(h, etag)| RemoteVault { header_json: serde_json::to_string(&h).expect("header serializes"), etag }))
}

/// What can be shown of a saved vault without unlocking it.
#[uniffi::export]
pub fn locked_vault(saved: String) -> Option<LockedVault> {
    vault::locked_info(&saved).ok().map(|i| LockedVault { settings: (&i.config).into(), vault_id: i.vault_id, last_sync: i.last_sync.map(secs) })
}

#[uniffi::export]
pub fn generate_password(recipe: PasswordRecipe) -> R<String> {
    let r = match recipe {
        PasswordRecipe::Apple => Recipe::Apple,
        PasswordRecipe::Random { length, lowercase, uppercase, digits, symbols, avoid_ambiguous } => Recipe::Random { length, lowercase, uppercase, digits, symbols, avoid_ambiguous },
        PasswordRecipe::Passphrase { words, separator, capitalize, number } => Recipe::Passphrase { words, separator, capitalize, number },
    };
    Ok(generator::generate(&r)?)
}

/// A password for a website, following its known rules.
#[uniffi::export]
pub fn generate_for_site(host: String) -> String {
    generator::generate_for_site(&host)
}

#[uniffi::export]
pub fn password_strength(password: String) -> Strength {
    let s = generator::strength(&password);
    Strength { bits: s.bits, score: s.score }
}

#[uniffi::export]
pub fn one_time_code(secret: String) -> R<OneTimeCode> {
    Ok(code_record(totp::code(&secret, now())?))
}

#[uniffi::export]
pub fn is_valid_totp(secret: String) -> bool {
    totp::is_valid(&secret)
}

#[uniffi::export]
pub fn import_needs_password(text: String) -> bool {
    import::needs_password(&text)
}

#[uniffi::export]
pub fn registrable_domain(host: String) -> String {
    cleanpassword_core::matching::registrable_domain(&host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> S3Settings {
        S3Settings { bucket: "b".into(), region: "us-east-1".into(), prefix: "P".into(), endpoint: None }
    }

    fn keys() -> AwsKeys {
        AwsKeys { access_key_id: "A".into(), secret_access_key: "S".into(), session_token: None }
    }

    fn login(name: &str, url: &str) -> ItemFields {
        ItemFields {
            kind: Kind::Login,
            name: name.into(),
            username: "me".into(),
            password: "pw".into(),
            websites: vec![Website { uri: url.into(), matching: Matching::Default }],
            totp: "JBSWY3DPEHPK3PXP".into(),
            notes: String::new(),
            folder: "Work".into(),
            favorite: false,
            fields: vec![CustomField { name: "PIN".into(), value: "1234".into(), hidden: true }],
        }
    }

    #[test]
    fn a_vault_through_the_bindings() {
        let pw = "a long master password".to_string();
        let s = VaultSession::create(settings(), keys(), pw.clone()).unwrap();
        let id = s.add(login("Example", "https://example.com")).unwrap();
        let item = s.get(id.clone()).unwrap();
        assert_eq!(item.fields, login("Example", "https://example.com"));
        assert_eq!(s.matches("https://www.example.com/login".into()).len(), 1);
        assert!(s.matches("example.com".into())[0].exact, "AutoFill passes bare domains");
        assert_eq!(s.totp(id.clone()).unwrap().code.len(), 6);
        assert_eq!(s.folders(), vec!["Work".to_string()]);

        let saved = s.save();
        assert!(matches!(VaultSession::unlock(saved.clone(), "nope".into()), Err(CoreError::WrongPassword)));
        let again = VaultSession::unlock_with_key(saved.clone(), s.key()).unwrap();
        assert_eq!(again.items().len(), 1);
        let info = locked_vault(saved).unwrap();
        assert_eq!(info.settings, settings());
        assert!(locked_vault("garbage".into()).is_none());
    }

    #[test]
    fn passkeys_through_the_bindings() {
        let s = VaultSession::create(settings(), keys(), "a long master password".into()).unwrap();
        let r = s.create_passkey("example.com".into(), "Example".into(), b"user-1".to_vec(), "me@example.com".into(), "Me".into(), None).unwrap();
        assert_eq!(r.credential_id.len(), 16);
        let item = s.get(r.item_id.clone()).unwrap();
        assert_eq!(item.passkeys[0].credential_id, r.credential_id);
        assert_eq!(item.passkeys[0].user_handle, b"user-1");
        let options = s.passkeys_for("example.com".into(), vec![]);
        assert_eq!(options.len(), 1);
        assert!(s.passkey_excluded("example.com".into(), vec![r.credential_id.clone()]));
        let sig = s.assert_passkey(r.item_id.clone(), r.credential_id.clone(), "example.com".into(), vec![9; 32]).unwrap();
        assert_eq!(sig.user_handle, b"user-1");
        s.delete_passkey(r.item_id.clone(), item.passkeys[0].id.clone()).unwrap();
        assert!(s.passkeys_for("example.com".into(), vec![]).is_empty());

        // No item ("A New Login"): a new login, not the site's login that
        // has no user name (which would get this one's).
        let blank = s.add(ItemFields { username: String::new(), ..login("Example", "https://example.com") }).unwrap();
        let r2 = s.create_passkey("example.com".into(), "Example".into(), b"user-2".to_vec(), "two@example.com".into(), "Two".into(), None).unwrap();
        assert_ne!(r2.item_id, blank);
        assert_eq!(s.get(blank.clone()).unwrap().fields.username, "");
        assert!(s.get(blank).unwrap().passkeys.is_empty());
    }

    #[test]
    fn helpers() {
        assert_eq!(generate_password(PasswordRecipe::Apple).unwrap().len(), 20);
        assert!(generate_password(PasswordRecipe::Passphrase { words: 4, separator: " ".into(), capitalize: false, number: false }).unwrap().contains(' '));
        assert!(password_strength("password".into()).score == 0);
        assert!(is_valid_totp("JBSWY3DPEHPK3PXP".into()));
        assert_eq!(registrable_domain("a.b.example.co.uk".into()), "example.co.uk");
    }
}
