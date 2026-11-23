//! CleanPassword's core for the Chrome extension, as WebAssembly. Only the
//! extension's service worker loads it: content scripts in web pages never
//! see the vault (see `extension/README.md`).
//!
//! Values cross as plain JS objects (serde); errors as `Error`s whose
//! message is fit to show, with `name` set to `WrongPassword` when that's
//! what it is.
//!
//! Syncing needs a `fetch`-like function from JavaScript:
//! `({method, url, headers: [[k, v]], body: Uint8Array}) =>
//! Promise<{status, headers: [[k, v]], body: Uint8Array}>`, which must not
//! follow redirects.

use std::cell::RefCell;
use std::rc::Rc;

use cleanpassword_core::import::{self, ImportedItem};
use cleanpassword_core::s3::{HttpRequest, HttpResponse, Transport};
use cleanpassword_core::sync::{self, SyncReport};
use cleanpassword_core::vault::{self, VaultHeader};
use cleanpassword_core::passkey::PasskeyTarget;
use cleanpassword_core::{generator, passkey, rules, totp, AwsCredentials, Error, ItemData, S3Config, Vault};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

fn to_js<T: Serialize + ?Sized>(v: &T) -> Result<JsValue, JsError> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible()).map_err(|e| JsError::new(&e.to_string()))
}

fn from_js<T: DeserializeOwned>(v: JsValue) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(v).map_err(|e| JsError::new(&format!("bad argument: {e}")))
}

/// A JS `Error` with the message; `name` is `WrongPassword` for a wrong
/// password, so the UI can tell.
fn err(e: Error) -> JsValue {
    let js = js_sys::Error::new(&e.to_string());
    if matches!(e, Error::WrongPassword) {
        js.set_name("WrongPassword");
    }
    js.into()
}

fn bad(e: JsError) -> JsValue {
    e.into()
}

/// A transport over a JS function.
struct JsTransport(js_sys::Function);

#[derive(Serialize)]
struct JsRequest<'a> {
    method: &'a str,
    url: &'a str,
    headers: &'a [(String, String)],
}

#[derive(Deserialize)]
struct JsResponse {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Transport for JsTransport {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let obj = to_js(&JsRequest { method: &req.method, url: &req.url, headers: &req.headers }).map_err(|_| "request".to_string())?;
        js_sys::Reflect::set(&obj, &"body".into(), &js_sys::Uint8Array::from(req.body.as_slice()).into()).map_err(|_| "request body".to_string())?;
        let promise = self.0.call1(&JsValue::NULL, &obj).map_err(js_message)?;
        let resp = JsFuture::from(js_sys::Promise::from(promise)).await.map_err(js_message)?;
        let body = js_sys::Reflect::get(&resp, &"body".into()).map_err(js_message)?;
        let body = if body.is_undefined() || body.is_null() { Vec::new() } else { js_sys::Uint8Array::new(&body).to_vec() };
        let r: JsResponse = serde_wasm_bindgen::from_value(resp).map_err(|e| e.to_string())?;
        Ok(HttpResponse { status: r.status, headers: r.headers, body })
    }
}

fn js_message(v: JsValue) -> String {
    v.dyn_ref::<js_sys::Error>().map(|e| String::from(e.message())).or_else(|| v.as_string()).unwrap_or_else(|| "network error".into())
}

/// An unlocked vault. Calls must not overlap a running `sync` (the service
/// worker queues them).
#[wasm_bindgen]
pub struct Session {
    vault: Rc<RefCell<Option<Vault>>>,
}

fn session(v: Vault) -> Session {
    Session { vault: Rc::new(RefCell::new(Some(v))) }
}

type JsResult<T> = Result<T, JsValue>;

impl Session {
    fn with<T>(&self, f: impl FnOnce(&Vault) -> T) -> JsResult<T> {
        let b = self.vault.borrow();
        let v = b.as_ref().ok_or_else(|| bad(JsError::new("the vault is busy syncing")))?;
        Ok(f(v))
    }

    fn with_mut<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> JsResult<T> {
        let mut b = self.vault.borrow_mut();
        let v = b.as_mut().ok_or_else(|| bad(JsError::new("the vault is busy syncing")))?;
        Ok(f(v))
    }
}

#[derive(Serialize)]
struct HeaderInfo {
    /// `vault.json` as text, to pass to `Session.join`.
    header: String,
    etag: String,
}

#[derive(Serialize)]
struct ImportResult {
    added: usize,
    skipped: usize,
    merged: usize,
    warnings: Vec<String>,
}

#[wasm_bindgen]
impl Session {
    /// A new vault (`config`: `{bucket, region, prefix, endpoint?}`,
    /// `credentials`: `{access_key_id, secret_access_key, session_token?}`).
    pub fn create(config: JsValue, credentials: JsValue, password: &str) -> JsResult<Session> {
        let config: S3Config = from_js(config).map_err(bad)?;
        let credentials: AwsCredentials = from_js(credentials).map_err(bad)?;
        Vault::create(config, credentials, password).map(session).map_err(err)
    }

    /// Joins the vault in a folder (`header` and `etag` from `fetchHeader`).
    pub fn join(config: JsValue, credentials: JsValue, header: &str, etag: &str, password: &str) -> JsResult<Session> {
        let config: S3Config = from_js(config).map_err(bad)?;
        let credentials: AwsCredentials = from_js(credentials).map_err(bad)?;
        let header: VaultHeader = serde_json::from_str(header).map_err(|e| bad(JsError::new(&e.to_string())))?;
        Vault::join(config, credentials, header, etag.to_owned(), password).map(session).map_err(err)
    }

    pub fn unlock(saved: &str, password: &str) -> JsResult<Session> {
        Vault::unlock(saved, password).map(session).map_err(err)
    }

    #[wasm_bindgen(js_name = unlockWithKey)]
    pub fn unlock_with_key(saved: &str, key: &str) -> JsResult<Session> {
        Vault::unlock_with_key(saved, key).map(session).map_err(err)
    }

    /// The string to keep in `chrome.storage.local` (all secrets sealed).
    pub fn save(&self) -> JsResult<String> {
        self.with(|v| v.save())
    }

    /// The vault key, for `chrome.storage.session` while unlocked.
    #[wasm_bindgen(js_name = keyB64)]
    pub fn key_b64(&self) -> JsResult<String> {
        self.with(|v| v.key_b64().to_string())
    }

    pub fn items(&self) -> JsResult<JsValue> {
        self.with(|v| to_js(&v.items()))?.map_err(bad)
    }

    pub fn trash(&self) -> JsResult<JsValue> {
        self.with(|v| to_js(&v.trash()))?.map_err(bad)
    }

    pub fn get(&self, id: &str) -> JsResult<JsValue> {
        self.with(|v| to_js(&v.get(id)))?.map_err(bad)
    }

    pub fn folders(&self) -> JsResult<JsValue> {
        self.with(|v| to_js(&v.folders()))?.map_err(bad)
    }

    pub fn search(&self, query: &str) -> JsResult<JsValue> {
        self.with(|v| to_js(&v.search(query)))?.map_err(bad)
    }

    /// Logins for a page, best first: `[{id, name, username, quality}]`.
    pub fn matches(&self, url: &str) -> JsResult<JsValue> {
        self.with(|v| to_js(&v.matches(url)))?.map_err(bad)
    }

    /// Every login saved for a page, passkey-only ones too (see
    /// `Vault::site_logins`): `[{id, name, username, quality}]`.
    #[wasm_bindgen(js_name = siteLogins)]
    pub fn site_logins(&self, url: &str) -> JsResult<JsValue> {
        self.with(|v| to_js(&v.site_logins(url)))?.map_err(bad)
    }

    pub fn audit(&self) -> JsResult<JsValue> {
        self.with(|v| to_js(&v.audit()))?.map_err(bad)
    }

    /// How many logins `mergeDuplicates` would merge into others.
    pub fn duplicates(&self) -> JsResult<usize> {
        self.with(|v| v.duplicates())
    }

    /// Merges logins saved more than once for one site (once per host, as
    /// browsers export them); the others go to the trash. Returns how many.
    #[wasm_bindgen(js_name = mergeDuplicates)]
    pub fn merge_duplicates(&self) -> JsResult<usize> {
        self.with_mut(|v| v.merge_duplicates())
    }

    pub fn add(&self, data: JsValue) -> JsResult<String> {
        let data: ItemData = from_js(data).map_err(bad)?;
        self.with_mut(|v| v.add(data))?.map_err(err)
    }

    pub fn update(&self, id: &str, data: JsValue) -> JsResult<bool> {
        let data: ItemData = from_js(data).map_err(bad)?;
        self.with_mut(|v| v.update(id, data))?.map_err(err)
    }

    pub fn delete(&self, id: &str) -> JsResult<()> {
        self.with_mut(|v| v.delete(id))?.map_err(err)
    }

    pub fn restore(&self, id: &str) -> JsResult<()> {
        self.with_mut(|v| v.restore(id))?.map_err(err)
    }

    pub fn purge(&self, id: &str) -> JsResult<()> {
        self.with_mut(|v| v.purge(id))?.map_err(err)
    }

    /// The current TOTP code of an item: `{code, period, remaining}`.
    pub fn totp(&self, id: &str) -> JsResult<JsValue> {
        let secret = self.with(|v| v.get(id).map(|i| i.totp.clone()))?.ok_or_else(|| bad(JsError::new("no such item")))?;
        to_js(&totp::code(&secret, now_secs()).map_err(err)?).map_err(bad)
    }

    /// Imports a Bitwarden JSON/CSV or other CSV export:
    /// `{added, skipped, warnings}`.
    #[wasm_bindgen(js_name = importFile)]
    pub fn import_file(&self, text: &str, password: Option<String>) -> JsResult<JsValue> {
        let imported = import::import_file(text, password.as_deref()).map_err(err)?;
        let warnings = imported.warnings;
        let items: Vec<ImportedItem> = imported.items;
        let s = self.with_mut(|v| v.import(items))?;
        to_js(&ImportResult { added: s.added, skipped: s.skipped, merged: s.merged, warnings }).map_err(bad)
    }

    /// Every item as an unencrypted Bitwarden JSON export.
    #[wasm_bindgen(js_name = exportJson)]
    pub fn export_json(&self) -> JsResult<String> {
        self.with(|v| import::export_bitwarden_json(&v.items()))
    }

    #[wasm_bindgen(js_name = changeMasterPassword)]
    pub fn change_master_password(&self, current: &str, new: &str) -> JsResult<()> {
        self.with_mut(|v| v.change_master_password(current, new))?.map_err(err)
    }

    #[wasm_bindgen(js_name = setCredentials)]
    pub fn set_credentials(&self, credentials: JsValue) -> JsResult<()> {
        let c: AwsCredentials = from_js(credentials).map_err(bad)?;
        self.with_mut(|v| v.set_credentials(c))?.map_err(err)
    }

    pub fn config(&self) -> JsResult<JsValue> {
        self.with(|v| to_js(v.config()))?.map_err(bad)
    }

    /// The access key ID (never the secret).
    #[wasm_bindgen(js_name = accessKeyId)]
    pub fn access_key_id(&self) -> JsResult<String> {
        self.with(|v| v.credentials().access_key_id.clone())
    }

    #[wasm_bindgen(js_name = hasUnsyncedChanges)]
    pub fn has_unsynced_changes(&self) -> JsResult<bool> {
        self.with(|v| v.has_unsynced_changes())
    }

    #[wasm_bindgen(js_name = lastSync)]
    pub fn last_sync(&self) -> JsResult<Option<String>> {
        self.with(|v| v.last_sync().map(|t| t.to_rfc3339()))
    }

    // ---- Passkeys (byte strings cross as base64url) -------------------------

    /// The passkeys for a relying party (limited to `allow`, credential ids,
    /// if not empty): `[{item_id, item_name, credential_id, user_name,
    /// user_display_name}]`.
    #[wasm_bindgen(js_name = passkeysFor)]
    pub fn passkeys_for(&self, rp_id: &str, allow: Vec<String>) -> JsResult<JsValue> {
        let allow = decode_all(&allow)?;
        self.with(|v| to_js(&v.passkeys_for(rp_id, &allow)))?.map_err(bad)
    }

    /// Whether one of the site's existing credentials (`exclude`) is here.
    #[wasm_bindgen(js_name = passkeyExcluded)]
    pub fn passkey_excluded(&self, rp_id: &str, exclude: Vec<String>) -> JsResult<bool> {
        let exclude = decode_all(&exclude)?;
        self.with(|v| v.passkey_excluded(rp_id, &exclude))
    }

    /// Creates a passkey (`request`: `{rp_id, rp_name, user_handle,
    /// user_name, user_display_name}`), on `item_id` (the login the user
    /// chose), or on a new login without one:
    /// `{item_id, credential_id, attestation_object, authenticator_data,
    /// public_key}`.
    #[wasm_bindgen(js_name = createPasskey)]
    pub fn create_passkey(&self, request: JsValue, item_id: Option<String>) -> JsResult<JsValue> {
        #[derive(Deserialize)]
        struct Req {
            rp_id: String,
            #[serde(default)]
            rp_name: String,
            user_handle: String,
            #[serde(default)]
            user_name: String,
            #[serde(default)]
            user_display_name: String,
        }
        let r: Req = from_js(request).map_err(bad)?;
        let req = passkey::NewPasskey {
            rp_id: r.rp_id,
            rp_name: r.rp_name,
            user_handle: passkey::unb64(&r.user_handle).map_err(err)?,
            user_name: r.user_name,
            user_display_name: r.user_display_name,
        };
        let target = item_id.as_deref().filter(|s| !s.is_empty()).map_or(PasskeyTarget::New, PasskeyTarget::Item);
        let reg = self.with_mut(|v| v.create_passkey_on(&req, target))?.map_err(err)?;
        to_js(&serde_json::json!({
            "item_id": reg.item_id,
            "credential_id": passkey::b64url(&reg.credential_id),
            "attestation_object": passkey::b64url(&reg.attestation_object),
            "authenticator_data": passkey::b64url(&reg.authenticator_data),
            "public_key": passkey::b64url(&reg.public_key),
        }))
        .map_err(bad)
    }

    /// Signs in with a passkey: `{credential_id, authenticator_data,
    /// signature, user_handle}`.
    #[wasm_bindgen(js_name = assertPasskey)]
    pub fn assert_passkey(&self, item_id: &str, credential_id: &str, rp_id: &str, client_data_hash: &str) -> JsResult<JsValue> {
        let id = passkey::unb64(credential_id).map_err(err)?;
        let hash = passkey::unb64(client_data_hash).map_err(err)?;
        let a = self.with_mut(|v| v.assert_passkey(item_id, &id, rp_id, &hash))?.map_err(err)?;
        to_js(&serde_json::json!({
            "credential_id": passkey::b64url(&a.credential_id),
            "authenticator_data": passkey::b64url(&a.authenticator_data),
            "signature": passkey::b64url(&a.signature),
            "user_handle": passkey::b64url(&a.user_handle),
        }))
        .map_err(bad)
    }

    #[wasm_bindgen(js_name = deletePasskey)]
    pub fn delete_passkey(&self, item_id: &str, credential_id: &str) -> JsResult<()> {
        self.with_mut(|v| v.delete_passkey(item_id, credential_id))?.map_err(err)
    }

    /// Syncs with S3; resolves to the report. Other calls fail while it
    /// runs.
    /// `progress(done, total)`, if given, hears how many of the items to
    /// download have come so far.
    pub fn sync(&self, fetch: js_sys::Function, progress: Option<js_sys::Function>) -> js_sys::Promise {
        let cell = self.vault.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let taken = cell.borrow_mut().take();
            let mut vault = taken.ok_or_else(|| bad(JsError::new("a sync is already running")))?;
            let mut report = |done: usize, total: usize| {
                if let Some(f) = &progress {
                    let _ = f.call2(&JsValue::NULL, &JsValue::from(done as u32), &JsValue::from(total as u32));
                }
            };
            let result: Result<SyncReport, Error> = vault.sync_with_progress(&JsTransport(fetch), &mut report).await;
            *cell.borrow_mut() = Some(vault);
            match result {
                Ok(report) => to_js(&report).map_err(bad),
                Err(e) => Err(err(e)),
            }
        })
    }
}

/// `vault.json` in the folder (`{header, etag}`), or `null` if there's no
/// vault there yet.
#[wasm_bindgen(js_name = fetchHeader)]
pub fn fetch_header(config: JsValue, credentials: JsValue, fetch: js_sys::Function) -> js_sys::Promise {
    wasm_bindgen_futures::future_to_promise(async move {
        let config: S3Config = from_js(config).map_err(bad)?;
        let credentials: AwsCredentials = from_js(credentials).map_err(bad)?;
        match sync::fetch_header(&JsTransport(fetch), &config, &credentials).await {
            Ok(None) => Ok(JsValue::NULL),
            Ok(Some((h, etag))) => to_js(&HeaderInfo { header: serde_json::to_string(&h).expect("header"), etag }).map_err(bad),
            Err(e) => Err(err(e)),
        }
    })
}

/// The S3 settings of a saved vault, without unlocking it.
#[wasm_bindgen(js_name = lockedInfo)]
pub fn locked_info(saved: &str) -> JsResult<JsValue> {
    to_js(&vault::locked_info(saved).map_err(err)?).map_err(bad)
}

/// A password from a recipe: `{kind: "apple"}`, `{kind: "random", length,
/// lowercase, uppercase, digits, symbols, avoid_ambiguous}` or
/// `{kind: "passphrase", words, separator, capitalize, number}`.
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(recipe: JsValue) -> JsResult<String> {
    let recipe: generator::Recipe = from_js(recipe).map_err(bad)?;
    generator::generate(&recipe).map_err(err)
}


/// A user name from a recipe: `{kind: "word", capitalize, number}`,
/// `{kind: "plusAddress", email}` or `{kind: "catchAll", domain}`.
#[wasm_bindgen(js_name = generateUsername)]
pub fn generate_username(recipe: JsValue) -> JsResult<String> {
    let recipe: generator::UsernameRecipe = from_js(recipe).map_err(bad)?;
    generator::generate_username(&recipe).map_err(err)
}
/// A password for a site, following its known rules (or its
/// `passwordrules` attribute, if given).
#[wasm_bindgen(js_name = generateForSite)]
pub fn generate_for_site(host: &str, password_rules: Option<String>) -> String {
    match password_rules.filter(|r| !r.trim().is_empty()) {
        Some(r) => generator::generate_with_rules(&rules::Rules::parse(&r)),
        None => generator::generate_for_site(host),
    }
}

/// `{bits, score}` (score 0–4).
#[wasm_bindgen]
pub fn strength(password: &str) -> JsResult<JsValue> {
    to_js(&generator::strength(password)).map_err(bad)
}

#[wasm_bindgen(js_name = totpCode)]
pub fn totp_code(secret: &str) -> JsResult<JsValue> {
    to_js(&totp::code(secret, now_secs()).map_err(err)?).map_err(bad)
}

#[wasm_bindgen(js_name = importNeedsPassword)]
pub fn import_needs_password(text: &str) -> bool {
    import::needs_password(text)
}

/// The registrable domain of a host (`www.example.co.uk` → `example.co.uk`).
#[wasm_bindgen(js_name = registrableDomain)]
pub fn registrable_domain(host: &str) -> String {
    cleanpassword_core::matching::registrable_domain(host)
}

fn decode_all(ids: &[String]) -> JsResult<Vec<Vec<u8>>> {
    ids.iter().map(|s| passkey::unb64(s).map_err(err)).collect()
}

/// The client data JSON a browser would make for a passkey request.
#[wasm_bindgen(js_name = clientDataJson)]
pub fn client_data_json(kind: &str, challenge: &str, origin: &str, cross_origin: bool) -> JsResult<String> {
    Ok(passkey::client_data_json(kind, &passkey::unb64(challenge).map_err(err)?, origin, cross_origin))
}

/// Whether a page at `origin` may use passkeys for `rp_id`.
#[wasm_bindgen(js_name = rpIdAllowed)]
pub fn rp_id_allowed(rp_id: &str, origin: &str) -> bool {
    passkey::rp_id_allowed(rp_id, origin)
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
