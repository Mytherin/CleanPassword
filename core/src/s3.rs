//! A small S3 client: signed GET, conditional PUT, DELETE and listing,
//! over a [`Transport`] the app supplies, so the same code runs in Chrome
//! (on `fetch`) and on iOS (on a native HTTP client).
//!
//! Requests are signed with AWS Signature Version 4 (as in CleanNotes; the
//! AWS SDK needs an async runtime and doesn't build for WebAssembly).
//! Writes are conditional: `If-Match: <etag>` for updates and
//! `If-None-Match: *` for new objects, so S3 refuses a write based on an
//! outdated copy instead of losing another device's change (S3 has
//! supported both since 2024; Cloudflare R2 and MinIO do too).

use std::future::Future;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::vault::{AwsCredentials, S3Config};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    /// Lowercase names. `host` isn't among them: it follows from the URL
    /// (and browsers refuse to set it).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Sends HTTP requests. Must not follow redirects (S3 answers a request
/// for a bucket in another region with one, and the signature doesn't
/// carry over); return the 3xx response instead.
pub trait Transport {
    fn send(&self, request: HttpRequest) -> impl Future<Output = std::result::Result<HttpResponse, String>>;
}

/// An error S3 answered with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Error {
    pub status: u16,
    pub code: String,
    pub message: String,
    /// The bucket's region, when S3 named it.
    pub region: Option<String>,
}

impl S3Error {
    /// The access key itself is refused (wrong, deleted or expired).
    pub fn is_auth(&self) -> bool {
        matches!(self.code.as_str(), "InvalidAccessKeyId" | "SignatureDoesNotMatch" | "InvalidToken" | "ExpiredToken")
    }
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.status, self.code.as_str()) {
            (301 | 307, _) | (_, "PermanentRedirect" | "TemporaryRedirect" | "AuthorizationHeaderMalformed") => match &self.region {
                Some(r) => write!(f, "the bucket is in region {r}; enter that as its region"),
                None => write!(f, "the bucket is in another region than the one entered ({} {})", self.status, self.code),
            },
            (_, "NoSuchBucket") => f.write_str("there's no bucket with that name"),
            (_, "AccessDenied") => write!(f, "S3 denied access; check that the IAM policy allows this bucket and folder ({})", self.message),
            (_, "InvalidAccessKeyId") => f.write_str("S3 doesn't know that access key ID"),
            (_, "SignatureDoesNotMatch") => f.write_str("S3 refused the secret access key"),
            (_, "InvalidToken" | "ExpiredToken") => f.write_str("the session token is invalid or has expired"),
            (_, "RequestTimeTooSkewed") => f.write_str("this device's clock is off, so S3 refuses the request"),
            (s, "") => write!(f, "S3 answered {s}"),
            (s, c) => write!(f, "S3 answered {s} {c}: {}", self.message),
        }
    }
}

impl std::error::Error for S3Error {}

/// A conditional write.
#[derive(Clone, Copy, Debug)]
pub enum Cond<'a> {
    /// Only if the object is still at this ETag.
    Match(&'a str),
    /// Only if there's no such object yet.
    Absent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Put {
    Stored { etag: String },
    /// Refused: the object changed (or appeared, or is gone) since.
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub data: Vec<u8>,
    pub etag: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    /// Relative to the folder.
    pub name: String,
    pub etag: String,
    pub modified: Option<DateTime<Utc>>,
}

pub struct Client<'a, T: Transport> {
    config: &'a S3Config,
    credentials: &'a AwsCredentials,
    transport: &'a T,
}

impl<'a, T: Transport> Client<'a, T> {
    pub fn new(config: &'a S3Config, credentials: &'a AwsCredentials, transport: &'a T) -> Self {
        Client { config, credentials, transport }
    }

    /// The key prefix: the folder with a trailing `/`, or nothing.
    fn root(&self) -> String {
        let p = self.config.prefix.trim().trim_matches('/');
        if p.is_empty() {
            String::new()
        } else {
            format!("{p}/")
        }
    }

    /// Base URL and encoded path for a key (`""` for the bucket itself).
    fn url_parts(&self, key: &str) -> (String, String) {
        let key = uri_encode(key, true);
        let bucket = uri_encode(&self.config.bucket, false);
        let region = self.config.region.trim();
        match self.config.endpoint.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
            Some(e) => (e.trim_end_matches('/').to_owned(), format!("/{bucket}/{key}")),
            // A bucket name with dots doesn't match the wildcard certificate.
            None if self.config.bucket.contains('.') => (format!("https://s3.{region}.amazonaws.com"), format!("/{bucket}/{key}")),
            None => (format!("https://{}.s3.{region}.amazonaws.com", self.config.bucket), format!("/{key}")),
        }
    }

    async fn request(&self, method: &str, key: &str, query: &[(String, String)], body: Vec<u8>, extra: &[(&str, String)]) -> Result<HttpResponse> {
        let (base, path) = self.url_parts(key);
        let q = canonical_query(query);
        let full = if q.is_empty() { format!("{base}{path}") } else { format!("{base}{path}?{q}") };
        let url = url::Url::parse(&full).map_err(|_| Error::invalid(format!("the S3 address {full} isn't valid")))?;
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        let payload = sha256_hex(&body);
        let mut signed_headers = vec![("host", host), ("x-amz-content-sha256", payload.clone())];
        if let Some(t) = self.credentials.session_token.as_deref().filter(|t| !t.is_empty()) {
            signed_headers.push(("x-amz-security-token", t.to_owned()));
        }
        let signed = sign(
            method,
            &path,
            &q,
            &signed_headers,
            &payload,
            self.credentials.access_key_id.trim(),
            self.credentials.secret_access_key.trim(),
            self.config.region.trim(),
            Utc::now(),
        );
        let mut headers: Vec<(String, String)> = signed_headers.into_iter().filter(|(k, _)| *k != "host").map(|(k, v)| (k.to_owned(), v)).collect();
        headers.push(("x-amz-date".into(), signed.amz_date));
        headers.push(("authorization".into(), signed.authorization));
        headers.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
        let req = HttpRequest { method: method.to_owned(), url: full, headers, body };
        self.transport.send(req).await.map_err(Error::Network)
    }

    pub async fn get(&self, name: &str) -> Result<Option<Object>> {
        let key = format!("{}{name}", self.root());
        let r = self.request("GET", &key, &[], Vec::new(), &[]).await?;
        if r.status == 404 && error_code(&r) != "NoSuchBucket" {
            return Ok(None);
        }
        if !r.ok() {
            return Err(s3_error(&r).into());
        }
        let etag = r.header("etag").ok_or_else(|| Error::invalid("S3 sent no ETag"))?.to_owned();
        Ok(Some(Object { data: r.body, etag }))
    }

    pub async fn put(&self, name: &str, data: Vec<u8>, cond: Cond<'_>) -> Result<Put> {
        let key = format!("{}{name}", self.root());
        let c = match cond {
            Cond::Match(e) => ("if-match", e.to_owned()),
            Cond::Absent => ("if-none-match", "*".to_owned()),
        };
        let r = self.request("PUT", &key, &[], data, &[("content-type", "application/octet-stream".into()), c]).await?;
        if matches!(r.status, 404 | 409 | 412) && error_code(&r) != "NoSuchBucket" {
            return Ok(Put::Conflict);
        }
        if !r.ok() {
            return Err(s3_error(&r).into());
        }
        let etag = r.header("etag").ok_or_else(|| Error::invalid("S3 sent no ETag"))?.to_owned();
        Ok(Put::Stored { etag })
    }

    pub async fn delete(&self, name: &str) -> Result<()> {
        let key = format!("{}{name}", self.root());
        let r = self.request("DELETE", &key, &[], Vec::new(), &[]).await?;
        if !r.ok() && r.status != 404 {
            return Err(s3_error(&r).into());
        }
        Ok(())
    }

    /// Every object whose name (relative to the folder) starts with
    /// `prefix`.
    pub async fn list(&self, prefix: &str) -> Result<Vec<Listed>> {
        let root = self.root();
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut q = vec![("list-type".to_owned(), "2".to_owned()), ("prefix".to_owned(), format!("{root}{prefix}"))];
            if let Some(t) = &token {
                q.push(("continuation-token".to_owned(), t.clone()));
            }
            let r = self.request("GET", "", &q, Vec::new(), &[]).await?;
            if !r.ok() {
                return Err(s3_error(&r).into());
            }
            let xml = String::from_utf8_lossy(&r.body);
            for c in xml_tags(&xml, "Contents") {
                let (Some(key), Some(etag)) = (xml_tag(c, "Key"), xml_tag(c, "ETag")) else { continue };
                let key = decode(key);
                let Some(name) = key.strip_prefix(&root) else { continue };
                let modified = xml_tag(c, "LastModified").and_then(|m| DateTime::parse_from_rfc3339(m).ok()).map(|t| t.with_timezone(&Utc));
                out.push(Listed { name: name.to_owned(), etag: decode(etag), modified });
            }
            match (xml_tag(&xml, "IsTruncated"), xml_tag(&xml, "NextContinuationToken")) {
                (Some("true"), Some(t)) => token = Some(decode(t)),
                _ => return Ok(out),
            }
        }
    }
}

fn error_code(r: &HttpResponse) -> String {
    xml_tag(&String::from_utf8_lossy(&r.body), "Code").map(decode).unwrap_or_default()
}

fn s3_error(r: &HttpResponse) -> S3Error {
    let body = String::from_utf8_lossy(&r.body);
    let region = r.header("x-amz-bucket-region").map(str::to_owned).or_else(|| xml_tag(&body, "Region").map(decode)).filter(|s| !s.is_empty());
    S3Error { status: r.status, code: error_code(r), message: xml_tag(&body, "Message").map(decode).unwrap_or_default(), region }
}

// ---- Signature Version 4 ----------------------------------------------------

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// URI-encodes as AWS wants: everything but unreserved characters, and `/`
/// too unless `keep_slash`.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The canonical query string: pairs encoded and sorted.
pub fn canonical_query(params: &[(String, String)]) -> String {
    let mut enc: Vec<(String, String)> = params.iter().map(|(k, v)| (uri_encode(k, false), uri_encode(v, false))).collect();
    enc.sort();
    enc.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

pub struct Signed {
    pub authorization: String,
    pub amz_date: String,
}

/// Signs a request. `path` is the encoded path, `query` the canonical query
/// string, and `headers` the headers to sign (including `host` and
/// `x-amz-content-sha256`; `x-amz-date` is added).
#[allow(clippy::too_many_arguments)]
pub fn sign(method: &str, path: &str, query: &str, headers: &[(&str, String)], payload_hash: &str, access_key: &str, secret_key: &str, region: &str, now: DateTime<Utc>) -> Signed {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let mut hs: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_lowercase(), v.trim().to_owned())).collect();
    hs.push(("x-amz-date".into(), amz_date.clone()));
    hs.sort();
    let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = hs.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let canonical = format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let k = hmac(format!("AWS4{secret_key}").as_bytes(), &date);
    let k = hmac(&k, region);
    let k = hmac(&k, "s3");
    let k = hmac(&k, "aws4_request");
    let signature = hex(&hmac(&k, &to_sign));
    Signed { authorization: format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope},SignedHeaders={signed_headers},Signature={signature}"), amz_date }
}

// ---- XML ------------------------------------------------------------------

fn xml_tag<'x>(xml: &'x str, tag: &str) -> Option<&'x str> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(&xml[start..end])
}

fn xml_tags<'x>(xml: &'x str, tag: &str) -> Vec<&'x str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else { break };
        out.push(&after[..j]);
        rest = &after[j + close.len()..];
    }
    out
}

/// XML character references and the predefined entities.
fn decode(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        let Some(end) = after.find(';') else {
            out.push_str(after);
            return out;
        };
        let ent = &after[1..end];
        let c = match ent {
            "quot" => Some('"'),
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "apos" => Some('\''),
            _ if ent.starts_with("#x") => u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32),
            _ if ent.starts_with('#') => ent[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match c {
            Some(c) => out.push(c),
            None => out.push_str(&after[..=end]),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

// ---- An in-memory S3 for tests ------------------------------------------------

#[cfg(test)]
pub(crate) mod fake {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    /// Enough of S3 for the sync engine: objects with ETags, conditional
    /// PUTs, listing (with paging), and a switch to fail requests.
    #[derive(Default)]
    pub struct FakeS3 {
        pub objects: RefCell<BTreeMap<String, (Vec<u8>, String)>>,
        counter: RefCell<u64>,
        pub fail: RefCell<bool>,
        pub requests: RefCell<Vec<String>>,
        /// Keys per listing page.
        pub page: usize,
    }

    impl FakeS3 {
        pub fn new() -> FakeS3 {
            FakeS3 { page: 2, ..Default::default() }
        }

        fn key_of(url: &url::Url) -> String {
            // Virtual-hosted style: the path is the key.
            let p = url.path().trim_start_matches('/');
            percent_decode(p)
        }
    }

    fn percent_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    fn resp(status: u16, headers: Vec<(String, String)>, body: impl Into<Vec<u8>>) -> HttpResponse {
        HttpResponse { status, headers, body: body.into() }
    }

    impl Transport for FakeS3 {
        async fn send(&self, req: HttpRequest) -> std::result::Result<HttpResponse, String> {
            if *self.fail.borrow() {
                return Err("offline".into());
            }
            let url = url::Url::parse(&req.url).unwrap();
            assert!(req.headers.iter().any(|(k, v)| k == "authorization" && v.starts_with("AWS4-HMAC-SHA256 ")));
            let key = Self::key_of(&url);
            self.requests.borrow_mut().push(format!("{} {key}", req.method));
            let header = |n: &str| req.headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
            let mut objects = self.objects.borrow_mut();
            match req.method.as_str() {
                "GET" if key.is_empty() => {
                    let q: BTreeMap<String, String> = url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
                    let prefix = q.get("prefix").cloned().unwrap_or_default();
                    let after = q.get("continuation-token").cloned().unwrap_or_default();
                    let keys: Vec<&String> = objects.keys().filter(|k| k.starts_with(&prefix) && **k > after).collect();
                    let page: Vec<&String> = keys.iter().take(self.page).copied().collect();
                    let mut xml = String::from("<ListBucketResult>");
                    for k in &page {
                        let etag = &objects[*k].1;
                        xml += &format!("<Contents><Key>{k}</Key><LastModified>2024-01-01T00:00:00.000Z</LastModified><ETag>{}</ETag></Contents>", etag.replace('"', "&quot;"));
                    }
                    if keys.len() > page.len() {
                        xml += &format!("<IsTruncated>true</IsTruncated><NextContinuationToken>{}</NextContinuationToken>", page.last().unwrap());
                    } else {
                        xml += "<IsTruncated>false</IsTruncated>";
                    }
                    xml += "</ListBucketResult>";
                    Ok(resp(200, vec![], xml))
                }
                "GET" => match objects.get(&key) {
                    Some((data, etag)) => Ok(resp(200, vec![("ETag".into(), etag.clone())], data.clone())),
                    None => Ok(resp(404, vec![], "<Error><Code>NoSuchKey</Code></Error>")),
                },
                "PUT" => {
                    let current = objects.get(&key).map(|(_, e)| e.clone());
                    if header("if-none-match").as_deref() == Some("*") && current.is_some() {
                        return Ok(resp(412, vec![], "<Error><Code>PreconditionFailed</Code></Error>"));
                    }
                    if let Some(m) = header("if-match") {
                        match current {
                            None => return Ok(resp(404, vec![], "<Error><Code>NoSuchKey</Code></Error>")),
                            Some(c) if c != m => return Ok(resp(412, vec![], "<Error><Code>PreconditionFailed</Code></Error>")),
                            _ => {}
                        }
                    }
                    *self.counter.borrow_mut() += 1;
                    let etag = format!("\"etag-{}\"", self.counter.borrow());
                    objects.insert(key, (req.body, etag.clone()));
                    Ok(resp(200, vec![("ETag".into(), etag)], ""))
                }
                "DELETE" => {
                    objects.remove(&key);
                    Ok(resp(204, vec![], ""))
                }
                m => panic!("unexpected {m}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The "GET Object" example from AWS's Signature Version 4 docs.
    #[test]
    fn aws_documented_example() {
        let now = DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z").unwrap().with_timezone(&Utc);
        let empty = sha256_hex(b"");
        let s = sign(
            "GET",
            "/test.txt",
            "",
            &[("host", "examplebucket.s3.amazonaws.com".into()), ("range", "bytes=0-9".into()), ("x-amz-content-sha256", empty.clone())],
            &empty,
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            now,
        );
        assert_eq!(
            s.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn query_and_xml() {
        assert_eq!(canonical_query(&[("prefix".into(), "My Vault/".into()), ("list-type".into(), "2".into())]), "list-type=2&prefix=My%20Vault%2F");
        assert_eq!(decode("&quot;abc&quot; &amp; &#x41;&#66;"), "\"abc\" & AB");
        assert_eq!(xml_tags("<a>1</a><a>2</a>", "a"), vec!["1", "2"]);
    }

    #[test]
    fn errors_read_well() {
        let e = S3Error { status: 301, code: "PermanentRedirect".into(), message: String::new(), region: Some("eu-west-1".into()) };
        assert!(e.to_string().contains("eu-west-1"));
        assert!(S3Error { status: 403, code: "InvalidAccessKeyId".into(), message: String::new(), region: None }.is_auth());
    }
}
