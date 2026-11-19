//! Which items belong to a web page.
//!
//! By default an item matches pages on the same *registrable domain*
//! (eTLD+1 from the Public Suffix List: `accounts.example.co.uk` and
//! `www.example.co.uk` share `example.co.uk`, but `a.github.io` and
//! `b.github.io` don't), as in Bitwarden, Apple Passwords and Chrome. An
//! item saved on the exact host ranks above one saved elsewhere on the
//! domain. Items can also be set to match by host, URL prefix, exact URL
//! or regular expression, or never, as in Bitwarden.
//!
//! Sites that share one sign-in across several domains (`envato.com` and
//! `themeforest.net`, …) come from Apple's password-manager-resources
//! (`data/shared-credentials.json`, MIT licensed); those match too, ranked
//! below the site's own items.
//!
//! A login saved for an `https` site is never offered on a plain `http`
//! page: that page could be an attacker on the network.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::item::{ItemUri, UriMatch};

/// A web page (or a saved address) taken apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub scheme: String,
    /// Lowercase, IDNA (punycode) form, no trailing dot.
    pub host: String,
    /// The port, or the scheme's default.
    pub port: Option<u16>,
    /// The registrable domain (eTLD+1), or the host for IP addresses and
    /// single-label names such as `localhost`.
    pub domain: String,
    /// The whole URL, normalized.
    pub url: String,
}

/// An address as typed or saved: a URL, or just a host (`example.com` is
/// taken as `https://example.com`). Only `http` and `https` addresses are
/// web pages.
pub fn parse_page(s: &str) -> Option<Page> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let full = if s.contains("://") { s.to_owned() } else { format!("https://{s}") };
    let url = url::Url::parse(&full).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let domain = registrable_domain(&host);
    Some(Page { scheme: url.scheme().to_owned(), port: url.port_or_known_default(), domain, host, url: url.to_string() })
}

/// `www.example.co.uk` → `example.co.uk`.
pub fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    match psl::domain_str(&host) {
        Some(d) => d.to_owned(),
        None => host,
    }
}

/// How well a saved address matches a page; better matches sort first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Quality {
    /// A different domain that shares sign-ins with it.
    Related = 1,
    /// Same registrable domain, other host.
    Domain = 2,
    /// Same host (or an exact, prefix or pattern match).
    Host = 3,
}

pub fn match_uri(saved: &ItemUri, page: &Page) -> Option<Quality> {
    let mode = saved.match_mode.unwrap_or(UriMatch::Domain);
    match mode {
        UriMatch::Never => None,
        UriMatch::Regex => {
            let re = regex_lite::Regex::new(&saved.uri).ok()?;
            re.is_match(&page.url).then_some(Quality::Host)
        }
        UriMatch::Exact => {
            let s = parse_page(&saved.uri)?;
            (secure_enough(&s, page) && s.url == page.url).then_some(Quality::Host)
        }
        UriMatch::StartsWith => {
            let s = parse_page(&saved.uri)?;
            (secure_enough(&s, page) && page.url.starts_with(&s.url)).then_some(Quality::Host)
        }
        UriMatch::Host => {
            let s = parse_page(&saved.uri)?;
            (secure_enough(&s, page) && s.host == page.host && s.port == page.port).then_some(Quality::Host)
        }
        UriMatch::Domain => {
            let s = parse_page(&saved.uri)?;
            if !secure_enough(&s, page) {
                return None;
            }
            // A saved port other than the scheme's default must match.
            let saved_port_explicit = url::Url::parse(&s.url).ok().and_then(|u| u.port()).is_some();
            if saved_port_explicit && s.port != page.port {
                return None;
            }
            if s.host == page.host {
                Some(Quality::Host)
            } else if s.domain == page.domain {
                Some(Quality::Domain)
            } else if shares_credentials(&s.domain, &page.domain) {
                Some(Quality::Related)
            } else {
                None
            }
        }
    }
}

/// An `https` login isn't offered on an `http` page.
fn secure_enough(saved: &Page, page: &Page) -> bool {
    !(saved.scheme == "https" && page.scheme == "http")
}

/// Whether a login for `saved` (a registrable domain) can be used on `page`
/// (another one), per Apple's list of sites sharing sign-ins.
pub fn shares_credentials(saved: &str, page: &str) -> bool {
    let s = shared();
    if let (Some(a), Some(b)) = (s.groups.get(saved), s.groups.get(page)) {
        if a == b {
            return true;
        }
    }
    s.from_to.iter().any(|(from, to)| from.iter().any(|d| d == saved) && to.iter().any(|d| d == page))
}

/// One key per site, for telling whether two logins are for the same site:
/// the registrable domain, or the group of domains sharing one sign-in
/// (`envato.com` and `themeforest.net` are one site).
pub fn site_key(domain: &str) -> String {
    match shared().groups.get(domain) {
        Some(g) => format!("shared:{g}"),
        None => domain.to_owned(),
    }
}

struct Shared {
    /// Domain → index of the group it shares sign-ins with.
    groups: HashMap<String, usize>,
    /// Sign-ins for the `from` domains work on the `to` domains.
    from_to: Vec<(Vec<String>, Vec<String>)>,
}

fn shared() -> &'static Shared {
    static SHARED: OnceLock<Shared> = OnceLock::new();
    SHARED.get_or_init(|| {
        #[derive(Deserialize)]
        struct Entry {
            #[serde(default)]
            shared: Vec<String>,
            #[serde(default)]
            from: Vec<String>,
            #[serde(default)]
            to: Vec<String>,
        }
        let entries: Vec<Entry> = serde_json::from_str(include_str!("../data/shared-credentials.json")).unwrap_or_default();
        let mut groups = HashMap::new();
        let mut from_to = Vec::new();
        for (i, e) in entries.into_iter().enumerate() {
            for d in e.shared {
                groups.insert(d.to_ascii_lowercase(), i);
            }
            if !e.from.is_empty() && !e.to.is_empty() {
                from_to.push((e.from, e.to));
            }
        }
        Shared { groups, from_to }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(u: &str) -> Page {
        parse_page(u).unwrap()
    }

    fn q(saved: &str, mode: Option<UriMatch>, url: &str) -> Option<Quality> {
        match_uri(&ItemUri { uri: saved.into(), match_mode: mode }, &page(url))
    }

    #[test]
    fn parsing() {
        let p = page("HTTPS://Accounts.Example.co.uk./login?x=1");
        assert_eq!(p.host, "accounts.example.co.uk");
        assert_eq!(p.domain, "example.co.uk");
        assert_eq!(p.port, Some(443));
        assert_eq!(page("example.com").scheme, "https");
        assert_eq!(page("http://192.168.1.1:8080").domain, "192.168.1.1");
        assert_eq!(page("http://localhost:3000").domain, "localhost");
        assert_eq!(page("https://bücher.de").host, "xn--bcher-kva.de");
        assert!(parse_page("androidapp://com.example").is_none());
        assert!(parse_page("javascript:alert(1)").is_none());
        assert!(parse_page("").is_none());
    }

    #[test]
    fn domain_matching() {
        assert_eq!(q("https://example.com", None, "https://example.com/login"), Some(Quality::Host));
        assert_eq!(q("https://example.com", None, "https://accounts.example.com/"), Some(Quality::Domain));
        assert_eq!(q("example.com", None, "https://www.example.com/"), Some(Quality::Domain));
        assert_eq!(q("https://example.com", None, "https://example.com.evil.net/"), None);
        assert_eq!(q("https://example.com", None, "https://notexample.com/"), None);
        // github.io is a public suffix: users' sites are separate domains.
        assert_eq!(q("https://alice.github.io", None, "https://mallory.github.io/"), None);
    }

    #[test]
    fn https_logins_stay_off_http_pages() {
        assert_eq!(q("https://example.com", None, "http://example.com/"), None);
        assert_eq!(q("http://example.com", None, "https://example.com/"), Some(Quality::Host));
        assert_eq!(q("http://router.local", None, "http://router.local/"), Some(Quality::Host));
    }

    #[test]
    fn ports() {
        assert_eq!(q("https://example.com:8443", None, "https://example.com/"), None);
        assert_eq!(q("https://example.com:8443", None, "https://example.com:8443/x"), Some(Quality::Host));
        assert_eq!(q("https://example.com", None, "https://example.com:8443/"), Some(Quality::Host));
    }

    #[test]
    fn other_modes() {
        assert_eq!(q("https://a.example.com", Some(UriMatch::Host), "https://b.example.com/"), None);
        assert_eq!(q("https://a.example.com", Some(UriMatch::Host), "https://a.example.com/x"), Some(Quality::Host));
        assert_eq!(q("https://example.com/app", Some(UriMatch::StartsWith), "https://example.com/app/login"), Some(Quality::Host));
        assert_eq!(q("https://example.com/app", Some(UriMatch::StartsWith), "https://example.com/other"), None);
        assert_eq!(q("https://example.com/a", Some(UriMatch::Exact), "https://example.com/a"), Some(Quality::Host));
        assert_eq!(q("https://example.com/a", Some(UriMatch::Exact), "https://example.com/a/b"), None);
        assert_eq!(q(r"^https://(www\.)?example\.com/", Some(UriMatch::Regex), "https://www.example.com/x"), Some(Quality::Host));
        assert_eq!(q("https://example.com", Some(UriMatch::Never), "https://example.com/"), None);
    }

    #[test]
    fn apples_shared_credentials() {
        assert!(shares_credentials("envato.com", "themeforest.net"));
        assert_eq!(q("https://envato.com", None, "https://themeforest.net/"), Some(Quality::Related));
        assert!(!shares_credentials("example.com", "themeforest.net"));
    }
}
