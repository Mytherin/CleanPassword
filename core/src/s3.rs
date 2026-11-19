//! S3: the client CleanPassword shares with CleanNotes, from the
//! `cleanbucket` crate (in the CleanNotes repository, pinned to a revision in
//! `core/Cargo.toml`). Signed GET, HEAD, conditional PUT, DELETE and listing,
//! over a [`Transport`] the app supplies, so the same code runs in Chrome (on
//! `fetch`) and on iOS (on a native HTTP client).
//!
//! Writes are conditional: `If-Match: <etag>` for updates and
//! `If-None-Match: *` for new objects, so S3 refuses a write based on an
//! outdated copy instead of losing another device's change.
//!
//! This module re-exports the crate under the names the rest of the core,
//! and the Chrome and iOS bindings, use, and opens it on a vault's
//! [`S3Config`] and [`AwsCredentials`].

pub use cleanbucket::s3::{
    canonical_query, sha256_hex, sign, uri_encode, Client, Cond, Credentials, HttpRequest, HttpResponse, Listed, Location, Object, Put, S3Error, Signed, Transport,
};

use crate::vault::{AwsCredentials, S3Config};

impl S3Config {
    /// Where the vault is, as the S3 client takes it.
    pub fn location(&self) -> Location {
        Location { bucket: self.bucket.clone(), region: self.region.clone(), prefix: self.prefix.clone(), endpoint: self.endpoint.clone() }
    }
}

impl AwsCredentials {
    /// The access key, as the S3 client takes it (wiped when dropped).
    pub fn for_client(&self) -> Credentials {
        Credentials { access_key_id: self.access_key_id.clone(), secret_access_key: self.secret_access_key.clone(), session_token: self.session_token.clone() }
    }
}

impl From<cleanbucket::Error> for crate::Error {
    fn from(e: cleanbucket::Error) -> Self {
        match e {
            cleanbucket::Error::Network(m) => crate::Error::Network(m),
            cleanbucket::Error::S3(e) => crate::Error::S3(e),
            cleanbucket::Error::Invalid(m) => crate::Error::Invalid(m),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;

    /// The "GET Object" example from AWS's Signature Version 4 docs, through
    /// the shared client's signer.
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
    fn settings_and_errors_carry_over() {
        let c = S3Config { bucket: "b".into(), region: "eu-west-1".into(), prefix: "Vault/".into(), endpoint: None };
        assert_eq!(c.location().root(), "Vault/");
        let k = AwsCredentials { access_key_id: "AKIA".into(), secret_access_key: "s".into(), session_token: Some("t".into()) };
        assert_eq!(k.for_client().session_token.as_deref(), Some("t"));
        let e: crate::Error = cleanbucket::Error::Network("offline".into()).into();
        assert!(matches!(e, crate::Error::Network(_)));
        let e = S3Error { status: 301, code: "PermanentRedirect".into(), message: String::new(), region: Some("eu-west-1".into()) };
        assert!(e.to_string().contains("eu-west-1"));
    }
}
