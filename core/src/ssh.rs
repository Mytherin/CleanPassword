//! SSH keys: what an [`ItemKind::SshKey`](crate::ItemKind::SshKey) item's
//! public key and fingerprint are, worked out from its keys.
//!
//! - An OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`) carries
//!   its public key unencrypted, even when the private key is protected by a
//!   passphrase: the item's public key is taken from it.
//! - The fingerprint is `ssh-keygen -l`'s: `SHA256:` and the base64 (without
//!   padding) of the SHA-256 of the public key's blob.
//!
//! Older formats (`BEGIN RSA PRIVATE KEY` and similar) aren't read: their
//! public key is whatever was typed or imported.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::item::{Field, SSH_KEY_DETAILS};

pub const PRIVATE_KEY: &str = "Private key";
pub const PUBLIC_KEY: &str = "Public key";
pub const FINGERPRINT: &str = "Fingerprint";

const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";
const MAGIC: &[u8] = b"openssh-key-v1\0";

/// Reads the SSH wire format's length-prefixed strings.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (n, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*n))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > self.0.len() {
            return None;
        }
        let (s, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(s)
    }
}

/// The key type a public key blob starts with (`ssh-ed25519`, `ssh-rsa`…).
fn blob_type(blob: &[u8]) -> Option<&str> {
    let t = std::str::from_utf8(Reader(blob).string()?).ok()?;
    (!t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic())).then_some(t)
}

/// The public key of an OpenSSH private key, as `<type> <base64>` (without
/// a comment); `None` if it isn't one.
pub fn public_key_from_private(private_key: &str) -> Option<String> {
    let s = private_key.trim();
    let body = s.strip_prefix(BEGIN)?.trim_end().strip_suffix(END)?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = STANDARD.decode(b64).ok()?;
    let mut r = Reader(bytes.strip_prefix(MAGIC)?);
    let (_cipher, _kdf, _kdf_options) = (r.string()?, r.string()?, r.string()?);
    if r.u32()? == 0 {
        return None;
    }
    let blob = r.string()?;
    Some(format!("{} {}", blob_type(blob)?, STANDARD.encode(blob)))
}

/// A public key's blob, from `<type> <base64> [comment]`; `None` if it
/// isn't one.
fn public_blob(public_key: &str) -> Option<Vec<u8>> {
    let mut parts = public_key.split_whitespace();
    let (kind, b64) = (parts.next()?, parts.next()?);
    let blob = STANDARD.decode(b64).ok()?;
    (blob_type(&blob)? == kind).then_some(blob)
}

/// A public key's fingerprint, as `ssh-keygen -l` shows it
/// (`SHA256:…`); `None` if it isn't a public key.
pub fn fingerprint(public_key: &str) -> Option<String> {
    let blob = public_blob(public_key)?;
    Some(format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob))))
}

/// An SSH key item's fields made whole: its details first, in order and
/// hidden as they should be; a private key file ending with a line break; the public key taken from an OpenSSH private
/// key (keeping a typed one's comment when it's the same key); and the
/// fingerprint of the public key, or none if there's no public key to take
/// it from.
pub fn complete(fields: Vec<Field>) -> Vec<Field> {
    let value = |label: &str| fields.iter().find(|f| f.name == label).map(|f| f.value.trim().to_owned()).filter(|v| !v.is_empty());
    // A key file ends with a line break: ssh refuses one without.
    let private = value(PRIVATE_KEY).map(|v| if v.starts_with("-----BEGIN ") { v + "\n" } else { v });
    let mut public = value(PUBLIC_KEY);
    if let Some(derived) = private.as_deref().and_then(public_key_from_private) {
        if public.as_deref().and_then(public_blob) != public_blob(&derived) {
            public = Some(derived);
        }
    }
    let fingerprint = public.as_deref().and_then(fingerprint);
    let mut out = Vec::new();
    for (spec, v) in SSH_KEY_DETAILS.iter().zip([private, public, fingerprint]) {
        if let Some(value) = v {
            out.push(Field { name: spec.label.into(), value, hidden: spec.hidden });
        }
    }
    out.extend(fields.into_iter().filter(|f| !SSH_KEY_DETAILS.iter().any(|d| d.label == f.name)));
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // `ssh-keygen -t ed25519 -C test@example.com -N ''`.
    pub(crate) const PRIVATE: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACCE/pc1EOIyYU1Sh8P6uh+HnKFVDyJhhXy7qixk8a4l7wAAAJhjSVCNY0lQ\njQAAAAtzc2gtZWQyNTUxOQAAACCE/pc1EOIyYU1Sh8P6uh+HnKFVDyJhhXy7qixk8a4l7w\nAAAEA/7ZuV0t1pgRX/N0GDN8F/GcKVNeLQMltowhAstQ4MEoT+lzUQ4jJhTVKHw/q6H4ec\noVUPImGFfLuqLGTxriXvAAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n";
    pub(crate) const PUBLIC: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIT+lzUQ4jJhTVKHw/q6H4ecoVUPImGFfLuqLGTxriXv test@example.com";
    pub(crate) const KEY_FINGERPRINT: &str = "SHA256:+/VgYdYRbJwZKgCRYaKZNh2IjC+SgEQZo+2XTL58vKM";
    // Another, with the passphrase "secret".
    const ENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABC/1kZl/Z\nLH9P2/bQzUSOJ8AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJAAYqhJEGojhABq\nlqAP0aIcjOBNrXow2EGDaRT/LX1RAAAAoCMp0mlTETPgDxKCQwFWNbsrzuS9k/ajYzc3gn\nMVpAaXT1Ljqk288PFUaYLP5G4tSOZZr7trYyLUftqOfQVnzbkvyr84b6WYqf39D3CTObd9\n9FBEfDJd9teVTbuf91DaPBhQBJUeEsopZQC1lYgPSA02BYC5pP7AYXcQLTwmpJWDo/mLMa\ne/hcZ44hGFuLNNM88m7THBPCzrXo7/yqOY1wM=\n-----END OPENSSH PRIVATE KEY-----\n";
    // `ssh-keygen -t rsa -m PEM`: the older format, not read.
    const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDNVl/NOvmmVExHG3EU870AqwvFa7UbkBFmHjx0yzM+VVdAEuT7\nnHXUAweGKGsVMDXmsY4/Hd84lN+78vo5s0d6fbpthsvkT3ROBgxDu6oDUrgpevZQ\nBXcsWOx/+iOWfJCLTa47SI2rp2wPMhZlMBaeRfJACBE6+AgSZoh+a158VQIDAQAB\nAoGAOvp8Oe6elm/QGPyA1ovL1c1LbEErm+cdmD9HDiTvaxAIJ5dFvh+KmILmPlqN\np2BZmxGU0fw6iX35ZXq89KXR+ZECUM60K7zdrhAChXM+1skhYcQfONSLngzn94zQ\nSe1UOk1lHugwHwCHKM/oZTUwLBpMVMxA7mw2n2iz7h6sbQECQQDzTt33+TeO6drR\nE0Ns3kxjQ6jglMvu6UW4pqFQ2tz3E3ccRLOzhJdu4Qvy2qLTdMSSOwmVnQnX9seR\nOKvRnIRdAkEA2AxyfsMVZqetOi/enGsvDEi5+SFCGxA0aLRY4mej5zaxKlkmyghv\n7ZtQZZ9ZFDV4gy+p33/n1bC9Z+zVSP7YWQJBALpADTrd0+Hasl6J2HtmUCNMj+Ib\nBWGFwJFxPNugLrYUeIFzNfyd6y49p9/n7ezg3fjyqIuXAwoHJw3Ly/tRTSECQQCh\ngoShcPNxv44Hfru7UYFlfITS0mMZ2j5ju9bqwjHMap19HBKcXDxYc5BhuAMe0W5b\nG+mxNGw62ppts6YqoKFZAkAx5OVKMHWXatCVv0FjhV9LlzuCEP1gMYoFJZZDDUSd\nOtdPg5fUsNSQX+Vxy6uq5lXkdbzebZfzfyfV0ieT+n7B\n-----END RSA PRIVATE KEY-----\n";

    fn f(name: &str, value: &str, hidden: bool) -> Field {
        Field { name: name.into(), value: value.into(), hidden }
    }

    #[test]
    fn public_keys_and_fingerprints() {
        let public = PUBLIC.rsplit_once(' ').unwrap().0;
        assert_eq!(public_key_from_private(PRIVATE).as_deref(), Some(public));
        assert_eq!(public_key_from_private(&format!("  {}  ", PRIVATE.replace('\n', "\r\n"))).as_deref(), Some(public), "pasted with other line endings");
        assert_eq!(public_key_from_private(ENCRYPTED).as_deref(), Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJAAYqhJEGojhABqlqAP0aIcjOBNrXow2EGDaRT/LX1R"), "even with a passphrase");
        assert_eq!(public_key_from_private(PEM), None);
        assert_eq!(public_key_from_private("hello"), None);
        assert_eq!(public_key_from_private(&PRIVATE[..200]), None);
        assert_eq!(fingerprint(PUBLIC).as_deref(), Some(KEY_FINGERPRINT));
        assert_eq!(fingerprint(public).as_deref(), Some(KEY_FINGERPRINT), "the comment doesn't count");
        assert_eq!(fingerprint("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDNVl/NOvmmVExHG3EU870AqwvFa7UbkBFmHjx0yzM+VVdAEuT7nHXUAweGKGsVMDXmsY4/Hd84lN+78vo5s0d6fbpthsvkT3ROBgxDu6oDUrgpevZQBXcsWOx/+iOWfJCLTa47SI2rp2wPMhZlMBaeRfJACBE6+AgSZoh+a158VQ== pem").as_deref(), Some("SHA256:rgOriuxf9ySynALQDUebzPL58ECqgwqt/0qIJrpCySY"));
        assert_eq!(fingerprint(&PUBLIC.replace("ssh-ed25519", "ssh-rsa")), None, "the type must be the blob's");
        assert_eq!(fingerprint("ssh-ed25519 not-base64"), None);
    }

    #[test]
    fn completing_an_item() {
        let public = PUBLIC.rsplit_once(' ').unwrap().0;
        // From the private key alone: its public key and fingerprint, in
        // order, before the other fields.
        let out = complete(vec![f("Server", "example.com", false), f(PRIVATE_KEY, PRIVATE, false)]);
        assert_eq!(out, [f(PRIVATE_KEY, PRIVATE, true), f(PUBLIC_KEY, public, false), f(FINGERPRINT, KEY_FINGERPRINT, false), f("Server", "example.com", false)]);
        // A typed public key of the same key keeps its comment.
        let out = complete(vec![f(PRIVATE_KEY, PRIVATE, true), f(PUBLIC_KEY, PUBLIC, false)]);
        assert_eq!(out[1].value, PUBLIC);
        // Another key's public key is replaced, and a stale fingerprint too.
        let out = complete(vec![f(PRIVATE_KEY, PRIVATE, true), f(PUBLIC_KEY, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDNVl/NOvmmVExHG3EU870AqwvFa7UbkBFmHjx0yzM+VVdAEuT7nHXUAweGKGsVMDXmsY4/Hd84lN+78vo5s0d6fbpthsvkT3ROBgxDu6oDUrgpevZQBXcsWOx/+iOWfJCLTa47SI2rp2wPMhZlMBaeRfJACBE6+AgSZoh+a158VQ== pem", false), f(FINGERPRINT, "SHA256:old", false)]);
        assert_eq!(out[1].value, public);
        assert_eq!(out[2].value, KEY_FINGERPRINT);
        // A key in the older format keeps the public key it came with.
        let out = complete(vec![f(PRIVATE_KEY, PEM, true), f(PUBLIC_KEY, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDNVl/NOvmmVExHG3EU870AqwvFa7UbkBFmHjx0yzM+VVdAEuT7nHXUAweGKGsVMDXmsY4/Hd84lN+78vo5s0d6fbpthsvkT3ROBgxDu6oDUrgpevZQBXcsWOx/+iOWfJCLTa47SI2rp2wPMhZlMBaeRfJACBE6+AgSZoh+a158VQ== pem", false)]);
        assert_eq!(out[2], f(FINGERPRINT, "SHA256:rgOriuxf9ySynALQDUebzPL58ECqgwqt/0qIJrpCySY", false));
        // A key file ends with a line break (ssh refuses one without).
        assert_eq!(complete(vec![f(PRIVATE_KEY, PRIVATE.trim(), true)])[0].value, PRIVATE);
        // No public key, no fingerprint.
        assert_eq!(complete(vec![f(PRIVATE_KEY, PEM, true), f(FINGERPRINT, "SHA256:old", false)]), [f(PRIVATE_KEY, PEM, true)]);
    }
}
