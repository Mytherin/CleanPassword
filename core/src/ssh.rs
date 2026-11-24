//! SSH keys: what an [`ItemKind::SshKey`](crate::ItemKind::SshKey) item's
//! public key and fingerprint are, worked out from its keys.
//!
//! - The item's public key is taken from its private key when it can be:
//!   - an OpenSSH private key (`BEGIN OPENSSH PRIVATE KEY`) carries its
//!     public key unencrypted, even when it has a passphrase;
//!   - an RSA key in the older formats (`BEGIN RSA PRIVATE KEY`, PKCS#1, or
//!     `BEGIN PRIVATE KEY`, PKCS#8) holds its modulus and public exponent,
//!     unless it has a passphrase (then all of it is encrypted).
//! - The fingerprint is `ssh-keygen -l`'s: `SHA256:` and the base64 (without
//!   padding) of the SHA-256 of the public key's blob.
//!
//! Other keys (EC or Ed25519 in the older formats, older keys with a
//! passphrase) keep the public key that was typed or imported.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::item::{Field, SSH_KEY_DETAILS};

pub const PRIVATE_KEY: &str = "Private key";
pub const PUBLIC_KEY: &str = "Public key";
pub const FINGERPRINT: &str = "Fingerprint";

const MAGIC: &[u8] = b"openssh-key-v1\0";
/// PKCS#8's algorithm id for RSA keys (1.2.840.113549.1.1.1), DER.
const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

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

/// A PEM block's label (`OPENSSH PRIVATE KEY`…) and contents; `None` if
/// it isn't one, or has headers (`Proc-Type: 4,ENCRYPTED`: a key with a
/// passphrase in the older formats).
fn pem(text: &str) -> Option<(&str, Vec<u8>)> {
    let rest = text.trim().strip_prefix("-----BEGIN ")?;
    let (label, rest) = rest.split_once("-----")?;
    let body = rest.trim_end().strip_suffix(&format!("-----END {label}-----"))?;
    if body.contains(':') {
        return None;
    }
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    Some((label, STANDARD.decode(b64).ok()?))
}

/// Reads DER: the tag and contents of each element in turn.
struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.0.split_first()?;
        let (&first, mut rest) = rest.split_first()?;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || n > rest.len() {
                return None;
            }
            let (bytes, after) = rest.split_at(n);
            rest = after;
            bytes.iter().fold(0usize, |len, &b| len << 8 | b as usize)
        };
        if len > rest.len() {
            return None;
        }
        let (contents, after) = rest.split_at(len);
        self.0 = after;
        Some((tag, contents))
    }

    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        self.next().filter(|(t, _)| *t == tag).map(|(_, c)| c)
    }
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;

/// An `ssh-rsa` public key blob from a PKCS#1 RSAPrivateKey (version,
/// modulus, public exponent, then the private parts).
fn rsa_blob(pkcs1: &[u8]) -> Option<Vec<u8>> {
    let mut key = Der(Der(pkcs1).expect(SEQUENCE)?);
    key.expect(INTEGER)?;
    let (n, e) = (key.expect(INTEGER)?, key.expect(INTEGER)?);
    // DER's positive integers are SSH's mpints: big-endian, with a zero
    // byte in front when the top bit is set.
    let positive = |i: &[u8]| !i.is_empty() && i[0] & 0x80 == 0;
    if !positive(n) || !positive(e) {
        return None;
    }
    let mut blob = Vec::new();
    for part in [b"ssh-rsa".as_slice(), e, n] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    Some(blob)
}

/// The PKCS#1 key inside a PKCS#8 PrivateKeyInfo, if it's an RSA key.
fn pkcs8_rsa(der: &[u8]) -> Option<&[u8]> {
    let mut info = Der(Der(der).expect(SEQUENCE)?);
    info.expect(INTEGER)?;
    let mut algorithm = Der(info.expect(SEQUENCE)?);
    (algorithm.expect(OID)? == RSA_OID).then_some(())?;
    info.expect(OCTET_STRING)
}

/// The public key blob of an OpenSSH private key.
fn openssh_blob(bytes: &[u8]) -> Option<&[u8]> {
    let mut r = Reader(bytes.strip_prefix(MAGIC)?);
    let (_cipher, _kdf, _kdf_options) = (r.string()?, r.string()?, r.string()?);
    if r.u32()? == 0 {
        return None;
    }
    r.string()
}

/// The public key of a private key, as `<type> <base64>` (without a
/// comment); `None` if it isn't one this reads (see the module's notes).
pub fn public_key_from_private(private_key: &str) -> Option<String> {
    let (label, der) = pem(private_key)?;
    let blob = match label {
        "OPENSSH PRIVATE KEY" => openssh_blob(&der)?.to_vec(),
        "RSA PRIVATE KEY" => rsa_blob(&der)?,
        "PRIVATE KEY" => rsa_blob(pkcs8_rsa(&der)?)?,
        _ => return None,
    };
    Some(format!("{} {}", blob_type(&blob)?, STANDARD.encode(&blob)))
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
    // `ssh-keygen -t rsa -m PEM`, `-m PKCS8`, and `-m PEM` with the
    // passphrase "secret" (not read: all of it is encrypted).
    const ENCRYPTED_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,E25EA0339935354DEF946A86F8E40875\n\nSvmDOw+02ECeSwODVFIYb+14sj9Mff9+fcj3yL/bFRY/K5vcDb1uHvMVfYMPbIwG\noqnDDtE10T6coAcPWNVIpQXAayb+cRf1eVNr6dDv5UYpC62P2lZSJN85E6yeevAE\nrlcHyg1U4ioqQ7BU/2BHrP9ZWRBZp4WybRm7LNHJuviV9n7/w9wroxHDRCZRUbp2\nSVp0hPMLQtURqom7lxt0oEGIRg5Fxrphkkvevy1iiJJtnlt2Encqri+pLidJsWpX\nY6/Qi7gWsLyjTgRxt//NqTt5eyFUKaxFN21jsprNYJqXXs5gpIwOs4gdQFsGUUhM\nb2ljhx6s4E8AWMbjyGJdZv31ugzi+ZQnr7RRVIYZtFqq7P8gK9ZR1N+rcpKXho80\nycT9pd5eME11aP/VmP40b1ItMq0JyRngkn+JxSOb4Em//06vCbgZWux/vm0IdRTD\nmNTedDlTrljaGMDHFyPJjVvsUWbN/4N0ZhtfxOO7Ws2x3mSEH3eyFgGGSYwOE3bY\nVhvK5ESapHB/icZjwq9s0SE4SdPg4sTDy4IwWTVXu4EALg5ZA9JaMRk2GwURZBGD\ncfKPC8xLhMSEESZSOOMeZpj/2WNWQBRg8gYzyKkdZ++27Gek+65B0aEdyNS3lyyj\nYy2FHIf0LI8XhW1+KYtc9pexEp4POYZnc3wejBDvGrnI4lVeZVMBbSfscNrDyl/s\nnOCeAbPmb3jP1upI/QrEn2b7Z6/GS4G+1Bg4ztNn4GyI1aAuGr6q/GvSSTr9Axer\nsiIcam+tWKgLzjW7kCGylpLgppqum9qZ4FHJDi8gX+z0HWzbTVD4q8W9MaYhCYW4\n-----END RSA PRIVATE KEY-----\n";
    const PKCS8: &str = "-----BEGIN PRIVATE KEY-----\nMIICeQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBAM9wX/4KgIBLHfQQ\nx8eYdftoj/9fPE5/D9Zmj7P/NM519BPtAqeOkk2rhaSzqHyE4iq4O5Qr7YIzB1Xy\nwwdz6pd8vC27iGRDJ8SJ6VWVistN7TN2RRG2QK2rIVLAQH55ZO4TLbd4OknX9WZl\nFnC7/QBEhQD0hs0PMLmN+zqaDginAgMBAAECgYEAkjhwMa5NbiGE96lsaXE6mQDX\nn/cNl3dRPpwE56gZHP9gETucB2gkEMO67KIHPd6dXeeHd6aPQJufrCH2/6Xh0age\nYwgtaCdkDDgW5qPqVnhjFr2Y8mcxTP3Fp/u2enNw6lhkI+MsMOoNmqeGJY7VC5Hw\nN4l9vPEEDDjQ4Mgco8ECQQD973L44xjk4dkD5WOpuvyu7YgywtJVu61ca8hylKab\nRplLtJHqUEzAdmaZ8tMKM47nCpM2/Vm7IqiuYFkILEBpAkEA0SAlf+ZwjyB1/xI0\nflONFQEMU6AgvgTmgskafQb6xOWH6O5FxBab8jK+JwljGmuOAoIoFYIk7r+5EUYb\nnkPejwJBAI0tlyoweCKoPdMgsWwn/Vvzy4kNL4tisFt1wReS9Z3WflvMpGM1Cbbn\nHNvyWMqPJ5/kDTzBViXoeweXoWgd0iECQQCxUxPZHvpksr67OaGfWJNxswDTzBzX\nY2pejc3TJF7xJDwZTCmGOzGirlpE2ZXaKkcxY1I/4qoUdCemOQ9kJOKLAkEAn0gf\n41zHKn8GeSVSchoJzOeD3jaTwF1pZdKHiuaweL6BjCLzbhaY1gdLiIbOl1F1xJND\nq6Vwh2zBo4+rb2T1Xg==\n-----END PRIVATE KEY-----\n";
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
        let without_comment = |k: &str| k.rsplit_once(' ').unwrap().0.to_owned();
        assert_eq!(public_key_from_private(PEM), Some(without_comment("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDNVl/NOvmmVExHG3EU870AqwvFa7UbkBFmHjx0yzM+VVdAEuT7nHXUAweGKGsVMDXmsY4/Hd84lN+78vo5s0d6fbpthsvkT3ROBgxDu6oDUrgpevZQBXcsWOx/+iOWfJCLTa47SI2rp2wPMhZlMBaeRfJACBE6+AgSZoh+a158VQ== pem")), "PKCS#1");
        assert_eq!(public_key_from_private(PKCS8), Some(without_comment("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDPcF/+CoCASx30EMfHmHX7aI//XzxOfw/WZo+z/zTOdfQT7QKnjpJNq4Wks6h8hOIquDuUK+2CMwdV8sMHc+qXfLwtu4hkQyfEielVlYrLTe0zdkURtkCtqyFSwEB+eWTuEy23eDpJ1/VmZRZwu/0ARIUA9IbNDzC5jfs6mg4Ipw== p8")), "PKCS#8");
        assert_eq!(public_key_from_private(ENCRYPTED_PEM), None);
        assert_eq!(public_key_from_private(&PEM.replace("RSA PRIVATE KEY", "EC PRIVATE KEY")), None);
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
        // An RSA key in the older format: its public key and fingerprint.
        let out = complete(vec![f(PRIVATE_KEY, PEM, true)]);
        assert_eq!(out[2], f(FINGERPRINT, "SHA256:rgOriuxf9ySynALQDUebzPL58ECqgwqt/0qIJrpCySY", false));
        // One with a passphrase keeps the public key it came with.
        let out = complete(vec![f(PRIVATE_KEY, ENCRYPTED_PEM, true), f(PUBLIC_KEY, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDBCkqC29IaRPfTM3Tv4Q7B0TCa2wJ997UHrUJGgQaWOnT2gE5Zu7f7DbRi7lFKCel4pA1nzXAX79LBy6yuAWmP0ltwUFfGsWXRA4/KEiaXV1aWiMLZHgv42/zBIOY5jOb9E3ofczKRt7pgkhXv7oOLZuqUZ6te6SguZc4TWLDozQ== encpem", false)]);
        assert_eq!(out[1].value, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDBCkqC29IaRPfTM3Tv4Q7B0TCa2wJ997UHrUJGgQaWOnT2gE5Zu7f7DbRi7lFKCel4pA1nzXAX79LBy6yuAWmP0ltwUFfGsWXRA4/KEiaXV1aWiMLZHgv42/zBIOY5jOb9E3ofczKRt7pgkhXv7oOLZuqUZ6te6SguZc4TWLDozQ== encpem");
        assert!(out[2].value.starts_with("SHA256:"));
        // A key file ends with a line break (ssh refuses one without).
        assert_eq!(complete(vec![f(PRIVATE_KEY, PRIVATE.trim(), true)])[0].value, PRIVATE);
        // No public key, no fingerprint.
        assert_eq!(complete(vec![f(PRIVATE_KEY, ENCRYPTED_PEM, true), f(FINGERPRINT, "SHA256:old", false)]), [f(PRIVATE_KEY, ENCRYPTED_PEM, true)]);
    }
}
