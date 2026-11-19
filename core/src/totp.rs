//! Time-based one-time codes (RFC 6238), from what an item's TOTP field
//! holds: a base32 secret (spaces and dashes ignored), an
//! `otpauth://totp/…?secret=…&digits=…&period=…&algorithm=…` URI, or
//! `steam://SECRET` (Steam Guard's 5-character codes).

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Spec {
    secret: Vec<u8>,
    digits: u32,
    period: u64,
    algorithm: Algorithm,
    steam: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Code {
    pub code: String,
    pub period: u64,
    /// Seconds until the next code.
    pub remaining: u64,
}

/// The code at `unix_time` (seconds).
pub fn code(totp: &str, unix_time: u64) -> Result<Code> {
    let spec = parse(totp)?;
    let counter = unix_time / spec.period;
    macro_rules! digest {
        ($d:ty) => {{
            let mut m = <Hmac<$d> as Mac>::new_from_slice(&spec.secret).expect("HMAC takes any key length");
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }};
    }
    let hash = match spec.algorithm {
        Algorithm::Sha1 => digest!(sha1::Sha1),
        Algorithm::Sha256 => digest!(sha2::Sha256),
        Algorithm::Sha512 => digest!(sha2::Sha512),
    };
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([hash[offset] & 0x7f, hash[offset + 1], hash[offset + 2], hash[offset + 3]]);
    let code = if spec.steam {
        const STEAM: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";
        let mut v = bin as usize;
        (0..5)
            .map(|_| {
                let c = STEAM[v % STEAM.len()] as char;
                v /= STEAM.len();
                c
            })
            .collect()
    } else {
        // 10^10 doesn't fit a u32 (10-digit codes are allowed).
        format!("{:0width$}", u64::from(bin) % 10u64.pow(spec.digits), width = spec.digits as usize)
    };
    Ok(Code { code, period: spec.period, remaining: spec.period - unix_time % spec.period })
}

/// Whether the text is a TOTP secret this can make codes from.
pub fn is_valid(totp: &str) -> bool {
    parse(totp).is_ok()
}

fn parse(totp: &str) -> Result<Spec> {
    let t = totp.trim();
    let bad = || Error::invalid("that isn't a TOTP secret");
    if let Some(secret) = t.strip_prefix("steam://") {
        return Ok(Spec { secret: base32(secret).ok_or_else(bad)?, digits: 5, period: 30, algorithm: Algorithm::Sha1, steam: true });
    }
    if t.to_ascii_lowercase().starts_with("otpauth://") {
        let url = url::Url::parse(t).map_err(|_| bad())?;
        if url.host_str() != Some("totp") {
            return Err(Error::invalid("only time-based (TOTP) codes are supported"));
        }
        let mut spec = Spec { secret: Vec::new(), digits: 6, period: 30, algorithm: Algorithm::Sha1, steam: false };
        for (k, v) in url.query_pairs() {
            match k.to_ascii_lowercase().as_str() {
                "secret" => spec.secret = base32(&v).ok_or_else(bad)?,
                "digits" => spec.digits = v.parse().ok().filter(|d| (6..=10).contains(d)).ok_or_else(bad)?,
                "period" => spec.period = v.parse().ok().filter(|p| (1..=3600).contains(p)).ok_or_else(bad)?,
                "algorithm" => {
                    spec.algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(bad()),
                    }
                }
                "encoder" if v.eq_ignore_ascii_case("steam") => spec.steam = true,
                _ => {}
            }
        }
        if spec.secret.is_empty() {
            return Err(bad());
        }
        if spec.steam {
            spec.digits = 5;
        }
        return Ok(spec);
    }
    Ok(Spec { secret: base32(t).ok_or_else(bad)?, digits: 6, period: 30, algorithm: Algorithm::Sha1, steam: false })
}

/// RFC 4648 base32, case-insensitive, ignoring spaces, dashes and padding.
fn base32(s: &str) -> Option<Vec<u8>> {
    let mut bits: u64 = 0;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return None,
        };
        bits = (bits << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238's test vectors (secrets are ASCII "1234567890…", base32).
    #[test]
    fn rfc6238_vectors() {
        let sha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let sha256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
        let sha512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";
        let uri = |s: &str, alg: &str| format!("otpauth://totp/Test?secret={s}&digits=8&algorithm={alg}");
        assert_eq!(code(&uri(sha1, "SHA1"), 59).unwrap().code, "94287082");
        assert_eq!(code(&uri(sha256, "SHA256"), 59).unwrap().code, "46119246");
        assert_eq!(code(&uri(sha512, "SHA512"), 59).unwrap().code, "90693936");
        assert_eq!(code(&uri(sha1, "SHA1"), 1111111109).unwrap().code, "07081804");
        assert_eq!(code(&uri(sha1, "SHA1"), 20000000000).unwrap().code, "65353130");
    }

    #[test]
    fn plain_secrets_and_remaining_time() {
        let c = code("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", 59).unwrap();
        assert_eq!(c.code, "287082");
        assert_eq!(c.remaining, 1);
        assert_eq!(code("GEZDGNBVGY3TQOJQ", 30).unwrap().remaining, 30);
        assert!(is_valid("JBSWY3DPEHPK3PXP"));
        assert!(!is_valid("not base32!"));
        assert!(!is_valid("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn nine_and_ten_digit_codes() {
        let uri = |d: u32| format!("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits={d}");
        // RFC 6238's SHA-1 vector at t=59 truncates to 1094287082.
        assert_eq!(code(&uri(10), 59).unwrap().code, "1094287082");
        assert_eq!(code(&uri(9), 59).unwrap().code, "094287082");
        assert!(code(&uri(11), 59).is_err());
    }

    #[test]
    fn steam_codes() {
        let c = code("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
        assert_eq!(c.code.len(), 5);
        assert!(c.code.chars().all(|ch| "23456789BCDFGHJKMNPQRTVWXY".contains(ch)));
    }
}
