//! Generating passwords.
//!
//! - **Apple-style** (the default, as Safari suggests): `dobdyp-1ruzfa-hiFtoz`,
//!   three groups of six letters with one capital and one digit: about
//!   71 bits, easy to type on a phone, and accepted almost everywhere.
//! - **Random**: a length and character classes of your choice.
//! - **Passphrase**: words from the EFF's long wordlist (7776 words,
//!   12.9 bits each).
//!
//! Characters are drawn uniformly with the operating system's random
//! numbers. For a website with known password rules ([`crate::rules`]), the
//! password follows them.

use std::sync::OnceLock;

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::rules::{Rules, DIGIT, LOWER, SPECIAL, UPPER};
use crate::{Error, Result};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Recipe {
    #[default]
    Apple,
    Random {
        length: u32,
        #[serde(default = "yes")]
        lowercase: bool,
        #[serde(default = "yes")]
        uppercase: bool,
        #[serde(default = "yes")]
        digits: bool,
        #[serde(default = "yes")]
        symbols: bool,
        /// Leaves out characters that look alike (`l 1 I O 0`).
        #[serde(default)]
        avoid_ambiguous: bool,
    },
    Passphrase {
        words: u32,
        #[serde(default = "dash")]
        separator: String,
        #[serde(default)]
        capitalize: bool,
        /// Adds a digit to one of the words.
        #[serde(default)]
        number: bool,
    },
}

fn yes() -> bool {
    true
}

fn dash() -> String {
    "-".into()
}

const AMBIGUOUS: &str = "lI1O0o|`'\"";

pub fn generate(recipe: &Recipe) -> Result<String> {
    match recipe {
        Recipe::Apple => Ok(apple()),
        Recipe::Random { length, lowercase, uppercase, digits, symbols, avoid_ambiguous } => {
            let length = *length as usize;
            if !(4..=256).contains(&length) {
                return Err(Error::invalid("the length must be between 4 and 256"));
            }
            let mut classes: Vec<Vec<char>> = Vec::new();
            for (on, set) in [(*lowercase, LOWER), (*uppercase, UPPER), (*digits, DIGIT), (*symbols, "!@#$%^&*-_=+?.,:;~")] {
                if on {
                    classes.push(set.chars().filter(|c| !*avoid_ambiguous || !AMBIGUOUS.contains(*c)).collect());
                }
            }
            if classes.is_empty() {
                return Err(Error::invalid("choose at least one kind of character"));
            }
            let all: Vec<char> = classes.concat();
            // Drawn uniformly, retried until every class is there: still
            // uniform over the passwords that have them all.
            loop {
                let pw: Vec<char> = (0..length).map(|_| all[OsRng.gen_range(0..all.len())]).collect();
                if length < classes.len() || classes.iter().all(|c| pw.iter().any(|x| c.contains(x))) {
                    return Ok(pw.into_iter().collect());
                }
            }
        }
        Recipe::Passphrase { words, separator, capitalize, number } => {
            if !(3..=20).contains(words) {
                return Err(Error::invalid("use between 3 and 20 words"));
            }
            let list = wordlist();
            let mut ws: Vec<String> = (0..*words).map(|_| list[OsRng.gen_range(0..list.len())].to_owned()).collect();
            if *capitalize {
                for w in &mut ws {
                    let mut c = w.chars();
                    if let Some(f) = c.next() {
                        *w = f.to_uppercase().chain(c).collect();
                    }
                }
            }
            if *number {
                let i = OsRng.gen_range(0..ws.len());
                ws[i].push(char::from(b'0' + OsRng.gen_range(0..10u8)));
            }
            Ok(ws.join(separator))
        }
    }
}

/// `xxxxxx-xxxxxx-xxxxxx`: lowercase letters with one capital and one digit.
fn apple() -> String {
    let lower: Vec<char> = LOWER.chars().collect();
    let mut chars: Vec<char> = (0..18).map(|_| lower[OsRng.gen_range(0..lower.len())]).collect();
    let mut positions: Vec<usize> = (0..18).collect();
    positions.shuffle(&mut OsRng);
    chars[positions[0]] = chars[positions[0]].to_ascii_uppercase();
    chars[positions[1]] = char::from(b'0' + OsRng.gen_range(0..10u8));
    let s: String = chars.into_iter().collect();
    format!("{}-{}-{}", &s[0..6], &s[6..12], &s[12..18])
}

/// The longest password made for a site's rules.
const MAX_SITE_LENGTH: usize = 128;

/// A password for a website: Apple-style when the site's rules (if any)
/// accept it, otherwise random within its rules, as long as the rules
/// allow (up to 20 characters by default).
pub fn generate_for_site(host: &str) -> String {
    match crate::rules::rules_for_host(host) {
        Some(rules) => generate_with_rules(&rules),
        None => apple(),
    }
}

pub fn generate_with_rules(rules: &Rules) -> String {
    for _ in 0..20 {
        let pw = apple();
        if rules.accepts(&pw) {
            return pw;
        }
    }
    let charset = rules.charset();
    // 20 characters if the rules allow. A page's `passwordrules` attribute
    // can say anything: a minimum above the maximum (the minimum wins, as
    // it's what the site checks first), or lengths no one would type.
    let min = rules.min_length.unwrap_or(1).clamp(1, MAX_SITE_LENGTH);
    let max = rules.max_length.unwrap_or(usize::MAX).clamp(min, MAX_SITE_LENGTH);
    let len = 20.clamp(min, max);
    for _ in 0..10_000 {
        let pw: String = (0..len).map(|_| charset[OsRng.gen_range(0..charset.len())]).collect();
        if rules.accepts(&pw) {
            return pw;
        }
    }
    // Rules nothing satisfies (contradictory): the best effort.
    (0..len).map(|_| charset[OsRng.gen_range(0..charset.len())]).collect()
}

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| include_str!("../data/eff_large_wordlist.txt").lines().filter_map(|l| l.split('\t').nth(1)).map(str::trim).collect())
}

/// A rough strength estimate for a password people chose (not a
/// generated one): bits from length and character variety, with penalties
/// for repeats and sequences. `score` is 0 (very weak) to 4 (strong).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Strength {
    pub bits: f64,
    pub score: u8,
}

pub fn strength(password: &str) -> Strength {
    let chars: Vec<char> = password.chars().collect();
    if chars.is_empty() {
        return Strength { bits: 0.0, score: 0 };
    }
    let mut pool = 0;
    if chars.iter().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if chars.iter().any(|c| SPECIAL.contains(*c) || *c == ' ') {
        pool += 33;
    }
    if chars.iter().any(|c| !c.is_ascii()) {
        pool += 100;
    }
    // Characters that repeat or continue a sequence add little.
    let mut effective = 0.0;
    for (i, c) in chars.iter().enumerate() {
        let prev = if i > 0 { Some(chars[i - 1]) } else { None };
        let step = prev.map(|p| *c as i32 - p as i32);
        effective += match step {
            Some(0) => 0.1,
            Some(1 | -1) => 0.3,
            _ => 1.0,
        };
    }
    let mut bits = effective * (pool as f64).log2();
    let lower = password.to_lowercase();
    if COMMON.iter().any(|w| lower.contains(w)) {
        bits = bits.min(20.0);
    }
    let score = match bits {
        b if b < 28.0 => 0,
        b if b < 36.0 => 1,
        b if b < 60.0 => 2,
        b if b < 80.0 => 3,
        _ => 4,
    };
    Strength { bits: (bits * 10.0).round() / 10.0, score }
}

const COMMON: &[&str] = &["password", "123456", "qwerty", "letmein", "welcome", "iloveyou", "admin", "abc123", "monkey", "dragon", "football"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_style() {
        for _ in 0..50 {
            let pw = generate(&Recipe::Apple).unwrap();
            assert_eq!(pw.len(), 20);
            let parts: Vec<&str> = pw.split('-').collect();
            assert_eq!(parts.len(), 3);
            assert!(parts.iter().all(|p| p.len() == 6));
            assert_eq!(pw.chars().filter(|c| c.is_ascii_uppercase()).count(), 1);
            assert_eq!(pw.chars().filter(|c| c.is_ascii_digit()).count(), 1);
        }
        assert_ne!(generate(&Recipe::Apple).unwrap(), generate(&Recipe::Apple).unwrap());
    }

    #[test]
    fn random_has_every_class() {
        let r = Recipe::Random { length: 12, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: true };
        for _ in 0..50 {
            let pw = generate(&r).unwrap();
            assert_eq!(pw.chars().count(), 12);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()) && pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()) && pw.chars().any(|c| !c.is_ascii_alphanumeric()));
            assert!(!pw.chars().any(|c| AMBIGUOUS.contains(c)));
        }
        let digits = Recipe::Random { length: 6, lowercase: false, uppercase: false, digits: true, symbols: false, avoid_ambiguous: false };
        assert!(generate(&digits).unwrap().chars().all(|c| c.is_ascii_digit()));
        let none = Recipe::Random { length: 6, lowercase: false, uppercase: false, digits: false, symbols: false, avoid_ambiguous: false };
        assert!(generate(&none).is_err());
    }

    #[test]
    fn passphrases() {
        assert_eq!(wordlist().len(), 7776);
        let pw = generate(&Recipe::Passphrase { words: 5, separator: "-".into(), capitalize: true, number: true }).unwrap();
        let words: Vec<&str> = pw.split('-').collect();
        assert_eq!(words.len(), 5);
        assert!(words.iter().all(|w| w.chars().next().unwrap().is_uppercase()));
        assert_eq!(pw.chars().filter(|c| c.is_ascii_digit()).count(), 1);
    }

    #[test]
    fn follows_site_rules() {
        let rules = Rules::parse("minlength: 8; maxlength: 12; required: digit; required: [!#]; allowed: lower;");
        for _ in 0..20 {
            let pw = generate_with_rules(&rules);
            assert!(rules.accepts(&pw), "{pw}");
            assert_eq!(pw.len(), 12);
        }
        // Rules Apple-style passwords meet: Apple-style.
        let loose = Rules::parse("minlength: 8; required: lower; required: upper; required: digit;");
        assert_eq!(generate_with_rules(&loose).len(), 20);
    }

    /// A page's `passwordrules` attribute is the page's to write.
    #[test]
    fn odd_site_rules_dont_panic_or_hang() {
        assert_eq!(generate_with_rules(&Rules::parse("minlength: 30; maxlength: 24; required: digit;")).len(), 30, "the minimum wins");
        assert_eq!(generate_with_rules(&Rules::parse("minlength: 99999999; required: digit;")).len(), MAX_SITE_LENGTH);
        assert_eq!(generate_with_rules(&Rules::parse("maxlength: 0; required: digit;")).len(), 1);
        assert_eq!(generate_with_rules(&Rules::parse("minlength: 0; maxlength: 4; required: digit;")).len(), 4);
    }

    #[test]
    fn strength_estimates() {
        assert_eq!(strength("").score, 0);
        assert_eq!(strength("password123").score, 0);
        assert_eq!(strength("aaaaaaaaaaaa").score, 0);
        assert!(strength("abcdefgh").score <= 1);
        assert!(strength(&generate(&Recipe::Apple).unwrap()).score >= 3);
        assert_eq!(strength("correct-horse-battery-staple-xylophone").score, 4);
    }
}
