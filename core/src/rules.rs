//! Websites' password rules, in Apple's password rules language
//! (`minlength: 8; maxlength: 16; required: lower, upper; required: digit;
//! allowed: [-_]; max-consecutive: 2`), for generating passwords the site
//! accepts. Rules for known sites come from Apple's
//! password-manager-resources (`data/password-rules.json`, MIT licensed); a
//! page's own `passwordrules` attribute can be parsed the same way.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use serde::Deserialize;

pub const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
pub const DIGIT: &str = "0123456789";
/// Apple's `special` class, without the space (a space in a generated
/// password is too easily lost).
pub const SPECIAL: &str = "-~!@#$%^&*_+=`|(){}[:;\"'<>,.?]/\\";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    /// Each set needs at least one character from it.
    pub required: Vec<BTreeSet<char>>,
    /// Allowed besides the required sets.
    pub allowed: BTreeSet<char>,
    pub max_consecutive: Option<usize>,
}

impl Rules {
    pub fn parse(text: &str) -> Rules {
        let text = text.replace("&quot;", "\"");
        let mut rules = Rules::default();
        for part in split_rules(&text) {
            let Some((name, value)) = part.split_once(':') else { continue };
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "minlength" => rules.min_length = value.parse().ok().or(rules.min_length),
                "maxlength" => rules.max_length = value.parse().ok().or(rules.max_length),
                "max-consecutive" => {
                    let n: Option<usize> = value.parse().ok();
                    rules.max_consecutive = match (rules.max_consecutive, n) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    }
                }
                "required" => {
                    let set = classes(value);
                    if !set.is_empty() {
                        rules.required.push(set);
                    }
                }
                "allowed" => rules.allowed.extend(classes(value)),
                _ => {}
            }
        }
        rules
    }

    /// Every character a password may use.
    pub fn charset(&self) -> Vec<char> {
        let mut all: BTreeSet<char> = self.allowed.clone();
        for r in &self.required {
            all.extend(r);
        }
        if all.is_empty() {
            all = ascii_printable();
        }
        all.into_iter().collect()
    }

    /// Whether `password` follows the rules.
    pub fn accepts(&self, password: &str) -> bool {
        let chars: Vec<char> = password.chars().collect();
        let charset: BTreeSet<char> = self.charset().into_iter().collect();
        if self.min_length.is_some_and(|m| chars.len() < m) || self.max_length.is_some_and(|m| chars.len() > m) {
            return false;
        }
        if !chars.iter().all(|c| charset.contains(c)) {
            return false;
        }
        if !self.required.iter().all(|set| chars.iter().any(|c| set.contains(c))) {
            return false;
        }
        if let Some(max) = self.max_consecutive {
            let mut run = 0;
            for (i, c) in chars.iter().enumerate() {
                run = if i > 0 && chars[i - 1] == *c { run + 1 } else { 1 };
                if run > max {
                    return false;
                }
            }
        }
        true
    }
}

/// Splits on `;` outside `[…]`.
fn split_rules(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_brackets = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '[' if !in_brackets => {
                in_brackets = true;
                cur.push(c);
                // A `]` right after `[` is a literal one.
                if chars.peek() == Some(&']') {
                    cur.push(']');
                    chars.next();
                }
            }
            ']' if in_brackets => {
                in_brackets = false;
                cur.push(c)
            }
            ';' if !in_brackets => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out.into_iter().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect()
}

fn ascii_printable() -> BTreeSet<char> {
    (0x21u8..0x7f).map(char::from).collect()
}

/// `lower, digit, [-_]` → the characters of those classes.
fn classes(value: &str) -> BTreeSet<char> {
    let mut set = BTreeSet::new();
    let mut rest = value;
    while !rest.trim().is_empty() {
        let r = rest.trim_start_matches([',', ' ']);
        if let Some(inner) = r.strip_prefix('[') {
            // A literal `]` may come first, as in `[]-]`.
            let end = inner.char_indices().skip(1).find(|(_, c)| *c == ']').map(|(i, _)| i).or_else(|| (inner == "]").then_some(0));
            let Some(end) = end else { break };
            set.extend(inner[..end].chars().filter(|c| c.is_ascii_graphic()));
            rest = &inner[end + 1..];
        } else {
            let end = r.find(',').unwrap_or(r.len());
            match r[..end].trim() {
                "upper" => set.extend(UPPER.chars()),
                "lower" => set.extend(LOWER.chars()),
                "digit" => set.extend(DIGIT.chars()),
                "special" => set.extend(SPECIAL.chars()),
                "ascii-printable" | "unicode" => set.extend(ascii_printable()),
                _ => {}
            }
            rest = &r[end..];
            if rest.starts_with(',') {
                rest = &rest[1..];
            }
        }
    }
    set
}

/// Apple's rules for a website (by host, then by its registrable domain).
pub fn rules_for_host(host: &str) -> Option<Rules> {
    static ALL: OnceLock<HashMap<String, String>> = OnceLock::new();
    let all = ALL.get_or_init(|| {
        #[derive(Deserialize)]
        struct Entry {
            #[serde(rename = "password-rules")]
            rules: String,
        }
        let map: HashMap<String, Entry> = serde_json::from_str(include_str!("../data/password-rules.json")).unwrap_or_default();
        map.into_iter().map(|(k, v)| (k.to_ascii_lowercase(), v.rules)).collect()
    });
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    all.get(&host).or_else(|| all.get(&crate::matching::registrable_domain(&host))).map(|t| Rules::parse(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apples_language() {
        // `required: lower, upper` would mean one of either; these are both.
        let either = Rules::parse("required: lower, upper;");
        assert_eq!(either.required[0].len(), 52);
        assert!(either.accepts("abc"));
        let r = Rules::parse("minlength: 8; maxlength: 16; required: lower; required: upper; required: digit; allowed: [-_.]; max-consecutive: 2;");
        assert_eq!(r.min_length, Some(8));
        assert_eq!(r.max_length, Some(16));
        assert_eq!(r.required.len(), 3);
        assert!(r.allowed.contains(&'-') && r.allowed.contains(&'.') && !r.allowed.contains(&'!'));
        assert_eq!(r.max_consecutive, Some(2));
        assert!(r.accepts("Abcdef12-x"));
        assert!(!r.accepts("abcdef12"), "no upper");
        assert!(!r.accepts("Abcdef12!"), "! not allowed");
        assert!(!r.accepts("Abccc12x"), "three in a row");
        assert!(!r.accepts("Ab1"), "too short");
    }

    #[test]
    fn brackets_with_odd_characters() {
        let r = Rules::parse("required: [-().&@?'#,/&quot;+;]; allowed: []-], digit;");
        let req = &r.required[0];
        for c in "-().&@?'#,/\"+;".chars() {
            assert!(req.contains(&c), "{c}");
        }
        assert!(r.allowed.contains(&']') && r.allowed.contains(&'-') && r.allowed.contains(&'7'));
    }

    #[test]
    fn known_sites() {
        let r = rules_for_host("www.1800flowers.com").expect("in Apple's list");
        assert_eq!(r.min_length, Some(6));
        assert!(rules_for_host("no-rules-here.example").is_none());
    }

    #[test]
    fn every_rule_in_apples_list_parses_to_something_usable() {
        let map: HashMap<String, serde_json::Value> = serde_json::from_str(include_str!("../data/password-rules.json")).unwrap();
        assert!(map.len() > 100);
        for (site, v) in map {
            let r = Rules::parse(v["password-rules"].as_str().unwrap());
            assert!(!r.charset().is_empty(), "{site}");
            if let (Some(min), Some(max)) = (r.min_length, r.max_length) {
                assert!(min <= max, "{site}");
            }
        }
    }
}
