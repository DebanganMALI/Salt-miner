//! Saltminer core — the identification and audit engine.

/// How sure we are about a single guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// One possible identification of a hash string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub algorithm: String,
    pub confidence: Confidence,
    pub reason: String,
}

/// Known hash prefixes: (prefix, algorithm, note).
const PREFIX_RULES: &[(&str, &str, &str)] = &[
    (
        "$argon2id$",
        "Argon2id",
        "modern PHC string, current standard",
    ),
    (
        "$argon2i$",
        "Argon2i",
        "PHC string, side-channel-resistant variant",
    ),
    ("$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"),
    ("$2b$", "bcrypt", "bcrypt PHC string, 2b variant"),
    ("$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"),
    ("$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"),
    ("$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy)"),
    ("$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant"),
    (
        "pbkdf2_sha256$",
        "Django PBKDF2-SHA256",
        "Django default password hash",
    ),
];

/// Identify a hash string. Returns a ranked list of candidates.
pub fn identify(input: &str) -> Vec<Candidate> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Vec::new();
    }

    for &(prefix, algorithm, note) in PREFIX_RULES {
        if trimmed.starts_with(prefix) {
            return vec![Candidate {
                algorithm: algorithm.to_string(),
                confidence: Confidence::High,
                reason: format!("prefix {prefix} — {note}"),
            }];
        }
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_no_candidates() {
        assert!(identify("").is_empty());
    }

    #[test]
    fn bcrypt_prefix_is_high_confidence() {
        let result = identify("$2b$12$abcdefghijklmnopqrstuv");
        assert_eq!(result[0].algorithm, "bcrypt");
        assert_eq!(result[0].confidence, Confidence::High);
    }

    #[test]
    fn argon2id_prefix_is_recognized() {
        let result = identify("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA");
        assert_eq!(result[0].algorithm, "Argon2id");
    }

    #[test]
    fn unknown_input_returns_empty() {
        assert!(identify("just some random text").is_empty());
    }
}
