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

/// True if the text is non-empty and every character is a hex digit.
fn is_hex(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// True for MySQL5: a `*` followed by exactly 40 uppercase hex chars.
fn is_mysql5(text: &str) -> bool {
    if text.len() != 41 || !text.starts_with('*') {
        return false;
    }
    text[1..]
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
}

/// Algorithms that produce a hex string of this length, most common first.
fn length_rules(len: usize) -> &'static [&'static str] {
    match len {
        32 => &["MD5", "NTLM", "MD4", "RIPEMD-128"],
        40 => &["SHA-1", "RIPEMD-160"],
        56 => &["SHA-224", "SHA3-224"],
        64 => &["SHA-256", "SHA3-256", "BLAKE2s-256"],
        96 => &["SHA-384", "SHA3-384"],
        128 => &["SHA-512", "SHA3-512", "BLAKE2b-512"],
        _ => &[],
    }
}

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

    // MySQL5
    if is_mysql5(trimmed) {
        return vec![Candidate {
            algorithm: "MySQL5".to_string(),
            confidence: Confidence::High,
            reason: "`*` + 40 uppercase hex chars".to_string(),
        }];
    }

    // pwdump / NTLM (Windows SAM): user:rid:lm(32 hex):nt(32 hex):::
    if trimmed.ends_with(":::") {
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() == 7
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && parts[2].len() == 32
            && is_hex(parts[2])
            && parts[3].len() == 32
            && is_hex(parts[3])
        {
            return vec![Candidate {
                algorithm: "NTLM".to_string(),
                confidence: Confidence::High,
                reason: "pwdump line — the NT hash is NTLM".to_string(),
            }];
        }
    }

    // NetNTLMv2 / NetNTLMv1: colon-delimited challenge-response records
    if trimmed.contains("::") && trimmed.matches(':').count() >= 4 {
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() >= 6 && parts[4].len() == 32 && is_hex(parts[4]) {
            return vec![Candidate {
                algorithm: "NetNTLMv2".to_string(),
                confidence: Confidence::High,
                reason: "user::domain:challenge:hmac(32 hex):blob shape".to_string(),
            }];
        }
        if parts.len() >= 6 && parts[3].len() == 48 && is_hex(parts[3]) {
            return vec![Candidate {
                algorithm: "NetNTLMv1".to_string(),
                confidence: Confidence::High,
                reason: "user::domain:lm(48 hex):nt(48 hex):challenge shape".to_string(),
            }];
        }
    }

    if is_hex(trimmed) {
        let algorithms = length_rules(trimmed.len());
        let mut candidates = Vec::new();
        for (index, algorithm) in algorithms.iter().enumerate() {
            let confidence = if index == 0 {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            let label = if index == 0 {
                "most likely at this length"
            } else {
                "also possible at this length"
            };
            candidates.push(Candidate {
                algorithm: algorithm.to_string(),
                confidence,
                reason: format!("{} hex chars — {label}", trimmed.len()),
            });
        }
        return candidates;
    }

    // Not hashes, but say what they actually are.
    if trimmed.starts_with("eyJ") {
        return vec![Candidate {
            algorithm: "JWT (not a hash)".to_string(),
            confidence: Confidence::Low,
            reason: "leading `eyJ` is base64 of `{\"` — a JWT, not a hash".to_string(),
        }];
    }

    if trimmed.len() > 8 && trimmed.contains(['+', '/', '=']) {
        return vec![Candidate {
            algorithm: "Base64 blob (not a hash)".to_string(),
            confidence: Confidence::Low,
            reason: "contains base64-only chars (`+`, `/`, `=`)".to_string(),
        }];
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
    fn md5_length_is_medium_confidence() {
        let result = identify("5f4dcc3b5aa765d61d8327deb882cf99");
        assert_eq!(result[0].algorithm, "MD5");
        assert_eq!(result[0].confidence, Confidence::Medium);
        let names: Vec<&str> = result.iter().map(|c| c.algorithm.as_str()).collect();
        assert!(names.contains(&"NTLM"));
    }

    #[test]
    fn sha256_length_is_recognized() {
        let hash = "a".repeat(64);
        let result = identify(&hash);
        assert_eq!(result[0].algorithm, "SHA-256");
    }

    #[test]
    fn mysql5_is_recognized() {
        let result = identify("*A4B6157319038724E3560894F7F932C8886EBFCF");
        assert_eq!(result[0].algorithm, "MySQL5");
        assert_eq!(result[0].confidence, Confidence::High);
    }

    #[test]
    fn mysql5_rejects_lowercase_body() {
        let result = identify("*a4b6157319038724e3560894f7f932c8886ebfcf");
        let claimed_mysql5 = !result.is_empty() && result[0].algorithm == "MySQL5";
        assert!(!claimed_mysql5);
    }

    #[test]
    fn netntlmv2_is_recognized() {
        let sample = format!(
            "alice::CORP:1122334455667788:{}:{}",
            "a".repeat(32),
            "b".repeat(64)
        );
        let result = identify(&sample);
        assert_eq!(result[0].algorithm, "NetNTLMv2");
    }

    #[test]
    fn pwdump_line_is_ntlm() {
        let sample = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::";
        let result = identify(sample);
        assert_eq!(result[0].algorithm, "NTLM");
    }

    #[test]
    fn jwt_is_flagged_as_not_a_hash() {
        let result = identify("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig");
        assert!(result[0].algorithm.contains("JWT"));
        assert_eq!(result[0].confidence, Confidence::Low);
    }

    #[test]
    fn base64_blob_is_flagged_as_not_a_hash() {
        let result = identify("VGhpcyBpcyBub3QgYSBoYXNoLg==");
        assert!(result[0].algorithm.contains("Base64"));
    }

    #[test]
    fn unknown_input_returns_empty() {
        assert!(identify("just some random text").is_empty());
    }
}
