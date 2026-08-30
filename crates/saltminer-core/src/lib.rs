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

/// Identify a hash string. Returns a ranked list of candidates.
pub fn identify(input: &str) -> Vec<Candidate> {
    let _trimmed = input.trim();
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_no_candidates() {
        let result = identify("");
        assert!(result.is_empty());
    }

    #[test]
    fn candidate_can_be_built() {
        let c = Candidate {
            algorithm: String::from("SHA-256"),
            confidence: Confidence::Medium,
            reason: String::from("64 hex chars"),
        };
        assert_eq!(c.confidence, Confidence::Medium);
        assert_eq!(c.algorithm, "SHA-256");
    }
}
