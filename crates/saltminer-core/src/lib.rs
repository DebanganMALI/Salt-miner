//! Saltminer core — the identification and audit engine.
//!
//! This crate is pure: no I/O, no printing, no network. It takes a
//! hash string and returns what it might be. The CLI, GUI, and Python
//! bindings will all call into here, and every test lives in this crate.

/// Identify a hash string. Returns a list of candidate algorithm names.
///
/// Right now it always returns an empty list — this is the Day 1 stub.
/// On Day 2 we replace `String` with a real `Candidate` type that carries
/// a confidence level and a reason.
pub fn identify(input: &str) -> Vec<String> {
    // `trim` removes stray spaces/newlines from a pasted hash.
    // Prefixed with `_` so the compiler knows we do not use it yet.
    let _trimmed = input.trim();
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_no_candidates() {
        // Arrange / Act
        let result = identify("");
        // Assert
        assert!(result.is_empty());
    }
}
