//! Pure preflight contract. Requires independently authenticated inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightError {
    MissingKey,
    MissingEvidence,
    UntrustedProvider,
}
pub fn check(key_ref: &str, evidence_digest: &[u8; 32], trusted_provider: bool) -> Result<(), PreflightError> {
    if key_ref.is_empty() {
        return Err(PreflightError::MissingKey);
    }
    if evidence_digest == &[0; 32] {
        return Err(PreflightError::MissingEvidence);
    }
    if !trusted_provider {
        return Err(PreflightError::UntrustedProvider);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_missing_first_requirement() {
        assert_eq!(
            check( "", &[1; 32], true),
            Err(PreflightError::MissingKey)
        );
    }
}
