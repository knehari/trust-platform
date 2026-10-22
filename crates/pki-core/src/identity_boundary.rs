//! Pure preflight contract. Requires independently authenticated inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightError {
    MissingSubject,
    MissingIssuer,
    Expired,
}
pub fn check(subject: &str, issuer: &str, expires_at: u64, now: u64) -> Result<(), PreflightError> {
    if subject.trim().is_empty() {
        return Err(PreflightError::MissingSubject);
    }
    if issuer.trim().is_empty() {
        return Err(PreflightError::MissingIssuer);
    }
    if expires_at <= now {
        return Err(PreflightError::Expired);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_missing_first_requirement() {
        assert_eq!(
            check("", "trusted-issuer", 10, 0),
            Err(PreflightError::MissingSubject)
        );
    }
}
