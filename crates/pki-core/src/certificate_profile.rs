//! Pure preflight contract. Requires independently authenticated inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightError {
    InvalidLifetime,
    MissingSan,
    ForbiddenCa,
}
pub fn check(validity_days: u16, dns_sans: usize, is_ca: bool) -> Result<(), PreflightError> {
    if validity_days == 0 || validity_days > 398 {
        return Err(PreflightError::InvalidLifetime);
    }
    if dns_sans == 0 {
        return Err(PreflightError::MissingSan);
    }
    if is_ca {
        return Err(PreflightError::ForbiddenCa);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_missing_first_requirement() {
        assert_eq!(
            check( 0, 1, false),
            Err(PreflightError::InvalidLifetime)
        );
    }
}
