//! Policy decision only, not an actual retention worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionError {
    InvalidPeriod,
    LegalHold,
    UnverifiedExport,
}
pub fn permit_deletion(
    retention_days: u32,
    legal_hold: bool,
    export_verified: bool,
) -> Result<(), RetentionError> {
    if retention_days == 0 {
        return Err(RetentionError::InvalidPeriod);
    }
    if legal_hold {
        return Err(RetentionError::LegalHold);
    }
    if !export_verified {
        return Err(RetentionError::UnverifiedExport);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_unverified_export() {
        assert_eq!(
            permit_deletion(365, false, false),
            Err(RetentionError::UnverifiedExport)
        );
    }
}
