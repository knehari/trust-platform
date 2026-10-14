#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationError {
    Unauthorized,
    InvalidReason,
    InvalidSerial,
}
pub fn authorize_revocation(
    authorized: bool,
    reason: u8,
    serial: &[u8],
) -> Result<(), RevocationError> {
    if !authorized {
        return Err(RevocationError::Unauthorized);
    }
    if !matches!(reason, 0 | 1 | 2 | 3 | 4 | 5 | 6 | 8 | 9 | 10) {
        return Err(RevocationError::InvalidReason);
    }
    if serial.is_empty() || serial.len() > 20 || serial[0] & 0x80 != 0 {
        return Err(RevocationError::InvalidSerial);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_reason_and_identity() {
        assert_eq!(
            authorize_revocation(false, 1, &[1]),
            Err(RevocationError::Unauthorized)
        );
        assert_eq!(
            authorize_revocation(true, 7, &[1]),
            Err(RevocationError::InvalidReason)
        );
        assert!(authorize_revocation(true, 1, &[1]).is_ok());
    }
}
