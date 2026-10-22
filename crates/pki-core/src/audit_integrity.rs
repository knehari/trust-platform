//! Fail-closed domain preflight. Inputs must be independently authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    EmptyDigest,
    NotAnchored,
    InvalidSignature,
}
pub fn check(
    digest: &[u8; 32],
    externally_anchored: bool,
    signature_verified: bool,
) -> Result<(), GateError> {
    if digest == &[0; 32] {
        return Err(GateError::EmptyDigest);
    }
    if !externally_anchored {
        return Err(GateError::NotAnchored);
    }
    if !signature_verified {
        return Err(GateError::InvalidSignature);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_first_missing_requirement() {
        assert_eq!(check(&[0; 32], true, true), Err(GateError::EmptyDigest));
    }
}
