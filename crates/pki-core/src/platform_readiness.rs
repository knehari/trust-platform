//! Preflight only. Boolean inputs are not independent security evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    Identity,
    Signer,
    Audit,
    Recovery,
}
pub fn check(
    identity_verified: bool,
    signer_attested: bool,
    audit_anchored: bool,
    recovery_tested: bool,
) -> Result<(), GateError> {
    if !identity_verified {
        return Err(GateError::Identity);
    }
    if !signer_attested {
        return Err(GateError::Signer);
    }
    if !audit_anchored {
        return Err(GateError::Audit);
    }
    if !recovery_tested {
        return Err(GateError::Recovery);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unverified_identity() {
        assert_eq!(check(false, true, true, true), Err(GateError::Identity));
    }
}
