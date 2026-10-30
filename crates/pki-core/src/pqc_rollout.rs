//! Fail-closed domain preflight. Inputs must be independently authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    NoHybrid,
    PeerIncompatible,
    FallbackNotApproved,
}
pub fn check(
    hybrid_supported: bool,
    peer_compatible: bool,
    fallback_approved: bool,
) -> Result<(), GateError> {
    if !hybrid_supported {
        return Err(GateError::NoHybrid);
    }
    if !peer_compatible {
        return Err(GateError::PeerIncompatible);
    }
    if !fallback_approved {
        return Err(GateError::FallbackNotApproved);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_first_missing_requirement() {
        assert_eq!(check(false, true, true), Err(GateError::NoHybrid));
    }
}
