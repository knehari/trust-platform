#![forbid(unsafe_code)]
//! Native CA orchestration skeleton. No certificate issuance implemented.

use trust_pki_policy::{IssuanceRequest, PolicyEngine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceState {
    Received,
    CsrValidated,
    Authorized,
    SerialReserved,
    Signing,
    Signed,
    Published,
    Rejected,
    ReconciliationRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuanceError {
    Unauthorized,
    InvalidTransition,
}

pub fn authorize_request(
    policy: &impl PolicyEngine,
    request: &IssuanceRequest<'_>,
) -> Result<IssuanceState, IssuanceError> {
    policy.authorize(request)
        .map(|_| IssuanceState::Authorized)
        .map_err(|_| IssuanceError::Unauthorized)
}

/// State transition contract; persistence and idempotency will be implemented later.
pub fn can_transition(from: IssuanceState, to: IssuanceState) -> bool {
    use IssuanceState::*;
    matches!((from, to),
        (Received, CsrValidated) | (Received, Rejected) |
        (CsrValidated, Authorized) | (CsrValidated, Rejected) |
        (Authorized, SerialReserved) |
        (SerialReserved, Signing) |
        (Signing, Signed) | (Signing, ReconciliationRequired) |
        (Signed, Published))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_pki_policy::{DenyAll, IssuanceRequest};
    #[test]
    fn deny_all_blocks_authorization() {
        let request = IssuanceRequest {
            requester_id: "actor", profile_id: "server",
            subject_common_name: "example.invalid", dns_sans: &[],
        };
        assert_eq!(authorize_request(&DenyAll, &request), Err(IssuanceError::Unauthorized));
    }
    #[test]
    fn cannot_skip_authorization() {
        assert!(!can_transition(IssuanceState::Received, IssuanceState::Signing));
        assert!(!can_transition(IssuanceState::CsrValidated, IssuanceState::SerialReserved));
    }
}
