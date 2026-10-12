//! V1.6 policy approval identity-binding guard.
//! This module does NOT authenticate an IdP token, attest a key, or authorize humans.
//! Only a trusted authentication/entitlement adapter may construct these inputs.
use crate::policy_decisions::VerifiedDualApproval;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRole {
    Preparer,
    Approver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedReviewer<'a> {
    /// Stable non-reassignable subject identifier established by an external trusted IdP adapter.
    pub subject_id: &'a str,
    /// Stable issuer/tenant of the trusted IdP.
    pub identity_issuer: &'a str,
    /// Key binding was established out of band by an independent authority.
    pub pinned_key_id: &'a str,
    /// Entitlement established from the trusted authority, not from request payload.
    pub role: PolicyRole,
    /// Scope established from a trusted policy service.
    pub ca_id: &'a str,
    /// Adapter guarantees this timestamp is from a trusted source.
    pub authenticated_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewerBindingError {
    InvalidIdentity,
    ExpiredSession,
    RoleMismatch,
    WrongIssuerScope,
    KeyMismatch,
    SameHuman,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundPolicyDecision {
    pub ca_id: String,
    pub proposer_subject: String,
    pub approver_subject: String,
    pub identity_issuer: String,
    pub evidence_sha256: [u8; 32],
}

fn safe_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Adds reviewer and role checks to an already cryptographically verified v1.5 receipt.
/// The caller MUST authenticate sessions and obtain key/role mappings from independent
/// trusted authorities. No caller-supplied JSON identities can be treated as trusted.
pub fn bind_verified_policy_decision(
    verified: &VerifiedDualApproval,
    preparer: &TrustedReviewer<'_>,
    approver: &TrustedReviewer<'_>,
    trusted_now_unix: i64,
    max_session_age_seconds: i64,
) -> Result<BoundPolicyDecision, ReviewerBindingError> {
    let claim = verified.claim();
    if !safe_id(preparer.subject_id)
        || !safe_id(approver.subject_id)
        || !safe_id(preparer.identity_issuer)
        || !safe_id(approver.identity_issuer)
        || !safe_id(preparer.pinned_key_id)
        || !safe_id(approver.pinned_key_id)
        || max_session_age_seconds <= 0
        || trusted_now_unix <= 0
    {
        return Err(ReviewerBindingError::InvalidIdentity);
    }
    if preparer.authenticated_at_unix <= 0
        || approver.authenticated_at_unix <= 0
        || preparer.authenticated_at_unix > trusted_now_unix
        || approver.authenticated_at_unix > trusted_now_unix
        || trusted_now_unix - preparer.authenticated_at_unix > max_session_age_seconds
        || trusted_now_unix - approver.authenticated_at_unix > max_session_age_seconds
    {
        return Err(ReviewerBindingError::ExpiredSession);
    }
    if preparer.role != PolicyRole::Preparer || approver.role != PolicyRole::Approver {
        return Err(ReviewerBindingError::RoleMismatch);
    }
    if preparer.ca_id != claim.ca_id
        || approver.ca_id != claim.ca_id
        || preparer.identity_issuer != approver.identity_issuer
    {
        return Err(ReviewerBindingError::WrongIssuerScope);
    }
    if preparer.pinned_key_id != verified.proposer_key_id()
        || approver.pinned_key_id != verified.approver_key_id()
    {
        return Err(ReviewerBindingError::KeyMismatch);
    }
    if preparer.subject_id == approver.subject_id {
        return Err(ReviewerBindingError::SameHuman);
    }
    Ok(BoundPolicyDecision {
        ca_id: claim.ca_id.clone(),
        proposer_subject: preparer.subject_id.to_owned(),
        approver_subject: approver.subject_id.to_owned(),
        identity_issuer: preparer.identity_issuer.to_owned(),
        evidence_sha256: *verified.evidence_sha256(),
    })
}
