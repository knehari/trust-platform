//! V1.6 policy approval identity-binding guard.
//! This module does NOT authenticate an IdP token, attest a key, or authorize humans.
//! Only a trusted authentication/entitlement adapter may construct these inputs.
use crate::authentication::{
    evaluate_authentication_context, AuthenticationContext, AuthenticationPolicy,
    AuthenticationPolicyError,
};
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
        || trusted_now_unix
            .checked_sub(preparer.authenticated_at_unix)
            .is_none_or(|age| age > max_session_age_seconds)
        || trusted_now_unix
            .checked_sub(approver.authenticated_at_unix)
            .is_none_or(|age| age > max_session_age_seconds)
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

/// Applies independent authentication policy gates before reviewer binding.
/// Context values MUST originate from verified protocol adapters and must
/// never be constructed directly from untrusted requests in production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatedApprovalError {
    PreparerAuthentication(AuthenticationPolicyError),
    ApproverAuthentication(AuthenticationPolicyError),
    IdentityMismatch,
    ReviewerBinding(ReviewerBindingError),
}

pub struct ReviewerAuthentication<'a, 'b> {
    pub reviewer: &'a TrustedReviewer<'b>,
    pub context: &'a AuthenticationContext<'b>,
    pub policy: &'a AuthenticationPolicy<'b>,
}

pub fn bind_authenticated_policy_decision(
    verified: &VerifiedDualApproval,
    preparer_input: &ReviewerAuthentication<'_, '_>,
    approver_input: &ReviewerAuthentication<'_, '_>,
    trusted_now_unix: i64,
) -> Result<BoundPolicyDecision, AuthenticatedApprovalError> {
    let preparer = preparer_input.reviewer;
    let approver = approver_input.reviewer;
    let preparer_auth = preparer_input.context;
    let approver_auth = approver_input.context;
    let preparer_policy = preparer_input.policy;
    let approver_policy = approver_input.policy;
    evaluate_authentication_context(preparer_auth, preparer_policy, trusted_now_unix)
        .map_err(AuthenticatedApprovalError::PreparerAuthentication)?;
    evaluate_authentication_context(approver_auth, approver_policy, trusted_now_unix)
        .map_err(AuthenticatedApprovalError::ApproverAuthentication)?;
    if preparer_auth.subject != preparer.subject_id
        || preparer_auth.issuer != preparer.identity_issuer
        || preparer_auth.authenticated_at_unix != preparer.authenticated_at_unix
        || approver_auth.subject != approver.subject_id
        || approver_auth.issuer != approver.identity_issuer
        || approver_auth.authenticated_at_unix != approver.authenticated_at_unix
    {
        return Err(AuthenticatedApprovalError::IdentityMismatch);
    }
    let maximum_age = preparer_policy
        .maximum_session_age_seconds
        .min(approver_policy.maximum_session_age_seconds);
    bind_verified_policy_decision(verified, preparer, approver, trusted_now_unix, maximum_age)
        .map_err(AuthenticatedApprovalError::ReviewerBinding)
}
