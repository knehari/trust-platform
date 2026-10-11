//! Cryptographically verified, but NON-AUTHORITATIVE draft CP/CPS trace for a
//! certificate already issued. It does NOT approve CP/CPS or authorize signing.
//! LAB ONLY: checked P-256 leaf, pinned issuer root and exact TBS/serial/OID.

use crate::{
    ca_observation::ObservedCaPublicCertificate,
    cp_cps::{generate, Input},
    lab_x509_verifier::LabX509Verifier,
    orchestrator::{CertificateVerifier, IssuancePlan},
    x509_extensions::ApprovedPolicyBinding,
};
use sha2::{Digest, Sha256};
use x509_cert::{der::Decode, Certificate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceError {
    InvalidInput,
    PolicyMismatch,
    CertificateInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDraftCertificateTrace {
    ca_id: String,
    request_id: String,
    policy_revision: String,
    policy_oid: String,
    certificate_sha256: [u8; 32],
    issuer_ca_sha256: [u8; 32],
    cp_sha256: [u8; 32],
    cps_sha256: [u8; 32],
    source_sha256: [u8; 32],
}
impl VerifiedDraftCertificateTrace {
    pub fn ca_id(&self) -> &str { &self.ca_id }
    pub fn request_id(&self) -> &str { &self.request_id }
    pub fn policy_revision(&self) -> &str { &self.policy_revision }
    pub fn policy_oid(&self) -> &str { &self.policy_oid }
    pub fn certificate_sha256(&self) -> &[u8; 32] { &self.certificate_sha256 }
    pub fn issuer_ca_sha256(&self) -> &[u8; 32] { &self.issuer_ca_sha256 }
    pub fn cp_sha256(&self) -> &[u8; 32] { &self.cp_sha256 }
    pub fn cps_sha256(&self) -> &[u8; 32] { &self.cps_sha256 }
    pub fn source_sha256(&self) -> &[u8; 32] { &self.source_sha256 }
}

/// A successfully verified link is still *only* a DRAFT reference.
/// The observed CA root may be authentic under a pinned external root cert,
/// but its operating state/configuration and document approval are UNKNOWN.
///
/// Real issuance gates must check approved immutable CP/CPS effective dates and
/// policy authority identity BEFORE signing, rather than attaching drafts later.
pub fn verify_certificate_draft_trace(
    observed_ca: &ObservedCaPublicCertificate,
    plan: &IssuancePlan<'_>,
    leaf_certificate_der: &[u8],
    declared_policy: &Input<'_>,
    certificate_policy: &ApprovedPolicyBinding,
    expected_leaf_dns: &str,
) -> Result<VerifiedDraftCertificateTrace, TraceError> {
    if plan.ca_id.is_empty() || plan.request_id.is_empty()
        || plan.policy_revision != declared_policy.policy.policy_version
        || certificate_policy.oid().to_string() != declared_policy.policy_oid
        || declared_policy.repository.is_empty()
        || expected_leaf_dns.is_empty()
    {
        return Err(TraceError::PolicyMismatch);
    }

    // Rebuild the drafts from the SAME declared policy snapshot; a hostile
    // caller cannot supply a separate claimed CP/CPS digest in this interface.
    let generated = generate(declared_policy).map_err(|_| TraceError::InvalidInput)?;
    if generated.publication_authorized {
        return Err(TraceError::InvalidInput);
    }
    let ca = Certificate::from_der(observed_ca.certificate_der())
        .map_err(|_| TraceError::CertificateInvalid)?;
    let verifier = LabX509Verifier::new(
        ca,
        certificate_policy.clone(),
        expected_leaf_dns.to_owned(),
    );
    verifier.verify(plan, leaf_certificate_der)
        .map_err(|_| TraceError::CertificateInvalid)?;

    Ok(VerifiedDraftCertificateTrace {
        ca_id: plan.ca_id.to_owned(),
        request_id: plan.request_id.to_owned(),
        policy_revision: plan.policy_revision.to_owned(),
        policy_oid: declared_policy.policy_oid.to_owned(),
        certificate_sha256: Sha256::digest(leaf_certificate_der).into(),
        issuer_ca_sha256: *observed_ca.certificate_sha256(),
        cp_sha256: generated.cp.sha256,
        cps_sha256: generated.cps.sha256,
        source_sha256: generated.policy_snapshot_sha256,
    })
}
