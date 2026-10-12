//! Lab-only pre-sign TBS certificatePolicies evidence. An OID string supplied
//! by the client is insufficient: inspect the exact DER that will be signed.
//! This struct is NOT an authenticated CP/CPS approval or identity attestation.
use crate::{
    orchestrator::IssuancePlan,
    x509_extensions::{certificate_policies, ApprovedPolicyBinding},
};
use sha2::{Digest, Sha256};
use x509_cert::{der::{Decode, Encode}, TbsCertificate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    InvalidTbs,
    WrongPolicyRevision,
    WrongPolicyOid,
    WrongSerial,
    WrongAlgorithm,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPresignPolicyIntent {
    ca_id: String,
    request_id: String,
    policy_oid: String,
    tbs_sha256: [u8; 32],
}
impl VerifiedPresignPolicyIntent {
    pub fn ca_id(&self) -> &str { &self.ca_id }
    pub fn request_id(&self) -> &str { &self.request_id }
    pub fn policy_oid(&self) -> &str { &self.policy_oid }
    pub fn tbs_sha256(&self) -> &[u8; 32] { &self.tbs_sha256 }
}

/// Inspect TBS DER and compare the exact X.509 certificatePolicies extension
/// with a trusted binding. Policy approval, its effective dates and issuer
/// authorization must still be checked by the database in the same transaction
/// as the signing intent. No HSM or external signing occurs here.
pub fn verify_presign_policy(
    plan: &IssuancePlan<'_>,
    required_policy_revision: &str,
    expected_policy: &ApprovedPolicyBinding,
) -> Result<VerifiedPresignPolicyIntent, GateError> {
    if plan.ca_id.is_empty() || plan.request_id.is_empty()
        || plan.tbs_der.is_empty() || plan.serial_der.is_empty()
        || plan.policy_revision != required_policy_revision
    {
        return Err(GateError::WrongPolicyRevision);
    }
    let tbs = TbsCertificate::from_der(plan.tbs_der).map_err(|_| GateError::InvalidTbs)?;
    if tbs.to_der().map_err(|_| GateError::InvalidTbs)? != plan.tbs_der {
        return Err(GateError::InvalidTbs);
    }
    if tbs.serial_number.as_bytes() != plan.serial_der {
        return Err(GateError::WrongSerial);
    }
    if tbs.signature.oid.to_string() != "1.2.840.10045.4.3.2"
        || tbs.signature.parameters.is_some() {
        return Err(GateError::WrongAlgorithm);
    }
    let expected = certificate_policies(expected_policy).map_err(|_| GateError::WrongPolicyOid)?;
    let actual: Vec<_> = tbs.extensions.as_ref()
        .ok_or(GateError::WrongPolicyOid)?
        .iter().filter(|extension| extension.extn_id.to_string()=="2.5.29.32")
        .collect();
    if actual.len()!=1 || actual[0]!=&expected {
        return Err(GateError::WrongPolicyOid);
    }
    Ok(VerifiedPresignPolicyIntent {
        ca_id: plan.ca_id.to_owned(),
        request_id: plan.request_id.to_owned(),
        policy_oid: expected_policy.oid().to_string(),
        tbs_sha256: Sha256::digest(plan.tbs_der).into(),
    })
}
