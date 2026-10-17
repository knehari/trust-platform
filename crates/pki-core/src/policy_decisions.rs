//! Two cryptographically signed CP/CPS policy decision statements.
//! LAB ONLY: pins provide key authenticity, NOT human identity/IdP authority.
//! Signatures do not prove the operational controls described in a CPS.
//! This has no signing/publishing or certificate recovery functionality.
use sha2::{Digest, Sha256};
use trust_pki_crypto::{canonical_p256_public_key_sec1, verify_p256_ecdsa_sha256};

const DOMAIN: &[u8] = b"STP-CP-CPS-DUAL-APPROVAL-V1\0";
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    InvalidClaim,
    UntrustedKey,
    InvalidSignature,
    IdenticalApprover,
    PolicyMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalClaim {
    pub ca_id: String,
    pub draft_id: String,
    pub policy_oid: String,
    pub policy_revision: String,
    pub cp_sha256: [u8; 32],
    pub cps_sha256: [u8; 32],
    pub effective_from_unix: i64,
    pub effective_until_unix: i64,
    pub decision_nonce: [u8; 32],
}
fn field_ok(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic())
}
impl ApprovalClaim {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        if ![
            &self.ca_id,
            &self.draft_id,
            &self.policy_oid,
            &self.policy_revision,
        ]
        .iter()
        .all(|v| field_ok(v))
            || self.cp_sha256 == [0; 32]
            || self.cps_sha256 == [0; 32]
            || self.decision_nonce == [0; 32]
            || self.effective_from_unix <= 0
            || self.effective_until_unix <= self.effective_from_unix
        {
            return Err(ApprovalError::InvalidClaim);
        }
        let mut v = DOMAIN.to_vec();
        for field in [
            &self.ca_id,
            &self.draft_id,
            &self.policy_oid,
            &self.policy_revision,
        ] {
            v.extend_from_slice(&(field.len() as u16).to_be_bytes());
            v.extend_from_slice(field.as_bytes());
        }
        v.extend_from_slice(&self.cp_sha256);
        v.extend_from_slice(&self.cps_sha256);
        v.extend_from_slice(&self.effective_from_unix.to_be_bytes());
        v.extend_from_slice(&self.effective_until_unix.to_be_bytes());
        v.extend_from_slice(&self.decision_nonce);
        Ok(v)
    }
}
pub struct PinnedPolicyKey<'a> {
    pub key_id: &'a str,
    pub sec1_p256_public: &'a [u8],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerStatement {
    pub key_id: String,
    pub signature_der: Vec<u8>,
}
pub struct DualApproval<'a> {
    pub claim: &'a ApprovalClaim,
    pub proposer: &'a SignerStatement,
    pub approver: &'a SignerStatement,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDualApproval {
    claim: ApprovalClaim,
    claim_canonical: Vec<u8>,
    proposer_key_id: String,
    approver_key_id: String,
    proposer_signature: Vec<u8>,
    approver_signature: Vec<u8>,
    evidence_sha256: [u8; 32],
}
impl VerifiedDualApproval {
    pub fn claim(&self) -> &ApprovalClaim {
        &self.claim
    }
    pub fn claim_canonical(&self) -> &[u8] {
        &self.claim_canonical
    }
    pub fn proposer_key_id(&self) -> &str {
        &self.proposer_key_id
    }
    pub fn approver_key_id(&self) -> &str {
        &self.approver_key_id
    }
    pub fn proposer_signature(&self) -> &[u8] {
        &self.proposer_signature
    }
    pub fn approver_signature(&self) -> &[u8] {
        &self.approver_signature
    }
    pub fn evidence_sha256(&self) -> &[u8; 32] {
        &self.evidence_sha256
    }
}

/// Both policy keys MUST be independently pinned by a trusted configuration
/// authority and provisioned to separate role-holders outside this function.
/// Their signing statements bind to the SAME immutable claim and nonce.
pub fn verify_dual_approval(
    signed: &DualApproval<'_>,
    pinned_proposer: &PinnedPolicyKey<'_>,
    pinned_approver: &PinnedPolicyKey<'_>,
    expected: &ApprovalClaim,
) -> Result<VerifiedDualApproval, ApprovalError> {
    if signed.claim != expected {
        return Err(ApprovalError::PolicyMismatch);
    }
    let bytes = signed.claim.canonical_bytes()?;
    if pinned_proposer.key_id == pinned_approver.key_id
        || pinned_proposer.sec1_p256_public == pinned_approver.sec1_p256_public
        || signed.proposer.key_id == signed.approver.key_id
    {
        return Err(ApprovalError::IdenticalApprover);
    }
    if signed.proposer.key_id != pinned_proposer.key_id
        || signed.approver.key_id != pinned_approver.key_id
        || !field_ok(pinned_proposer.key_id)
        || !field_ok(pinned_approver.key_id)
        || pinned_proposer.sec1_p256_public.is_empty()
        || pinned_approver.sec1_p256_public.is_empty()
    {
        return Err(ApprovalError::UntrustedKey);
    }
    // Compare the actual P-256 curve points, not caller-controlled key IDs or
    // SEC1 octets: one key can have different compressed/uncompressed encodings.
    let proposer_point = canonical_p256_public_key_sec1(pinned_proposer.sec1_p256_public)
        .map_err(|_| ApprovalError::UntrustedKey)?;
    let approver_point = canonical_p256_public_key_sec1(pinned_approver.sec1_p256_public)
        .map_err(|_| ApprovalError::UntrustedKey)?;
    if proposer_point == approver_point {
        return Err(ApprovalError::IdenticalApprover);
    }

    verify_p256_ecdsa_sha256(
        pinned_proposer.sec1_p256_public,
        &bytes,
        &signed.proposer.signature_der,
    )
    .map_err(|_| ApprovalError::InvalidSignature)?;
    verify_p256_ecdsa_sha256(
        pinned_approver.sec1_p256_public,
        &bytes,
        &signed.approver.signature_der,
    )
    .map_err(|_| ApprovalError::InvalidSignature)?;
    let mut sha = Sha256::new();
    sha.update(&bytes);
    sha.update((signed.proposer.key_id.len() as u16).to_be_bytes());
    sha.update(signed.proposer.key_id.as_bytes());
    sha.update((signed.proposer.signature_der.len() as u16).to_be_bytes());
    sha.update(&signed.proposer.signature_der);
    sha.update((signed.approver.key_id.len() as u16).to_be_bytes());
    sha.update(signed.approver.key_id.as_bytes());
    sha.update((signed.approver.signature_der.len() as u16).to_be_bytes());
    sha.update(&signed.approver.signature_der);
    let evidence_sha256 = sha.finalize().into();
    Ok(VerifiedDualApproval {
        claim: signed.claim.clone(),
        claim_canonical: bytes,
        proposer_key_id: signed.proposer.key_id.clone(),
        approver_key_id: signed.approver.key_id.clone(),
        proposer_signature: signed.proposer.signature_der.clone(),
        approver_signature: signed.approver.signature_der.clone(),
        evidence_sha256,
    })
}
