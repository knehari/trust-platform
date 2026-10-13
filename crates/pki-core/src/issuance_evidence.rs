//! Immutable, deterministic digest over a completed issuance correlation record.
//! This is a lab-grade integrity commitment, not a signed audit receipt.
//! Callers must separately authenticate source records and audit provenance.
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    InvalidIdentifier,
    InvalidDigest,
}

/// Values must be sourced from an independently authenticated, successful
/// database issuance record. Do not trust these from the CSR or an API caller.
pub struct IssuanceEvidence<'a> {
    pub ca_id: &'a str,
    pub request_id: &'a str,
    pub actor_id: &'a str,
    pub operation_ref: &'a str,
    pub signer_key_ref: &'a str,
    pub policy_revision: &'a str,
    pub tbs_sha256: &'a [u8],
    pub certificate_sha256: &'a [u8],
}

fn identifier_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Domain-separated, length-prefixed encoding prevents field ambiguity.
/// V1 is a stable evidence-commitment format, not a signature or authorization.
pub fn issuance_evidence_sha256(value: &IssuanceEvidence<'_>) -> Result<[u8; 32], ReceiptError> {
    let identifiers = [
        value.ca_id,
        value.request_id,
        value.actor_id,
        value.operation_ref,
        value.signer_key_ref,
        value.policy_revision,
    ];
    if !identifiers.iter().all(|item| identifier_valid(item)) {
        return Err(ReceiptError::InvalidIdentifier);
    }
    if value.tbs_sha256.len() != 32 || value.certificate_sha256.len() != 32 {
        return Err(ReceiptError::InvalidDigest);
    }
    let mut hash = Sha256::new();
    hash.update(b"trust-platform:issuance-evidence:v1\0");
    for field in identifiers {
        let bytes = field.as_bytes();
        hash.update((bytes.len() as u32).to_be_bytes());
        hash.update(bytes);
    }
    hash.update(value.tbs_sha256);
    hash.update(value.certificate_sha256);
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>(operation_ref: &'a str, cert: &'a [u8]) -> IssuanceEvidence<'a> {
        IssuanceEvidence {
            ca_id: "ca",
            request_id: "request",
            actor_id: "actor",
            operation_ref,
            signer_key_ref: "signer",
            policy_revision: "revision",
            tbs_sha256: &[0x11; 32],
            certificate_sha256: cert,
        }
    }

    #[test]
    fn commitment_is_deterministic_and_sensitive_to_certificate_and_operation() {
        let a = [0x22; 32];
        let b = [0x23; 32];
        let first = issuance_evidence_sha256(&sample("op", &a)).unwrap();
        assert_eq!(first, issuance_evidence_sha256(&sample("op", &a)).unwrap());
        assert_ne!(first, issuance_evidence_sha256(&sample("op2", &a)).unwrap());
        assert_ne!(first, issuance_evidence_sha256(&sample("op", &b)).unwrap());
    }

    #[test]
    fn rejects_ambiguous_identifiers_and_bad_digests() {
        let cert = [0x22; 32];
        assert_eq!(
            issuance_evidence_sha256(&sample("bad\noperation", &cert)),
            Err(ReceiptError::InvalidIdentifier)
        );
        assert_eq!(
            issuance_evidence_sha256(&sample("op", &[0x11; 31])),
            Err(ReceiptError::InvalidDigest)
        );
    }
}
