//! Read-only inspection of ambiguous external signing outcomes (lab scaffold).
//!
//! This module NEVER invokes a signer, transitions a request to SIGNED, or
//! treats "not found" as proof that no signature occurred. A future production
//! implementation must authenticate the provider, verify its evidence source,
//! and bind operation references to the original immutable signing journal.

use crate::orchestrator::{CertificateVerifier, IssuancePlan};
use sha2::{Digest, Sha256};

pub const MAX_RECONCILIATION_CERT_DER: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationError {
    InvalidPlan,
    ProviderUnavailable,
    ProviderEvidenceInvalid,
    CorrelationMismatch,
    InvalidCertificate,
}

/// A read-only provider response. This is data, NOT proof of authenticity by
/// itself: the provider adapter's transport and evidence attestation matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderResponse {
    SignedCertificate {
        operation_ref: String,
        signer_key_ref: String,
        certificate_der: Vec<u8>,
        evidence_sha256: [u8; 32],
    },
    /// Provider says no matching result was found. This is NOT a proof
    /// that the signing operation was never executed.
    NoResultFound {
        operation_ref: String,
        evidence_sha256: [u8; 32],
    },
    /// Unavailable, timed out or inconclusive information.
    Unknown,
}

/// Deliberately no sign method. A production adapter MUST use a verified
/// read-only provider credential and authenticated, integrity-protected channel.
pub trait ReadOnlySigningProvider {
    fn lookup(
        &self,
        operation_ref: &str,
        signer_key_ref: &str,
    ) -> Result<ProviderResponse, ReconciliationError>;
}

/// Even verified output remains quarantined pending a separate review process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationFinding {
    VerifiedCertificate {
        certificate_sha256: [u8; 32],
        provider_evidence_sha256: [u8; 32],
    },
    NoResultEvidence {
        provider_evidence_sha256: [u8; 32],
    },
    Unknown,
}

/// Strictly read-only: DOES NOT modify PostgreSQL, approve publishing or sign.
/// expected_tbs_sha256 must be read from the immutable database signing intent.
/// The X.509 verifier must be independently trusted for issuer/profile checks.
pub fn inspect_provider<P: ReadOnlySigningProvider, V: CertificateVerifier>(
    provider: &P,
    verifier: &V,
    plan: &IssuancePlan<'_>,
    expected_tbs_sha256: &[u8; 32],
) -> Result<ReconciliationFinding, ReconciliationError> {
    if plan.operation_ref.is_empty()
        || plan.signer_key_ref.is_empty()
        || plan.tbs_der.is_empty()
        || plan.serial_der.is_empty()
        || expected_tbs_sha256 == &[0u8; 32]
    {
        return Err(ReconciliationError::InvalidPlan);
    }
    let actual_tbs_sha256: [u8; 32] = Sha256::digest(plan.tbs_der).into();
    if &actual_tbs_sha256 != expected_tbs_sha256 {
        return Err(ReconciliationError::CorrelationMismatch);
    }

    match provider.lookup(plan.operation_ref, plan.signer_key_ref)? {
        ProviderResponse::SignedCertificate {
            operation_ref,
            signer_key_ref,
            certificate_der,
            evidence_sha256,
        } => {
            if operation_ref != plan.operation_ref || signer_key_ref != plan.signer_key_ref {
                return Err(ReconciliationError::CorrelationMismatch);
            }
            if evidence_sha256 == [0u8; 32]
                || certificate_der.is_empty()
                || certificate_der.len() > MAX_RECONCILIATION_CERT_DER
            {
                return Err(ReconciliationError::ProviderEvidenceInvalid);
            }
            verifier
                .verify(plan, &certificate_der)
                .map_err(|_| ReconciliationError::InvalidCertificate)?;
            Ok(ReconciliationFinding::VerifiedCertificate {
                certificate_sha256: Sha256::digest(&certificate_der).into(),
                provider_evidence_sha256: evidence_sha256,
            })
        }
        ProviderResponse::NoResultFound {
            operation_ref,
            evidence_sha256,
        } => {
            if operation_ref != plan.operation_ref {
                return Err(ReconciliationError::CorrelationMismatch);
            }
            if evidence_sha256 == [0u8; 32] {
                return Err(ReconciliationError::ProviderEvidenceInvalid);
            }
            Ok(ReconciliationFinding::NoResultEvidence {
                provider_evidence_sha256: evidence_sha256,
            })
        }
        ProviderResponse::Unknown => Ok(ReconciliationFinding::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::{CertificateVerifier, IssueError};

    struct FakeProvider(ProviderResponse);
    impl ReadOnlySigningProvider for FakeProvider {
        fn lookup(
            &self,
            _: &str,
            _: &str,
        ) -> Result<ProviderResponse, ReconciliationError> {
            Ok(self.0.clone())
        }
    }

    struct FakeVerifier(bool);
    impl CertificateVerifier for FakeVerifier {
        fn verify(&self, _: &IssuancePlan<'_>, _: &[u8]) -> Result<(), IssueError> {
            if self.0 {
                Ok(())
            } else {
                Err(IssueError::VerificationFailure)
            }
        }
    }

    fn plan<'a>() -> IssuancePlan<'a> {
        IssuancePlan {
            ca_id: "lab",
            request_id: "request",
            actor_id: "maker",
            signer_key_ref: "key-1",
            policy_revision: "v1",
            operation_ref: "op-1",
            serial_der: &[0x41],
            tbs_der: b"original-tbs",
        }
    }

    fn digest() -> [u8; 32] {
        Sha256::digest(b"original-tbs").into()
    }

    #[test]
    fn accepted_provider_result_still_requires_verifier() {
        let provider = FakeProvider(ProviderResponse::SignedCertificate {
            operation_ref: "op-1".into(),
            signer_key_ref: "key-1".into(),
            certificate_der: b"mock-only-der".to_vec(),
            evidence_sha256: [1; 32],
        });
        assert!(matches!(
            inspect_provider(&provider, &FakeVerifier(true), &plan(), &digest()),
            Ok(ReconciliationFinding::VerifiedCertificate { .. })
        ));
        assert_eq!(
            inspect_provider(&provider, &FakeVerifier(false), &plan(), &digest()),
            Err(ReconciliationError::InvalidCertificate)
        );
    }

    #[test]
    fn incorrect_operation_or_key_is_rejected() {
        for (op, key) in [("wrong", "key-1"), ("op-1", "wrong")] {
            let provider = FakeProvider(ProviderResponse::SignedCertificate {
                operation_ref: op.into(),
                signer_key_ref: key.into(),
                certificate_der: b"mock-only-der".to_vec(),
                evidence_sha256: [1; 32],
            });
            assert_eq!(
                inspect_provider(&provider, &FakeVerifier(true), &plan(), &digest()),
                Err(ReconciliationError::CorrelationMismatch)
            );
        }
    }

    #[test]
    fn changed_journal_tbs_hash_is_rejected_before_provider_query() {
        let provider = FakeProvider(ProviderResponse::Unknown);
        assert_eq!(
            inspect_provider(&provider, &FakeVerifier(true), &plan(), &[3; 32]),
            Err(ReconciliationError::CorrelationMismatch)
        );
    }

    #[test]
    fn no_result_never_becomes_permission_to_retry() {
        let provider = FakeProvider(ProviderResponse::NoResultFound {
            operation_ref: "op-1".into(),
            evidence_sha256: [2; 32],
        });
        assert_eq!(
            inspect_provider(&provider, &FakeVerifier(true), &plan(), &digest()),
            Ok(ReconciliationFinding::NoResultEvidence {
                provider_evidence_sha256: [2; 32]
            })
        );
    }

    #[test]
    fn zero_evidence_and_unknown_result_remain_fail_closed() {
        let zero = FakeProvider(ProviderResponse::NoResultFound {
            operation_ref: "op-1".into(),
            evidence_sha256: [0; 32],
        });
        assert_eq!(
            inspect_provider(&zero, &FakeVerifier(true), &plan(), &digest()),
            Err(ReconciliationError::ProviderEvidenceInvalid)
        );
        let unknown = FakeProvider(ProviderResponse::Unknown);
        assert_eq!(
            inspect_provider(&unknown, &FakeVerifier(true), &plan(), &digest()),
            Ok(ReconciliationFinding::Unknown)
        );
    }
}
