//! Structural X.509 binding for an immutable signing plan.
//! Does not verify issuer keys, trust chains, crypto signatures or profiles.
use crate::orchestrator::{
    issue_once, CertificateAssembler, CertificateVerifier, ExternalSigner, IssuanceJournal,
    IssuancePlan, IssueError,
};
use crate::serial::SerialNumber as ReservedSerial;
use crate::serial_binding::verify_certificate_reserved_serial;
use x509_cert::{
    der::{Decode, Encode},
    serial_number::SerialNumber,
    Certificate, TbsCertificate,
};

/// Apply before invoking an external signer, so malformed or mismatched TBS
/// never leads to a signing intent or cryptographic operation.
pub fn preflight_issuance_plan(plan: &IssuancePlan<'_>) -> Result<(), IssueError> {
    // Refuse missing or unbounded trusted metadata before any durable intent.
    for value in [
        plan.ca_id,
        plan.request_id,
        plan.actor_id,
        plan.signer_key_ref,
        plan.policy_revision,
        plan.operation_ref,
    ] {
        if value.is_empty()
            || value.len() > 256
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(IssueError::VerificationFailure);
        }
    }
    if plan.tbs_der.is_empty() || plan.tbs_der.len() > 64 * 1024 {
        return Err(IssueError::VerificationFailure);
    }
    let reserved = ReservedSerial::from_positive_der_content(plan.serial_der)
        .map_err(|_| IssueError::VerificationFailure)?;
    let tbs =
        TbsCertificate::from_der(plan.tbs_der).map_err(|_| IssueError::VerificationFailure)?;
    if tbs.to_der().map_err(|_| IssueError::VerificationFailure)? != plan.tbs_der {
        return Err(IssueError::VerificationFailure);
    }
    let expected = SerialNumber::new(reserved.as_der_content())
        .map_err(|_| IssueError::VerificationFailure)?;
    if tbs.serial_number != expected {
        return Err(IssueError::VerificationFailure);
    }
    Ok(())
}

/// Composes X.509 structural binding with a separate cryptographic verifier.
/// This wrapper MUST NOT be used with a permissive test double in production.
pub struct BoundX509Verifier<V>(pub V);

impl<V: CertificateVerifier> CertificateVerifier for BoundX509Verifier<V> {
    fn verify(&self, plan: &IssuancePlan<'_>, certificate_der: &[u8]) -> Result<(), IssueError> {
        preflight_issuance_plan(plan)?;
        if certificate_der.is_empty() || certificate_der.len() > 64 * 1024 {
            return Err(IssueError::VerificationFailure);
        }
        let cert =
            Certificate::from_der(certificate_der).map_err(|_| IssueError::VerificationFailure)?;
        if cert
            .tbs_certificate
            .to_der()
            .map_err(|_| IssueError::VerificationFailure)?
            != plan.tbs_der
        {
            return Err(IssueError::VerificationFailure);
        }
        let reserved = ReservedSerial::from_positive_der_content(plan.serial_der)
            .map_err(|_| IssueError::VerificationFailure)?;
        verify_certificate_reserved_serial(certificate_der, &reserved)
            .map_err(|_| IssueError::VerificationFailure)?;
        self.0.verify(plan, certificate_der)
    }
}

/// Sign only after an issuer-reserved serial matches a canonical X.509 TBS.
/// The independent verifier supplied by the caller must check cryptographic
/// signature validity, issuer binding, certificate profile and policy.
pub fn issue_x509_once<J, S, A, V>(
    journal: &mut J,
    signer: &mut S,
    assembler: &A,
    verifier: V,
    plan: &IssuancePlan<'_>,
) -> Result<Vec<u8>, IssueError>
where
    J: IssuanceJournal,
    S: ExternalSigner,
    A: CertificateAssembler,
    V: CertificateVerifier,
{
    preflight_issuance_plan(plan)?;
    issue_once(
        journal,
        signer,
        assembler,
        &BoundX509Verifier(verifier),
        plan,
    )
}

#[cfg(all(test, feature = "lab-software"))]
mod tests {
    use super::*;
    use crate::rsa_pss_x509_lab::issue_ephemeral_rsa_pss_root;

    #[derive(Default)]
    struct CountingJournal {
        intent_calls: usize,
    }

    impl IssuanceJournal for CountingJournal {
        fn record_intent(
            &mut self,
            _plan: &IssuancePlan<'_>,
            _digest: &[u8; 32],
        ) -> Result<(), IssueError> {
            self.intent_calls += 1;
            Ok(())
        }

        fn mark_uncertain(&mut self, _plan: &IssuancePlan<'_>) -> Result<(), IssueError> {
            Ok(())
        }

        fn persist_verified(
            &mut self,
            _plan: &IssuancePlan<'_>,
            _tbs_digest: &[u8; 32],
            _certificate_digest: &[u8; 32],
            _certificate: &[u8],
        ) -> Result<(), IssueError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingSigner {
        calls: usize,
    }

    impl ExternalSigner for CountingSigner {
        fn sign_once(
            &mut self,
            _key_ref: &str,
            _operation_ref: &str,
            _tbs: &[u8],
        ) -> Result<Vec<u8>, IssueError> {
            self.calls += 1;
            Err(IssueError::SigningFailure)
        }
    }

    struct UnreachableAssembler;

    impl CertificateAssembler for UnreachableAssembler {
        fn assemble(&self, _tbs: &[u8], _signature: &[u8]) -> Result<Vec<u8>, IssueError> {
            panic!("assembler must never be called for an invalid TBS")
        }
    }

    struct UnreachableVerifier;

    impl CertificateVerifier for UnreachableVerifier {
        fn verify(&self, _plan: &IssuancePlan<'_>, _der: &[u8]) -> Result<(), IssueError> {
            panic!("verifier must never be called for an invalid TBS")
        }
    }

    #[test]
    fn invalid_reserved_serial_never_creates_intent_or_calls_signer() {
        let root = issue_ephemeral_rsa_pss_root().unwrap();
        let tbs = root.tbs_certificate.to_der().unwrap();
        let plan = IssuancePlan {
            ca_id: "lab-ca",
            request_id: "lab-request",
            actor_id: "lab-actor",
            signer_key_ref: "lab-signer",
            policy_revision: "lab-policy",
            operation_ref: "lab-operation",
            serial_der: &[0x42],
            tbs_der: &tbs,
        };
        let mut journal = CountingJournal::default();
        let mut signer = CountingSigner::default();
        assert_eq!(
            issue_x509_once(
                &mut journal,
                &mut signer,
                &UnreachableAssembler,
                UnreachableVerifier,
                &plan
            ),
            Err(IssueError::VerificationFailure)
        );
        assert_eq!(journal.intent_calls, 0);
        assert_eq!(signer.calls, 0);
    }

    #[test]
    fn invalid_operational_metadata_is_rejected_before_journal_or_signer() {
        let root = issue_ephemeral_rsa_pss_root().unwrap();
        let tbs = root.tbs_certificate.to_der().unwrap();
        let serial = root.tbs_certificate.serial_number.as_bytes();
        let mut journal = CountingJournal::default();
        let mut signer = CountingSigner::default();
        let long_operation = "x".repeat(257);
        for operation in ["", " ambiguous", "trailing ", "line\nfeed", long_operation.as_str()] {
            let plan = IssuancePlan {
                ca_id: "lab-ca",
                request_id: "request",
                actor_id: "actor",
                signer_key_ref: "signer",
                policy_revision: "v1",
                operation_ref: operation,
                serial_der: serial,
                tbs_der: &tbs,
            };
            assert_eq!(
                issue_x509_once(
                    &mut journal,
                    &mut signer,
                    &UnreachableAssembler,
                    UnreachableVerifier,
                    &plan,
                ),
                Err(IssueError::VerificationFailure)
            );
        }
        assert_eq!(journal.intent_calls, 0);
        assert_eq!(signer.calls, 0);
    }

    #[test]
    fn rejects_unreserved_tbs_before_signing() {
        let root = issue_ephemeral_rsa_pss_root().unwrap();
        let tbs = root.tbs_certificate.to_der().unwrap();
        let serial_der = root.tbs_certificate.serial_number.to_der().unwrap();
        let valid_serial = &serial_der[2..];
        let plan = IssuancePlan {
            ca_id: "lab-ca",
            request_id: "lab-request",
            actor_id: "lab-actor",
            signer_key_ref: "lab-signer",
            policy_revision: "lab-policy",
            operation_ref: "lab-operation",
            serial_der: valid_serial,
            tbs_der: &tbs,
        };
        assert_eq!(preflight_issuance_plan(&plan), Ok(()));
        let mismatch = IssuancePlan {
            serial_der: &[0x42],
            ..plan
        };
        assert_eq!(
            preflight_issuance_plan(&mismatch),
            Err(IssueError::VerificationFailure)
        );
    }
}
