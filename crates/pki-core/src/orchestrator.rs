//! Laboratory signing orchestration with injected failure boundaries.
//!
//! This is a protocol-level scaffold, NOT a production issuance API.
//! The signing provider, authenticated requester, verified policy, stable TBS
//! and independent certificate verifier must be supplied by trusted components.
//! A durable database intent and an external signature CANNOT be atomic.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueError {
    JournalFailure,
    ReplayedOrAmbiguousIntent,
    SigningFailure,
    AssemblyFailure,
    VerificationFailure,
    PersistenceFailure,
}

/// All references must already be authorized, unique, and bound to a validated
/// CSR/profile. Application code must not use CSR-controlled policy data.
pub struct IssuancePlan<'a> {
    pub ca_id: &'a str,
    pub request_id: &'a str,
    pub actor_id: &'a str,
    pub signer_key_ref: &'a str,
    pub policy_revision: &'a str,
    pub operation_ref: &'a str,
    pub serial_der: &'a [u8],
    pub tbs_der: &'a [u8],
}

/// The implementation MUST durably commit intent and return an error on replay.
/// This is an intentionally narrow interface; no DB grant is implied.
pub trait IssuanceJournal {
    fn record_intent(
        &mut self,
        plan: &IssuancePlan<'_>,
        tbs_sha256: &[u8; 32],
    ) -> Result<(), IssueError>;

    fn mark_uncertain(&mut self, plan: &IssuancePlan<'_>) -> Result<(), IssueError>;

    fn persist_verified(
        &mut self,
        plan: &IssuancePlan<'_>,
        tbs_sha256: &[u8; 32],
        certificate_sha256: &[u8; 32],
        certificate_der: &[u8],
    ) -> Result<(), IssueError>;
}

/// Returns only the signature bytes. In production, a signer implementation
/// must use a hardware key reference and enforce the authorized algorithm.
pub trait ExternalSigner {
    fn sign_once(
        &mut self,
        key_ref: &str,
        operation_ref: &str,
        tbs_der: &[u8],
    ) -> Result<Vec<u8>, IssueError>;
}

/// The assembler cannot mutate the already-journaled TBS.
pub trait CertificateAssembler {
    fn assemble(
        &self,
        tbs_der: &[u8],
        signature: &[u8],
    ) -> Result<Vec<u8>, IssueError>;
}

/// Verifier MUST independently validate the signature, issuer public key,
/// serial, TBS equality, profile, SANs, validity and policy OIDs.
/// A test double MUST NEVER be mistaken for a real X.509 verifier.
pub trait CertificateVerifier {
    fn verify(
        &self,
        plan: &IssuancePlan<'_>,
        certificate_der: &[u8],
    ) -> Result<(), IssueError>;
}

fn record_uncertain<J: IssuanceJournal>(journal: &mut J, plan: &IssuancePlan<'_>) {
    // Best effort only: a database outage can prevent this write.
    // Recovery MUST scan durable UNCONFIRMED intents and treat them as ambiguous.
    let _ = journal.mark_uncertain(plan);
}

/// May call sign_once at most once, and ONLY after durable intent exists.
/// Every failure after intent creation is fail-closed and must be reconciled.
/// Returning Err does NOT imply the external signer made no signature.
pub fn issue_once<J, S, A, V>(
    journal: &mut J,
    signer: &mut S,
    assembler: &A,
    verifier: &V,
    plan: &IssuancePlan<'_>,
) -> Result<Vec<u8>, IssueError>
where
    J: IssuanceJournal,
    S: ExternalSigner,
    A: CertificateAssembler,
    V: CertificateVerifier,
{
    if plan.tbs_der.is_empty() || plan.serial_der.is_empty() || plan.operation_ref.is_empty() {
        return Err(IssueError::JournalFailure);
    }

    let tbs_sha256: [u8; 32] = Sha256::digest(plan.tbs_der).into();
    // No signer invocation if durable journal refuses or reports replay.
    journal.record_intent(plan, &tbs_sha256)?;

    let signature = match signer.sign_once(plan.signer_key_ref, plan.operation_ref, plan.tbs_der) {
        Ok(bytes) => bytes,
        Err(_) => {
            record_uncertain(journal, plan);
            return Err(IssueError::SigningFailure);
        }
    };

    let certificate = match assembler.assemble(plan.tbs_der, &signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            record_uncertain(journal, plan);
            return Err(IssueError::AssemblyFailure);
        }
    };

    if verifier.verify(plan, &certificate).is_err() {
        record_uncertain(journal, plan);
        return Err(IssueError::VerificationFailure);
    }

    let certificate_sha256: [u8; 32] = Sha256::digest(&certificate).into();
    if journal
        .persist_verified(plan, &tbs_sha256, &certificate_sha256, &certificate)
        .is_err()
    {
        record_uncertain(journal, plan);
        return Err(IssueError::PersistenceFailure);
    }

    Ok(certificate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeJournal {
        durable_intent: bool,
        uncertain: bool,
        stored: bool,
        fail_intent: bool,
        fail_persist: bool,
    }

    impl IssuanceJournal for FakeJournal {
        fn record_intent(
            &mut self,
            _plan: &IssuancePlan<'_>,
            _digest: &[u8; 32],
        ) -> Result<(), IssueError> {
            if self.durable_intent || self.fail_intent {
                return Err(IssueError::ReplayedOrAmbiguousIntent);
            }
            self.durable_intent = true;
            Ok(())
        }

        fn mark_uncertain(&mut self, _plan: &IssuancePlan<'_>) -> Result<(), IssueError> {
            self.uncertain = true;
            Ok(())
        }

        fn persist_verified(
            &mut self,
            _plan: &IssuancePlan<'_>,
            _tbs: &[u8; 32],
            _hash: &[u8; 32],
            _cert: &[u8],
        ) -> Result<(), IssueError> {
            if self.fail_persist {
                return Err(IssueError::PersistenceFailure);
            }
            self.stored = true;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeSigner {
        calls: u32,
        fail: bool,
    }
    impl ExternalSigner for FakeSigner {
        fn sign_once(
            &mut self,
            _key: &str,
            _operation: &str,
            _tbs: &[u8],
        ) -> Result<Vec<u8>, IssueError> {
            self.calls += 1;
            if self.fail {
                Err(IssueError::SigningFailure)
            } else {
                Ok(vec![0xab, 0xcd])
            }
        }
    }

    struct Assembler;
    impl CertificateAssembler for Assembler {
        fn assemble(&self, tbs: &[u8], signature: &[u8]) -> Result<Vec<u8>, IssueError> {
            let mut output = tbs.to_vec();
            output.extend_from_slice(signature);
            Ok(output)
        }
    }

    struct Verifier(bool);
    impl CertificateVerifier for Verifier {
        fn verify(
            &self,
            _plan: &IssuancePlan<'_>,
            _certificate: &[u8],
        ) -> Result<(), IssueError> {
            if self.0 { Ok(()) } else { Err(IssueError::VerificationFailure) }
        }
    }

    fn plan<'a>() -> IssuancePlan<'a> {
        IssuancePlan {
            ca_id: "lab-ca",
            request_id: "req",
            actor_id: "trusted-actor",
            signer_key_ref: "lab-key",
            policy_revision: "v1",
            operation_ref: "single-operation",
            serial_der: &[0x42],
            tbs_der: b"lab-only-tbs",
        }
    }

    #[test]
    fn signing_never_happens_before_a_durable_intent() {
        let mut journal = FakeJournal { fail_intent: true, ..Default::default() };
        let mut signer = FakeSigner::default();
        assert!(issue_once(&mut journal, &mut signer, &Assembler, &Verifier(true), &plan()).is_err());
        assert_eq!(signer.calls, 0);
        assert!(!journal.stored);
    }

    #[test]
    fn successful_path_writes_result_and_only_signs_once() {
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner::default();
        let cert = issue_once(&mut journal, &mut signer, &Assembler, &Verifier(true), &plan()).unwrap();
        assert!(cert.ends_with(&[0xab, 0xcd]));
        assert_eq!(signer.calls, 1);
        assert!(journal.stored);
        assert!(!journal.uncertain);
    }

    #[test]
    fn signer_timeout_marks_ambiguous_and_prevents_blind_retry() {
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner { fail: true, ..Default::default() };
        assert_eq!(
            issue_once(&mut journal, &mut signer, &Assembler, &Verifier(true), &plan()),
            Err(IssueError::SigningFailure)
        );
        assert!(journal.uncertain);
        assert_eq!(
            issue_once(&mut journal, &mut signer, &Assembler, &Verifier(true), &plan()),
            Err(IssueError::ReplayedOrAmbiguousIntent)
        );
        assert_eq!(signer.calls, 1);
    }

    #[test]
    fn verification_failure_never_persists_certificate() {
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner::default();
        assert_eq!(
            issue_once(&mut journal, &mut signer, &Assembler, &Verifier(false), &plan()),
            Err(IssueError::VerificationFailure)
        );
        assert!(!journal.stored);
        assert!(journal.uncertain);
    }

    #[test]
    fn db_failure_after_signature_is_ambiguous_not_reissued() {
        let mut journal = FakeJournal { fail_persist: true, ..Default::default() };
        let mut signer = FakeSigner::default();
        assert_eq!(
            issue_once(&mut journal, &mut signer, &Assembler, &Verifier(true), &plan()),
            Err(IssueError::PersistenceFailure)
        );
        assert!(journal.uncertain);
        assert_eq!(
            issue_once(&mut journal, &mut signer, &Assembler, &Verifier(true), &plan()),
            Err(IssueError::ReplayedOrAmbiguousIntent)
        );
        assert_eq!(signer.calls, 1);
    }
}
