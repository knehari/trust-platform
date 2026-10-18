//! CRL signing orchestration: durable intent before signing, a single
//! signature, independent verification before persistence.
//!
//! Lab-only protocol scaffold, NOT a production API. A durable database intent
//! and an external signature CANNOT be atomic; see `orchestrator::issue_once`.

use crate::crl::{CrlAssembler, CrlError, CrlReservation, CrlVerifier};
use crate::orchestrator::ExternalSigner;
use sha2::{Digest, Sha256};

/// All references must already be authorized and bound to the reservation.
pub struct CrlPlan<'a> {
    pub reservation: &'a CrlReservation,
    pub signer_key_ref: &'a str,
    pub operation_ref: &'a str,
    pub tbs_der: &'a [u8],
}

/// The implementation MUST durably commit intent and return an error on replay.
pub trait CrlJournal {
    fn record_intent(&mut self, plan: &CrlPlan<'_>, tbs_sha256: &[u8; 32]) -> Result<(), CrlError>;

    fn mark_uncertain(&mut self, plan: &CrlPlan<'_>) -> Result<(), CrlError>;

    fn persist_verified(
        &mut self,
        plan: &CrlPlan<'_>,
        tbs_sha256: &[u8; 32],
        crl_sha256: &[u8; 32],
        crl_der: &[u8],
    ) -> Result<(), CrlError>;
}

fn record_uncertain<J: CrlJournal>(journal: &mut J, plan: &CrlPlan<'_>) {
    // Best effort only: a database outage can prevent this write.
    // Recovery MUST scan durable intents without a result and treat them as ambiguous.
    let _ = journal.mark_uncertain(plan);
}

/// May call sign_once at most once, and ONLY after durable intent exists.
/// Every failure after intent creation is fail-closed and must be reconciled;
/// a CRL number is never reused and a CRL is never re-signed automatically.
/// Returning Err does NOT imply the external signer made no signature.
pub fn crl_once<J, S, A, V>(
    journal: &mut J,
    signer: &mut S,
    assembler: &A,
    verifier: &V,
    plan: &CrlPlan<'_>,
) -> Result<Vec<u8>, CrlError>
where
    J: CrlJournal,
    S: ExternalSigner,
    A: CrlAssembler,
    V: CrlVerifier,
{
    if plan.tbs_der.is_empty() || plan.operation_ref.is_empty() {
        return Err(CrlError::JournalFailure);
    }

    let tbs_sha256: [u8; 32] = Sha256::digest(plan.tbs_der).into();
    // No signer invocation if the durable journal refuses or reports replay.
    journal.record_intent(plan, &tbs_sha256)?;

    let signature = match signer.sign_once(plan.signer_key_ref, plan.operation_ref, plan.tbs_der) {
        Ok(bytes) => bytes,
        Err(_) => {
            record_uncertain(journal, plan);
            return Err(CrlError::SigningFailure);
        }
    };

    let crl = match assembler.assemble(plan.tbs_der, &signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            record_uncertain(journal, plan);
            return Err(CrlError::AssemblyFailure);
        }
    };

    if verifier.verify(plan.reservation, &crl).is_err() {
        record_uncertain(journal, plan);
        return Err(CrlError::VerificationFailure);
    }

    let crl_sha256: [u8; 32] = Sha256::digest(&crl).into();
    if journal
        .persist_verified(plan, &tbs_sha256, &crl_sha256, &crl)
        .is_err()
    {
        record_uncertain(journal, plan);
        return Err(CrlError::PersistenceFailure);
    }

    Ok(crl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::IssueError;

    #[derive(Default)]
    struct FakeJournal {
        fail_intent: bool,
        fail_persist: bool,
        uncertain_calls: u32,
        persisted: Option<([u8; 32], [u8; 32], Vec<u8>)>,
        intent_calls: u32,
    }

    impl CrlJournal for FakeJournal {
        fn record_intent(&mut self, _p: &CrlPlan<'_>, _d: &[u8; 32]) -> Result<(), CrlError> {
            self.intent_calls += 1;
            if self.fail_intent {
                return Err(CrlError::JournalFailure);
            }
            Ok(())
        }
        fn mark_uncertain(&mut self, _p: &CrlPlan<'_>) -> Result<(), CrlError> {
            self.uncertain_calls += 1;
            Ok(())
        }
        fn persist_verified(
            &mut self,
            _p: &CrlPlan<'_>,
            tbs: &[u8; 32],
            crl_hash: &[u8; 32],
            der: &[u8],
        ) -> Result<(), CrlError> {
            if self.fail_persist {
                return Err(CrlError::PersistenceFailure);
            }
            self.persisted = Some((*tbs, *crl_hash, der.to_vec()));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeSigner {
        calls: u32,
        fail: bool,
    }
    impl ExternalSigner for FakeSigner {
        fn sign_once(&mut self, _k: &str, _o: &str, _t: &[u8]) -> Result<Vec<u8>, IssueError> {
            self.calls += 1;
            if self.fail {
                Err(IssueError::SigningFailure)
            } else {
                Ok(vec![0xab, 0xcd])
            }
        }
    }

    struct Assembler(bool);
    impl CrlAssembler for Assembler {
        fn assemble(&self, tbs: &[u8], sig: &[u8]) -> Result<Vec<u8>, CrlError> {
            if !self.0 {
                return Err(CrlError::AssemblyFailure);
            }
            let mut out = tbs.to_vec();
            out.extend_from_slice(sig);
            Ok(out)
        }
    }

    struct Verifier(bool);
    impl CrlVerifier for Verifier {
        fn verify(&self, _r: &CrlReservation, _d: &[u8]) -> Result<(), CrlError> {
            if self.0 {
                Ok(())
            } else {
                Err(CrlError::VerificationFailure)
            }
        }
    }

    fn reservation() -> CrlReservation {
        CrlReservation::new("lab-ca", 1, 1_700_000_000, 1_700_086_400, vec![], None).unwrap()
    }

    fn plan<'a>(r: &'a CrlReservation, tbs: &'a [u8], op: &'a str) -> CrlPlan<'a> {
        CrlPlan {
            reservation: r,
            signer_key_ref: "lab-key",
            operation_ref: op,
            tbs_der: tbs,
        }
    }

    #[test]
    fn never_signs_without_intent() {
        let r = reservation();
        let mut journal = FakeJournal {
            fail_intent: true,
            ..Default::default()
        };
        let mut signer = FakeSigner::default();
        let result = crl_once(
            &mut journal,
            &mut signer,
            &Assembler(true),
            &Verifier(true),
            &plan(&r, b"tbs", "op"),
        );
        assert_eq!(result, Err(CrlError::JournalFailure));
        assert_eq!(signer.calls, 0);
        assert_eq!(journal.uncertain_calls, 0);
        assert!(journal.persisted.is_none());
    }

    #[test]
    fn each_failure_after_intent_marks_uncertain() {
        let r = reservation();
        let cases: [(bool, bool, bool, bool, CrlError); 4] = [
            (true, false, false, false, CrlError::SigningFailure),
            (false, true, false, false, CrlError::AssemblyFailure),
            (false, false, true, false, CrlError::VerificationFailure),
            (false, false, false, true, CrlError::PersistenceFailure),
        ];
        for (sign_fail, asm_fail, ver_fail, persist_fail, expected) in cases {
            let mut journal = FakeJournal {
                fail_persist: persist_fail,
                ..Default::default()
            };
            let mut signer = FakeSigner {
                fail: sign_fail,
                ..Default::default()
            };
            let result = crl_once(
                &mut journal,
                &mut signer,
                &Assembler(!asm_fail),
                &Verifier(!ver_fail),
                &plan(&r, b"tbs", "op"),
            );
            assert_eq!(result, Err(expected.clone()));
            assert_eq!(journal.uncertain_calls, 1, "{expected:?}");
            assert_eq!(signer.calls, 1, "{expected:?}");
            assert!(journal.persisted.is_none(), "{expected:?}");
        }
    }

    #[test]
    fn success_signs_once_and_persists_verified_bytes() {
        let r = reservation();
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner::default();
        let der = crl_once(
            &mut journal,
            &mut signer,
            &Assembler(true),
            &Verifier(true),
            &plan(&r, b"tbs", "op"),
        )
        .unwrap();
        assert_eq!(signer.calls, 1);
        assert_eq!(journal.uncertain_calls, 0);
        let (tbs_hash, crl_hash, stored) = journal.persisted.unwrap();
        assert_eq!(stored, der);
        let expected_crl: [u8; 32] = Sha256::digest(&der).into();
        let expected_tbs: [u8; 32] = Sha256::digest(b"tbs").into();
        assert_eq!(crl_hash, expected_crl);
        assert_eq!(tbs_hash, expected_tbs);
    }

    #[test]
    fn empty_tbs_or_operation_is_rejected_before_journal() {
        let r = reservation();
        for (tbs, op) in [(&b""[..], "op"), (&b"tbs"[..], "")] {
            let mut journal = FakeJournal::default();
            let mut signer = FakeSigner::default();
            let result = crl_once(
                &mut journal,
                &mut signer,
                &Assembler(true),
                &Verifier(true),
                &plan(&r, tbs, op),
            );
            assert_eq!(result, Err(CrlError::JournalFailure));
            assert_eq!(journal.intent_calls, 0);
            assert_eq!(signer.calls, 0);
        }
    }
}
