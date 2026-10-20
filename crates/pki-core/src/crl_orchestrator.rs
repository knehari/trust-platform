//! CRL signing orchestration: durable intent before signing, a single
//! signature, independent verification before persistence.
//!
//! Lab-only protocol scaffold, NOT a production API. A durable database intent
//! and an external signature CANNOT be atomic; see `orchestrator::issue_once`.

use crate::crl::{build_tbs_cert_list, CrlAssembler, CrlError, CrlReservation, CrlVerifier};
use crate::orchestrator::ExternalSigner;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// All references must already be authorized and bound to the reservation.
/// There is no caller-supplied TBS: `crl_once` builds the bytes it journals
/// and signs from `reservation` and `issuer`, so they cannot diverge from the
/// reserved snapshot. `issuer` MUST come from a trusted service-side record.
pub struct CrlPlan<'a> {
    pub reservation: &'a CrlReservation,
    pub issuer: &'a Certificate,
    pub signer_key_ref: &'a str,
    pub operation_ref: &'a str,
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
    if plan.operation_ref.is_empty() || plan.signer_key_ref.is_empty() {
        return Err(CrlError::JournalFailure);
    }
    // The verifier must check against the very issuer the TBS is built from;
    // otherwise a mismatch would only surface after the signature.
    if verifier.issuer() != plan.issuer {
        return Err(CrlError::IssuerMismatch);
    }
    // Built before the intent: an issuer the builder refuses never reaches
    // the journal or the signer.
    let tbs_der = build_tbs_cert_list(plan.issuer, plan.reservation)?;

    let tbs_sha256: [u8; 32] = Sha256::digest(&tbs_der).into();
    // No signer invocation if the durable journal refuses or reports replay.
    journal.record_intent(plan, &tbs_sha256)?;

    let signature = match signer.sign_once(plan.signer_key_ref, plan.operation_ref, &tbs_der) {
        Ok(bytes) => bytes,
        Err(_) => {
            record_uncertain(journal, plan);
            return Err(CrlError::SigningFailure);
        }
    };

    let crl = match assembler.assemble(&tbs_der, &signature) {
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
        intent_tbs: Option<[u8; 32]>,
        fail_uncertain: bool,
        operations: Vec<&'static str>,
    }

    /// Records which journal step saw which operation reference.
    fn seen(journal: &mut FakeJournal, step: &'static str, plan: &CrlPlan<'_>) {
        journal.operations.push(step);
        assert_eq!(plan.operation_ref, "op", "{step} got another operation_ref");
    }

    impl CrlJournal for FakeJournal {
        fn record_intent(&mut self, p: &CrlPlan<'_>, d: &[u8; 32]) -> Result<(), CrlError> {
            seen(self, "intent", p);
            self.intent_calls += 1;
            self.intent_tbs = Some(*d);
            if self.fail_intent {
                return Err(CrlError::JournalFailure);
            }
            Ok(())
        }
        fn mark_uncertain(&mut self, p: &CrlPlan<'_>) -> Result<(), CrlError> {
            seen(self, "uncertain", p);
            self.uncertain_calls += 1;
            if self.fail_uncertain {
                return Err(CrlError::JournalFailure);
            }
            Ok(())
        }
        fn persist_verified(
            &mut self,
            p: &CrlPlan<'_>,
            tbs: &[u8; 32],
            crl_hash: &[u8; 32],
            der: &[u8],
        ) -> Result<(), CrlError> {
            seen(self, "persist", p);
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
        signed: Vec<u8>,
        operation_ref: String,
    }
    impl ExternalSigner for FakeSigner {
        fn sign_once(&mut self, _k: &str, o: &str, t: &[u8]) -> Result<Vec<u8>, IssueError> {
            self.calls += 1;
            self.operation_ref = o.to_owned();
            self.signed = t.to_vec();
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

    struct Verifier {
        ok: bool,
        issuer: Certificate,
    }
    impl CrlVerifier for Verifier {
        fn verify(&self, _r: &CrlReservation, _d: &[u8]) -> Result<(), CrlError> {
            if self.ok {
                Ok(())
            } else {
                Err(CrlError::VerificationFailure)
            }
        }
        fn issuer(&self) -> &Certificate {
            &self.issuer
        }
    }

    fn verifier(issuer: &Certificate, ok: bool) -> Verifier {
        Verifier {
            ok,
            issuer: issuer.clone(),
        }
    }

    fn reservation() -> CrlReservation {
        CrlReservation::new("lab-ca", 1, 1_700_000_000, 1_700_086_400, vec![], None).unwrap()
    }

    /// Structurally valid issuer for the TBS builder; its key and signature
    /// are placeholders and are never verified by these tests.
    fn issuer() -> Certificate {
        use std::{str::FromStr, time::Duration};
        use x509_cert::{
            der::{
                asn1::{BitString, ObjectIdentifier, OctetString},
                Any, Encode,
            },
            ext::{
                pkix::{KeyUsage, KeyUsages},
                Extension,
            },
            name::Name,
            serial_number::SerialNumber,
            spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
            time::Validity,
            TbsCertificate, Version,
        };
        let oid = |s: &str| ObjectIdentifier::new(s).unwrap();
        let ecdsa_sha256 = AlgorithmIdentifierOwned {
            oid: oid("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let mut point = vec![0x04];
        point.extend([0x11; 64]);
        let name = Name::from_str("CN=Orchestrator Test Issuer").unwrap();
        Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[1]).unwrap(),
                signature: ecdsa_sha256.clone(),
                issuer: name.clone(),
                validity: Validity::from_now(Duration::from_secs(3600)).unwrap(),
                subject: name,
                subject_public_key_info: SubjectPublicKeyInfoOwned {
                    algorithm: AlgorithmIdentifierOwned {
                        oid: oid("1.2.840.10045.2.1"),
                        parameters: Some(Any::encode_from(&oid("1.2.840.10045.3.1.7")).unwrap()),
                    },
                    subject_public_key: BitString::from_bytes(&point).unwrap(),
                },
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(vec![
                    crate::x509_extensions::subject_key_identifier(&[7; 20]).unwrap(),
                    Extension {
                        extn_id: oid("2.5.29.15"),
                        critical: true,
                        extn_value: OctetString::new(
                            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                                .to_der()
                                .unwrap(),
                        )
                        .unwrap(),
                    },
                ]),
            },
            signature_algorithm: ecdsa_sha256,
            signature: BitString::from_bytes(&[0]).unwrap(),
        }
    }

    fn plan<'a>(r: &'a CrlReservation, issuer: &'a Certificate, op: &'a str) -> CrlPlan<'a> {
        CrlPlan {
            reservation: r,
            issuer,
            signer_key_ref: "lab-key",
            operation_ref: op,
        }
    }

    #[test]
    fn never_signs_without_intent() {
        let r = reservation();
        let issuer = issuer();
        let mut journal = FakeJournal {
            fail_intent: true,
            ..Default::default()
        };
        let mut signer = FakeSigner::default();
        let result = crl_once(
            &mut journal,
            &mut signer,
            &Assembler(true),
            &verifier(&issuer, true),
            &plan(&r, &issuer, "op"),
        );
        assert_eq!(result, Err(CrlError::JournalFailure));
        assert_eq!(signer.calls, 0);
        assert_eq!(journal.uncertain_calls, 0);
        assert!(journal.persisted.is_none());
    }

    #[test]
    fn each_failure_after_intent_marks_uncertain() {
        let r = reservation();
        let issuer = issuer();
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
                &verifier(&issuer, !ver_fail),
                &plan(&r, &issuer, "op"),
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
        let issuer = issuer();
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner::default();
        let der = crl_once(
            &mut journal,
            &mut signer,
            &Assembler(true),
            &verifier(&issuer, true),
            &plan(&r, &issuer, "op"),
        )
        .unwrap();
        assert_eq!(signer.calls, 1);
        assert_eq!(journal.uncertain_calls, 0);
        let built = build_tbs_cert_list(&issuer, &r).unwrap();
        assert_eq!(signer.signed, built);
        let (tbs_hash, crl_hash, stored) = journal.persisted.unwrap();
        assert_eq!(stored, der);
        let expected_crl: [u8; 32] = Sha256::digest(&der).into();
        let expected_tbs: [u8; 32] = Sha256::digest(&built).into();
        assert_eq!(crl_hash, expected_crl);
        assert_eq!(tbs_hash, expected_tbs);
    }

    #[test]
    fn empty_operation_is_rejected_before_journal() {
        let r = reservation();
        let issuer = issuer();
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner::default();
        let result = crl_once(
            &mut journal,
            &mut signer,
            &Assembler(true),
            &verifier(&issuer, true),
            &plan(&r, &issuer, ""),
        );
        assert_eq!(result, Err(CrlError::JournalFailure));
        assert_eq!(journal.intent_calls, 0);
        assert_eq!(signer.calls, 0);
    }

    /// Regression: the TBS used to be a caller field, journaled and signed
    /// without any link to the reservation. Intent, signature and stored
    /// digest now all cover the bytes built from the reservation.
    #[test]
    fn intent_and_signature_cover_the_tbs_built_from_the_reservation() {
        let r = reservation();
        let issuer = issuer();
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner::default();
        crl_once(
            &mut journal,
            &mut signer,
            &Assembler(true),
            &verifier(&issuer, true),
            &plan(&r, &issuer, "op"),
        )
        .unwrap();
        let built = build_tbs_cert_list(&issuer, &r).unwrap();
        let built_sha256: [u8; 32] = Sha256::digest(&built).into();
        assert_eq!(journal.intent_tbs, Some(built_sha256));
        assert_eq!(signer.signed, built);
    }

    #[test]
    fn issuer_refused_by_the_builder_never_reaches_journal_or_signer() {
        let r = reservation();
        let mut issuer = issuer();
        issuer.tbs_certificate.extensions = None;
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner::default();
        let result = crl_once(
            &mut journal,
            &mut signer,
            &Assembler(true),
            &verifier(&issuer, true),
            &plan(&r, &issuer, "op"),
        );
        assert_eq!(result, Err(CrlError::Encoding));
        assert_eq!(journal.intent_calls, 0);
        assert_eq!(signer.calls, 0);
    }

    /// The plan's operation reference reaches every journal step and the
    /// signer (the store binds intent, uncertainty and storage to it).
    #[test]
    fn operation_ref_reaches_journal_and_signer() {
        let r = reservation();
        let issuer = issuer();
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner::default();
        crl_once(
            &mut journal,
            &mut signer,
            &Assembler(true),
            &verifier(&issuer, true),
            &plan(&r, &issuer, "op"),
        )
        .unwrap();
        assert_eq!(journal.operations, ["intent", "persist"]);
        assert_eq!(signer.operation_ref, "op");
    }

    /// mark_uncertain is best effort: when it fails too, the original error
    /// is returned and nothing is persisted (recovery scans durable intents).
    #[test]
    fn failing_mark_uncertain_keeps_the_original_error() {
        let r = reservation();
        let issuer = issuer();
        for (sign_fail, ver_fail, expected) in [
            (true, false, CrlError::SigningFailure),
            (false, true, CrlError::VerificationFailure),
        ] {
            let mut journal = FakeJournal {
                fail_uncertain: true,
                ..Default::default()
            };
            let mut signer = FakeSigner {
                fail: sign_fail,
                ..Default::default()
            };
            let result = crl_once(
                &mut journal,
                &mut signer,
                &Assembler(true),
                &verifier(&issuer, !ver_fail),
                &plan(&r, &issuer, "op"),
            );
            assert_eq!(result, Err(expected.clone()));
            assert_eq!(journal.operations, ["intent", "uncertain"], "{expected:?}");
            assert!(journal.persisted.is_none(), "{expected:?}");
            assert_eq!(signer.calls, 1, "{expected:?}");
        }
    }

    /// Regression: a verifier for another issuer, or an empty signer key
    /// reference, used to be noticed only after the intent and signature.
    #[test]
    fn mismatched_verifier_or_empty_key_ref_never_reaches_journal_or_signer() {
        let r = reservation();
        let issuer = issuer();
        let mut other = issuer.clone();
        other.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[2]).unwrap();
        let mut journal = FakeJournal::default();
        let mut signer = FakeSigner::default();
        assert_eq!(
            crl_once(
                &mut journal,
                &mut signer,
                &Assembler(true),
                &verifier(&other, true),
                &plan(&r, &issuer, "op"),
            ),
            Err(CrlError::IssuerMismatch)
        );
        let mut no_key = plan(&r, &issuer, "op");
        no_key.signer_key_ref = "";
        assert_eq!(
            crl_once(
                &mut journal,
                &mut signer,
                &Assembler(true),
                &verifier(&issuer, true),
                &no_key,
            ),
            Err(CrlError::JournalFailure)
        );
        assert_eq!(journal.intent_calls, 0);
        assert_eq!(signer.calls, 0);
    }
}
