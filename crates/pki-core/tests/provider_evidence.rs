//! Signed collector evidence tests using explicitly ephemeral lab keys.
//! A signed collector statement is NOT a signed statement from a real HSM.
#![cfg(feature = "lab-software")]

use sha2::{Digest, Sha256};
use std::cell::Cell;
use trust_pki_core::{
    orchestrator::{CertificateVerifier, IssuancePlan, IssueError},
    provider_evidence::{
        inspect_attested_provider, AttestedFinding, CollectorAttestation, EvidenceClaim,
        EvidenceError, EvidenceKind, PinnedCollectorKey,
    },
    reconciliation::{ProviderResponse, ReadOnlySigningProvider, ReconciliationError},
};
use trust_pki_crypto::{
    lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider,
};
use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

struct ReadOnlyFixture {
    reply: ProviderResponse,
    lookups: Cell<usize>,
}
impl ReadOnlySigningProvider for ReadOnlyFixture {
    fn lookup(
        &self,
        _: &str,
        _: &str,
    ) -> Result<ProviderResponse, ReconciliationError> {
        self.lookups.set(self.lookups.get() + 1);
        Ok(self.reply.clone())
    }
}
struct StrictFixtureVerifier;
impl CertificateVerifier for StrictFixtureVerifier {
    fn verify(&self, _: &IssuancePlan<'_>, certificate: &[u8]) -> Result<(), IssueError> {
        if certificate == b"fixture-cert" {
            Ok(())
        } else {
            Err(IssueError::VerificationFailure)
        }
    }
}

fn plan<'a>() -> IssuancePlan<'a> {
    IssuancePlan {
        ca_id: "lab-issuer",
        request_id: "req-1",
        actor_id: "operator",
        signer_key_ref: "lab-key",
        policy_revision: "v1",
        operation_ref: "op-1",
        serial_der: &[0x41],
        tbs_der: b"authorized-tbs",
    }
}

fn claim(kind: EvidenceKind) -> EvidenceClaim {
    EvidenceClaim {
        issuer_id: "lab-issuer".into(),
        operation_ref: "op-1".into(),
        signer_key_ref: "lab-key".into(),
        collector_key_id: "auditor-2026-q4".into(),
        audit_event_id: "audit-event-1".into(),
        observed_at_unix_seconds: 1_781_200_000,
        tbs_sha256: Sha256::digest(b"authorized-tbs").into(),
        raw_provider_log_sha256: [0x88; 32],
        certificate_sha256: match kind {
            EvidenceKind::RetrievedSignedCertificate => {
                Some(Sha256::digest(b"fixture-cert").into())
            }
            _ => None,
        },
        kind,
    }
}

fn sign_claim(
    signer: &EphemeralP256Signer,
    claim: EvidenceClaim,
) -> CollectorAttestation {
    let signature = signer.sign(
        signer.key_ref(),
        SignatureAlgorithm::EcdsaP256Sha256,
        &claim.canonical_bytes().unwrap(),
    ).unwrap();
    CollectorAttestation {
        claim,
        signature_der: signature,
    }
}

fn pinned_sec1(signer: &EphemeralP256Signer) -> Vec<u8> {
    let spki = signer.public_key_spki_der(signer.key_ref()).unwrap();
    SubjectPublicKeyInfoOwned::from_der(&spki).unwrap()
        .subject_public_key.as_bytes().unwrap().to_vec()
}

fn fixture_provider() -> ReadOnlyFixture {
    ReadOnlyFixture {
        reply: ProviderResponse::SignedCertificate {
            operation_ref: "op-1".into(),
            signer_key_ref: "lab-key".into(),
            certificate_der: b"fixture-cert".to_vec(),
            evidence_sha256: [0x88; 32],
        },
        lookups: Cell::new(0),
    }
}

#[test]
fn valid_collector_signature_and_exact_certificate_binding() {
    let signer = EphemeralP256Signer::generate("audit-collector").unwrap();
    let pubkey = pinned_sec1(&signer);
    let key = PinnedCollectorKey {
        key_id: "auditor-2026-q4",
        public_key_sec1: &pubkey,
    };
    let att = sign_claim(&signer, claim(EvidenceKind::RetrievedSignedCertificate));
    let provider = fixture_provider();
    let tbs_hash: [u8; 32] = Sha256::digest(b"authorized-tbs").into();
    let finding = inspect_attested_provider(
        &provider, &StrictFixtureVerifier, &plan(), &tbs_hash, &att, &key,
    ).unwrap();
    assert!(matches!(finding, AttestedFinding::VerifiedRecoveredCandidate { .. }));
    assert_eq!(provider.lookups.get(), 1);
}

#[test]
fn tampering_with_the_signed_claim_or_signature_is_rejected() {
    let signer = EphemeralP256Signer::generate("collector").unwrap();
    let pubkey = pinned_sec1(&signer);
    let key = PinnedCollectorKey {
        key_id: "auditor-2026-q4",
        public_key_sec1: &pubkey,
    };
    let mut att = sign_claim(&signer, claim(EvidenceKind::RetrievedSignedCertificate));
    att.claim.operation_ref = "changed-op".into();
    let tbs_hash: [u8; 32] = Sha256::digest(b"authorized-tbs").into();
    let provider = fixture_provider();
    assert_eq!(
        inspect_attested_provider(
            &provider, &StrictFixtureVerifier, &plan(), &tbs_hash, &att, &key
        ),
        Err(EvidenceError::InvalidSignature)
    );
    assert_eq!(provider.lookups.get(), 0);
    let mut att = sign_claim(&signer, claim(EvidenceKind::RetrievedSignedCertificate));
    att.signature_der[0] ^= 0x01;
    assert_eq!(
        inspect_attested_provider(
            &provider, &StrictFixtureVerifier, &plan(), &tbs_hash, &att, &key
        ),
        Err(EvidenceError::InvalidSignature)
    );
}

#[test]
fn untrusted_audit_key_and_journal_mismatch_fail_closed() {
    let signer = EphemeralP256Signer::generate("collector").unwrap();
    let wrong_signer = EphemeralP256Signer::generate("wrong").unwrap();
    let key = PinnedCollectorKey {
        key_id: "auditor-2026-q4",
        public_key_sec1: &pinned_sec1(&wrong_signer),
    };
    let att = sign_claim(&signer, claim(EvidenceKind::RetrievedSignedCertificate));
    let tbs_hash: [u8; 32] = Sha256::digest(b"authorized-tbs").into();
    assert_eq!(
        inspect_attested_provider(
            &fixture_provider(), &StrictFixtureVerifier, &plan(), &tbs_hash, &att, &key
        ),
        Err(EvidenceError::InvalidSignature)
    );
    let pubkey = pinned_sec1(&signer);
    let trusted_key = PinnedCollectorKey {
        key_id: "auditor-2026-q4",
        public_key_sec1: &pubkey,
    };
    assert_eq!(
        inspect_attested_provider(
            &fixture_provider(), &StrictFixtureVerifier, &plan(), &[0x12; 32], &att, &trusted_key
        ),
        Err(EvidenceError::IntentMismatch)
    );
}

#[test]
fn signed_claim_cannot_launder_different_certificate_or_provider_log() {
    let signer = EphemeralP256Signer::generate("collector").unwrap();
    let pubkey = pinned_sec1(&signer);
    let key = PinnedCollectorKey {
        key_id: "auditor-2026-q4",
        public_key_sec1: &pubkey,
    };
    let att = sign_claim(&signer, claim(EvidenceKind::RetrievedSignedCertificate));
    let tbs_hash: [u8; 32] = Sha256::digest(b"authorized-tbs").into();
    let altered = ReadOnlyFixture {
        reply: ProviderResponse::SignedCertificate {
            operation_ref: "op-1".into(),
            signer_key_ref: "lab-key".into(),
            certificate_der: b"another-cert".to_vec(),
            evidence_sha256: [0x88; 32],
        },
        lookups: Cell::new(0),
    };
    assert_eq!(
        inspect_attested_provider(
            &altered, &StrictFixtureVerifier, &plan(), &tbs_hash, &att, &key
        ),
        Err(EvidenceError::ProviderMismatch)
    );
    let altered_log = ReadOnlyFixture {
        reply: ProviderResponse::SignedCertificate {
            operation_ref: "op-1".into(),
            signer_key_ref: "lab-key".into(),
            certificate_der: b"fixture-cert".to_vec(),
            evidence_sha256: [0x77; 32],
        },
        lookups: Cell::new(0),
    };
    assert_eq!(
        inspect_attested_provider(
            &altered_log, &StrictFixtureVerifier, &plan(), &tbs_hash, &att, &key
        ),
        Err(EvidenceError::ProviderMismatch)
    );
}

#[test]
fn no_log_record_is_not_proof_of_no_signing() {
    let signer = EphemeralP256Signer::generate("collector").unwrap();
    let pubkey = pinned_sec1(&signer);
    let key = PinnedCollectorKey {
        key_id: "auditor-2026-q4",
        public_key_sec1: &pubkey,
    };
    for kind in [EvidenceKind::NoMatchingEvent, EvidenceKind::SigningEventObserved] {
        let att = sign_claim(&signer, claim(kind));
        let provider = fixture_provider();
        let tbs_hash: [u8; 32] = Sha256::digest(b"authorized-tbs").into();
        let finding = inspect_attested_provider(
            &provider, &StrictFixtureVerifier, &plan(), &tbs_hash, &att, &key,
        ).unwrap();
        assert!(matches!(
            finding,
            AttestedFinding::NoMatchingEventObserved { .. } | AttestedFinding::EventOnly { .. }
        ));
        assert_eq!(provider.lookups.get(), 0);
    }
}

#[test]
fn canonical_envelope_rejects_unbounded_metadata_and_unsigned_result() {
    let mut candidate = claim(EvidenceKind::SigningEventObserved);
    candidate.certificate_sha256 = Some([0x15; 32]);
    assert_eq!(candidate.canonical_bytes(), Err(EvidenceError::InvalidClaim));
    let mut candidate = claim(EvidenceKind::SigningEventObserved);
    candidate.operation_ref = "x".repeat(129);
    assert_eq!(candidate.canonical_bytes(), Err(EvidenceError::InvalidClaim));
    let mut candidate = claim(EvidenceKind::NoMatchingEvent);
    candidate.audit_event_id = "event id with spaces".into();
    assert_eq!(candidate.canonical_bytes(), Err(EvidenceError::InvalidClaim));
}
