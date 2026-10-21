//! Real P-256 X.509 signing + independent verification + PostgreSQL persistence.
//! Ephemeral CA only. Not a production PKI or real process-crash recovery.
#![cfg(all(feature = "postgres-store", feature = "lab-software"))]

use std::env;
use trust_pki_core::{
    csr::verify_pkcs10_p256,
    lab_ca::EphemeralLabCa,
    lab_x509_verifier::{LabCertificateAssembler, LabX509Verifier},
    orchestrator::{
        issue_once, CertificateAssembler, CertificateVerifier, ExternalSigner, IssuancePlan,
        IssueError,
    },
    postgres_store::PgIssuanceStore,
    serial::SerialNumber,
    x509_extensions::ApprovedPolicyBinding,
};
use trust_pki_crypto::SignatureAlgorithm;
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
use x509_cert::{
    der::{Decode, DecodePem, Encode},
    request::CertReq,
    Certificate,
};

fn context() -> (
    trust_pki_core::csr::VerifiedCsr,
    trust_pki_policy::Authorization,
    ApprovedPolicyBinding,
) {
    let csr = CertReq::from_pem(include_str!("fixtures/ecdsa-p256-request.pem")).unwrap();
    let der = csr.to_der().unwrap();
    let verified = verify_pkcs10_p256(&der, "api.lab.invalid").unwrap();
    let policy = StaticPolicy {
        profile_id: "lab-server".into(),
        policy_version: "v1".into(),
        allowed_actors: vec!["lab-actor".into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
        max_validity_days: 3,
        max_dns_sans: 2,
    };
    let san = ["api.lab.invalid"];
    let request = IssuanceRequest {
        profile_id: "lab-server",
        subject_common_name: "api.lab.invalid",
        dns_sans: &san,
        validity_days: 1,
        ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    };
    let actor = AuthenticatedPrincipal {
        subject_id: "lab-actor",
    };
    let authorization = policy.authorize(&actor, &request).unwrap();
    // Test fixture OID, unassigned, not a real approved document.
    let binding =
        ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "lab-doc-v1", [7; 32]).unwrap();
    (verified, authorization, binding)
}

#[test]
fn real_x509_certificate_is_verified_then_persisted_once() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let mut db = PgIssuanceStore::connect_lab(&url).unwrap();
    let ca_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let (csr, authorization, binding) = context();
    let request = db
        .create_request(
            ca_id,
            "real-x509-verified-1",
            csr.fingerprint_sha256(),
            "lab-actor",
            "v1",
        )
        .unwrap();
    assert!(!request.replay);
    db.transition(
        ca_id,
        &request.request_id,
        "RECEIVED",
        "CSR_VALIDATED",
        "lab-actor",
    )
    .unwrap();
    db.transition(
        ca_id,
        &request.request_id,
        "CSR_VALIDATED",
        "AUTHORIZED",
        "lab-actor",
    )
    .unwrap();
    let serial_data = db
        .reserve_serial(ca_id, &request.request_id, "lab-actor")
        .unwrap();
    let serial = SerialNumber::from_positive_der_content(&serial_data).unwrap();
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let tbs = ca
        .prepare_leaf_tbs(&csr, &authorization, &serial, &binding)
        .unwrap();
    let tbs_der = tbs.to_der().unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();

    let plan = IssuancePlan {
        ca_id,
        request_id: &request.request_id,
        actor_id: "lab-actor",
        signer_key_ref: &key_ref,
        policy_revision: "v1",
        operation_ref: "real-verified-op-1",
        serial_der: &serial_data,
        tbs_der: &tbs_der,
    };
    let verifier = LabX509Verifier::new(root, binding, "api.lab.invalid".into());
    let result = issue_once(&mut db, &mut ca, &LabCertificateAssembler, &verifier, &plan).unwrap();
    let parsed = Certificate::from_der(&result).unwrap();
    assert_eq!(parsed.tbs_certificate.serial_number.as_bytes(), serial_data);

    // Separate connection confirms that the signed DER is actually persistent,
    // not merely returned from the signing function.
    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let row = reader
        .query_one(
            "SELECT c.certificate_der, si.outcome
         FROM certificate c JOIN signing_intent si
           ON si.ca_id=c.ca_id AND si.request_id=c.request_id
         WHERE c.request_id=$1::text::uuid",
            &[&request.request_id],
        )
        .unwrap();
    let persisted: Vec<u8> = row.get(0);
    let outcome: String = row.get(1);
    assert_eq!(persisted, result);
    assert_eq!(outcome, "CERTIFICATE_STORED");

    let replay = issue_once(&mut db, &mut ca, &LabCertificateAssembler, &verifier, &plan);
    assert_eq!(replay, Err(IssueError::ReplayedOrAmbiguousIntent));
}

#[test]
fn lab_verifier_rejects_fake_signature_and_wrong_domain() {
    let (csr, authorization, binding) = context();
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let serial = SerialNumber::from_positive_der_content(&[0x22]).unwrap();
    let tbs = ca
        .prepare_leaf_tbs(&csr, &authorization, &serial, &binding)
        .unwrap();
    let tbs_der = tbs.to_der().unwrap();
    let fake_certificate = LabCertificateAssembler
        .assemble(&tbs_der, &[1, 2, 3])
        .unwrap();
    let plan = IssuancePlan {
        ca_id: "lab",
        request_id: "test",
        actor_id: "actor",
        signer_key_ref: "lab",
        policy_revision: "v1",
        operation_ref: "one",
        serial_der: serial.as_der_content(),
        tbs_der: &tbs_der,
    };
    let verifier = LabX509Verifier::new(
        ca.root_certificate().clone(),
        binding.clone(),
        "api.lab.invalid".into(),
    );
    assert_eq!(
        verifier.verify(&plan, &fake_certificate),
        Err(IssueError::VerificationFailure)
    );

    let key_ref = ca.lab_signer_key_ref().to_owned();
    let signature = ca.sign_once(&key_ref, "single", &tbs_der).unwrap();
    let authentic_der = LabCertificateAssembler
        .assemble(&tbs_der, &signature)
        .unwrap();
    assert_eq!(verifier.verify(&plan, &authentic_der), Ok(()));

    let wrong_domain = LabX509Verifier::new(
        ca.root_certificate().clone(),
        binding,
        "other.lab.invalid".into(),
    );
    assert_eq!(
        wrong_domain.verify(&plan, &authentic_der),
        Err(IssueError::VerificationFailure)
    );
}

#[test]
fn read_only_reconciliation_checks_real_x509_and_immutable_intent() {
    use sha2::{Digest, Sha256};
    use trust_pki_core::reconciliation::{
        inspect_provider, ProviderResponse, ReadOnlySigningProvider, ReconciliationError,
        ReconciliationFinding,
    };

    struct LabReadOnlyProvider(ProviderResponse);
    impl ReadOnlySigningProvider for LabReadOnlyProvider {
        fn lookup(
            &self,
            _operation: &str,
            _key_ref: &str,
        ) -> Result<ProviderResponse, ReconciliationError> {
            Ok(self.0.clone())
        }
    }

    let (csr, authorization, binding) = context();
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let serial = SerialNumber::from_positive_der_content(&[0x43]).unwrap();
    let tbs = ca
        .prepare_leaf_tbs(&csr, &authorization, &serial, &binding)
        .unwrap();
    let tbs_der = tbs.to_der().unwrap();
    let signer_key = ca.lab_signer_key_ref().to_owned();
    let signature = ca
        .sign_once(&signer_key, "read-only-lab-op", &tbs_der)
        .unwrap();
    let certificate_der = LabCertificateAssembler
        .assemble(&tbs_der, &signature)
        .unwrap();
    let plan = IssuancePlan {
        ca_id: "lab-ca",
        request_id: "lab-request",
        actor_id: "maker",
        signer_key_ref: &signer_key,
        policy_revision: "v1",
        operation_ref: "read-only-lab-op",
        serial_der: serial.as_der_content(),
        tbs_der: &tbs_der,
    };
    let verifier = LabX509Verifier::new(
        ca.root_certificate().clone(),
        binding,
        "api.lab.invalid".into(),
    );
    let hash: [u8; 32] = Sha256::digest(&tbs_der).into();
    let provider = LabReadOnlyProvider(ProviderResponse::SignedCertificate {
        operation_ref: "read-only-lab-op".into(),
        signer_key_ref: signer_key.clone(),
        certificate_der: certificate_der.clone(),
        evidence_sha256: [0x19; 32],
    });
    let result = inspect_provider(&provider, &verifier, &plan, &hash).unwrap();
    assert_eq!(
        result,
        ReconciliationFinding::VerifiedCertificate {
            certificate_sha256: Sha256::digest(&certificate_der).into(),
            provider_evidence_sha256: [0x19; 32],
        }
    );

    let fake = LabReadOnlyProvider(ProviderResponse::SignedCertificate {
        operation_ref: "read-only-lab-op".into(),
        signer_key_ref: signer_key.clone(),
        certificate_der: vec![1, 2, 3],
        evidence_sha256: [0x19; 32],
    });
    assert_eq!(
        inspect_provider(&fake, &verifier, &plan, &hash),
        Err(ReconciliationError::InvalidCertificate)
    );
    assert_eq!(
        inspect_provider(&provider, &verifier, &plan, &[0x01; 32]),
        Err(ReconciliationError::CorrelationMismatch)
    );
}

#[test]
fn real_x509_requires_pinned_signed_collector_evidence_before_positive_finding() {
    use sha2::{Digest, Sha256};
    use trust_pki_core::{
        provider_evidence::{
            inspect_attested_provider, AttestedFinding, CollectorAttestation, EvidenceClaim,
            EvidenceError, EvidenceKind, PinnedCollectorKey,
        },
        reconciliation::{ProviderResponse, ReadOnlySigningProvider, ReconciliationError},
    };
    use trust_pki_crypto::{
        lab::EphemeralP256Signer, SignatureAlgorithm as CryptoAlg, SigningProvider,
    };
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    struct ReadOnlyFixture(ProviderResponse);
    impl ReadOnlySigningProvider for ReadOnlyFixture {
        fn lookup(
            &self,
            _op: &str,
            _key_ref: &str,
        ) -> Result<ProviderResponse, ReconciliationError> {
            Ok(self.0.clone())
        }
    }

    let (csr, authorization, binding) = context();
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let serial = SerialNumber::from_positive_der_content(&[0x55]).unwrap();
    let tbs = ca
        .prepare_leaf_tbs(&csr, &authorization, &serial, &binding)
        .unwrap();
    let tbs_der = tbs.to_der().unwrap();
    let ca_key_ref = ca.lab_signer_key_ref().to_owned();
    let signature = ca
        .sign_once(&ca_key_ref, "independent-audit-op", &tbs_der)
        .unwrap();
    let certificate_der = LabCertificateAssembler
        .assemble(&tbs_der, &signature)
        .unwrap();
    let verifier = LabX509Verifier::new(
        ca.root_certificate().clone(),
        binding,
        "api.lab.invalid".into(),
    );
    let plan = IssuancePlan {
        ca_id: "lab-ca",
        request_id: "audit-lab-request",
        actor_id: "operator",
        signer_key_ref: &ca_key_ref,
        policy_revision: "v1",
        operation_ref: "independent-audit-op",
        serial_der: serial.as_der_content(),
        tbs_der: &tbs_der,
    };
    let collector = EphemeralP256Signer::generate("independent-audit-collector").unwrap();
    let spki = collector.public_key_spki_der(collector.key_ref()).unwrap();
    let audit_public_key = SubjectPublicKeyInfoOwned::from_der(&spki)
        .unwrap()
        .subject_public_key
        .as_bytes()
        .unwrap()
        .to_vec();
    let trusted_key = PinnedCollectorKey {
        key_id: "audit-collector-1",
        public_key_sec1: &audit_public_key,
    };
    let journal_hash: [u8; 32] = Sha256::digest(&tbs_der).into();
    let claim = EvidenceClaim {
        issuer_id: "lab-ca".into(),
        request_id: "audit-lab-request".into(),
        policy_revision: "v1".into(),
        operation_ref: "independent-audit-op".into(),
        signer_key_ref: ca_key_ref.clone(),
        collector_key_id: "audit-collector-1".into(),
        audit_event_id: "independent-event-1".into(),
        observed_at_unix_seconds: 1_781_200_000,
        tbs_sha256: journal_hash,
        raw_provider_log_sha256: [0x71; 32],
        certificate_sha256: Some(Sha256::digest(&certificate_der).into()),
        kind: EvidenceKind::RetrievedSignedCertificate,
    };
    let signature_der = collector
        .sign(
            collector.key_ref(),
            CryptoAlg::EcdsaP256Sha256,
            &claim.canonical_bytes().unwrap(),
        )
        .unwrap();
    let mut attestation = CollectorAttestation {
        claim,
        signature_der,
    };
    let provider = ReadOnlyFixture(ProviderResponse::SignedCertificate {
        operation_ref: "independent-audit-op".into(),
        signer_key_ref: ca_key_ref.clone(),
        certificate_der: certificate_der.clone(),
        evidence_sha256: [0x71; 32],
    });
    let finding = inspect_attested_provider(
        &provider,
        &verifier,
        &plan,
        &journal_hash,
        &attestation,
        &trusted_key,
    )
    .unwrap();
    assert!(matches!(
        finding,
        AttestedFinding::VerifiedRecoveredCandidate { .. }
    ));

    // An attacker cannot silently change the certified result hash in a
    // previously signed collector statement.
    attestation.claim.certificate_sha256 = Some([0x99; 32]);
    assert_eq!(
        inspect_attested_provider(
            &provider,
            &verifier,
            &plan,
            &journal_hash,
            &attestation,
            &trusted_key
        ),
        Err(EvidenceError::InvalidSignature)
    );
}

#[test]
fn verified_collector_evidence_persists_once_and_leaves_issuance_quarantined() {
    use sha2::{Digest, Sha256};
    use trust_pki_core::{
        provider_evidence::{
            verify_collector_evidence, CollectorAttestation, EvidenceClaim, EvidenceKind,
            PinnedCollectorKey,
        },
        reconciliation::{ProviderResponse, ReadOnlySigningProvider, ReconciliationError},
    };
    use trust_pki_crypto::{
        lab::EphemeralP256Signer, SignatureAlgorithm as CryptoAlg, SigningProvider,
    };
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    struct ReadOnlyCertificate(ProviderResponse);
    impl ReadOnlySigningProvider for ReadOnlyCertificate {
        fn lookup(&self, _: &str, _: &str) -> Result<ProviderResponse, ReconciliationError> {
            Ok(self.0.clone())
        }
    }

    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let mut db = PgIssuanceStore::connect_lab(&url).unwrap();
    let (csr, authorization, binding) = context();
    let request = db
        .create_request(
            ca_id,
            "v11-audit-evidence-receipt",
            csr.fingerprint_sha256(),
            "lab-actor",
            "v1",
        )
        .unwrap();
    db.transition(
        ca_id,
        &request.request_id,
        "RECEIVED",
        "CSR_VALIDATED",
        "lab-actor",
    )
    .unwrap();
    db.transition(
        ca_id,
        &request.request_id,
        "CSR_VALIDATED",
        "AUTHORIZED",
        "lab-actor",
    )
    .unwrap();
    let serial_data = db
        .reserve_serial(ca_id, &request.request_id, "lab-actor")
        .unwrap();
    let serial = SerialNumber::from_positive_der_content(&serial_data).unwrap();
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let tbs = ca
        .prepare_leaf_tbs(&csr, &authorization, &serial, &binding)
        .unwrap();
    let tbs_der = tbs.to_der().unwrap();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let hash: [u8; 32] = Sha256::digest(&tbs_der).into();

    db.record_signing_intent(&trust_pki_core::postgres_store::SigningIntentInput {
        ca_id,
        request_id: &request.request_id,
        actor_id: "lab-actor",
        signer_key_ref: &key_ref,
        tbs_sha256: &hash,
        policy_revision: "v1",
        operation_ref: "lab-v11-audit-op",
    })
    .unwrap();
    db.mark_uncertain(ca_id, &request.request_id, "lab-actor")
        .unwrap();

    let signature = ca
        .sign_once(&key_ref, "lab-v11-audit-op", &tbs_der)
        .unwrap();
    let certificate_der = LabCertificateAssembler
        .assemble(&tbs_der, &signature)
        .unwrap();
    let provider = ReadOnlyCertificate(ProviderResponse::SignedCertificate {
        operation_ref: "lab-v11-audit-op".into(),
        signer_key_ref: key_ref.clone(),
        certificate_der: certificate_der.clone(),
        evidence_sha256: [0x93; 32],
    });
    let verifier = LabX509Verifier::new(
        ca.root_certificate().clone(),
        binding,
        "api.lab.invalid".into(),
    );
    let plan = IssuancePlan {
        ca_id,
        request_id: &request.request_id,
        actor_id: "lab-actor",
        signer_key_ref: &key_ref,
        policy_revision: "v1",
        operation_ref: "lab-v11-audit-op",
        serial_der: &serial_data,
        tbs_der: &tbs_der,
    };

    let collector = EphemeralP256Signer::generate("lab-collector-v11").unwrap();
    let spki = collector.public_key_spki_der(collector.key_ref()).unwrap();
    let collector_sec1 = SubjectPublicKeyInfoOwned::from_der(&spki)
        .unwrap()
        .subject_public_key
        .as_bytes()
        .unwrap()
        .to_vec();
    let pinned = PinnedCollectorKey {
        key_id: "lab-collector-v11",
        public_key_sec1: &collector_sec1,
    };
    let claim = EvidenceClaim {
        issuer_id: ca_id.into(),
        request_id: request.request_id.clone(),
        policy_revision: "v1".into(),
        operation_ref: "lab-v11-audit-op".into(),
        signer_key_ref: key_ref.clone(),
        collector_key_id: "lab-collector-v11".into(),
        audit_event_id: "lab-event-v11-unique".into(),
        observed_at_unix_seconds: 1_781_200_000,
        tbs_sha256: hash,
        raw_provider_log_sha256: [0x93; 32],
        certificate_sha256: Some(Sha256::digest(&certificate_der).into()),
        kind: EvidenceKind::RetrievedSignedCertificate,
    };
    let collector_signature = collector
        .sign(
            collector.key_ref(),
            CryptoAlg::EcdsaP256Sha256,
            &claim.canonical_bytes().unwrap(),
        )
        .unwrap();
    let attestation = CollectorAttestation {
        claim,
        signature_der: collector_signature,
    };
    let verified =
        verify_collector_evidence(&provider, &verifier, &plan, &hash, &attestation, &pinned)
            .unwrap();

    let receipt_id = db.persist_verified_collector_evidence(&verified).unwrap();
    assert!(!receipt_id.is_empty());
    // Reusing the exact same signed observation MUST be rejected, not
    // silently converted to a second audit event or a fresh signature.
    assert!(db.persist_verified_collector_evidence(&verified).is_err());

    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let row = reader
        .query_one(
            "SELECT c.state, ce.evidence_kind, ce.canonical_claim,
                ce.collector_signature_der, ce.claim_sha256
         FROM certificate_request c
         JOIN signing_collector_evidence ce
           ON ce.ca_id=c.ca_id AND ce.request_id=c.request_id
         WHERE c.request_id=$1::text::uuid",
            &[&request.request_id],
        )
        .unwrap();
    let state: String = row.get(0);
    let kind: String = row.get(1);
    let canonical: Vec<u8> = row.get(2);
    let saved_signature: Vec<u8> = row.get(3);
    let digest: Vec<u8> = row.get(4);
    assert_eq!(state, "RECONCILIATION_REQUIRED");
    assert_eq!(kind, "RETRIEVED_CERTIFICATE");
    assert_eq!(canonical, verified.canonical_claim());
    assert_eq!(saved_signature, verified.signature_der());
    assert_eq!(digest, Sha256::digest(verified.canonical_claim()).to_vec());

    let row = reader
        .query_one(
            "SELECT (SELECT count(*) FROM certificate WHERE request_id=$1::text::uuid),
                (SELECT count(*) FROM audit_event
                 WHERE request_id=$1::text::uuid
                   AND event_type='signing.collector.evidence')",
            &[&request.request_id],
        )
        .unwrap();
    assert_eq!(row.get::<usize, i64>(0), 0);
    assert_eq!(row.get::<usize, i64>(1), 1);
}

#[test]
fn pinned_ca_and_draft_cps_are_traced_to_real_issued_x509_without_approval() {
    use sha2::{Digest, Sha256};
    use trust_pki_core::{
        ca_observation::observe_pinned_lab_ca,
        cp_cps::{generate, Input as CpCpsInput},
        policy_trace::{verify_certificate_draft_trace, TraceError},
    };

    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let (csr, authorization, binding) = context();
    let policy = StaticPolicy {
        profile_id: "lab-server".into(),
        policy_version: "v1".into(),
        allowed_actors: vec!["lab-actor".into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
        max_validity_days: 3,
        max_dns_sans: 2,
    };
    let source = CpCpsInput {
        policy: &policy,
        policy_oid: "1.3.6.1.4.1.55555.1.1",
        edition: "lab-doc-v1",
        issuer: "Sovereign Trust Lab Root",
        authority: "Unapproved Lab Policy Board",
        repository: "lab.invalid/draft",
    };
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let ca_der = root.to_der().unwrap();
    // TEST ONLY: the pin here comes from the test fixture. Production must
    // obtain its trusted pin independently, not from the certificate itself.
    let pin: [u8; 32] = Sha256::digest(&ca_der).into();
    let observed = observe_pinned_lab_ca(&ca_der, &pin).unwrap();
    let mut db = PgIssuanceStore::connect_lab(&url).unwrap();
    let observation_id = db
        .register_ca_public_observation(ca_id, "lab-operator", &observed)
        .unwrap();
    let observation_replay = db
        .register_ca_public_observation(ca_id, "lab-operator", &observed)
        .unwrap();
    assert_eq!(observation_id, observation_replay);
    let draft_id = db
        .register_cp_cps_draft(ca_id, &observation_id, "lab-operator", &source)
        .unwrap();
    let draft = generate(&source).unwrap();
    assert!(!draft.publication_authorized);

    let request = db
        .create_request(
            ca_id,
            "v13-observed-ca-draft-trace",
            csr.fingerprint_sha256(),
            "lab-actor",
            "v1",
        )
        .unwrap();
    db.transition(
        ca_id,
        &request.request_id,
        "RECEIVED",
        "CSR_VALIDATED",
        "lab-actor",
    )
    .unwrap();
    db.transition(
        ca_id,
        &request.request_id,
        "CSR_VALIDATED",
        "AUTHORIZED",
        "lab-actor",
    )
    .unwrap();
    let serial_data = db
        .reserve_serial(ca_id, &request.request_id, "lab-actor")
        .unwrap();
    let serial = SerialNumber::from_positive_der_content(&serial_data).unwrap();
    let tbs = ca
        .prepare_leaf_tbs(&csr, &authorization, &serial, &binding)
        .unwrap();
    let tbs_der = tbs.to_der().unwrap();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let plan = IssuancePlan {
        ca_id,
        request_id: &request.request_id,
        actor_id: "lab-actor",
        signer_key_ref: &key_ref,
        policy_revision: "v1",
        operation_ref: "v13-observed-ca-issuance",
        serial_der: &serial_data,
        tbs_der: &tbs_der,
    };
    let verifier = LabX509Verifier::new(root.clone(), binding.clone(), "api.lab.invalid".into());
    let signed_der =
        issue_once(&mut db, &mut ca, &LabCertificateAssembler, &verifier, &plan).unwrap();

    let validated = verify_certificate_draft_trace(
        &observed,
        &plan,
        &signed_der,
        &source,
        &binding,
        "api.lab.invalid",
    )
    .unwrap();
    assert_eq!(
        validated.certificate_sha256(),
        &<[u8; 32]>::from(Sha256::digest(&signed_der))
    );
    assert_eq!(validated.issuer_ca_sha256(), observed.certificate_sha256());

    let wrong_source = CpCpsInput {
        policy: &policy,
        policy_oid: "1.3.6.1.4.1.55555.1.9",
        edition: "lab-doc-v1",
        issuer: "Sovereign Trust Lab Root",
        authority: "Unapproved Lab Policy Board",
        repository: "lab.invalid/draft",
    };
    assert_eq!(
        verify_certificate_draft_trace(
            &observed,
            &plan,
            &signed_der,
            &wrong_source,
            &binding,
            "api.lab.invalid"
        ),
        Err(TraceError::PolicyMismatch)
    );
    let another_ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let another_root_der = another_ca.root_certificate().to_der().unwrap();
    let other_pin: [u8; 32] = Sha256::digest(&another_root_der).into();
    let other_observed = observe_pinned_lab_ca(&another_root_der, &other_pin).unwrap();
    assert_eq!(
        verify_certificate_draft_trace(
            &other_observed,
            &plan,
            &signed_der,
            &source,
            &binding,
            "api.lab.invalid"
        ),
        Err(TraceError::CertificateInvalid)
    );

    assert_eq!(
        db.record_issued_certificate_draft_trace("lab-operator", &draft_id, &validated)
            .unwrap(),
        "DRAFT_REFERENCE_ONLY"
    );
    // Existing cert is NOT re-signed, and draft is NOT approved or published.
    assert!(db
        .record_issued_certificate_draft_trace("lab-operator", &draft_id, &validated)
        .is_err());

    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let row = reader
        .query_one(
            "SELECT t.trace_state,p.state,p.policy_oid,p.cp_sha256,p.cps_sha256,
                o.ca_certificate_sha256,c.certificate_der
         FROM issued_certificate_draft_trace t
         JOIN certificate c ON c.ca_id=t.ca_id AND c.request_id=t.request_id
         JOIN cp_cps_draft_snapshot p ON p.ca_id=t.ca_id AND p.draft_id=t.draft_id
         JOIN ca_public_observation o
             ON o.ca_id=p.ca_id AND o.observation_id=p.observation_id
         WHERE t.request_id=$1::text::uuid",
            &[&request.request_id],
        )
        .unwrap();
    assert_eq!(row.get::<usize, String>(0), "DRAFT_REFERENCE_ONLY");
    assert_eq!(row.get::<usize, String>(1), "DRAFT_UNAPPROVED");
    assert_eq!(row.get::<usize, String>(2), source.policy_oid);
    assert_eq!(row.get::<usize, Vec<u8>>(3), draft.cp.sha256.to_vec());
    assert_eq!(row.get::<usize, Vec<u8>>(4), draft.cps.sha256.to_vec());
    assert_eq!(row.get::<usize, Vec<u8>>(5), pin.to_vec());
    assert_eq!(row.get::<usize, Vec<u8>>(6), signed_der);
}

/// `url` with `role` set for the session (the test login is a superuser).
fn url_as(url: &str, role: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}options=-crole%3D{role}")
}

#[test]
fn issuance_service_role_issues_through_functions_only() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let service_url = url_as(&url, "trust_issuance_service");
    let mut db = PgIssuanceStore::connect_lab(&service_url)
        .expect("trust_issuance_service (migration 0035) must exist");
    let ca_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let (csr, authorization, binding) = context();
    let request = db
        .create_request(
            ca_id,
            "service-role-issuance-1",
            csr.fingerprint_sha256(),
            "lab-actor",
            "v1",
        )
        .unwrap();
    db.transition(
        ca_id,
        &request.request_id,
        "RECEIVED",
        "CSR_VALIDATED",
        "lab-actor",
    )
    .unwrap();
    db.transition(
        ca_id,
        &request.request_id,
        "CSR_VALIDATED",
        "AUTHORIZED",
        "lab-actor",
    )
    .unwrap();
    let serial_data = db
        .reserve_serial(ca_id, &request.request_id, "lab-actor")
        .unwrap();
    let serial = SerialNumber::from_positive_der_content(&serial_data).unwrap();
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let tbs_der = ca
        .prepare_leaf_tbs(&csr, &authorization, &serial, &binding)
        .unwrap()
        .to_der()
        .unwrap();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let plan = IssuancePlan {
        ca_id,
        request_id: &request.request_id,
        actor_id: "lab-actor",
        signer_key_ref: &key_ref,
        policy_revision: "v1",
        operation_ref: "service-role-op-1",
        serial_der: &serial_data,
        tbs_der: &tbs_der,
    };
    let verifier = LabX509Verifier::new(
        ca.root_certificate().clone(),
        binding,
        "api.lab.invalid".into(),
    );
    let issued = issue_once(&mut db, &mut ca, &LabCertificateAssembler, &verifier, &plan).unwrap();
    assert_eq!(
        issue_once(&mut db, &mut ca, &LabCertificateAssembler, &verifier, &plan),
        Err(IssueError::ReplayedOrAmbiguousIntent)
    );

    // The same login cannot write or read the issuance tables directly: a
    // stolen service credential cannot persist a certificate that skipped
    // the signing intent, nor rewrite an intent.
    let mut direct = postgres::Client::connect(&service_url, postgres::NoTls).unwrap();
    let denied = |client: &mut postgres::Client, sql: &str| {
        let error = client.batch_execute(sql).expect_err(sql);
        assert_eq!(
            error.code().map(|c| c.code()),
            Some("42501"),
            "{sql}: {error}"
        );
    };
    denied(
        &mut direct,
        &format!(
            "INSERT INTO certificate(ca_id, request_id, serial_der_content, certificate_der)
             VALUES ('{ca_id}', '{}', '\\x01', '\\x30')",
            request.request_id
        ),
    );
    denied(
        &mut direct,
        "UPDATE signing_intent SET outcome = 'CERTIFICATE_STORED'",
    );
    denied(
        &mut direct,
        "UPDATE certificate_request SET state = 'AUTHORIZED'",
    );
    denied(
        &mut direct,
        "INSERT INTO serial_reservation SELECT * FROM serial_reservation LIMIT 0",
    );
    denied(
        &mut direct,
        "INSERT INTO audit_event SELECT * FROM audit_event LIMIT 0",
    );
    denied(&mut direct, "UPDATE ca SET policy_gate_epoch = 0");
    denied(&mut direct, "SELECT certificate_der FROM certificate");
    // Nor reach the policy administration functions (lab policy gate setup).
    denied(
        &mut direct,
        &format!("SELECT activate_ca_policy_gate_lab('{ca_id}', 'lab-actor')"),
    );

    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let stored: Vec<u8> = reader
        .query_one(
            "SELECT certificate_der FROM certificate WHERE request_id = $1::text::uuid",
            &[&request.request_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(stored, issued);
}
