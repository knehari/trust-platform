//! Status changes and CRL journal against PostgreSQL, with real P-256 signing.
//! Ephemeral lab CA only. Not a production PKI.
#![cfg(all(feature = "postgres-store", feature = "lab-software"))]

use std::env;
use trust_pki_core::{
    crl::{build_tbs_cert_list, CrlError, LabCrlAssembler, LabCrlVerifier},
    crl_orchestrator::{crl_once, CrlPlan},
    csr::{verify_pkcs10_p256, VerifiedCsr},
    lab_ca::EphemeralLabCa,
    lab_x509_verifier::{LabCertificateAssembler, LabX509Verifier},
    orchestrator::{issue_once, ExternalSigner, IssuancePlan, IssueError},
    postgres_store::PgIssuanceStore,
    revocation::{CertificateStatus, OfficerIdentity, RevocationReason, StatusAction},
    revocation_policy::StatusChangeError,
    revocation_store::{PgRevocationStore, RevocationStoreError},
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

const ISSUER: &str = "https://idp.lab.invalid";

fn context() -> (
    VerifiedCsr,
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

/// Counts how often the (single, shared) lab CA is asked to sign.
struct CountingSigner<'a> {
    ca: &'a mut EphemeralLabCa,
    calls: u32,
}

impl ExternalSigner for CountingSigner<'_> {
    fn sign_once(
        &mut self,
        key_ref: &str,
        operation_ref: &str,
        tbs_der: &[u8],
    ) -> Result<Vec<u8>, IssueError> {
        self.calls += 1;
        self.ca.sign_once(key_ref, operation_ref, tbs_der)
    }
}

fn issue_leaf(
    db: &mut PgIssuanceStore,
    ca: &mut EphemeralLabCa,
    ca_id: &str,
    n: u32,
) -> SerialNumber {
    let (csr, authorization, binding) = context();
    let request = db
        .create_request(
            ca_id,
            &format!("crl-{n}"),
            csr.fingerprint_sha256(),
            "lab-actor",
            "v1",
        )
        .unwrap();
    for (from, to) in [
        ("RECEIVED", "CSR_VALIDATED"),
        ("CSR_VALIDATED", "AUTHORIZED"),
    ] {
        db.transition(ca_id, &request.request_id, from, to, "lab-actor")
            .unwrap();
    }
    let serial_data = db
        .reserve_serial(ca_id, &request.request_id, "lab-actor")
        .unwrap();
    let serial = SerialNumber::from_positive_der_content(&serial_data).unwrap();
    let tbs = ca
        .prepare_leaf_tbs(&csr, &authorization, &serial, &binding)
        .unwrap();
    let tbs_der = tbs.to_der().unwrap();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let operation_ref = format!("crl-issue-op-{n}");
    let plan = IssuancePlan {
        ca_id,
        request_id: &request.request_id,
        actor_id: "lab-actor",
        signer_key_ref: &key_ref,
        policy_revision: "v1",
        operation_ref: &operation_ref,
        serial_der: &serial_data,
        tbs_der: &tbs_der,
    };
    let verifier = LabX509Verifier::new(
        ca.root_certificate().clone(),
        binding,
        "api.lab.invalid".into(),
    );
    let der = issue_once(db, ca, &LabCertificateAssembler, &verifier, &plan).unwrap();
    assert_eq!(
        Certificate::from_der(&der)
            .unwrap()
            .tbs_certificate
            .serial_number
            .as_bytes(),
        serial_data
    );
    serial
}

fn change(
    store: &mut PgRevocationStore,
    ca_id: &str,
    serial: &SerialNumber,
    action: StatusAction,
    reason: Option<RevocationReason>,
) {
    let maker = OfficerIdentity {
        issuer: ISSUER,
        subject: "maker",
    };
    let checker = OfficerIdentity {
        issuer: ISSUER,
        subject: "checker",
    };
    let id = store
        .propose(ca_id, serial, action, reason, None, &maker)
        .unwrap();
    store.approve(&id, &checker, action, reason).unwrap();
}

fn sqlstate(error: &RevocationStoreError) -> Option<String> {
    match error {
        RevocationStoreError::Database(e) => e.code().map(|c| c.code().to_owned()),
        _ => None,
    }
}

#[test]
fn status_changes_feed_a_signed_stored_crl_with_replay_and_failure_handling() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };

    // Fresh CA per run; the CI test user owns the schema.
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let ca_id: String = owner
        .query_one(
            "INSERT INTO ca(ca_id,display_name,policy_version)
             VALUES (gen_random_uuid(),'Revocation CRL Lab CA','v1') RETURNING ca_id::text",
            &[],
        )
        .unwrap()
        .get(0);
    owner
        .execute(
            "INSERT INTO ca_revocation_policy(ca_id,suspension_allowed)
             VALUES ($1::text::uuid,true)",
            &[&ca_id],
        )
        .unwrap();
    for subject in ["maker", "checker"] {
        owner
            .execute(
                "INSERT INTO revocation_officer_grant(issuer,subject,ca_id)
                 VALUES ($1,$2,$3::text::uuid)",
                &[&ISSUER, &subject, &ca_id],
            )
            .unwrap();
    }

    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
    let s1 = issue_leaf(&mut issuance, &mut ca, &ca_id, 1);
    let s2 = issue_leaf(&mut issuance, &mut ca, &ca_id, 2);
    let s3 = issue_leaf(&mut issuance, &mut ca, &ca_id, 3);

    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    change(
        &mut store,
        &ca_id,
        &s1,
        StatusAction::Revoke,
        Some(RevocationReason::KeyCompromise),
    );
    change(
        &mut store,
        &ca_id,
        &s2,
        StatusAction::Suspend,
        Some(RevocationReason::CertificateHold),
    );
    assert_eq!(
        store.status(&ca_id, &s1).unwrap(),
        CertificateStatus::Revoked
    );
    assert_eq!(
        store.status(&ca_id, &s2).unwrap(),
        CertificateStatus::Suspended
    );
    assert_eq!(store.status(&ca_id, &s3).unwrap(), CertificateStatus::Valid);

    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let verifier = LabCrlVerifier::new(root.clone());

    // CRL 1: #1 (keyCompromise) and #2 (certificateHold).
    let r1 = store
        .reserve_crl(&ca_id, "crl-operator", "crl-op-1")
        .unwrap();
    assert_eq!(r1.crl_number, 1);
    assert_eq!(r1.entries.len(), 2);
    let reason_of = |r: &trust_pki_core::crl::CrlReservation, s: &SerialNumber| {
        r.entries
            .iter()
            .find(|e| &e.serial == s)
            .map(|e| e.reason.code())
    };
    assert_eq!(reason_of(&r1, &s1), Some(1));
    assert_eq!(reason_of(&r1, &s2), Some(6));
    let tbs1 = build_tbs_cert_list(&root, &r1).unwrap();
    let plan1 = CrlPlan {
        reservation: &r1,
        signer_key_ref: &key_ref,
        operation_ref: "crl-op-1",
        tbs_der: &tbs1,
    };
    let mut signer = CountingSigner {
        ca: &mut ca,
        calls: 0,
    };
    let crl1 = crl_once(&mut store, &mut signer, &LabCrlAssembler, &verifier, &plan1).unwrap();
    assert_eq!(signer.calls, 1);
    let row = reader
        .query_one(
            "SELECT crl_der, status FROM crl_publication
             WHERE ca_id=$1::text::uuid AND crl_number=1",
            &[&ca_id],
        )
        .unwrap();
    assert_eq!(row.get::<usize, Vec<u8>>(0), crl1);
    assert_eq!(row.get::<usize, String>(1), "STORED");

    // CRL 2: after releasing #2 only #1 remains.
    change(&mut store, &ca_id, &s2, StatusAction::Release, None);
    let r2 = store
        .reserve_crl(&ca_id, "crl-operator", "crl-op-2")
        .unwrap();
    assert_eq!(r2.crl_number, 2);
    assert_eq!(r2.entries.len(), 1);
    assert_eq!(reason_of(&r2, &s1), Some(1));
    let tbs2 = build_tbs_cert_list(&root, &r2).unwrap();
    let plan2 = CrlPlan {
        reservation: &r2,
        signer_key_ref: &key_ref,
        operation_ref: "crl-op-2",
        tbs_der: &tbs2,
    };
    crl_once(&mut store, &mut signer, &LabCrlAssembler, &verifier, &plan2).unwrap();
    assert_eq!(signer.calls, 2);

    // Replay: intent refused, signer untouched.
    assert_eq!(
        crl_once(&mut store, &mut signer, &LabCrlAssembler, &verifier, &plan2),
        Err(CrlError::ReplayedOrAmbiguousIntent)
    );
    assert_eq!(signer.calls, 2);

    // A verifier built from another CA rejects: fail closed and quarantine.
    let other = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let wrong_verifier = LabCrlVerifier::new(other.root_certificate().clone());
    let r3 = store
        .reserve_crl(&ca_id, "crl-operator", "crl-op-3")
        .unwrap();
    assert_eq!(r3.crl_number, 3);
    let tbs3 = build_tbs_cert_list(&root, &r3).unwrap();
    let plan3 = CrlPlan {
        reservation: &r3,
        signer_key_ref: &key_ref,
        operation_ref: "crl-op-3",
        tbs_der: &tbs3,
    };
    assert_eq!(
        crl_once(
            &mut store,
            &mut signer,
            &LabCrlAssembler,
            &wrong_verifier,
            &plan3
        ),
        Err(CrlError::VerificationFailure)
    );
    let status3: String = reader
        .query_one(
            "SELECT status FROM crl_publication WHERE ca_id=$1::text::uuid AND crl_number=3",
            &[&ca_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(status3, "RECONCILIATION_REQUIRED");
    let r4 = store
        .reserve_crl(&ca_id, "crl-operator", "crl-op-4")
        .unwrap();
    assert_eq!(r4.crl_number, 4);

    // Terminal state is refused before any SQL write.
    let count = |c: &mut postgres::Client| -> i64 {
        c.query_one(
            "SELECT count(*) FROM certificate_status_change WHERE ca_id=$1::text::uuid",
            &[&ca_id],
        )
        .unwrap()
        .get(0)
    };
    let before = count(&mut reader);
    let maker = OfficerIdentity {
        issuer: ISSUER,
        subject: "maker",
    };
    let denied = store.propose(
        &ca_id,
        &s1,
        StatusAction::Revoke,
        Some(RevocationReason::Superseded),
        None,
        &maker,
    );
    assert!(matches!(
        denied,
        Err(RevocationStoreError::Denied(
            StatusChangeError::TerminalState
        ))
    ));
    assert_eq!(count(&mut reader), before);

    // Maker cannot approve their own proposal: SQL rule violation 23514.
    let id = store
        .propose(
            &ca_id,
            &s3,
            StatusAction::Revoke,
            Some(RevocationReason::Superseded),
            Some(1_700_000_000),
            &maker,
        )
        .unwrap();
    let err = store
        .approve(
            &id,
            &maker,
            StatusAction::Revoke,
            Some(RevocationReason::Superseded),
        )
        .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("23514"));
    assert_eq!(store.status(&ca_id, &s3).unwrap(), CertificateStatus::Valid);
    store.withdraw(&id, &maker).unwrap();

    // No INTENT_RECORDED row is left behind, so nothing is quarantined.
    assert_eq!(store.quarantine_stale_crl_intents(&ca_id, 3600).unwrap(), 0);
}
