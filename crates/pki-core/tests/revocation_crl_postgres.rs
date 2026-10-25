//! Status changes and CRL journal against PostgreSQL, with real P-256 signing.
//! Ephemeral lab CA only. Not a production PKI.
#![cfg(all(feature = "postgres-store", feature = "lab-software"))]

use std::env;
use trust_pki_core::{
    clock,
    crl::{
        verify_published_crl, verify_published_delta_crl, CrlAssembler, CrlError, CrlReservation,
        LabCrlAssembler, LabCrlVerifier,
    },
    crl_orchestrator::{crl_once, reconcile_crl, CrlJournal, CrlPlan, SignerPublicKey},
    csr::{verify_pkcs10_p256, VerifiedCsr},
    lab_ca::EphemeralLabCa,
    lab_x509_verifier::{LabCertificateAssembler, LabX509Verifier},
    officer_credential::{canonical_officer_key, CredentialChangeKind, CredentialError},
    orchestrator::{issue_once, ExternalSigner, IssuancePlan, IssueError},
    postgres_store::PgIssuanceStore,
    revocation::{CertificateStatus, OfficerIdentity, RevocationReason, StatusAction},
    revocation_policy::StatusChangeError,
    revocation_store::{
        officer_grant_digest, CredentialContent, OfficerGrantAction, PgRevocationStore,
        RevocationStoreError,
    },
    serial::SerialNumber,
    x509_extensions::{crl_distribution_points, crl_distribution_url, ApprovedPolicyBinding},
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

impl SignerPublicKey for CountingSigner<'_> {
    fn signer_spki_der(&self, key_ref: &str) -> Result<Vec<u8>, CrlError> {
        self.ca.signer_spki_der(key_ref)
    }
}

/// Signs with the right key, then corrupts the signature: the CRL fails
/// independent verification after signing (quarantine path).
struct CorruptingSigner<'a>(&'a mut EphemeralLabCa);

impl SignerPublicKey for CorruptingSigner<'_> {
    fn signer_spki_der(&self, key_ref: &str) -> Result<Vec<u8>, CrlError> {
        self.0.signer_spki_der(key_ref)
    }
}

impl ExternalSigner for CorruptingSigner<'_> {
    fn sign_once(
        &mut self,
        key_ref: &str,
        operation_ref: &str,
        tbs_der: &[u8],
    ) -> Result<Vec<u8>, IssueError> {
        let mut signature = self.0.sign_once(key_ref, operation_ref, tbs_der)?;
        let last = signature.len() - 1;
        signature[last] ^= 0x01;
        Ok(signature)
    }
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
    issue_leaf_with(db, ca, ca_id, n, None)
}

/// Like `issue_leaf`; the verifier requires `crl_distribution_point` when
/// the CA was configured with one.
fn issue_leaf_with(
    db: &mut PgIssuanceStore,
    ca: &mut EphemeralLabCa,
    ca_id: &str,
    n: u32,
    crl_distribution_point: Option<&str>,
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
    let verifier = match crl_distribution_point {
        Some(url) => verifier.with_crl_distribution_point(url),
        None => verifier,
    };
    let der = issue_once(db, ca, &LabCertificateAssembler, &verifier, &plan).unwrap();
    let cert = Certificate::from_der(&der).unwrap();
    assert_eq!(cert.tbs_certificate.serial_number.as_bytes(), serial_data);
    // The stored not_after is the certificate's (migration 0031).
    let mut reader =
        postgres::Client::connect(&env::var("TRUST_CI_DATABASE_URL").unwrap(), postgres::NoTls)
            .unwrap();
    let stored: i64 = reader
        .query_one(
            "SELECT extract(epoch FROM not_after)::bigint FROM certificate
             WHERE ca_id = $1::text::uuid AND serial_der_content = $2",
            &[&ca_id, &serial_data],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        stored,
        cert.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64
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

/// Writes root.der, leaf1..3.der and crl1/crl2.der exactly as stored.
fn export_stored_artefacts(
    reader: &mut postgres::Client,
    ca_id: &str,
    root: &Certificate,
    serials: [&SerialNumber; 3],
    dir: &str,
) {
    let dir = std::path::Path::new(dir);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("root.der"), root.to_der().unwrap()).unwrap();
    for (n, serial) in serials.iter().enumerate() {
        let der: Vec<u8> = reader
            .query_one(
                "SELECT certificate_der FROM certificate
                 WHERE ca_id=$1::text::uuid AND serial_der_content=$2",
                &[&ca_id, &serial.as_der_content()],
            )
            .unwrap()
            .get(0);
        std::fs::write(dir.join(format!("leaf{}.der", n + 1)), der).unwrap();
    }
    for number in [1_i64, 2] {
        let der: Vec<u8> = reader
            .query_one(
                "SELECT crl_der FROM crl_publication
                 WHERE ca_id=$1::text::uuid AND crl_number=$2 AND status='STORED'",
                &[&ca_id, &number],
            )
            .unwrap()
            .get(0);
        std::fs::write(dir.join(format!("crl{number}.der")), der).unwrap();
    }
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
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();
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
    assert_eq!(r1.crl_number(), 1);
    assert_eq!(r1.entries().len(), 2);
    let reason_of = |r: &CrlReservation, s: &SerialNumber| {
        r.entries()
            .iter()
            .find(|e| &e.serial == s)
            .map(|e| e.reason.code())
    };
    assert_eq!(reason_of(&r1, &s1), Some(1));
    assert_eq!(reason_of(&r1, &s2), Some(6));
    let plan1 = CrlPlan {
        reservation: &r1,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-op-1",
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
    assert_eq!(r2.crl_number(), 2);
    assert_eq!(r2.entries().len(), 1);
    assert_eq!(reason_of(&r2, &s1), Some(1));
    let plan2 = CrlPlan {
        reservation: &r2,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-op-2",
    };
    crl_once(&mut store, &mut signer, &LabCrlAssembler, &verifier, &plan2).unwrap();
    assert_eq!(signer.calls, 2);

    // Hand the persisted artefacts (read back from PostgreSQL, not the
    // in-memory values) to tests/crl_openssl_lab.sh when CI asks for them.
    if let Ok(dir) = env::var("TRUST_CRL_EXPORT_DIR") {
        export_stored_artefacts(&mut reader, &ca_id, &root, [&s1, &s2, &s3], &dir);
    }

    // Replay: intent refused, signer untouched.
    assert_eq!(
        crl_once(&mut store, &mut signer, &LabCrlAssembler, &verifier, &plan2),
        Err(CrlError::ReplayedOrAmbiguousIntent)
    );
    assert_eq!(signer.calls, 2);

    // A verifier built from another CA than the plan's issuer is a
    // configuration error: refused before the intent, nothing is signed.
    let mut other = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let wrong_verifier = LabCrlVerifier::new(other.root_certificate().clone());
    let r3 = store
        .reserve_crl(&ca_id, "crl-operator", "crl-op-3")
        .unwrap();
    assert_eq!(r3.crl_number(), 3);
    let plan3 = CrlPlan {
        reservation: &r3,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-op-3",
    };
    assert_eq!(
        crl_once(
            &mut store,
            &mut signer,
            &LabCrlAssembler,
            &wrong_verifier,
            &plan3
        ),
        Err(CrlError::IssuerMismatch)
    );
    assert_eq!(signer.calls, 2, "no signature for a mismatched verifier");
    let status_of = |c: &mut postgres::Client, n: i64| -> String {
        c.query_one(
            "SELECT status FROM crl_publication WHERE ca_id=$1::text::uuid AND crl_number=$2",
            &[&ca_id, &n],
        )
        .unwrap()
        .get(0)
    };
    assert_eq!(status_of(&mut reader, 3), "RESERVED");

    // A signer holding another key than the issuer's is refused before the
    // intent: the CA would otherwise sign with an unexpected key.
    let other_key_ref = other.lab_signer_key_ref().to_owned();
    let mut wrong_signer = CountingSigner {
        ca: &mut other,
        calls: 0,
    };
    let plan3_other_key = CrlPlan {
        signer_key_ref: &other_key_ref,
        ..plan3
    };
    assert_eq!(
        crl_once(
            &mut store,
            &mut wrong_signer,
            &LabCrlAssembler,
            &verifier,
            &plan3_other_key
        ),
        Err(CrlError::IssuerMismatch)
    );
    assert_eq!(
        wrong_signer.calls, 0,
        "no signature by a key that is not the issuer's"
    );
    assert_eq!(status_of(&mut reader, 3), "RESERVED");

    // A bad signature by the right key fails independent verification after
    // signing: fail closed and quarantine.
    assert_eq!(
        crl_once(
            &mut store,
            &mut CorruptingSigner(signer.ca),
            &LabCrlAssembler,
            &verifier,
            &plan3
        ),
        Err(CrlError::VerificationFailure)
    );
    assert_eq!(status_of(&mut reader, 3), "RECONCILIATION_REQUIRED");
    let r4 = store
        .reserve_crl(&ca_id, "crl-operator", "crl-op-4")
        .unwrap();
    assert_eq!(r4.crl_number(), 4);

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

/// Fresh CA with suspension enabled and maker/checker grants.
fn fresh_ca(url: &str) -> String {
    let mut owner = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let ca_id: String = owner
        .query_one(
            "INSERT INTO ca(ca_id,display_name,policy_version)
             VALUES (gen_random_uuid(),'Revocation CRL Regression CA','v1') RETURNING ca_id::text",
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
    ca_id
}

/// I1 regression: a reservation whose entries were altered between reserve
/// and sign must be refused by the journal before the signer is called, and
/// the revocation must stay uncovered (crl_due, overdue tracking).
#[test]
fn tampered_reservation_is_refused_before_signing() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
    let s1 = issue_leaf(&mut issuance, &mut ca, &ca_id, 101);
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();
    change(
        &mut store,
        &ca_id,
        &s1,
        StatusAction::Revoke,
        Some(RevocationReason::KeyCompromise),
    );

    let r = store
        .reserve_crl(&ca_id, "crl-operator", "crl-tamper-1")
        .unwrap();
    assert_eq!(r.entries().len(), 1);
    // The reservation is sealed (no `r.entries.clear()` any more); a caller can
    // still build a look-alike with the same number and times but no entries.
    // The database must refuse its intent before anything is signed.
    let forged = CrlReservation::new(
        r.ca_id(),
        r.crl_number(),
        r.this_update_unix(),
        r.next_update_unix(),
        Vec::new(),
        r.expired_certs_on_crl_since_unix(),
    )
    .unwrap();
    let plan = CrlPlan {
        reservation: &forged,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-tamper-1",
    };
    let verifier = LabCrlVerifier::new(root.clone());
    let mut signer = CountingSigner {
        ca: &mut ca,
        calls: 0,
    };
    let result = crl_once(&mut store, &mut signer, &LabCrlAssembler, &verifier, &plan);
    assert_eq!(result, Err(CrlError::ReplayedOrAmbiguousIntent));
    assert_eq!(signer.calls, 0, "signer must not be called");

    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let status: String = reader
        .query_one(
            "SELECT status FROM crl_publication WHERE ca_id=$1::text::uuid AND crl_number=1",
            &[&ca_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(status, "RESERVED");
    let due: bool = reader
        .query_one("SELECT crl_due($1::text::uuid)", &[&ca_id])
        .unwrap()
        .get(0);
    assert!(due, "the revocation is not covered by any stored CRL");

    // Same number and entries, other times: refused as well.
    let shifted = CrlReservation::new(
        r.ca_id(),
        r.crl_number(),
        r.this_update_unix() + 1,
        r.next_update_unix(),
        r.entries().to_vec(),
        r.expired_certs_on_crl_since_unix(),
    )
    .unwrap();
    let plan = CrlPlan {
        reservation: &shifted,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-tamper-1",
    };
    assert_eq!(
        crl_once(&mut store, &mut signer, &LabCrlAssembler, &verifier, &plan),
        Err(CrlError::ReplayedOrAmbiguousIntent)
    );
    assert_eq!(signer.calls, 0, "signer must not be called");

    // The genuine reservation is still signable and then covers the change.
    let plan = CrlPlan {
        reservation: &r,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-tamper-1",
    };
    crl_once(&mut store, &mut signer, &LabCrlAssembler, &verifier, &plan).unwrap();
    assert_eq!(signer.calls, 1);
    let status: String = reader
        .query_one(
            "SELECT status FROM crl_publication WHERE ca_id=$1::text::uuid AND crl_number=1",
            &[&ca_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(status, "STORED");
}

/// I2 regression: invalidity dates outside 1970-01-01 .. 9999-12-31 or in the
/// future must be refused at proposal (they would make every later CRL
/// unbuildable once approved).
#[test]
fn out_of_range_invalidity_dates_are_refused() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
    let s1 = issue_leaf(&mut issuance, &mut ca, &ca_id, 201);
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let count = |c: &mut postgres::Client| -> i64 {
        c.query_one(
            "SELECT count(*) FROM certificate_status_change WHERE ca_id=$1::text::uuid",
            &[&ca_id],
        )
        .unwrap()
        .get(0)
    };
    let maker = OfficerIdentity {
        issuer: ISSUER,
        subject: "maker",
    };
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    for bad in [
        -86_400i64,      // 1969-12-31
        -1,              // 1969-12-31T23:59:59Z, collides with "no date" (-1)
        -2_208_988_800,  // 1900-01-01
        253_402_300_800, // 10000-01-01
        568_971_820_800, // 20000-01-01
        now + 3_600,     // future
    ] {
        let result = store.propose(
            &ca_id,
            &s1,
            StatusAction::Revoke,
            Some(RevocationReason::KeyCompromise),
            Some(bad),
            &maker,
        );
        assert!(
            matches!(
                result,
                Err(RevocationStoreError::Denied(
                    StatusChangeError::InvalidityDateOutOfRange
                ))
            ),
            "invalidity {bad}: {result:?}"
        );
        assert_eq!(count(&mut reader), 0, "invalidity {bad} left a row");
    }
    // In range and in the past: accepted.
    store
        .propose(
            &ca_id,
            &s1,
            StatusAction::Revoke,
            Some(RevocationReason::KeyCompromise),
            Some(now - 3_600),
            &maker,
        )
        .unwrap();
    assert_eq!(count(&mut reader), 1);

    // The database refuses the same dates on its own (22023), for a caller
    // that skips the Rust check.
    let mut direct = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    for bad in ["1900-01-01 00:00:00+00", "20000-01-01 00:00:00+00"] {
        let err = direct
            .query_one(
                "SELECT propose_certificate_status_change($1::text::uuid, $2, 'REVOKE',
                     1::smallint, $3::text::timestamptz, $4, 'checker')",
                &[&ca_id, &s1.as_der_content(), &bad, &ISSUER],
            )
            .unwrap_err();
        assert_eq!(
            err.code().map(|c| c.code().to_owned()).as_deref(),
            Some("22023"),
            "{bad}: {err:?}"
        );
    }
}

/// ETSI EN 319 411-2 keeps status beyond expiry: a CRL stored for that target
/// carries ExpiredCertsOnCRL (2.5.29.60) set to the CA's creation time, and
/// CRLs for the RFC 5280 and EN 319 411-1 targets do not.
#[test]
fn expired_certs_on_crl_follows_the_conformance_target() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    for (n, target) in ["RFC5280", "ETSI_EN_319_411_1", "ETSI_EN_319_411_2"]
        .into_iter()
        .enumerate()
    {
        let ca_id = fresh_ca(&url);
        owner
            .execute(
                "UPDATE ca_revocation_policy
                 SET conformance_target=$2, suspension_cps_ref='CPS 4.9.13 (lab)'
                 WHERE ca_id=$1::text::uuid",
                &[&ca_id, &target],
            )
            .unwrap();
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let root = ca.root_certificate().clone();
        let key_ref = ca.lab_signer_key_ref().to_owned();
        let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
        let serial = issue_leaf(&mut issuance, &mut ca, &ca_id, 1);
        let mut store = PgRevocationStore::connect_lab(&url).unwrap();
        store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();
        change(
            &mut store,
            &ca_id,
            &serial,
            StatusAction::Revoke,
            Some(RevocationReason::Superseded),
        );

        let operation = format!("crl-target-op-{n}");
        let reservation = store
            .reserve_crl(&ca_id, "crl-operator", &operation)
            .unwrap();
        let plan = CrlPlan {
            reservation: &reservation,
            issuer: &root,
            signer_key_ref: &key_ref,
            operation_ref: &operation,
        };
        let verifier = LabCrlVerifier::new(root.clone());
        crl_once(&mut store, &mut ca, &LabCrlAssembler, &verifier, &plan).unwrap();

        let row = owner
            .query_one(
                "SELECT p.crl_der, floor(extract(epoch FROM c.created_at))::bigint
                 FROM crl_publication p JOIN ca c ON c.ca_id=p.ca_id
                 WHERE p.ca_id=$1::text::uuid AND p.status='STORED'",
                &[&ca_id],
            )
            .unwrap();
        let stored: Vec<u8> = row.get(0);
        let ca_created_unix: i64 = row.get(1);
        let crl = x509_cert::crl::CertificateList::from_der(&stored).unwrap();
        let expired_certs = crl
            .tbs_cert_list
            .crl_extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id.to_string() == "2.5.29.60");
        if target == "ETSI_EN_319_411_2" {
            let ext = expired_certs.expect("411-2 CRL must carry ExpiredCertsOnCRL");
            assert!(!ext.critical);
            let since =
                x509_cert::der::asn1::GeneralizedTime::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(since.to_unix_duration().as_secs() as i64, ca_created_unix);
        } else {
            assert!(
                expired_certs.is_none(),
                "{target} CRL must not carry ExpiredCertsOnCRL"
            );
        }
    }
}

/// Migration 0016: a reservation abandoned by its worker is retired, and a
/// late worker can no longer record an intent for it or reach the signer.
#[test]
fn abandoned_reservation_is_never_signed() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();
    let late = store
        .reserve_crl(&ca_id, "crl-operator", "crl-late-op")
        .unwrap();
    assert_eq!(store.abandon_stale_crl_reservations(&ca_id, 0).unwrap(), 1);

    let mut signer = CountingSigner {
        ca: &mut ca,
        calls: 0,
    };
    let plan = CrlPlan {
        reservation: &late,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-late-op",
    };
    let verifier = LabCrlVerifier::new(root.clone());
    assert_eq!(
        crl_once(&mut store, &mut signer, &LabCrlAssembler, &verifier, &plan),
        Err(CrlError::ReserveAgain)
    );
    assert_eq!(signer.calls, 0);

    // The number stays taken: the next reservation is number 2.
    let next = store
        .reserve_crl(&ca_id, "crl-operator", "crl-next-op")
        .unwrap();
    assert_eq!(next.crl_number(), 2);
}

/// A database answer of the wrong shape is an error, never a panic. A
/// private schema shadows `certificate_status` with a NULL-returning function
/// and only this test's connection puts it first on its search_path.
#[test]
fn malformed_database_answer_is_an_error_not_a_panic() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let schema = format!("shadow_{}", ca_id.replace('-', ""));
    owner
        .batch_execute(&format!(
            "CREATE SCHEMA {schema};
             CREATE FUNCTION {schema}.certificate_status(uuid, bytea) RETURNS text
                 LANGUAGE sql AS 'SELECT NULL::text';"
        ))
        .unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    let shadowed = format!("{url}{separator}options=-csearch_path%3D{schema},public");
    let mut store = PgRevocationStore::connect_lab(&shadowed).unwrap();
    let serial = SerialNumber::from_positive_der_content(&[0x01]).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.status(&ca_id, &serial)
    }));
    owner
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .unwrap();
    assert!(
        matches!(result, Ok(Err(RevocationStoreError::InconsistentResult))),
        "expected InconsistentResult, got a panic or another outcome"
    );
}

/// Migration 0017: once CRL n+1 is stored, a late worker holding the
/// reservation for n is refused before signing.
#[test]
fn reservation_older_than_a_stored_crl_is_never_signed() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();
    let late = store
        .reserve_crl(&ca_id, "crl-operator", "crl-slow-op")
        .unwrap();
    let fast = store
        .reserve_crl(&ca_id, "crl-operator", "crl-fast-op")
        .unwrap();
    let verifier = LabCrlVerifier::new(root.clone());
    let mut signer = CountingSigner {
        ca: &mut ca,
        calls: 0,
    };
    let plan = |reservation, operation_ref| CrlPlan {
        reservation,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref,
    };
    crl_once(
        &mut store,
        &mut signer,
        &LabCrlAssembler,
        &verifier,
        &plan(&fast, "crl-fast-op"),
    )
    .unwrap();
    assert_eq!(signer.calls, 1);
    assert_eq!(
        crl_once(
            &mut store,
            &mut signer,
            &LabCrlAssembler,
            &verifier,
            &plan(&late, "crl-slow-op"),
        ),
        Err(CrlError::ReserveAgain)
    );
    assert_eq!(signer.calls, 1);
}

/// RELEASE carries no invalidity date (migration 0014 refuses it); the Rust
/// pre-check must say so with a typed denial before any SQL write.
#[test]
fn release_with_an_invalidity_date_is_denied_before_sql() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
    let serial = issue_leaf(&mut issuance, &mut ca, &ca_id, 301);
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    change(
        &mut store,
        &ca_id,
        &serial,
        StatusAction::Suspend,
        Some(RevocationReason::CertificateHold),
    );
    let maker = OfficerIdentity {
        issuer: ISSUER,
        subject: "maker",
    };
    let result = store.propose(
        &ca_id,
        &serial,
        StatusAction::Release,
        None,
        Some(1_700_000_000),
        &maker,
    );
    assert!(
        matches!(
            result,
            Err(RevocationStoreError::Denied(
                StatusChangeError::ReasonNotAllowedForAction
            ))
        ),
        "got {result:?}"
    );
}

/// Journal whose final store always fails, as after a lost connection.
struct FailingStore<'a>(&'a mut PgRevocationStore);

impl CrlJournal for FailingStore<'_> {
    fn record_intent(&mut self, plan: &CrlPlan<'_>, tbs_sha256: &[u8; 32]) -> Result<(), CrlError> {
        self.0.record_intent(plan, tbs_sha256)
    }
    fn mark_uncertain(&mut self, plan: &CrlPlan<'_>) -> Result<(), CrlError> {
        self.0.mark_uncertain(plan)
    }
    fn persist_verified(
        &mut self,
        _plan: &CrlPlan<'_>,
        _tbs_sha256: &[u8; 32],
        _crl_sha256: &[u8; 32],
        _crl_der: &[u8],
    ) -> Result<(), CrlError> {
        Err(CrlError::PersistenceFailure)
    }
}

/// A CRL signed and verified but not stored is returned to the caller and,
/// after independent re-verification against the rebuilt reservation, stored
/// by reconciliation instead of losing the number.
#[test]
fn verified_crl_whose_storage_failed_is_reconciled() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
    let serial = issue_leaf(&mut issuance, &mut ca, &ca_id, 401);
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();
    change(
        &mut store,
        &ca_id,
        &serial,
        StatusAction::Revoke,
        Some(RevocationReason::KeyCompromise),
    );
    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let status = |c: &mut postgres::Client| -> String {
        c.query_one(
            "SELECT status FROM crl_publication WHERE ca_id=$1::text::uuid AND crl_number=1",
            &[&ca_id],
        )
        .unwrap()
        .get(0)
    };

    let reservation = store
        .reserve_crl(&ca_id, "crl-operator", "crl-lost-op")
        .unwrap();
    let verifier = LabCrlVerifier::new(root.clone());
    let plan = CrlPlan {
        reservation: &reservation,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-lost-op",
    };
    let crl = match crl_once(
        &mut FailingStore(&mut store),
        &mut ca,
        &LabCrlAssembler,
        &verifier,
        &plan,
    ) {
        Err(CrlError::VerifiedButNotStored(der)) => der,
        other => panic!("expected VerifiedButNotStored, got {other:?}"),
    };
    assert_eq!(status(&mut reader), "RECONCILIATION_REQUIRED");

    // The reservation is rebuilt from the database, not taken from memory.
    let rebuilt = store.load_reservation(&ca_id, 1).unwrap();
    assert_eq!(rebuilt, reservation);

    // Altered bytes are refused by the independent verifier.
    let mut altered = crl.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x01;
    assert_eq!(
        reconcile_crl(
            &mut store,
            &verifier,
            &rebuilt,
            "crl-lost-op",
            "crl-reviewer",
            &altered
        ),
        Err(CrlError::VerificationFailure)
    );
    assert_eq!(status(&mut reader), "RECONCILIATION_REQUIRED");

    reconcile_crl(
        &mut store,
        &verifier,
        &rebuilt,
        "crl-lost-op",
        "crl-reviewer",
        &crl,
    )
    .unwrap();
    assert_eq!(status(&mut reader), "STORED");
    let row = reader
        .query_one(
            "SELECT p.crl_der,
                    (SELECT count(*) FROM audit_event a WHERE a.ca_id = p.ca_id
                       AND a.event_type = 'crl.reconciled' AND a.actor_id = 'crl-reviewer'
                       AND a.decision = 'STORED:1')
             FROM crl_publication p WHERE p.ca_id=$1::text::uuid AND p.crl_number=1",
            &[&ca_id],
        )
        .unwrap();
    let stored: Vec<u8> = row.get(0);
    let audits: i64 = row.get(1);
    assert_eq!((stored, audits), (crl.clone(), 1));

    // Reconciling again is refused: the row is final.
    assert_eq!(
        reconcile_crl(
            &mut store,
            &verifier,
            &rebuilt,
            "crl-lost-op",
            "crl-reviewer",
            &crl
        ),
        Err(CrlError::ReplayedOrAmbiguousIntent)
    );

    // For tests/crl_reconcile.sh, which runs the crl_reconcile tool: a
    // second CRL left quarantined, its DER and the issuer certificate.
    if let Ok(dir) = env::var("TRUST_CRL_EXPORT_DIR") {
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = store
            .reserve_crl(&ca_id, "crl-operator", "crl-lost-op-2")
            .unwrap();
        let plan = CrlPlan {
            reservation: &second,
            issuer: &root,
            signer_key_ref: &key_ref,
            operation_ref: "crl-lost-op-2",
        };
        let der = match crl_once(
            &mut FailingStore(&mut store),
            &mut ca,
            &LabCrlAssembler,
            &verifier,
            &plan,
        ) {
            Err(CrlError::VerifiedButNotStored(der)) => der,
            other => panic!("expected VerifiedButNotStored, got {other:?}"),
        };
        let dir = std::path::Path::new(&dir).join("reconcile");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("crl.der"), der).unwrap();
        std::fs::write(dir.join("issuer.der"), root.to_der().unwrap()).unwrap();
        let other = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        std::fs::write(
            dir.join("other_issuer.der"),
            other.root_certificate().to_der().unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("ids"),
            format!("{ca_id} {}\n", second.crl_number()),
        )
        .unwrap();
    }
}

/// Scheduled housekeeping: a CA without a CRL is due; a reservation left by
/// a dead worker is retired; once a CRL is stored nothing needs attention.
#[test]
fn housekeeping_reports_and_cleans_up() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();

    store
        .reserve_crl(&ca_id, "crl-operator", "crl-dead-worker")
        .unwrap();
    let report = store.crl_housekeeping(&ca_id, 0, 3600).unwrap();
    assert_eq!(
        (
            report.abandoned,
            report.quarantined,
            report.crl_due,
            report.overdue_changes
        ),
        (1, 0, true, 0)
    );
    assert!(report.needs_attention());

    let reservation = store
        .reserve_crl(&ca_id, "crl-operator", "crl-housekeeping-op")
        .unwrap();
    let plan = CrlPlan {
        reservation: &reservation,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-housekeeping-op",
    };
    let verifier = LabCrlVerifier::new(root.clone());
    crl_once(&mut store, &mut ca, &LabCrlAssembler, &verifier, &plan).unwrap();
    let report = store.crl_housekeeping(&ca_id, 3600, 3600).unwrap();
    assert!(!report.needs_attention(), "{report:?}");
}

/// Issue found by review: nothing tied a reservation's CA to the issuer the
/// CRL is built and signed with, so another CA's consistent issuer, key and
/// verifier stored that CA's CRL under this ca_id. Refused before signing.
#[test]
fn crl_of_another_ca_is_refused_before_signing() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_a = fresh_ca(&url);
    let mut other = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let other_root = other.root_certificate().clone();
    let other_key = other.lab_signer_key_ref().to_owned();
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    let ca_a_root = EphemeralLabCa::new("Sovereign Trust Lab Root")
        .unwrap()
        .root_certificate()
        .clone();
    store
        .register_ca_issuer(&ca_a, &ca_a_root, "ca-admin")
        .unwrap();
    let reservation = store
        .reserve_crl(&ca_a, "crl-operator", "crl-cross-op")
        .unwrap();
    let mut signer = CountingSigner {
        ca: &mut other,
        calls: 0,
    };
    let plan = CrlPlan {
        reservation: &reservation,
        issuer: &other_root,
        signer_key_ref: &other_key,
        operation_ref: "crl-cross-op",
    };
    let result = crl_once(
        &mut store,
        &mut signer,
        &LabCrlAssembler,
        &LabCrlVerifier::new(other_root.clone()),
        &plan,
    );
    assert_eq!(result.map(|_| ()), Err(CrlError::IssuerMismatch));
    assert_eq!(signer.calls, 0);

    // Registration: idempotent for the same certificate, another one is
    // refused by the database, and a certificate that cannot issue CRLs is
    // refused before any SQL.
    store
        .register_ca_issuer(&ca_a, &ca_a_root, "ca-admin")
        .unwrap();
    let err = store
        .register_ca_issuer(&ca_a, &other_root, "ca-admin")
        .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("23514"));
    let mut not_a_ca = other_root.clone();
    not_a_ca
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .retain(|e| e.extn_id.to_string() != "2.5.29.19");
    let fresh = fresh_ca(&url);
    assert!(matches!(
        store.register_ca_issuer(&fresh, &not_a_ca, "ca-admin"),
        Err(RevocationStoreError::InvalidIssuer)
    ));
}

/// `url` with `role` set for the session (the test login is a superuser,
/// which may assume any role; a deployment grants each service login one
/// capability role instead).
fn url_as(url: &str, role: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}options=-crole%3D{role}")
}

/// Migration 0023 (ADR-0006 part A): the Rust store runs the whole pipeline
/// with EXECUTE-only capability roles, and each role is refused the others'
/// functions.
#[test]
fn least_privilege_roles_run_the_whole_pipeline() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
    let serial = issue_leaf(&mut issuance, &mut ca, &ca_id, 501);

    let mut admin = PgRevocationStore::connect_lab(&url_as(&url, "trust_ca_admin")).unwrap();
    let mut officer =
        PgRevocationStore::connect_lab(&url_as(&url, "trust_revocation_officer_api")).unwrap();
    let mut signer_store =
        PgRevocationStore::connect_lab(&url_as(&url, "trust_crl_signer")).unwrap();
    let mut operator = PgRevocationStore::connect_lab(&url_as(&url, "trust_crl_operator")).unwrap();

    // Issuer registration needs two CA admins (0024); a single admin can no
    // longer register directly.
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    owner
        .execute(
            "INSERT INTO ca_admin_grant(issuer, subject, ca_id)
             VALUES ($2, 'admin-a', $1::text::uuid), ($2, 'admin-b', $1::text::uuid)",
            &[&ca_id, &ISSUER],
        )
        .unwrap();
    let admin_a = OfficerIdentity {
        issuer: ISSUER,
        subject: "admin-a",
    };
    let admin_b = OfficerIdentity {
        issuer: ISSUER,
        subject: "admin-b",
    };
    assert_eq!(
        sqlstate(
            &admin
                .register_ca_issuer(&ca_id, &root, "ca-admin")
                .unwrap_err()
        )
        .as_deref(),
        Some("42501")
    );
    let registration = admin
        .propose_issuer_registration(&ca_id, &root, &admin_a)
        .unwrap();
    assert_eq!(
        sqlstate(
            &admin
                .approve_issuer_registration(&registration, &root, &admin_a)
                .unwrap_err()
        )
        .as_deref(),
        Some("23514"),
        "maker cannot approve"
    );
    admin
        .approve_issuer_registration(&registration, &root, &admin_b)
        .unwrap();

    // An officer grant, also under dual control; the Rust digest is the SQL one.
    let officer_3 = OfficerIdentity {
        issuer: ISSUER,
        subject: "officer-3",
    };
    let digest = officer_grant_digest(OfficerGrantAction::Grant, &officer_3);
    let sql_digest: Vec<u8> = owner
        .query_one(
            "SELECT ca_admin_content_digest('GRANT_OFFICER', NULL, $1, $2)",
            &[&ISSUER, &"officer-3"],
        )
        .unwrap()
        .get(0);
    assert_eq!(sql_digest, digest);
    let grant = admin
        .propose_officer_grant(&ca_id, OfficerGrantAction::Grant, &officer_3, &admin_b)
        .unwrap();
    admin
        .approve_officer_grant(&grant, OfficerGrantAction::Grant, &officer_3, &admin_a)
        .unwrap();
    change(
        &mut officer,
        &ca_id,
        &serial,
        StatusAction::Revoke,
        Some(RevocationReason::KeyCompromise),
    );
    assert_eq!(
        officer.status(&ca_id, &serial).unwrap(),
        CertificateStatus::Revoked
    );

    let reservation = signer_store
        .reserve_crl(&ca_id, "crl-operator", "crl-lp-op")
        .unwrap();
    assert_eq!(reservation.entries().len(), 1);
    let plan = CrlPlan {
        reservation: &reservation,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-lp-op",
    };
    let verifier = LabCrlVerifier::new(root.clone());
    crl_once(
        &mut signer_store,
        &mut ca,
        &LabCrlAssembler,
        &verifier,
        &plan,
    )
    .unwrap();
    assert_eq!(
        signer_store
            .load_reservation(&ca_id, reservation.crl_number())
            .unwrap(),
        reservation
    );
    assert!(!operator
        .crl_housekeeping(&ca_id, 3600, 3600)
        .unwrap()
        .needs_attention());

    // Each role is refused the others' functions (42501).
    let maker = OfficerIdentity {
        issuer: ISSUER,
        subject: "maker",
    };
    let denied = |e: &RevocationStoreError| sqlstate(e).as_deref() == Some("42501");
    assert!(denied(
        &signer_store
            .propose(
                &ca_id,
                &serial,
                StatusAction::Revoke,
                Some(RevocationReason::Superseded),
                None,
                &maker
            )
            .unwrap_err()
    ));
    assert!(denied(
        &officer
            .reserve_crl(&ca_id, "x", "crl-lp-denied")
            .unwrap_err()
    ));
    assert!(denied(
        &operator
            .reserve_crl(&ca_id, "x", "crl-lp-denied")
            .unwrap_err()
    ));
    assert!(denied(
        &signer_store
            .crl_housekeeping(&ca_id, 3600, 3600)
            .unwrap_err()
    ));
    assert!(denied(
        &officer
            .register_ca_issuer(&ca_id, &root, "officer")
            .unwrap_err()
    ));
}

/// `url` with other credentials (lab test logins only).
fn url_with_login(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap();
    let (_, host_and_path) = rest.split_once('@').unwrap();
    format!("{scheme}://{user}:{password}@{host_and_path}")
}

/// A service connection refuses a privileged login (superuser, or member of
/// the owner role) and accepts a plain login holding one capability role.
#[test]
fn service_connections_refuse_privileged_sessions() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    // Cluster-wide test logins; test-only password, lab database only.
    owner
        .batch_execute(
            "DO $$ BEGIN
                 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_signer_login_test') THEN
                     CREATE ROLE trust_signer_login_test LOGIN PASSWORD 'test-only-not-secret'
                         IN ROLE trust_crl_signer;
                 END IF;
                 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_owner_login_test') THEN
                     CREATE ROLE trust_owner_login_test LOGIN PASSWORD 'test-only-not-secret'
                         IN ROLE trust_revocation_owner;
                 END IF;
             END $$;",
        )
        .unwrap();
    assert!(matches!(
        PgRevocationStore::connect_lab_service(&url),
        Err(RevocationStoreError::PrivilegedSession)
    ));
    assert!(
        matches!(
            PgRevocationStore::connect_lab_service(&url_as(&url, "trust_crl_signer")),
            Err(RevocationStoreError::PrivilegedSession)
        ),
        "a superuser login stays privileged whatever role it sets"
    );
    assert!(matches!(
        PgRevocationStore::connect_lab_service(&url_with_login(
            &url,
            "trust_owner_login_test",
            "test-only-not-secret"
        )),
        Err(RevocationStoreError::PrivilegedSession)
    ));
    let mut signer = PgRevocationStore::connect_lab_service(&url_with_login(
        &url,
        "trust_signer_login_test",
        "test-only-not-secret",
    ))
    .unwrap();
    // The plain login works for its capability and nothing else.
    let ca_id = fresh_ca(&url);
    signer
        .reserve_crl(&ca_id, "crl-operator", "crl-login-op")
        .unwrap();
    let maker = OfficerIdentity {
        issuer: ISSUER,
        subject: "maker",
    };
    let serial = SerialNumber::from_positive_der_content(&[0x01]).unwrap();
    assert_eq!(
        sqlstate(
            &signer
                .propose(
                    &ca_id,
                    &serial,
                    StatusAction::Revoke,
                    Some(RevocationReason::Superseded),
                    None,
                    &maker
                )
                .unwrap_err()
        )
        .as_deref(),
        Some("42501")
    );
}

/// Migration 0026 (ADR-0006 condition 3): a schema change outside a reviewed
/// migration reaches the housekeeping operator; other service roles cannot
/// read the audit.
#[test]
fn unreviewed_schema_changes_reach_the_operator() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let table = format!("schema_audit_probe_{}", fresh_ca(&url).replace('-', "_"));
    owner
        .batch_execute(&format!("CREATE TABLE {table} (a INT)"))
        .unwrap();
    let mut operator = PgRevocationStore::connect_lab(&url_as(&url, "trust_crl_operator")).unwrap();
    assert!(operator.unreviewed_schema_changes().unwrap() >= 1);
    let mut officer =
        PgRevocationStore::connect_lab(&url_as(&url, "trust_revocation_officer_api")).unwrap();
    assert_eq!(
        sqlstate(&officer.unreviewed_schema_changes().unwrap_err()).as_deref(),
        Some("42501")
    );
    owner.batch_execute(&format!("DROP TABLE {table}")).unwrap();
}

/// A fresh random P-256 public key (uncompressed SEC1) from an ephemeral
/// lab CA; nothing is signed with it.
fn fresh_p256_key() -> Vec<u8> {
    EphemeralLabCa::new("Sovereign Trust Lab Root")
        .unwrap()
        .root_certificate()
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec()
}

/// Migration 0028 (ADR-0007 step 1): officer keys are compared as curve
/// points. One key enrolled once in uncompressed form cannot be enrolled
/// again in compressed form for another officer; an invalid point never
/// reaches the database, and raw uncompressed bytes are refused by it.
#[test]
fn officer_credentials_compare_keys_as_curve_points() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    owner
        .execute(
            "INSERT INTO ca_admin_grant(issuer, subject, ca_id)
             VALUES ($2, 'admin-a', $1::text::uuid), ($2, 'admin-b', $1::text::uuid)",
            &[&ca_id, &ISSUER],
        )
        .unwrap();
    // fresh_ca already grants the officers "maker" and "checker".
    let mut admin = PgRevocationStore::connect_lab(&url_as(&url, "trust_ca_admin")).unwrap();
    let identity = |subject| OfficerIdentity {
        issuer: ISSUER,
        subject,
    };
    let (admin_a, admin_b) = (identity("admin-a"), identity("admin-b"));
    let (maker, checker) = (identity("maker"), identity("checker"));
    // Credential ids unique per run: the CA id bytes plus a tag.
    let credential = |tag: u8| {
        let mut id = ca_id.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let uncompressed = fresh_p256_key();
    assert_eq!(uncompressed.len(), 65);
    let compressed = canonical_officer_key(&uncompressed).unwrap();

    let enrol = |admin: &mut PgRevocationStore, content: &CredentialContent<'_>| {
        let change = admin.propose_credential_enrollment(content, &admin_a)?;
        admin.approve_credential_change(&change, CredentialChangeKind::Enroll, content, &admin_b)
    };
    let first_id = credential(1);
    let first = CredentialContent {
        ca_id: &ca_id,
        credential_id: &first_id,
        officer: &maker,
        person_id: "person-maker",
        public_key_sec1: &uncompressed,
    };
    enrol(&mut admin, &first).unwrap();
    let stored: Vec<u8> = owner
        .query_one(
            "SELECT public_key_sec1 FROM officer_credential WHERE credential_id = $1",
            &[&first_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(stored, compressed.to_vec(), "stored in canonical form");

    // The same key, compressed, under another credential id and officer.
    let second_id = credential(2);
    let same_key = CredentialContent {
        ca_id: &ca_id,
        credential_id: &second_id,
        officer: &checker,
        person_id: "person-checker",
        public_key_sec1: &compressed,
    };
    let refused = enrol(&mut admin, &same_key).unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some("23514"));
    // Raw uncompressed bytes are refused by the database itself.
    let raw = owner
        .query_one(
            "SELECT propose_credential_change($1::text::uuid, 'ENROLL_CREDENTIAL', $2, $3,
                 'checker', 'person-checker', $4, $3, 'admin-a')",
            &[&ca_id, &second_id, &ISSUER, &uncompressed],
        )
        .unwrap_err();
    assert_eq!(raw.code().map(|c| c.code()), Some("22023"));
    // A point off the curve never reaches the database.
    let mut off_curve = uncompressed.clone();
    off_curve[64] ^= 1;
    let invalid = admin
        .propose_credential_enrollment(
            &CredentialContent {
                public_key_sec1: &off_curve,
                ..same_key
            },
            &admin_a,
        )
        .unwrap_err();
    assert!(matches!(
        invalid,
        RevocationStoreError::InvalidCredential(CredentialError::InvalidPublicKey)
    ));

    // The checker approves only the content it reviewed.
    let other_key = fresh_p256_key();
    let checker_content = CredentialContent {
        public_key_sec1: &other_key,
        ..same_key
    };
    let change = admin
        .propose_credential_enrollment(&checker_content, &admin_a)
        .unwrap();
    let misread = admin
        .approve_credential_change(
            &change,
            CredentialChangeKind::Enroll,
            &CredentialContent {
                person_id: "someone-else",
                ..checker_content
            },
            &admin_b,
        )
        .unwrap_err();
    assert_eq!(sqlstate(&misread).as_deref(), Some("23514"));
    admin
        .approve_credential_change(
            &change,
            CredentialChangeKind::Enroll,
            &checker_content,
            &admin_b,
        )
        .unwrap();

    // Removal: the checker reviews the stored person and key.
    let removal = admin
        .propose_credential_removal(&ca_id, &first_id, &maker, &admin_b)
        .unwrap();
    admin
        .approve_credential_change(&removal, CredentialChangeKind::Remove, &first, &admin_a)
        .unwrap();
    let status: String = owner
        .query_one(
            "SELECT status FROM officer_credential WHERE credential_id = $1",
            &[&first_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(status, "REMOVED");
}

/// Issued certificates carry the CA's CRL distribution point (RFC 5280
/// 4.2.1.13): one revoked and one valid leaf, a stored CRL covering the
/// revocation. With TRUST_CDP_EXPORT_DIR set, root.der, revoked.der,
/// valid.der and ca_id are written for tests/crl_distribution_point_e2e.sh,
/// where OpenSSL follows the URL to the crl_distribution binary.
#[test]
fn issued_certificates_point_relying_parties_to_the_crl() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let base = env::var("TRUST_CDP_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:18083".into());
    let ca_id = fresh_ca(&url);
    let cdp = crl_distribution_url(&base, &ca_id);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    ca.set_crl_distribution_point(&cdp).unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
    let revoked = issue_leaf_with(&mut issuance, &mut ca, &ca_id, 1, Some(&cdp));
    let valid = issue_leaf_with(&mut issuance, &mut ca, &ca_id, 2, Some(&cdp));

    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();
    change(
        &mut store,
        &ca_id,
        &revoked,
        StatusAction::Revoke,
        Some(RevocationReason::KeyCompromise),
    );
    let reservation = store
        .reserve_crl(&ca_id, "crl-operator", "crl-cdp-op")
        .unwrap();
    let plan = CrlPlan {
        reservation: &reservation,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "crl-cdp-op",
    };
    crl_once(
        &mut store,
        &mut ca,
        &LabCrlAssembler,
        &LabCrlVerifier::new(root.clone()),
        &plan,
    )
    .unwrap();

    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let expected = crl_distribution_points(&cdp).unwrap();
    let mut stored = Vec::new();
    for serial in [&revoked, &valid] {
        let der: Vec<u8> = reader
            .query_one(
                "SELECT certificate_der FROM certificate
                 WHERE ca_id = $1::text::uuid AND serial_der_content = $2",
                &[&ca_id, &serial.as_der_content()],
            )
            .unwrap()
            .get(0);
        let cert = Certificate::from_der(&der).unwrap();
        let points: Vec<_> = cert
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .filter(|e| e.extn_id.to_string() == "2.5.29.31")
            .collect();
        assert_eq!(points, vec![&expected], "stored leaf carries the CDP");
        stored.push(der);
    }
    if let Ok(dir) = env::var("TRUST_CDP_EXPORT_DIR") {
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("root.der"), root.to_der().unwrap()).unwrap();
        std::fs::write(dir.join("revoked.der"), &stored[0]).unwrap();
        std::fs::write(dir.join("valid.der"), &stored[1]).unwrap();
        std::fs::write(dir.join("ca_id"), &ca_id).unwrap();
    }
}

/// ADR-0006 condition 6: the database clock is checked against the Rust
/// core's clock. Here the Rust clock runs a minute ahead (a database a
/// minute behind): the CRL reservation is refused before anything can be
/// signed, stays RESERVED, and housekeeping retires it and raises the alarm.
#[test]
fn a_skewed_database_clock_is_refused_before_signing() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    let reading = store.database_clock().unwrap();
    assert!(
        reading.within(clock::DEFAULT_MAX_CLOCK_SKEW_US),
        "{reading:?}"
    );

    fn a_minute_ahead() -> i64 {
        clock::system_clock_us() + 60_000_000
    }
    store.set_clock_source(a_minute_ahead);
    assert!(matches!(
        store.reserve_crl(&ca_id, "crl-operator", "crl-skew-op"),
        Err(RevocationStoreError::ClockSkew)
    ));
    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let status: String = reader
        .query_one(
            "SELECT status FROM crl_publication WHERE ca_id = $1::text::uuid",
            &[&ca_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(status, "RESERVED", "never got an intent");
    let report = store.crl_housekeeping(&ca_id, 0, 3600).unwrap();
    assert!(!report.clock_within_bound, "{report:?}");
    assert!(report.clock.skew_us < -55_000_000, "{report:?}");
    assert_eq!(report.abandoned, 1);
    assert!(report.needs_attention());
}

/// Migration 0032: a revoked certificate stored with a not_after earlier
/// than its real expiry would be pruned from the CRL by 0031; the Rust core
/// re-reads the certificate before recording the intent and refuses to sign
/// the CRL that leaves it out.
#[test]
fn a_falsified_expiry_cannot_prune_a_revoked_certificate() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    owner
        .execute(
            "UPDATE ca_revocation_policy SET keep_expired_on_crl = false
             WHERE ca_id = $1::text::uuid",
            &[&ca_id],
        )
        .unwrap();
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();

    // A real leaf (valid for a day), stored as if it had expired yesterday.
    let (csr, authorization, binding) = context();
    let serial = SerialNumber::from_positive_der_content(&[0x0a]).unwrap();
    let leaf = ca
        .issue_leaf(&csr, &authorization, &serial, &binding)
        .unwrap();
    owner
        .execute(
            "WITH request AS (
                 INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                     requester_id, policy_version, state)
                 VALUES (gen_random_uuid(), $1::text::uuid, 'falsified-expiry',
                         sha256('csr'::bytea), 'requester', 'v1', 'PUBLISHED')
                 RETURNING request_id),
             reservation AS (
                 INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
                 SELECT $1::text::uuid, '\\x0a', request_id FROM request
                 RETURNING request_id)
             INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                 certificate_der, signed_at, not_after)
             SELECT $1::text::uuid, '\\x0a', request_id, sha256($2), $2,
                    now() - interval '2 days', now() - interval '1 day'
             FROM reservation",
            &[&ca_id, &leaf.to_der().unwrap()],
        )
        .unwrap();
    change(
        &mut store,
        &ca_id,
        &serial,
        StatusAction::Revoke,
        Some(RevocationReason::KeyCompromise),
    );

    let verifier = LabCrlVerifier::new(root.clone());
    let sign = |store: &mut PgRevocationStore, ca: &mut EphemeralLabCa, op: &str| {
        let reservation = store.reserve_crl(&ca_id, "crl-operator", op).unwrap();
        let plan = CrlPlan {
            reservation: &reservation,
            issuer: &root,
            signer_key_ref: &key_ref,
            operation_ref: op,
        };
        let result = crl_once(store, ca, &LabCrlAssembler, &verifier, &plan);
        (reservation.entries().len(), result)
    };
    // CRL 1 still lists it (not yet on a CRL issued after the claimed expiry).
    let (listed, first) = sign(&mut store, &mut ca, "crl-falsified-1");
    assert_eq!(listed, 1);
    first.unwrap();
    // CRL 2 would leave it out: refused before signing.
    let (listed, second) = sign(&mut store, &mut ca, "crl-falsified-2");
    assert_eq!(listed, 0, "the database pruned the entry");
    assert_eq!(second.unwrap_err(), CrlError::UnexplainedOmission);
    let status: String = owner
        .query_one(
            "SELECT status FROM crl_publication WHERE ca_id = $1::text::uuid AND crl_number = 2",
            &[&ca_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(status, "RESERVED", "no intent, nothing signed");
}

/// Migration 0033: the housekeeping job covers every CA that can publish
/// CRLs (registered issuer), and only the CRL operator may list them.
#[test]
fn housekeeping_lists_every_crl_issuing_ca() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let (issuing, silent) = (fresh_ca(&url), fresh_ca(&url));
    let root = EphemeralLabCa::new("Sovereign Trust Lab Root")
        .unwrap()
        .root_certificate()
        .clone();
    PgRevocationStore::connect_lab(&url)
        .unwrap()
        .register_ca_issuer(&issuing, &root, "ca-admin")
        .unwrap();
    let mut operator = PgRevocationStore::connect_lab(&url_as(&url, "trust_crl_operator")).unwrap();
    let cas = operator.crl_issuing_cas().unwrap();
    assert!(cas.contains(&issuing));
    assert!(
        !cas.contains(&silent),
        "a CA without issuer cannot publish CRLs"
    );
    for role in [
        "trust_crl_signer",
        "trust_revocation_officer_api",
        "trust_ca_admin",
    ] {
        let mut other = PgRevocationStore::connect_lab(&url_as(&url, role)).unwrap();
        assert_eq!(
            sqlstate(&other.crl_issuing_cas().unwrap_err()).as_deref(),
            Some("42501"),
            "{role}"
        );
    }
}

/// ADR-0006 condition 3: role changes (new logins, role grants, elevated
/// attributes) are not caught by the event triggers. Migration 0057 keeps
/// a reviewed snapshot of the security-relevant role state; housekeeping
/// reports the lines that differ until a superuser acknowledges them.
#[test]
fn unreviewed_role_changes_are_reported() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut operator = PgRevocationStore::connect_lab(&format!(
        "{url}{}options=-crole%3Dtrust_crl_operator",
        if url.contains('?') { '&' } else { '?' }
    ))
    .unwrap();
    owner
        .batch_execute("SELECT acknowledge_role_state('test baseline')")
        .unwrap();
    assert_eq!(operator.unreviewed_role_changes().unwrap(), 0);
    // A new login that can act as a CA admin is a role change.
    owner
        .batch_execute(
            "DROP ROLE IF EXISTS trust_rolecheck_ci;
             CREATE ROLE trust_rolecheck_ci LOGIN;
             GRANT trust_ca_admin TO trust_rolecheck_ci",
        )
        .unwrap();
    assert!(operator.unreviewed_role_changes().unwrap() >= 2);
    owner
        .batch_execute("SELECT acknowledge_role_state('test: rolecheck login reviewed')")
        .unwrap();
    assert_eq!(operator.unreviewed_role_changes().unwrap(), 0);
    // So is an elevated attribute.
    owner
        .batch_execute("ALTER ROLE trust_rolecheck_ci CREATEROLE")
        .unwrap();
    assert!(operator.unreviewed_role_changes().unwrap() >= 1);
    owner
        .batch_execute(
            "DROP ROLE trust_rolecheck_ci;
             SELECT acknowledge_role_state('test cleanup')",
        )
        .unwrap();
    // Only a superuser acknowledges.
    let mut ack = postgres::Client::connect(
        &format!(
            "{url}{}options=-crole%3Dtrust_crl_operator",
            if url.contains('?') { '&' } else { '?' }
        ),
        postgres::NoTls,
    )
    .unwrap();
    let denied = ack
        .batch_execute("SELECT acknowledge_role_state('operator')")
        .unwrap_err();
    assert_eq!(denied.code().map(|c| c.code()), Some("42501"));
}

/// Delta CRLs through the database (migration 0059, RFC 5280 5.2.4): the
/// base complete CRL advertises them (freshestCRL from the CA policy), the
/// delta shares the numbering, lists the new revocation and the released
/// hold, is signed and stored by the same pipeline, and is never published
/// as the complete CRL.
#[test]
fn delta_crl_is_reserved_signed_and_stored_through_the_database() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let delta_url = "http://crl.lab.invalid/delta/test.crl";
    let mut owner = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
    let s1 = issue_leaf(&mut issuance, &mut ca, &ca_id, 601);
    let s2 = issue_leaf(&mut issuance, &mut ca, &ca_id, 602);
    let s3 = issue_leaf(&mut issuance, &mut ca, &ca_id, 603);
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();
    let verifier = LabCrlVerifier::new(root.clone());
    let sign =
        |store: &mut PgRevocationStore, ca: &mut EphemeralLabCa, r: &CrlReservation, op: &str| {
            let plan = CrlPlan {
                reservation: r,
                issuer: &root,
                signer_key_ref: &key_ref,
                operation_ref: op,
            };
            crl_once(store, ca, &LabCrlAssembler, &verifier, &plan).unwrap()
        };

    // Deltas are off by default: refused before anything is written.
    let err = store
        .reserve_delta_crl(&ca_id, "crl-operator", "delta-off")
        .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("55000"));

    owner
        .execute(
            "UPDATE ca_revocation_policy SET delta_crl_url = $2 WHERE ca_id = $1::text::uuid",
            &[&ca_id, &delta_url],
        )
        .unwrap();
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
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let base = store
        .reserve_crl(&ca_id, "crl-operator", "delta-base")
        .unwrap();
    assert_eq!(base.freshest_crl_url(), Some(delta_url));
    let base_der = sign(&mut store, &mut ca, &base, "delta-base");
    assert_eq!(
        verify_published_crl(&root, &base_der).unwrap().crl_number,
        base.crl_number()
    );

    change(&mut store, &ca_id, &s2, StatusAction::Release, None);
    change(
        &mut store,
        &ca_id,
        &s3,
        StatusAction::Revoke,
        Some(RevocationReason::Superseded),
    );
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let delta = store
        .reserve_delta_crl(&ca_id, "crl-operator", "delta-1")
        .unwrap();
    assert_eq!(
        delta.crl_number(),
        base.crl_number() + 1,
        "one numbering sequence"
    );
    assert_eq!(delta.base_crl_number(), Some(base.crl_number()));
    assert_eq!(delta.freshest_crl_url(), None);
    assert_eq!(delta.entries().len(), 1);
    assert_eq!(delta.entries()[0].serial, s3);
    assert_eq!(delta.entries()[0].reason, RevocationReason::Superseded);
    assert_eq!(delta.released().len(), 1);
    assert_eq!(delta.released()[0].serial, s2);
    // Rebuilt from the database, the reservation is the same: a
    // quarantined delta can be reconciled like a complete CRL.
    assert_eq!(
        store.load_reservation(&ca_id, delta.crl_number()).unwrap(),
        delta
    );
    let delta_der = sign(&mut store, &mut ca, &delta, "delta-1");
    let published = verify_published_delta_crl(&root, &delta_der).unwrap();
    assert_eq!(published.base_crl_number, base.crl_number());
    assert_eq!(
        verify_published_crl(&root, &delta_der),
        Err(CrlError::VerificationFailure)
    );

    // The distribution point's functions keep the two apart.
    let publisher_row = owner
        .query_one(
            "SELECT (SELECT crl_number FROM published_crl($1::text::uuid)),
                    (SELECT crl_number FROM published_delta_crl($1::text::uuid))",
            &[&ca_id],
        )
        .unwrap();
    assert_eq!(publisher_row.get::<usize, i64>(0), base.crl_number() as i64);
    assert_eq!(
        publisher_row.get::<usize, i64>(1),
        delta.crl_number() as i64
    );

    if let Ok(dir) = env::var("TRUST_CRL_EXPORT_DIR") {
        let dir = std::path::Path::new(&dir).join("delta");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("root.der"), root.to_der().unwrap()).unwrap();
        for (n, serial) in [&s1, &s2, &s3].iter().enumerate() {
            let der: Vec<u8> = owner
                .query_one(
                    "SELECT certificate_der FROM certificate
                     WHERE ca_id=$1::text::uuid AND serial_der_content=$2",
                    &[&ca_id, &serial.as_der_content()],
                )
                .unwrap()
                .get(0);
            std::fs::write(dir.join(format!("leaf{}.der", n + 1)), der).unwrap();
        }
        for (name, number) in [
            ("crl1", base.crl_number()),
            ("crl_delta", delta.crl_number()),
        ] {
            let der: Vec<u8> = owner
                .query_one(
                    "SELECT crl_der FROM crl_publication
                     WHERE ca_id=$1::text::uuid AND crl_number=$2 AND status='STORED'",
                    &[&ca_id, &(number as i64)],
                )
                .unwrap()
                .get(0);
            std::fs::write(dir.join(format!("{name}.der")), der).unwrap();
        }
    }
}

/// After a restore from an older backup (migration 0060): the revocations a
/// published CRL lists but the database lost are re-applied from that CRL,
/// once its signature verifies against the CA's registered issuer; the next
/// CRL is numbered above it, lists them again and goes through the normal
/// signing pipeline.
#[test]
fn revocations_lost_in_a_restore_are_reapplied_from_the_published_crl() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = fresh_ca(&url);
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = ca.root_certificate().clone();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    let mut issuance = PgIssuanceStore::connect_lab(&url).unwrap();
    let s1 = issue_leaf(&mut issuance, &mut ca, &ca_id, 701);
    let s2 = issue_leaf(&mut issuance, &mut ca, &ca_id, 702);
    let s3 = issue_leaf(&mut issuance, &mut ca, &ca_id, 703);
    let mut store = PgRevocationStore::connect_lab(&url).unwrap();
    store.register_ca_issuer(&ca_id, &root, "ca-admin").unwrap();
    // The restored database: only the hold on s2 survived.
    change(
        &mut store,
        &ca_id,
        &s2,
        StatusAction::Suspend,
        Some(RevocationReason::CertificateHold),
    );

    // CRL 5, published before the database was rolled back: s1 and s2
    // keyCompromise, and a certificate issued after the backup.
    let lost_serial = SerialNumber::from_positive_der_content(&[0x7f, 0x01]).unwrap();
    let now = trust_pki_core::clock::system_clock_us() / 1_000_000 + 1;
    let entry = |serial: &SerialNumber| trust_pki_core::crl::CrlEntry {
        serial: serial.clone(),
        revoked_at_unix: now - 60,
        reason: RevocationReason::KeyCompromise,
        invalidity_at_unix: None,
    };
    let lost = CrlReservation::new(
        &ca_id,
        5,
        now,
        now + 86_400,
        vec![entry(&s1), entry(&s2), entry(&lost_serial)],
        None,
    )
    .unwrap();
    let sign_crl = |ca: &mut EphemeralLabCa, r: &CrlReservation| {
        let tbs = trust_pki_core::crl::build_tbs_cert_list(&root, r).unwrap();
        let signature = ca.sign_once(&key_ref, "lost-crl", &tbs).unwrap();
        LabCrlAssembler.assemble(&tbs, &signature).unwrap()
    };
    let lost_der = sign_crl(&mut ca, &lost);

    // The same CRL signed by another key is refused before the database.
    let mut forger = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let forged_tbs = trust_pki_core::crl::build_tbs_cert_list(&root, &lost).unwrap();
    let forger_key = forger.lab_signer_key_ref().to_owned();
    let forged_sig = forger
        .sign_once(&forger_key, "forged", &forged_tbs)
        .unwrap();
    let forged = LabCrlAssembler.assemble(&forged_tbs, &forged_sig).unwrap();
    assert!(matches!(
        store.restore_revocations_from_crl(&ca_id, &forged, "restore drill"),
        Err(RevocationStoreError::InvalidCrl)
    ));
    assert_eq!(store.status(&ca_id, &s1).unwrap(), CertificateStatus::Valid);

    use trust_pki_core::revocation_store::RestoreOutcome;
    let mut outcomes = store
        .restore_revocations_from_crl(&ca_id, &lost_der, "restore drill")
        .unwrap();
    outcomes.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected = vec![
        (s1.clone(), RestoreOutcome::Restored),
        (s2.clone(), RestoreOutcome::Upgraded),
        (lost_serial.clone(), RestoreOutcome::UnknownCertificate),
    ];
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(outcomes, expected);
    assert_eq!(
        store.status(&ca_id, &s1).unwrap(),
        CertificateStatus::Revoked
    );
    assert_eq!(
        store.status(&ca_id, &s2).unwrap(),
        CertificateStatus::Revoked
    );
    assert_eq!(store.status(&ca_id, &s3).unwrap(), CertificateStatus::Valid);
    // The same CRL again: nothing changes.
    assert!(store
        .restore_revocations_from_crl(&ca_id, &lost_der, "restore drill")
        .unwrap()
        .iter()
        .all(|(serial, outcome)| *outcome == RestoreOutcome::Present || *serial == lost_serial));

    // The next CRL is 6, lists both revocations and is signed, verified
    // and stored by the usual pipeline.
    let next = store
        .reserve_crl(&ca_id, "crl-operator", "after-restore")
        .unwrap();
    assert_eq!(next.crl_number(), 6);
    let listed: Vec<&SerialNumber> = next.entries().iter().map(|e| &e.serial).collect();
    assert!(listed.contains(&&s1) && listed.contains(&&s2) && listed.len() == 2);
    let verifier = LabCrlVerifier::new(root.clone());
    let plan = CrlPlan {
        reservation: &next,
        issuer: &root,
        signer_key_ref: &key_ref,
        operation_ref: "after-restore",
    };
    crl_once(&mut store, &mut ca, &LabCrlAssembler, &verifier, &plan).unwrap();
    // An older CRL can no longer be restored over it.
    assert!(matches!(
        store.restore_revocations_from_crl(&ca_id, &lost_der, "restore drill"),
        Err(RevocationStoreError::Database(_))
    ));

    // For tests/crl_restore_revocations.sh, which runs the binary: CRL 7
    // (s3 superseded as well, never applied here) and a forged copy.
    if let Ok(dir) = env::var("TRUST_CRL_EXPORT_DIR") {
        let dir = std::path::Path::new(&dir).join("restore");
        std::fs::create_dir_all(&dir).unwrap();
        let mut s3_entry = entry(&s3);
        s3_entry.reason = RevocationReason::Superseded;
        let seventh = CrlReservation::new(
            &ca_id,
            7,
            now + 1,
            now + 86_400,
            vec![entry(&s1), entry(&s2), s3_entry, entry(&lost_serial)],
            None,
        )
        .unwrap();
        std::fs::write(dir.join("crl7.der"), sign_crl(&mut ca, &seventh)).unwrap();
        let tbs = trust_pki_core::crl::build_tbs_cert_list(&root, &seventh).unwrap();
        let sig = forger.sign_once(&forger_key, "forged-7", &tbs).unwrap();
        std::fs::write(
            dir.join("crl7_forged.der"),
            LabCrlAssembler.assemble(&tbs, &sig).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("ids"),
            format!(
                "{ca_id} {} {}\n",
                hex(s3.as_der_content()),
                hex(lost_serial.as_der_content())
            ),
        )
        .unwrap();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
