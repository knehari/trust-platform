//! Laboratory pre-sign policy enforcement using real ECDSA P-256 X.509 TBS.
//! Neither actor strings nor draft approval establish real PKI authorization.
#![cfg(all(feature = "postgres-store", feature = "lab-software"))]

use sha2::{Digest, Sha256};
use std::env;
use trust_pki_core::{
    ca_observation::observe_pinned_lab_ca,
    cp_cps::{generate, Input as CpCpsInput},
    csr::verify_pkcs10_p256,
    lab_ca::EphemeralLabCa,
    lab_x509_verifier::{LabCertificateAssembler, LabX509Verifier},
    orchestrator::{issue_once, IssuancePlan},
    policy_gate::{verify_presign_policy, GateError},
    postgres_store::PgIssuanceStore,
    serial::SerialNumber,
    x509_extensions::ApprovedPolicyBinding,
};
use trust_pki_crypto::SignatureAlgorithm;
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
use x509_cert::{
    der::{DecodePem, Encode},
    request::CertReq,
};

fn configured_policy() -> StaticPolicy {
    StaticPolicy {
        profile_id: "lab-server".into(),
        policy_version: "v1".into(),
        allowed_actors: vec!["lab-actor".into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
        max_validity_days: 3,
        max_dns_sans: 2,
    }
}
#[test]
fn real_x509_issuance_requires_active_two_actor_policy_and_exact_oid() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        return;
    };
    let ca_id = "88888888-8888-4888-8888-888888888888";
    let mut raw_db = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    raw_db
        .execute(
            "INSERT INTO ca(ca_id,display_name,policy_version)
         VALUES($1::text::uuid,'Pre-sign Approval Gate CI','v1')
         ON CONFLICT(ca_id) DO NOTHING",
            &[&ca_id],
        )
        .unwrap();
    drop(raw_db);

    let mut db = PgIssuanceStore::connect_lab(&url).unwrap();
    let ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root_der = ca.root_certificate().to_der().unwrap();
    let trusted_pin: [u8; 32] = Sha256::digest(&root_der).into();
    let observed = observe_pinned_lab_ca(&root_der, &trusted_pin).unwrap();
    let observed_id = db
        .register_ca_public_observation(ca_id, "lab-observer", &observed)
        .unwrap();
    let policy = configured_policy();
    let input = CpCpsInput {
        policy: &policy,
        policy_oid: "1.3.6.1.4.1.55555.1.1",
        edition: "lab-approved-edition",
        issuer: "Sovereign Trust Lab Root",
        authority: "Unverified Lab Board",
        repository: "lab.invalid/drafts",
    };
    let drafts = generate(&input).unwrap();
    assert!(!drafts.publication_authorized);
    let draft_id = db
        .register_cp_cps_draft(ca_id, &observed_id, "lab-preparer", &input)
        .unwrap();

    // Actor identity is NOT authenticated in the laboratory DB.
    let approval_id = db.approve_draft_policy_lab(
        &trust_pki_core::postgres_store::LabDraftApproval {
            ca_id,
            draft_id: &draft_id,
            proposer: "maker",
            approver: "checker",
            cp_sha256: &drafts.cp.sha256,
            cps_sha256: &drafts.cps.sha256,
            effective_from: "2025-01-01T00:00:00Z",
            effective_until: "2030-01-01T00:00:00Z",
        },
    ).unwrap();
    assert_eq!(
        db.activate_issuer_policy_gate_lab(ca_id, "lab-admin")
            .unwrap(),
        "ENFORCE_ALL_NEW_SIGNING_INTENTS"
    );

    let csr = CertReq::from_pem(include_str!("fixtures/ecdsa-p256-request.pem")).unwrap();
    let csr_der = csr.to_der().unwrap();
    let verified_csr = verify_pkcs10_p256(&csr_der, "api.lab.invalid").unwrap();
    let req = IssuanceRequest {
        profile_id: "lab-server",
        subject_common_name: "api.lab.invalid",
        dns_sans: &["api.lab.invalid"],
        validity_days: 1,
        ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    };
    let authorization = policy
        .authorize(
            &AuthenticatedPrincipal {
                subject_id: "lab-actor",
            },
            &req,
        )
        .unwrap();
    let request = db
        .create_request(
            ca_id,
            "v14-real-policy-gated",
            verified_csr.fingerprint_sha256(),
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
    let binding = ApprovedPolicyBinding::new(
        "1.3.6.1.4.1.55555.1.1",
        "lab-approved-edition",
        drafts.cp.sha256,
    )
    .unwrap();
    let mut signing_ca = ca;
    let tbs = signing_ca
        .prepare_leaf_tbs(&verified_csr, &authorization, &serial, &binding)
        .unwrap();
    let tbs_der = tbs.to_der().unwrap();
    let key_ref = signing_ca.lab_signer_key_ref().to_owned();
    let plan = IssuancePlan {
        ca_id,
        request_id: &request.request_id,
        actor_id: "lab-actor",
        signer_key_ref: &key_ref,
        policy_revision: "v1",
        operation_ref: "v14-approved-op",
        serial_der: &serial_data,
        tbs_der: &tbs_der,
    };

    // The opt-in database trigger must reject old direct sign paths
    // until a matching approved document is granted.
    let mut spy = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    assert!(spy
        .query_one(
            "SELECT intent_id FROM create_signing_intent(
            $1::text::uuid,$2::text::uuid,$3,$4,$5,$6,$7
        )",
            &[
                &ca_id,
                &request.request_id,
                &"lab-actor",
                &key_ref,
                &&Sha256::digest(&tbs_der)[..],
                &"v1",
                &"v14-approved-op"
            ],
        )
        .is_err());

    // The OID must be extracted from the exact X509 TBS, not asserted by
    // a user or CSR, and must agree with the effective document edition.
    let wrong_binding = ApprovedPolicyBinding::new(
        "1.3.6.1.4.1.55555.1.99",
        "lab-approved-edition",
        drafts.cp.sha256,
    )
    .unwrap();
    assert_eq!(
        verify_presign_policy(&plan, "v1", &wrong_binding),
        Err(GateError::WrongPolicyOid)
    );
    assert_eq!(
        verify_presign_policy(&plan, "v2", &binding),
        Err(GateError::WrongPolicyRevision)
    );
    let verified = verify_presign_policy(&plan, "v1", &binding).unwrap();

    assert_eq!(
        db.grant_presign_policy_lab(&approval_id, "lab-authority", &verified)
            .unwrap(),
        "GRANTED_FOR_THIS_TBS_ONLY"
    );
    let verifier = LabX509Verifier::new(
        signing_ca.root_certificate().clone(),
        binding,
        "api.lab.invalid".into(),
    );
    let der = issue_once(
        &mut db,
        &mut signing_ca,
        &LabCertificateAssembler,
        &verifier,
        &plan,
    )
    .unwrap();

    let mut check = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let row = check
        .query_one(
            "SELECT cr.state, p.approver, p.policy_oid,
                c.certificate_der
         FROM certificate_request cr
         JOIN issuance_policy_grant g ON g.ca_id=cr.ca_id
                AND g.request_id=cr.request_id
         JOIN approved_policy_edition p
                ON p.ca_id=g.ca_id AND p.approval_id=g.approval_id
         JOIN certificate c
                ON c.ca_id=cr.ca_id AND c.request_id=cr.request_id
         WHERE cr.request_id=$1::text::uuid",
            &[&request.request_id],
        )
        .unwrap();
    assert_eq!(row.get::<usize, String>(0), "SIGNED");
    assert_eq!(row.get::<usize, String>(1), "checker");
    assert_eq!(row.get::<usize, String>(2), input.policy_oid);
    assert_eq!(row.get::<usize, Vec<u8>>(3), der);
}
