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
