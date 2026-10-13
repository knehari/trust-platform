//! Actual PostgreSQL journal + native RSA-PSS X.509 signing integration.
//! Disposable lab CA/DB only. This does NOT test authorization or HSM custody.
#![cfg(all(feature = "postgres-store", feature = "lab-software"))]
use std::env;
use trust_pki_core::{
    issuance_x509_binding::issue_x509_once,
    orchestrator::{IssuancePlan, IssueError},
    postgres_store::PgIssuanceStore,
    rsa_pss_orchestrator_lab::{LabRsaPssAssembler, LabRsaPssExternalSigner, LabRsaPssVerifier},
    rsa_pss_x509_lab::create_root_and_signer,
};
use x509_cert::{
    der::{Decode, Encode},
    serial_number::SerialNumber,
    Certificate,
};

#[test]
fn rsa_pss_intent_signature_and_certificate_are_durable_and_nonreplayable() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        return;
    };
    let ca_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let actor = "rsa-pss-integration";
    let mut db = PgIssuanceStore::connect_lab(&url).unwrap();
    let request = db
        .create_request(ca_id, "v18-rsa-pss-persist-once", &[0x81; 32], actor, "v1")
        .unwrap();
    assert!(!request.replay);
    db.transition(
        ca_id,
        &request.request_id,
        "RECEIVED",
        "CSR_VALIDATED",
        actor,
    )
    .unwrap();
    db.transition(
        ca_id,
        &request.request_id,
        "CSR_VALIDATED",
        "AUTHORIZED",
        actor,
    )
    .unwrap();
    let serial = db
        .reserve_validated_serial(ca_id, &request.request_id, actor)
        .unwrap();
    let (issuer, key) = create_root_and_signer().unwrap();
    let signer_ref = key.key_ref().0.clone();
    let mut tbs = issuer.tbs_certificate.clone();
    tbs.serial_number = SerialNumber::new(serial.as_der_content()).unwrap();
    let tbs_der = tbs.to_der().unwrap();
    let plan = IssuancePlan {
        ca_id,
        request_id: &request.request_id,
        actor_id: actor,
        signer_key_ref: &signer_ref,
        policy_revision: "v1",
        operation_ref: "v18-rsa-pss-persist-op",
        serial_der: serial.as_der_content(),
        tbs_der: &tbs_der,
    };
    let mut signer = LabRsaPssExternalSigner(key);
    let result = issue_x509_once(
        &mut db,
        &mut signer,
        &LabRsaPssAssembler,
        LabRsaPssVerifier {
            issuer: issuer.clone(),
        },
        &plan,
    )
    .unwrap();
    let parsed = Certificate::from_der(&result).unwrap();
    assert_eq!(parsed.tbs_certificate.serial_number, tbs.serial_number);
    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let row = reader
        .query_one(
            "SELECT c.certificate_der, si.outcome FROM certificate c
         JOIN signing_intent si USING (ca_id, request_id)
         WHERE c.request_id=$1::text::uuid",
            &[&request.request_id],
        )
        .unwrap();
    let persisted: Vec<u8> = row.get(0);
    let outcome: String = row.get(1);
    assert_eq!(persisted, result);
    assert_eq!(outcome, "CERTIFICATE_STORED");
    assert_eq!(
        issue_x509_once(
            &mut db,
            &mut signer,
            &LabRsaPssAssembler,
            LabRsaPssVerifier { issuer },
            &plan,
        ),
        Err(IssueError::ReplayedOrAmbiguousIntent)
    );
}
