//! Actual PostgreSQL journal + native RSA-PSS X.509 signing integration.
//! Disposable lab CA/DB only. This does NOT test authorization or HSM custody.
#![cfg(all(feature = "postgres-store", feature = "lab-software"))]
use std::env;
use trust_pki_core::{
    csr::verify_pkcs10_p256,
    issuance_x509_binding::issue_x509_once,
    orchestrator::{IssuancePlan, IssueError},
    postgres_store::PgIssuanceStore,
    rsa_pss_orchestrator_lab::{LabRsaPssAssembler, LabRsaPssExternalSigner, LabRsaPssVerifier},
    rsa_pss_x509_lab::{create_root_and_signer, prepare_rsa_pss_server_tbs},
    x509_extensions::ApprovedPolicyBinding,
};
use trust_pki_crypto::SignatureAlgorithm;
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
use x509_cert::{
    der::{Decode, DecodePem, Encode},
    request::CertReq,
    Certificate,
};

#[test]
fn rsa_pss_intent_signature_and_certificate_are_durable_and_nonreplayable() {
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        return;
    };
    let ca_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let actor = "rsa-pss-integration";
    let csr = CertReq::from_pem(include_str!("fixtures/ecdsa-p256-request.pem")).unwrap();
    let verified = verify_pkcs10_p256(&csr.to_der().unwrap(), "api.lab.invalid").unwrap();
    let allowed = StaticPolicy {
        profile_id: "lab-server-rsa-pss".into(),
        policy_version: "v1".into(),
        allowed_actors: vec![actor.into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::RsaPssSha256],
        max_validity_days: 3,
        max_dns_sans: 2,
    };
    let dns = ["api.lab.invalid"];
    let authorization = allowed.authorize(
        &AuthenticatedPrincipal { subject_id: actor },
        &IssuanceRequest {
            profile_id: "lab-server-rsa-pss",
            subject_common_name: "api.lab.invalid",
            dns_sans: &dns,
            validity_days: 1,
            ca_signature_algorithm: SignatureAlgorithm::RsaPssSha256,
        },
    ).unwrap();
    let binding = ApprovedPolicyBinding::new(
        "1.3.6.1.4.1.55555.1.1", "lab-doc-v1", [7; 32],
    ).unwrap();
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
    let tbs = prepare_rsa_pss_server_tbs(
        &verified, &authorization, &binding, &serial, &issuer,
    ).unwrap();
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
    assert_eq!(parsed.tbs_certificate.subject, *verified.subject());
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
