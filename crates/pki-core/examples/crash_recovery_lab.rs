//! Demonstrate a real SIGKILL between signing and database result persistence.
//! This is a lab-only process; never run against a production CA or database.
//!
//! cargo build -p trust-pki-core --example crash_recovery_lab
//!   --features postgres-store,lab-software --locked
//! TRUST_CI_DATABASE_URL=... target/debug/examples/crash_recovery_lab crash
//! TRUST_CI_DATABASE_URL=... target/debug/examples/crash_recovery_lab recover
//!
//! "crash" blocks AFTER a valid RustCrypto signature exists, before the DB
//! stores the resulting certificate. The CI harness sends SIGKILL.
//! "recover" runs as a separate process and DOES NOT invoke a signer.

#![cfg(all(feature = "postgres-store", feature = "lab-software"))]

use sha2::{Digest, Sha256};
use std::{
    env,
    io::{self, Write},
    thread,
    time::Duration,
};
use trust_pki_core::{
    csr::verify_pkcs10_p256,
    lab_ca::EphemeralLabCa,
    lab_x509_verifier::{LabCertificateAssembler, LabX509Verifier},
    orchestrator::{CertificateAssembler, CertificateVerifier, ExternalSigner, IssuancePlan},
    postgres_store::{PgIssuanceStore, SigningIntentInput},
    serial::SerialNumber,
    x509_extensions::ApprovedPolicyBinding,
};
use trust_pki_crypto::SignatureAlgorithm;
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
use x509_cert::{
    der::{DecodePem, Encode},
    request::CertReq,
};

const CA_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const ACTOR: &str = "v0-8-crash-lab";
const REQUEST_KEY: &str = "v0-8-sigkill-request";
const OPERATION_REF: &str = "v0-8-sigkill-operation";

fn simulate_crash_after_signature(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = PgIssuanceStore::connect_lab(url).map_err(|e| format!("{e:?}"))?;
    let csr = CertReq::from_pem(include_str!("../tests/fixtures/ecdsa-p256-request.pem"))?;
    let csr_der = csr.to_der()?;
    let verified = verify_pkcs10_p256(&csr_der, "api.lab.invalid").map_err(|e| format!("{e:?}"))?;
    let policy = StaticPolicy {
        profile_id: "lab-server".into(),
        policy_version: "v1".into(),
        allowed_actors: vec![ACTOR.into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
        max_validity_days: 3,
        max_dns_sans: 1,
    };
    let principal = AuthenticatedPrincipal { subject_id: ACTOR };
    let names = ["api.lab.invalid"];
    let request = IssuanceRequest {
        profile_id: "lab-server",
        subject_common_name: "api.lab.invalid",
        dns_sans: &names,
        validity_days: 1,
        ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    };
    let authorization = policy
        .authorize(&principal, &request)
        .map_err(|e| format!("{e:?}"))?;
    let binding =
        ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "unapproved-fixture", [7; 32])
            .map_err(|e| format!("{e:?}"))?;
    let persisted = store
        .create_request(
            CA_ID,
            REQUEST_KEY,
            verified.fingerprint_sha256(),
            ACTOR,
            "v1",
        )
        .map_err(|e| format!("{e:?}"))?;
    if persisted.replay {
        return Err("Crash demonstration must use a fresh request".into());
    }
    store
        .transition(
            CA_ID,
            &persisted.request_id,
            "RECEIVED",
            "CSR_VALIDATED",
            ACTOR,
        )
        .map_err(|e| format!("{e:?}"))?;
    store
        .transition(
            CA_ID,
            &persisted.request_id,
            "CSR_VALIDATED",
            "AUTHORIZED",
            ACTOR,
        )
        .map_err(|e| format!("{e:?}"))?;
    let serial_data = store
        .reserve_serial(CA_ID, &persisted.request_id, ACTOR)
        .map_err(|e| format!("{e:?}"))?;
    let serial =
        SerialNumber::from_positive_der_content(&serial_data).map_err(|e| format!("{e:?}"))?;
    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").map_err(|e| format!("{e:?}"))?;
    let tbs = ca
        .prepare_leaf_tbs(&verified, &authorization, &serial, &binding)
        .map_err(|e| format!("{e:?}"))?;
    let tbs_der = tbs.to_der()?;
    let digest: [u8; 32] = Sha256::digest(&tbs_der).into();
    let key_ref = ca.lab_signer_key_ref().to_owned();
    store
        .record_signing_intent(&SigningIntentInput {
            ca_id: CA_ID,
            request_id: &persisted.request_id,
            actor_id: ACTOR,
            signer_key_ref: &key_ref,
            tbs_sha256: &digest,
            policy_revision: "v1",
            operation_ref: OPERATION_REF,
        })
        .map_err(|e| format!("{e:?}"))?;

    // This is a *real cryptographic signature* of the lab leaf's X.509 TBS.
    // Deliberately never persist the signed DER; SIGKILL is injected below.
    let sig = ca
        .sign_once(&key_ref, OPERATION_REF, &tbs_der)
        .map_err(|e| format!("{e:?}"))?;
    let assembled = LabCertificateAssembler
        .assemble(&tbs_der, &sig)
        .map_err(|e| format!("{e:?}"))?;
    let verifier = LabX509Verifier::new(
        ca.root_certificate().clone(),
        binding,
        "api.lab.invalid".to_owned(),
    );
    let plan = IssuancePlan {
        ca_id: CA_ID,
        request_id: &persisted.request_id,
        actor_id: ACTOR,
        signer_key_ref: &key_ref,
        policy_revision: "v1",
        operation_ref: OPERATION_REF,
        serial_der: &serial_data,
        tbs_der: &tbs_der,
    };
    verifier
        .verify(&plan, &assembled)
        .map_err(|e| format!("{e:?}"))?;
    println!("SIGNED_VERIFIED_NOT_STORED:{}", persisted.request_id);
    io::stdout().flush()?;
    // CI sends SIGKILL here. This sleep does not perform another signature.
    thread::sleep(Duration::from_secs(120));
    Err("SIGKILL test did not terminate the worker".into())
}

fn recover_without_resigning(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = PgIssuanceStore::connect_lab(url).map_err(|e| format!("{e:?}"))?;
    let candidates = store
        .quarantine_stale(CA_ID, 0, 20, "v0-8-recovery-scanner")
        .map_err(|e| format!("{e:?}"))?;
    for candidate in &candidates {
        if candidate.operation_ref != OPERATION_REF {
            return Err("unexpected candidate selected for recovery".into());
        }
        println!("QUARANTINED_OPERATION:{}", candidate.operation_ref);
    }
    println!("QUARANTINED_COUNT:{}", candidates.len());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::var("TRUST_CI_DATABASE_URL")?;
    match env::args().nth(1).as_deref() {
        Some("crash") => simulate_crash_after_signature(&url),
        Some("recover") => recover_without_resigning(&url),
        _ => Err("usage: crash_recovery_lab crash|recover".into()),
    }
}
