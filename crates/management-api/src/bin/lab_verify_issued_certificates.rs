//! Laboratory audit tool: re-verifies every certificate issued for a
//! certificate application (migration 0029, ADR-0017) independently of the
//! API and of the lab signer that produced it.
//!
//! For each issued application it checks, with the reviewed `pki-core`
//! verifier, that the stored certificate is the server leaf the application
//! describes: signed by the CA's registered issuer certificate, for the
//! subject key of the stored CSR (whose proof-of-possession is re-verified),
//! with the application's common name and DNS names, the reserved serial and
//! the profile's extensions. It also checks that the stored fingerprint is
//! the certificate's, that the signing intent journaled the digest of this
//! very TBS and was claimed exactly once by the signer, and that the
//! application was approved by a registration officer.
//!
//! PostgreSQL verifies neither X.509 nor ECDSA, so a compromised API or
//! writer login could store what the API would refuse; this tool is how that
//! is detected. Run it as the database owner:
//! `TRUST_VERIFY_DATABASE_URL=… cargo run -p trust-management-api --bin lab_verify_issued_certificates`
use std::{env, error::Error, io, process::ExitCode, time::SystemTime};

use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};
use trust_pki_core::{
    application_leaf::{verify_server_leaf, LeafFacts},
    csr::verify_pkcs10_p256,
};
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

struct Issued {
    application_id: String,
    csr_der: Vec<u8>,
    subject_cn: String,
    dns_names: Vec<String>,
    validity_days: i32,
    serial: Vec<u8>,
    certificate_der: Vec<u8>,
    fingerprint: Vec<u8>,
    signed_at: SystemTime,
    issuer_der: Vec<u8>,
    tbs_sha256: Vec<u8>,
    outcome: String,
    claims: i64,
    decision: Option<String>,
}

fn problems(record: &Issued) -> Vec<String> {
    let mut found = Vec::new();
    if Sha256::digest(&record.certificate_der)[..] != record.fingerprint[..] {
        found.push("stored fingerprint is not the certificate's".into());
    }
    if record.outcome != "CERTIFICATE_STORED" {
        found.push(format!("signing intent outcome is {}", record.outcome));
    }
    if record.claims != 1 {
        found.push(format!(
            "signer claimed the intent {} time(s)",
            record.claims
        ));
    }
    if record.decision.as_deref() != Some("approve") {
        found.push("the application was not approved".into());
    }
    let issuer = match Certificate::from_der(&record.issuer_der) {
        Ok(issuer) => issuer,
        Err(_) => {
            found.push("issuer certificate does not decode".into());
            return found;
        }
    };
    let csr = match verify_pkcs10_p256(&record.csr_der, &record.subject_cn) {
        Ok(csr) => csr,
        Err(reason) => {
            found.push(format!("stored CSR does not verify ({reason:?})"));
            return found;
        }
    };
    let tbs_der = match Certificate::from_der(&record.certificate_der)
        .ok()
        .and_then(|certificate| certificate.tbs_certificate.to_der().ok())
    {
        Some(tbs_der) => tbs_der,
        None => {
            found.push("stored certificate does not decode".into());
            return found;
        }
    };
    if Sha256::digest(&tbs_der)[..] != record.tbs_sha256[..] {
        found.push("journaled TBS digest is not the certificate's".into());
    }
    let facts = LeafFacts {
        subject_cn: &record.subject_cn,
        dns_names: &record.dns_names,
        subject_public_key: csr.subject_public_key(),
        validity_days: u32::try_from(record.validity_days).unwrap_or(0),
        serial: &record.serial,
    };
    if let Err(reason) = verify_server_leaf(
        &issuer,
        &facts,
        &tbs_der,
        &record.certificate_der,
        record.signed_at,
    ) {
        found.push(format!("certificate does not verify ({reason:?})"));
    }
    found
}

fn main() -> Result<ExitCode, Box<dyn Error>> {
    let url = env::var("TRUST_VERIFY_DATABASE_URL")
        .map_err(|_| io::Error::other("set TRUST_VERIFY_DATABASE_URL to a lab database"))?;
    let mut db = Client::connect(&url, NoTls)
        .map_err(|_| io::Error::other("issuance database unavailable"))?;
    let rows = db.query(
        "SELECT i.application_id::text, a.csr_der, a.subject_cn, a.dns_names, a.validity_days, \
                c.serial_der_content, c.certificate_der, c.fingerprint_sha256, c.signed_at, \
                k.certificate_der, s.tbs_sha256, s.outcome, \
                (SELECT count(*) FROM lab_signer_claim l WHERE l.intent_id = s.intent_id), \
                d.decision \
           FROM certificate_application_issuance i \
           JOIN certificate_application a ON a.application_id = i.application_id \
           JOIN certificate c ON c.ca_id = i.ca_id AND c.request_id = i.request_id \
           JOIN ca_issuer_certificate k ON k.ca_id = i.ca_id \
           LEFT JOIN signing_intent s ON s.ca_id = i.ca_id AND s.request_id = i.request_id \
           LEFT JOIN certificate_application_decision d ON d.application_id = i.application_id \
          ORDER BY i.started_at",
        &[],
    )?;
    let mut failed = 0usize;
    for row in &rows {
        let record = Issued {
            application_id: row.get(0),
            csr_der: row.get(1),
            subject_cn: row.get(2),
            dns_names: row.get(3),
            validity_days: row.get(4),
            serial: row.get(5),
            certificate_der: row.get(6),
            fingerprint: row.get(7),
            signed_at: row.get(8),
            issuer_der: row.get(9),
            tbs_sha256: row.get::<_, Option<Vec<u8>>>(10).unwrap_or_default(),
            outcome: row
                .get::<_, Option<String>>(11)
                .unwrap_or_else(|| "missing".into()),
            claims: row.get(12),
            decision: row.get(13),
        };
        let found = problems(&record);
        if !found.is_empty() {
            failed += 1;
            eprintln!(
                "FAIL application {}: {}",
                record.application_id,
                found.join("; ")
            );
        }
    }
    if failed > 0 {
        eprintln!("{failed} problem(s) in the issued certificates");
        return Ok(ExitCode::FAILURE);
    }
    println!(
        "PASS: {} certificate(s) issued for applications verified independently",
        rows.len()
    );
    Ok(ExitCode::SUCCESS)
}
