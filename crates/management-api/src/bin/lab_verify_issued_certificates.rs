//! Laboratory audit tool: re-verifies every certificate issued for a
//! certificate application (migration 0029, ADR-0017) independently of the
//! API and of the lab signer that produced it.
//!
//! For each issued application it checks, with the reviewed `pki-core`
//! verifier, that the stored certificate is the server leaf the application
//! describes: signed by the CA's registered issuer certificate, for the
//! subject key of the stored CSR (whose proof-of-possession is re-verified),
//! with the application's common name and DNS names, the reserved serial and
//! the profile's extensions, including the CRL distribution point
//! snapshotted with the signing intent (migration 0031). It also checks that the stored fingerprint is
//! the certificate's, that the signing intent journaled the digest of this
//! very TBS and was claimed exactly once by the signer, and that the
//! application was approved by a registration officer.
//!
//! For each core revocation of such a certificate (migration 0030, ADR-0018)
//! it checks that an approved revocation request carries the same reason,
//! and that a registration officer other than the one who asked approved
//! it. For each published CRL it rebuilds the CRL from the database's own
//! entries, number and instants, and verifies the stored DER against the
//! issuer certificate's key; it checks the stored digests and exactly one
//! signer claim.
//!
//! PostgreSQL verifies neither X.509 nor ECDSA, so a compromised API or
//! writer login could store what the API would refuse; this tool is how that
//! is detected. Run it as the database owner:
//! `TRUST_VERIFY_DATABASE_URL=… cargo run -p trust-management-api --bin lab_verify_issued_certificates`
use std::{env, error::Error, io, process::ExitCode, time::SystemTime};

use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};
use trust_pki_core::{
    application_crl::{build_crl_tbs, parse_utc_seconds, verify_crl, CrlEntry, CrlFacts},
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
    crl_distribution_point: Option<String>,
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
        crl_distribution_point: record.crl_distribution_point.as_deref(),
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

/// Revocations without an approved request of the same reason, by an
/// officer other than the requester.
fn revocation_problems(db: &mut Client) -> Result<Vec<(String, String)>, postgres::Error> {
    Ok(db
        .query(
            "SELECT encode(r.serial_der_content, 'hex'), concat_ws('; ', \
                 CASE WHEN q.revocation_id IS NULL THEN 'no approved revocation request' END, \
                 CASE WHEN q.reason_code <> r.reason_code THEN 'reason differs from the request' END, \
                 CASE WHEN qe.actor_issuer = de.actor_issuer AND qe.actor_subject = de.actor_subject \
                      THEN 'approved by its requester' END, \
                 CASE WHEN de.event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM management_role_grant g \
                      WHERE g.issuer = de.actor_issuer AND g.subject = de.actor_subject \
                        AND g.ca_id = r.ca_id AND g.lifecycle_role = 'registration-officer') \
                      THEN 'approver holds no registration-officer grant' END) \
             FROM revocation r \
             JOIN certificate c ON c.ca_id = r.ca_id AND c.serial_der_content = r.serial_der_content \
             JOIN certificate_application_issuance i ON i.ca_id = c.ca_id AND i.request_id = c.request_id \
             LEFT JOIN certificate_revocation_request q ON q.ca_id = r.ca_id \
                  AND q.serial_der_content = r.serial_der_content \
                  AND EXISTS (SELECT 1 FROM certificate_revocation_decision d \
                              WHERE d.revocation_id = q.revocation_id AND d.decision = 'approve') \
             LEFT JOIN certificate_application_event qe ON qe.event_id = q.requested_event_id \
             LEFT JOIN certificate_revocation_decision dd ON dd.revocation_id = q.revocation_id \
             LEFT JOIN certificate_application_event de ON de.event_id = dd.decided_event_id",
            &[],
        )?
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
        .filter(|(_, reasons)| !reasons.is_empty())
        .collect())
}

/// Published CRLs that do not verify against the database's own facts.
fn crl_problems(db: &mut Client) -> Result<(usize, Vec<(String, String)>), postgres::Error> {
    let crls = db.query(
        "SELECT d.ca_id::text || '#' || d.crl_number, i.intent_id::text, d.crl_der, d.crl_sha256, \
                p.crl_sha256, i.crl_number, \
                to_char(i.this_update AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                to_char(i.next_update AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                k.certificate_der, i.outcome, i.tbs_sha256, \
                (SELECT count(*) FROM lab_signer_crl_claim l WHERE l.intent_id = i.intent_id) \
           FROM crl_document d \
           JOIN crl_signing_intent i ON i.intent_id = d.intent_id \
           JOIN ca_issuer_certificate k ON k.ca_id = d.ca_id \
           LEFT JOIN crl_publication p ON p.ca_id = d.ca_id AND p.crl_number = d.crl_number \
          ORDER BY d.ca_id, d.crl_number",
        &[],
    )?;
    let mut found = Vec::new();
    for row in &crls {
        let label: String = row.get(0);
        let intent: String = row.get(1);
        let der: Vec<u8> = row.get(2);
        let mut reasons = Vec::new();
        if row.get::<_, Vec<u8>>(3) != Sha256::digest(&der).to_vec()
            || row.get::<_, Option<Vec<u8>>>(4) != Some(Sha256::digest(&der).to_vec())
        {
            reasons.push("stored digests are not the CRL's".to_owned());
        }
        if row.get::<_, String>(9) != "PUBLISHED" || row.get::<_, i64>(11) != 1 {
            reasons.push("intent not published after exactly one signer claim".to_owned());
        }
        let entries = db
            .query(
                "SELECT serial, to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                 reason_code FROM crl_intent_entries($1::text::uuid)",
                &[&intent],
            )?
            .iter()
            .map(|entry| {
                Some(CrlEntry {
                    serial: entry.get(0),
                    revoked_at: parse_utc_seconds(&entry.get::<_, String>(1)).ok()?,
                    reason_code: u8::try_from(entry.get::<_, i16>(2)).ok()?,
                })
            })
            .collect::<Option<Vec<_>>>();
        let (Some(entries), Ok(this_update), Ok(next_update), Ok(number), Ok(issuer)) = (
            entries,
            parse_utc_seconds(&row.get::<_, String>(6)),
            parse_utc_seconds(&row.get::<_, String>(7)),
            u64::try_from(row.get::<_, i64>(5)),
            Certificate::from_der(&row.get::<_, Vec<u8>>(8)),
        ) else {
            reasons.push("unreadable CRL facts".to_owned());
            found.push((label, reasons.join("; ")));
            continue;
        };
        let facts = CrlFacts {
            crl_number: number,
            this_update,
            next_update,
            entries: &entries,
        };
        match build_crl_tbs(&issuer, &facts).map(|tbs| tbs.to_der()) {
            Ok(Ok(tbs_der)) => {
                if Some(Sha256::digest(&tbs_der).to_vec()) != row.get::<_, Option<Vec<u8>>>(10) {
                    reasons.push("journaled TBS digest is not the rebuilt CRL's".to_owned());
                }
                if let Err(reason) = verify_crl(&issuer, &facts, &tbs_der, &der) {
                    reasons.push(format!("CRL does not verify ({reason:?})"));
                }
            }
            _ => reasons.push("the CRL facts cannot be rebuilt".to_owned()),
        }
        if !reasons.is_empty() {
            found.push((label, reasons.join("; ")));
        }
    }
    Ok((crls.len(), found))
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
                d.decision, dp.url \
           FROM certificate_application_issuance i \
           JOIN certificate_application a ON a.application_id = i.application_id \
           JOIN certificate c ON c.ca_id = i.ca_id AND c.request_id = i.request_id \
           JOIN ca_issuer_certificate k ON k.ca_id = i.ca_id \
           LEFT JOIN signing_intent s ON s.ca_id = i.ca_id AND s.request_id = i.request_id \
           LEFT JOIN certificate_application_decision d ON d.application_id = i.application_id \
           LEFT JOIN signing_intent_crl_distribution_point dp ON dp.intent_id = s.intent_id \
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
            crl_distribution_point: row.get(14),
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
    let revocations = revocation_problems(&mut db)?;
    for (serial, reasons) in &revocations {
        failed += 1;
        eprintln!("FAIL revocation of serial {serial}: {reasons}");
    }
    let revoked: i64 = db
        .query_one(
            "SELECT count(*) FROM revocation r JOIN certificate c USING (ca_id, serial_der_content) \
             JOIN certificate_application_issuance i ON i.ca_id = c.ca_id AND i.request_id = c.request_id",
            &[],
        )?
        .get(0);
    let (crl_count, crls) = crl_problems(&mut db)?;
    for (label, reasons) in &crls {
        failed += 1;
        eprintln!("FAIL CRL {label}: {reasons}");
    }
    if failed > 0 {
        eprintln!("{failed} problem(s) in the issued certificates, revocations or CRLs");
        return Ok(ExitCode::FAILURE);
    }
    println!(
        "PASS: {} certificate(s) issued for applications, {revoked} revocation(s) and {crl_count} CRL(s) verified independently",
        rows.len()
    );
    Ok(ExitCode::SUCCESS)
}
