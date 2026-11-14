//! Laboratory audit tool: re-verifies every certificate issued for a
//! certificate application (migration 0030, ADR-0017) independently of the
//! API and of the lab signer that produced it.
//!
//! For each issued application it checks, with the reviewed `pki-core`
//! verifier, that the stored certificate is the server leaf the application
//! describes: signed by the CA's registered issuer certificate, for the
//! subject key of the stored CSR (whose proof-of-possession is re-verified),
//! with the application's common name and DNS names, the reserved serial and
//! the profile's extensions, including the CRL distribution point
//! snapshotted with the signing intent (migration 0032). It also checks that the stored fingerprint is
//! the certificate's, that the signing intent journaled the digest of this
//! very TBS and was claimed exactly once by the signer, and that the
//! application was approved by a registration officer.
//!
//! For each core revocation of such a certificate (migration 0031, ADR-0018)
//! it checks that an approved revocation request carries the same reason,
//! and that a registration officer other than the one who asked approved
//! it. For each published CRL it rebuilds the CRL from the database's own
//! entries, number and instants, and verifies the stored DER against the
//! issuer certificate's key; it checks the stored digests and exactly one
//! signer claim.
//!
//! For each request a registered RA system signed (migration 0038, ADR-0025)
//! it rebuilds the signed bytes from the application itself (CA, profile, CSR
//! digest, names, validity) and the request's identifiers, checks that they
//! are the stored bytes, and verifies the RA's signature with the RA's
//! registered key. It also checks that the application was submitted and
//! approved by that RA.
//!
//! Since migration 0041 (ADR-0028) every issuance needs a signed
//! authorization: an RA request (version 1, or version 2 with the subject and
//! optional extensions), or a registration officer's signed approval. For each
//! officer decision it rebuilds the claim from the application, checks it is
//! the stored claim, and verifies the signature with the officer's registered
//! key. A certificate whose signing intent was recorded after 0041 without such
//! a proof is reported. The certificate's subject is the authorized one, so the
//! stored CSR is checked for proof of possession only.
//!
//! Since migration 0042 (ADR-0029), every revocation or confirmed void
//! recorded after the proof requirement carries a signed proof: an RA's signed
//! revocation, or an officer's signed revocation approval or void
//! confirmation. For each officer proof the tool rebuilds the claim from the
//! request or void, and checks the registered key's signature, the decision,
//! the grant and the actor; it reports an entry recorded since then without
//! a proof.
//!
//! PostgreSQL verifies neither X.509 nor ECDSA, so a compromised API or
//! writer login could store what the API would refuse; this tool is how that
//! is detected. Run it as the database owner:
//! `TRUST_VERIFY_DATABASE_URL=… cargo run -p trust-management-api --bin lab_verify_issued_certificates`
use std::{env, error::Error, io, process::ExitCode, time::SystemTime};

use postgres::Client;
use sha2::{Digest, Sha256};
use trust_pki_core::{
    application_crl::{build_crl_tbs, parse_utc_seconds, verify_crl, CrlEntry, CrlFacts},
    application_leaf::{optional_extensions_valid, verify_server_leaf, LeafFacts},
    authorization::{
        officer_decision_claim, revocation_decision_claim, void_confirmation_claim,
        OfficerDecision, RevocationDecision, VoidConfirmation,
    },
    csr::verify_pkcs10_p256_possession,
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
    extensions: Vec<String>,
    /// False for an issuance after migration 0041 with no signed proof.
    proven: bool,
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
    if !record.proven {
        found.push("no signed authorization (RA request or officer approval)".into());
    }
    if !optional_extensions_valid(&record.extensions) {
        found.push("optional extensions outside the catalogue".into());
    }
    let issuer = match Certificate::from_der(&record.issuer_der) {
        Ok(issuer) => issuer,
        Err(_) => {
            found.push("issuer certificate does not decode".into());
            return found;
        }
    };
    let csr = match verify_pkcs10_p256_possession(&record.csr_der) {
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
        client_auth: record.extensions.iter().any(|e| e == "client-auth"),
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
    // A revocation an RA signed (migration 0039) is requested and approved
    // by that RA; ra_revocation_problems verifies its signature. Every other
    // revocation needs an officer other than the requester.
    let ra_signed = if db
        .query_one(
            "SELECT to_regclass('public.ra_revocation_request') IS NOT NULL",
            &[],
        )?
        .get::<_, bool>(0)
    {
        "EXISTS (SELECT 1 FROM ra_revocation_request rr WHERE rr.revocation_id = q.revocation_id \
         AND de.actor_issuer = 'urn:trust-platform:ra' AND de.actor_subject = rr.ra_id)"
    } else {
        "false"
    };
    Ok(db
        .query(
            &format!("SELECT encode(r.serial_der_content, 'hex'), concat_ws('; ', \
                 CASE WHEN q.revocation_id IS NULL THEN 'no approved revocation request' END, \
                 CASE WHEN q.reason_code <> r.reason_code THEN 'reason differs from the request' END, \
                 CASE WHEN qe.actor_issuer = de.actor_issuer AND qe.actor_subject = de.actor_subject \
                      AND NOT {ra_signed} THEN 'approved by its requester' END, \
                 CASE WHEN de.event_id IS NOT NULL AND NOT {ra_signed} AND NOT EXISTS (SELECT 1 FROM management_role_grant g \
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
             LEFT JOIN certificate_application_event de ON de.event_id = dd.decided_event_id"),
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

/// Every RA-signed request: the stored bytes are the application's, and the
/// RA's registered key signed them.
fn ra_request_problems(db: &mut Client) -> Result<(usize, Vec<(String, String)>), postgres::Error> {
    if !db
        .query_one(
            "SELECT to_regclass('public.ra_issuance_request') IS NOT NULL",
            &[],
        )?
        .get::<_, bool>(0)
    {
        return Ok((0, Vec::new()));
    }
    // Version 2 requests (migration 0041) also sign the subject and options.
    let v2 = db
        .query_one(
            "SELECT to_regclass('public.certificate_application_option') IS NOT NULL",
            &[],
        )?
        .get::<_, bool>(0);
    let (version, subject, extensions) = if v2 {
        (
            "r.message_version",
            "a.subject_cn",
            "certificate_application_extensions(a.application_id)",
        )
    } else {
        ("1::smallint", "a.subject_cn", "'{}'::text[]")
    };
    let rows = db.query(
        &format!("SELECT r.ra_id, uuid_send(r.request_id), uuid_send(a.ca_id), a.profile_id, a.csr_der, \
                a.dns_names, a.validity_days, extract(epoch FROM r.signed_at)::bigint, r.message, \
                r.signature, s.public_key_sec1, a.application_id::text, \
                (SELECT array_agg(e.action || '|' || e.actor_issuer || '|' || e.actor_subject ORDER BY e.action) \
                 FROM certificate_application_event e \
                 WHERE e.application_id = a.application_id \
                   AND e.action IN ('application.submitted', 'application.approved')), \
                {version}, {subject}, {extensions} \
         FROM ra_issuance_request r \
         JOIN certificate_application a ON a.application_id = r.application_id AND a.ca_id = r.ca_id \
         JOIN ra_system s ON s.ra_id = r.ra_id \
         ORDER BY r.recorded_at"),
        &[],
    )?;
    let mut problems = Vec::new();
    for row in &rows {
        let ra_id: String = row.get(0);
        let application: String = row.get(11);
        let mut reasons = Vec::new();
        let ids = (
            <[u8; 16]>::try_from(row.get::<_, Vec<u8>>(1).as_slice()).ok(),
            <[u8; 16]>::try_from(row.get::<_, Vec<u8>>(2).as_slice()).ok(),
        );
        let (Some(request_id), Some(ca_id)) = ids else {
            problems.push((application, "malformed identifiers".to_owned()));
            continue;
        };
        let dns_names: Vec<String> = row.get(5);
        let validity: i32 = row.get(6);
        let profile_id: String = row.get(3);
        let base = trust_pki_core::ra_request::RaIssuanceRequest {
            ra_id: &ra_id,
            ca_id,
            profile_id: &profile_id,
            request_id,
            csr_sha256: Sha256::digest(row.get::<_, Vec<u8>>(4)).into(),
            dns_names: &dns_names,
            validity_days: u32::try_from(validity).unwrap_or(0),
            signed_at_unix: row.get(7),
        };
        let subject_cn: String = row.get(14);
        let extensions: Vec<String> = row.get(15);
        let rebuilt = match row.get::<_, i16>(13) {
            // Version 1 binds neither the subject nor an extension.
            1 => {
                if dns_names.first() != Some(&subject_cn) || !extensions.is_empty() {
                    reasons
                        .push("a version 1 request with a subject or extension it does not sign");
                }
                trust_pki_core::ra_request::ra_issuance_message(&base)
            }
            _ => trust_pki_core::ra_request::ra_issuance_message_v2(
                &trust_pki_core::ra_request::RaIssuanceRequestV2 {
                    base,
                    subject_cn: &subject_cn,
                    extensions: &extensions,
                },
            ),
        };
        let message: Vec<u8> = row.get(8);
        if rebuilt.as_deref().ok() != Some(message.as_slice()) {
            reasons.push("the stored bytes are not the application's");
        }
        let signature: Vec<u8> = row.get(9);
        let key: Vec<u8> = row.get(10);
        if trust_pki_crypto::verify_p256_ecdsa_sha256(&key, &message, &signature).is_err() {
            reasons.push("the RA's key did not sign the stored bytes");
        }
        let expected = vec![
            format!("application.approved|urn:trust-platform:ra|{ra_id}"),
            format!("application.submitted|urn:trust-platform:ra|{ra_id}"),
        ];
        if row.get::<_, Option<Vec<String>>>(12) != Some(expected) {
            reasons.push("not submitted and approved by that RA");
        }
        if !reasons.is_empty() {
            problems.push((application, reasons.join("; ")));
        }
    }
    Ok((rows.len(), problems))
}

/// Every RA-signed revocation (migration 0039): the stored bytes are the
/// revocation's, the RA's key signed them, and the RA obtained the
/// certificate through the channel.
fn ra_revocation_problems(
    db: &mut Client,
) -> Result<(usize, Vec<(String, String)>), postgres::Error> {
    if !db
        .query_one(
            "SELECT to_regclass('public.ra_revocation_request') IS NOT NULL",
            &[],
        )?
        .get::<_, bool>(0)
    {
        return Ok((0, Vec::new()));
    }
    let rows = db.query(
        "SELECT rr.ra_id, uuid_send(rr.request_id), uuid_send(rr.ca_id), q.serial_der_content, q.reason_code, \
                q.reason, extract(epoch FROM rr.signed_at)::bigint, rr.message, rr.signature, s.public_key_sec1, \
                encode(q.serial_der_content, 'hex'), \
                EXISTS (SELECT 1 FROM ra_issuance_request ri WHERE ri.ra_id = rr.ra_id \
                        AND ri.application_id = q.application_id) \
         FROM ra_revocation_request rr \
         JOIN certificate_revocation_request q ON q.revocation_id = rr.revocation_id \
         JOIN ra_system s ON s.ra_id = rr.ra_id \
         ORDER BY rr.recorded_at",
        &[],
    )?;
    let mut problems = Vec::new();
    for row in &rows {
        let serial_hex: String = row.get(10);
        let ids = (
            <[u8; 16]>::try_from(row.get::<_, Vec<u8>>(1).as_slice()).ok(),
            <[u8; 16]>::try_from(row.get::<_, Vec<u8>>(2).as_slice()).ok(),
        );
        let (Some(request_id), Some(ca_id)) = ids else {
            problems.push((serial_hex, "malformed identifiers".to_owned()));
            continue;
        };
        let ra_id: String = row.get(0);
        let serial: Vec<u8> = row.get(3);
        let reason_code: i16 = row.get(4);
        let reason: String = row.get(5);
        let rebuilt = trust_pki_core::ra_request::ra_revocation_message(
            &trust_pki_core::ra_request::RaRevocationRequest {
                ra_id: &ra_id,
                ca_id,
                request_id,
                serial: &serial,
                reason_code: u16::try_from(reason_code).unwrap_or(u16::MAX),
                reason: &reason,
                signed_at_unix: row.get(6),
            },
        );
        let message: Vec<u8> = row.get(7);
        let mut reasons = Vec::new();
        if rebuilt.as_deref().ok() != Some(message.as_slice()) {
            reasons.push("the stored bytes are not the revocation's");
        }
        let signature: Vec<u8> = row.get(8);
        let key: Vec<u8> = row.get(9);
        if trust_pki_crypto::verify_p256_ecdsa_sha256(&key, &message, &signature).is_err() {
            reasons.push("the RA's key did not sign the stored bytes");
        }
        if !row.get::<_, bool>(11) {
            reasons.push("the RA did not obtain this certificate");
        }
        if !reasons.is_empty() {
            problems.push((serial_hex, reasons.join("; ")));
        }
    }
    Ok((rows.len(), problems))
}

/// Every officer's signed decision (migration 0041): the stored claim is the
/// application's, and the officer's registered key signed it.
fn officer_decision_problems(
    db: &mut Client,
) -> Result<(usize, Vec<(String, String)>), postgres::Error> {
    if !proofs_schema(db)? {
        return Ok((0, Vec::new()));
    }
    let rows = db.query(
        "SELECT z.application_id::text, z.decision, a.ca_id::text, a.profile_id, a.revision, a.csr_der, \
                a.subject_cn, a.dns_names, a.validity_days, certificate_application_extensions(a.application_id), \
                z.key_id, to_char(z.claim_issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                z.claim, z.signature_der, z.public_key_sec1, k.public_key_sec1, \
                d.decision, \
                EXISTS (SELECT 1 FROM management_role_grant g WHERE g.issuer = k.issuer \
                        AND g.subject = k.subject AND g.ca_id = a.ca_id \
                        AND g.lifecycle_role = 'registration-officer'), \
                e.actor_issuer = k.issuer AND e.actor_subject = k.subject \
         FROM certificate_application_authorization z \
         JOIN certificate_application a ON a.application_id = z.application_id \
         JOIN registration_officer_key k ON k.key_id = z.key_id \
         JOIN certificate_application_event e ON e.event_id = z.event_id \
         LEFT JOIN certificate_application_decision d ON d.application_id = z.application_id \
         ORDER BY z.claim_issued_at",
        &[],
    )?;
    let mut problems = Vec::new();
    for row in &rows {
        let application: String = row.get(0);
        let decision: String = row.get(1);
        let ca_id: String = row.get(2);
        let profile_id: String = row.get(3);
        let dns_names: Vec<String> = row.get(7);
        let extensions: Vec<String> = row.get(9);
        let key_id: String = row.get(10);
        let issued_at: String = row.get(11);
        let subject_cn: String = row.get(6);
        let csr_sha256: [u8; 32] = Sha256::digest(row.get::<_, Vec<u8>>(5)).into();
        let claim: String = row.get(12);
        let mut reasons = Vec::new();
        let rebuilt = officer_decision_claim(&OfficerDecision {
            decision: &decision,
            ca_id: &ca_id,
            application_id: &application,
            profile_id: &profile_id,
            revision: row.get(4),
            csr_sha256: &csr_sha256,
            subject_cn: &subject_cn,
            dns_names: &dns_names,
            validity_days: row.get(8),
            extensions: &extensions,
            key_id: &key_id,
            issued_at: &issued_at,
        });
        if rebuilt.as_deref().ok() != Some(claim.as_str()) {
            reasons.push("the stored claim is not the application's");
        }
        let stored_key: Vec<u8> = row.get(14);
        let registered_key: Vec<u8> = row.get(15);
        if stored_key != registered_key {
            reasons.push("the recorded key is not the officer's registered key");
        }
        let signature: Vec<u8> = row.get(13);
        if trust_pki_crypto::verify_p256_ecdsa_sha256(&registered_key, claim.as_bytes(), &signature)
            .is_err()
        {
            reasons.push("the officer's key did not sign the claim");
        }
        if row.get::<_, Option<String>>(16).as_deref() != Some(decision.as_str()) {
            reasons.push("the recorded decision is not the signed one");
        }
        if !row.get::<_, bool>(17) {
            reasons.push("the key's officer holds no registration-officer grant");
        }
        if !row.get::<_, bool>(18) {
            reasons.push("the decision event is not the key's officer");
        }
        if !reasons.is_empty() {
            problems.push((application, reasons.join("; ")));
        }
    }
    Ok((rows.len(), problems))
}

/// Signed revocation decisions and void confirmations (migration 0042), and
/// CRL entries recorded since the requirement without a proof.
fn revocation_proof_problems(
    db: &mut Client,
) -> Result<(usize, Vec<(String, String)>), postgres::Error> {
    if !db
        .query_one(
            "SELECT to_regclass('public.certificate_revocation_authorization') IS NOT NULL",
            &[],
        )?
        .get::<_, bool>(0)
    {
        return Ok((0, Vec::new()));
    }
    let instant =
        "to_char(z.claim_issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')";
    let checks = "z.public_key_sec1 = k.public_key_sec1, \
                  EXISTS (SELECT 1 FROM management_role_grant g WHERE g.issuer = k.issuer \
                          AND g.subject = k.subject AND g.ca_id = e.ca_id \
                          AND g.lifecycle_role = 'registration-officer'), \
                  e.actor_issuer = k.issuer AND e.actor_subject = k.subject";
    let mut problems = Vec::new();
    let revocations = db.query(
        &format!(
            "SELECT q.revocation_id::text, z.decision, q.ca_id::text, q.application_id::text, \
                    q.serial_der_content, q.reason_code, z.key_id, {instant}, z.claim, z.signature_der, \
                    k.public_key_sec1, d.decision, {checks} \
             FROM certificate_revocation_authorization z \
             JOIN certificate_revocation_request q ON q.revocation_id = z.revocation_id \
             JOIN registration_officer_key k ON k.key_id = z.key_id \
             JOIN certificate_application_event e ON e.event_id = z.event_id \
             LEFT JOIN certificate_revocation_decision d ON d.revocation_id = z.revocation_id"
        ),
        &[],
    )?;
    for row in &revocations {
        let id: String = row.get(0);
        let decision: String = row.get(1);
        let (ca_id, application_id): (String, String) = (row.get(2), row.get(3));
        let serial: Vec<u8> = row.get(4);
        let (key_id, issued_at, claim): (String, String, String) =
            (row.get(6), row.get(7), row.get(8));
        let rebuilt = revocation_decision_claim(&RevocationDecision {
            decision: &decision,
            ca_id: &ca_id,
            application_id: &application_id,
            revocation_id: &id,
            serial: &serial,
            reason_code: row.get(5),
            key_id: &key_id,
            issued_at: &issued_at,
        });
        let mut reasons = officer_proof_reasons(
            rebuilt.as_deref().ok() == Some(claim.as_str()),
            &row.get::<_, Vec<u8>>(10),
            &claim,
            &row.get::<_, Vec<u8>>(9),
            [row.get(12), row.get(13), row.get(14)],
        );
        if row.get::<_, Option<String>>(11).as_deref() != Some(decision.as_str()) {
            reasons.push("the recorded decision is not the signed one");
        }
        if !reasons.is_empty() {
            problems.push((format!("revocation {id}"), reasons.join("; ")));
        }
    }
    let voids = db.query(
        &format!(
            "SELECT v.application_id::text, v.ca_id::text, v.serial_der_content, v.signer_claimed, \
                    z.key_id, {instant}, z.claim, z.signature_der, k.public_key_sec1, \
                    v.confirmed_event_id = z.event_id, {checks} \
             FROM certificate_void_authorization z \
             JOIN certificate_application_void v ON v.application_id = z.application_id \
             JOIN registration_officer_key k ON k.key_id = z.key_id \
             JOIN certificate_application_event e ON e.event_id = z.event_id"
        ),
        &[],
    )?;
    for row in &voids {
        let (application_id, ca_id): (String, String) = (row.get(0), row.get(1));
        let serial: Vec<u8> = row.get(2);
        let (key_id, issued_at, claim): (String, String, String) =
            (row.get(4), row.get(5), row.get(6));
        let rebuilt = void_confirmation_claim(&VoidConfirmation {
            ca_id: &ca_id,
            application_id: &application_id,
            serial: &serial,
            signer_claimed: row.get(3),
            key_id: &key_id,
            issued_at: &issued_at,
        });
        let mut reasons = officer_proof_reasons(
            rebuilt.as_deref().ok() == Some(claim.as_str()),
            &row.get::<_, Vec<u8>>(8),
            &claim,
            &row.get::<_, Vec<u8>>(7),
            [row.get(10), row.get(11), row.get(12)],
        );
        if !row.get::<_, bool>(9) {
            reasons.push("the confirmation event is not the signed one");
        }
        if !reasons.is_empty() {
            problems.push((
                format!("void of application {application_id}"),
                reasons.join("; "),
            ));
        }
    }
    // Entries recorded since the requirement need a proof.
    for row in db.query(
        "SELECT 'revocation of serial ' || encode(r.serial_der_content, 'hex') \
         FROM revocation r CROSS JOIN crl_entry_proof_policy p \
         JOIN certificate c ON c.ca_id = r.ca_id AND c.serial_der_content = r.serial_der_content \
         JOIN certificate_application_issuance i ON i.ca_id = c.ca_id AND i.request_id = c.request_id \
         WHERE r.revoked_at >= p.required_since AND NOT EXISTS ( \
             SELECT 1 FROM certificate_revocation_request q \
             JOIN certificate_revocation_decision d ON d.revocation_id = q.revocation_id AND d.decision = 'approve' \
             WHERE q.ca_id = r.ca_id AND q.serial_der_content = r.serial_der_content \
               AND (EXISTS (SELECT 1 FROM ra_revocation_request rr WHERE rr.revocation_id = q.revocation_id) \
                    OR EXISTS (SELECT 1 FROM certificate_revocation_authorization z \
                               WHERE z.revocation_id = q.revocation_id AND z.decision = 'approve'))) \
         UNION ALL \
         SELECT 'void of application ' || v.application_id::text \
         FROM certificate_application_void v CROSS JOIN crl_entry_proof_policy p \
         WHERE v.voided_at >= p.required_since \
           AND NOT EXISTS (SELECT 1 FROM certificate_void_authorization z WHERE z.application_id = v.application_id)",
        &[],
    )? {
        problems.push((row.get(0), "no signed proof (ADR-0029)".to_owned()));
    }
    Ok((revocations.len() + voids.len(), problems))
}

/// The common checks of an officer's signed claim.
fn officer_proof_reasons(
    claim_is_rebuilt: bool,
    registered_key: &[u8],
    claim: &str,
    signature: &[u8],
    [same_key, granted, actor]: [bool; 3],
) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if !claim_is_rebuilt {
        reasons.push("the stored claim is not the record's");
    }
    if !same_key {
        reasons.push("the recorded key is not the officer's registered key");
    }
    if trust_pki_crypto::verify_p256_ecdsa_sha256(registered_key, claim.as_bytes(), signature)
        .is_err()
    {
        reasons.push("the officer's key did not sign the claim");
    }
    if !granted {
        reasons.push("the key's officer holds no registration-officer grant");
    }
    if !actor {
        reasons.push("the decision event is not the key's officer");
    }
    reasons
}

fn proofs_schema(db: &mut Client) -> Result<bool, postgres::Error> {
    Ok(db
        .query_one(
            "SELECT to_regclass('public.certificate_application_authorization') IS NOT NULL",
            &[],
        )?
        .get(0))
}

fn main() -> Result<ExitCode, Box<dyn Error>> {
    let url = env::var("TRUST_VERIFY_DATABASE_URL")
        .map_err(|_| io::Error::other("set TRUST_VERIFY_DATABASE_URL to a lab database"))?;
    let mut db = trust_db_connect::connect(&url)
        .map_err(|_| io::Error::other("issuance database unavailable"))?;
    // Since 0041 an issuance needs a signed proof. Intents recorded before it
    // was applied (per the runner's ledger) had none to give.
    let ledger: bool = db
        .query_one(
            "SELECT to_regclass('public.management_migration_ledger') IS NOT NULL",
            &[],
        )?
        .get(0);
    let before_proofs = if ledger {
        "s.created_at < coalesce((SELECT applied_at FROM management_migration_ledger \
         WHERE version = '0041_signer_authorization_proofs'), '-infinity')"
    } else {
        "false"
    };
    let (extensions, proven) = if proofs_schema(&mut db)? {
        (
            "certificate_application_extensions(a.application_id)".to_owned(),
            format!(
                "EXISTS (SELECT 1 FROM ra_issuance_request q WHERE q.application_id = a.application_id) \
                 OR EXISTS (SELECT 1 FROM certificate_application_authorization z \
                            WHERE z.application_id = a.application_id AND z.decision = 'approve') \
                 OR {before_proofs}"
            ),
        )
    } else {
        ("'{}'::text[]".to_owned(), "true".to_owned())
    };
    let rows = db.query(
        &format!("SELECT i.application_id::text, a.csr_der, a.subject_cn, a.dns_names, a.validity_days, \
                c.serial_der_content, c.certificate_der, c.fingerprint_sha256, c.signed_at, \
                k.certificate_der, s.tbs_sha256, s.outcome, \
                (SELECT count(*) FROM lab_signer_claim l WHERE l.intent_id = s.intent_id), \
                d.decision, dp.url, {extensions}, {proven} \
           FROM certificate_application_issuance i \
           JOIN certificate_application a ON a.application_id = i.application_id \
           JOIN certificate c ON c.ca_id = i.ca_id AND c.request_id = i.request_id \
           JOIN ca_issuer_certificate k ON k.ca_id = i.ca_id \
           LEFT JOIN signing_intent s ON s.ca_id = i.ca_id AND s.request_id = i.request_id \
           LEFT JOIN certificate_application_decision d ON d.application_id = i.application_id \
           LEFT JOIN signing_intent_crl_distribution_point dp ON dp.intent_id = s.intent_id \
          ORDER BY i.started_at"),
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
            extensions: row.get(15),
            proven: row.get::<_, Option<bool>>(16).unwrap_or(false),
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
    let (ra_revocations, ra_revocation_failures) = ra_revocation_problems(&mut db)?;
    for (serial, reasons) in &ra_revocation_failures {
        failed += 1;
        eprintln!("FAIL RA revocation of serial {serial}: {reasons}");
    }
    let (ra_count, ra_requests) = ra_request_problems(&mut db)?;
    for (application, reasons) in &ra_requests {
        failed += 1;
        eprintln!("FAIL RA request for application {application}: {reasons}");
    }
    let (officer_count, officer_decisions) = officer_decision_problems(&mut db)?;
    for (application, reasons) in &officer_decisions {
        failed += 1;
        eprintln!("FAIL officer decision on application {application}: {reasons}");
    }
    let (revocation_proof_count, revocation_proofs) = revocation_proof_problems(&mut db)?;
    for (label, reasons) in &revocation_proofs {
        failed += 1;
        eprintln!("FAIL {label}: {reasons}");
    }
    if failed > 0 {
        eprintln!("{failed} problem(s) in the issued certificates, revocations or CRLs");
        return Ok(ExitCode::FAILURE);
    }
    println!(
        "PASS: {} certificate(s) issued for applications, {revoked} revocation(s), {crl_count} CRL(s), {ra_count} RA-signed request(s), {officer_count} signed officer decision(s), {revocation_proof_count} signed revocation or void decision(s) and {ra_revocations} RA-signed revocation(s) verified independently",
        rows.len()
    );
    Ok(ExitCode::SUCCESS)
}
