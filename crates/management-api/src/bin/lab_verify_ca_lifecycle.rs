//! Laboratory audit tool: re-verifies the CA lifecycle records (migrations
//! 0025–0026, ADR-0013 and ADR-0014) independently of the API that recorded
//! them.
//!
//! For each registered issuer certificate it checks, with the same verifier
//! the API uses, that the stored DER is a self-signed P-256 root that was
//! valid when it was registered, and that the stored SPKI digest, common
//! name and validity are the certificate's own and match the proposal.
//!
//! For each CA decision it checks that the stored claim is the claim the
//! database rebuilds, that the key is the approver's registered CA key, and
//! that the signature verifies over the claim (reviewed `p256` verifier of
//! `trust-pki-crypto`). Approvals of one proposal must come from distinct
//! approvers and keys. Each activated CA must have two approvals, no
//! rejection, an activator who did not decide, and a `ca` row that matches
//! the proposal.
//!
//! PostgreSQL verifies neither X.509 nor ECDSA, so a compromised API or
//! writer login could record what the API would refuse; this tool is how
//! that is detected. Run it as the database owner:
//! `TRUST_VERIFY_DATABASE_URL=… cargo run -p trust-management-api --bin lab_verify_ca_lifecycle`
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    io,
    process::ExitCode,
    time::SystemTime,
};

use postgres::{Client, NoTls};

#[allow(dead_code)]
#[path = "../ca_certificate.rs"]
mod ca_certificate;

struct RecordedCertificate {
    ca_id: String,
    der: Vec<u8>,
    spki_sha256: Vec<u8>,
    subject_cn: String,
    not_before: SystemTime,
    not_after: SystemTime,
    registered_at: SystemTime,
    display_name: String,
}

fn certificate_problems(record: &RecordedCertificate) -> Vec<String> {
    let mut found = Vec::new();
    match ca_certificate::verify_lab_root(&record.der, record.registered_at) {
        Err(reason) => found.push(format!("stored certificate does not verify ({reason:?})")),
        Ok(root) => {
            if root.spki_sha256.as_slice() != record.spki_sha256.as_slice() {
                found.push("stored SPKI digest is not the certificate's".into());
            }
            if root.subject_cn != record.subject_cn || root.subject_cn != record.display_name {
                found.push("common name differs from the record or the proposal".into());
            }
            if root.not_before != record.not_before || root.not_after != record.not_after {
                found.push("stored validity is not the certificate's".into());
            }
        }
    }
    found
}

struct RecordedDecision {
    ca_id: String,
    decision: String,
    approver: String,
    public_key: Vec<u8>,
    claim: String,
    signature: Vec<u8>,
    key_registered: bool,
    claim_matches: bool,
}

fn decision_problems(decision: &RecordedDecision) -> Vec<&'static str> {
    let mut found = Vec::new();
    if !decision.claim_matches {
        found.push("stored claim differs from the rebuilt claim");
    }
    if !decision.key_registered {
        found.push("key is not the approver's registered CA key");
    }
    if trust_pki_crypto::canonical_p256_public_key_sec1(&decision.public_key).is_err()
        || trust_pki_crypto::verify_p256_ecdsa_sha256(
            &decision.public_key,
            decision.claim.as_bytes(),
            &decision.signature,
        )
        .is_err()
    {
        found.push("signature does not verify over the claim");
    }
    found
}

fn load_certificates(db: &mut Client) -> Result<Vec<RecordedCertificate>, postgres::Error> {
    Ok(db
        .query(
            "SELECT c.ca_id::text, c.certificate_der, c.spki_sha256, c.subject_cn, c.not_before, \
                    c.not_after, c.registered_at, p.display_name \
             FROM ca_issuer_certificate c JOIN ca_proposal p USING (ca_id) ORDER BY c.registered_at",
            &[],
        )?
        .into_iter()
        .map(|row| RecordedCertificate {
            ca_id: row.get(0),
            der: row.get(1),
            spki_sha256: row.get(2),
            subject_cn: row.get(3),
            not_before: row.get(4),
            not_after: row.get(5),
            registered_at: row.get(6),
            display_name: row.get(7),
        })
        .collect())
}

fn load_decisions(db: &mut Client) -> Result<Vec<RecordedDecision>, postgres::Error> {
    Ok(db
        .query(
            "SELECT d.ca_id::text, d.decision, d.approver_issuer || ' ' || d.approver_subject, \
                    d.public_key_sec1, d.claim, d.signature_der, \
                    k.issuer = d.approver_issuer AND k.subject = d.approver_subject \
                        AND k.public_key_sec1 = d.public_key_sec1, \
                    d.claim = ca_decision_claim(d.decision, d.ca_id, c.certificate_sha256, c.spki_sha256, \
                        c.registered_event_id, d.approver_issuer, d.approver_subject, d.key_id, \
                        d.claim_issued_at) \
             FROM ca_decision d \
             JOIN ca_issuer_certificate c USING (ca_id) \
             JOIN ca_approver_key k ON k.key_id = d.key_id \
             ORDER BY d.ca_id, d.decided_at",
            &[],
        )?
        .into_iter()
        .map(|row| RecordedDecision {
            ca_id: row.get(0),
            decision: row.get(1),
            approver: row.get(2),
            public_key: row.get(3),
            claim: row.get(4),
            signature: row.get(5),
            key_registered: row.get(6),
            claim_matches: row.get(7),
        })
        .collect())
}

/// Activated CAs whose records break the activation rules, with the reason.
fn activation_problems(db: &mut Client) -> Result<Vec<(String, String)>, postgres::Error> {
    Ok(db
        .query(
            "SELECT a.ca_id::text, concat_ws('; ', \
                 CASE WHEN (SELECT count(*) FROM ca_decision d WHERE d.ca_id = a.ca_id \
                            AND d.decision = 'approve') < 2 THEN 'fewer than two approvals' END, \
                 CASE WHEN EXISTS (SELECT 1 FROM ca_decision d WHERE d.ca_id = a.ca_id \
                            AND d.decision = 'reject') THEN 'a rejection was recorded' END, \
                 CASE WHEN EXISTS (SELECT 1 FROM ca_decision d WHERE d.ca_id = a.ca_id \
                            AND d.approver_issuer = e.actor_issuer \
                            AND d.approver_subject = e.actor_subject) \
                      THEN 'the activator decided on the proposal' END, \
                 CASE WHEN NOT EXISTS (SELECT 1 FROM ca c WHERE c.ca_id = a.ca_id \
                            AND c.display_name = p.display_name \
                            AND c.policy_version = p.policy_version) \
                      THEN 'the CA row does not match the proposal' END) \
             FROM ca_activation a \
             JOIN ca_lifecycle_event e ON e.event_id = a.event_id \
             JOIN ca_proposal p ON p.ca_id = a.ca_id",
            &[],
        )?
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
        .filter(|(_, reasons)| !reasons.is_empty())
        .collect())
}

fn main() -> Result<ExitCode, Box<dyn Error>> {
    let url = env::var("TRUST_VERIFY_DATABASE_URL")
        .map_err(|_| io::Error::other("set TRUST_VERIFY_DATABASE_URL to a lab database"))?;
    let mut db = Client::connect(&url, NoTls)
        .map_err(|_| io::Error::other("CA lifecycle database unavailable"))?;
    let mut failed = 0usize;
    let certificates = load_certificates(&mut db)?;
    for record in &certificates {
        let found = certificate_problems(record);
        if !found.is_empty() {
            failed += 1;
            eprintln!("FAIL certificate of {}: {}", record.ca_id, found.join("; "));
        }
    }
    let decisions = load_decisions(&mut db)?;
    let mut approvals: BTreeMap<&str, Vec<&RecordedDecision>> = BTreeMap::new();
    for decision in &decisions {
        let found = decision_problems(decision);
        if !found.is_empty() {
            failed += 1;
            eprintln!(
                "FAIL {} {} by {}: {}",
                decision.ca_id,
                decision.decision,
                decision.approver,
                found.join("; ")
            );
        }
        if decision.decision == "approve" {
            approvals.entry(&decision.ca_id).or_default().push(decision);
        }
    }
    for (ca_id, list) in &approvals {
        let approvers: BTreeSet<&str> = list.iter().map(|d| d.approver.as_str()).collect();
        let points: BTreeSet<Vec<u8>> = list
            .iter()
            .map(|d| {
                trust_pki_crypto::canonical_p256_public_key_sec1(&d.public_key).unwrap_or_default()
            })
            .collect();
        if approvers.len() != list.len() || points.len() != list.len() {
            failed += 1;
            eprintln!("FAIL {ca_id}: approvals share an approver or a key");
        }
    }
    let activations = activation_problems(&mut db)?;
    for (ca_id, reasons) in &activations {
        failed += 1;
        eprintln!("FAIL activation of {ca_id}: {reasons}");
    }
    if failed > 0 {
        eprintln!("{failed} problem(s) in the CA lifecycle records");
        return Ok(ExitCode::FAILURE);
    }
    let activated: i64 = db
        .query_one("SELECT count(*) FROM ca_activation", &[])?
        .get(0);
    println!(
        "PASS: {} issuer certificate(s), {} CA decision(s) and {} activation(s) verified independently",
        certificates.len(),
        decisions.len(),
        activated
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use x509_cert::{der::Encode, Certificate};

    fn record(der: Vec<u8>) -> RecordedCertificate {
        let certificate = <Certificate as x509_cert::der::Decode>::from_der(&der).unwrap();
        let spki = certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let validity = &certificate.tbs_certificate.validity;
        RecordedCertificate {
            ca_id: "test".into(),
            spki_sha256: Sha256::digest(spki).to_vec(),
            subject_cn: "Trust Lab OpenSSL Root".into(),
            not_before: validity.not_before.to_system_time(),
            not_after: validity.not_after.to_system_time(),
            registered_at: validity.not_before.to_system_time(),
            display_name: "Trust Lab OpenSSL Root".into(),
            der,
        }
    }

    fn vector() -> Vec<u8> {
        let pem = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/ca-root/openssl-p256-root.crt"
        ))
        .unwrap();
        ca_certificate::certificate_der_from_pem(&pem).unwrap()
    }

    #[test]
    fn a_faithful_record_passes_and_each_divergence_fails() {
        assert!(certificate_problems(&record(vector())).is_empty());
        let mut other_name = record(vector());
        other_name.display_name = "Another Root".into();
        assert_eq!(certificate_problems(&other_name).len(), 1);
        let mut other_key = record(vector());
        other_key.spki_sha256 = vec![0; 32];
        assert_eq!(certificate_problems(&other_key).len(), 1);
        let mut tampered = record(vector());
        let last = tampered.der.len() - 1;
        tampered.der[last] ^= 1;
        assert_eq!(certificate_problems(&tampered).len(), 1);
        let mut late = record(vector());
        late.registered_at = late.not_after;
        assert_eq!(certificate_problems(&late).len(), 1);
    }
}
