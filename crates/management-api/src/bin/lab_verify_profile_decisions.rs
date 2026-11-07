//! Laboratory audit tool: re-verifies every recorded profile decision
//! (migration 0023, ADR-0011) independently of the API that recorded it.
//!
//! For each decision it checks that:
//! * the stored claim is the claim the database's own function rebuilds from
//!   the submission, approver, key and issue time;
//! * the submission digest still equals the revision's recomputed digest;
//! * the key used is the one registered to that approver;
//! * the signature verifies over the claim with that key (reviewed `p256`
//!   verifier from `trust-pki-crypto`);
//! * the approvals of each revision come from distinct approvers and keys.
//!
//! PostgreSQL does not verify ECDSA, so a compromised API or writer login
//! could record an unsigned decision; this tool is how that is detected. Run
//! it as the database owner (it reads the owner-only tables):
//! `TRUST_VERIFY_DATABASE_URL=… cargo run -p trust-management-api --bin lab_verify_profile_decisions`
use std::{collections::BTreeMap, env, error::Error, io, process::ExitCode};

use postgres::{Client, NoTls};

#[derive(Debug)]
struct RecordedDecision {
    revision: String,
    decision: String,
    approver: String,
    public_key: Vec<u8>,
    registered_key: Vec<u8>,
    claim: String,
    signature: Vec<u8>,
    key_owner_matches: bool,
    claim_matches: bool,
    digest_matches: bool,
}

/// The reasons a decision fails verification; empty when it passes.
fn problems(decision: &RecordedDecision) -> Vec<&'static str> {
    let mut found = Vec::new();
    if !decision.claim_matches {
        found.push("stored claim differs from the rebuilt claim");
    }
    if !decision.digest_matches {
        found.push("submission digest differs from the revision digest");
    }
    if !decision.key_owner_matches || decision.public_key != decision.registered_key {
        found.push("key is not the approver's registered key");
    }
    let point = trust_pki_crypto::canonical_p256_public_key_sec1(&decision.public_key);
    if point.is_err()
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

/// Approvals of one revision must come from distinct approvers and keys
/// (compared as canonical curve points).
fn approvals_are_distinct(approvals: &[&RecordedDecision]) -> bool {
    let mut approvers = std::collections::BTreeSet::new();
    let mut points = std::collections::BTreeSet::new();
    approvals.iter().all(|decision| {
        let point = trust_pki_crypto::canonical_p256_public_key_sec1(&decision.public_key)
            .unwrap_or_default();
        approvers.insert(decision.approver.clone()) && points.insert(point)
    })
}

fn load(db: &mut Client) -> Result<Vec<RecordedDecision>, postgres::Error> {
    Ok(db
        .query(
            "SELECT x.ca_id::text || '/' || x.profile_id || '/' || x.revision, x.decision, \
                    x.approver_issuer || ' ' || x.approver_subject, x.public_key_sec1, k.public_key_sec1, \
                    x.claim, x.signature_der, \
                    k.issuer = x.approver_issuer AND k.subject = x.approver_subject, \
                    x.claim = profile_decision_claim(x.decision, x.ca_id, x.profile_id, x.revision, \
                        s.snapshot_sha256, s.event_id, x.approver_issuer, x.approver_subject, x.key_id, \
                        x.claim_issued_at), \
                    s.snapshot_sha256 = profile_draft_snapshot_sha256(x.ca_id, x.profile_id, x.revision) \
             FROM certificate_profile_decision x \
             JOIN certificate_profile_submission s USING (ca_id, profile_id, revision) \
             JOIN profile_approver_key k ON k.key_id = x.key_id \
             ORDER BY x.ca_id, x.profile_id, x.revision, x.decided_at",
            &[],
        )?
        .into_iter()
        .map(|row| RecordedDecision {
            revision: row.get(0),
            decision: row.get(1),
            approver: row.get(2),
            public_key: row.get(3),
            registered_key: row.get(4),
            claim: row.get(5),
            signature: row.get(6),
            key_owner_matches: row.get(7),
            claim_matches: row.get(8),
            digest_matches: row.get(9),
        })
        .collect())
}

fn main() -> Result<ExitCode, Box<dyn Error>> {
    let url = env::var("TRUST_VERIFY_DATABASE_URL")
        .map_err(|_| io::Error::other("set TRUST_VERIFY_DATABASE_URL to a lab database"))?;
    let mut db = Client::connect(&url, NoTls)
        .map_err(|_| io::Error::other("profile decision database unavailable"))?;
    let decisions = load(&mut db)?;
    let mut failed = 0usize;
    let mut by_revision: BTreeMap<&str, Vec<&RecordedDecision>> = BTreeMap::new();
    for decision in &decisions {
        let found = problems(decision);
        if !found.is_empty() {
            failed += 1;
            eprintln!(
                "FAIL {} {} by {}: {}",
                decision.revision,
                decision.decision,
                decision.approver,
                found.join("; ")
            );
        }
        if decision.decision == "approve" {
            by_revision
                .entry(&decision.revision)
                .or_default()
                .push(decision);
        }
    }
    for (revision, approvals) in &by_revision {
        if !approvals_are_distinct(approvals) {
            failed += 1;
            eprintln!("FAIL {revision}: approvals share an approver or a key");
        }
    }
    if failed > 0 {
        eprintln!("{failed} problem(s) in {} decision(s)", decisions.len());
        return Ok(ExitCode::FAILURE);
    }
    println!(
        "PASS: {} profile decision(s) on {} approved or pending revision(s) verified independently",
        decisions.len(),
        by_revision.len()
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn decision(key: &SigningKey, approver: &str, claim: &str) -> RecordedDecision {
        let public = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let signature: Signature = key.sign(claim.as_bytes());
        RecordedDecision {
            revision: "ca/profile/1".into(),
            decision: "approve".into(),
            approver: approver.into(),
            registered_key: public.clone(),
            public_key: public,
            claim: claim.into(),
            signature: signature.to_der().as_bytes().to_vec(),
            key_owner_matches: true,
            claim_matches: true,
            digest_matches: true,
        }
    }

    #[test]
    fn each_tampering_is_reported() {
        let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let other = SigningKey::from_slice(&[0x22; 32]).unwrap();
        assert!(problems(&decision(&key, "a", "claim")).is_empty());
        let mut altered = decision(&key, "a", "claim");
        altered.claim = "claim with other text".into();
        assert_eq!(
            problems(&altered),
            ["signature does not verify over the claim"]
        );
        let mut swapped = decision(&key, "a", "claim");
        swapped.registered_key = decision(&other, "a", "claim").public_key;
        assert_eq!(
            problems(&swapped),
            ["key is not the approver's registered key"]
        );
        let mut rebuilt = decision(&key, "a", "claim");
        rebuilt.claim_matches = false;
        rebuilt.digest_matches = false;
        assert_eq!(problems(&rebuilt).len(), 2);
    }

    #[test]
    fn approvals_need_distinct_approvers_and_keys() {
        let first = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let second = SigningKey::from_slice(&[0x22; 32]).unwrap();
        let a = decision(&first, "a", "x");
        let b = decision(&second, "b", "x");
        assert!(approvals_are_distinct(&[&a, &b]));
        let same_key = decision(&first, "b", "x");
        assert!(!approvals_are_distinct(&[&a, &same_key]));
        let same_approver = decision(&second, "a", "x");
        assert!(!approvals_are_distinct(&[&a, &same_approver]));
    }
}
