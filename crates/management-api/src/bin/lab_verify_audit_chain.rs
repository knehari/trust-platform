//! Laboratory audit tool: verifies the tamper-evident audit chain of
//! migration 0036 (ADR-0022) independently of the database functions that
//! built it.
//!
//! From the raw columns of `audit_event` and `audit_chain_link` it
//! recomputes, with `trust_pki_core::audit_chain`, the canonical digest of
//! every sealed event and every link, and checks that:
//! - sequences start at 1 and have no gap;
//! - each link names the previous link's hash, from an all-zero genesis;
//! - each sealed event still exists and still has the sealed digest;
//! - each link's hash is the recomputed one.
//!
//! It then prints a manifest (JSON on stdout: head sequence and hash, link
//! count, unsealed events). The chain only proves something against a head
//! kept **outside** the database: whoever can rewrite `audit_event` can
//! rebuild the chain too. Export the manifest, and later pass its head back:
//! `TRUST_AUDIT_EXPECTED_HEAD=<seq>:<hex>` fails unless the link at that
//! sequence still carries that hash, which shows that nothing sealed up to
//! it was altered, removed or reordered since.
//!
//! Signed checkpoints (migration 0037, ADR-0023) remove the need to export
//! the head by hand. Each checkpoint must name a link of the recomputed
//! chain, with that link's hash. With the audit public key
//! (`TRUST_AUDIT_CHECKPOINT_PUBLIC_KEY`, a PEM file supplied out of band, never
//! read from the database), each checkpoint must also carry that key's
//! identifier and a valid ECDSA P-256 signature over
//! `trust_pki_core::audit_chain::audit_checkpoint_message`. A chain rebuilt by
//! the database owner then fails at every checkpoint the owner could not
//! re-sign. `TRUST_AUDIT_REQUIRE_CHECKPOINT=1` also fails without the key, or
//! when sealed links have no checkpoint.
//!
//! `TRUST_AUDIT_REQUIRE_SEALED=1` also fails while any event is unsealed.
//! Run it as the database owner:
//! `TRUST_VERIFY_DATABASE_URL=… cargo run -p trust-management-api --bin lab_verify_audit_chain`
use std::{collections::HashMap, env, error::Error, fs, io, process::ExitCode};

use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};
use trust_pki_core::audit_chain::{
    audit_checkpoint_message, audit_event_digest, next_audit_hash, AuditEventFields, GENESIS_HASH,
};
use x509_cert::{
    der::{asn1::ObjectIdentifier, DecodePem, Encode},
    spki::SubjectPublicKeyInfoOwned,
};

/// The audit public key: its SEC1 point and identifier (SHA-256 of the
/// SubjectPublicKeyInfo DER, as the signer computes it).
struct AuditPublicKey {
    point: Vec<u8>,
    key_id: [u8; 32],
}

fn read_public_key(path: &str) -> Result<AuditPublicKey, String> {
    let pem = fs::read_to_string(path).map_err(|_| "cannot read the audit public key")?;
    let spki = SubjectPublicKeyInfoOwned::from_pem(pem.as_bytes())
        .map_err(|_| "the audit public key is not a PEM SubjectPublicKeyInfo")?;
    let p256 = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    let ec = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
    if spki.algorithm.oid != ec || curve != Some(p256) {
        return Err("the audit public key is not a P-256 key".into());
    }
    let der = spki
        .to_der()
        .map_err(|_| "cannot encode the audit public key")?;
    Ok(AuditPublicKey {
        point: spki.subject_public_key.raw_bytes().to_vec(),
        key_id: Sha256::digest(der).into(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn uuid16(value: Option<Vec<u8>>) -> Result<Option<[u8; 16]>, String> {
    value
        .map(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| "UUID not 16 bytes".into()))
        .transpose()
}

fn hash32(bytes: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).ok()
}

/// `<seq>:<64 hex digits>`, as the manifest prints it.
fn parse_expected_head(value: &str) -> Result<(i64, String), String> {
    let (seq, hash) = value
        .split_once(':')
        .ok_or("TRUST_AUDIT_EXPECTED_HEAD must be <seq>:<hex>")?;
    let seq: i64 = seq
        .parse()
        .ok()
        .filter(|seq| *seq > 0)
        .ok_or("expected head sequence must be a positive integer")?;
    let hash = hash.to_ascii_lowercase();
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected head hash must be 64 hexadecimal digits".into());
    }
    Ok((seq, hash))
}

fn main() -> Result<ExitCode, Box<dyn Error>> {
    let url = env::var("TRUST_VERIFY_DATABASE_URL")
        .map_err(|_| io::Error::other("set TRUST_VERIFY_DATABASE_URL to a lab database"))?;
    let expected_head = env::var("TRUST_AUDIT_EXPECTED_HEAD")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| parse_expected_head(&value))
        .transpose()
        .map_err(io::Error::other)?;
    let require_sealed = env::var("TRUST_AUDIT_REQUIRE_SEALED").is_ok_and(|value| value == "1");
    let require_checkpoint =
        env::var("TRUST_AUDIT_REQUIRE_CHECKPOINT").is_ok_and(|value| value == "1");
    let public_key = env::var("TRUST_AUDIT_CHECKPOINT_PUBLIC_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|path| read_public_key(&path))
        .transpose()
        .map_err(io::Error::other)?;
    let mut db = Client::connect(&url, NoTls)?;
    // One snapshot for the links and the unsealed count.
    let mut tx = db
        .build_transaction()
        .isolation_level(postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()?;
    let rows = tx.query(
        "SELECT l.seq, uuid_send(l.event_id), l.event_sha256, l.previous_hash, l.chain_hash, \
                uuid_send(a.event_id), uuid_send(a.ca_id), uuid_send(a.request_id), a.actor_id, \
                a.event_type, a.decision, a.policy_version, \
                (extract(epoch FROM a.recorded_at) * 1000000)::bigint \
         FROM audit_chain_link l LEFT JOIN audit_event a ON a.event_id = l.event_id \
         ORDER BY l.seq",
        &[],
    )?;
    let unsealed: i64 = tx
        .query_one(
            "SELECT count(*) FROM audit_event a \
             WHERE NOT EXISTS (SELECT 1 FROM audit_chain_link l WHERE l.event_id = a.event_id)",
            &[],
        )?
        .get(0);
    let checkpoints = if tx
        .query_one(
            "SELECT to_regclass('public.audit_chain_checkpoint') IS NOT NULL",
            &[],
        )?
        .get::<_, bool>(0)
    {
        tx.query(
            "SELECT seq, chain_hash, key_id, extract(epoch FROM signed_at)::bigint, signature \
             FROM audit_chain_checkpoint ORDER BY seq",
            &[],
        )?
    } else {
        Vec::new()
    };
    tx.commit()?;

    let mut problems: Vec<String> = Vec::new();
    let mut previous = GENESIS_HASH;
    let mut expected_found = false;
    // The recomputed hash at each sequence, for the checkpoints.
    let mut heads: HashMap<i64, [u8; 32]> = HashMap::new();
    for (index, row) in rows.iter().enumerate() {
        let seq: i64 = row.get(0);
        let want_seq = i64::try_from(index).unwrap_or(i64::MAX).saturating_add(1);
        if seq != want_seq {
            problems.push(format!("link {seq}: expected sequence {want_seq}"));
            break;
        }
        let stored_event: Vec<u8> = row.get(2);
        let stored_previous: Vec<u8> = row.get(3);
        let stored_hash: Vec<u8> = row.get(4);
        if stored_previous.as_slice() != previous.as_slice() {
            problems.push(format!(
                "link {seq}: does not name the previous link's hash"
            ));
        }
        let Some(event_id) = row.get::<_, Option<Vec<u8>>>(5) else {
            problems.push(format!("link {seq}: its event no longer exists"));
            previous = hash32(&stored_hash).unwrap_or(GENESIS_HASH);
            heads.insert(seq, previous);
            continue;
        };
        let fields = (|| -> Result<[u8; 32], String> {
            let event = AuditEventFields {
                event_id: uuid16(Some(event_id))?.ok_or("missing event id")?,
                ca_id: uuid16(row.get(6))?,
                request_id: uuid16(row.get(7))?,
                actor_id: row.get(8),
                event_type: row.get(9),
                decision: row.get(10),
                policy_version: row.get(11),
                recorded_at_micros: row.get(12),
            };
            audit_event_digest(&event).map_err(|_| "field too long".to_string())
        })();
        let digest = match fields {
            Ok(digest) => digest,
            Err(reason) => {
                problems.push(format!("link {seq}: {reason}"));
                previous = hash32(&stored_hash).unwrap_or(GENESIS_HASH);
                heads.insert(seq, previous);
                continue;
            }
        };
        if stored_event.as_slice() != digest.as_slice() {
            problems.push(format!(
                "link {seq}: the event differs from what was sealed"
            ));
        }
        let Ok(sequence) = u64::try_from(seq) else {
            problems.push(format!("link {seq}: negative sequence"));
            break;
        };
        // Recompute from what was sealed, so one altered event reports once
        // rather than breaking every later link.
        let sealed_digest = hash32(&stored_event).unwrap_or(digest);
        let recomputed = next_audit_hash(&previous, sequence, &sealed_digest);
        if stored_hash.as_slice() != recomputed.as_slice() {
            problems.push(format!("link {seq}: chain hash does not recompute"));
        }
        if let Some((head_seq, head_hash)) = &expected_head {
            if *head_seq == seq {
                expected_found = true;
                if hex(&recomputed) != *head_hash {
                    problems.push(format!(
                        "link {seq}: differs from the exported head {head_hash}"
                    ));
                }
            }
        }
        previous = recomputed;
        heads.insert(seq, recomputed);
    }
    let mut verified_signatures = 0usize;
    for checkpoint in &checkpoints {
        let seq: i64 = checkpoint.get(0);
        let chain_hash: Vec<u8> = checkpoint.get(1);
        let key_id: Vec<u8> = checkpoint.get(2);
        let signed_at: i64 = checkpoint.get(3);
        let signature: Vec<u8> = checkpoint.get(4);
        let Some(head) = heads.get(&seq) else {
            problems.push(format!("checkpoint {seq}: no such link in the chain"));
            continue;
        };
        if chain_hash.as_slice() != head.as_slice() {
            problems.push(format!(
                "checkpoint {seq}: differs from the recomputed chain"
            ));
            continue;
        }
        let Some(key) = &public_key else { continue };
        let (Ok(sequence), Some(stored_key_id)) = (u64::try_from(seq), hash32(&key_id)) else {
            problems.push(format!("checkpoint {seq}: malformed"));
            continue;
        };
        if stored_key_id != key.key_id {
            problems.push(format!("checkpoint {seq}: signed by another key"));
            continue;
        }
        let message = audit_checkpoint_message(sequence, head, signed_at, &key.key_id);
        if trust_pki_crypto::verify_p256_ecdsa_sha256(&key.point, &message, &signature).is_err() {
            problems.push(format!("checkpoint {seq}: the signature does not verify"));
            continue;
        }
        verified_signatures += 1;
    }
    let latest_checkpoint = checkpoints.last().map(|row| row.get::<_, i64>(0));
    if require_checkpoint {
        if public_key.is_none() {
            problems
                .push("TRUST_AUDIT_CHECKPOINT_PUBLIC_KEY is required to verify checkpoints".into());
        }
        if !rows.is_empty() && checkpoints.is_empty() {
            problems.push("sealed links have no signed checkpoint".into());
        }
    }
    if let Some((head_seq, _)) = &expected_head {
        if !expected_found {
            problems.push(format!(
                "the exported head {head_seq} is no longer in the chain"
            ));
        }
    }
    if require_sealed && unsealed > 0 {
        problems.push(format!("{unsealed} event(s) are not sealed"));
    }

    let head_seq = rows.len();
    let manifest = serde_json::json!({
        "manifest": "trust-platform:audit-chain-manifest:v1",
        "chain": "trust-platform:audit-chain:v1",
        "event_encoding": "trust-platform:audit-event:v1",
        "head_seq": head_seq,
        "head_hash": hex(&previous),
        "expected_head": expected_head.as_ref().map(|(seq, hash)| format!("{seq}:{hash}")),
        "unsealed_events": unsealed,
        "checkpoints": checkpoints.len(),
        "latest_checkpoint_seq": latest_checkpoint,
        "checkpoint_signatures": if public_key.is_some() { "verified" } else { "not checked" },
        "verified": problems.is_empty(),
    });
    println!("{manifest}");
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("FAIL {problem}");
        }
        eprintln!("{} problem(s) in the audit chain", problems.len());
        return Ok(ExitCode::FAILURE);
    }
    eprintln!(
        "PASS: {head_seq} sealed audit event(s) verified independently; {unsealed} not yet sealed; \
         {} checkpoint(s), {verified_signatures} signature(s) verified",
        checkpoints.len()
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::parse_expected_head;

    #[test]
    fn expected_head_is_strict() {
        let hash = "AB".repeat(32);
        assert_eq!(
            parse_expected_head(&format!("3:{hash}")),
            Ok((3, "ab".repeat(32)))
        );
        assert!(parse_expected_head(&format!("0:{hash}")).is_err());
        assert!(parse_expected_head(&format!("-1:{hash}")).is_err());
        assert!(parse_expected_head("3:abcd").is_err());
        assert!(parse_expected_head(&format!("3:{}", "zz".repeat(32))).is_err());
        assert!(parse_expected_head(&hash).is_err());
    }
}
