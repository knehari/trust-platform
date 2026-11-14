//! Signed checkpoints of the audit chain (ADR-0023, Proposed).
//!
//! The signer signs the head of the audit chain of migration 0036 with a
//! P-256 audit key, distinct from every CA key, only after it has:
//! - recomputed, in Rust and from the raw events, every link after the last
//!   checkpoint it signed;
//! - checked that the database still holds that checkpoint, unchanged.
//!
//! Its last checkpoint lives in a state file outside the database. A chain
//! rewritten or rolled back behind it is therefore refused, even by someone
//! who controls the whole database. Without the key, nobody can produce a
//! checkpoint that `lab_verify_audit_chain` accepts.

use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    SecretKey,
};
use sha2::{Digest, Sha256};
use trust_pki_core::audit_chain::{
    audit_checkpoint_message, audit_event_digest, next_audit_hash, AuditEventFields, GENESIS_HASH,
};

use crate::{spki_der, Refusal};

/// Links read per database call.
pub const LINK_BATCH: i32 = 10_000;

/// The raw columns of one sealed event, as `lab_signer_audit_links` returns them.
#[derive(Debug, Clone)]
pub struct LinkEvent {
    pub event_id: Vec<u8>,
    pub ca_id: Option<Vec<u8>>,
    pub request_id: Option<Vec<u8>>,
    pub actor_id: String,
    pub event_type: String,
    pub decision: String,
    pub policy_version: Option<String>,
    pub recorded_at_micros: i64,
}

/// One link of the chain; `event` is absent when its event no longer exists.
#[derive(Debug, Clone)]
pub struct AuditLink {
    pub seq: i64,
    pub event_sha256: Vec<u8>,
    pub previous_hash: Vec<u8>,
    pub chain_hash: Vec<u8>,
    pub event: Option<LinkEvent>,
}

/// A checkpoint as the database stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCheckpoint {
    pub seq: i64,
    pub chain_hash: Vec<u8>,
    pub key_id: Vec<u8>,
    pub signed_at_unix: i64,
    pub signature: Vec<u8>,
}

/// What the signer remembers outside the database: the last checkpoint it
/// signed, or confirmed, under its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointState {
    pub seq: u64,
    pub chain_hash: [u8; 32],
    pub key_id: [u8; 32],
}

/// The result of one request: the checkpoint now current, and whether this
/// request signed it (false when there was nothing new to sign).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointOutcome {
    pub state: CheckpointState,
    pub signed: bool,
}

/// The signer's access to the audit tables, through migration 0037's functions.
pub trait AuditStore {
    fn latest_checkpoint(&mut self) -> Result<Option<StoredCheckpoint>, Refusal>;
    fn links(&mut self, after: u64, max: i32) -> Result<Vec<AuditLink>, Refusal>;
    fn record_checkpoint(
        &mut self,
        seq: u64,
        chain_hash: &[u8; 32],
        key_id: &[u8; 32],
        signed_at_unix: i64,
        signature: &[u8],
    ) -> Result<(), Refusal>;
}

/// SHA-256 of the key's SubjectPublicKeyInfo DER.
pub fn audit_key_id(key: &SecretKey) -> Result<[u8; 32], Refusal> {
    Ok(Sha256::digest(spki_der(key).map_err(|_| Refusal::AuditKeyFile)?).into())
}

fn bytes32(value: &[u8]) -> Result<[u8; 32], Refusal> {
    <[u8; 32]>::try_from(value).map_err(|_| Refusal::AuditChain)
}

fn uuid16(value: &[u8]) -> Result<[u8; 16], Refusal> {
    <[u8; 16]>::try_from(value).map_err(|_| Refusal::AuditChain)
}

fn checkpoint_signature_valid(
    key: &SecretKey,
    key_id: &[u8; 32],
    checkpoint: &StoredCheckpoint,
    chain_hash: &[u8; 32],
) -> bool {
    let Ok(seq) = u64::try_from(checkpoint.seq) else {
        return false;
    };
    let Ok(signature) = Signature::from_der(&checkpoint.signature) else {
        return false;
    };
    checkpoint.key_id.as_slice() == key_id
        && checkpoint.chain_hash.as_slice() == chain_hash
        && VerifyingKey::from(key.public_key())
            .verify(
                &audit_checkpoint_message(seq, chain_hash, checkpoint.signed_at_unix, key_id),
                &signature,
            )
            .is_ok()
}

/// Verifies the chain after `state` (or from the genesis without one) and
/// signs a checkpoint of its head, which the store records. Refuses before
/// signing when the database does not extend what this signer signed.
pub fn sign_audit_checkpoint<S: AuditStore>(
    store: &mut S,
    key: &SecretKey,
    state: Option<&CheckpointState>,
    now_unix: i64,
) -> Result<CheckpointOutcome, Refusal> {
    let key_id = audit_key_id(key)?;
    if state.is_some_and(|state| state.key_id != key_id) {
        return Err(Refusal::AuditKeyChanged);
    }
    let latest = store.latest_checkpoint()?;
    if let Some(latest) = &latest {
        if latest.key_id.as_slice() != key_id {
            return Err(Refusal::AuditCheckpointSignature);
        }
    }
    let (mut seq, mut head) = match state {
        Some(state) => {
            // The database must still hold the last checkpoint this signer
            // signed, or one after it (signed but not yet remembered).
            let Some(latest) = &latest else {
                return Err(Refusal::AuditRollback);
            };
            let latest_seq = u64::try_from(latest.seq).map_err(|_| Refusal::AuditRollback)?;
            if latest_seq < state.seq
                || (latest_seq == state.seq && latest.chain_hash.as_slice() != state.chain_hash)
            {
                return Err(Refusal::AuditRollback);
            }
            (state.seq, state.chain_hash)
        }
        None => (0, GENESIS_HASH),
    };
    let latest_seq = latest
        .as_ref()
        .map(|latest| u64::try_from(latest.seq).unwrap_or(u64::MAX))
        .unwrap_or(0);
    // The stored checkpoint at the starting point, when there is one, must
    // also verify (it is the state, or the genesis has none).
    if let (Some(latest), true) = (&latest, latest_seq == seq && seq > 0) {
        if !checkpoint_signature_valid(key, &key_id, latest, &head) {
            return Err(Refusal::AuditCheckpointSignature);
        }
    }
    loop {
        let links = store.links(seq, LINK_BATCH)?;
        let count = links.len();
        for link in links {
            let link_seq = u64::try_from(link.seq).map_err(|_| Refusal::AuditChain)?;
            if link_seq != seq + 1 || link.previous_hash.as_slice() != head {
                return Err(Refusal::AuditChain);
            }
            let event = link.event.as_ref().ok_or(Refusal::AuditChain)?;
            let digest = audit_event_digest(&AuditEventFields {
                event_id: uuid16(&event.event_id)?,
                ca_id: event.ca_id.as_deref().map(uuid16).transpose()?,
                request_id: event.request_id.as_deref().map(uuid16).transpose()?,
                actor_id: &event.actor_id,
                event_type: &event.event_type,
                decision: &event.decision,
                policy_version: event.policy_version.as_deref(),
                recorded_at_micros: event.recorded_at_micros,
            })
            .map_err(|_| Refusal::AuditChain)?;
            if link.event_sha256.as_slice() != digest {
                return Err(Refusal::AuditChain);
            }
            let next = next_audit_hash(&head, link_seq, &digest);
            if bytes32(&link.chain_hash)? != next {
                return Err(Refusal::AuditChain);
            }
            seq = link_seq;
            head = next;
            if let (Some(latest), true) = (&latest, latest_seq == seq) {
                if !checkpoint_signature_valid(key, &key_id, latest, &head) {
                    return Err(Refusal::AuditCheckpointSignature);
                }
            }
        }
        if count < usize::try_from(LINK_BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    if latest_seq > seq {
        // A checkpoint beyond the chain the database returned.
        return Err(Refusal::AuditRollback);
    }
    let state = CheckpointState {
        seq,
        chain_hash: head,
        key_id,
    };
    if seq == 0 || seq == latest_seq {
        return Ok(CheckpointOutcome {
            state,
            signed: false,
        });
    }
    let message = audit_checkpoint_message(seq, &head, now_unix, &key_id);
    let signature: Signature = SigningKey::from(key).sign(&message);
    let signature = signature.to_der().as_bytes().to_vec();
    store.record_checkpoint(seq, &head, &key_id, now_unix, &signature)?;
    Ok(CheckpointOutcome {
        state,
        signed: true,
    })
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The state file: `{"seq":…,"chain_hash":"<hex>","key_id":"<hex>"}`.
pub fn encode_state(state: &CheckpointState) -> String {
    serde_json::json!({
        "seq": state.seq, "chain_hash": hex(&state.chain_hash), "key_id": hex(&state.key_id),
    })
    .to_string()
}

/// Parses the state file strictly: a damaged file is an error, never "no state".
pub fn decode_state(text: &str) -> Result<CheckpointState, Refusal> {
    let value: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|_| Refusal::AuditStateFile)?;
    let object = value.as_object().ok_or(Refusal::AuditStateFile)?;
    if object.len() != 3 {
        return Err(Refusal::AuditStateFile);
    }
    let seq = object
        .get("seq")
        .and_then(serde_json::Value::as_u64)
        .filter(|seq| *seq > 0)
        .ok_or(Refusal::AuditStateFile)?;
    let field = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .and_then(unhex32)
            .ok_or(Refusal::AuditStateFile)
    };
    Ok(CheckpointState {
        seq,
        chain_hash: field("chain_hash")?,
        key_id: field("key_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Event(&'static str, i64);

    /// An in-memory chain built with the same construction as migration 0036.
    #[derive(Default)]
    struct FakeAudit {
        links: Vec<AuditLink>,
        checkpoints: Vec<StoredCheckpoint>,
        refuse_record: bool,
    }

    impl FakeAudit {
        fn push(&mut self, event: Event) {
            let seq = self.links.len() as u64 + 1;
            let previous = self
                .links
                .last()
                .map(|link| bytes32(&link.chain_hash).unwrap())
                .unwrap_or(GENESIS_HASH);
            let raw = LinkEvent {
                event_id: vec![seq as u8; 16],
                ca_id: Some(vec![7; 16]),
                request_id: None,
                actor_id: "lab-ra-officer".into(),
                event_type: event.0.into(),
                decision: "allow".into(),
                policy_version: Some("v1".into()),
                recorded_at_micros: event.1,
            };
            let digest = digest_of(&raw);
            self.links.push(AuditLink {
                seq: seq as i64,
                event_sha256: digest.to_vec(),
                previous_hash: previous.to_vec(),
                chain_hash: next_audit_hash(&previous, seq, &digest).to_vec(),
                event: Some(raw),
            });
        }
    }

    fn digest_of(event: &LinkEvent) -> [u8; 32] {
        audit_event_digest(&AuditEventFields {
            event_id: uuid16(&event.event_id).unwrap(),
            ca_id: event.ca_id.as_deref().map(|id| uuid16(id).unwrap()),
            request_id: None,
            actor_id: &event.actor_id,
            event_type: &event.event_type,
            decision: &event.decision,
            policy_version: event.policy_version.as_deref(),
            recorded_at_micros: event.recorded_at_micros,
        })
        .unwrap()
    }

    impl AuditStore for FakeAudit {
        fn latest_checkpoint(&mut self) -> Result<Option<StoredCheckpoint>, Refusal> {
            Ok(self.checkpoints.last().cloned())
        }
        fn links(&mut self, after: u64, max: i32) -> Result<Vec<AuditLink>, Refusal> {
            Ok(self
                .links
                .iter()
                .filter(|link| link.seq as u64 > after)
                .take(max as usize)
                .cloned()
                .collect())
        }
        fn record_checkpoint(
            &mut self,
            seq: u64,
            chain_hash: &[u8; 32],
            key_id: &[u8; 32],
            signed_at_unix: i64,
            signature: &[u8],
        ) -> Result<(), Refusal> {
            if self.refuse_record {
                return Err(Refusal::Database);
            }
            self.checkpoints.push(StoredCheckpoint {
                seq: seq as i64,
                chain_hash: chain_hash.to_vec(),
                key_id: key_id.to_vec(),
                signed_at_unix,
                signature: signature.to_vec(),
            });
            Ok(())
        }
    }

    fn key() -> SecretKey {
        SecretKey::random(&mut rand::rngs::OsRng)
    }

    fn chain(events: usize) -> FakeAudit {
        let mut audit = FakeAudit::default();
        for index in 0..events {
            audit.push(Event("certificate.revoked", 1_000_000 * index as i64));
        }
        audit
    }

    #[test]
    fn signs_a_verified_head_that_the_audit_key_verifies() {
        let key = key();
        let mut audit = chain(3);
        let outcome = sign_audit_checkpoint(&mut audit, &key, None, 1_794_225_600).unwrap();
        assert!(outcome.signed);
        assert_eq!(outcome.state.seq, 3);
        let stored = audit.checkpoints.last().unwrap().clone();
        assert_eq!(stored.chain_hash, audit.links[2].chain_hash);
        let message = audit_checkpoint_message(
            3,
            &outcome.state.chain_hash,
            1_794_225_600,
            &outcome.state.key_id,
        );
        assert!(VerifyingKey::from(key.public_key())
            .verify(&message, &Signature::from_der(&stored.signature).unwrap())
            .is_ok());
        // Nothing new: no second signature, same state.
        let again =
            sign_audit_checkpoint(&mut audit, &key, Some(&outcome.state), 1_794_225_660).unwrap();
        assert_eq!((again.signed, &again.state), (false, &outcome.state));
        assert_eq!(audit.checkpoints.len(), 1);
        // Growth: the next checkpoint extends the first.
        audit.push(Event("crl.published", 9_000_000));
        let next =
            sign_audit_checkpoint(&mut audit, &key, Some(&outcome.state), 1_794_225_720).unwrap();
        assert_eq!((next.signed, next.state.seq), (true, 4));
    }

    #[test]
    fn an_empty_chain_signs_nothing() {
        let outcome = sign_audit_checkpoint(&mut FakeAudit::default(), &key(), None, 0).unwrap();
        assert!(!outcome.signed);
        assert_eq!(outcome.state.seq, 0);
    }

    #[test]
    fn a_changed_event_or_link_is_refused_before_signing() {
        let key = key();
        for tamper in 0..4 {
            let mut audit = chain(3);
            match tamper {
                0 => audit.links[1].event.as_mut().unwrap().decision = "deny".into(),
                1 => audit.links[1].event = None,
                2 => audit.links[2].previous_hash = vec![0; 32],
                _ => {
                    audit.links.remove(1);
                }
            }
            assert_eq!(
                sign_audit_checkpoint(&mut audit, &key, None, 0),
                Err(Refusal::AuditChain),
                "tamper {tamper}"
            );
            assert!(audit.checkpoints.is_empty());
        }
    }

    #[test]
    fn a_database_behind_the_state_is_refused() {
        let key = key();
        let mut audit = chain(3);
        let first = sign_audit_checkpoint(&mut audit, &key, None, 100)
            .unwrap()
            .state;
        // Checkpoints removed (a restored or rewritten database).
        let mut rolled_back = chain(3);
        assert_eq!(
            sign_audit_checkpoint(&mut rolled_back, &key, Some(&first), 200),
            Err(Refusal::AuditRollback)
        );
        // Rebuilt history: a checkpoint row copied over a different chain.
        let mut rebuilt = FakeAudit::default();
        rebuilt.push(Event("certificate.revoked", 0));
        rebuilt.push(Event("crl.published", 1));
        rebuilt.push(Event("certificate.revoked", 2));
        let mut forged = audit.checkpoints[0].clone();
        forged.chain_hash = rebuilt.links[2].chain_hash.clone();
        rebuilt.checkpoints.push(forged);
        assert_eq!(
            sign_audit_checkpoint(&mut rebuilt, &key, Some(&first), 200),
            Err(Refusal::AuditRollback)
        );
        // Without state the signer recomputes from the genesis, and the copied
        // checkpoint does not verify over the rebuilt chain.
        assert_eq!(
            sign_audit_checkpoint(&mut rebuilt, &key, None, 200),
            Err(Refusal::AuditCheckpointSignature)
        );
    }

    #[test]
    fn a_lost_state_recovers_from_verified_checkpoints() {
        let key = key();
        let mut audit = chain(3);
        sign_audit_checkpoint(&mut audit, &key, None, 100).unwrap();
        audit.push(Event("crl.published", 5));
        // State file lost, or the signer stopped after recording: recompute
        // from the genesis, confirm the stored checkpoint, sign the new head.
        let outcome = sign_audit_checkpoint(&mut audit, &key, None, 200).unwrap();
        assert_eq!((outcome.signed, outcome.state.seq), (true, 4));
    }

    #[test]
    fn another_key_or_a_changed_key_is_refused() {
        let key = key();
        let mut audit = chain(2);
        let state = sign_audit_checkpoint(&mut audit, &key, None, 100)
            .unwrap()
            .state;
        audit.push(Event("crl.published", 5));
        let other = self::key();
        assert_eq!(
            sign_audit_checkpoint(&mut audit, &other, Some(&state), 200),
            Err(Refusal::AuditKeyChanged)
        );
        assert_eq!(
            sign_audit_checkpoint(&mut audit, &other, None, 200),
            Err(Refusal::AuditCheckpointSignature)
        );
    }

    #[test]
    fn a_failed_record_returns_no_state() {
        let mut audit = chain(2);
        audit.refuse_record = true;
        assert_eq!(
            sign_audit_checkpoint(&mut audit, &key(), None, 100),
            Err(Refusal::Database)
        );
    }

    #[test]
    fn the_state_file_round_trips_and_rejects_damage() {
        let state = CheckpointState {
            seq: 42,
            chain_hash: [0xab; 32],
            key_id: [0x01; 32],
        };
        assert_eq!(decode_state(&encode_state(&state)), Ok(state));
        for damaged in [
            "",
            "{}",
            "not json",
            r#"{"seq":0,"chain_hash":"00","key_id":"00"}"#,
            &format!(
                r#"{{"seq":1,"chain_hash":"{}","key_id":"{}"}}"#,
                "zz".repeat(32),
                "00".repeat(32)
            ),
            &format!(
                r#"{{"seq":1,"chain_hash":"{}","key_id":"{}","x":1}}"#,
                "00".repeat(32),
                "00".repeat(32)
            ),
        ] {
            assert_eq!(
                decode_state(damaged),
                Err(Refusal::AuditStateFile),
                "{damaged}"
            );
        }
    }
}
