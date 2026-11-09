use sha2::{Digest, Sha256};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    Sequence,
    PreviousDigest,
}
pub fn next_audit_hash(previous: &[u8; 32], sequence: u64, event_sha256: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"trust-platform:audit-chain:v1\0");
    hash.update(previous);
    hash.update(sequence.to_be_bytes());
    hash.update(event_sha256);
    hash.finalize().into()
}
#[derive(Debug, Default)]
pub struct AuditChain {
    sequence: u64,
    head: [u8; 32],
}
impl AuditChain {
    pub fn head(&self) -> [u8; 32] {
        self.head
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn append(
        &mut self,
        sequence: u64,
        previous: &[u8; 32],
        event: &[u8; 32],
    ) -> Result<[u8; 32], ChainError> {
        if sequence != self.sequence.checked_add(1).ok_or(ChainError::Sequence)? {
            return Err(ChainError::Sequence);
        }
        if previous != &self.head {
            return Err(ChainError::PreviousDigest);
        }
        let next = next_audit_hash(previous, sequence, event);
        self.sequence = sequence;
        self.head = next;
        Ok(next)
    }
}
/// The genesis "previous hash" of sequence 1.
pub const GENESIS_HASH: [u8; 32] = [0; 32];

/// The columns of one `audit_event` row (migration 0001), as the canonical
/// encoding of migration 0036 (ADR-0022) reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventFields<'a> {
    pub event_id: [u8; 16],
    pub ca_id: Option<[u8; 16]>,
    pub request_id: Option<[u8; 16]>,
    pub actor_id: &'a str,
    pub event_type: &'a str,
    pub decision: &'a str,
    pub policy_version: Option<&'a str>,
    /// Microseconds since the Unix epoch, negative before it.
    pub recorded_at_micros: i64,
}

/// A text column too long for its 32-bit length prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldTooLong;

fn put_text(out: &mut Vec<u8>, text: &str) -> Result<(), FieldTooLong> {
    let length = u32::try_from(text.len()).map_err(|_| FieldTooLong)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn put_optional_uuid(out: &mut Vec<u8>, value: Option<[u8; 16]>) {
    match value {
        None => out.push(0),
        Some(uuid) => {
            out.push(1);
            out.extend_from_slice(&uuid);
        }
    }
}

/// Canonical encoding (version 1) of an audit event; the same bytes as the
/// SQL function `audit_event_canonical` of migration 0036. Every column, in
/// table order: texts are 32-bit big-endian length-prefixed UTF-8, optional
/// values carry a presence byte, the instant is a big-endian `i64`.
pub fn audit_event_canonical(event: &AuditEventFields<'_>) -> Result<Vec<u8>, FieldTooLong> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"trust-platform:audit-event:v1\0");
    out.extend_from_slice(&event.event_id);
    put_optional_uuid(&mut out, event.ca_id);
    put_optional_uuid(&mut out, event.request_id);
    put_text(&mut out, event.actor_id)?;
    put_text(&mut out, event.event_type)?;
    put_text(&mut out, event.decision)?;
    match event.policy_version {
        None => out.push(0),
        Some(version) => {
            out.push(1);
            put_text(&mut out, version)?;
        }
    }
    out.extend_from_slice(&event.recorded_at_micros.to_be_bytes());
    Ok(out)
}

/// SHA-256 of the canonical encoding: the `event_sha256` of a chain link.
pub fn audit_event_digest(event: &AuditEventFields<'_>) -> Result<[u8; 32], FieldTooLong> {
    Ok(Sha256::digest(audit_event_canonical(event)?).into())
}

/// The bytes an audit checkpoint signature covers (ADR-0023, version 1): the
/// head of the chain at `seq`, when it was signed (Unix seconds) and the key
/// identifier (SHA-256 of the signing key's SubjectPublicKeyInfo DER), so a
/// signature cannot be moved to another head, instant or key.
pub fn audit_checkpoint_message(
    seq: u64,
    chain_hash: &[u8; 32],
    signed_at_unix: i64,
    key_id: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + 8 + 32 + 8 + 32);
    message.extend_from_slice(b"trust-platform:audit-checkpoint:v1\0");
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(chain_hash);
    message.extend_from_slice(&signed_at_unix.to_be_bytes());
    message.extend_from_slice(key_id);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `11111111-1111-4111-8111-111111111111` and similar fixtures.
    fn uuid(byte: u8) -> [u8; 16] {
        let mut id = [byte; 16];
        id[6] = 0x40 | (byte & 0x0f);
        id[8] = 0x80 | (byte & 0x0f);
        id
    }

    // Vectors computed by PostgreSQL 16 with audit_event_canonical
    // (tests/management_audit_chain.sql asserts the same digests).
    #[test]
    fn canonical_encoding_matches_the_database() {
        let event = AuditEventFields {
            event_id: uuid(0x11),
            ca_id: Some(uuid(0x22)),
            request_id: None,
            actor_id: "lab-ra-officer",
            event_type: "certificate.revoked",
            decision: "allow",
            policy_version: Some("v1"),
            // 2026-11-09T12:00:00.123456Z
            recorded_at_micros: 1_794_225_600_123_456,
        };
        assert_eq!(
            hex(&audit_event_canonical(&event).unwrap()),
            "74727573742d706c6174666f726d3a61756469742d6576656e743a763100111111111111411181111111111111110122222222222242228222222222222222000000000e6c61622d72612d6f6666696365720000001363657274696669636174652e7265766f6b656400000005616c6c6f770100000002763100065fd6b38ad240"
        );
        assert_eq!(
            hex(&audit_event_digest(&event).unwrap()),
            "1950603ca47066137e2477b0a66d2f76d88eba13be0fd6d6ab1cdd50cf9b2911"
        );
        let before_epoch = AuditEventFields {
            event_id: uuid(0x33),
            ca_id: None,
            request_id: Some(uuid(0x44)),
            actor_id: "crl-renewer",
            event_type: "crl.published",
            decision: "persisted",
            policy_version: None,
            // 1969-12-31T23:59:59.5Z
            recorded_at_micros: -500_000,
        };
        assert_eq!(
            hex(&audit_event_digest(&before_epoch).unwrap()),
            "1b660fd39da5e79549650877fb1517f8fa8671c746a345b294c8df5886888bcf"
        );
    }

    #[test]
    fn checkpoint_message_binds_every_field() {
        let message = audit_checkpoint_message(7, &[1; 32], 1_794_225_600, &[2; 32]);
        assert_eq!(message.len(), 35 + 8 + 32 + 8 + 32);
        assert!(message.starts_with(b"trust-platform:audit-checkpoint:v1\0"));
        for other in [
            audit_checkpoint_message(8, &[1; 32], 1_794_225_600, &[2; 32]),
            audit_checkpoint_message(7, &[3; 32], 1_794_225_600, &[2; 32]),
            audit_checkpoint_message(7, &[1; 32], 1_794_225_601, &[2; 32]),
            audit_checkpoint_message(7, &[1; 32], 1_794_225_600, &[4; 32]),
        ] {
            assert_ne!(other, message);
        }
    }

    #[test]
    fn every_field_changes_the_digest() {
        let base = AuditEventFields {
            event_id: [1; 16],
            ca_id: Some([2; 16]),
            request_id: Some([3; 16]),
            actor_id: "a",
            event_type: "b",
            decision: "c",
            policy_version: Some("d"),
            recorded_at_micros: 5,
        };
        let digest = audit_event_digest(&base).unwrap();
        let variants = [
            AuditEventFields {
                event_id: [9; 16],
                ..base.clone()
            },
            AuditEventFields {
                ca_id: None,
                ..base.clone()
            },
            AuditEventFields {
                request_id: None,
                ..base.clone()
            },
            AuditEventFields {
                actor_id: "ab",
                event_type: "",
                ..base.clone()
            },
            AuditEventFields {
                decision: "C",
                ..base.clone()
            },
            AuditEventFields {
                policy_version: None,
                ..base.clone()
            },
            AuditEventFields {
                policy_version: Some(""),
                ..base.clone()
            },
            AuditEventFields {
                recorded_at_micros: 6,
                ..base.clone()
            },
        ];
        for variant in variants {
            assert_ne!(audit_event_digest(&variant).unwrap(), digest, "{variant:?}");
        }
    }
    #[test]
    fn detects_sequence_replay_and_chain_fork() {
        let mut log = AuditChain::default();
        let genesis = log.head();
        let first = log.append(1, &genesis, &[1; 32]).unwrap();
        assert_eq!(log.append(1, &first, &[2; 32]), Err(ChainError::Sequence));
        assert_eq!(
            log.append(2, &genesis, &[2; 32]),
            Err(ChainError::PreviousDigest)
        );
        assert!(log.append(2, &first, &[2; 32]).is_ok());
    }
}
