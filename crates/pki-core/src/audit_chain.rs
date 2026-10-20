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
    /// Continue a chain from a trusted point (an external checkpoint).
    pub fn resume(sequence: u64, head: [u8; 32]) -> Self {
        Self { sequence, head }
    }
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

/// A row sealed into the database audit chain (migration 0027), with its raw
/// columns. `digest` re-encodes it independently of the database:
/// "trust-platform:audit-record:v1\0", the source name, then each column as
/// 0x00 (NULL) or 0x01 + 4-byte big-endian length + bytes (UUID 16 bytes,
/// text UTF-8, timestamps and integers 8-byte big-endian, timestamps in
/// microseconds since the Unix epoch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRecord {
    Event {
        event_id: [u8; 16],
        ca_id: Option<[u8; 16]>,
        request_id: Option<[u8; 16]>,
        actor_id: String,
        event_type: String,
        decision: String,
        policy_version: Option<String>,
        recorded_at_us: i64,
    },
    SchemaChange {
        change_seq: i64,
        recorded_at_us: i64,
        event: String,
        command_tag: String,
        object_type: Option<String>,
        schema_name: Option<String>,
        object_identity: Option<String>,
        session_user_name: String,
        transaction_id: u64,
    },
}

fn field(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => out.push(0),
        Some(bytes) => {
            out.push(1);
            // Columns are far below 4 GiB (PostgreSQL limits a value to 1 GiB).
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
    }
}

impl AuditRecord {
    pub fn source(&self) -> &'static str {
        match self {
            Self::Event { .. } => "audit_event",
            Self::SchemaChange { .. } => "schema_change_audit",
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut out = b"trust-platform:audit-record:v1\0".to_vec();
        field(&mut out, Some(self.source().as_bytes()));
        match self {
            Self::Event {
                event_id,
                ca_id,
                request_id,
                actor_id,
                event_type,
                decision,
                policy_version,
                recorded_at_us,
            } => {
                field(&mut out, Some(event_id));
                field(&mut out, ca_id.as_ref().map(|v| &v[..]));
                field(&mut out, request_id.as_ref().map(|v| &v[..]));
                field(&mut out, Some(actor_id.as_bytes()));
                field(&mut out, Some(event_type.as_bytes()));
                field(&mut out, Some(decision.as_bytes()));
                field(&mut out, policy_version.as_deref().map(str::as_bytes));
                field(&mut out, Some(&recorded_at_us.to_be_bytes()));
            }
            Self::SchemaChange {
                change_seq,
                recorded_at_us,
                event,
                command_tag,
                object_type,
                schema_name,
                object_identity,
                session_user_name,
                transaction_id,
            } => {
                field(&mut out, Some(&change_seq.to_be_bytes()));
                field(&mut out, Some(&recorded_at_us.to_be_bytes()));
                field(&mut out, Some(event.as_bytes()));
                field(&mut out, Some(command_tag.as_bytes()));
                field(&mut out, object_type.as_deref().map(str::as_bytes));
                field(&mut out, schema_name.as_deref().map(str::as_bytes));
                field(&mut out, object_identity.as_deref().map(str::as_bytes));
                field(&mut out, Some(session_user_name.as_bytes()));
                field(&mut out, Some(&transaction_id.to_be_bytes()));
            }
        }
        Sha256::digest(&out).into()
    }
}

/// Parse a UUID in PostgreSQL's canonical text form (lowercase 8-4-4-4-12).
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
        return None;
    }
    let hex: Vec<u8> = bytes.iter().copied().filter(|&b| b != b'-').collect();
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks(2).enumerate() {
        let nibble = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        out[i] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

/// One sealed chain entry as stored. `record` is None when the source row
/// no longer exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEntry {
    pub sequence: u64,
    pub previous: [u8; 32],
    pub event_sha256: [u8; 32],
    pub entry_hash: [u8; 32],
    pub record: Option<AuditRecord>,
}

/// A chain head exported outside the database (the external anchor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub sequence: u64,
    pub head: [u8; 32],
}

const CHECKPOINT_TAG: &str = "audit-chain-checkpoint v1";

impl Checkpoint {
    pub fn to_line(&self) -> String {
        let head: String = self.head.iter().map(|b| format!("{b:02x}")).collect();
        format!("{CHECKPOINT_TAG} {} {head}", self.sequence)
    }

    pub fn parse_line(line: &str) -> Option<Self> {
        let rest = line.strip_prefix(CHECKPOINT_TAG)?.strip_prefix(' ')?;
        let (sequence, head) = rest.split_once(' ')?;
        if sequence.starts_with('0') || head.len() != 64 {
            return None;
        }
        let sequence = sequence.parse().ok()?;
        let mut out = [0u8; 32];
        for (i, pair) in head.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).ok()?;
            if pair.bytes().any(|c| c.is_ascii_uppercase()) {
                return None;
            }
            out[i] = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self {
            sequence,
            head: out,
        })
    }
}

/// Why a sealed chain failed verification; `sequence` is the first bad entry
/// (or the checkpoint that could not be reached).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerifyError {
    /// Checkpoints are not strictly increasing.
    CheckpointOrder,
    /// The chain skips or repeats a sequence number, or forks.
    Chain { sequence: u64, error: ChainError },
    /// The sealed source row was deleted.
    SourceMissing { sequence: u64 },
    /// The source row no longer matches the digest sealed for it.
    RecordAltered { sequence: u64 },
    /// The stored entry hash is not the hash of the entry.
    EntryHash { sequence: u64 },
    /// The chain differs from an exported checkpoint (rewritten history).
    CheckpointMismatch { sequence: u64 },
    /// The chain ends before an exported checkpoint (truncated).
    Truncated { sequence: u64 },
}

/// Verify a sealed chain from its first entry, re-encoding every record and
/// comparing the heads with the exported checkpoints. Returns the chain
/// head on success. Entries must be given in sequence order.
pub fn verify_sealed_chain(
    entries: impl IntoIterator<Item = SealedEntry>,
    checkpoints: &[Checkpoint],
) -> Result<AuditChain, ChainVerifyError> {
    if checkpoints
        .windows(2)
        .any(|w| w[0].sequence >= w[1].sequence)
    {
        return Err(ChainVerifyError::CheckpointOrder);
    }
    let mut pending = checkpoints.iter().peekable();
    let mut chain = AuditChain::default();
    for entry in entries {
        let sequence = entry.sequence;
        let record = entry
            .record
            .as_ref()
            .ok_or(ChainVerifyError::SourceMissing { sequence })?;
        let digest = record.digest();
        if digest != entry.event_sha256 {
            return Err(ChainVerifyError::RecordAltered { sequence });
        }
        let head = chain
            .append(sequence, &entry.previous, &digest)
            .map_err(|error| ChainVerifyError::Chain { sequence, error })?;
        if head != entry.entry_hash {
            return Err(ChainVerifyError::EntryHash { sequence });
        }
        if let Some(checkpoint) = pending.next_if(|c| c.sequence == sequence) {
            if checkpoint.head != head {
                return Err(ChainVerifyError::CheckpointMismatch { sequence });
            }
        }
    }
    match pending.next() {
        Some(missed) => Err(ChainVerifyError::Truncated {
            sequence: missed.sequence,
        }),
        None => Ok(chain),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn record(decision: &str) -> AuditRecord {
        AuditRecord::Event {
            event_id: parse_uuid("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b").unwrap(),
            ca_id: None,
            request_id: None,
            actor_id: "actor".into(),
            event_type: "probe".into(),
            decision: decision.into(),
            policy_version: Some("v1".into()),
            recorded_at_us: 1_792_533_719_346_371,
        }
    }

    fn sealed(decisions: &[&str]) -> Vec<SealedEntry> {
        let mut chain = AuditChain::default();
        decisions
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let record = record(d);
                let previous = chain.head();
                let entry_hash = chain
                    .append(i as u64 + 1, &previous, &record.digest())
                    .unwrap();
                SealedEntry {
                    sequence: i as u64 + 1,
                    previous,
                    event_sha256: record.digest(),
                    entry_hash,
                    record: Some(record),
                }
            })
            .collect()
    }

    #[test]
    fn encoding_separates_null_from_empty_and_fields() {
        let base = record("ok");
        let mut empty_version = base.clone();
        if let AuditRecord::Event { policy_version, .. } = &mut empty_version {
            *policy_version = Some(String::new());
        }
        let mut no_version = base.clone();
        if let AuditRecord::Event { policy_version, .. } = &mut no_version {
            *policy_version = None;
        }
        assert_ne!(empty_version.digest(), no_version.digest());
        // Moving a byte between adjacent fields changes the digest.
        let mut shifted = base.clone();
        if let AuditRecord::Event {
            actor_id,
            event_type,
            ..
        } = &mut shifted
        {
            *actor_id = "actorp".into();
            *event_type = "robe".into();
        }
        assert_ne!(base.digest(), shifted.digest());
    }

    #[test]
    fn verifies_sealed_chain_and_detects_tampering() {
        let entries = sealed(&["a", "b", "c"]);
        let head = verify_sealed_chain(entries.clone(), &[]).unwrap();
        let anchor = Checkpoint {
            sequence: 2,
            head: entries[1].entry_hash,
        };
        assert_eq!(head.head(), entries[2].entry_hash);
        assert!(verify_sealed_chain(entries.clone(), &[anchor]).is_ok());

        let mut altered = entries.clone();
        altered[1].record = Some(record("forged"));
        assert_eq!(
            verify_sealed_chain(altered, &[]).unwrap_err(),
            ChainVerifyError::RecordAltered { sequence: 2 }
        );
        let mut missing = entries.clone();
        missing[0].record = None;
        assert_eq!(
            verify_sealed_chain(missing, &[]).unwrap_err(),
            ChainVerifyError::SourceMissing { sequence: 1 }
        );
        let mut gap = entries.clone();
        gap.remove(1);
        assert!(matches!(
            verify_sealed_chain(gap, &[]).unwrap_err(),
            ChainVerifyError::Chain { sequence: 3, .. }
        ));
        let mut bad_hash = entries.clone();
        bad_hash[2].entry_hash = [7; 32];
        assert_eq!(
            verify_sealed_chain(bad_hash, &[]).unwrap_err(),
            ChainVerifyError::EntryHash { sequence: 3 }
        );
        // A consistently recomputed chain passes on its own; only the
        // exported checkpoint reveals the rewrite.
        let rewritten = sealed(&["a", "forged", "c"]);
        assert!(verify_sealed_chain(rewritten.clone(), &[]).is_ok());
        assert_eq!(
            verify_sealed_chain(rewritten, &[anchor]).unwrap_err(),
            ChainVerifyError::CheckpointMismatch { sequence: 2 }
        );
        assert_eq!(
            verify_sealed_chain(entries[..1].to_vec(), &[anchor]).unwrap_err(),
            ChainVerifyError::Truncated { sequence: 2 }
        );
        assert_eq!(
            verify_sealed_chain(entries, &[anchor, anchor]).unwrap_err(),
            ChainVerifyError::CheckpointOrder
        );
    }

    #[test]
    fn checkpoint_lines_round_trip_strictly() {
        let checkpoint = Checkpoint {
            sequence: 42,
            head: [0xab; 32],
        };
        let line = checkpoint.to_line();
        assert_eq!(Checkpoint::parse_line(&line), Some(checkpoint));
        assert_eq!(Checkpoint::parse_line(&line.to_uppercase()), None);
        assert_eq!(Checkpoint::parse_line(&line.replace(" 42 ", " 042 ")), None);
        assert_eq!(Checkpoint::parse_line(&line.replace(" 42 ", " 0 ")), None);
        assert_eq!(Checkpoint::parse_line(&line[..line.len() - 2]), None);
        assert_eq!(Checkpoint::parse_line(&format!("{line} extra")), None);
    }

    #[test]
    fn uuid_parser_accepts_only_canonical_text() {
        assert_eq!(
            parse_uuid("00000000-0000-0000-0000-0000000000ff").unwrap()[15],
            0xff
        );
        assert!(parse_uuid("00000000-0000-0000-0000-0000000000FF").is_none());
        assert!(parse_uuid("000000000000-0000-0000-0000000000ff").is_none());
        assert!(parse_uuid("00000000-0000-0000-0000-0000000000f").is_none());
    }
}
