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
}
