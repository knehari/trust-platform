#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyError {
    InvalidQuorum,
    MissingWitness,
    DuplicateWitness,
}
pub fn validate_witnesses(required: usize, witnesses: &[&str]) -> Result<(), CeremonyError> {
    if !(2..=16).contains(&required) {
        return Err(CeremonyError::InvalidQuorum);
    }
    if witnesses.len() < required {
        return Err(CeremonyError::MissingWitness);
    }
    for (i, w) in witnesses.iter().enumerate() {
        if w.trim().is_empty() || w.len() > 256 || w.chars().any(char::is_control) {
            return Err(CeremonyError::MissingWitness);
        }
        if witnesses[..i].contains(w) {
            return Err(CeremonyError::DuplicateWitness);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quorum_is_fail_closed() {
        assert!(validate_witnesses(2, &["alice", "bob"]).is_ok());
        assert_eq!(
            validate_witnesses(2, &["alice", "alice"]),
            Err(CeremonyError::DuplicateWitness)
        );
        assert_eq!(
            validate_witnesses(2, &["alice"]),
            Err(CeremonyError::MissingWitness)
        );
        assert_eq!(
            validate_witnesses(1, &["alice"]),
            Err(CeremonyError::InvalidQuorum)
        );
    }
}
