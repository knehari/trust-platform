//! Fail-closed domain preflight. Inputs must be independently authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    UnknownOperation,
    InvalidBudget,
    Exhausted,
}
pub fn check(max_attempts: u16, attempts: u16, operation_known: bool) -> Result<(), GateError> {
    if !operation_known {
        return Err(GateError::UnknownOperation);
    }
    if max_attempts == 0 {
        return Err(GateError::InvalidBudget);
    }
    if attempts >= max_attempts {
        return Err(GateError::Exhausted);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_first_missing_requirement() {
        assert_eq!(check(1, 1, true), Err(GateError::Exhausted));
        assert_eq!(check(1, 0, false), Err(GateError::UnknownOperation));
        assert_eq!(check(0, 0, true), Err(GateError::InvalidBudget));
    }
}
