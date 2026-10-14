//! Fail-closed domain preflight. Inputs must be independently authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    InvalidWindow,
    InvalidLimit,
    RateExceeded,
}
pub fn check(window_seconds: u32, used: u32, limit: u32) -> Result<(), GateError> {
    if window_seconds == 0 {
        return Err(GateError::InvalidWindow);
    }
    if limit == 0 {
        return Err(GateError::InvalidLimit);
    }
    if used >= limit {
        return Err(GateError::RateExceeded);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_first_missing_requirement() {
        assert_eq!(check(0, 0, 10), Err(GateError::InvalidWindow));
    }
}
