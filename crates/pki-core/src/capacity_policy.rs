//! Pure admission decision; distributed quota enforcement requires an atomic store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    InvalidConfiguration,
    Saturated,
    TooManyPending,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityLimits {
    pub max_in_flight: u32,
    pub max_pending: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacitySnapshot {
    pub in_flight: u32,
    pub pending: u32,
}
pub fn admit(limits: CapacityLimits, snapshot: CapacitySnapshot) -> Result<(), AdmissionError> {
    if limits.max_in_flight == 0 || limits.max_pending == 0 {
        return Err(AdmissionError::InvalidConfiguration);
    }
    if snapshot.in_flight >= limits.max_in_flight {
        return Err(AdmissionError::Saturated);
    }
    if snapshot.pending >= limits.max_pending {
        return Err(AdmissionError::TooManyPending);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_at_hard_limit_and_bad_config() {
        let l = CapacityLimits {
            max_in_flight: 2,
            max_pending: 5,
        };
        assert_eq!(admit(l, CapacitySnapshot { in_flight: 0, pending: 0 }), Ok(()));
        assert!(admit(
            l,
            CapacitySnapshot {
                in_flight: 1,
                pending: 4
            }
        )
        .is_ok());
        assert_eq!(
            admit(
                l,
                CapacitySnapshot {
                    in_flight: 2,
                    pending: 0
                }
            ),
            Err(AdmissionError::Saturated)
        );
        assert_eq!(
            admit(
                l,
                CapacitySnapshot {
                    in_flight: 0,
                    pending: 5
                }
            ),
            Err(AdmissionError::TooManyPending)
        );
        assert_eq!(
            admit(
                CapacityLimits {
                    max_in_flight: 0,
                    max_pending: 1
                },
                CapacitySnapshot {
                    in_flight: 0,
                    pending: 0
                }
            ),
            Err(AdmissionError::InvalidConfiguration)
        );
    }
}
