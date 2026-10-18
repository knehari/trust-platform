//! Pure status-change decision layer for the lab revocation slice.
//!
//! These are lab rules, re-checked by the database (migration 0014); this
//! module performs no I/O and is not an authorization decision.

use crate::crl::{MAX_CRL_TIME_UNIX, MIN_CRL_TIME_UNIX};
use crate::revocation::{CertificateStatus, RevocationReason, StatusAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusChangeError {
    UnknownReason,
    ReasonNotAllowedForAction,
    SuspensionDisabled,
    InvalidTransition,
    TerminalState,
    /// Outside 1970-01-01 .. 9999-12-31 or later than now.
    InvalidityDateOutOfRange,
}

/// An invalidity date is a known or suspected past date (RFC 5280 5.3.2) and
/// must stay encodable in every later CRL (an approved revocation never
/// changes): 1970-01-01T00:00:00Z ..= min(now, 9999-12-31T23:59:59Z).
/// Migration 0014 re-checks the same bounds with the database clock.
pub fn check_invalidity_date(
    invalidity_at_unix: Option<i64>,
    now_unix: i64,
) -> Result<(), StatusChangeError> {
    match invalidity_at_unix {
        Some(t) if !(MIN_CRL_TIME_UNIX..=MAX_CRL_TIME_UNIX).contains(&t) || t > now_unix => {
            Err(StatusChangeError::InvalidityDateOutOfRange)
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Suspend,
    Release,
    RevokeFromValid,
    RevokeFromSuspended,
}

/// Fails closed. Check order: terminal state, reason shape, state, policy.
/// RELEASE stays allowed when suspension was disabled after the hold.
pub fn decide_status_change(
    current: CertificateStatus,
    action: StatusAction,
    reason: Option<RevocationReason>,
    suspension_allowed: bool,
) -> Result<Transition, StatusChangeError> {
    use StatusChangeError::*;
    if current == CertificateStatus::Revoked {
        return Err(TerminalState);
    }
    match action {
        StatusAction::Suspend => {
            if reason != Some(RevocationReason::CertificateHold) {
                return Err(ReasonNotAllowedForAction);
            }
            if current != CertificateStatus::Valid {
                return Err(InvalidTransition);
            }
            if !suspension_allowed {
                return Err(SuspensionDisabled);
            }
            Ok(Transition::Suspend)
        }
        StatusAction::Release => {
            if reason.is_some() {
                return Err(ReasonNotAllowedForAction);
            }
            if current != CertificateStatus::Suspended {
                return Err(InvalidTransition);
            }
            Ok(Transition::Release)
        }
        StatusAction::Revoke => match reason {
            None | Some(RevocationReason::CertificateHold) => Err(ReasonNotAllowedForAction),
            Some(_) => match current {
                CertificateStatus::Valid => Ok(Transition::RevokeFromValid),
                CertificateStatus::Suspended => Ok(Transition::RevokeFromSuspended),
                CertificateStatus::Revoked => Err(TerminalState),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::{CertificateStatus, RevocationReason, StatusAction};

    const STATUSES: [CertificateStatus; 3] = [
        CertificateStatus::Valid,
        CertificateStatus::Suspended,
        CertificateStatus::Revoked,
    ];
    const ACTIONS: [StatusAction; 3] = [
        StatusAction::Suspend,
        StatusAction::Release,
        StatusAction::Revoke,
    ];

    fn reasons() -> Vec<Option<RevocationReason>> {
        let mut v = vec![None];
        for c in [0i16, 1, 2, 3, 4, 5, 6, 9, 10] {
            v.push(Some(RevocationReason::from_code(c).expect("known code")));
        }
        v
    }

    #[test]
    fn exhaustive_transition_table() {
        use CertificateStatus::*;
        use StatusAction::*;
        use StatusChangeError::*;
        for status in STATUSES {
            for action in ACTIONS {
                for reason in reasons() {
                    for allowed in [true, false] {
                        let hold = reason == Some(RevocationReason::CertificateHold);
                        let expected = match (status, action) {
                            (Revoked, _) => Err(TerminalState),
                            (Valid, Suspend) => match reason {
                                Some(_) if !hold => Err(ReasonNotAllowedForAction),
                                None => Err(ReasonNotAllowedForAction),
                                _ if !allowed => Err(SuspensionDisabled),
                                _ => Ok(Transition::Suspend),
                            },
                            (Suspended, Suspend) => {
                                if hold {
                                    Err(InvalidTransition)
                                } else {
                                    Err(ReasonNotAllowedForAction)
                                }
                            }
                            (Suspended, Release) => match reason {
                                None => Ok(Transition::Release),
                                Some(_) => Err(ReasonNotAllowedForAction),
                            },
                            (Valid, Release) => match reason {
                                None => Err(InvalidTransition),
                                Some(_) => Err(ReasonNotAllowedForAction),
                            },
                            (Valid, Revoke) => match reason {
                                Some(_) if !hold => Ok(Transition::RevokeFromValid),
                                _ => Err(ReasonNotAllowedForAction),
                            },
                            (Suspended, Revoke) => match reason {
                                Some(_) if !hold => Ok(Transition::RevokeFromSuspended),
                                _ => Err(ReasonNotAllowedForAction),
                            },
                        };
                        assert_eq!(
                            decide_status_change(status, action, reason, allowed),
                            expected,
                            "{status:?} {action:?} {reason:?} allowed={allowed}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn release_allowed_after_suspension_disabled() {
        assert_eq!(
            decide_status_change(
                CertificateStatus::Suspended,
                StatusAction::Release,
                None,
                false
            ),
            Ok(Transition::Release)
        );
    }

    #[test]
    fn revoke_from_suspended_with_hold_reason_rejected() {
        assert_eq!(
            decide_status_change(
                CertificateStatus::Suspended,
                StatusAction::Revoke,
                Some(RevocationReason::CertificateHold),
                true
            ),
            Err(StatusChangeError::ReasonNotAllowedForAction)
        );
    }

    #[test]
    fn invalidity_date_bounds() {
        let now = 1_800_000_000;
        let reject = Err(StatusChangeError::InvalidityDateOutOfRange);
        assert_eq!(check_invalidity_date(None, now), Ok(()));
        assert_eq!(check_invalidity_date(Some(0), now), Ok(()));
        assert_eq!(check_invalidity_date(Some(now), now), Ok(()));
        assert_eq!(check_invalidity_date(Some(now + 1), now), reject);
        assert_eq!(check_invalidity_date(Some(-1), now), reject);
        assert_eq!(check_invalidity_date(Some(-2_208_988_800), now), reject);
        assert_eq!(check_invalidity_date(Some(i64::MIN), now), reject);
        // beyond 9999-12-31 even with a clock that claims a later "now"
        assert_eq!(
            check_invalidity_date(Some(253_402_300_800), i64::MAX),
            reject
        );
        assert_eq!(
            check_invalidity_date(Some(253_402_300_799), i64::MAX),
            Ok(())
        );
    }
}
