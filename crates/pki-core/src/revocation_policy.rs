//! Pure status-change decision layer for the lab revocation slice.
//!
//! These are lab rules, re-checked by the database (migration 0014); this
//! module performs no I/O and is not an authorization decision.

use crate::revocation::{CertificateStatus, RevocationReason, StatusAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusChangeError {
    UnknownReason,
    ReasonNotAllowedForAction,
    SuspensionDisabled,
    InvalidTransition,
    TerminalState,
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
}
