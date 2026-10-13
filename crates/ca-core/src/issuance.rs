//! Issuance state machine (docs/architecture/issuance-state-machine.md, ADR-0002).

use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IssuanceState {
    Received,
    CsrValidated,
    Authorized,
    SerialReserved,
    Signing,
    Signed,
    Published,
    Rejected,
    FailedRetryable,
    FailedFinal,
    ReconciliationRequired,
    /// Serial burned; never reused. Preventively revoked when reached from
    /// `ReconciliationRequired`.
    Voided,
}

impl IssuanceState {
    pub const ALL: [Self; 12] = [
        Self::Received,
        Self::CsrValidated,
        Self::Authorized,
        Self::SerialReserved,
        Self::Signing,
        Self::Signed,
        Self::Published,
        Self::Rejected,
        Self::FailedRetryable,
        Self::FailedFinal,
        Self::ReconciliationRequired,
        Self::Voided,
    ];

    /// Allowed successor states. This table is the single source of truth.
    pub const fn successors(self) -> &'static [Self] {
        use IssuanceState::*;
        match self {
            Received => &[CsrValidated, Rejected],
            CsrValidated => &[Authorized, Rejected],
            Authorized => &[SerialReserved, Rejected],
            SerialReserved => &[Signing, Rejected, Voided],
            Signing => &[Signed, FailedRetryable, FailedFinal, ReconciliationRequired],
            Signed => &[Published],
            ReconciliationRequired => &[Signed, Voided],
            FailedRetryable => &[Voided],
            Published | Rejected | FailedFinal | Voided => &[],
        }
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        self.successors().contains(&next)
    }

    pub fn is_terminal(self) -> bool {
        self.successors().is_empty()
    }

    /// States in which a serial may have been used by a signature, so it must
    /// never be released.
    pub fn serial_possibly_used(self) -> bool {
        matches!(self, Self::Signing | Self::Signed | Self::Published | Self::ReconciliationRequired)
    }

    pub fn transition(self, next: Self) -> Result<Self, TransitionError> {
        if self.can_transition_to(next) { Ok(next) } else { Err(TransitionError { from: self, to: next }) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionError {
    pub from: IssuanceState,
    pub to: IssuanceState,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal issuance transition {:?} -> {:?}", self.from, self.to)
    }
}

impl std::error::Error for TransitionError {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::IssuanceState::*;
    use super::*;

    #[test]
    fn nominal_path() {
        let mut s = Received;
        for next in [CsrValidated, Authorized, SerialReserved, Signing, Signed, Published] {
            s = s.transition(next).unwrap();
        }
        assert!(s.is_terminal());
    }

    #[test]
    fn signing_cannot_be_retried_in_place() {
        // ADR-0002: never re-sign blindly; a retry is a new intent and a new serial.
        assert!(!FailedRetryable.can_transition_to(Signing));
        assert!(!ReconciliationRequired.can_transition_to(Signing));
        assert!(!Signing.can_transition_to(Signing));
    }

    #[test]
    fn no_signing_without_authorization_and_serial() {
        for s in IssuanceState::ALL {
            if s.can_transition_to(Signing) {
                assert_eq!(s, SerialReserved);
            }
        }
    }

    #[test]
    fn reconciliation_only_from_signing() {
        for s in IssuanceState::ALL {
            if s.can_transition_to(ReconciliationRequired) {
                assert_eq!(s, Signing);
            }
        }
    }

    #[test]
    fn terminal_states() {
        let terminals: Vec<_> = IssuanceState::ALL.into_iter().filter(|s| s.is_terminal()).collect();
        assert_eq!(terminals, vec![Published, Rejected, FailedFinal, Voided]);
    }

    #[test]
    fn every_non_initial_state_is_reachable() {
        for target in IssuanceState::ALL.into_iter().filter(|s| *s != Received) {
            assert!(IssuanceState::ALL.iter().any(|s| s.can_transition_to(target)), "{target:?}");
        }
    }
}
