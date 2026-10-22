#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDecision {
    ReturnPersisted,
    ReconcileManually,
    RejectUnknownOperation,
}
pub fn decide_recovery(
    intent_recorded: bool,
    certificate_persisted: bool,
    operation_known: bool,
) -> RecoveryDecision {
    if certificate_persisted && intent_recorded {
        return RecoveryDecision::ReturnPersisted;
    }
    if !operation_known {
        return RecoveryDecision::RejectUnknownOperation;
    }
    RecoveryDecision::ReconcileManually
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncertainty_never_resigns() {
        assert_eq!(
            decide_recovery(true, false, true),
            RecoveryDecision::ReconcileManually
        );
        assert_eq!(
            decide_recovery(true, true, true),
            RecoveryDecision::ReturnPersisted
        );
    }
}
