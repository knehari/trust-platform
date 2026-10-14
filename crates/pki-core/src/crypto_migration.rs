#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationError {
    NoApprovedTarget,
    UnsupportedProvider,
    MissingRollbackPlan,
}
#[derive(Debug, Clone, Copy)]
pub struct MigrationDecision {
    pub target_approved: bool,
    pub provider_supported: bool,
    pub rollback_tested: bool,
}
pub fn authorize_migration(d: MigrationDecision) -> Result<(), MigrationError> {
    if !d.target_approved {
        return Err(MigrationError::NoApprovedTarget);
    }
    if !d.provider_supported {
        return Err(MigrationError::UnsupportedProvider);
    }
    if !d.rollback_tested {
        return Err(MigrationError::MissingRollbackPlan);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsupported_targets() {
        assert_eq!(
            authorize_migration(MigrationDecision {
                target_approved: false,
                provider_supported: true,
                rollback_tested: true
            }),
            Err(MigrationError::NoApprovedTarget)
        );
    }
}
