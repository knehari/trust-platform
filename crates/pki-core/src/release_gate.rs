//! A fail-closed release gate model, not itself a legal or security approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    LegalClearance,
    SecurityReview,
    HardwareKeyCustody,
    Recovery,
    AuditEvidence,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct ReleaseEvidence {
    pub legal_ip_approved: bool,
    pub independent_security_review: bool,
    pub hardware_key_custody_verified: bool,
    pub operational_recovery_tested: bool,
    pub independently_anchored_audit: bool,
}
pub fn evaluate_release(e: ReleaseEvidence) -> Result<(), GateError> {
    if !e.legal_ip_approved {
        return Err(GateError::LegalClearance);
    }
    if !e.independent_security_review {
        return Err(GateError::SecurityReview);
    }
    if !e.hardware_key_custody_verified {
        return Err(GateError::HardwareKeyCustody);
    }
    if !e.operational_recovery_tested {
        return Err(GateError::Recovery);
    }
    if !e.independently_anchored_audit {
        return Err(GateError::AuditEvidence);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_requires_all_independent_gates() {
        assert_eq!(
            evaluate_release(ReleaseEvidence::default()),
            Err(GateError::LegalClearance)
        );
        let mut e = ReleaseEvidence {
            legal_ip_approved: true,
            independent_security_review: true,
            hardware_key_custody_verified: true,
            operational_recovery_tested: true,
            independently_anchored_audit: true,
        };
        assert!(evaluate_release(e).is_ok());
        e.independently_anchored_audit = false;
        assert_eq!(evaluate_release(e), Err(GateError::AuditEvidence));
    }
}
