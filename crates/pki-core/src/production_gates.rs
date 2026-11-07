#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionGateError {
    MissingIdentity,
    MissingHardware,
    MissingAudit,
    MissingSecurityApproval,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct ProductionEvidence {
    pub identity_boundary_tested: bool,
    pub hardware_key_custody_verified: bool,
    pub independent_audit_export_verified: bool,
    pub independent_security_approval: bool,
}
pub fn authorize_production(e: ProductionEvidence) -> Result<(), ProductionGateError> {
    if !e.identity_boundary_tested {
        return Err(ProductionGateError::MissingIdentity);
    }
    if !e.hardware_key_custody_verified {
        return Err(ProductionGateError::MissingHardware);
    }
    if !e.independent_audit_export_verified {
        return Err(ProductionGateError::MissingAudit);
    }
    if !e.independent_security_approval {
        return Err(ProductionGateError::MissingSecurityApproval);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_to_denial() {
        assert_eq!(
            authorize_production(ProductionEvidence::default()),
            Err(ProductionGateError::MissingIdentity)
        );
    }
}
