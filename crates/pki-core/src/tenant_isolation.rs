//! Pure preflight contract. Requires independently authenticated inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightError {
    MissingTenant,
    CrossTenant,
    MissingRole,
}
pub fn check(tenant: &str, resource_tenant: &str, allowed_role: bool) -> Result<(), PreflightError> {
    if tenant.is_empty() {
        return Err(PreflightError::MissingTenant);
    }
    if tenant != resource_tenant {
        return Err(PreflightError::CrossTenant);
    }
    if !allowed_role {
        return Err(PreflightError::MissingRole);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_missing_first_requirement() {
        assert_eq!(
            check( "", "tenant-b", true),
            Err(PreflightError::MissingTenant)
        );
    }
}
