//! Provider deployment boundary (lab contracts only).
//! Provider attestations are declarations, not cryptographic evidence.
use crate::provider_capabilities::{evaluate_lab_capabilities, CapabilityError, CryptoOperationPolicy, ProviderCapabilities};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    EphemeralSoftwareLab,
    Pkcs11Hsm,
    CloudKms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyClass {
    VolatileSoftware,
    ExternalNonExportable,
}

#[derive(Debug, Clone)]
pub struct ProviderDeployment<'a> {
    pub provider_id: &'a str,
    pub kind: ProviderKind,
    pub custody: CustodyClass,
    pub capabilities: ProviderCapabilities<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSelectionError {
    InvalidProviderIdentity,
    ProductionProviderUnavailable,
    IncompatibleCustody,
    Capability(CapabilityError),
}

/// Explicitly lab-only: hardware and cloud backends are not wired up.
/// Production callers must NOT use this function as provider attestation.
pub fn select_lab_provider(
    provider: &ProviderDeployment<'_>,
    policy: &CryptoOperationPolicy<'_>,
) -> Result<(), ProviderSelectionError> {
    if provider.provider_id.is_empty()
        || provider.provider_id.len() > 128
        || !provider.provider_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(ProviderSelectionError::InvalidProviderIdentity);
    }
    if provider.kind != ProviderKind::EphemeralSoftwareLab {
        return Err(ProviderSelectionError::ProductionProviderUnavailable);
    }
    if provider.custody != CustodyClass::VolatileSoftware {
        return Err(ProviderSelectionError::IncompatibleCustody);
    }
    evaluate_lab_capabilities(&provider.capabilities, policy)
        .map_err(ProviderSelectionError::Capability)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{provider_capabilities::CryptoOperation, SignatureAlgorithm};

    #[test]
    fn rejects_fake_hardware_and_cloud_advertisements() {
        let operations = [CryptoOperation::Sign];
        let allowed = [SignatureAlgorithm::EcdsaP256Sha256];
        let policy = CryptoOperationPolicy {
            allowed_algorithms: &allowed,
            required_operations: &operations,
            certificate_profile_verified: false,
        };
        let mut provider = ProviderDeployment {
            provider_id: "hsm-1",
            kind: ProviderKind::Pkcs11Hsm,
            custody: CustodyClass::ExternalNonExportable,
            capabilities: ProviderCapabilities {
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
                operations: &operations,
            },
        };
        assert_eq!(
            select_lab_provider(&provider, &policy),
            Err(ProviderSelectionError::ProductionProviderUnavailable)
        );
        provider.kind = ProviderKind::CloudKms;
        assert_eq!(
            select_lab_provider(&provider, &policy),
            Err(ProviderSelectionError::ProductionProviderUnavailable)
        );
        provider.kind = ProviderKind::EphemeralSoftwareLab;
        assert_eq!(
            select_lab_provider(&provider, &policy),
            Err(ProviderSelectionError::IncompatibleCustody)
        );
        provider.custody = CustodyClass::VolatileSoftware;
        assert_eq!(select_lab_provider(&provider, &policy), Ok(()));
    }

    #[test]
    fn rejects_malformed_deployment_id() {
        let operations = [CryptoOperation::Sign];
        let allowed = [SignatureAlgorithm::EcdsaP256Sha256];
        let policy = CryptoOperationPolicy {
            allowed_algorithms: &allowed,
            required_operations: &operations,
            certificate_profile_verified: false,
        };
        let provider = ProviderDeployment {
            provider_id: "untrusted\nbackend",
            kind: ProviderKind::EphemeralSoftwareLab,
            custody: CustodyClass::VolatileSoftware,
            capabilities: ProviderCapabilities {
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
                operations: &operations,
            },
        };
        assert_eq!(
            select_lab_provider(&provider, &policy),
            Err(ProviderSelectionError::InvalidProviderIdentity)
        );
    }
}
