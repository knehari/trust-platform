//! Fine-grained cryptographic capability negotiation (laboratory).
//! Declared operations are NOT trusted evidence of provider implementation.
use crate::algorithm_catalog::{descriptor, ImplementationStatus};
use crate::SignatureAlgorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoOperation {
    GenerateKey,
    Sign,
    Verify,
    ExportPublicKeySpki,
    EncodeX509Certificate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    DeniedByPolicy,
    UnimplementedAlgorithm,
    MissingProviderOperation,
    MissingCertificateProfile,
}

/// Explicit trusted deployment configuration; the caller must independently
/// verify claims through adapter conformance tests before enabling any operation.
#[derive(Debug, Clone)]
pub struct ProviderCapabilities<'a> {
    pub algorithm: SignatureAlgorithm,
    pub operations: &'a [CryptoOperation],
}

#[derive(Debug, Clone)]
pub struct CryptoOperationPolicy<'a> {
    pub allowed_algorithms: &'a [SignatureAlgorithm],
    pub required_operations: &'a [CryptoOperation],
    pub certificate_profile_verified: bool,
}

/// Conservative negotiation for the existing laboratory issuer.
/// A provider claim cannot change an unimplemented algorithm into a supported one.
pub fn evaluate_lab_capabilities(
    capabilities: &ProviderCapabilities<'_>,
    policy: &CryptoOperationPolicy<'_>,
) -> Result<(), CapabilityError> {
    if !policy.allowed_algorithms.contains(&capabilities.algorithm) {
        return Err(CapabilityError::DeniedByPolicy);
    }
    if descriptor(capabilities.algorithm).implementation != ImplementationStatus::LabOnly {
        return Err(CapabilityError::UnimplementedAlgorithm);
    }
    if policy
        .required_operations
        .iter()
        .any(|operation| !capabilities.operations.contains(operation))
    {
        return Err(CapabilityError::MissingProviderOperation);
    }
    if policy
        .required_operations
        .contains(&CryptoOperation::EncodeX509Certificate)
        && !policy.certificate_profile_verified
    {
        return Err(CapabilityError::MissingCertificateProfile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_required_operations_must_be_explicit() {
        let operations = [CryptoOperation::Sign, CryptoOperation::Verify];
        let caps = ProviderCapabilities {
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            operations: &operations,
        };
        let required = [CryptoOperation::Sign, CryptoOperation::GenerateKey];
        let allowed = [SignatureAlgorithm::EcdsaP256Sha256];
        let policy = CryptoOperationPolicy {
            allowed_algorithms: &allowed,
            required_operations: &required,
            certificate_profile_verified: false,
        };
        assert_eq!(
            evaluate_lab_capabilities(&caps, &policy),
            Err(CapabilityError::MissingProviderOperation)
        );
    }

    #[test]
    fn provider_advertisement_cannot_enable_pqc() {
        let operations = [
            CryptoOperation::GenerateKey,
            CryptoOperation::Sign,
            CryptoOperation::Verify,
            CryptoOperation::ExportPublicKeySpki,
            CryptoOperation::EncodeX509Certificate,
        ];
        let caps = ProviderCapabilities {
            algorithm: SignatureAlgorithm::MlDsa65,
            operations: &operations,
        };
        let allowed = [SignatureAlgorithm::MlDsa65];
        let policy = CryptoOperationPolicy {
            allowed_algorithms: &allowed,
            required_operations: &operations,
            certificate_profile_verified: true,
        };
        assert_eq!(
            evaluate_lab_capabilities(&caps, &policy),
            Err(CapabilityError::UnimplementedAlgorithm)
        );
    }

    #[test]
    fn certificate_profile_is_independent_of_signing_capability() {
        let operations = [
            CryptoOperation::Sign,
            CryptoOperation::EncodeX509Certificate,
        ];
        let caps = ProviderCapabilities {
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            operations: &operations,
        };
        let allowed = [SignatureAlgorithm::EcdsaP256Sha256];
        let policy = CryptoOperationPolicy {
            allowed_algorithms: &allowed,
            required_operations: &operations,
            certificate_profile_verified: false,
        };
        assert_eq!(
            evaluate_lab_capabilities(&caps, &policy),
            Err(CapabilityError::MissingCertificateProfile)
        );
    }
}
