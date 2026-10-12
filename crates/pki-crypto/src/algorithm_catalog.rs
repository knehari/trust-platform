//! Crypto-agility discovery and selection rules.
//! A catalogue entry is NOT an implementation or an approval for X.509 issuance.
use crate::{SignatureAlgorithm, SigningProvider};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoFamily {
    Classical,
    PostQuantum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImplementationStatus {
    LabOnly,
    NotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmDescriptor {
    pub algorithm: SignatureAlgorithm,
    pub family: CryptoFamily,
    pub implementation: ImplementationStatus,
    pub identifier: &'static str,
}

/// Conservative built-in discovery catalogue. Extend through reviewed releases;
/// do not infer support from a string, OID, provider advertisement or policy alone.
pub const ALGORITHMS: [AlgorithmDescriptor; 3] = [
    AlgorithmDescriptor {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        family: CryptoFamily::Classical,
        implementation: ImplementationStatus::LabOnly,
        identifier: "ecdsa-p256-sha256",
    },
    AlgorithmDescriptor {
        algorithm: SignatureAlgorithm::RsaPssSha256,
        family: CryptoFamily::Classical,
        implementation: ImplementationStatus::NotImplemented,
        identifier: "rsa-pss-sha256",
    },
    AlgorithmDescriptor {
        algorithm: SignatureAlgorithm::MlDsa65,
        family: CryptoFamily::PostQuantum,
        implementation: ImplementationStatus::NotImplemented,
        identifier: "ml-dsa-65",
    },
];

pub fn descriptor(algorithm: SignatureAlgorithm) -> &'static AlgorithmDescriptor {
    ALGORITHMS
        .iter()
        .find(|entry| entry.algorithm == algorithm)
        .expect("known algorithm enum must have a catalogue descriptor")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmSelectionError {
    ForbiddenByPolicy,
    Unimplemented,
    UnsupportedByProvider,
}

/// Fail closed. No algorithm fallback or silent classical downgrade.
/// LabOnly never means production ready.
pub fn select_lab_algorithm(
    provider: &impl SigningProvider,
    algorithm: SignatureAlgorithm,
    policy_allowlist: &[SignatureAlgorithm],
) -> Result<&'static AlgorithmDescriptor, AlgorithmSelectionError> {
    if !policy_allowlist.contains(&algorithm) {
        return Err(AlgorithmSelectionError::ForbiddenByPolicy);
    }
    let selected = descriptor(algorithm);
    if selected.implementation != ImplementationStatus::LabOnly {
        return Err(AlgorithmSelectionError::Unimplemented);
    }
    if !provider.supports(algorithm) {
        return Err(AlgorithmSelectionError::UnsupportedByProvider);
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CryptoError, KeyRef, UnconfiguredProvider};

    struct AdvertisedProvider;
    impl SigningProvider for AdvertisedProvider {
        fn supports(&self, _algorithm: SignatureAlgorithm) -> bool {
            true
        }
        fn public_key_spki_der(&self, _key: &KeyRef) -> Result<Vec<u8>, CryptoError> {
            Err(CryptoError::KeyUnavailable)
        }
        fn sign(
            &self,
            _key: &KeyRef,
            _algorithm: SignatureAlgorithm,
            _message: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            Err(CryptoError::SigningFailed)
        }
    }

    #[test]
    fn known_but_unimplemented_algorithms_never_become_available() {
        let provider = AdvertisedProvider;
        for algorithm in [SignatureAlgorithm::RsaPssSha256, SignatureAlgorithm::MlDsa65] {
            assert_eq!(
                select_lab_algorithm(&provider, algorithm, &[algorithm]),
                Err(AlgorithmSelectionError::Unimplemented)
            );
        }
    }

    #[test]
    fn no_implicit_fallback_from_an_unavailable_provider() {
        let provider = UnconfiguredProvider;
        assert_eq!(
            select_lab_algorithm(
                &provider,
                SignatureAlgorithm::EcdsaP256Sha256,
                &[SignatureAlgorithm::EcdsaP256Sha256]
            ),
            Err(AlgorithmSelectionError::UnsupportedByProvider)
        );
    }

    #[test]
    fn policy_denial_precedes_provider_capabilities() {
        assert_eq!(
            select_lab_algorithm(&AdvertisedProvider, SignatureAlgorithm::EcdsaP256Sha256, &[]),
            Err(AlgorithmSelectionError::ForbiddenByPolicy)
        );
    }

    #[test]
    fn catalogue_explicitly_marks_pqc_unimplemented() {
        assert_eq!(descriptor(SignatureAlgorithm::MlDsa65).family, CryptoFamily::PostQuantum);
        assert_eq!(
            descriptor(SignatureAlgorithm::MlDsa65).implementation,
            ImplementationStatus::NotImplemented
        );
    }
}
