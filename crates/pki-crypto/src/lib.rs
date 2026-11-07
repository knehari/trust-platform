#![forbid(unsafe_code)]
// Production code returns errors; `expect` is reserved for documented invariants.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
//! Signing boundary and algorithm negotiation.
//! No signing provider is enabled in production builds.

pub mod algorithm_catalog;
pub mod certificate_algorithm_binding;
pub mod crypto_agility;
#[cfg(feature = "lab-software")]
pub mod ecdsa_p256_lab;
pub mod issuer_key_binding;
#[cfg(feature = "lab-software")]
pub mod lab;
pub mod legacy_algorithm_bridge;
#[cfg(feature = "lab-software")]
pub mod multi_algorithm_lab;
#[cfg(all(feature = "lab-software", unix))]
pub mod openssl_classical_lab;
pub mod provider_capabilities;
pub mod provider_deployment;
#[cfg(feature = "lab-software")]
pub mod rsa_pkcs1_lab;
#[cfg(feature = "lab-software")]
pub mod rsa_pss_agile_lab;
#[cfg(feature = "lab-software")]
pub mod rsa_pss_lab;
pub mod rsa_pss_profile;
pub mod suite_registry;
pub mod typed_algorithm_catalog;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    RsaPssSha256,
    EcdsaP256Sha256,
    MlDsa65,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    UnsupportedAlgorithm,
    KeyUnavailable,
    SigningFailed,
    InvalidPublicKey,
    InvalidSignature,
}

/// Never passes key material to application callers.
/// Provider-specific encoding and prehash rules must be defined by the adapter.
pub trait SigningProvider {
    fn supports(&self, algorithm: SignatureAlgorithm) -> bool;
    fn public_key_spki_der(&self, key: &KeyRef) -> Result<Vec<u8>, CryptoError>;
    fn sign(
        &self,
        key: &KeyRef,
        algorithm: SignatureAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Fail-closed placeholder. The absence of a provider is NEVER a software-key fallback.
pub struct UnconfiguredProvider;

impl SigningProvider for UnconfiguredProvider {
    fn supports(&self, _algorithm: SignatureAlgorithm) -> bool {
        false
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

/// Canonicalize a P-256 SEC1 public key before checking identity or provisioning
/// independent policy-review keys. Both compressed and uncompressed representations
/// of one curve point yield the same 33-byte canonical representation.
pub fn canonical_p256_public_key_sec1(public_key_sec1: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use p256::ecdsa::VerifyingKey;

    let key = VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    Ok(key.to_encoded_point(true).as_bytes().to_vec())
}

/// Verify a PKCS#10 ECDSA-with-SHA256 signature over canonical DER bytes.
///
/// The caller MUST check the CSR SignatureAlgorithm OID and the SPKI curve
/// parameters before calling this function. No generic algorithm fallback.
pub fn verify_p256_ecdsa_sha256(
    public_key_sec1: &[u8],
    signed_message: &[u8],
    der_signature: &[u8],
) -> Result<(), CryptoError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature =
        Signature::from_der(der_signature).map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify(signed_message, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_unconfigured_algorithm_is_rejected() {
        let provider = UnconfiguredProvider;
        for algorithm in [
            SignatureAlgorithm::RsaPssSha256,
            SignatureAlgorithm::EcdsaP256Sha256,
            SignatureAlgorithm::MlDsa65,
        ] {
            assert!(!provider.supports(algorithm));
            assert_eq!(
                provider.sign(&KeyRef("test-key".into()), algorithm, b"tbs"),
                Err(CryptoError::SigningFailed)
            );
        }
    }

    #[test]
    fn unconfigured_provider_never_exposes_a_public_key_or_secret() {
        let provider = UnconfiguredProvider;
        assert_eq!(
            provider.public_key_spki_der(&KeyRef("missing".into())),
            Err(CryptoError::KeyUnavailable)
        );
    }
}
