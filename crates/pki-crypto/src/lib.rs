#![forbid(unsafe_code)]
//! Signing boundary: interfaces only; no real keys or crypto primitives.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

pub trait SigningProvider {
    fn supports(&self, algorithm: SignatureAlgorithm) -> bool;
    fn public_key_spki_der(&self, key: &KeyRef) -> Result<Vec<u8>, CryptoError>;
    /// Input semantics must be defined per algorithm by the adapter.
    fn sign(&self, key: &KeyRef, algorithm: SignatureAlgorithm, message: &[u8])
        -> Result<Vec<u8>, CryptoError>;
}

/// Fail-closed placeholder, never returns a signature.
pub struct UnconfiguredProvider;

impl SigningProvider for UnconfiguredProvider {
    fn supports(&self, _algorithm: SignatureAlgorithm) -> bool { false }
    fn public_key_spki_der(&self, _key: &KeyRef) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::KeyUnavailable)
    }
    fn sign(&self, _key: &KeyRef, _algorithm: SignatureAlgorithm, _message: &[u8])
        -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::SigningFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_signing_without_provider() {
        let provider = UnconfiguredProvider;
        assert!(!provider.supports(SignatureAlgorithm::MlDsa65));
        assert_eq!(provider.sign(&KeyRef("test".into()), SignatureAlgorithm::MlDsa65, b"data"),
            Err(CryptoError::SigningFailed));
    }
}
