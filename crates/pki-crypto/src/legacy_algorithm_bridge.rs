//! Backwards-compatible bridge from the legacy fixed signing identifiers into
//! the versioned algorithm-suite model. This cannot grant production readiness.
use crate::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};
use crate::SignatureAlgorithm;

/// Legacy identifiers are deliberately limited to the already-existing use cases.
/// New algorithm suites must NOT be coerced to a "nearest" old enum.
pub const fn legacy_suite(algorithm: SignatureAlgorithm) -> AlgorithmSuite {
    match algorithm {
        SignatureAlgorithm::RsaPssSha256 => AlgorithmSuite {
            scheme: SignatureScheme::RsaPss,
            key: KeyParameter::Rsa3072,
            digest: Digest::Sha256,
        },
        SignatureAlgorithm::EcdsaP256Sha256 => AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P256,
            digest: Digest::Sha256,
        },
        SignatureAlgorithm::MlDsa65 => AlgorithmSuite {
            scheme: SignatureScheme::MlDsa,
            key: KeyParameter::MlDsa65,
            digest: Digest::Intrinsic,
        },
    }
}

/// No generalized downcast is possible: the legacy RSA name does not carry the
/// key size. Require a typed parameterized path for all new issuances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyBridgeError { AmbiguousRsaKeySize, NotRepresentable }

pub fn legacy_identifier(suite: AlgorithmSuite) -> Result<SignatureAlgorithm, LegacyBridgeError> {
    match (suite.scheme, suite.key, suite.digest) {
        (SignatureScheme::Ecdsa, KeyParameter::P256, Digest::Sha256) =>
            Ok(SignatureAlgorithm::EcdsaP256Sha256),
        (SignatureScheme::MlDsa, KeyParameter::MlDsa65, Digest::Intrinsic) =>
            Ok(SignatureAlgorithm::MlDsa65),
        (SignatureScheme::RsaPss, KeyParameter::Rsa2048 | KeyParameter::Rsa3072 |
         KeyParameter::Rsa4096 | KeyParameter::Rsa8192, Digest::Sha256) =>
            Err(LegacyBridgeError::AmbiguousRsaKeySize),
        _ => Err(LegacyBridgeError::NotRepresentable),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_mapping_is_explicit() {
        assert_eq!(legacy_suite(SignatureAlgorithm::EcdsaP256Sha256).key, KeyParameter::P256);
        assert_eq!(legacy_suite(SignatureAlgorithm::MlDsa65).scheme, SignatureScheme::MlDsa);
    }
    #[test]
    fn rsa_size_is_never_inferred_on_round_trip() {
        assert_eq!(legacy_identifier(legacy_suite(SignatureAlgorithm::RsaPssSha256)),
                   Err(LegacyBridgeError::AmbiguousRsaKeySize));
        let ecc = AlgorithmSuite { scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P384, digest: Digest::Sha384 };
        assert_eq!(legacy_identifier(ecc), Err(LegacyBridgeError::NotRepresentable));
    }
}
