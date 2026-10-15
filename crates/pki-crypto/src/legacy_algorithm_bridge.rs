//! Explicit migration bridge; never infer an RSA key size from a legacy identifier.
use crate::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};
use crate::SignatureAlgorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyBridgeError {
    AmbiguousRsaKeySize,
    NotRepresentable,
}

/// Legacy RSA-PSS omits key size, so conversion must fail closed.
pub const fn legacy_suite(
    algorithm: SignatureAlgorithm,
) -> Result<AlgorithmSuite, LegacyBridgeError> {
    match algorithm {
        SignatureAlgorithm::RsaPssSha256 => Err(LegacyBridgeError::AmbiguousRsaKeySize),
        SignatureAlgorithm::EcdsaP256Sha256 => Ok(AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P256,
            digest: Digest::Sha256,
        }),
        SignatureAlgorithm::MlDsa65 => Ok(AlgorithmSuite {
            scheme: SignatureScheme::MlDsa,
            key: KeyParameter::MlDsa65,
            digest: Digest::Intrinsic,
        }),
    }
}

pub fn legacy_identifier(
    suite: AlgorithmSuite,
) -> Result<SignatureAlgorithm, LegacyBridgeError> {
    match (suite.scheme, suite.key, suite.digest) {
        (SignatureScheme::Ecdsa, KeyParameter::P256, Digest::Sha256) => {
            Ok(SignatureAlgorithm::EcdsaP256Sha256)
        }
        (SignatureScheme::MlDsa, KeyParameter::MlDsa65, Digest::Intrinsic) => {
            Ok(SignatureAlgorithm::MlDsa65)
        }
        (
            SignatureScheme::RsaPss,
            KeyParameter::Rsa2048
            | KeyParameter::Rsa3072
            | KeyParameter::Rsa4096
            | KeyParameter::Rsa8192,
            Digest::Sha256,
        ) => Err(LegacyBridgeError::AmbiguousRsaKeySize),
        _ => Err(LegacyBridgeError::NotRepresentable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_mapping_is_explicit() {
        assert_eq!(
            legacy_suite(SignatureAlgorithm::EcdsaP256Sha256)
                .unwrap()
                .key,
            KeyParameter::P256
        );
        assert_eq!(
            legacy_suite(SignatureAlgorithm::MlDsa65)
                .unwrap()
                .scheme,
            SignatureScheme::MlDsa
        );
    }

    #[test]
    fn rsa_size_is_never_inferred_on_round_trip() {
        assert_eq!(
            legacy_suite(SignatureAlgorithm::RsaPssSha256),
            Err(LegacyBridgeError::AmbiguousRsaKeySize)
        );
        let ecc = AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P384,
            digest: Digest::Sha384,
        };
        assert_eq!(
            legacy_identifier(ecc),
            Err(LegacyBridgeError::NotRepresentable)
        );
    }
}
