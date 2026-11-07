//! Shared implementation routing for typed laboratory suites.
//! Registration describes code, not successful conformance, CSR, X.509 profile,
//! durable issuance, key custody, or production qualification. Those require
//! independent evidence for the exact provider/key/digest/profile combination.
use crate::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaboratoryBackend {
    RustCrypto,
    OpenSsl3,
}

/// Source-level implementation route. RSA sizes are separate suite identities;
/// registering RSA8192 does not claim it has passed positive interoperability.
pub const fn registered_backend(suite: AlgorithmSuite) -> Option<LaboratoryBackend> {
    use Digest::{Intrinsic, Sha256, Sha384, Sha512};
    use KeyParameter::{Rsa2048, Rsa3072, Rsa4096, Rsa8192, P256, P384, P521};
    use SignatureScheme::{Ecdsa, RsaPkcs1V15, RsaPss};
    match (suite.scheme, suite.key, suite.digest) {
        (RsaPss | RsaPkcs1V15, Rsa2048 | Rsa3072 | Rsa4096 | Rsa8192, Sha256 | Sha384 | Sha512)
        | (Ecdsa, P256, Sha256) => Some(LaboratoryBackend::RustCrypto),
        (Ecdsa, P384, Sha384)
        | (Ecdsa, P521, Sha512)
        | (SignatureScheme::Ed25519, KeyParameter::Ed25519, Intrinsic)
        | (SignatureScheme::Ed448, KeyParameter::Ed448, Intrinsic) => {
            Some(LaboratoryBackend::OpenSsl3)
        }
        _ => None,
    }
}

/// Compiled implementation availability. This does not probe the OpenSSL binary
/// or authorize a key/policy. Missing features never enable software fallback.
pub const fn compiled_backend(suite: AlgorithmSuite) -> Option<LaboratoryBackend> {
    if !cfg!(feature = "lab-software") {
        return None;
    }
    match registered_backend(suite) {
        Some(LaboratoryBackend::OpenSsl3) if !cfg!(unix) => None,
        backend => backend,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed_algorithm_catalog::{planned_classical_suites, production_enabled};

    #[test]
    fn implementation_does_not_promote_candidate_qualification() {
        for record in planned_classical_suites() {
            assert!(registered_backend(record.suite).is_some());
            assert!(!production_enabled(&record));
            if !cfg!(feature = "lab-software") {
                assert_eq!(compiled_backend(record.suite), None);
            }
        }
    }

    #[test]
    fn invalid_suites_and_pqc_have_no_signing_route() {
        for suite in [
            AlgorithmSuite {
                scheme: SignatureScheme::Ecdsa,
                key: KeyParameter::P256,
                digest: Digest::Sha512,
            },
            AlgorithmSuite {
                scheme: SignatureScheme::MlDsa,
                key: KeyParameter::MlDsa65,
                digest: Digest::Intrinsic,
            },
        ] {
            assert_eq!(registered_backend(suite), None);
            assert_eq!(compiled_backend(suite), None);
        }
    }
}
