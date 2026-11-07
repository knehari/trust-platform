//! Algorithm-neutral policy contract, not a signing implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    RsaPss,
    RsaPkcs1V15,
    Ecdsa,
    Ed25519,
    Ed448,
    MlDsa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyParameter {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Rsa8192,
    P256,
    P384,
    P521,
    Ed25519,
    Ed448,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Digest {
    Sha256,
    Sha384,
    Sha512,
    Intrinsic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlgorithmSuite {
    pub scheme: SignatureScheme,
    pub key: KeyParameter,
    pub digest: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAgilityError {
    InvalidCombination,
    PolicyDenied,
    UnsupportedProvider,
    NotConformanceTested,
    ProfileDenied,
}

pub fn validate_suite(s: AlgorithmSuite) -> Result<(), CryptoAgilityError> {
    use Digest::*;
    use KeyParameter::*;
    use SignatureScheme::{Ecdsa, RsaPkcs1V15, RsaPss};

    let valid = matches!(
        (s.scheme, s.key, s.digest),
        (
            RsaPss | RsaPkcs1V15,
            Rsa2048 | Rsa3072 | Rsa4096 | Rsa8192,
            Sha256 | Sha384 | Sha512
        ) | (Ecdsa, P256, Sha256)
            | (Ecdsa, P384, Sha384)
            | (Ecdsa, P521, Sha512)
            | (SignatureScheme::Ed25519, KeyParameter::Ed25519, Intrinsic)
            | (SignatureScheme::Ed448, KeyParameter::Ed448, Intrinsic)
            | (
                SignatureScheme::MlDsa,
                MlDsa44 | MlDsa65 | MlDsa87,
                Intrinsic
            )
    );
    if valid {
        Ok(())
    } else {
        Err(CryptoAgilityError::InvalidCombination)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    GenerateKey,
    Sign,
    Verify,
    ExportSpki,
    EncodeX509,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderSuite<'a> {
    pub suite: AlgorithmSuite,
    pub supported_operations: &'a [Operation],
    pub conformance_verified: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SuitePolicy<'a> {
    pub allowed_suites: &'a [AlgorithmSuite],
    pub required_operations: &'a [Operation],
    pub x509_profile_approved: bool,
}

/// Fail closed: callers must authenticate configuration and provider evidence.
pub fn authorize_suite(
    requested: AlgorithmSuite,
    provider: &ProviderSuite<'_>,
    policy: &SuitePolicy<'_>,
) -> Result<(), CryptoAgilityError> {
    validate_suite(requested)?;
    if !policy.allowed_suites.contains(&requested) || policy.required_operations.is_empty() {
        return Err(CryptoAgilityError::PolicyDenied);
    }
    if requested != provider.suite
        || policy
            .required_operations
            .iter()
            .any(|op| !provider.supported_operations.contains(op))
    {
        return Err(CryptoAgilityError::UnsupportedProvider);
    }
    if !provider.conformance_verified {
        return Err(CryptoAgilityError::NotConformanceTested);
    }
    if !policy.x509_profile_approved {
        return Err(CryptoAgilityError::ProfileDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA: AlgorithmSuite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPss,
        key: KeyParameter::Rsa4096,
        digest: Digest::Sha384,
    };

    #[test]
    fn classical_suites_are_structurally_extensible() {
        for key in [
            KeyParameter::Rsa2048,
            KeyParameter::Rsa3072,
            KeyParameter::Rsa4096,
            KeyParameter::Rsa8192,
        ] {
            assert!(validate_suite(AlgorithmSuite {
                scheme: SignatureScheme::RsaPss,
                key,
                digest: Digest::Sha256,
            })
            .is_ok());
        }
        for (key, digest) in [
            (KeyParameter::P256, Digest::Sha256),
            (KeyParameter::P384, Digest::Sha384),
            (KeyParameter::P521, Digest::Sha512),
        ] {
            assert!(validate_suite(AlgorithmSuite {
                scheme: SignatureScheme::Ecdsa,
                key,
                digest,
            })
            .is_ok());
        }
    }

    #[test]
    fn invalid_combinations_rejected() {
        for suite in [
            AlgorithmSuite {
                scheme: SignatureScheme::Ecdsa,
                key: KeyParameter::P256,
                digest: Digest::Sha512,
            },
            AlgorithmSuite {
                scheme: SignatureScheme::RsaPss,
                key: KeyParameter::P384,
                digest: Digest::Sha384,
            },
            AlgorithmSuite {
                scheme: SignatureScheme::Ed25519,
                key: KeyParameter::Ed25519,
                digest: Digest::Sha256,
            },
        ] {
            assert_eq!(
                validate_suite(suite),
                Err(CryptoAgilityError::InvalidCombination)
            );
        }
    }

    #[test]
    fn provider_requires_explicit_conformance() {
        let ops = [Operation::Sign, Operation::Verify];
        let provider = ProviderSuite {
            suite: RSA,
            supported_operations: &ops,
            conformance_verified: false,
        };
        let policy = SuitePolicy {
            allowed_suites: &[RSA],
            required_operations: &ops,
            x509_profile_approved: true,
        };
        assert_eq!(
            authorize_suite(RSA, &provider, &policy),
            Err(CryptoAgilityError::NotConformanceTested)
        );
        let verified = ProviderSuite {
            conformance_verified: true,
            ..provider
        };
        assert_eq!(authorize_suite(RSA, &verified, &policy), Ok(()));
    }

    #[test]
    fn no_policy_fallback_or_missing_operations() {
        let ops = [Operation::Sign];
        let provider = ProviderSuite {
            suite: RSA,
            supported_operations: &ops,
            conformance_verified: true,
        };
        let required = [Operation::Sign, Operation::Verify];
        let policy = SuitePolicy {
            allowed_suites: &[RSA],
            required_operations: &required,
            x509_profile_approved: true,
        };
        assert_eq!(
            authorize_suite(RSA, &provider, &policy),
            Err(CryptoAgilityError::UnsupportedProvider)
        );
        let other = AlgorithmSuite {
            key: KeyParameter::Rsa2048,
            ..RSA
        };
        assert_eq!(
            authorize_suite(other, &provider, &policy),
            Err(CryptoAgilityError::PolicyDenied)
        );
    }
}
