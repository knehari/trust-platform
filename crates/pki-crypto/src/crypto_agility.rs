//! Algorithm-neutral classical signing policy and provider conformance gate.
//! This is a policy contract, NOT a signing implementation, HSM attestation or
//! evidence that any algorithm is production-ready.
#![allow(dead_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    RsaPss, RsaPkcs1V15, Ecdsa, Ed25519, Ed448, MlDsa,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyParameter {
    Rsa2048, Rsa3072, Rsa4096, Rsa8192,
    P256, P384, P521, Ed25519, Ed448, MlDsa44, MlDsa65, MlDsa87,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Digest { Sha256, Sha384, Sha512, Intrinsic }
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
/// Validates algorithm semantics, without claiming the underlying crypto exists.
pub fn validate_suite(s: AlgorithmSuite) -> Result<(), CryptoAgilityError> {
    use Digest::*;
    use KeyParameter::*;
    use SignatureScheme::*;
    let valid = match (s.scheme, s.key, s.digest) {
        (RsaPss | RsaPkcs1V15, Rsa2048 | Rsa3072 | Rsa4096 | Rsa8192, Sha256 | Sha384 | Sha512) => true,
        (Ecdsa, P256, Sha256) | (Ecdsa, P384, Sha384) | (Ecdsa, P521, Sha512) => true,
        (SignatureScheme::Ed25519, KeyParameter::Ed25519, Intrinsic) => true,
        (SignatureScheme::Ed448, KeyParameter::Ed448, Intrinsic) => true,
        (SignatureScheme::MlDsa, MlDsa44 | MlDsa65 | MlDsa87, Intrinsic) => true,
        _ => false,
    };
    if valid { Ok(()) } else { Err(CryptoAgilityError::InvalidCombination) }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation { GenerateKey, Sign, Verify, ExportSpki, EncodeX509 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderSuite<'a> {
    pub suite: AlgorithmSuite,
    pub supported_operations: &'a [Operation],
    /// Only set after independently reviewing a versioned conformance report.
    pub conformance_verified: bool,
}
#[derive(Debug, Clone, Copy)]
pub struct SuitePolicy<'a> {
    pub allowed_suites: &'a [AlgorithmSuite],
    pub required_operations: &'a [Operation],
    pub x509_profile_approved: bool,
}
/// All inputs must originate in trusted policy and verified provider inventory.
/// Fail-closed: no fallback, no implicit downgrade, no magic "RSA >= 3072".
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
        || policy.required_operations.iter().any(|op| !provider.supported_operations.contains(op))
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
        scheme: SignatureScheme::RsaPss, key: KeyParameter::Rsa4096, digest: Digest::Sha384,
    };
    #[test]
    fn classical_suites_are_structurally_extensible() {
        for key in [KeyParameter::Rsa2048, KeyParameter::Rsa3072, KeyParameter::Rsa4096, KeyParameter::Rsa8192] {
            assert!(validate_suite(AlgorithmSuite {scheme: SignatureScheme::RsaPss, key, digest: Digest::Sha256}).is_ok());
        }
        for (key, digest) in [(KeyParameter::P256, Digest::Sha256), (KeyParameter::P384, Digest::Sha384), (KeyParameter::P521, Digest::Sha512)] {
            assert!(validate_suite(AlgorithmSuite {scheme: SignatureScheme::Ecdsa, key, digest}).is_ok());
        }
        assert!(validate_suite(AlgorithmSuite {scheme: SignatureScheme::Ed25519, key: KeyParameter::Ed25519, digest: Digest::Intrinsic}).is_ok());
    }
    #[test]
    fn rejects_cross_family_and_incompatible_hash() {
        assert_eq!(validate_suite(AlgorithmSuite {scheme: SignatureScheme::Ecdsa, key: KeyParameter::P256, digest: Digest::Sha512}), Err(CryptoAgilityError::InvalidCombination));
        assert_eq!(validate_suite(AlgorithmSuite {scheme: SignatureScheme::RsaPss, key: KeyParameter::P384, digest: Digest::Sha384}), Err(CryptoAgilityError::InvalidCombination));
        assert_eq!(validate_suite(AlgorithmSuite {scheme: SignatureScheme::Ed25519, key: KeyParameter::Ed25519, digest: Digest::Sha256}), Err(CryptoAgilityError::InvalidCombination));
    }
    #[test]
    fn provider_claim_never_automatically_enables_signing() {
        let ops = [Operation::Sign, Operation::Verify, Operation::EncodeX509];
        let caps = ProviderSuite {suite: RSA, supported_operations: &ops, conformance_verified: false};
        let policy = SuitePolicy {allowed_suites: &[RSA], required_operations: &ops, x509_profile_approved: true};
        assert_eq!(authorize_suite(RSA, &caps, &policy), Err(CryptoAgilityError::NotConformanceTested));
        let caps = ProviderSuite {conformance_verified: true, ..caps};
        assert_eq!(authorize_suite(RSA, &caps, &policy), Ok(()));
    }
    #[test]
    fn policy_can_disallow_rsa2048_without_removing_capability() {
        let legacy = AlgorithmSuite {key: KeyParameter::Rsa2048, ..RSA};
        let ops = [Operation::Sign];
        let caps = ProviderSuite {suite: legacy, supported_operations: &ops, conformance_verified: true};
        let policy = SuitePolicy {allowed_suites: &[RSA], required_operations: &ops, x509_profile_approved: true};
        assert_eq!(authorize_suite(legacy, &caps, &policy), Err(CryptoAgilityError::PolicyDenied));
    }
    #[test]
    fn no_silent_fallback_or_partial_operations() {
        let ops = [Operation::Sign];
        let caps = ProviderSuite {suite: RSA, supported_operations: &ops, conformance_verified: true};
        let required = [Operation::Sign, Operation::Verify];
        let policy = SuitePolicy {allowed_suites: &[RSA], required_operations: &required, x509_profile_approved: true};
        assert_eq!(authorize_suite(RSA, &caps, &policy), Err(CryptoAgilityError::UnsupportedProvider));
        let other = AlgorithmSuite {key: KeyParameter::Rsa3072, ..RSA};
        assert_eq!(authorize_suite(other, &caps, &policy), Err(CryptoAgilityError::PolicyDenied));
    }
}
