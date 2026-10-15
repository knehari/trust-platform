//! Independently authorize issuer signatures and subject public keys.
//! An X.509 signature scheme is NOT constrained by the certificate subject key type.
//! Preflight only: no issuance, provider attestation, or production eligibility.
use crate::crypto_agility::{validate_suite, AlgorithmSuite, CryptoAgilityError, KeyParameter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateAlgorithmBinding {
    pub issuer_signature: AlgorithmSuite,
    pub subject_key: KeyParameter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    InvalidIssuerScheme,
    IssuerPolicyDenied,
    SubjectPolicyDenied,
}

/// The CSR key algorithm is intentionally distinct from the issuer signing key.
/// The trusted certificate profile must authorize both independently.
pub fn authorize_certificate_binding(
    binding: CertificateAlgorithmBinding,
    issuer_suites: &[AlgorithmSuite],
    allowed_subject_keys: &[KeyParameter],
) -> Result<(), BindingError> {
    validate_suite(binding.issuer_signature)
        .map_err(|_error: CryptoAgilityError| BindingError::InvalidIssuerScheme)?;
    if !issuer_suites.contains(&binding.issuer_signature) {
        return Err(BindingError::IssuerPolicyDenied);
    }
    if !allowed_subject_keys.contains(&binding.subject_key) {
        return Err(BindingError::SubjectPolicyDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_agility::{Digest, SignatureScheme};

    const RSA_ISSUER: AlgorithmSuite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPss,
        key: KeyParameter::Rsa3072,
        digest: Digest::Sha256,
    };
    const EC_ISSUER: AlgorithmSuite = AlgorithmSuite {
        scheme: SignatureScheme::Ecdsa,
        key: KeyParameter::P256,
        digest: Digest::Sha256,
    };

    #[test]
    fn rsa_issuer_can_authorize_ecc_subject() {
        assert_eq!(
            authorize_certificate_binding(
                CertificateAlgorithmBinding {
                    issuer_signature: RSA_ISSUER,
                    subject_key: KeyParameter::P384,
                },
                &[RSA_ISSUER],
                &[KeyParameter::P384],
            ),
            Ok(())
        );
    }

    #[test]
    fn ecc_issuer_can_authorize_rsa_subject() {
        assert_eq!(
            authorize_certificate_binding(
                CertificateAlgorithmBinding {
                    issuer_signature: EC_ISSUER,
                    subject_key: KeyParameter::Rsa4096,
                },
                &[EC_ISSUER],
                &[KeyParameter::Rsa4096],
            ),
            Ok(())
        );
    }

    #[test]
    fn both_policies_must_be_explicit() {
        let binding = CertificateAlgorithmBinding {
            issuer_signature: RSA_ISSUER,
            subject_key: KeyParameter::P256,
        };
        assert_eq!(
            authorize_certificate_binding(binding, &[], &[KeyParameter::P256]),
            Err(BindingError::IssuerPolicyDenied)
        );
        assert_eq!(
            authorize_certificate_binding(binding, &[RSA_ISSUER], &[]),
            Err(BindingError::SubjectPolicyDenied)
        );
    }
}
