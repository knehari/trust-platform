//! Strict PKCS#10 lab acceptance (RFC 2986): DER and proof-of-possession.
//!
//! This module does NOT authorize an identity or copy SANs/extensions from a CSR.
//! Certificate names and allowed uses are supplied independently by policy.
//!
//! Currently only ECDSA P-256 with SHA-256 is supported (explicit allowlist).

use sha2::{Digest, Sha256};
use std::str::FromStr;
use trust_pki_crypto::verify_p256_ecdsa_sha256;
use x509_cert::{
    der::{Decode, Encode},
    name::Name,
    request::{CertReq, Version},
    spki::SubjectPublicKeyInfoOwned,
};

pub const MAX_CSR_DER_BYTES: usize = 16 * 1024;
const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";
const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const P256_PARAMS_DER: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsrValidationError {
    EmptyOrOversize,
    InvalidDer,
    WrongVersion,
    UnsupportedSignatureAlgorithm,
    UnsupportedSubjectKeyAlgorithm,
    InvalidPublicKey,
    InvalidSignature,
    SubjectMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCsr {
    /// Verified public key is safe to include in the subject certificate.
    subject_public_key: SubjectPublicKeyInfoOwned,
    subject: Name,
    fingerprint_sha256: [u8; 32],
}

impl VerifiedCsr {
    pub fn subject_public_key(&self) -> &SubjectPublicKeyInfoOwned {
        &self.subject_public_key
    }

    pub fn subject(&self) -> &Name {
        &self.subject
    }

    pub fn fingerprint_sha256(&self) -> &[u8; 32] {
        &self.fingerprint_sha256
    }
}

/// Verifies a DER CSR and requires the exact CN selected by a separate trusted
/// policy decision. A successful return is NOT authorization to issue.
pub fn verify_pkcs10_p256(
    csr_der: &[u8],
    expected_common_name: &str,
) -> Result<VerifiedCsr, CsrValidationError> {
    if csr_der.is_empty() || csr_der.len() > MAX_CSR_DER_BYTES {
        return Err(CsrValidationError::EmptyOrOversize);
    }

    let csr = CertReq::from_der(csr_der).map_err(|_| CsrValidationError::InvalidDer)?;
    let canonical = csr.to_der().map_err(|_| CsrValidationError::InvalidDer)?;
    if canonical != csr_der {
        return Err(CsrValidationError::InvalidDer);
    }

    if csr.info.version != Version::V1 {
        return Err(CsrValidationError::WrongVersion);
    }

    if csr.algorithm.oid.to_string() != ECDSA_SHA256_OID || csr.algorithm.parameters.is_some() {
        return Err(CsrValidationError::UnsupportedSignatureAlgorithm);
    }

    let spki = &csr.info.public_key;
    if spki.algorithm.oid.to_string() != EC_PUBLIC_KEY_OID
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.to_der().ok())
            != Some(P256_PARAMS_DER.to_vec())
    {
        return Err(CsrValidationError::UnsupportedSubjectKeyAlgorithm);
    }

    let public_key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(CsrValidationError::InvalidPublicKey)?;

    // This deliberately supports only uncompressed P-256 points.
    if public_key.len() != 65 || public_key.first() != Some(&0x04) {
        return Err(CsrValidationError::InvalidPublicKey);
    }

    // The policy-selected identity, not any CSR extension request, is authoritative.
    let expected_subject = Name::from_str(&format!("CN={expected_common_name}"))
        .map_err(|_| CsrValidationError::SubjectMismatch)?;
    if csr.info.subject != expected_subject {
        return Err(CsrValidationError::SubjectMismatch);
    }

    let tbs = csr
        .info
        .to_der()
        .map_err(|_| CsrValidationError::InvalidDer)?;
    let signature = csr
        .signature
        .as_bytes()
        .ok_or(CsrValidationError::InvalidSignature)?;
    verify_p256_ecdsa_sha256(public_key, &tbs, signature)
        .map_err(|_| CsrValidationError::InvalidSignature)?;

    Ok(VerifiedCsr {
        subject_public_key: csr.info.public_key,
        subject: csr.info.subject,
        fingerprint_sha256: Sha256::digest(csr_der).into(),
    })
}


/// Opt-in laboratory verification for RSA PKCS#1 v1.5 signed PKCS#10 CSRs.
/// Requires an exact SHA-256/384/512 signature OID with ASN.1 NULL parameters,
/// an RSA SPKI, a supported observed modulus and verified proof of possession.
/// The caller must independently authorize names and requested extensions.
#[cfg(feature = "lab-software")]
pub fn verify_pkcs10_rsa_pkcs1_lab(
    csr_der: &[u8],
    expected_common_name: &str,
) -> Result<(VerifiedCsr, trust_pki_crypto::crypto_agility::AlgorithmSuite), CsrValidationError> {
    use trust_pki_crypto::{
        crypto_agility::{AlgorithmSuite, Digest as TypedDigest, SignatureScheme},
        rsa_pkcs1_lab::{observed_rsa_key_parameter, verify_pkcs1_spki_lab},
    };
    if csr_der.is_empty() || csr_der.len() > MAX_CSR_DER_BYTES {
        return Err(CsrValidationError::EmptyOrOversize);
    }
    let csr = CertReq::from_der(csr_der).map_err(|_| CsrValidationError::InvalidDer)?;
    if csr.to_der().map_err(|_| CsrValidationError::InvalidDer)? != csr_der {
        return Err(CsrValidationError::InvalidDer);
    }
    if csr.info.version != Version::V1 {
        return Err(CsrValidationError::WrongVersion);
    }
    let digest = match csr.algorithm.oid.to_string().as_str() {
        "1.2.840.113549.1.1.11" => TypedDigest::Sha256,
        "1.2.840.113549.1.1.12" => TypedDigest::Sha384,
        "1.2.840.113549.1.1.13" => TypedDigest::Sha512,
        _ => return Err(CsrValidationError::UnsupportedSignatureAlgorithm),
    };
    // RFC 4055: sha{256,384,512}WithRSAEncryption parameters MUST be NULL.
    if csr
        .algorithm
        .parameters
        .as_ref()
        .and_then(|params| params.to_der().ok())
        != Some(vec![0x05, 0x00])
    {
        return Err(CsrValidationError::UnsupportedSignatureAlgorithm);
    }
    let spki = &csr.info.public_key;
    if spki.algorithm.oid.to_string() != "1.2.840.113549.1.1.1"
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|params| params.to_der().ok())
            != Some(vec![0x05, 0x00])
    {
        return Err(CsrValidationError::UnsupportedSubjectKeyAlgorithm);
    }
    let expected_subject = Name::from_str(&format!("CN={expected_common_name}"))
        .map_err(|_| CsrValidationError::SubjectMismatch)?;
    if csr.info.subject != expected_subject {
        return Err(CsrValidationError::SubjectMismatch);
    }
    let spki_der = spki.to_der().map_err(|_| CsrValidationError::InvalidDer)?;
    let key = observed_rsa_key_parameter(&spki_der)
        .map_err(|_| CsrValidationError::InvalidPublicKey)?;
    let suite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPkcs1V15,
        key,
        digest,
    };
    let message = csr.info.to_der().map_err(|_| CsrValidationError::InvalidDer)?;
    let signature = csr
        .signature
        .as_bytes()
        .ok_or(CsrValidationError::InvalidSignature)?;
    verify_pkcs1_spki_lab(suite, &spki_der, &message, signature)
        .map_err(|_| CsrValidationError::InvalidSignature)?;
    Ok((
        VerifiedCsr {
            subject_public_key: csr.info.public_key,
            subject: csr.info.subject,
            fingerprint_sha256: Sha256::digest(csr_der).into(),
        },
        suite,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::DecodePem;

    fn valid_csr() -> Vec<u8> {
        CertReq::from_pem(include_str!("../tests/fixtures/ecdsa-p256-request.pem"))
            .unwrap()
            .to_der()
            .unwrap()
    }

    #[test]
    fn accepts_signed_p256_csr_for_selected_cn() {
        let verified = verify_pkcs10_p256(&valid_csr(), "api.lab.invalid").unwrap();
        assert_ne!(verified.fingerprint_sha256(), &[0u8; 32]);
        assert_eq!(
            verified.subject_public_key().algorithm.oid.to_string(),
            EC_PUBLIC_KEY_OID
        );
    }

    #[test]
    fn altered_signature_is_rejected() {
        let mut bytes = valid_csr();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(
            verify_pkcs10_p256(&bytes, "api.lab.invalid"),
            Err(CsrValidationError::InvalidSignature)
        );
    }

    #[test]
    fn trailing_bytes_and_oversize_are_rejected() {
        let mut bytes = valid_csr();
        bytes.push(0);
        assert_eq!(
            verify_pkcs10_p256(&bytes, "api.lab.invalid"),
            Err(CsrValidationError::InvalidDer)
        );
        assert_eq!(
            verify_pkcs10_p256(&vec![0; MAX_CSR_DER_BYTES + 1], "api.lab.invalid"),
            Err(CsrValidationError::EmptyOrOversize)
        );
    }

    #[test]
    fn wrong_subject_is_rejected() {
        assert_eq!(
            verify_pkcs10_p256(&valid_csr(), "admin.lab.invalid"),
            Err(CsrValidationError::SubjectMismatch)
        );
    }

    #[test]
    fn rsa_algorithm_is_explicitly_rejected() {
        let csr = CertReq::from_pem(include_str!(
            "../tests/fixtures/rsa-unsupported-request.pem"
        ))
        .unwrap()
        .to_der()
        .unwrap();
        assert_eq!(
            verify_pkcs10_p256(&csr, "api.lab.invalid"),
            Err(CsrValidationError::UnsupportedSignatureAlgorithm)
        );
    }

    #[cfg(feature = "lab-software")]
    #[test]
    fn real_rsa_pkcs1_csr_proof_of_possession_is_verified() {
        let original = CertReq::from_pem(include_str!(
            "../tests/fixtures/rsa-unsupported-request.pem"
        ))
        .unwrap()
        .to_der()
        .unwrap();
        let (verified, suite) =
            verify_pkcs10_rsa_pkcs1_lab(&original, "api.lab.invalid").unwrap();
        assert_eq!(
            suite,
            trust_pki_crypto::crypto_agility::AlgorithmSuite {
                scheme: trust_pki_crypto::crypto_agility::SignatureScheme::RsaPkcs1V15,
                key: trust_pki_crypto::crypto_agility::KeyParameter::Rsa2048,
                digest: trust_pki_crypto::crypto_agility::Digest::Sha256,
            }
        );
        assert_ne!(verified.fingerprint_sha256(), &[0u8; 32]);
        let mut tampered = original.clone();
        let end = tampered.len() - 1;
        tampered[end] ^= 0x01;
        assert_eq!(
            verify_pkcs10_rsa_pkcs1_lab(&tampered, "api.lab.invalid"),
            Err(CsrValidationError::InvalidSignature)
        );
        assert_eq!(
            verify_pkcs10_rsa_pkcs1_lab(&original, "other.lab.invalid"),
            Err(CsrValidationError::SubjectMismatch)
        );
        let mut trailing = original;
        trailing.push(0);
        assert_eq!(
            verify_pkcs10_rsa_pkcs1_lab(&trailing, "api.lab.invalid"),
            Err(CsrValidationError::InvalidDer)
        );
    }

    #[test]
    fn empty_request_fails_closed() {
        assert_eq!(
            verify_pkcs10_p256(&[], "api.lab.invalid"),
            Err(CsrValidationError::EmptyOrOversize)
        );
    }
}
