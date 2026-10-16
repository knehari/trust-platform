//! OpenSSL 3 laboratory X.509 roots for ECDSA P-384/P-521 and Ed25519/Ed448.
//! All keys are disposable; no production CA, HSM, trust path or serial store.
#![cfg(unix)]

use crate::agile_x509_identifier::{
    preflight_certificate_algorithm, signature_algorithm_identifier,
};
use std::{str::FromStr, time::Duration};
use trust_pki_crypto::{
    crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme},
    openssl_classical_lab::{verify_openssl_spki_lab, OpenSslClassicalLabKey},
};
use x509_cert::{
    der::{
        asn1::{BitString, ObjectIdentifier, OctetString},
        Decode, Encode,
    },
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity,
    Certificate, TbsCertificate, Version,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicalX509LabError {
    UnsupportedSuite,
    InvalidSpki,
    InvalidDer,
    InvalidSignature,
}

fn verify_spki_algorithm(
    spki: &SubjectPublicKeyInfoOwned,
    suite: AlgorithmSuite,
) -> Result<(), ClassicalX509LabError> {
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(ClassicalX509LabError::InvalidSpki)?;
    let (expected_oid, expected_params, expected_len): (&str, Option<&[u8]>, usize) =
        match (suite.scheme, suite.key, suite.digest) {
            (SignatureScheme::Ecdsa, KeyParameter::P384, Digest::Sha384) => (
                "1.2.840.10045.2.1",
                Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
                97,
            ),
            (SignatureScheme::Ecdsa, KeyParameter::P521, Digest::Sha512) => (
                "1.2.840.10045.2.1",
                Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]),
                133,
            ),
            (SignatureScheme::Ed25519, KeyParameter::Ed25519, Digest::Intrinsic) => {
                ("1.3.101.112", None, 32)
            }
            (SignatureScheme::Ed448, KeyParameter::Ed448, Digest::Intrinsic) => {
                ("1.3.101.113", None, 57)
            }
            _ => return Err(ClassicalX509LabError::UnsupportedSuite),
        };
    let actual = spki
        .algorithm
        .parameters
        .as_ref()
        .map(|p| p.to_der().map_err(|_| ClassicalX509LabError::InvalidSpki))
        .transpose()?;
    if spki.algorithm.oid.to_string() != expected_oid
        || actual.as_deref() != expected_params
        || key_bytes.len() != expected_len
        || (suite.scheme == SignatureScheme::Ecdsa && key_bytes.first() != Some(&0x04))
    {
        return Err(ClassicalX509LabError::InvalidSpki);
    }
    Ok(())
}

fn critical_extension<T: Encode>(oid: &str, value: &T) -> Result<Extension, ClassicalX509LabError> {
    let extn_id = ObjectIdentifier::new(oid).map_err(|_| ClassicalX509LabError::InvalidDer)?;
    let bytes = value
        .to_der()
        .map_err(|_| ClassicalX509LabError::InvalidDer)?;
    let extn_value = OctetString::new(bytes).map_err(|_| ClassicalX509LabError::InvalidDer)?;
    Ok(Extension {
        extn_id,
        critical: true,
        extn_value,
    })
}

/// Mathematical verification of TBS signature using the subject SPKI.
/// Not RFC 5280 path validation or trust-anchor acceptance.
pub fn verify_openssl_classical_root_lab(
    certificate: &Certificate,
    suite: AlgorithmSuite,
) -> Result<(), ClassicalX509LabError> {
    if certificate.tbs_certificate.subject != certificate.tbs_certificate.issuer {
        return Err(ClassicalX509LabError::InvalidDer);
    }
    let expected = signature_algorithm_identifier(suite)
        .map_err(|_| ClassicalX509LabError::UnsupportedSuite)?;
    preflight_certificate_algorithm(certificate, &expected)
        .map_err(|_| ClassicalX509LabError::InvalidDer)?;
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    verify_spki_algorithm(spki, suite)?;
    let public = spki
        .to_der()
        .map_err(|_| ClassicalX509LabError::InvalidDer)?;
    let message = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| ClassicalX509LabError::InvalidDer)?;
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or(ClassicalX509LabError::InvalidSignature)?;
    verify_openssl_spki_lab(suite, &public, &message, signature)
        .map_err(|_| ClassicalX509LabError::InvalidSignature)
}

/// Generates one disposable, self-signed certificate, for OpenSSL interop only.
/// EC certificates use ASN.1 DER ECDSA signatures; EdDSA signatures are raw.
pub fn issue_openssl_classical_root_lab(
    suite: AlgorithmSuite,
) -> Result<Certificate, ClassicalX509LabError> {
    create_openssl_classical_root_and_signer_lab(suite).map(|(cert, _key)| cert)
}

/// Returns a disposable root and its matching signing key for lab server
/// issuance tests. There is no HSM, persistence or private key export API.
pub fn create_openssl_classical_root_and_signer_lab(
    suite: AlgorithmSuite,
) -> Result<(Certificate, OpenSslClassicalLabKey), ClassicalX509LabError> {
    let key = OpenSslClassicalLabKey::generate(suite)
        .map_err(|_| ClassicalX509LabError::UnsupportedSuite)?;
    let spki = SubjectPublicKeyInfoOwned::from_der(key.public_spki_der())
        .map_err(|_| ClassicalX509LabError::InvalidSpki)?;
    verify_spki_algorithm(&spki, suite)?;
    let identifier = signature_algorithm_identifier(suite)
        .map_err(|_| ClassicalX509LabError::UnsupportedSuite)?;
    let subject = Name::from_str("CN=Sovereign Trust Classical Lab Root")
        .map_err(|_| ClassicalX509LabError::InvalidDer)?;
    let extensions = vec![
        critical_extension(
            "2.5.29.19",
            &BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            },
        )?,
        critical_extension(
            "2.5.29.15",
            &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        )?,
    ];
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[0x21]).map_err(|_| ClassicalX509LabError::InvalidDer)?,
        signature: identifier.clone(),
        issuer: subject.clone(),
        validity: Validity::from_now(Duration::from_secs(86_400))
            .map_err(|_| ClassicalX509LabError::InvalidDer)?,
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let message = tbs
        .to_der()
        .map_err(|_| ClassicalX509LabError::InvalidDer)?;
    let signature = key
        .sign(suite, &message)
        .map_err(|_| ClassicalX509LabError::InvalidSignature)?;
    key.verify(suite, &message, &signature)
        .map_err(|_| ClassicalX509LabError::InvalidSignature)?;
    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: identifier,
        signature: BitString::from_bytes(&signature)
            .map_err(|_| ClassicalX509LabError::InvalidDer)?,
    };
    let der = certificate
        .to_der()
        .map_err(|_| ClassicalX509LabError::InvalidDer)?;
    if Certificate::from_der(&der).map_err(|_| ClassicalX509LabError::InvalidDer)? != certificate {
        return Err(ClassicalX509LabError::InvalidDer);
    }
    verify_openssl_classical_root_lab(&certificate, suite)?;
    Ok((certificate, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_p384_p521_ed25519_ed448_real_x509_roots_and_tamper_refusal() {
        for suite in [
            AlgorithmSuite {
                scheme: SignatureScheme::Ecdsa,
                key: KeyParameter::P384,
                digest: Digest::Sha384,
            },
            AlgorithmSuite {
                scheme: SignatureScheme::Ecdsa,
                key: KeyParameter::P521,
                digest: Digest::Sha512,
            },
            AlgorithmSuite {
                scheme: SignatureScheme::Ed25519,
                key: KeyParameter::Ed25519,
                digest: Digest::Intrinsic,
            },
            AlgorithmSuite {
                scheme: SignatureScheme::Ed448,
                key: KeyParameter::Ed448,
                digest: Digest::Intrinsic,
            },
        ] {
            let cert = issue_openssl_classical_root_lab(suite).unwrap();
            assert_eq!(verify_openssl_classical_root_lab(&cert, suite), Ok(()));
            let mut tampered = cert.clone();
            let mut sig = tampered.signature.as_bytes().unwrap().to_vec();
            sig[0] ^= 0x01;
            tampered.signature = BitString::from_bytes(&sig).unwrap();
            assert_eq!(
                verify_openssl_classical_root_lab(&tampered, suite),
                Err(ClassicalX509LabError::InvalidSignature)
            );
            let wrong = AlgorithmSuite {
                scheme: SignatureScheme::RsaPss,
                key: KeyParameter::Rsa3072,
                digest: Digest::Sha256,
            };
            assert!(verify_openssl_classical_root_lab(&cert, wrong).is_err());
        }
    }
}
