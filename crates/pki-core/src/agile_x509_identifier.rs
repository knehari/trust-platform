//! Strict X.509 signature AlgorithmIdentifier serialization for typed suites.
//! Encoding an algorithm does NOT enable signing or certify a provider.
//! The CA must use the same identifier in TBS and outer Certificate fields.
use crate::rsa_pss_identifier::PSS_SHA256_MGF1_SHA256_SALT32_DER;
use trust_pki_crypto::crypto_agility::{validate_suite, AlgorithmSuite, Digest, SignatureScheme};
use x509_cert::{
    der::{
        asn1::{Any, ObjectIdentifier},
        Decode,
    },
    spki::AlgorithmIdentifierOwned,
    Certificate,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmIdentifierError {
    InvalidSuite,
    UnsupportedEncoding,
    InvalidDer,
    CertificateMismatch,
}

pub fn signature_algorithm_identifier(
    suite: AlgorithmSuite,
) -> Result<AlgorithmIdentifierOwned, AlgorithmIdentifierError> {
    validate_suite(suite).map_err(|_| AlgorithmIdentifierError::InvalidSuite)?;
    let (oid, parameters): (&str, Option<&[u8]>) = match (suite.scheme, suite.digest) {
        (SignatureScheme::RsaPss, Digest::Sha256) => (
            "1.2.840.113549.1.1.10",
            Some(PSS_SHA256_MGF1_SHA256_SALT32_DER),
        ),
        (SignatureScheme::RsaPkcs1V15, Digest::Sha256) => {
            ("1.2.840.113549.1.1.11", Some(&[0x05, 0x00]))
        }
        (SignatureScheme::RsaPkcs1V15, Digest::Sha384) => {
            ("1.2.840.113549.1.1.12", Some(&[0x05, 0x00]))
        }
        (SignatureScheme::RsaPkcs1V15, Digest::Sha512) => {
            ("1.2.840.113549.1.1.13", Some(&[0x05, 0x00]))
        }
        (SignatureScheme::Ecdsa, Digest::Sha256) => ("1.2.840.10045.4.3.2", None),
        (SignatureScheme::Ecdsa, Digest::Sha384) => ("1.2.840.10045.4.3.3", None),
        (SignatureScheme::Ecdsa, Digest::Sha512) => ("1.2.840.10045.4.3.4", None),
        (SignatureScheme::Ed25519, Digest::Intrinsic) => ("1.3.101.112", None),
        (SignatureScheme::Ed448, Digest::Intrinsic) => ("1.3.101.113", None),
        // SHA-384/512 PSS parameter DER must be implemented and independently
        // verified before any X.509 certificate may advertise those suites.
        _ => return Err(AlgorithmIdentifierError::UnsupportedEncoding),
    };
    let oid = ObjectIdentifier::new(oid).map_err(|_| AlgorithmIdentifierError::InvalidDer)?;
    let parameters = parameters
        .map(|der| Any::from_der(der).map_err(|_| AlgorithmIdentifierError::InvalidDer))
        .transpose()?;
    Ok(AlgorithmIdentifierOwned { oid, parameters })
}

/// Checks the exact algorithm identifier in both certificate locations.
/// This is NOT certificate path validation or verification of the signature.
pub fn preflight_certificate_algorithm(
    certificate: &Certificate,
    selected: &AlgorithmIdentifierOwned,
) -> Result<(), AlgorithmIdentifierError> {
    if certificate.tbs_certificate.signature != *selected
        || certificate.signature_algorithm != *selected
    {
        return Err(AlgorithmIdentifierError::CertificateMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_pki_crypto::crypto_agility::{KeyParameter, SignatureScheme};
    use x509_cert::der::Encode;

    fn suite(scheme: SignatureScheme, key: KeyParameter, digest: Digest) -> AlgorithmSuite {
        AlgorithmSuite {
            scheme,
            key,
            digest,
        }
    }

    #[test]
    fn ecdsa_identifiers_have_no_parameters() {
        for (key, digest, expected) in [
            (KeyParameter::P256, Digest::Sha256, "1.2.840.10045.4.3.2"),
            (KeyParameter::P384, Digest::Sha384, "1.2.840.10045.4.3.3"),
            (KeyParameter::P521, Digest::Sha512, "1.2.840.10045.4.3.4"),
        ] {
            let identifier =
                signature_algorithm_identifier(suite(SignatureScheme::Ecdsa, key, digest)).unwrap();
            assert_eq!(identifier.oid.to_string(), expected);
            assert!(identifier.parameters.is_none());
        }
    }

    #[test]
    fn rsa_pkcs1_identifiers_require_null_parameters() {
        for (hash, oid) in [
            (Digest::Sha256, "1.2.840.113549.1.1.11"),
            (Digest::Sha384, "1.2.840.113549.1.1.12"),
            (Digest::Sha512, "1.2.840.113549.1.1.13"),
        ] {
            let identifier = signature_algorithm_identifier(suite(
                SignatureScheme::RsaPkcs1V15,
                KeyParameter::Rsa3072,
                hash,
            ))
            .unwrap();
            assert_eq!(identifier.oid.to_string(), oid);
            assert_eq!(
                identifier.parameters.unwrap().to_der().unwrap(),
                [0x05, 0x00]
            );
        }
    }

    #[test]
    fn rsa_pss_only_encodes_the_tested_explicit_profile() {
        let pss = signature_algorithm_identifier(suite(
            SignatureScheme::RsaPss,
            KeyParameter::Rsa3072,
            Digest::Sha256,
        ))
        .unwrap();
        assert_eq!(pss.oid.to_string(), "1.2.840.113549.1.1.10");
        assert_eq!(
            pss.parameters.unwrap().to_der().unwrap(),
            PSS_SHA256_MGF1_SHA256_SALT32_DER
        );
        assert_eq!(
            signature_algorithm_identifier(suite(
                SignatureScheme::RsaPss,
                KeyParameter::Rsa3072,
                Digest::Sha384,
            )),
            Err(AlgorithmIdentifierError::UnsupportedEncoding)
        );
    }

    #[test]
    fn eddsa_parameters_must_be_absent() {
        for (scheme, key, oid) in [
            (
                SignatureScheme::Ed25519,
                KeyParameter::Ed25519,
                "1.3.101.112",
            ),
            (SignatureScheme::Ed448, KeyParameter::Ed448, "1.3.101.113"),
        ] {
            let value =
                signature_algorithm_identifier(suite(scheme, key, Digest::Intrinsic)).unwrap();
            assert_eq!(value.oid.to_string(), oid);
            assert!(value.parameters.is_none());
        }
    }
    #[cfg(feature = "lab-software")]
    #[test]
    fn live_lab_root_rejects_inner_and_outer_algorithm_mismatches() {
        let root = crate::lab_ca::EphemeralLabCa::new("Sovereign Trust Lab Root")
            .unwrap()
            .root_certificate()
            .clone();
        let ecdsa = signature_algorithm_identifier(suite(
            SignatureScheme::Ecdsa,
            KeyParameter::P256,
            Digest::Sha256,
        ))
        .unwrap();
        let pss = signature_algorithm_identifier(suite(
            SignatureScheme::RsaPss,
            KeyParameter::Rsa3072,
            Digest::Sha256,
        ))
        .unwrap();
        assert_eq!(preflight_certificate_algorithm(&root, &ecdsa), Ok(()));
        let mut wrong_outer = root.clone();
        wrong_outer.signature_algorithm = pss.clone();
        assert_eq!(
            preflight_certificate_algorithm(&wrong_outer, &ecdsa),
            Err(AlgorithmIdentifierError::CertificateMismatch)
        );
        let mut wrong_tbs = root;
        wrong_tbs.tbs_certificate.signature = pss;
        assert_eq!(
            preflight_certificate_algorithm(&wrong_tbs, &ecdsa),
            Err(AlgorithmIdentifierError::CertificateMismatch)
        );
    }
}
