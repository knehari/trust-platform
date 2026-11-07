//! Disposable RSA PKCS#1 v1.5 X.509 root interoperability fixture.
//! Not a production CA; no persisted keys, issuance ledger, revocation or HSM.
use std::{str::FromStr, time::Duration};
use trust_pki_crypto::{
    crypto_agility::{AlgorithmSuite, SignatureScheme},
    rsa_pkcs1_lab::{verify_pkcs1_spki_lab, EphemeralPkcs1LabKey},
    rsa_pss_lab::generate_lab_serial,
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
pub enum Pkcs1LabIssueError {
    UnsupportedSuite,
    InvalidKey,
    InvalidEncoding,
    SignatureInvalid,
}

fn extension<T: Encode>(name: &str, value: &T) -> Result<Extension, Pkcs1LabIssueError> {
    let oid = ObjectIdentifier::new(name).map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?;
    let der = value
        .to_der()
        .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?;
    let octets = OctetString::new(der).map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?;
    Ok(Extension {
        extn_id: oid,
        critical: true,
        extn_value: octets,
    })
}

/// The SPKI key is RSA regardless of which signature hash is selected.
/// Both X.509 signature identifiers MUST be exactly the typed suite OID
/// with the RSA PKCS#1 v1.5 required ASN.1 NULL parameters.
pub fn verify_pkcs1_x509_root_lab(
    cert: &Certificate,
    suite: AlgorithmSuite,
) -> Result<(), Pkcs1LabIssueError> {
    if suite.scheme != SignatureScheme::RsaPkcs1V15
        || cert.tbs_certificate.issuer != cert.tbs_certificate.subject
    {
        return Err(Pkcs1LabIssueError::UnsupportedSuite);
    }
    let expected = crate::agile_x509_identifier::signature_algorithm_identifier(suite)
        .map_err(|_| Pkcs1LabIssueError::UnsupportedSuite)?;
    crate::agile_x509_identifier::preflight_certificate_algorithm(cert, &expected)
        .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?;
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?;
    let signature = cert
        .signature
        .as_bytes()
        .ok_or(Pkcs1LabIssueError::SignatureInvalid)?;
    verify_pkcs1_spki_lab(suite, &spki, &tbs, signature)
        .map_err(|_| Pkcs1LabIssueError::SignatureInvalid)
}

/// Ephemeral RSA PKCS#1 v1.5 root for SHA-256, SHA-384 or SHA-512.
/// Never activate these compatibility signatures without explicit CA policy.
pub fn issue_rsa_pkcs1_root_lab(suite: AlgorithmSuite) -> Result<Certificate, Pkcs1LabIssueError> {
    if suite.scheme != SignatureScheme::RsaPkcs1V15 {
        return Err(Pkcs1LabIssueError::UnsupportedSuite);
    }
    let expected = crate::agile_x509_identifier::signature_algorithm_identifier(suite)
        .map_err(|_| Pkcs1LabIssueError::UnsupportedSuite)?;
    let key = EphemeralPkcs1LabKey::generate(suite).map_err(|_| Pkcs1LabIssueError::InvalidKey)?;
    let spki = SubjectPublicKeyInfoOwned::from_der(
        &key.public_spki_der()
            .map_err(|_| Pkcs1LabIssueError::InvalidKey)?,
    )
    .map_err(|_| Pkcs1LabIssueError::InvalidKey)?;
    let name = Name::from_str("CN=Sovereign Trust RSA PKCS1 Lab Root")
        .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?;
    let extensions = vec![
        extension(
            "2.5.29.19",
            &BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            },
        )?,
        extension(
            "2.5.29.15",
            &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        )?,
    ];
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&generate_lab_serial())
            .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?,
        signature: expected.clone(),
        issuer: name.clone(),
        validity: Validity::from_now(Duration::from_secs(24 * 60 * 60))
            .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?,
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let signed_der = tbs
        .to_der()
        .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?;
    let signature = key
        .sign(&signed_der)
        .map_err(|_| Pkcs1LabIssueError::SignatureInvalid)?;
    key.verify(&signed_der, &signature)
        .map_err(|_| Pkcs1LabIssueError::SignatureInvalid)?;
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: expected,
        signature: BitString::from_bytes(&signature)
            .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?,
    };
    let der = cert
        .to_der()
        .map_err(|_| Pkcs1LabIssueError::InvalidEncoding)?;
    if Certificate::from_der(&der).map_err(|_| Pkcs1LabIssueError::InvalidEncoding)? != cert {
        return Err(Pkcs1LabIssueError::InvalidEncoding);
    }
    verify_pkcs1_x509_root_lab(&cert, suite)?;
    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_pki_crypto::crypto_agility::{Digest, KeyParameter};

    #[test]
    fn independently_generated_root_serials_are_not_fixed() {
        let suite = AlgorithmSuite {
            scheme: SignatureScheme::RsaPkcs1V15,
            key: KeyParameter::Rsa2048,
            digest: Digest::Sha256,
        };
        let first = issue_rsa_pkcs1_root_lab(suite).unwrap();
        let second = issue_rsa_pkcs1_root_lab(suite).unwrap();
        assert_ne!(
            first.tbs_certificate.serial_number,
            second.tbs_certificate.serial_number
        );
    }

    #[test]
    fn real_rsa_pkcs1_x509_root_and_no_scheme_downgrade() {
        for digest in [Digest::Sha256, Digest::Sha384, Digest::Sha512] {
            let suite = AlgorithmSuite {
                scheme: SignatureScheme::RsaPkcs1V15,
                key: KeyParameter::Rsa2048,
                digest,
            };
            let root = issue_rsa_pkcs1_root_lab(suite).unwrap();
            assert_eq!(verify_pkcs1_x509_root_lab(&root, suite), Ok(()));
            // A matching signature OID is insufficient: the RSA modulus must
            // match the exact key parameter selected by trusted policy.
            let forged_key_size = AlgorithmSuite {
                key: KeyParameter::Rsa3072,
                ..suite
            };
            assert_eq!(
                verify_pkcs1_x509_root_lab(&root, forged_key_size),
                Err(Pkcs1LabIssueError::SignatureInvalid)
            );
            let mut forged_spki = root.clone();
            forged_spki
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .oid = ObjectIdentifier::new("1.2.840.10045.2.1").unwrap();
            assert_eq!(
                verify_pkcs1_x509_root_lab(&forged_spki, suite),
                Err(Pkcs1LabIssueError::SignatureInvalid)
            );
            let mut tampered = root.clone();
            let mut signature = tampered.signature.as_bytes().unwrap().to_vec();
            signature[0] ^= 0x01;
            tampered.signature = BitString::from_bytes(&signature).unwrap();
            assert_eq!(
                verify_pkcs1_x509_root_lab(&tampered, suite),
                Err(Pkcs1LabIssueError::SignatureInvalid)
            );
            let mismatched = AlgorithmSuite {
                digest: match digest {
                    Digest::Sha256 => Digest::Sha384,
                    _ => Digest::Sha256,
                },
                ..suite
            };
            assert_eq!(
                verify_pkcs1_x509_root_lab(&root, mismatched),
                Err(Pkcs1LabIssueError::InvalidEncoding)
            );
            let pss = AlgorithmSuite {
                scheme: SignatureScheme::RsaPss,
                ..suite
            };
            assert_eq!(
                verify_pkcs1_x509_root_lab(&root, pss),
                Err(Pkcs1LabIssueError::UnsupportedSuite)
            );
        }
    }
}
