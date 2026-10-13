//! Isolated RSA-PSS X.509 root fixture. Not a production CA or general issuer.
use crate::rsa_pss_identifier::{preflight_pss_certificate_der, PSS_SHA256_MGF1_SHA256_SALT32_DER};
use std::{str::FromStr, time::Duration};
use trust_pki_crypto::{
    rsa_pss_lab::EphemeralRsaPssLabSigner, KeyRef, SignatureAlgorithm, SigningProvider,
};
use x509_cert::{
    der::{
        asn1::{Any, BitString, ObjectIdentifier},
        Decode, Encode,
    },
    ext::pkix::{BasicConstraints, KeyUsage, KeyUsages},
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
    Certificate, TbsCertificate, Version,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPssLabIssueError {
    Key,
    Encoding,
    Signature,
}

/// Generates a disposable RSA-3072 self-signed root certificate with explicit
/// RSA-PSS SHA-256/MGF1-SHA256/32-byte salt parameters, for OpenSSL interop.
pub fn issue_ephemeral_rsa_pss_root() -> Result<Certificate, RsaPssLabIssueError> {
    let signer = EphemeralRsaPssLabSigner::generate(KeyRef("pss-x509-lab".into()))
        .map_err(|_| RsaPssLabIssueError::Key)?;
    let spki_der = signer
        .public_key_spki_der(signer.key_ref())
        .map_err(|_| RsaPssLabIssueError::Key)?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    let name = Name::from_str("CN=Sovereign Trust RSA-PSS Lab Root")
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    let oid = ObjectIdentifier::new("1.2.840.113549.1.1.10")
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    let params = Any::from_der(PSS_SHA256_MGF1_SHA256_SALT32_DER)
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    let algorithm = AlgorithmIdentifierOwned {
        oid,
        parameters: Some(params),
    };
    let constraints = BasicConstraints {
        ca: true,
        path_len_constraint: Some(0),
    };
    let usages = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign);
    let extensions = vec![
        x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new("2.5.29.19")
                .map_err(|_| RsaPssLabIssueError::Encoding)?,
            critical: true,
            extn_value: x509_cert::der::asn1::OctetString::new(
                constraints
                    .to_der()
                    .map_err(|_| RsaPssLabIssueError::Encoding)?,
            )
            .map_err(|_| RsaPssLabIssueError::Encoding)?,
        },
        x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new("2.5.29.15")
                .map_err(|_| RsaPssLabIssueError::Encoding)?,
            critical: true,
            extn_value: x509_cert::der::asn1::OctetString::new(
                usages.to_der().map_err(|_| RsaPssLabIssueError::Encoding)?,
            )
            .map_err(|_| RsaPssLabIssueError::Encoding)?,
        },
    ];
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[0x01]).map_err(|_| RsaPssLabIssueError::Encoding)?,
        signature: algorithm.clone(),
        issuer: name.clone(),
        validity: Validity::from_now(Duration::from_secs(86_400))
            .map_err(|_| RsaPssLabIssueError::Encoding)?,
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let message = tbs.to_der().map_err(|_| RsaPssLabIssueError::Encoding)?;
    let signature = signer
        .sign(signer.key_ref(), SignatureAlgorithm::RsaPssSha256, &message)
        .map_err(|_| RsaPssLabIssueError::Signature)?;
    signer
        .verify(&message, &signature)
        .map_err(|_| RsaPssLabIssueError::Signature)?;
    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature).map_err(|_| RsaPssLabIssueError::Encoding)?,
    };
    let der = certificate
        .to_der()
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    preflight_pss_certificate_der(&der).map_err(|_| RsaPssLabIssueError::Encoding)?;
    Ok(certificate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_rsa_pss_x509_fixture() {
        let cert = issue_ephemeral_rsa_pss_root().unwrap();
        assert_eq!(
            cert.signature_algorithm.oid.to_string(),
            "1.2.840.113549.1.1.10"
        );
        assert_eq!(cert.tbs_certificate.signature, cert.signature_algorithm);
        assert_eq!(cert.tbs_certificate.version, Version::V3);
        assert_eq!(
            Certificate::from_der(&cert.to_der().unwrap()).unwrap(),
            cert
        );
    }
}
