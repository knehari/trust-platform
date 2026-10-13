//! Isolated RSA-PSS X.509 root fixture. Not a production CA or general issuer.
use crate::csr::VerifiedCsr;
use crate::rsa_pss_identifier::{preflight_pss_certificate_der, PSS_SHA256_MGF1_SHA256_SALT32_DER};
use crate::serial::SerialNumber as ReservedSerial;
use crate::serial_binding::verify_certificate_reserved_serial;
use crate::x509_extensions::{self, ApprovedPolicyBinding};
use std::{str::FromStr, time::Duration};
use trust_pki_crypto::{
    rsa_pss_lab::{generate_lab_serial, EphemeralRsaPssLabSigner},
    KeyRef, SignatureAlgorithm, SigningProvider,
};
use trust_pki_policy::Authorization;
use x509_cert::{
    der::{
        asn1::{Any, BitString, Ia5String, ObjectIdentifier, OctetString},
        Decode, Encode,
    },
    ext::{
        pkix::{
            name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
            SubjectAltName,
        },
        Extension,
    },
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
    UnauthorizedProfile,
}

/// Generates a disposable RSA-3072 self-signed root certificate with explicit
/// RSA-PSS SHA-256/MGF1-SHA256/32-byte salt parameters, for OpenSSL interop.
pub fn issue_ephemeral_rsa_pss_root() -> Result<Certificate, RsaPssLabIssueError> {
    create_root_and_signer().map(|(root, _)| root)
}

fn create_root_and_signer() -> Result<(Certificate, EphemeralRsaPssLabSigner), RsaPssLabIssueError>
{
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
        serial_number: SerialNumber::new(&generate_lab_serial())
            .map_err(|_| RsaPssLabIssueError::Encoding)?,
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
    Ok((certificate, signer))
}

/// Issues one disposable lab server certificate from independently verified CSR
/// data and a policy-issued authorization. This does not replace durable serials,
/// HSM-backed signing, publication or revocation. The caller supplies a serial
/// already reserved by its issuer-scoped store; this function does not reserve it.
pub fn issue_ephemeral_rsa_pss_server_chain(
    csr: &VerifiedCsr,
    approval: &Authorization,
    policy: &ApprovedPolicyBinding,
    reserved_serial: &ReservedSerial,
) -> Result<(Certificate, Certificate), RsaPssLabIssueError> {
    if approval.ca_signature_algorithm() != SignatureAlgorithm::RsaPssSha256
        || approval.validity_days() == 0
        || approval.validity_days() > 3
        || approval.dns_sans().is_empty()
    {
        return Err(RsaPssLabIssueError::UnauthorizedProfile);
    }
    let expected = Name::from_str(&format!("CN={}", approval.common_name()))
        .map_err(|_| RsaPssLabIssueError::UnauthorizedProfile)?;
    if csr.subject() != &expected {
        return Err(RsaPssLabIssueError::UnauthorizedProfile);
    }
    let (root, signer) = create_root_and_signer()?;
    let algorithm = root.signature_algorithm.clone();
    let sans = approval
        .dns_sans()
        .iter()
        .map(|name| {
            Ia5String::new(name)
                .map(GeneralName::DnsName)
                .map_err(|_| RsaPssLabIssueError::UnauthorizedProfile)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let extension =
        |id: &str, critical: bool, der: Vec<u8>| -> Result<Extension, RsaPssLabIssueError> {
            Ok(Extension {
                extn_id: ObjectIdentifier::new(id).map_err(|_| RsaPssLabIssueError::Encoding)?,
                critical,
                extn_value: OctetString::new(der).map_err(|_| RsaPssLabIssueError::Encoding)?,
            })
        };
    let subject_key_id = x509_extensions::key_identifier(csr.subject_public_key())
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    let root_key_id =
        x509_extensions::key_identifier(&root.tbs_certificate.subject_public_key_info)
            .map_err(|_| RsaPssLabIssueError::Encoding)?;
    let extensions = vec![
        extension(
            "2.5.29.19",
            true,
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_der()
            .map_err(|_| RsaPssLabIssueError::Encoding)?,
        )?,
        extension(
            "2.5.29.15",
            true,
            KeyUsage(KeyUsages::DigitalSignature.into())
                .to_der()
                .map_err(|_| RsaPssLabIssueError::Encoding)?,
        )?,
        extension(
            "2.5.29.37",
            false,
            ExtendedKeyUsage(vec![ObjectIdentifier::new("1.3.6.1.5.5.7.3.1")
                .map_err(|_| RsaPssLabIssueError::Encoding)?])
            .to_der()
            .map_err(|_| RsaPssLabIssueError::Encoding)?,
        )?,
        extension(
            "2.5.29.17",
            false,
            SubjectAltName(sans)
                .to_der()
                .map_err(|_| RsaPssLabIssueError::Encoding)?,
        )?,
        x509_extensions::subject_key_identifier(&subject_key_id)
            .map_err(|_| RsaPssLabIssueError::Encoding)?,
        x509_extensions::authority_key_identifier(&root_key_id)
            .map_err(|_| RsaPssLabIssueError::Encoding)?,
        x509_extensions::certificate_policies(policy)
            .map_err(|_| RsaPssLabIssueError::UnauthorizedProfile)?,
    ];
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(reserved_serial.as_der_content())
            .map_err(|_| RsaPssLabIssueError::Encoding)?,
        signature: algorithm.clone(),
        issuer: root.tbs_certificate.subject.clone(),
        validity: Validity::from_now(Duration::from_secs(
            u64::from(approval.validity_days()) * 86_400,
        ))
        .map_err(|_| RsaPssLabIssueError::Encoding)?,
        subject: csr.subject().clone(),
        subject_public_key_info: csr.subject_public_key().clone(),
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
    let leaf = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature).map_err(|_| RsaPssLabIssueError::Encoding)?,
    };
    let der = leaf.to_der().map_err(|_| RsaPssLabIssueError::Encoding)?;
    preflight_pss_certificate_der(&der).map_err(|_| RsaPssLabIssueError::Encoding)?;
    verify_certificate_reserved_serial(&der, reserved_serial)
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    Ok((root, leaf))
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
