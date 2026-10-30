//! Lab-only X.509 server certificates signed by ECDSA P-384/P-521 or Ed25519/Ed448.
//! The subject P-256 CSR is cryptographically verified before entry here.
//! Native typed Policy authorizes independent issuer and subject algorithms.
#![cfg(unix)]

use crate::{
    csr::VerifiedCsr,
    native_typed_csr_binding::bind_native_approval_to_verified_csr,
    openssl_classical_x509_lab::create_openssl_classical_root_and_signer_lab,
    serial::SerialNumber as ReservedSerial,
    serial_binding::verify_certificate_reserved_serial,
    x509_extensions::{self, ApprovedPolicyBinding},
};
use std::time::Duration;
use trust_pki_crypto::{
    crypto_agility::AlgorithmSuite, openssl_classical_lab::verify_openssl_spki_lab,
};
use trust_pki_policy::native_typed_policy::NativeTypedAuthorization;
use x509_cert::{
    der::{
        asn1::{BitString, Ia5String, ObjectIdentifier, OctetString},
        Decode, Encode,
    },
    ext::{
        pkix::{
            name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
            SubjectAltName,
        },
        Extension,
    },
    serial_number::SerialNumber,
    time::Validity,
    Certificate, TbsCertificate, Version,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicalServerLabError {
    Unauthorized,
    Encoding,
    Signing,
    InvalidSignature,
}

/// Mathematical issuer signature only, NOT path validation or revocation.
pub fn verify_classical_server_issuer_signature_lab(
    issuer: &Certificate,
    leaf: &Certificate,
    suite: AlgorithmSuite,
) -> Result<(), ClassicalServerLabError> {
    if leaf.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(ClassicalServerLabError::InvalidSignature);
    }
    let identifier = crate::agile_x509_identifier::signature_algorithm_identifier(suite)
        .map_err(|_| ClassicalServerLabError::Unauthorized)?;
    crate::agile_x509_identifier::preflight_certificate_algorithm(leaf, &identifier)
        .map_err(|_| ClassicalServerLabError::InvalidSignature)?;
    crate::openssl_classical_x509_lab::verify_openssl_classical_root_lab(issuer, suite)
        .map_err(|_| ClassicalServerLabError::InvalidSignature)?;
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| ClassicalServerLabError::Encoding)?;
    let tbs = leaf
        .tbs_certificate
        .to_der()
        .map_err(|_| ClassicalServerLabError::Encoding)?;
    let signature = leaf
        .signature
        .as_bytes()
        .ok_or(ClassicalServerLabError::InvalidSignature)?;
    verify_openssl_spki_lab(suite, &spki, &tbs, signature)
        .map_err(|_| ClassicalServerLabError::InvalidSignature)
}

fn extension(
    oid: &str,
    critical: bool,
    bytes: Vec<u8>,
) -> Result<Extension, ClassicalServerLabError> {
    Ok(Extension {
        extn_id: ObjectIdentifier::new(oid).map_err(|_| ClassicalServerLabError::Encoding)?,
        critical,
        extn_value: OctetString::new(bytes).map_err(|_| ClassicalServerLabError::Encoding)?,
    })
}

/// Issues one disposable TLS leaf using only policy-approved SANs and identity.
/// Caller-provided serial must already be reserved in an issuer-scoped store.
pub fn issue_openssl_classical_server_chain_lab(
    csr: &VerifiedCsr,
    approved: &NativeTypedAuthorization,
    policy: &ApprovedPolicyBinding,
    reserved_serial: &ReservedSerial,
) -> Result<(Certificate, Certificate), ClassicalServerLabError> {
    bind_native_approval_to_verified_csr(approved, csr)
        .map_err(|_| ClassicalServerLabError::Unauthorized)?;
    if approved.validity_days() == 0
        || approved.validity_days() > 3
        || approved.dns_sans().is_empty()
    {
        return Err(ClassicalServerLabError::Unauthorized);
    }
    let suite = approved.issuer_suite();
    let (root, signer) = create_openssl_classical_root_and_signer_lab(suite)
        .map_err(|_| ClassicalServerLabError::Unauthorized)?;
    let algorithm = crate::agile_x509_identifier::signature_algorithm_identifier(suite)
        .map_err(|_| ClassicalServerLabError::Unauthorized)?;
    let sans = approved
        .dns_sans()
        .iter()
        .map(|name| {
            Ia5String::new(name)
                .map(GeneralName::DnsName)
                .map_err(|_| ClassicalServerLabError::Unauthorized)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let subject_key_id = x509_extensions::key_identifier(csr.subject_public_key())
        .map_err(|_| ClassicalServerLabError::Encoding)?;
    let root_key_id =
        x509_extensions::key_identifier(&root.tbs_certificate.subject_public_key_info)
            .map_err(|_| ClassicalServerLabError::Encoding)?;
    let extensions = vec![
        extension(
            "2.5.29.19",
            true,
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_der()
            .map_err(|_| ClassicalServerLabError::Encoding)?,
        )?,
        extension(
            "2.5.29.15",
            true,
            KeyUsage(KeyUsages::DigitalSignature.into())
                .to_der()
                .map_err(|_| ClassicalServerLabError::Encoding)?,
        )?,
        extension(
            "2.5.29.37",
            false,
            ExtendedKeyUsage(vec![ObjectIdentifier::new("1.3.6.1.5.5.7.3.1")
                .map_err(|_| ClassicalServerLabError::Encoding)?])
            .to_der()
            .map_err(|_| ClassicalServerLabError::Encoding)?,
        )?,
        extension(
            "2.5.29.17",
            false,
            SubjectAltName(sans)
                .to_der()
                .map_err(|_| ClassicalServerLabError::Encoding)?,
        )?,
        x509_extensions::subject_key_identifier(&subject_key_id)
            .map_err(|_| ClassicalServerLabError::Encoding)?,
        x509_extensions::authority_key_identifier(&root_key_id)
            .map_err(|_| ClassicalServerLabError::Encoding)?,
        x509_extensions::certificate_policies(policy)
            .map_err(|_| ClassicalServerLabError::Unauthorized)?,
    ];
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(reserved_serial.as_der_content())
            .map_err(|_| ClassicalServerLabError::Encoding)?,
        signature: algorithm.clone(),
        issuer: root.tbs_certificate.subject.clone(),
        validity: Validity::from_now(Duration::from_secs(
            u64::from(approved.validity_days()) * 86_400,
        ))
        .map_err(|_| ClassicalServerLabError::Encoding)?,
        subject: csr.subject().clone(),
        subject_public_key_info: csr.subject_public_key().clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let tbs_bytes = tbs
        .to_der()
        .map_err(|_| ClassicalServerLabError::Encoding)?;
    let signature = signer
        .sign(suite, &tbs_bytes)
        .map_err(|_| ClassicalServerLabError::Signing)?;
    signer
        .verify(suite, &tbs_bytes, &signature)
        .map_err(|_| ClassicalServerLabError::InvalidSignature)?;
    let leaf = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature)
            .map_err(|_| ClassicalServerLabError::Encoding)?,
    };
    let der = leaf
        .to_der()
        .map_err(|_| ClassicalServerLabError::Encoding)?;
    if Certificate::from_der(&der).map_err(|_| ClassicalServerLabError::Encoding)? != leaf {
        return Err(ClassicalServerLabError::Encoding);
    }
    verify_certificate_reserved_serial(&der, reserved_serial)
        .map_err(|_| ClassicalServerLabError::Encoding)?;
    verify_classical_server_issuer_signature_lab(&root, &leaf, suite)?;
    Ok((root, leaf))
}
