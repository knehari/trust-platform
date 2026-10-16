//! Isolated RSA-PSS X.509 root fixture. Not a production CA or general issuer.
use crate::csr::VerifiedCsr;
use crate::rsa_pss_identifier::preflight_pss_certificate_der;
use crate::serial::SerialNumber as ReservedSerial;
use crate::serial_binding::verify_certificate_reserved_serial;
use crate::x509_extensions::{self, ApprovedPolicyBinding};
use std::{str::FromStr, time::Duration};
use trust_pki_crypto::{
    crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme},
    rsa_pss_lab::{generate_lab_serial, EphemeralRsaPssLabSigner},
    KeyRef, SignatureAlgorithm, SigningProvider,
};
use trust_pki_policy::Authorization;
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
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
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

fn preflight_typed_pss_algorithm(
    certificate: &Certificate,
    digest: Digest,
) -> Result<(), RsaPssLabIssueError> {
    let suite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPss,
        key: KeyParameter::Rsa3072,
        digest,
    };
    let expected = crate::agile_x509_identifier::signature_algorithm_identifier(suite)
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    crate::agile_x509_identifier::preflight_certificate_algorithm(certificate, &expected)
        .map_err(|_| RsaPssLabIssueError::Encoding)
}

/// Generates a disposable RSA-3072 self-signed root certificate with explicit
/// RSA-PSS SHA-256/MGF1-SHA256/32-byte salt parameters, for OpenSSL interop.
pub fn issue_ephemeral_rsa_pss_root() -> Result<Certificate, RsaPssLabIssueError> {
    create_root_and_signer().map(|(root, _)| root)
}

/// Returns a disposable issuer and private signer for isolated integration tests.
/// Never persist or expose the ephemeral private key in production.
pub fn create_root_and_signer(
) -> Result<(Certificate, EphemeralRsaPssLabSigner), RsaPssLabIssueError> {
    create_root_and_signer_for_digest(Digest::Sha256)
}

/// Creates a self-signed disposable RSA-3072 lab root with an explicit typed
/// SHA-256/384/512 RSASSA-PSS profile. Not a production issuer.
pub fn create_root_and_signer_for_digest(
    digest: Digest,
) -> Result<(Certificate, EphemeralRsaPssLabSigner), RsaPssLabIssueError> {
    let suite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPss,
        key: KeyParameter::Rsa3072,
        digest,
    };
    let signer = EphemeralRsaPssLabSigner::generate(KeyRef("pss-x509-lab".into()))
        .map_err(|_| RsaPssLabIssueError::Key)?;
    let spki_der = signer
        .public_key_spki_der(signer.key_ref())
        .map_err(|_| RsaPssLabIssueError::Key)?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    let name = Name::from_str("CN=Sovereign Trust RSA-PSS Lab Root")
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    let algorithm = crate::agile_x509_identifier::signature_algorithm_identifier(suite)
        .map_err(|_| RsaPssLabIssueError::UnauthorizedProfile)?;
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
        .sign_suite(signer.key_ref(), suite, &message)
        .map_err(|_| RsaPssLabIssueError::Signature)?;
    signer
        .verify_suite(suite, &message, &signature)
        .map_err(|_| RsaPssLabIssueError::Signature)?;
    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature).map_err(|_| RsaPssLabIssueError::Encoding)?,
    };
    let der = certificate
        .to_der()
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    if digest == Digest::Sha256 {
        preflight_pss_certificate_der(&der).map_err(|_| RsaPssLabIssueError::Encoding)?;
    } else if Certificate::from_der(&der).map_err(|_| RsaPssLabIssueError::Encoding)? != certificate
    {
        return Err(RsaPssLabIssueError::Encoding);
    }
    crate::rsa_pss_identifier::check_pss_identifiers_for_digest(
        &certificate.tbs_certificate.signature,
        &certificate.signature_algorithm,
        digest,
    )
    .map_err(|_| RsaPssLabIssueError::Encoding)?;
    preflight_typed_pss_algorithm(&certificate, digest)?;
    Ok((certificate, signer))
}

/// Issues one disposable lab server certificate from independently verified CSR
/// data and a policy-issued authorization. This does not replace durable serials,
/// HSM-backed signing, publication or revocation. The caller supplies a serial
/// already reserved by its issuer-scoped store; this function does not reserve it.
/// Prepare a canonical, unsigned TLS-server TBS from approved inputs, using
/// the serial already atomically reserved by the caller. No signing occurs.
pub fn prepare_rsa_pss_server_tbs(
    csr: &VerifiedCsr,
    approval: &Authorization,
    policy: &ApprovedPolicyBinding,
    reserved_serial: &ReservedSerial,
    root: &Certificate,
) -> Result<TbsCertificate, RsaPssLabIssueError> {
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
    Ok(tbs)
}

pub fn issue_ephemeral_rsa_pss_server_chain(
    csr: &VerifiedCsr,
    approval: &Authorization,
    policy: &ApprovedPolicyBinding,
    reserved_serial: &ReservedSerial,
) -> Result<(Certificate, Certificate), RsaPssLabIssueError> {
    let (root, signer) = create_root_and_signer()?;
    let tbs = prepare_rsa_pss_server_tbs(csr, approval, policy, reserved_serial, &root)?;
    let algorithm = tbs.signature.clone();
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
    preflight_typed_pss_algorithm(&leaf, Digest::Sha256)?;
    verify_certificate_reserved_serial(&der, reserved_serial)
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    Ok((root, leaf))
}


/// Signs one disposable TLS server certificate with a typed RSA-PSS profile.
/// The caller must supply the *trusted* profile-specific suite allowlist.
/// A legacy SHA-256 authorization does NOT by itself authorize SHA-384/512.
/// All CSR identity/SAN/validity checks are still enforced by the legacy
/// approval; a separate suite check is mandatory until the native typed
/// policy engine can issue a durable suite-bound Authorization.
pub fn issue_ephemeral_rsa_pss_server_chain_for_digest(
    csr: &VerifiedCsr,
    approval: &Authorization,
    policy: &ApprovedPolicyBinding,
    reserved_serial: &ReservedSerial,
    digest: Digest,
    trusted_allowed_suites: &[AlgorithmSuite],
) -> Result<(Certificate, Certificate), RsaPssLabIssueError> {
    let suite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPss,
        key: KeyParameter::Rsa3072,
        digest,
    };
    if !trusted_allowed_suites.contains(&suite) {
        return Err(RsaPssLabIssueError::UnauthorizedProfile);
    }
    let (root, signer) = create_root_and_signer_for_digest(digest)?;
    let tbs = prepare_rsa_pss_server_tbs(csr, approval, policy, reserved_serial, &root)?;
    let expected = crate::agile_x509_identifier::signature_algorithm_identifier(suite)
        .map_err(|_| RsaPssLabIssueError::UnauthorizedProfile)?;
    if tbs.signature != expected {
        return Err(RsaPssLabIssueError::UnauthorizedProfile);
    }
    let message = tbs.to_der().map_err(|_| RsaPssLabIssueError::Encoding)?;
    let signature = signer
        .sign_suite(signer.key_ref(), suite, &message)
        .map_err(|_| RsaPssLabIssueError::Signature)?;
    signer
        .verify_suite(suite, &message, &signature)
        .map_err(|_| RsaPssLabIssueError::Signature)?;
    let leaf = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: expected,
        signature: BitString::from_bytes(&signature).map_err(|_| RsaPssLabIssueError::Encoding)?,
    };
    let der = leaf.to_der().map_err(|_| RsaPssLabIssueError::Encoding)?;
    if Certificate::from_der(&der).map_err(|_| RsaPssLabIssueError::Encoding)? != leaf {
        return Err(RsaPssLabIssueError::Encoding);
    }
    crate::rsa_pss_identifier::check_pss_identifiers_for_digest(
        &leaf.tbs_certificate.signature,
        &leaf.signature_algorithm,
        digest,
    )
    .map_err(|_| RsaPssLabIssueError::Encoding)?;
    preflight_typed_pss_algorithm(&leaf, digest)?;
    verify_certificate_reserved_serial(&der, reserved_serial)
        .map_err(|_| RsaPssLabIssueError::Encoding)?;
    crate::rsa_pss_issuer_verify_lab::verify_typed_rsa_pss_issuer_signature(
        &root, &leaf, suite,
    )
    .map_err(|_| RsaPssLabIssueError::Signature)?;
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
    #[test]
    fn rsa_pss_root_sha384_sha512_validate_typed_issuer_signature() {
        use crate::rsa_pss_issuer_verify_lab::verify_typed_rsa_pss_issuer_signature;
        for digest in [Digest::Sha384, Digest::Sha512] {
            let (root, _) = create_root_and_signer_for_digest(digest).unwrap();
            let suite = AlgorithmSuite {
                scheme: SignatureScheme::RsaPss,
                key: KeyParameter::Rsa3072,
                digest,
            };
            assert_eq!(
                verify_typed_rsa_pss_issuer_signature(&root, &root, suite),
                Ok(())
            );
            let wrong_digest = AlgorithmSuite {
                digest: Digest::Sha256,
                ..suite
            };
            assert!(verify_typed_rsa_pss_issuer_signature(&root, &root, wrong_digest).is_err());
        }
    }
}
