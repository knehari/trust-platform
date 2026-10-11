//! Parse an observed CA public certificate, not asserted runtime configuration.
//! LAB ONLY: narrow self-signed ECDSA P-256 root profile; the independently
//! pinned SHA256 establishes trust. This does not observe live HSM key custody.

use sha2::{Digest, Sha256};
use trust_pki_crypto::verify_p256_ecdsa_sha256;
use x509_cert::{
    der::{Decode, Encode},
    ext::pkix::{BasicConstraints, KeyUsage, KeyUsages},
    Certificate, Version,
};

const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";
const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";
const KEY_USAGE_OID: &str = "2.5.29.15";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationError {
    MissingExternalPin,
    InvalidCertificate,
    FingerprintMismatch,
    InvalidCaConstraints,
    InvalidSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCaPublicCertificate {
    certificate_der: Vec<u8>,
    certificate_sha256: [u8; 32],
    spki_sha256: [u8; 32],
}
impl ObservedCaPublicCertificate {
    pub fn certificate_der(&self) -> &[u8] { &self.certificate_der }
    pub fn certificate_sha256(&self) -> &[u8; 32] { &self.certificate_sha256 }
    pub fn spki_sha256(&self) -> &[u8; 32] { &self.spki_sha256 }
}

/// expected_fingerprint MUST come from trusted independent configuration.
/// Computing it from the same untrusted DER would constitute self-asserted trust.
/// This validates the real CA certificate bytes supplied to this observer,
/// not the CA service configuration, deployed profiles, HSM possession or time.
pub fn observe_pinned_lab_ca(
    certificate_der: &[u8],
    expected_fingerprint: &[u8; 32],
) -> Result<ObservedCaPublicCertificate, ObservationError> {
    if expected_fingerprint == &[0; 32] {
        return Err(ObservationError::MissingExternalPin);
    }
    if certificate_der.is_empty() || certificate_der.len() > 65_536 {
        return Err(ObservationError::InvalidCertificate);
    }
    let digest: [u8; 32] = Sha256::digest(certificate_der).into();
    if &digest != expected_fingerprint {
        return Err(ObservationError::FingerprintMismatch);
    }
    let cert = Certificate::from_der(certificate_der)
        .map_err(|_| ObservationError::InvalidCertificate)?;
    if cert.to_der().map_err(|_| ObservationError::InvalidCertificate)?
        != certificate_der
    {
        return Err(ObservationError::InvalidCertificate);
    }
    if cert.tbs_certificate.version != Version::V3
        || cert.tbs_certificate.issuer != cert.tbs_certificate.subject
        || cert.signature_algorithm != cert.tbs_certificate.signature
        || cert.signature_algorithm.oid.to_string() != ECDSA_SHA256_OID
        || cert.signature_algorithm.parameters.is_some()
        || cert.tbs_certificate.subject_public_key_info.algorithm.oid.to_string()
            != EC_PUBLIC_KEY_OID
    {
        return Err(ObservationError::InvalidCaConstraints);
    }
    let extensions = cert.tbs_certificate.extensions.as_ref()
        .ok_or(ObservationError::InvalidCaConstraints)?;
    let constraints: Vec<_> = extensions.iter()
        .filter(|x| x.extn_id.to_string() == BASIC_CONSTRAINTS_OID).collect();
    let usages: Vec<_> = extensions.iter()
        .filter(|x| x.extn_id.to_string() == KEY_USAGE_OID).collect();
    if constraints.len() != 1 || usages.len() != 1
        || !constraints[0].critical || !usages[0].critical
    {
        return Err(ObservationError::InvalidCaConstraints);
    }
    let bc = BasicConstraints::from_der(constraints[0].extn_value.as_bytes())
        .map_err(|_| ObservationError::InvalidCaConstraints)?;
    let ku = KeyUsage::from_der(usages[0].extn_value.as_bytes())
        .map_err(|_| ObservationError::InvalidCaConstraints)?;
    if !bc.ca || bc.path_len_constraint != Some(0)
        || ku != KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
    {
        return Err(ObservationError::InvalidCaConstraints);
    }
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let sec1 = spki.subject_public_key.as_bytes()
        .ok_or(ObservationError::InvalidCaConstraints)?;
    let tbs_der = cert.tbs_certificate.to_der()
        .map_err(|_| ObservationError::InvalidCertificate)?;
    let signature = cert.signature.as_bytes()
        .ok_or(ObservationError::InvalidSignature)?;
    verify_p256_ecdsa_sha256(sec1, &tbs_der, signature)
        .map_err(|_| ObservationError::InvalidSignature)?;
    let spki_der = spki.to_der().map_err(|_| ObservationError::InvalidCertificate)?;
    Ok(ObservedCaPublicCertificate {
        certificate_der: certificate_der.to_vec(),
        certificate_sha256: digest,
        spki_sha256: Sha256::digest(&spki_der).into(),
    })
}

#[cfg(all(test, feature = "lab-software"))]
mod tests {
    use super::*;
    use crate::lab_ca::EphemeralLabCa;

    #[test]
    fn pinned_self_signed_lab_root_is_observed() {
        let ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let der = ca.root_certificate().to_der().unwrap();
        let digest: [u8; 32] = Sha256::digest(&der).into();
        let observed = observe_pinned_lab_ca(&der, &digest).unwrap();
        assert_eq!(observed.certificate_der(), &der);
        assert_eq!(observed.certificate_sha256(), &digest);
        assert_ne!(observed.spki_sha256(), &[0; 32]);
    }

    #[test]
    fn wrong_external_pin_and_modified_signature_are_denied() {
        let ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let der = ca.root_certificate().to_der().unwrap();
        assert_eq!(
            observe_pinned_lab_ca(&der, &[9; 32]),
            Err(ObservationError::FingerprintMismatch)
        );
        assert_eq!(
            observe_pinned_lab_ca(&der, &[0; 32]),
            Err(ObservationError::MissingExternalPin)
        );
        let mut tampered = der;
        *tampered.last_mut().unwrap() ^= 0x01;
        let tampered_hash: [u8; 32] = Sha256::digest(&tampered).into();
        assert_eq!(
            observe_pinned_lab_ca(&tampered, &tampered_hash),
            Err(ObservationError::InvalidSignature)
        );
    }
}
