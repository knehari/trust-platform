//! Independent ECDSA/P-256 X.509 verifier for lab-only orchestrator tests.
//! Does not validate RFC 5280 paths, expiry against trusted time, revocation,
//! policy provenance, key custody, certificate transparency or QTSP status.

use crate::orchestrator::{CertificateAssembler, CertificateVerifier, IssueError, IssuancePlan};
use crate::x509_extensions::{certificate_policies, ApprovedPolicyBinding};
use trust_pki_crypto::verify_p256_ecdsa_sha256;
use x509_cert::{
    der::{asn1::BitString, Decode, Encode},
    ext::pkix::{name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName},
    Certificate, TbsCertificate,
};

const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const P256_SPKI: &str = "1.2.840.10045.2.1";
const POLICY_OID: &str = "2.5.29.32";
const SAN_OID: &str = "2.5.29.17";
const SERVER_AUTH_OID: &str = "2.5.29.37";
const KEY_USAGE_OID: &str = "2.5.29.15";
const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";

/// Assembles a certificate from EXACTLY the bytes previously journaled.
pub struct LabCertificateAssembler;
impl CertificateAssembler for LabCertificateAssembler {
    fn assemble(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>, IssueError> {
        let tbs = TbsCertificate::from_der(tbs_der)
            .map_err(|_| IssueError::AssemblyFailure)?;
        if tbs.signature.oid.to_string() != ECDSA_SHA256 || tbs.signature.parameters.is_some() {
            return Err(IssueError::AssemblyFailure);
        }
        let cert = Certificate {
            signature_algorithm: tbs.signature.clone(),
            tbs_certificate: tbs,
            signature: BitString::from_bytes(signature).map_err(|_| IssueError::AssemblyFailure)?,
        };
        cert.to_der().map_err(|_| IssueError::AssemblyFailure)
    }
}

/// The approved policy binding and issuer certificate MUST originate from trusted
/// service-side records. Lab constructor does not establish that provenance.
pub struct LabX509Verifier {
    issuer: Certificate,
    policy: ApprovedPolicyBinding,
    authorized_dns: String,
}

impl LabX509Verifier {
    pub fn new(issuer: Certificate, policy: ApprovedPolicyBinding, authorized_dns: String) -> Self {
        Self { issuer, policy, authorized_dns }
    }
}

impl CertificateVerifier for LabX509Verifier {
    fn verify(&self, plan: &IssuancePlan<'_>, bytes: &[u8]) -> Result<(), IssueError> {
        let fail = IssueError::VerificationFailure;
        let cert = Certificate::from_der(bytes).map_err(|_| fail.clone())?;
        let tbs = cert.tbs_certificate.to_der().map_err(|_| fail.clone())?;
        // This comparison makes the journaled TBS authoritative. Never accept a
        // new TBS constructed after the signature intent has been persisted.
        if tbs.as_slice() != plan.tbs_der {
            return Err(fail);
        }
        if cert.signature_algorithm != cert.tbs_certificate.signature
            || cert.signature_algorithm.oid.to_string() != ECDSA_SHA256
            || cert.signature_algorithm.parameters.is_some()
            || self.issuer.tbs_certificate.subject != cert.tbs_certificate.issuer
        {
            return Err(fail);
        }

        let serial_der = cert.tbs_certificate.serial_number.as_bytes();
        if serial_der != plan.serial_der {
            return Err(fail);
        }
        let issuer_key = &self.issuer.tbs_certificate.subject_public_key_info;
        if issuer_key.algorithm.oid.to_string() != P256_SPKI {
            return Err(fail);
        }
        let sec1 = issuer_key.subject_public_key.as_bytes().ok_or_else(|| fail.clone())?;
        let signature = cert.signature.as_bytes().ok_or_else(|| fail.clone())?;
        verify_p256_ecdsa_sha256(sec1, &tbs, signature).map_err(|_| fail.clone())?;

        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| fail.clone())?;
        let expected = certificate_policies(&self.policy).map_err(|_| fail.clone())?;
        let actual: Vec<_> = extensions
            .iter()
            .filter(|ext| ext.extn_id.to_string() == POLICY_OID)
            .collect();
        if actual.len() != 1 || actual[0] != &expected {
            return Err(fail);
        }
        for id in [SAN_OID, SERVER_AUTH_OID, KEY_USAGE_OID, BASIC_CONSTRAINTS_OID] {
            if extensions.iter().filter(|e| e.extn_id.to_string() == id).count() != 1 {
                return Err(fail);
            }
        }

        // Decode the actual ASN.1 SAN sequence; never accept raw substring matches.
        let san = extensions.iter().find(|e| e.extn_id.to_string() == SAN_OID)
            .ok_or_else(|| fail.clone())?;
        let san_decoded = SubjectAltName::from_der(san.extn_value.as_bytes())
            .map_err(|_| fail.clone())?;
        if san_decoded.0.len() != 1 {
            return Err(fail);
        }
        match &san_decoded.0[0] {
            GeneralName::DnsName(name) if name.as_str() == self.authorized_dns => {}
            _ => return Err(fail),
        }
        let constraints = extensions.iter().find(|e| e.extn_id.to_string() == BASIC_CONSTRAINTS_OID)
            .ok_or_else(|| fail.clone())?;
        let bc = BasicConstraints::from_der(constraints.extn_value.as_bytes())
            .map_err(|_| fail.clone())?;
        if bc.ca || bc.path_len_constraint.is_some() || !constraints.critical {
            return Err(fail);
        }
        let key_use = extensions.iter().find(|e| e.extn_id.to_string() == KEY_USAGE_OID)
            .ok_or_else(|| fail.clone())?;
        let ku = KeyUsage::from_der(key_use.extn_value.as_bytes())
            .map_err(|_| fail.clone())?;
        if ku != KeyUsage(KeyUsages::DigitalSignature.into()) || !key_use.critical {
            return Err(fail);
        }
        let eku_ext = extensions.iter().find(|e| e.extn_id.to_string() == SERVER_AUTH_OID)
            .ok_or_else(|| fail.clone())?;
        let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
            .map_err(|_| fail.clone())?;
        if eku.0.len() != 1 || eku.0[0].to_string() != "1.3.6.1.5.5.7.3.1" {
            return Err(fail);
        }
        Ok(())
    }
}
