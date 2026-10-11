//! Explicit certificate-policy binding and subject/authority key identifiers.
//!
//! RFC 7093 method 1: first 160 bits of SHA-256 over subjectPublicKey BIT STRING
//! (excluding the unused-bits count octet). SHA-256 is not a signature algorithm here.
//! This is laboratory certificate metadata only, not approved CP/CPS publishing.

use sha2::{Digest, Sha256};
use x509_cert::{
    der::{asn1::{ObjectIdentifier, OctetString}, Encode},
    ext::Extension,
    spki::SubjectPublicKeyInfoOwned,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    MissingSubjectPublicKey,
    MissingApprovedPolicy,
    InvalidPolicyOid,
    InvalidEncoding,
}

/// Tested explicit policy configuration, never taken from CSR attributes.
/// Real approval/version provenance must be verified by a durable control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedPolicyBinding {
    oid: ObjectIdentifier,
    document_version: String,
    document_sha256: [u8; 32],
}

impl ApprovedPolicyBinding {
    pub fn new(
        oid: &str,
        document_version: &str,
        document_sha256: [u8; 32],
    ) -> Result<Self, ExtensionError> {
        let policy_oid =
            ObjectIdentifier::new(oid).map_err(|_| ExtensionError::InvalidPolicyOid)?;
        // anyPolicy and empty/unversioned/unreferenced policies cannot be used.
        if oid == "2.5.29.32.0" || document_version.trim().is_empty()
            || document_version.len() > 128 || document_sha256 == [0u8; 32]
        {
            return Err(ExtensionError::MissingApprovedPolicy);
        }
        Ok(Self {
            oid: policy_oid,
            document_version: document_version.to_owned(),
            document_sha256,
        })
    }

    pub fn oid(&self) -> ObjectIdentifier { self.oid }
    pub fn document_version(&self) -> &str { &self.document_version }
    pub fn document_sha256(&self) -> &[u8; 32] { &self.document_sha256 }
}

pub fn key_identifier(
    spki: &SubjectPublicKeyInfoOwned,
) -> Result<[u8; 20], ExtensionError> {
    let key = spki.subject_public_key.as_bytes()
        .ok_or(ExtensionError::MissingSubjectPublicKey)?;
    if key.is_empty() { return Err(ExtensionError::MissingSubjectPublicKey); }
    let hash = Sha256::digest(key);
    let mut output = [0u8; 20];
    output.copy_from_slice(&hash[..20]);
    Ok(output)
}

fn extension(
    oid: &str,
    critical: bool,
    der: Vec<u8>,
) -> Result<Extension, ExtensionError> {
    let object_id = ObjectIdentifier::new(oid)
        .map_err(|_| ExtensionError::InvalidPolicyOid)?;
    Ok(Extension {
        extn_id: object_id,
        critical,
        extn_value: OctetString::new(der)
            .map_err(|_| ExtensionError::InvalidEncoding)?,
    })
}

pub fn subject_key_identifier(id: &[u8; 20]) -> Result<Extension, ExtensionError> {
    let inner = OctetString::new(*id)
        .map_err(|_| ExtensionError::InvalidEncoding)?
        .to_der()
        .map_err(|_| ExtensionError::InvalidEncoding)?;
    extension("2.5.29.14", false, inner)
}

pub fn authority_key_identifier(id: &[u8; 20]) -> Result<Extension, ExtensionError> {
    // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL ... }
    // Using only keyIdentifier. Fixed-size 20-byte field with short-form DER length.
    let mut inner = Vec::with_capacity(24);
    inner.extend_from_slice(&[0x30, 0x16, 0x80, 0x14]);
    inner.extend_from_slice(id);
    extension("2.5.29.35", false, inner)
}

pub fn certificate_policies(
    binding: &ApprovedPolicyBinding,
) -> Result<Extension, ExtensionError> {
    // CertificatePolicies ::= SEQUENCE OF PolicyInformation
    // PolicyInformation ::= SEQUENCE { policyIdentifier OBJECT IDENTIFIER, ... }
    // A single OID, no qualifiers: exact, simple DER short-form structure.
    let oid_der = binding.oid.to_der()
        .map_err(|_| ExtensionError::InvalidEncoding)?;
    if oid_der.len() > 125 { return Err(ExtensionError::InvalidEncoding); }
    let mut policy_information = vec![0x30, oid_der.len() as u8];
    policy_information.extend_from_slice(&oid_der);
    if policy_information.len() > 127 { return Err(ExtensionError::InvalidEncoding); }
    let mut policies = vec![0x30, policy_information.len() as u8];
    policies.extend_from_slice(&policy_information);
    extension("2.5.29.32", false, policies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::Decode;

    #[test]
    fn policy_binding_fail_closed() {
        assert_eq!(
            ApprovedPolicyBinding::new("2.5.29.32.0", "v1", [7; 32]),
            Err(ExtensionError::MissingApprovedPolicy)
        );
        assert_eq!(
            ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "", [7; 32]),
            Err(ExtensionError::MissingApprovedPolicy)
        );
        assert_eq!(
            ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "v1", [0; 32]),
            Err(ExtensionError::MissingApprovedPolicy)
        );
    }

    #[test]
    fn certificate_policy_is_der_sequence_of_policy_information() {
        // 55555 is a fixture OID only; not a product or organisation OID assignment.
        let b = ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "lab-doc-v1", [3;32]).unwrap();
        let ext = certificate_policies(&b).unwrap();
        let data = ext.extn_value.as_bytes();
        assert_eq!(data[0], 0x30);
        assert_eq!(data[2], 0x30);
        assert_eq!(data[4], 0x06);
        assert!(!ext.critical);
        assert_eq!(b.document_version(), "lab-doc-v1");
        assert_eq!(b.document_sha256(), &[3; 32]);
    }

    #[test]
    fn identifiers_use_expected_der_types() {
        let value = [42u8; 20];
        let ski = subject_key_identifier(&value).unwrap();
        assert_eq!(
            OctetString::from_der(ski.extn_value.as_bytes()).unwrap().as_bytes(),
            &value
        );
        let aki = authority_key_identifier(&value).unwrap();
        assert_eq!(&aki.extn_value.as_bytes()[..4], &[0x30, 0x16, 0x80, 0x14]);
        assert_eq!(&aki.extn_value.as_bytes()[4..], &value);
    }
}
