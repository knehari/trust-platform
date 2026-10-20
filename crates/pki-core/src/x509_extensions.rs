//! Explicit certificate-policy binding and subject/authority key identifiers.
//!
//! RFC 7093 method 1: first 160 bits of SHA-256 over subjectPublicKey BIT STRING
//! (excluding the unused-bits count octet). SHA-256 is not a signature algorithm here.
//! This is laboratory certificate metadata only, not approved CP/CPS publishing.

use sha2::{Digest, Sha256};
use x509_cert::{
    der::{
        asn1::{ObjectIdentifier, OctetString},
        Encode,
    },
    ext::Extension,
    spki::SubjectPublicKeyInfoOwned,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    MissingSubjectPublicKey,
    MissingApprovedPolicy,
    InvalidPolicyOid,
    InvalidEncoding,
    /// Not an acceptable CRL distribution point URL (see
    /// `crl_distribution_points`).
    InvalidDistributionPoint,
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
        if oid == "2.5.29.32.0"
            || document_version.trim().is_empty()
            || document_version.len() > 128
            || document_sha256 == [0u8; 32]
        {
            return Err(ExtensionError::MissingApprovedPolicy);
        }
        Ok(Self {
            oid: policy_oid,
            document_version: document_version.to_owned(),
            document_sha256,
        })
    }

    pub fn oid(&self) -> ObjectIdentifier {
        self.oid
    }
    pub fn document_version(&self) -> &str {
        &self.document_version
    }
    pub fn document_sha256(&self) -> &[u8; 32] {
        &self.document_sha256
    }
}

pub fn key_identifier(spki: &SubjectPublicKeyInfoOwned) -> Result<[u8; 20], ExtensionError> {
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(ExtensionError::MissingSubjectPublicKey)?;
    if key.is_empty() {
        return Err(ExtensionError::MissingSubjectPublicKey);
    }
    let hash = Sha256::digest(key);
    let mut output = [0u8; 20];
    output.copy_from_slice(&hash[..20]);
    Ok(output)
}

fn extension(oid: &str, critical: bool, der: Vec<u8>) -> Result<Extension, ExtensionError> {
    let object_id = ObjectIdentifier::new(oid).map_err(|_| ExtensionError::InvalidPolicyOid)?;
    Ok(Extension {
        extn_id: object_id,
        critical,
        extn_value: OctetString::new(der).map_err(|_| ExtensionError::InvalidEncoding)?,
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

pub fn certificate_policies(binding: &ApprovedPolicyBinding) -> Result<Extension, ExtensionError> {
    // CertificatePolicies ::= SEQUENCE OF PolicyInformation
    // PolicyInformation ::= SEQUENCE { policyIdentifier OBJECT IDENTIFIER, ... }
    // A single OID, no qualifiers: exact, simple DER short-form structure.
    let oid_der = binding
        .oid
        .to_der()
        .map_err(|_| ExtensionError::InvalidEncoding)?;
    if oid_der.len() > 125 {
        return Err(ExtensionError::InvalidEncoding);
    }
    let mut policy_information = vec![0x30, oid_der.len() as u8];
    policy_information.extend_from_slice(&oid_der);
    if policy_information.len() > 127 {
        return Err(ExtensionError::InvalidEncoding);
    }
    let mut policies = vec![0x30, policy_information.len() as u8];
    policies.extend_from_slice(&policy_information);
    extension("2.5.29.32", false, policies)
}

pub const CRL_DISTRIBUTION_POINTS_OID: &str = "2.5.29.31";

/// The lab distribution point URL of a CA (`crl_distribution` binary,
/// migration 0030): `<base>/crl/<ca-uuid>.crl`.
pub fn crl_distribution_url(base: &str, ca_id: &str) -> String {
    format!("{}/crl/{ca_id}.crl", base.trim_end_matches('/'))
}

/// RFC 5280 4.2.1.13 cRLDistributionPoints with exactly one distribution
/// point whose fullName is one URI, no reasons, no cRLIssuer; non-critical.
/// Only plain `http://` is accepted: RFC 5280 relying parties fetch CRLs
/// over HTTP, and HTTPS would make revocation checking depend on another
/// certificate's revocation status. The URL must name a host, be printable
/// ASCII without spaces, user information or fragment, and stay under 2 KiB.
pub fn crl_distribution_points(url: &str) -> Result<Extension, ExtensionError> {
    use x509_cert::{
        der::asn1::Ia5String,
        ext::pkix::{
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName},
            CrlDistributionPoints,
        },
    };
    let invalid = ExtensionError::InvalidDistributionPoint;
    let rest = url.strip_prefix("http://").ok_or(invalid.clone())?;
    let host = rest.split(['/', '?']).next().unwrap_or_default();
    if url.len() > 2048
        || host.is_empty()
        || !url.bytes().all(|b| b.is_ascii_graphic())
        || url.contains(['@', '#', '\\'])
    {
        return Err(invalid);
    }
    let name = Ia5String::new(url).map_err(|_| invalid.clone())?;
    let points = CrlDistributionPoints(vec![DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![
            GeneralName::UniformResourceIdentifier(name),
        ])),
        reasons: None,
        crl_issuer: None,
    }]);
    extension(
        CRL_DISTRIBUTION_POINTS_OID,
        false,
        points.to_der().map_err(|_| invalid)?,
    )
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
        let b = ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "lab-doc-v1", [3; 32]).unwrap();
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
            OctetString::from_der(ski.extn_value.as_bytes())
                .unwrap()
                .as_bytes(),
            &value
        );
        let aki = authority_key_identifier(&value).unwrap();
        assert_eq!(&aki.extn_value.as_bytes()[..4], &[0x30, 0x16, 0x80, 0x14]);
        assert_eq!(&aki.extn_value.as_bytes()[4..], &value);
    }

    #[test]
    fn crl_distribution_point_is_one_http_uri() {
        let url = crl_distribution_url(
            "http://crl.lab.invalid:8082/",
            "5eedc0de-0000-4000-8000-000000000031",
        );
        assert_eq!(
            url,
            "http://crl.lab.invalid:8082/crl/5eedc0de-0000-4000-8000-000000000031.crl"
        );
        let ext = crl_distribution_points(&url).unwrap();
        assert_eq!(ext.extn_id.to_string(), CRL_DISTRIBUTION_POINTS_OID);
        assert!(!ext.critical);
        // SEQUENCE { SEQUENCE { [0] { [0] { [6] url } } } }
        let der = ext.extn_value.as_bytes();
        let n = url.len();
        assert_eq!(
            &der[..10],
            &[
                0x30,
                (n + 8) as u8,
                0x30,
                (n + 6) as u8,
                0xa0,
                (n + 4) as u8,
                0xa0,
                (n + 2) as u8,
                0x86,
                n as u8
            ]
        );
        assert_eq!(&der[10..], url.as_bytes());
        for bad in [
            "https://crl.lab.invalid/crl/x.crl",
            "ldap://crl.lab.invalid/x",
            "http:///crl/x.crl",
            "http://user@crl.lab.invalid/x.crl",
            "http://crl.lab.invalid/x.crl#frag",
            "http://crl.lab.invalid/a b.crl",
            "http://crl.lab.invalid/\u{e9}.crl",
        ] {
            assert_eq!(
                crl_distribution_points(bad),
                Err(ExtensionError::InvalidDistributionPoint),
                "{bad}"
            );
        }
        let long = format!("http://crl.lab.invalid/{}", "a".repeat(2100));
        assert!(crl_distribution_points(&long).is_err());
    }
}
