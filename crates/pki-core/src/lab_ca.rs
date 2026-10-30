//! Ephemeral laboratory CA, opt-in feature only.
//!
//! Uses a native TBS X.509 builder (x509-cert) and a RustCrypto signer.
//! NEVER deploy it as an operational CA: no durable issuance, no real HSM,
//! no persisted key, no revocation authority, no independent security audit.

use crate::csr::VerifiedCsr;
use crate::serial::{
    InMemorySerialReservations, SerialNumber as SerialBytes, SerialReservationStore,
};
use crate::x509_extensions::{self, ApprovedPolicyBinding};
use std::str::FromStr;
use std::time::Duration;
use trust_pki_crypto::{
    crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme},
    lab::EphemeralP256Signer,
    SignatureAlgorithm, SigningProvider,
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
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
    Certificate, TbsCertificate, Version,
};

const ECDSA_WITH_SHA256_OID: &str = "1.2.840.10045.4.3.2";
const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";
const KEY_USAGE_OID: &str = "2.5.29.15";
const EXTENDED_KEY_USAGE_OID: &str = "2.5.29.37";
const SERVER_AUTH_OID: &str = "1.3.6.1.5.5.7.3.1";
const SUBJECT_ALT_NAME_OID: &str = "2.5.29.17";
const LAB_ROOT_VALIDITY_DAYS: u64 = 7;
const MAX_LAB_LEAF_VALIDITY_DAYS: u16 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabCaError {
    InvalidProfile,
    InvalidCertificate,
    InvalidKey,
    InvalidState,
    DuplicateSerial,
    SigningFailed,
}

fn oid(input: &str) -> Result<ObjectIdentifier, LabCaError> {
    ObjectIdentifier::new(input).map_err(|_| LabCaError::InvalidProfile)
}

fn extension<T: Encode>(oid_str: &str, critical: bool, value: &T) -> Result<Extension, LabCaError> {
    let der = value.to_der().map_err(|_| LabCaError::InvalidCertificate)?;
    Ok(Extension {
        extn_id: oid(oid_str)?,
        critical,
        extn_value: OctetString::new(der).map_err(|_| LabCaError::InvalidCertificate)?,
    })
}

fn ecdsa_algorithm() -> Result<AlgorithmIdentifierOwned, LabCaError> {
    Ok(AlgorithmIdentifierOwned {
        oid: oid(ECDSA_WITH_SHA256_OID)?,
        parameters: None,
    })
}

fn signed_certificate(
    tbs: TbsCertificate,
    signer: &EphemeralP256Signer,
) -> Result<Certificate, LabCaError> {
    if !signer.supports(SignatureAlgorithm::EcdsaP256Sha256) {
        return Err(LabCaError::InvalidKey);
    }
    let data = tbs.to_der().map_err(|_| LabCaError::InvalidCertificate)?;
    let sig = signer
        .sign(signer.key_ref(), SignatureAlgorithm::EcdsaP256Sha256, &data)
        .map_err(|_| LabCaError::SigningFailed)?;
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_algorithm()?,
        signature: BitString::from_bytes(&sig).map_err(|_| LabCaError::InvalidCertificate)?,
    };
    // Catch internal serialization errors before returning any certificate.
    let encoded = cert.to_der().map_err(|_| LabCaError::InvalidCertificate)?;
    let parsed = Certificate::from_der(&encoded).map_err(|_| LabCaError::InvalidCertificate)?;
    if parsed != cert {
        return Err(LabCaError::InvalidCertificate);
    }
    let suite = AlgorithmSuite {
        scheme: SignatureScheme::Ecdsa,
        key: KeyParameter::P256,
        digest: Digest::Sha256,
    };
    let identifier = crate::agile_x509_identifier::signature_algorithm_identifier(suite)
        .map_err(|_| LabCaError::InvalidCertificate)?;
    crate::agile_x509_identifier::preflight_certificate_algorithm(&parsed, &identifier)
        .map_err(|_| LabCaError::InvalidCertificate)?;
    Ok(cert)
}

/// A single-use process-local issuer for interop testing. Its signing key
/// disappears when the object is dropped; no HSM, DR or publication exists.
pub struct EphemeralLabCa {
    signer: EphemeralP256Signer,
    issuer_name: Name,
    root_certificate: Certificate,
    serials: InMemorySerialReservations,
    issuer_key_id: [u8; 20],
    /// cRLDistributionPoints added to every leaf, when configured.
    crl_distribution_point: Option<Extension>,
}

impl EphemeralLabCa {
    pub fn new(common_name: &str) -> Result<Self, LabCaError> {
        if common_name != "Sovereign Trust Lab Root" {
            return Err(LabCaError::InvalidProfile);
        }
        let issuer_name = Name::from_str("CN=Sovereign Trust Lab Root")
            .map_err(|_| LabCaError::InvalidProfile)?;
        let signer = EphemeralP256Signer::generate("ephemeral-lab-root")
            .map_err(|_| LabCaError::InvalidKey)?;
        let spki_der = signer
            .public_key_spki_der(signer.key_ref())
            .map_err(|_| LabCaError::InvalidKey)?;
        let spki =
            SubjectPublicKeyInfoOwned::from_der(&spki_der).map_err(|_| LabCaError::InvalidKey)?;
        let validity =
            Validity::from_now(Duration::from_secs(LAB_ROOT_VALIDITY_DAYS * 24 * 60 * 60))
                .map_err(|_| LabCaError::InvalidCertificate)?;
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        };
        let usages = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign);
        let issuer_key_id =
            x509_extensions::key_identifier(&spki).map_err(|_| LabCaError::InvalidKey)?;
        let extensions = vec![
            extension(BASIC_CONSTRAINTS_OID, true, &constraints)?,
            extension(KEY_USAGE_OID, true, &usages)?,
            x509_extensions::subject_key_identifier(&issuer_key_id)
                .map_err(|_| LabCaError::InvalidCertificate)?,
            x509_extensions::authority_key_identifier(&issuer_key_id)
                .map_err(|_| LabCaError::InvalidCertificate)?,
        ];
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[0x01])
                .map_err(|_| LabCaError::InvalidCertificate)?,
            signature: ecdsa_algorithm()?,
            issuer: issuer_name.clone(),
            validity,
            subject: issuer_name.clone(),
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        let root_certificate = signed_certificate(tbs, &signer)?;
        Ok(Self {
            signer,
            issuer_name,
            root_certificate,
            serials: InMemorySerialReservations::default(),
            issuer_key_id,
            crl_distribution_point: None,
        })
    }

    /// Leaves issued from now on carry this CRL distribution point
    /// (`x509_extensions::crl_distribution_points`: one plain `http://` URI).
    /// Without it, leaves carry none, as before.
    pub fn set_crl_distribution_point(&mut self, url: &str) -> Result<(), LabCaError> {
        self.crl_distribution_point = Some(
            x509_extensions::crl_distribution_points(url)
                .map_err(|_| LabCaError::InvalidProfile)?,
        );
        Ok(())
    }

    pub fn root_certificate(&self) -> &Certificate {
        &self.root_certificate
    }

    /// A certificate is issued only from independently verified CSR data AND
    /// the policy-authorized subject/SAN/algorithm/validity. CSR extensions
    /// are never copied into the issued certificate.
    pub fn issue_leaf(
        &mut self,
        csr: &VerifiedCsr,
        approval: &Authorization,
        serial: &SerialBytes,
        approved_policy: &ApprovedPolicyBinding,
    ) -> Result<Certificate, LabCaError> {
        let tbs = self.prepare_leaf_tbs(csr, approval, serial, approved_policy)?;
        signed_certificate(tbs, &self.signer)
    }

    /// Create a complete, pre-authorized test-only TBS before persisting intent.
    /// Calling this method reserves the lab serial in volatile memory.
    pub fn prepare_leaf_tbs(
        &mut self,
        csr: &VerifiedCsr,
        approval: &Authorization,
        serial: &SerialBytes,
        approved_policy: &ApprovedPolicyBinding,
    ) -> Result<TbsCertificate, LabCaError> {
        if approval.ca_signature_algorithm() != SignatureAlgorithm::EcdsaP256Sha256
            || approval.validity_days() == 0
            || approval.validity_days() > MAX_LAB_LEAF_VALIDITY_DAYS
            || approval.dns_sans().is_empty()
        {
            return Err(LabCaError::InvalidProfile);
        }
        let expected_name = Name::from_str(&format!("CN={}", approval.common_name()))
            .map_err(|_| LabCaError::InvalidProfile)?;
        if csr.subject() != &expected_name {
            return Err(LabCaError::InvalidProfile);
        }

        let sans = approval
            .dns_sans()
            .iter()
            .map(|name| {
                Ia5String::new(name)
                    .map(GeneralName::DnsName)
                    .map_err(|_| LabCaError::InvalidProfile)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let san = SubjectAltName(sans);
        let ku = KeyUsage(KeyUsages::DigitalSignature.into());
        let bc = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        };
        let eku = ExtendedKeyUsage(vec![oid(SERVER_AUTH_OID)?]);
        let subject_key_id = x509_extensions::key_identifier(csr.subject_public_key())
            .map_err(|_| LabCaError::InvalidKey)?;

        // Lab reservation is process-local. Production MUST have durable,
        // transactionally allocated issuer-scoped serial reservations.
        self.serials
            .reserve(&self.signer.key_ref().0, serial)
            .map_err(|_| LabCaError::DuplicateSerial)?;

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(serial.as_der_content())
                .map_err(|_| LabCaError::InvalidCertificate)?,
            signature: ecdsa_algorithm()?,
            issuer: self.issuer_name.clone(),
            validity: Validity::from_now(Duration::from_secs(
                u64::from(approval.validity_days()) * 24 * 60 * 60,
            ))
            .map_err(|_| LabCaError::InvalidCertificate)?,
            subject: csr.subject().clone(),
            subject_public_key_info: csr.subject_public_key().clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(
                vec![
                    extension(BASIC_CONSTRAINTS_OID, true, &bc)?,
                    extension(KEY_USAGE_OID, true, &ku)?,
                    extension(EXTENDED_KEY_USAGE_OID, false, &eku)?,
                    extension(SUBJECT_ALT_NAME_OID, false, &san)?,
                    x509_extensions::subject_key_identifier(&subject_key_id)
                        .map_err(|_| LabCaError::InvalidCertificate)?,
                    x509_extensions::authority_key_identifier(&self.issuer_key_id)
                        .map_err(|_| LabCaError::InvalidCertificate)?,
                    x509_extensions::certificate_policies(approved_policy)
                        .map_err(|_| LabCaError::InvalidProfile)?,
                ]
                .into_iter()
                .chain(self.crl_distribution_point.clone())
                .collect(),
            ),
        };

        Ok(tbs)
    }

    pub fn lab_signer_key_ref(&self) -> &str {
        &self.signer.key_ref().0
    }
}

/// Public key of the lab signing key; fails for any other key reference.
impl crate::crl_orchestrator::SignerPublicKey for EphemeralLabCa {
    fn signer_spki_der(&self, key_ref: &str) -> Result<Vec<u8>, crate::crl::CrlError> {
        if key_ref != self.signer.key_ref().0 {
            return Err(crate::crl::CrlError::IssuerMismatch);
        }
        self.signer
            .public_key_spki_der(self.signer.key_ref())
            .map_err(|_| crate::crl::CrlError::IssuerMismatch)
    }
}

/// The CA signing key stays in this ephemeral issuer; this is NOT an HSM.
impl crate::orchestrator::ExternalSigner for EphemeralLabCa {
    fn sign_once(
        &mut self,
        key_ref: &str,
        _operation_ref: &str,
        tbs_der: &[u8],
    ) -> Result<Vec<u8>, crate::orchestrator::IssueError> {
        if key_ref != self.signer.key_ref().0 {
            return Err(crate::orchestrator::IssueError::SigningFailure);
        }
        self.signer
            .sign(
                self.signer.key_ref(),
                SignatureAlgorithm::EcdsaP256Sha256,
                tbs_der,
            )
            .map_err(|_| crate::orchestrator::IssueError::SigningFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csr::verify_pkcs10_p256;
    use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
    use x509_cert::der::DecodePem;

    fn authorized() -> (VerifiedCsr, Authorization) {
        let csr = x509_cert::request::CertReq::from_pem(include_str!(
            "../tests/fixtures/ecdsa-p256-request.pem"
        ))
        .unwrap()
        .to_der()
        .unwrap();
        let verified = verify_pkcs10_p256(&csr, "api.lab.invalid").unwrap();
        let policy = StaticPolicy {
            profile_id: "lab-server".to_owned(),
            policy_version: "v1".to_owned(),
            allowed_actors: vec!["lab-requester".to_owned()],
            allowed_dns_zones: vec!["lab.invalid".to_owned()],
            allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
            max_validity_days: 3,
            max_dns_sans: 3,
        };
        let principal = AuthenticatedPrincipal {
            subject_id: "lab-requester",
        };
        let san = ["api.lab.invalid"];
        let request = IssuanceRequest {
            profile_id: "lab-server",
            subject_common_name: "api.lab.invalid",
            dns_sans: &san,
            validity_days: 1,
            ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let authorization = policy.authorize(&principal, &request).unwrap();
        (verified, authorization)
    }

    fn approved_test_policy() -> ApprovedPolicyBinding {
        // Fixture only: private enterprise OID shown is not assigned to this product.
        ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "lab-cp-v1", [9u8; 32]).unwrap()
    }

    #[test]
    fn creates_x509_v3_leaf_from_verified_csr() {
        let (csr, authorization) = authorized();
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let serial = SerialBytes::from_positive_der_content(&[0x02]).unwrap();
        let binding = approved_test_policy();
        let cert = ca
            .issue_leaf(&csr, &authorization, &serial, &binding)
            .unwrap();
        assert_eq!(cert.tbs_certificate.version, Version::V3);
        assert_eq!(cert.tbs_certificate.subject, *csr.subject());
        assert_eq!(
            cert.tbs_certificate.issuer,
            ca.root_certificate().tbs_certificate.subject
        );
        assert_eq!(cert.tbs_certificate.extensions.as_ref().unwrap().len(), 7);
        assert!(Certificate::from_der(&cert.to_der().unwrap()).is_ok());
    }

    #[test]
    fn leaf_aki_matches_root_ski_and_policy_is_explicit() {
        let (csr, approval) = authorized();
        let binding = approved_test_policy();
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let serial = SerialBytes::from_positive_der_content(&[0x42]).unwrap();
        let leaf = ca.issue_leaf(&csr, &approval, &serial, &binding).unwrap();
        let root_extensions = ca
            .root_certificate()
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap();
        let leaf_extensions = leaf.tbs_certificate.extensions.as_ref().unwrap();
        let root_ski = root_extensions
            .iter()
            .find(|e| e.extn_id.to_string() == "2.5.29.14")
            .unwrap();
        let leaf_aki = leaf_extensions
            .iter()
            .find(|e| e.extn_id.to_string() == "2.5.29.35")
            .unwrap();
        let expected_root_key_id = &root_ski.extn_value.as_bytes()[2..];
        assert_eq!(expected_root_key_id.len(), 20);
        assert_eq!(&leaf_aki.extn_value.as_bytes()[4..], expected_root_key_id);
        let policy_extension = leaf_extensions
            .iter()
            .find(|e| e.extn_id.to_string() == "2.5.29.32")
            .unwrap();
        let from_binding = x509_extensions::certificate_policies(&binding).unwrap();
        assert_eq!(policy_extension, &from_binding);
        assert!(!policy_extension.critical);
    }

    /// Leaves carry the configured CRL distribution point; the independent
    /// verifier accepts exactly the approved one and refuses a leaf with a
    /// distribution point it was not told to expect, or without one.
    #[test]
    fn crl_distribution_point_is_issued_and_verified_exactly() {
        use crate::lab_x509_verifier::LabX509Verifier;
        use crate::orchestrator::{CertificateVerifier, IssuancePlan};
        let (csr, approval) = authorized();
        let binding = approved_test_policy();
        let url = "http://127.0.0.1:18083/crl/5eedc0de-0000-4000-8000-000000000031.crl";
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        assert!(matches!(
            ca.set_crl_distribution_point("https://crl.lab.invalid/x.crl"),
            Err(LabCaError::InvalidProfile)
        ));
        let plain_serial = SerialBytes::from_positive_der_content(&[0x07]).unwrap();
        let plain = ca
            .issue_leaf(&csr, &approval, &plain_serial, &binding)
            .unwrap();
        ca.set_crl_distribution_point(url).unwrap();
        let serial = SerialBytes::from_positive_der_content(&[0x08]).unwrap();
        let leaf = ca.issue_leaf(&csr, &approval, &serial, &binding).unwrap();
        let extensions = leaf.tbs_certificate.extensions.as_ref().unwrap();
        assert_eq!(extensions.len(), 8);
        assert_eq!(
            extensions.last().unwrap(),
            &x509_extensions::crl_distribution_points(url).unwrap()
        );
        let check = |cert: &Certificate, expected: Option<&str>| {
            let der = cert.to_der().unwrap();
            let tbs = cert.tbs_certificate.to_der().unwrap();
            let plan = IssuancePlan {
                ca_id: "ca",
                request_id: "request",
                actor_id: "actor",
                signer_key_ref: "ephemeral-lab-root",
                policy_revision: "v1",
                operation_ref: "op",
                serial_der: cert.tbs_certificate.serial_number.as_bytes(),
                tbs_der: &tbs,
            };
            let verifier = LabX509Verifier::new(
                ca.root_certificate().clone(),
                binding.clone(),
                "api.lab.invalid".to_owned(),
            );
            let verifier = match expected {
                Some(url) => verifier.with_crl_distribution_point(url),
                None => verifier,
            };
            verifier.verify(&plan, &der).is_ok()
        };
        assert!(check(&leaf, Some(url)));
        assert!(check(&plain, None));
        assert!(
            !check(&leaf, None),
            "unexpected distribution point accepted"
        );
        assert!(
            !check(&plain, Some(url)),
            "missing distribution point accepted"
        );
        assert!(
            !check(&leaf, Some("http://127.0.0.1:18083/crl/other.crl")),
            "another distribution point accepted"
        );
    }

    #[test]
    fn duplicate_serial_never_results_in_second_cert() {
        let (csr, authorization) = authorized();
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let serial = SerialBytes::from_positive_der_content(&[0x05]).unwrap();
        let binding = approved_test_policy();
        ca.issue_leaf(&csr, &authorization, &serial, &binding)
            .unwrap();
        assert!(matches!(
            ca.issue_leaf(&csr, &authorization, &serial, &binding),
            Err(LabCaError::DuplicateSerial)
        ));
    }
}
