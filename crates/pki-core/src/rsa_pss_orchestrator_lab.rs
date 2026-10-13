//! RSA-PSS laboratory adapter for the durable-intent-first X.509 orchestrator.
//! Never expose ephemeral keys or this verifier as a production trust service.
use crate::{
    orchestrator::{
        CertificateAssembler, CertificateVerifier, ExternalSigner, IssuancePlan, IssueError,
    },
    rsa_pss_identifier::preflight_pss_certificate_identifier,
    rsa_pss_issuer_verify_lab::verify_rsa_pss_issuer_signature,
    x509_extensions::{self, ApprovedPolicyBinding},
};
use trust_pki_crypto::{
    rsa_pss_lab::EphemeralRsaPssLabSigner, SignatureAlgorithm, SigningProvider,
};
use x509_cert::{
    der::{asn1::BitString, Decode, Encode},
    ext::pkix::{name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName},
    Certificate, TbsCertificate,
};

/// The signer accepts only its matching key reference and performs one
/// invocation per call; replay prevention belongs to the durable journal.
pub struct LabRsaPssExternalSigner(pub EphemeralRsaPssLabSigner);

impl ExternalSigner for LabRsaPssExternalSigner {
    fn sign_once(
        &mut self,
        key_ref: &str,
        _operation_ref: &str,
        tbs_der: &[u8],
    ) -> Result<Vec<u8>, IssueError> {
        if key_ref != self.0.key_ref().0 {
            return Err(IssueError::SigningFailure);
        }
        self.0
            .sign(self.0.key_ref(), SignatureAlgorithm::RsaPssSha256, tbs_der)
            .map_err(|_| IssueError::SigningFailure)
    }
}

pub struct LabRsaPssAssembler;

impl CertificateAssembler for LabRsaPssAssembler {
    fn assemble(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>, IssueError> {
        let tbs = TbsCertificate::from_der(tbs_der).map_err(|_| IssueError::AssemblyFailure)?;
        let cert = Certificate {
            signature_algorithm: tbs.signature.clone(),
            tbs_certificate: tbs,
            signature: BitString::from_bytes(signature).map_err(|_| IssueError::AssemblyFailure)?,
        };
        preflight_pss_certificate_identifier(&cert).map_err(|_| IssueError::AssemblyFailure)?;
        cert.to_der().map_err(|_| IssueError::AssemblyFailure)
    }
}

pub struct LabRsaPssVerifier {
    pub issuer: Certificate,
}

impl CertificateVerifier for LabRsaPssVerifier {
    fn verify(&self, plan: &IssuancePlan<'_>, bytes: &[u8]) -> Result<(), IssueError> {
        let cert = Certificate::from_der(bytes).map_err(|_| IssueError::VerificationFailure)?;
        if cert
            .tbs_certificate
            .to_der()
            .map_err(|_| IssueError::VerificationFailure)?
            != plan.tbs_der
        {
            return Err(IssueError::VerificationFailure);
        }
        verify_rsa_pss_issuer_signature(&self.issuer, &cert)
    }
}

/// Laboratory server profile verification: checks exact authorized DNS and
/// policy binding as well as RSA-PSS issuer signature. This is not full RFC 5280
/// path validation (trusted clock, revocation, chain building, name constraints).
pub struct LabRsaPssServerVerifier {
    pub issuer: Certificate,
    pub policy: ApprovedPolicyBinding,
    pub authorized_dns: String,
}

impl CertificateVerifier for LabRsaPssServerVerifier {
    fn verify(&self, plan: &IssuancePlan<'_>, bytes: &[u8]) -> Result<(), IssueError> {
        let error = IssueError::VerificationFailure;
        let cert = Certificate::from_der(bytes).map_err(|_| error.clone())?;
        if cert.tbs_certificate.to_der().map_err(|_| error.clone())? != plan.tbs_der {
            return Err(error);
        }
        verify_rsa_pss_issuer_signature(&self.issuer, &cert)?;
        let extensions = cert.tbs_certificate.extensions.as_ref().ok_or(error.clone())?;
        if extensions.len() != 7 {
            return Err(error);
        }
        let single = |oid: &str| -> Result<&x509_cert::ext::Extension, IssueError> {
            let mut matching = extensions.iter().filter(|e| e.extn_id.to_string() == oid);
            let first = matching.next().ok_or(IssueError::VerificationFailure)?;
            if matching.next().is_some() {
                return Err(IssueError::VerificationFailure);
            }
            Ok(first)
        };
        if single("2.5.29.32")? != &x509_extensions::certificate_policies(&self.policy)
            .map_err(|_| error.clone())? {
            return Err(error);
        }
        let san = single("2.5.29.17")?;
        let names = SubjectAltName::from_der(san.extn_value.as_bytes())
            .map_err(|_| error.clone())?;
        if names.0.len() != 1 || !matches!(&names.0[0], GeneralName::DnsName(n) if n.as_str() == self.authorized_dns) {
            return Err(error);
        }
        let constraints = single("2.5.29.19")?;
        let basic = BasicConstraints::from_der(constraints.extn_value.as_bytes())
            .map_err(|_| error.clone())?;
        if !constraints.critical || basic.ca || basic.path_len_constraint.is_some() {
            return Err(error);
        }
        let key_use = single("2.5.29.15")?;
        let ku = KeyUsage::from_der(key_use.extn_value.as_bytes())
            .map_err(|_| error.clone())?;
        if !key_use.critical || ku != KeyUsage(KeyUsages::DigitalSignature.into()) {
            return Err(error);
        }
        let eku = single("2.5.29.37")?;
        let purposes = ExtendedKeyUsage::from_der(eku.extn_value.as_bytes())
            .map_err(|_| error.clone())?;
        if purposes.0.len() != 1 || purposes.0[0].to_string() != "1.3.6.1.5.5.7.3.1" {
            return Err(error);
        }
        let issuer_id = x509_extensions::key_identifier(&self.issuer.tbs_certificate.subject_public_key_info)
            .map_err(|_| error.clone())?;
        let subject_id = x509_extensions::key_identifier(&cert.tbs_certificate.subject_public_key_info)
            .map_err(|_| error.clone())?;
        if single("2.5.29.14")? != &x509_extensions::subject_key_identifier(&subject_id)
            .map_err(|_| error.clone())?
            || single("2.5.29.35")? != &x509_extensions::authority_key_identifier(&issuer_id)
                .map_err(|_| error.clone())? {
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        issuance_x509_binding::issue_x509_once, orchestrator::IssuanceJournal,
        rsa_pss_x509_lab::create_root_and_signer,
    };
    use sha2::{Digest, Sha256};

    #[derive(Default)]
    struct Journal {
        intent: bool,
        uncertain: bool,
        stored: bool,
        fail_store: bool,
    }

    impl IssuanceJournal for Journal {
        fn record_intent(
            &mut self,
            _plan: &IssuancePlan<'_>,
            _tbs_sha256: &[u8; 32],
        ) -> Result<(), IssueError> {
            if self.intent {
                return Err(IssueError::ReplayedOrAmbiguousIntent);
            }
            self.intent = true;
            Ok(())
        }
        fn mark_uncertain(&mut self, _plan: &IssuancePlan<'_>) -> Result<(), IssueError> {
            self.uncertain = true;
            Ok(())
        }
        fn persist_verified(
            &mut self,
            _plan: &IssuancePlan<'_>,
            _tbs_sha256: &[u8; 32],
            _cert_sha256: &[u8; 32],
            cert: &[u8],
        ) -> Result<(), IssueError> {
            if self.fail_store {
                return Err(IssueError::PersistenceFailure);
            }
            if Sha256::digest(cert).is_empty() {
                return Err(IssueError::VerificationFailure);
            }
            self.stored = true;
            Ok(())
        }
    }

    #[test]
    fn rsa_pss_x509_intent_first_and_replay_blocked() {
        let (issuer, key) = create_root_and_signer().unwrap();
        let tbs = issuer.tbs_certificate.to_der().unwrap();
        let serial = issuer.tbs_certificate.serial_number.as_bytes().to_vec();
        let key_reference = key.key_ref().0.clone();
        let plan = IssuancePlan {
            ca_id: "lab-ca",
            request_id: "lab-request",
            actor_id: "lab-actor",
            signer_key_ref: &key_reference,
            policy_revision: "lab-policy",
            operation_ref: "unique-op",
            serial_der: &serial,
            tbs_der: &tbs,
        };
        let mut journal = Journal::default();
        let mut signer = LabRsaPssExternalSigner(key);
        let cert = issue_x509_once(
            &mut journal,
            &mut signer,
            &LabRsaPssAssembler,
            LabRsaPssVerifier {
                issuer: issuer.clone(),
            },
            &plan,
        )
        .unwrap();
        assert!(journal.stored);
        assert!(!journal.uncertain);
        assert_eq!(
            Certificate::from_der(&cert).unwrap().tbs_certificate,
            issuer.tbs_certificate
        );
        assert_eq!(
            issue_x509_once(
                &mut journal,
                &mut signer,
                &LabRsaPssAssembler,
                LabRsaPssVerifier {
                    issuer: issuer.clone()
                },
                &plan,
            ),
            Err(IssueError::ReplayedOrAmbiguousIntent)
        );
    }

    #[test]
    fn persistence_failure_is_uncertain_and_never_resigned() {
        let (issuer, key) = create_root_and_signer().unwrap();
        let tbs = issuer.tbs_certificate.to_der().unwrap();
        let serial = issuer.tbs_certificate.serial_number.as_bytes().to_vec();
        let key_reference = key.key_ref().0.clone();
        let plan = IssuancePlan {
            ca_id: "lab-ca",
            request_id: "lab-request",
            actor_id: "lab-actor",
            signer_key_ref: &key_reference,
            policy_revision: "lab-policy",
            operation_ref: "unique-op",
            serial_der: &serial,
            tbs_der: &tbs,
        };
        let mut journal = Journal {
            fail_store: true,
            ..Default::default()
        };
        let mut signer = LabRsaPssExternalSigner(key);
        assert_eq!(
            issue_x509_once(
                &mut journal,
                &mut signer,
                &LabRsaPssAssembler,
                LabRsaPssVerifier {
                    issuer: issuer.clone()
                },
                &plan,
            ),
            Err(IssueError::PersistenceFailure)
        );
        assert!(journal.uncertain);
        assert!(!journal.stored);
    }
}
