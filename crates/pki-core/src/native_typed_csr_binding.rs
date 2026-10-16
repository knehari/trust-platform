//! Bind a native typed issuance authorization to an independently verified
//! PKCS#10 subject identity and key; never trust requester-declared key metadata.
//!
//! Only ECDSA P-256 CSRs are currently verified by the CSR boundary. Other
//! subject key algorithms fail closed until their proof-of-possession verifier
//! and SPKI key-parameter measurement are implemented.
use crate::csr::VerifiedCsr;
use std::str::FromStr;
use trust_pki_crypto::crypto_agility::KeyParameter;
use trust_pki_policy::native_typed_policy::NativeTypedAuthorization;
use x509_cert::{der::Encode, name::Name};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCsrBindingError {
    UnsupportedSubjectKey,
    SubjectMismatch,
    InvalidKeyParameters,
}

const P256_EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const P256_NAMED_CURVE_DER: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Ensures the authenticated, policy-authorized CN and subject key type
/// match a CSR already cryptographically verified by the PKCS#10 boundary.
pub fn bind_native_approval_to_verified_csr(
    approved: &NativeTypedAuthorization,
    csr: &VerifiedCsr,
) -> Result<(), NativeCsrBindingError> {
    let expected = Name::from_str(&format!("CN={}", approved.common_name()))
        .map_err(|_| NativeCsrBindingError::SubjectMismatch)?;
    if csr.subject() != &expected {
        return Err(NativeCsrBindingError::SubjectMismatch);
    }
    if approved.subject_key() != KeyParameter::P256 {
        return Err(NativeCsrBindingError::UnsupportedSubjectKey);
    }
    let spki = csr.subject_public_key();
    if spki.algorithm.oid.to_string() != P256_EC_PUBLIC_KEY_OID
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.to_der().ok())
            != Some(P256_NAMED_CURVE_DER.to_vec())
    {
        return Err(NativeCsrBindingError::InvalidKeyParameters);
    }
    Ok(())
}

/// An immutable binding of an authorized issuance to the exact validated CSR.
/// The digest is a correlation identifier, not a signature or evidence of
/// trusted policy origin. Revalidate against the same authorized request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundNativeCsr {
    approved: NativeTypedAuthorization,
    csr_sha256: [u8; 32],
}

impl BoundNativeCsr {
    pub fn authorized_suite(&self) -> trust_pki_crypto::crypto_agility::AlgorithmSuite {
        self.approved.issuer_suite()
    }

    pub fn csr_sha256(&self) -> &[u8; 32] {
        &self.csr_sha256
    }

    /// Prevent an issuance flow from substituting a second validated CSR
    /// after its authorization was bound to the original request.
    pub fn require_same_csr(
        &self,
        candidate: &VerifiedCsr,
    ) -> Result<(), NativeCsrBindingError> {
        bind_native_approval_to_verified_csr(&self.approved, candidate)?;
        if candidate.fingerprint_sha256() != &self.csr_sha256 {
            return Err(NativeCsrBindingError::SubjectMismatch);
        }
        Ok(())
    }
}

pub fn bind_native_csr(
    approved: NativeTypedAuthorization,
    csr: &VerifiedCsr,
) -> Result<BoundNativeCsr, NativeCsrBindingError> {
    bind_native_approval_to_verified_csr(&approved, csr)?;
    Ok(BoundNativeCsr {
        approved,
        csr_sha256: *csr.fingerprint_sha256(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csr::verify_pkcs10_p256;
    use trust_pki_crypto::crypto_agility::{AlgorithmSuite, Digest, SignatureScheme};
    use trust_pki_policy::{
        native_typed_policy::{NativeTypedIssuanceRequest, NativeTypedPolicy},
        AuthenticatedPrincipal,
    };
    use x509_cert::{
        der::{DecodePem, Encode},
        request::CertReq,
    };

    #[test]
    fn verified_p256_csr_binds_to_rsa_issuer_typed_approval() {
        let suite = AlgorithmSuite {
            scheme: SignatureScheme::RsaPkcs1V15,
            key: KeyParameter::Rsa3072,
            digest: Digest::Sha384,
        };
        let p = NativeTypedPolicy {
            profile_id: "lab-server".into(),
            policy_version: "v2".into(),
            allowed_actors: vec!["lab-requester".into()],
            allowed_dns_zones: vec!["lab.invalid".into()],
            allowed_issuer_suites: vec![suite],
            allowed_subject_keys: vec![KeyParameter::P256, KeyParameter::Rsa3072],
            max_validity_days: 3,
            max_dns_sans: 3,
        };
        let csr_der = CertReq::from_pem(include_str!("../tests/fixtures/ecdsa-p256-request.pem"))
            .unwrap()
            .to_der()
            .unwrap();
        let csr = verify_pkcs10_p256(&csr_der, "api.lab.invalid").unwrap();
        let principal = AuthenticatedPrincipal {
            subject_id: "lab-requester",
        };
        let names = ["api.lab.invalid"];
        let approved = p
            .authorize(
                &principal,
                &NativeTypedIssuanceRequest {
                    profile_id: "lab-server",
                    subject_common_name: "api.lab.invalid",
                    dns_sans: &names,
                    validity_days: 1,
                    issuer_suite: suite,
                    subject_key: KeyParameter::P256,
                },
            )
            .unwrap();
        assert_eq!(
            bind_native_approval_to_verified_csr(&approved, &csr),
            Ok(())
        );

        let bound = bind_native_csr(approved.clone(), &csr).unwrap();
        assert_eq!(bound.csr_sha256(), csr.fingerprint_sha256());
        assert_eq!(bound.authorized_suite(), suite);
        assert_eq!(bound.require_same_csr(&csr), Ok(()));

        let other = ["other.lab.invalid"];
        let wrong_cn = p
            .authorize(
                &principal,
                &NativeTypedIssuanceRequest {
                    subject_common_name: "other.lab.invalid",
                    dns_sans: &other,
                    profile_id: "lab-server",
                    validity_days: 1,
                    issuer_suite: suite,
                    subject_key: KeyParameter::P256,
                },
            )
            .unwrap();
        assert_eq!(
            bind_native_approval_to_verified_csr(&wrong_cn, &csr),
            Err(NativeCsrBindingError::SubjectMismatch)
        );
        assert_eq!(
            bind_native_csr(wrong_cn, &csr),
            Err(NativeCsrBindingError::SubjectMismatch)
        );

        let wrong_key = p
            .authorize(
                &principal,
                &NativeTypedIssuanceRequest {
                    profile_id: "lab-server",
                    subject_common_name: "api.lab.invalid",
                    dns_sans: &names,
                    validity_days: 1,
                    issuer_suite: suite,
                    subject_key: KeyParameter::Rsa3072,
                },
            )
            .unwrap();
        assert_eq!(
            bind_native_approval_to_verified_csr(&wrong_key, &csr),
            Err(NativeCsrBindingError::UnsupportedSubjectKey)
        );
    }
}
