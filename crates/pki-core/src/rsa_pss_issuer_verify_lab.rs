//! Laboratory RSA-PSS issuer signature verification.
//! This does not perform RFC 5280 path validation, revocation or policy checks.
use crate::rsa_pss_identifier::preflight_pss_certificate_identifier;
use trust_pki_crypto::rsa_pss_lab::verify_rsa_pss_sha256_spki;
use x509_cert::{der::Encode, Certificate};

/// Checks RSA-PSS parameters, exact issuer name and a valid RSA-3072+
/// signature over canonical TBS DER. Not an independently trusted chain.
pub fn verify_rsa_pss_issuer_signature(
    issuer: &Certificate,
    certificate: &Certificate,
) -> Result<(), crate::orchestrator::IssueError> {
    use crate::orchestrator::IssueError::VerificationFailure;
    preflight_pss_certificate_identifier(certificate).map_err(|_| VerificationFailure)?;
    if certificate.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(VerificationFailure);
    }
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| VerificationFailure)?;
    let tbs = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| VerificationFailure)?;
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or(VerificationFailure)?;
    verify_rsa_pss_sha256_spki(&spki, &tbs, signature).map_err(|_| VerificationFailure)
}
