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


/// Verifies a typed RSA-PSS issuer signature with exact SHA/MGF1/salt profile.
/// Issuer trust, path validation, revocation and policy are external obligations.
pub fn verify_typed_rsa_pss_issuer_signature(
    issuer: &Certificate,
    certificate: &Certificate,
    suite: trust_pki_crypto::crypto_agility::AlgorithmSuite,
) -> Result<(), crate::orchestrator::IssueError> {
    use crate::orchestrator::IssueError::VerificationFailure;
    use trust_pki_crypto::crypto_agility::SignatureScheme;
    if suite.scheme != SignatureScheme::RsaPss
        || certificate.tbs_certificate.issuer != issuer.tbs_certificate.subject
    {
        return Err(VerificationFailure);
    }
    let identifier = crate::agile_x509_identifier::signature_algorithm_identifier(suite)
        .map_err(|_| VerificationFailure)?;
    crate::agile_x509_identifier::preflight_certificate_algorithm(certificate, &identifier)
        .map_err(|_| VerificationFailure)?;
    crate::rsa_pss_identifier::check_pss_identifiers_for_digest(
        &certificate.tbs_certificate.signature,
        &certificate.signature_algorithm,
        suite.digest,
    )
    .map_err(|_| VerificationFailure)?;
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| VerificationFailure)?;
    let tbs = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| VerificationFailure)?;
    let signature = certificate.signature.as_bytes().ok_or(VerificationFailure)?;
    trust_pki_crypto::rsa_pss_agile_lab::verify_rsa_pss_spki_lab(
        suite, &spki, &tbs, signature,
    )
    .map_err(|_| VerificationFailure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa_pss_x509_lab::issue_ephemeral_rsa_pss_root;
    use x509_cert::der::asn1::BitString;

    #[test]
    fn valid_root_signature_verifies_and_tampering_is_rejected() {
        let issuer = issue_ephemeral_rsa_pss_root().unwrap();
        assert_eq!(verify_rsa_pss_issuer_signature(&issuer, &issuer), Ok(()));

        let mut forged = issuer.clone();
        let mut altered = forged.signature.as_bytes().unwrap().to_vec();
        altered[0] ^= 1;
        forged.signature = BitString::from_bytes(&altered).unwrap();
        assert_eq!(
            verify_rsa_pss_issuer_signature(&issuer, &forged),
            Err(crate::orchestrator::IssueError::VerificationFailure)
        );
    }

    #[test]
    fn unrelated_issuer_cannot_verify_signature() {
        let issuer = issue_ephemeral_rsa_pss_root().unwrap();
        let other = issue_ephemeral_rsa_pss_root().unwrap();
        assert_eq!(
            verify_rsa_pss_issuer_signature(&other, &issuer),
            Err(crate::orchestrator::IssueError::VerificationFailure)
        );
    }
    #[test]
    fn typed_rsa_pss_sha256_root_roundtrip_and_hash_mismatch_denial() {
        use trust_pki_crypto::crypto_agility::{
            AlgorithmSuite, Digest, KeyParameter, SignatureScheme,
        };
        let root = issue_ephemeral_rsa_pss_root().unwrap();
        let suite = AlgorithmSuite {
            scheme: SignatureScheme::RsaPss,
            key: KeyParameter::Rsa3072,
            digest: Digest::Sha256,
        };
        assert_eq!(verify_typed_rsa_pss_issuer_signature(&root, &root, suite), Ok(()));
        let different_hash = AlgorithmSuite {
            digest: Digest::Sha384,
            ..suite
        };
        assert_eq!(
            verify_typed_rsa_pss_issuer_signature(&root, &root, different_hash),
            Err(crate::orchestrator::IssueError::VerificationFailure)
        );
    }
}
