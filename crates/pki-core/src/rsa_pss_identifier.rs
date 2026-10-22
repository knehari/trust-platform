//! RSA-PSS X.509 AlgorithmIdentifier consistency preflight.
//! This is NOT verification of parameters, key strength or signatures.
use x509_cert::{
    der::{Decode, Encode},
    spki::AlgorithmIdentifierOwned,
    Certificate,
};

const RSASSA_PSS_OID: &str = "1.2.840.113549.1.1.10";

// A deliberately narrow DER allowlist: SHA-256, MGF1(SHA-256),
// saltLength=32, trailerField=1 (DEFAULT, therefore omitted in DER).
// Supports only explicitly encoded SHA-256 AlgorithmIdentifiers with NULL.
// This is not a general-purpose ASN.1 RSA-PSS decoder.
pub(crate) const PSS_SHA256_MGF1_SHA256_SALT32_DER: &[u8] = &[
    0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
];

// Exact DER is intentionally pinned: RSASSA-PSS-params, RFC 4055 / RFC 8017.
// Both hashAlgorithm and MGF1 hashAlgorithm must match; salt = digest length.
// trailerField = 1 is DEFAULT and must not appear in canonical DER.
const fn pss_params_variant(hash_oid_suffix: u8, salt_bytes: u8) -> [u8; 54] {
    let mut der = [0u8; 54];
    let mut i = 0;
    while i < 54 {
        der[i] = PSS_SHA256_MGF1_SHA256_SALT32_DER[i];
        i += 1;
    }
    der[16] = hash_oid_suffix;
    der[46] = hash_oid_suffix;
    der[53] = salt_bytes;
    der
}

pub(crate) const PSS_SHA384_MGF1_SHA384_SALT48_DER: [u8; 54] = pss_params_variant(0x02, 48);
pub(crate) const PSS_SHA512_MGF1_SHA512_SALT64_DER: [u8; 54] = pss_params_variant(0x03, 64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PssIdentifierError {
    WrongAlgorithm,
    MissingParameters,
    InconsistentParameters,
    InvalidParameterEnvelope,
    UnsupportedParameterProfile,
    InvalidDer,
    CertificateTooLarge,
}

/// Strict structural screening of a DER certificate, without trust-chain or
/// signature verification. Do not use this function as certificate acceptance.
pub fn preflight_pss_certificate_der(der: &[u8]) -> Result<(), PssIdentifierError> {
    if der.is_empty() || der.len() > 64 * 1024 {
        return Err(PssIdentifierError::CertificateTooLarge);
    }
    let certificate = Certificate::from_der(der).map_err(|_| PssIdentifierError::InvalidDer)?;
    if certificate
        .to_der()
        .map_err(|_| PssIdentifierError::InvalidDer)?
        != der
    {
        return Err(PssIdentifierError::InvalidDer);
    }
    preflight_pss_certificate_identifier(&certificate)
}

/// Reject inconsistent TBS / outer signature identifiers and absent PSS params.
/// Parameter parsing and cryptographic verification MUST follow separately.
pub fn preflight_pss_certificate_identifier(cert: &Certificate) -> Result<(), PssIdentifierError> {
    check_pss_identifiers(&cert.tbs_certificate.signature, &cert.signature_algorithm)
}

/// Preserve the legacy SHA-256-only preflight relied upon by its dedicated
/// RSA-PSS SHA-256 verifier. Do not silently broaden that verification path.
pub fn check_pss_identifiers(
    tbs: &AlgorithmIdentifierOwned,
    outer: &AlgorithmIdentifierOwned,
) -> Result<(), PssIdentifierError> {
    check_pss_identifiers_with_profile(tbs, outer, PSS_SHA256_MGF1_SHA256_SALT32_DER)
}

/// Strict typed parameter preflight for SHA-256, SHA-384 and SHA-512.
/// This function checks AlgorithmIdentifiers only; it does NOT verify
/// the signature, key strength or certificate trust chain.
pub fn check_pss_identifiers_for_digest(
    tbs: &AlgorithmIdentifierOwned,
    outer: &AlgorithmIdentifierOwned,
    digest: trust_pki_crypto::crypto_agility::Digest,
) -> Result<(), PssIdentifierError> {
    use trust_pki_crypto::crypto_agility::Digest;
    let expected: &[u8] = match digest {
        Digest::Sha256 => PSS_SHA256_MGF1_SHA256_SALT32_DER,
        Digest::Sha384 => &PSS_SHA384_MGF1_SHA384_SALT48_DER,
        Digest::Sha512 => &PSS_SHA512_MGF1_SHA512_SALT64_DER,
        Digest::Intrinsic => return Err(PssIdentifierError::UnsupportedParameterProfile),
    };
    check_pss_identifiers_with_profile(tbs, outer, expected)
}

fn check_pss_identifiers_with_profile(
    tbs: &AlgorithmIdentifierOwned,
    outer: &AlgorithmIdentifierOwned,
    expected: &[u8],
) -> Result<(), PssIdentifierError> {
    if tbs.oid.to_string() != RSASSA_PSS_OID || outer.oid.to_string() != RSASSA_PSS_OID {
        return Err(PssIdentifierError::WrongAlgorithm);
    }
    let tbs_params = tbs
        .parameters
        .as_ref()
        .ok_or(PssIdentifierError::MissingParameters)?;
    let outer_params = outer
        .parameters
        .as_ref()
        .ok_or(PssIdentifierError::MissingParameters)?;
    let tbs_der = tbs_params
        .to_der()
        .map_err(|_| PssIdentifierError::InvalidDer)?;
    let outer_der = outer_params
        .to_der()
        .map_err(|_| PssIdentifierError::InvalidDer)?;
    if tbs_der != outer_der {
        return Err(PssIdentifierError::InconsistentParameters);
    }
    if tbs_der.len() <= 2 || tbs_der[0] != 0x30 {
        return Err(PssIdentifierError::InvalidParameterEnvelope);
    }
    if tbs_der.as_slice() != expected {
        return Err(PssIdentifierError::UnsupportedParameterProfile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::{asn1::ObjectIdentifier, Any, Decode};

    fn identifier(oid: &str, params: Option<&[u8]>) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new(oid).unwrap(),
            parameters: params.map(|bytes| Any::from_der(bytes).unwrap()),
        }
    }

    #[test]
    fn rejects_invalid_or_excessive_certificate_der() {
        assert_eq!(
            preflight_pss_certificate_der(&[]),
            Err(PssIdentifierError::CertificateTooLarge)
        );
        assert_eq!(
            preflight_pss_certificate_der(&[0x30, 0x00]),
            Err(PssIdentifierError::InvalidDer)
        );
        assert_eq!(
            preflight_pss_certificate_der(&vec![0; 64 * 1024 + 1]),
            Err(PssIdentifierError::CertificateTooLarge)
        );
    }

    #[test]
    fn accepts_only_strict_sha256_mgf1_sha256_salt32_der() {
        let good = identifier(RSASSA_PSS_OID, Some(PSS_SHA256_MGF1_SHA256_SALT32_DER));
        assert_eq!(check_pss_identifiers(&good, &good), Ok(()));
        let mut wrong_salt = PSS_SHA256_MGF1_SHA256_SALT32_DER.to_vec();
        *wrong_salt.last_mut().unwrap() = 20;
        let bad = identifier(RSASSA_PSS_OID, Some(&wrong_salt));
        assert_eq!(
            check_pss_identifiers(&bad, &bad),
            Err(PssIdentifierError::UnsupportedParameterProfile)
        );
        let mut wrong_mgf_digest = PSS_SHA256_MGF1_SHA256_SALT32_DER.to_vec();
        wrong_mgf_digest[46] = 0x02;
        let bad = identifier(RSASSA_PSS_OID, Some(&wrong_mgf_digest));
        assert_eq!(
            check_pss_identifiers(&bad, &bad),
            Err(PssIdentifierError::UnsupportedParameterProfile)
        );
    }

    #[test]
    fn rejects_non_pss_signature_identifiers() {
        let ecdsa = identifier("1.2.840.10045.4.3.2", None);
        let pss = identifier(RSASSA_PSS_OID, Some(&[0x30, 0x00]));
        assert_eq!(
            check_pss_identifiers(&ecdsa, &pss),
            Err(PssIdentifierError::WrongAlgorithm)
        );
    }

    #[test]
    fn rejects_implicit_default_and_inconsistent_pss_params() {
        let empty = identifier(RSASSA_PSS_OID, None);
        let pss = identifier(RSASSA_PSS_OID, Some(&[0x30, 0x00]));
        assert_eq!(
            check_pss_identifiers(&empty, &pss),
            Err(PssIdentifierError::MissingParameters)
        );
        let different = identifier(RSASSA_PSS_OID, Some(&[0x30, 0x02, 0xa0, 0x00]));
        assert_eq!(
            check_pss_identifiers(&pss, &different),
            Err(PssIdentifierError::InconsistentParameters)
        );
        assert_eq!(
            check_pss_identifiers(&pss, &pss),
            Err(PssIdentifierError::InvalidParameterEnvelope)
        );
    }
    #[test]
    fn supports_strict_sha384_and_sha512_without_weakening_sha256_verifier() {
        use trust_pki_crypto::crypto_agility::Digest;
        for (digest, params, salt) in [
            (
                Digest::Sha384,
                PSS_SHA384_MGF1_SHA384_SALT48_DER.as_slice(),
                48u8,
            ),
            (
                Digest::Sha512,
                PSS_SHA512_MGF1_SHA512_SALT64_DER.as_slice(),
                64u8,
            ),
        ] {
            let good = identifier(RSASSA_PSS_OID, Some(params));
            assert_eq!(
                check_pss_identifiers_for_digest(&good, &good, digest),
                Ok(())
            );
            assert_eq!(
                check_pss_identifiers(&good, &good),
                Err(PssIdentifierError::UnsupportedParameterProfile)
            );
            let mut altered_salt = params.to_vec();
            *altered_salt.last_mut().unwrap() = salt - 1;
            let malformed = identifier(RSASSA_PSS_OID, Some(&altered_salt));
            assert_eq!(
                check_pss_identifiers_for_digest(&malformed, &malformed, digest),
                Err(PssIdentifierError::UnsupportedParameterProfile)
            );
            let mut mgf_mismatch = params.to_vec();
            mgf_mismatch[46] = 0x01;
            let malformed = identifier(RSASSA_PSS_OID, Some(&mgf_mismatch));
            assert_eq!(
                check_pss_identifiers_for_digest(&malformed, &malformed, digest),
                Err(PssIdentifierError::UnsupportedParameterProfile)
            );
            let sha256 = identifier(RSASSA_PSS_OID, Some(PSS_SHA256_MGF1_SHA256_SALT32_DER));
            assert_eq!(
                check_pss_identifiers_for_digest(&sha256, &good, digest),
                Err(PssIdentifierError::InconsistentParameters)
            );
        }
    }
}
