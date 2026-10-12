//! Strict RSA-PSS SHA-256 profile validation for a future signing adapter.
//! This module DOES NOT perform RSA signing or verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPssParameters {
    pub message_hash: HashAlgorithm,
    pub mgf1_hash: HashAlgorithm,
    pub salt_length_bytes: u16,
    pub trailer_field: u8,
    pub modulus_bits: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPssProfileError {
    AlgorithmNotAuthorized,
    UnsupportedHash,
    MismatchedMgf1Hash,
    InvalidSaltLength,
    InvalidTrailer,
    InsufficientKeySize,
}

/// Required profile for the planned SHA-256 RSA-PSS implementation:
/// SHA-256/MGF1-SHA256, 32-byte salt, trailer=1, RSA >=3072 bits.
/// This is a policy gate only. The adapter must independently check actual
/// key parameters and verify the complete signed data/signature.
pub fn validate_rsa_pss_sha256(params: &RsaPssParameters) -> Result<(), RsaPssProfileError> {
    if params.message_hash != HashAlgorithm::Sha256 {
        return Err(RsaPssProfileError::UnsupportedHash);
    }
    if params.mgf1_hash != HashAlgorithm::Sha256 {
        return Err(RsaPssProfileError::MismatchedMgf1Hash);
    }
    if params.salt_length_bytes != 32 {
        return Err(RsaPssProfileError::InvalidSaltLength);
    }
    if params.trailer_field != 1 {
        return Err(RsaPssProfileError::InvalidTrailer);
    }
    if params.modulus_bits < 3072 {
        return Err(RsaPssProfileError::InsufficientKeySize);
    }
    Ok(())
}


    
/// Checks the RSA-PSS parameter profile and the requested algorithm against
/// the issuer's explicit allowlist. This still performs no cryptographic work.
pub fn authorize_rsa_pss_sha256_profile(
    params: &RsaPssParameters,
    allowed: &[crate::SignatureAlgorithm],
) -> Result<(), RsaPssProfileError> {
    if !allowed.contains(&crate::SignatureAlgorithm::RsaPssSha256) {
        return Err(RsaPssProfileError::AlgorithmNotAuthorized);
    }
    validate_rsa_pss_sha256(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted() -> RsaPssParameters {
        RsaPssParameters {
            message_hash: HashAlgorithm::Sha256,
            mgf1_hash: HashAlgorithm::Sha256,
            salt_length_bytes: 32,
            trailer_field: 1,
            modulus_bits: 3072,
        }
    }

    #[test]
    fn policy_must_explicitly_authorize_rsa_pss() {
        assert_eq!(
            authorize_rsa_pss_sha256_profile(&accepted(), &[]),
            Err(RsaPssProfileError::AlgorithmNotAuthorized)
        );
        assert_eq!(
            authorize_rsa_pss_sha256_profile(
                &accepted(),
                &[crate::SignatureAlgorithm::EcdsaP256Sha256]
            ),
            Err(RsaPssProfileError::AlgorithmNotAuthorized)
        );
        assert_eq!(
            authorize_rsa_pss_sha256_profile(
                &accepted(),
                &[crate::SignatureAlgorithm::RsaPssSha256]
            ),
            Ok(())
        );
    }

    #[test]
    fn accepts_explicit_sha256_parameters() {
        assert_eq!(validate_rsa_pss_sha256(&accepted()), Ok(()));
        let mut p = accepted();
        p.modulus_bits = 4096;
        assert_eq!(validate_rsa_pss_sha256(&p), Ok(()));
    }

    #[test]
    fn rejects_wrong_digest_and_mgf1() {
        let mut p = accepted();
        p.message_hash = HashAlgorithm::Sha384;
        assert_eq!(
            validate_rsa_pss_sha256(&p),
            Err(RsaPssProfileError::UnsupportedHash)
        );
        p = accepted();
        p.mgf1_hash = HashAlgorithm::Sha512;
        assert_eq!(
            validate_rsa_pss_sha256(&p),
            Err(RsaPssProfileError::MismatchedMgf1Hash)
        );
    }

    #[test]
    fn rejects_unsafe_or_incompatible_parameters() {
        let mut p = accepted();
        p.salt_length_bytes = 20;
        assert_eq!(
            validate_rsa_pss_sha256(&p),
            Err(RsaPssProfileError::InvalidSaltLength)
        );
        p = accepted();
        p.trailer_field = 2;
        assert_eq!(
            validate_rsa_pss_sha256(&p),
            Err(RsaPssProfileError::InvalidTrailer)
        );
        p = accepted();
        p.modulus_bits = 2048;
        assert_eq!(
            validate_rsa_pss_sha256(&p),
            Err(RsaPssProfileError::InsufficientKeySize)
        );
    }
}
