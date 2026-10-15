//! Experimental RSA-PSS signer with explicit size and digest negotiation.
//! Ephemeral laboratory keys only: not a HSM, CA or production key store.
use crate::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};
use rsa::{
    pss::{Signature, SigningKey, VerifyingKey},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Sha256, Sha384, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaLabError {
    InvalidParameters,
    InvalidKeySize,
    InvalidSignature,
    SigningFailure,
}

fn expected_bits(key: KeyParameter) -> Option<usize> {
    match key {
        KeyParameter::Rsa2048 => Some(2048),
        KeyParameter::Rsa3072 => Some(3072),
        KeyParameter::Rsa4096 => Some(4096),
        KeyParameter::Rsa8192 => Some(8192),
        _ => None,
    }
}

fn authorize(suite: AlgorithmSuite, observed_bits: usize) -> Result<(), RsaLabError> {
    if suite.scheme != SignatureScheme::RsaPss {
        return Err(RsaLabError::InvalidParameters);
    }
    if expected_bits(suite.key) != Some(observed_bits) {
        return Err(RsaLabError::InvalidKeySize);
    }
    if suite.digest == Digest::Intrinsic {
        return Err(RsaLabError::InvalidParameters);
    }
    Ok(())
}

/// Accepts an already-generated laboratory key; never imports production secrets.
pub fn sign_rsa_pss_lab(
    suite: AlgorithmSuite,
    key: &RsaPrivateKey,
    message: &[u8],
) -> Result<Vec<u8>, RsaLabError> {
    authorize(suite, RsaPublicKey::from(key).n().bits())?;
    use rand::rngs::OsRng;
    let signature = match suite.digest {
        Digest::Sha256 => SigningKey::<Sha256>::new(key.clone())
            .sign_with_rng(&mut OsRng, message)
            .to_vec(),
        Digest::Sha384 => SigningKey::<Sha384>::new(key.clone())
            .sign_with_rng(&mut OsRng, message)
            .to_vec(),
        Digest::Sha512 => SigningKey::<Sha512>::new(key.clone())
            .sign_with_rng(&mut OsRng, message)
            .to_vec(),
        Digest::Intrinsic => return Err(RsaLabError::InvalidParameters),
    };
    Ok(signature)
}

pub fn verify_rsa_pss_lab(
    suite: AlgorithmSuite,
    key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), RsaLabError> {
    authorize(suite, key.n().bits())?;
    let parsed = Signature::try_from(signature).map_err(|_| RsaLabError::InvalidSignature)?;
    let valid = match suite.digest {
        Digest::Sha256 => VerifyingKey::<Sha256>::new(key.clone()).verify(message, &parsed),
        Digest::Sha384 => VerifyingKey::<Sha384>::new(key.clone()).verify(message, &parsed),
        Digest::Sha512 => VerifyingKey::<Sha512>::new(key.clone()).verify(message, &parsed),
        Digest::Intrinsic => return Err(RsaLabError::InvalidParameters),
    };
    valid.map_err(|_| RsaLabError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_pss_digest_agility_and_tamper_rejection() {
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = RsaPublicKey::from(&key);
        for digest in [Digest::Sha256, Digest::Sha384, Digest::Sha512] {
            let suite = AlgorithmSuite {
                scheme: SignatureScheme::RsaPss,
                key: KeyParameter::Rsa2048,
                digest,
            };
            let signature = sign_rsa_pss_lab(suite, &key, b"tbs").unwrap();
            assert_eq!(
                verify_rsa_pss_lab(suite, &public, b"tbs", &signature),
                Ok(())
            );
            assert_eq!(
                verify_rsa_pss_lab(suite, &public, b"other", &signature),
                Err(RsaLabError::InvalidSignature)
            );
            let wrong = AlgorithmSuite {
                key: KeyParameter::Rsa3072,
                ..suite
            };
            assert_eq!(
                sign_rsa_pss_lab(wrong, &key, b"tbs"),
                Err(RsaLabError::InvalidKeySize)
            );
        }
    }
}
