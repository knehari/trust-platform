//! RSA PKCS#1 v1.5 compatibility signing for isolated laboratories only.
//! PKCS#1 v1.5 is never an implicit fallback from RSA-PSS.
use crate::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};
use rsa::{
    pkcs8::{DecodePublicKey, EncodePublicKey},
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    signature::{SignatureEncoding, Signer, Verifier},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Sha256, Sha384, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPkcs1LabError {
    UnsupportedSuite,
    KeySizeMismatch,
    InvalidPublicKey,
    KeyGenerationFailed,
    InvalidSignature,
}

fn bits(key: KeyParameter) -> Option<usize> {
    match key {
        KeyParameter::Rsa2048 => Some(2048),
        KeyParameter::Rsa3072 => Some(3072),
        KeyParameter::Rsa4096 => Some(4096),
        KeyParameter::Rsa8192 => Some(8192),
        _ => None,
    }
}

fn validate(suite: AlgorithmSuite, observed_bits: usize) -> Result<(), RsaPkcs1LabError> {
    if suite.scheme != SignatureScheme::RsaPkcs1V15
        || !matches!(
            suite.digest,
            Digest::Sha256 | Digest::Sha384 | Digest::Sha512
        )
    {
        return Err(RsaPkcs1LabError::UnsupportedSuite);
    }
    if bits(suite.key) != Some(observed_bits) {
        return Err(RsaPkcs1LabError::KeySizeMismatch);
    }
    Ok(())
}

pub fn sign_pkcs1_lab(
    suite: AlgorithmSuite,
    private: &RsaPrivateKey,
    message: &[u8],
) -> Result<Vec<u8>, RsaPkcs1LabError> {
    validate(suite, RsaPublicKey::from(private).n().bits())?;
    let signature = match suite.digest {
        Digest::Sha256 => SigningKey::<Sha256>::new(private.clone())
            .sign(message)
            .to_vec(),
        Digest::Sha384 => SigningKey::<Sha384>::new(private.clone())
            .sign(message)
            .to_vec(),
        Digest::Sha512 => SigningKey::<Sha512>::new(private.clone())
            .sign(message)
            .to_vec(),
        Digest::Intrinsic => return Err(RsaPkcs1LabError::UnsupportedSuite),
    };
    Ok(signature)
}

pub fn verify_pkcs1_lab(
    suite: AlgorithmSuite,
    public: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), RsaPkcs1LabError> {
    validate(suite, public.n().bits())?;
    let signature =
        Signature::try_from(signature).map_err(|_| RsaPkcs1LabError::InvalidSignature)?;
    let result = match suite.digest {
        Digest::Sha256 => VerifyingKey::<Sha256>::new(public.clone()).verify(message, &signature),
        Digest::Sha384 => VerifyingKey::<Sha384>::new(public.clone()).verify(message, &signature),
        Digest::Sha512 => VerifyingKey::<Sha512>::new(public.clone()).verify(message, &signature),
        Digest::Intrinsic => return Err(RsaPkcs1LabError::UnsupportedSuite),
    };
    result.map_err(|_| RsaPkcs1LabError::InvalidSignature)
}


/// An ephemeral process-local RSA key. Never serializes private material.
pub struct EphemeralPkcs1LabKey {
    suite: AlgorithmSuite,
    private: RsaPrivateKey,
}

impl EphemeralPkcs1LabKey {
    pub fn generate(suite: AlgorithmSuite) -> Result<Self, RsaPkcs1LabError> {
        let key_bits = bits(suite.key).ok_or(RsaPkcs1LabError::UnsupportedSuite)?;
        validate(suite, key_bits)?;
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, key_bits)
            .map_err(|_| RsaPkcs1LabError::KeyGenerationFailed)?;
        Ok(Self { suite, private })
    }

    pub fn public_spki_der(&self) -> Result<Vec<u8>, RsaPkcs1LabError> {
        RsaPublicKey::from(&self.private)
            .to_public_key_der()
            .map(|v| v.as_bytes().to_vec())
            .map_err(|_| RsaPkcs1LabError::InvalidPublicKey)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RsaPkcs1LabError> {
        sign_pkcs1_lab(self.suite, &self.private, message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), RsaPkcs1LabError> {
        verify_pkcs1_lab(
            self.suite,
            &RsaPublicKey::from(&self.private),
            message,
            signature,
        )
    }
}

/// Verify mathematical signature using the actual issuer SubjectPublicKeyInfo.
pub fn verify_pkcs1_spki_lab(
    suite: AlgorithmSuite,
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), RsaPkcs1LabError> {
    let public = RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|_| RsaPkcs1LabError::InvalidPublicKey)?;
    verify_pkcs1_lab(suite, &public, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_pkcs1_lab_roundtrip_and_downgrade_rejection() {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        for digest in [Digest::Sha256, Digest::Sha384, Digest::Sha512] {
            let suite = AlgorithmSuite {
                scheme: SignatureScheme::RsaPkcs1V15,
                key: KeyParameter::Rsa2048,
                digest,
            };
            let signature = sign_pkcs1_lab(suite, &private, b"to-be-signed").unwrap();
            let spki = public.to_public_key_der().unwrap();
            assert_eq!(
                verify_pkcs1_spki_lab(suite, spki.as_bytes(), b"to-be-signed", &signature),
                Ok(())
            );
            assert_eq!(
                verify_pkcs1_lab(suite, &public, b"to-be-signed", &signature),
                Ok(())
            );
            assert_eq!(
                verify_pkcs1_lab(suite, &public, b"tampered", &signature),
                Err(RsaPkcs1LabError::InvalidSignature)
            );
            let pss = AlgorithmSuite {
                scheme: SignatureScheme::RsaPss,
                ..suite
            };
            assert_eq!(
                sign_pkcs1_lab(pss, &private, b"to-be-signed"),
                Err(RsaPkcs1LabError::UnsupportedSuite)
            );
        }
    }
}
