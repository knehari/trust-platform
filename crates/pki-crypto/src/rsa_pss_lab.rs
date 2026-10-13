//! Ephemeral RSA-PSS laboratory signer. Never use as a production CA key store.
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs8::{DecodePublicKey, EncodePublicKey},
    pss::{Signature, SigningKey, VerifyingKey},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

use crate::{CryptoError, KeyRef, SignatureAlgorithm, SigningProvider};

/// Random, positive, canonical 19-octet serial for a disposable lab certificate.
/// This does not provide durable issuer-scoped uniqueness across processes.
pub fn generate_lab_serial() -> [u8; 19] {
    let mut serial = [0u8; 19];
    OsRng.fill_bytes(&mut serial);
    serial[0] = (serial[0] & 0x3f) | 0x40;
    serial
}

/// Verify RSA-PSS SHA-256 with an explicit 32-octet salt against a public
/// SubjectPublicKeyInfo. Laboratory interoperability only: callers must first
/// validate the X.509 AlgorithmIdentifiers and certificate profile.
pub fn verify_rsa_pss_sha256_spki(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let public_key =
        RsaPublicKey::from_public_key_der(spki_der).map_err(|_| CryptoError::InvalidPublicKey)?;
    if public_key.size() < 384 {
        return Err(CryptoError::InvalidPublicKey);
    }
    let signature =
        Signature::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;
    VerifyingKey::<Sha256>::new(public_key)
        .verify(message, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub struct EphemeralRsaPssLabSigner {
    key_ref: KeyRef,
    key: RsaPrivateKey,
}

impl EphemeralRsaPssLabSigner {
    pub fn generate(key_ref: KeyRef) -> Result<Self, CryptoError> {
        let key = RsaPrivateKey::new(&mut OsRng, 3072).map_err(|_| CryptoError::SigningFailed)?;
        Ok(Self { key_ref, key })
    }

    pub fn key_ref(&self) -> &KeyRef {
        &self.key_ref
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let public_key = RsaPublicKey::from(&self.key);
        let verifier = VerifyingKey::<Sha256>::new(public_key);
        let signature =
            Signature::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;
        verifier
            .verify(message, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

impl SigningProvider for EphemeralRsaPssLabSigner {
    fn supports(&self, algorithm: SignatureAlgorithm) -> bool {
        algorithm == SignatureAlgorithm::RsaPssSha256
    }

    fn public_key_spki_der(&self, key: &KeyRef) -> Result<Vec<u8>, CryptoError> {
        if key != &self.key_ref {
            return Err(CryptoError::KeyUnavailable);
        }
        RsaPublicKey::from(&self.key)
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    fn sign(
        &self,
        key: &KeyRef,
        algorithm: SignatureAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if key != &self.key_ref {
            return Err(CryptoError::KeyUnavailable);
        }
        if !self.supports(algorithm) {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        let signer = SigningKey::<Sha256>::new(self.key.clone());
        Ok(signer.sign_with_rng(&mut OsRng, message).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomized_lab_serials_are_positive_canonical_and_distinct() {
        let first = generate_lab_serial();
        let second = generate_lab_serial();
        assert_eq!(first.len(), 19);
        assert_eq!(first[0] & 0xc0, 0x40);
        assert_ne!(first, second);
    }

    #[test]
    fn signs_verifies_and_rejects_tampering() {
        let key_ref = KeyRef("rsa-pss-lab".into());
        let provider = EphemeralRsaPssLabSigner::generate(key_ref.clone()).unwrap();
        let signature = provider
            .sign(&key_ref, SignatureAlgorithm::RsaPssSha256, b"hello")
            .unwrap();
        assert_eq!(provider.verify(b"hello", &signature), Ok(()));
        assert_eq!(
            provider.verify(b"modified", &signature),
            Err(CryptoError::InvalidSignature)
        );
        assert_eq!(
            provider.sign(
                &KeyRef("wrong".into()),
                SignatureAlgorithm::RsaPssSha256,
                b"hello"
            ),
            Err(CryptoError::KeyUnavailable)
        );
        assert_eq!(
            provider.sign(&key_ref, SignatureAlgorithm::MlDsa65, b"hello"),
            Err(CryptoError::UnsupportedAlgorithm)
        );
        let spki = provider.public_key_spki_der(&key_ref).unwrap();
        assert_eq!(verify_rsa_pss_sha256_spki(&spki, b"hello", &signature), Ok(()));
        assert_eq!(
            verify_rsa_pss_sha256_spki(&spki, b"altered", &signature),
            Err(CryptoError::InvalidSignature)
        );
    }
}
