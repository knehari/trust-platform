//! Explicitly opted-in, ephemeral laboratory signing key provider.
//!
//! No persistent private key, HSM integration or production key lifecycle.
//! Do not expose this feature in a production binary.

use super::{CryptoError, KeyRef, SignatureAlgorithm, SigningProvider};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::EncodePublicKey;

/// The secret remains inside this object and is dropped with the process.
/// CA continuity and revocation are impossible after a process restart.
pub struct EphemeralP256Signer {
    label: KeyRef,
    private: SigningKey,
}

impl EphemeralP256Signer {
    pub fn generate(label: &str) -> Result<Self, CryptoError> {
        if label.trim().is_empty() {
            return Err(CryptoError::KeyUnavailable);
        }

        Ok(Self {
            label: KeyRef(label.to_owned()),
            private: SigningKey::random(&mut OsRng),
        })
    }

    pub fn key_ref(&self) -> &KeyRef {
        &self.label
    }
}

impl SigningProvider for EphemeralP256Signer {
    fn supports(&self, algorithm: SignatureAlgorithm) -> bool {
        algorithm == SignatureAlgorithm::EcdsaP256Sha256
    }

    fn public_key_spki_der(&self, key: &KeyRef) -> Result<Vec<u8>, CryptoError> {
        if key != self.key_ref() {
            return Err(CryptoError::KeyUnavailable);
        }

        self.private
            .verifying_key()
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
        if key != self.key_ref() {
            return Err(CryptoError::KeyUnavailable);
        }
        if !self.supports(algorithm) {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        let signature: Signature = self.private.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// A P-256 key loaded from a PKCS#8 file, for laboratory anchoring jobs
/// that must sign with the same key across runs (audit checkpoints). The
/// key file is plaintext on disk: never a production custody mechanism.
pub struct LabP256KeyFile {
    private: SigningKey,
}

impl LabP256KeyFile {
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        use p256::pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_der(der)
            .map(|private| Self { private })
            .map_err(|_| CryptoError::KeyUnavailable)
    }

    /// Compressed SEC1 public key.
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.private
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// ECDSA P-256 with SHA-256 over `message`, DER encoded.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.private.sign(message);
        signature.to_der().as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_p256_ecdsa_sha256;
    use p256::pkcs8::DecodePublicKey;

    #[test]
    fn laboratory_signer_rejects_wrong_keys_and_algorithms() {
        let signer = EphemeralP256Signer::generate("lab-root").unwrap();
        assert_eq!(
            signer.sign(
                &KeyRef("wrong".into()),
                SignatureAlgorithm::EcdsaP256Sha256,
                b"msg"
            ),
            Err(CryptoError::KeyUnavailable)
        );
        assert_eq!(
            signer.sign(signer.key_ref(), SignatureAlgorithm::MlDsa65, b"msg"),
            Err(CryptoError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn generated_signature_is_verified() {
        let signer = EphemeralP256Signer::generate("lab-root").unwrap();
        let signature = signer
            .sign(
                signer.key_ref(),
                SignatureAlgorithm::EcdsaP256Sha256,
                b"lab-tbs",
            )
            .unwrap();
        let spki = signer.public_key_spki_der(signer.key_ref()).unwrap();
        let public = p256::PublicKey::from_public_key_der(&spki).unwrap();
        let sec1 = public.to_sec1_bytes();
        verify_p256_ecdsa_sha256(sec1.as_ref(), b"lab-tbs", &signature).unwrap();
        assert!(verify_p256_ecdsa_sha256(sec1.as_ref(), b"other", &signature).is_err());
    }

    #[test]
    fn key_file_signs_verifiably_and_refuses_garbage() {
        use p256::pkcs8::EncodePrivateKey;
        let key = SigningKey::random(&mut OsRng);
        let der = key.to_pkcs8_der().unwrap();
        let file = LabP256KeyFile::from_pkcs8_der(der.as_bytes()).unwrap();
        let signature = file.sign(b"checkpoint");
        verify_p256_ecdsa_sha256(&file.public_key_sec1(), b"checkpoint", &signature).unwrap();
        assert!(verify_p256_ecdsa_sha256(&file.public_key_sec1(), b"other", &signature).is_err());
        assert!(matches!(
            LabP256KeyFile::from_pkcs8_der(&[0x30, 0x00]),
            Err(CryptoError::KeyUnavailable)
        ));
    }
}
