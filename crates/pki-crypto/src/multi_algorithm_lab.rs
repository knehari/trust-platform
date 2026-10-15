//! Typed laboratory signing dispatcher. No production key custody or PKI issuance.
//! A signature suite and key reference must be explicitly authorized together.
//! No downgrade or fallback is permitted when a suite is unsupported.
use crate::crypto_agility::{validate_suite, AlgorithmSuite, KeyParameter, SignatureScheme};
use crate::issuer_key_binding::require_issuer_key_binding;
use crate::{crypto_agility::CryptoAgilityError, KeyRef};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};

pub enum LaboratoryKey {
    Rsa(RsaPrivateKey),
    EcdsaP256(p256::ecdsa::SigningKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    KeyRefMismatch,
    ForbiddenByPolicy,
    UnsupportedSuite,
    InvalidSignature,
}

pub struct LaboratorySigner {
    key_ref: KeyRef,
    key: LaboratoryKey,
}

impl LaboratorySigner {
    pub fn rsa(key_ref: KeyRef, key: RsaPrivateKey) -> Self {
        Self {
            key_ref,
            key: LaboratoryKey::Rsa(key),
        }
    }

    pub fn ecdsa_p256(key_ref: KeyRef, key: p256::ecdsa::SigningKey) -> Self {
        Self {
            key_ref,
            key: LaboratoryKey::EcdsaP256(key),
        }
    }

    /// Observed from the actual in-memory laboratory key, never caller metadata.
    fn observed_key_parameter(&self) -> Option<KeyParameter> {
        match &self.key {
            LaboratoryKey::Rsa(private) => match RsaPublicKey::from(private).n().bits() {
                2048 => Some(KeyParameter::Rsa2048),
                3072 => Some(KeyParameter::Rsa3072),
                4096 => Some(KeyParameter::Rsa4096),
                8192 => Some(KeyParameter::Rsa8192),
                _ => None,
            },
            LaboratoryKey::EcdsaP256(_) => Some(KeyParameter::P256),
        }
    }

    fn authorize(
        &self,
        key_ref: &KeyRef,
        suite: AlgorithmSuite,
        policy_allowlist: &[AlgorithmSuite],
    ) -> Result<(), DispatchError> {
        if key_ref != &self.key_ref {
            return Err(DispatchError::KeyRefMismatch);
        }
        if !policy_allowlist.contains(&suite) {
            return Err(DispatchError::ForbiddenByPolicy);
        }
        validate_suite(suite).map_err(|_e: CryptoAgilityError| DispatchError::UnsupportedSuite)?;
        let measured = self
            .observed_key_parameter()
            .ok_or(DispatchError::UnsupportedSuite)?;
        require_issuer_key_binding(suite, measured, true)
            .map_err(|_| DispatchError::UnsupportedSuite)
    }

    /// The caller supplies trusted policy for each operation. No default suite.
    pub fn sign(
        &self,
        key_ref: &KeyRef,
        suite: AlgorithmSuite,
        policy_allowlist: &[AlgorithmSuite],
        message: &[u8],
    ) -> Result<Vec<u8>, DispatchError> {
        self.authorize(key_ref, suite, policy_allowlist)?;
        match (&self.key, suite.scheme) {
            (LaboratoryKey::Rsa(private), SignatureScheme::RsaPss) => {
                crate::rsa_pss_agile_lab::sign_rsa_pss_lab(suite, private, message)
                    .map_err(|_| DispatchError::UnsupportedSuite)
            }
            (LaboratoryKey::Rsa(private), SignatureScheme::RsaPkcs1V15) => {
                crate::rsa_pkcs1_lab::sign_pkcs1_lab(suite, private, message)
                    .map_err(|_| DispatchError::UnsupportedSuite)
            }
            (LaboratoryKey::EcdsaP256(key), SignatureScheme::Ecdsa) => {
                crate::ecdsa_p256_lab::sign_p256_lab(suite, key, message)
                    .map_err(|_| DispatchError::UnsupportedSuite)
            }
            _ => Err(DispatchError::UnsupportedSuite),
        }
    }

    pub fn verify(
        &self,
        key_ref: &KeyRef,
        suite: AlgorithmSuite,
        policy_allowlist: &[AlgorithmSuite],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), DispatchError> {
        self.authorize(key_ref, suite, policy_allowlist)?;
        match (&self.key, suite.scheme) {
            (LaboratoryKey::Rsa(private), SignatureScheme::RsaPss) => {
                let public = RsaPublicKey::from(private);
                crate::rsa_pss_agile_lab::verify_rsa_pss_lab(suite, &public, message, signature)
                    .map_err(|_| DispatchError::InvalidSignature)
            }
            (LaboratoryKey::Rsa(private), SignatureScheme::RsaPkcs1V15) => {
                let public = RsaPublicKey::from(private);
                crate::rsa_pkcs1_lab::verify_pkcs1_lab(suite, &public, message, signature)
                    .map_err(|_| DispatchError::InvalidSignature)
            }
            (LaboratoryKey::EcdsaP256(key), SignatureScheme::Ecdsa) => {
                let public = key.verifying_key().to_encoded_point(false);
                crate::ecdsa_p256_lab::verify_p256_lab(suite, public.as_bytes(), message, signature)
                    .map_err(|_| DispatchError::InvalidSignature)
            }
            _ => Err(DispatchError::UnsupportedSuite),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_agility::{Digest, KeyParameter};

    const RSA_PSS: AlgorithmSuite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPss,
        key: KeyParameter::Rsa2048,
        digest: Digest::Sha256,
    };
    const RSA_PKCS1: AlgorithmSuite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPkcs1V15,
        key: KeyParameter::Rsa2048,
        digest: Digest::Sha384,
    };
    const ECDSA: AlgorithmSuite = AlgorithmSuite {
        scheme: SignatureScheme::Ecdsa,
        key: KeyParameter::P256,
        digest: Digest::Sha256,
    };

    #[test]
    fn rsa_suites_are_explicit_and_not_interchangeable() {
        let key_ref = KeyRef("rsa-lab".into());
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let signer = LaboratorySigner::rsa(key_ref.clone(), private);
        let allowed = &[RSA_PSS, RSA_PKCS1];
        for suite in allowed {
            let signature = signer.sign(&key_ref, *suite, allowed, b"tbs").unwrap();
            assert_eq!(
                signer.verify(&key_ref, *suite, allowed, b"tbs", &signature),
                Ok(())
            );
            assert_eq!(
                signer.verify(&key_ref, *suite, allowed, b"tampered", &signature),
                Err(DispatchError::InvalidSignature)
            );
        }
        let signature = signer.sign(&key_ref, RSA_PSS, allowed, b"tbs").unwrap();
        assert_eq!(
            signer.verify(&key_ref, RSA_PKCS1, allowed, b"tbs", &signature),
            Err(DispatchError::InvalidSignature)
        );
        assert_eq!(
            signer.sign(&key_ref, RSA_PKCS1, &[RSA_PSS], b"tbs"),
            Err(DispatchError::ForbiddenByPolicy)
        );
    }

    #[test]
    fn p256_sign_verify_with_key_reference_and_policy_gates() {
        let key_ref = KeyRef("p256-lab".into());
        let key = p256::ecdsa::SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
        let signer = LaboratorySigner::ecdsa_p256(key_ref.clone(), key);
        let signature = signer.sign(&key_ref, ECDSA, &[ECDSA], b"tbs").unwrap();
        assert_eq!(
            signer.verify(&key_ref, ECDSA, &[ECDSA], b"tbs", &signature),
            Ok(())
        );
        assert_eq!(
            signer.sign(&KeyRef("other".into()), ECDSA, &[ECDSA], b"tbs"),
            Err(DispatchError::KeyRefMismatch)
        );
        assert_eq!(
            signer.sign(&key_ref, RSA_PSS, &[ECDSA, RSA_PSS], b"tbs"),
            Err(DispatchError::UnsupportedSuite)
        );
    }
}
