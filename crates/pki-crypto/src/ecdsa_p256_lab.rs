//! P-256 ECDSA proof-of-execution for isolated laboratory tests.
//! This module is not a production CA or a key custody provider.
use crate::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabSignatureError {
    UnsupportedSuite,
    InvalidKey,
    InvalidSignature,
}

pub fn sign_p256_lab(
    suite: AlgorithmSuite,
    key: &p256::ecdsa::SigningKey,
    message: &[u8],
) -> Result<Vec<u8>, LabSignatureError> {
    use p256::ecdsa::signature::Signer;
    if suite
        != (AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P256,
            digest: Digest::Sha256,
        })
    {
        return Err(LabSignatureError::UnsupportedSuite);
    }
    let signature: p256::ecdsa::Signature = key.sign(message);
    Ok(signature.to_der().as_bytes().to_vec())
}

pub fn verify_p256_lab(
    suite: AlgorithmSuite,
    public_key_sec1: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<(), LabSignatureError> {
    use p256::ecdsa::signature::Verifier;
    if suite
        != (AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P256,
            digest: Digest::Sha256,
        })
    {
        return Err(LabSignatureError::UnsupportedSuite);
    }
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| LabSignatureError::InvalidKey)?;
    let signature = p256::ecdsa::Signature::from_der(signature_der)
        .map_err(|_| LabSignatureError::InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| LabSignatureError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    const P256: AlgorithmSuite = AlgorithmSuite {
        scheme: SignatureScheme::Ecdsa,
        key: KeyParameter::P256,
        digest: Digest::Sha256,
    };

    #[test]
    fn signature_roundtrip_and_tamper_rejection() {
        let key = p256::ecdsa::SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let signature = sign_p256_lab(P256, &key, b"certificate-tbs").unwrap();
        assert_eq!(
            verify_p256_lab(P256, public.as_bytes(), b"certificate-tbs", &signature),
            Ok(())
        );
        assert_eq!(
            verify_p256_lab(P256, public.as_bytes(), b"altered-tbs", &signature),
            Err(LabSignatureError::InvalidSignature)
        );
        let mut corrupt = signature;
        corrupt[0] ^= 1;
        assert_eq!(
            verify_p256_lab(P256, public.as_bytes(), b"certificate-tbs", &corrupt),
            Err(LabSignatureError::InvalidSignature)
        );
    }

    #[test]
    fn refuse_unsupported_curve_instead_of_fallback() {
        let key = p256::ecdsa::SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
        let p384 = AlgorithmSuite {
            key: KeyParameter::P384,
            digest: Digest::Sha384,
            ..P256
        };
        assert_eq!(
            sign_p256_lab(p384, &key, b"payload"),
            Err(LabSignatureError::UnsupportedSuite)
        );
    }
}
