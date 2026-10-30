//! Bind selected signature suite to the issuer key's observed properties.
//! This is a preflight contract; the adapter must measure properties from SPKI
//! or the HSM key handle, not from untrusted caller input.
use crate::crypto_agility::{validate_suite, AlgorithmSuite, KeyParameter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBindingError {
    InvalidSuite,
    KeyParameterMismatch,
    UnverifiedKey,
}

/// An explicit, trusted measurement is required before allowing signing.
/// Never assume RSA-3072 from an algorithm identifier or silently downgrade.
pub fn require_issuer_key_binding(
    suite: AlgorithmSuite,
    observed_key: KeyParameter,
    measurement_verified: bool,
) -> Result<(), KeyBindingError> {
    validate_suite(suite).map_err(|_| KeyBindingError::InvalidSuite)?;
    if !measurement_verified {
        return Err(KeyBindingError::UnverifiedKey);
    }
    if suite.key != observed_key {
        return Err(KeyBindingError::KeyParameterMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_agility::{Digest, SignatureScheme};

    #[test]
    fn rsa_size_is_bound_to_the_measured_key() {
        let suite = AlgorithmSuite {
            scheme: SignatureScheme::RsaPss,
            key: KeyParameter::Rsa4096,
            digest: Digest::Sha384,
        };
        assert_eq!(
            require_issuer_key_binding(suite, KeyParameter::Rsa4096, true),
            Ok(())
        );
        assert_eq!(
            require_issuer_key_binding(suite, KeyParameter::Rsa3072, true),
            Err(KeyBindingError::KeyParameterMismatch)
        );
        assert_eq!(
            require_issuer_key_binding(suite, KeyParameter::Rsa4096, false),
            Err(KeyBindingError::UnverifiedKey)
        );
    }

    #[test]
    fn curve_substitution_is_rejected() {
        let suite = AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P384,
            digest: Digest::Sha384,
        };
        assert_eq!(
            require_issuer_key_binding(suite, KeyParameter::P256, true),
            Err(KeyBindingError::KeyParameterMismatch)
        );
    }
}
