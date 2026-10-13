//! Signing provider contract (ADR-0004).
//!
//! - Algorithms are a closed enum; each variant fixes all its parameters.
//! - The signing input is explicit ([`SignInput`]): no "message or digest" ambiguity.
//! - Every signature is bound to a [`SigningAuthorization`] over the SHA-256 of the
//!   exact TBS bytes, and is verified by an independent [`SignatureVerifier`]
//!   before it is returned ([`sign_tbs`]).
//! - Failures are classified; [`SignError::Indeterminate`] means the outcome is
//!   unknown and the issuance must go to reconciliation (ADR-0002).

#![forbid(unsafe_code)]

use core::fmt;

use der::asn1::ObjectIdentifier;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Hash algorithms used for prehash signature schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// Closed set of signature algorithms (ADR-0003 suites).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    /// RSA-PSS, MGF1 with the same hash, salt length = hash length.
    RsaPssSha256,
    RsaPssSha384,
    /// Legacy-compatibility profile only.
    RsaPkcs1Sha256,
    /// Pure Ed25519 (no Ed25519ph).
    Ed25519,
    /// Pure ML-DSA, empty context string (FIPS 204, RFC 9881).
    MlDsa44,
    MlDsa65,
    MlDsa87,
    /// Composite ML-DSA + ECDSA (IETF LAMPS draft; lab only until RFC).
    CompositeMlDsa65EcdsaP256,
    CompositeMlDsa87EcdsaP384,
}

/// How a `SignatureAlgorithm` consumes its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputMode {
    /// The caller hashes with this algorithm and passes [`SignInput::Prehashed`].
    Prehash(HashAlgorithm),
    /// The full message is signed ([`SignInput::Message`]); ML-DSA may also accept
    /// [`SignInput::MlDsaExternalMu`] when the provider advertises it.
    Message,
}

/// Parameters field encoding required in an `AlgorithmIdentifier`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamsEncoding {
    /// Parameters must be absent.
    Absent,
    /// Parameters must be ASN.1 NULL.
    Null,
}

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const OID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const OID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

impl SignatureAlgorithm {
    pub const fn input_mode(self) -> InputMode {
        match self {
            Self::EcdsaP256Sha256 | Self::RsaPssSha256 | Self::RsaPkcs1Sha256 => {
                InputMode::Prehash(HashAlgorithm::Sha256)
            }
            Self::EcdsaP384Sha384 | Self::RsaPssSha384 => InputMode::Prehash(HashAlgorithm::Sha384),
            Self::Ed25519
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87
            | Self::CompositeMlDsa65EcdsaP256
            | Self::CompositeMlDsa87EcdsaP384 => InputMode::Message,
        }
    }

    pub const fn is_standalone_ml_dsa(self) -> bool {
        matches!(self, Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87)
    }

    /// Suites that ADR-0003 restricts to lab profiles.
    pub const fn is_lab_only(self) -> bool {
        self.is_standalone_ml_dsa() || matches!(self, Self::CompositeMlDsa65EcdsaP256 | Self::CompositeMlDsa87EcdsaP384)
    }

    /// Checks that `input` is a valid signing input for this algorithm.
    pub fn accepts(self, input: &SignInput<'_>) -> Result<(), InputError> {
        match (self.input_mode(), input) {
            (InputMode::Prehash(h), SignInput::Prehashed(d)) if d.len() == h.output_len() => Ok(()),
            (InputMode::Prehash(h), SignInput::Prehashed(d)) => {
                Err(InputError::DigestLength { expected: h.output_len(), actual: d.len() })
            }
            (InputMode::Message, SignInput::Message(_)) => Ok(()),
            (InputMode::Message, SignInput::MlDsaExternalMu(_)) if self.is_standalone_ml_dsa() => Ok(()),
            _ => Err(InputError::IncompatibleInput(self)),
        }
    }

    /// Builds the signing input for `tbs` according to [`Self::input_mode`].
    /// Hashing is owned by the core, never by provider adapters.
    pub fn input_for<'a>(self, tbs: &'a [u8], digest_buf: &'a mut Vec<u8>) -> SignInput<'a> {
        match self.input_mode() {
            InputMode::Prehash(h) => {
                *digest_buf = h.digest(tbs);
                SignInput::Prehashed(digest_buf.as_slice())
            }
            InputMode::Message => SignInput::Message(tbs),
        }
    }

    /// Algorithm OID and required parameters encoding. `None` for algorithms
    /// whose identifier is not (yet) supported for parsing: RSA-PSS needs
    /// parameter parsing, composite OIDs are draft-dependent.
    pub fn oid(self) -> Option<(ObjectIdentifier, ParamsEncoding)> {
        Some(match self {
            Self::EcdsaP256Sha256 => (OID_ECDSA_SHA256, ParamsEncoding::Absent),
            Self::EcdsaP384Sha384 => (OID_ECDSA_SHA384, ParamsEncoding::Absent),
            Self::RsaPkcs1Sha256 => (OID_RSA_SHA256, ParamsEncoding::Null),
            Self::Ed25519 => (OID_ED25519, ParamsEncoding::Absent),
            Self::MlDsa44 => (OID_ML_DSA_44, ParamsEncoding::Absent),
            Self::MlDsa65 => (OID_ML_DSA_65, ParamsEncoding::Absent),
            Self::MlDsa87 => (OID_ML_DSA_87, ParamsEncoding::Absent),
            Self::RsaPssSha256
            | Self::RsaPssSha384
            | Self::CompositeMlDsa65EcdsaP256
            | Self::CompositeMlDsa87EcdsaP384 => return None,
        })
    }

    /// Reverse of [`Self::oid`]; unknown OIDs are rejected (no fallback).
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        ALL.iter().copied().find(|a| a.oid().is_some_and(|(o, _)| &o == oid))
    }
}

const ALL: [SignatureAlgorithm; 11] = [
    SignatureAlgorithm::EcdsaP256Sha256,
    SignatureAlgorithm::EcdsaP384Sha384,
    SignatureAlgorithm::RsaPssSha256,
    SignatureAlgorithm::RsaPssSha384,
    SignatureAlgorithm::RsaPkcs1Sha256,
    SignatureAlgorithm::Ed25519,
    SignatureAlgorithm::MlDsa44,
    SignatureAlgorithm::MlDsa65,
    SignatureAlgorithm::MlDsa87,
    SignatureAlgorithm::CompositeMlDsa65EcdsaP256,
    SignatureAlgorithm::CompositeMlDsa87EcdsaP384,
];

/// Explicit signing input (ADR-0004 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInput<'a> {
    Message(&'a [u8]),
    Prehashed(&'a [u8]),
    MlDsaExternalMu(&'a [u8; 64]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    IncompatibleInput(SignatureAlgorithm),
    DigestLength { expected: usize, actual: usize },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompatibleInput(a) => write!(f, "signing input not accepted by {a:?}"),
            Self::DigestLength { expected, actual } => {
                write!(f, "digest length {actual}, expected {expected}")
            }
        }
    }
}

/// Opaque reference to a key held by a provider. Never carries key material.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyRef(String);

impl KeyRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn id(&self) -> &str {
        &self.0
    }
}

/// Authorization to sign exactly one TBS structure (ADR-0004 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningAuthorization {
    intent_id: String,
    key: KeyRef,
    algorithm: SignatureAlgorithm,
    tbs_sha256: [u8; 32],
}

impl SigningAuthorization {
    /// Binds an authorization to the SHA-256 of the exact bytes to be signed.
    pub fn for_tbs(intent_id: impl Into<String>, key: KeyRef, algorithm: SignatureAlgorithm, tbs: &[u8]) -> Self {
        Self { intent_id: intent_id.into(), key, algorithm, tbs_sha256: Sha256::digest(tbs).into() }
    }
    pub fn intent_id(&self) -> &str {
        &self.intent_id
    }
    pub fn key(&self) -> &KeyRef {
        &self.key
    }
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
    pub fn tbs_sha256(&self) -> &[u8; 32] {
        &self.tbs_sha256
    }
    /// True if this authorization covers `tbs` with `key` and `algorithm`.
    pub fn covers(&self, key: &KeyRef, algorithm: SignatureAlgorithm, tbs: &[u8]) -> bool {
        self.key == *key && self.algorithm == algorithm && self.tbs_sha256 == <[u8; 32]>::from(Sha256::digest(tbs))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub algorithms: Vec<SignatureAlgorithm>,
    pub ml_dsa_external_mu: bool,
}

/// Classified signing outcome (ADR-0004 §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    /// Definitive: refused before anything was signed.
    Rejected(String),
    /// Definitive: the provider reports failure; no signature exists.
    Failed(String),
    /// Unknown outcome: a signature may exist. Must go to reconciliation.
    Indeterminate(String),
    /// A signature was produced but did not verify. Security event; discard it.
    VerificationFailed,
}

impl SignError {
    /// True when it is certain that no valid signature was produced.
    pub fn is_definitive(&self) -> bool {
        !matches!(self, Self::Indeterminate(_))
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(m) => write!(f, "signing rejected: {m}"),
            Self::Failed(m) => write!(f, "signing failed: {m}"),
            Self::Indeterminate(m) => write!(f, "signing outcome indeterminate: {m}"),
            Self::VerificationFailed => f.write_str("produced signature failed verification"),
        }
    }
}

impl std::error::Error for SignError {}

/// A signing backend (software lab provider, PKCS#11 adapter, ...).
///
/// Implementations must re-check that `authz` covers the request and must
/// classify errors conservatively: any error after the request may have reached
/// the device is [`SignError::Indeterminate`].
pub trait SigningProvider {
    fn capabilities(&self) -> Capabilities;
    /// DER-encoded SubjectPublicKeyInfo of `key`.
    fn public_key(&self, key: &KeyRef) -> Result<Vec<u8>, SignError>;
    fn sign(
        &self,
        key: &KeyRef,
        algorithm: SignatureAlgorithm,
        input: SignInput<'_>,
        authz: &SigningAuthorization,
    ) -> Result<Signature, SignError>;
}

/// Signature verification, independent from the signing path.
pub trait SignatureVerifier {
    fn verify(
        &self,
        spki_der: &[u8],
        algorithm: SignatureAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), VerifyError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Unsupported,
    Invalid,
}

/// Signs `tbs` under `authz` and verifies the result before returning it
/// (ADR-0004 §5). This is the only signing entry point the CA core uses.
pub fn sign_tbs(
    provider: &dyn SigningProvider,
    verifier: &dyn SignatureVerifier,
    ca_spki_der: &[u8],
    key: &KeyRef,
    algorithm: SignatureAlgorithm,
    tbs: &[u8],
    authz: &SigningAuthorization,
) -> Result<Signature, SignError> {
    if !authz.covers(key, algorithm, tbs) {
        return Err(SignError::Rejected("authorization does not cover this TBS, key or algorithm".into()));
    }
    if !provider.capabilities().algorithms.contains(&algorithm) {
        return Err(SignError::Rejected(format!("provider does not support {algorithm:?}")));
    }
    let mut digest_buf = Vec::new();
    let input = algorithm.input_for(tbs, &mut digest_buf);
    algorithm.accepts(&input).map_err(|e| SignError::Rejected(e.to_string()))?;

    let signature = provider.sign(key, algorithm, input, authz)?;
    verifier.verify(ca_spki_der, algorithm, tbs, &signature.0).map_err(|_| SignError::VerificationFailed)?;
    Ok(signature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockProvider {
        result: Result<Signature, SignError>,
        seen: RefCell<Vec<Vec<u8>>>,
    }

    impl SigningProvider for MockProvider {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256, SignatureAlgorithm::MlDsa65],
                ml_dsa_external_mu: false,
            }
        }
        fn public_key(&self, _: &KeyRef) -> Result<Vec<u8>, SignError> {
            Ok(vec![])
        }
        fn sign(
            &self,
            _: &KeyRef,
            _: SignatureAlgorithm,
            input: SignInput<'_>,
            _: &SigningAuthorization,
        ) -> Result<Signature, SignError> {
            let bytes = match input {
                SignInput::Message(m) | SignInput::Prehashed(m) => m.to_vec(),
                SignInput::MlDsaExternalMu(m) => m.to_vec(),
            };
            self.seen.borrow_mut().push(bytes);
            self.result.clone()
        }
    }

    struct MockVerifier(bool);
    impl SignatureVerifier for MockVerifier {
        fn verify(&self, _: &[u8], _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<(), VerifyError> {
            if self.0 { Ok(()) } else { Err(VerifyError::Invalid) }
        }
    }

    fn provider(result: Result<Signature, SignError>) -> MockProvider {
        MockProvider { result, seen: RefCell::new(vec![]) }
    }

    const TBS: &[u8] = b"tbs-certificate-der";

    #[test]
    fn prehash_algorithms_receive_digest_not_message() {
        let p = provider(Ok(Signature(vec![1])));
        let key = KeyRef::new("ca-1");
        let alg = SignatureAlgorithm::EcdsaP256Sha256;
        let authz = SigningAuthorization::for_tbs("i1", key.clone(), alg, TBS);
        sign_tbs(&p, &MockVerifier(true), &[], &key, alg, TBS, &authz).unwrap();
        assert_eq!(p.seen.borrow()[0], HashAlgorithm::Sha256.digest(TBS));
    }

    #[test]
    fn ml_dsa_receives_full_message() {
        let p = provider(Ok(Signature(vec![1])));
        let key = KeyRef::new("ca-1");
        let alg = SignatureAlgorithm::MlDsa65;
        let authz = SigningAuthorization::for_tbs("i1", key.clone(), alg, TBS);
        sign_tbs(&p, &MockVerifier(true), &[], &key, alg, TBS, &authz).unwrap();
        assert_eq!(p.seen.borrow()[0], TBS);
    }

    #[test]
    fn authorization_for_other_tbs_is_rejected_before_provider() {
        let p = provider(Ok(Signature(vec![1])));
        let key = KeyRef::new("ca-1");
        let alg = SignatureAlgorithm::EcdsaP256Sha256;
        let authz = SigningAuthorization::for_tbs("i1", key.clone(), alg, b"other");
        let err = sign_tbs(&p, &MockVerifier(true), &[], &key, alg, TBS, &authz).unwrap_err();
        assert!(matches!(err, SignError::Rejected(_)));
        assert!(p.seen.borrow().is_empty());
    }

    #[test]
    fn authorization_for_other_key_or_algorithm_is_rejected() {
        let p = provider(Ok(Signature(vec![1])));
        let key = KeyRef::new("ca-1");
        let authz = SigningAuthorization::for_tbs("i1", key.clone(), SignatureAlgorithm::MlDsa65, TBS);
        assert!(
            sign_tbs(&p, &MockVerifier(true), &[], &key, SignatureAlgorithm::EcdsaP256Sha256, TBS, &authz).is_err()
        );
        assert!(
            sign_tbs(&p, &MockVerifier(true), &[], &KeyRef::new("ca-2"), SignatureAlgorithm::MlDsa65, TBS, &authz)
                .is_err()
        );
        assert!(p.seen.borrow().is_empty());
    }

    #[test]
    fn unsupported_algorithm_is_rejected_without_fallback() {
        let p = provider(Ok(Signature(vec![1])));
        let key = KeyRef::new("ca-1");
        let alg = SignatureAlgorithm::MlDsa87;
        let authz = SigningAuthorization::for_tbs("i1", key.clone(), alg, TBS);
        assert!(matches!(sign_tbs(&p, &MockVerifier(true), &[], &key, alg, TBS, &authz), Err(SignError::Rejected(_))));
    }

    #[test]
    fn invalid_signature_is_never_returned() {
        let p = provider(Ok(Signature(vec![0xff])));
        let key = KeyRef::new("ca-1");
        let alg = SignatureAlgorithm::EcdsaP256Sha256;
        let authz = SigningAuthorization::for_tbs("i1", key.clone(), alg, TBS);
        assert_eq!(sign_tbs(&p, &MockVerifier(false), &[], &key, alg, TBS, &authz), Err(SignError::VerificationFailed));
    }

    #[test]
    fn indeterminate_outcome_is_propagated_and_not_definitive() {
        let p = provider(Err(SignError::Indeterminate("timeout".into())));
        let key = KeyRef::new("ca-1");
        let alg = SignatureAlgorithm::EcdsaP256Sha256;
        let authz = SigningAuthorization::for_tbs("i1", key.clone(), alg, TBS);
        let err = sign_tbs(&p, &MockVerifier(true), &[], &key, alg, TBS, &authz).unwrap_err();
        assert!(!err.is_definitive());
    }

    #[test]
    fn input_compatibility_table() {
        use SignatureAlgorithm as A;
        let d32 = [0u8; 32];
        let mu = [0u8; 64];
        assert!(A::EcdsaP256Sha256.accepts(&SignInput::Prehashed(&d32)).is_ok());
        assert!(A::EcdsaP384Sha384.accepts(&SignInput::Prehashed(&d32)).is_err());
        assert!(A::EcdsaP256Sha256.accepts(&SignInput::Message(b"m")).is_err());
        assert!(A::MlDsa65.accepts(&SignInput::Prehashed(&d32)).is_err());
        assert!(A::MlDsa65.accepts(&SignInput::MlDsaExternalMu(&mu)).is_ok());
        assert!(A::Ed25519.accepts(&SignInput::MlDsaExternalMu(&mu)).is_err());
        assert!(A::CompositeMlDsa65EcdsaP256.accepts(&SignInput::MlDsaExternalMu(&mu)).is_err());
    }

    #[test]
    fn oid_round_trip_and_lab_only() {
        for a in ALL {
            if let Some((oid, _)) = a.oid() {
                assert_eq!(SignatureAlgorithm::from_oid(&oid), Some(a));
            }
        }
        assert!(SignatureAlgorithm::MlDsa65.is_lab_only());
        assert!(!SignatureAlgorithm::EcdsaP384Sha384.is_lab_only());
    }
}
