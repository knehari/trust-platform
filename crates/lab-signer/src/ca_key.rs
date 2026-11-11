//! The signer's keys (ADR-0034, ADR-0035, Proposed): the CA key and the
//! audit checkpoint key, each a laboratory software key file or a key held in
//! a PKCS#11 token that never leaves it.
//!
//! Signature contract, for every source: ECDSA over P-256 with SHA-256.
//! - The signed message is the exact DER of the TBSCertificate or
//!   TBSCertList.
//! - The signer computes SHA-256 of those bytes itself and hands the 32-byte
//!   digest to the token with `CKM_ECDSA` (pre-hashed). It never uses a
//!   combined mechanism, so the hash applied is always the one the X.509
//!   algorithm identifier (`ecdsa-with-SHA256`) names.
//! - The token returns `r || s` (2 × 32 bytes, PKCS#11 v2.40 §2.3.1); the
//!   signer re-encodes it as the DER `ECDSA-Sig-Value` that X.509 requires.
//! - The signer verifies every signature under the token's public key before
//!   it returns it, so a faulty or substituted token key cannot emit a bad
//!   or foreign signature.
//!
//! A token key is used only when the token reports it as a P-256 EC private
//! key that is sensitive, not extractable, always sensitive and never
//! extractable: generated inside the token and never exported, not imported.
//! Anything else is refused; there is no fallback to a software key.

use std::path::PathBuf;

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    error::{Error as Pkcs11Error, RvError},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    PublicKey, SecretKey,
};
use sha2::{Digest, Sha256};

use crate::Refusal;

/// DER of the named-curve OID prime256v1 (1.2.840.10045.3.1.7), the only
/// `CKA_EC_PARAMS` accepted.
pub const P256_EC_PARAMS: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// A P-256 key that signs with ECDSA / SHA-256.
pub trait P256Key {
    fn public_key(&self) -> Result<PublicKey, Refusal>;
    /// The DER `ECDSA-Sig-Value` over SHA-256(`message`).
    fn sign_sha256(&self, message: &[u8]) -> Result<Vec<u8>, Refusal>;
}

impl P256Key for SecretKey {
    fn public_key(&self) -> Result<PublicKey, Refusal> {
        Ok(SecretKey::public_key(self))
    }

    fn sign_sha256(&self, message: &[u8]) -> Result<Vec<u8>, Refusal> {
        let signature: Signature = SigningKey::from(self.clone()).sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// Where a token key lives. The PIN is the token's user PIN; it is never
/// logged.
#[derive(Clone)]
pub struct Pkcs11Config {
    /// The PKCS#11 module (shared library), e.g. SoftHSM2's `libsofthsm2.so`.
    pub module: PathBuf,
    /// The label of the one token that holds the key.
    pub token_label: String,
    /// The `CKA_LABEL` of the key pair.
    pub key_label: String,
    pub pin: String,
}

impl Pkcs11Config {
    /// The CA key: `TRUST_SIGNER_PKCS11_MODULE`, `_TOKEN_LABEL`,
    /// `_KEY_LABEL` and `_PIN`.
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_env_prefix("TRUST_SIGNER_PKCS11")
    }

    /// `<prefix>_MODULE`, `_TOKEN_LABEL`, `_KEY_LABEL` and `_PIN`: `None`
    /// when no module is named, an error when the module is named but
    /// anything else is missing or empty.
    pub fn from_env_prefix(prefix: &str) -> Result<Option<Self>, String> {
        let get = |name: String| std::env::var(name).ok().filter(|value| !value.is_empty());
        let Some(module) = get(format!("{prefix}_MODULE")) else {
            return Ok(None);
        };
        let need = |suffix: &str| {
            get(format!("{prefix}_{suffix}"))
                .ok_or_else(|| format!("{prefix}_{suffix} is required with {prefix}_MODULE"))
        };
        Ok(Some(Self {
            module: PathBuf::from(module),
            token_label: need("TOKEN_LABEL")?,
            key_label: need("KEY_LABEL")?,
            pin: need("PIN")?,
        }))
    }
}

/// Loads and initialises a PKCS#11 module.
pub fn load_module(path: &std::path::Path) -> Result<Pkcs11, Refusal> {
    let context = Pkcs11::new(path).map_err(token)?;
    match context.initialize(CInitializeArgs::OsThreads) {
        Ok(()) | Err(Pkcs11Error::AlreadyInitialized) => Ok(context),
        Err(error) => Err(token(error)),
    }
}

/// An open PKCS#11 module and the slot of the configured token. Each
/// operation opens its own session and logs in.
pub struct Pkcs11Key {
    context: Pkcs11,
    slot: Slot,
    key_label: String,
    pin: AuthPin,
}

fn token(_: Pkcs11Error) -> Refusal {
    Refusal::Token
}

/// `CKA_EC_POINT` is a DER OCTET STRING holding the uncompressed point
/// (PKCS#11 v2.40 §2.3.3). Some modules return the bare point; both are
/// accepted, nothing else.
pub fn ec_point_public_key(ec_point: &[u8]) -> Result<PublicKey, Refusal> {
    let point = match ec_point {
        [0x04, 0x41, rest @ ..] if rest.len() == 65 => rest,
        [0x04, ..] if ec_point.len() == 65 => ec_point,
        _ => return Err(Refusal::KeyNotProtected),
    };
    PublicKey::from_sec1_bytes(point).map_err(|_| Refusal::KeyNotProtected)
}

/// The DER `ECDSA-Sig-Value` for a PKCS#11 `r || s` P-256 signature.
pub fn raw_signature_der(raw: &[u8]) -> Result<Vec<u8>, Refusal> {
    if raw.len() != 64 {
        return Err(Refusal::Token);
    }
    let signature = Signature::from_slice(raw).map_err(|_| Refusal::Token)?;
    Ok(signature.to_der().as_bytes().to_vec())
}

impl Pkcs11Key {
    /// Loads the module and finds the token by label: exactly one slot.
    pub fn open(config: &Pkcs11Config) -> Result<Self, Refusal> {
        Self::open_in(&load_module(&config.module)?, config)
    }

    /// The same, in a module already loaded: one process loads a module
    /// once, since dropping its last handle finalizes it (C_Finalize).
    pub fn open_in(context: &Pkcs11, config: &Pkcs11Config) -> Result<Self, Refusal> {
        let context = context.clone();
        let mut slots = Vec::new();
        for slot in context.get_slots_with_initialized_token().map_err(token)? {
            if context.get_token_info(slot).map_err(token)?.label() == config.token_label {
                slots.push(slot);
            }
        }
        let [slot] = slots[..] else {
            return Err(Refusal::Token);
        };
        Ok(Self {
            context,
            slot,
            key_label: config.key_label.clone(),
            pin: AuthPin::new(config.pin.clone()),
        })
    }

    fn session(&self, read_write: bool) -> Result<Session, Refusal> {
        let session = if read_write {
            self.context.open_rw_session(self.slot)
        } else {
            self.context.open_ro_session(self.slot)
        }
        .map_err(token)?;
        match session.login(UserType::User, Some(&self.pin)) {
            Ok(()) => Ok(session),
            Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
            Err(error) => Err(token(error)),
        }
    }

    fn labelled(&self, class: ObjectClass) -> Vec<Attribute> {
        vec![
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC),
            Attribute::Label(self.key_label.as_bytes().to_vec()),
        ]
    }

    /// The one private key with the label, after checking it is a P-256 key
    /// generated in the token and never exportable.
    fn private_key(&self, session: &Session) -> Result<ObjectHandle, Refusal> {
        let found = session
            .find_objects(&self.labelled(ObjectClass::PRIVATE_KEY))
            .map_err(token)?;
        let [key] = found[..] else {
            return Err(Refusal::KeyFile);
        };
        let attributes = session
            .get_attributes(
                key,
                &[
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::AlwaysSensitive,
                    AttributeType::NeverExtractable,
                    AttributeType::Sign,
                    AttributeType::EcParams,
                ],
            )
            .map_err(token)?;
        let protected = attributes.len() == 6
            && attributes.iter().all(|attribute| match attribute {
                Attribute::Sensitive(value)
                | Attribute::AlwaysSensitive(value)
                | Attribute::NeverExtractable(value)
                | Attribute::Sign(value) => *value,
                Attribute::Extractable(value) => !*value,
                Attribute::EcParams(params) => params[..] == P256_EC_PARAMS,
                _ => false,
            });
        if !protected {
            return Err(Refusal::KeyNotProtected);
        }
        Ok(key)
    }

    fn public_key_in(&self, session: &Session) -> Result<PublicKey, Refusal> {
        let found = session
            .find_objects(&self.labelled(ObjectClass::PUBLIC_KEY))
            .map_err(token)?;
        let [key] = found[..] else {
            return Err(Refusal::KeyFile);
        };
        match &session
            .get_attributes(key, &[AttributeType::EcPoint])
            .map_err(token)?[..]
        {
            [Attribute::EcPoint(point)] => ec_point_public_key(point),
            _ => Err(Refusal::KeyNotProtected),
        }
    }

    /// Ceremony only (ADR-0034): generates the key pair inside the token,
    /// sensitive and not extractable, under a label no object uses yet.
    pub fn generate(&self) -> Result<PublicKey, Refusal> {
        let session = self.session(true)?;
        let label = self.key_label.as_bytes().to_vec();
        if !session
            .find_objects(&[Attribute::Label(label.clone())])
            .map_err(token)?
            .is_empty()
        {
            return Err(Refusal::KeyExists);
        }
        let id = session.generate_random_vec(16).map_err(token)?;
        let public_template = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::VerifyRecover(false),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
            Attribute::EcParams(P256_EC_PARAMS.to_vec()),
            Attribute::Label(label.clone()),
            Attribute::Id(id.clone()),
        ];
        let private_template = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::SignRecover(false),
            Attribute::Derive(false),
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
            Attribute::Label(label),
            Attribute::Id(id),
        ];
        session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &public_template,
                &private_template,
            )
            .map_err(token)?;
        // The new key must pass the same checks as every later use.
        self.private_key(&session)?;
        self.public_key_in(&session)
    }

    /// Random bytes from the token's generator.
    pub fn random(&self, length: u32) -> Result<Vec<u8>, Refusal> {
        self.session(false)?
            .generate_random_vec(length)
            .map_err(token)
    }
}

impl P256Key for Pkcs11Key {
    fn public_key(&self) -> Result<PublicKey, Refusal> {
        let session = self.session(false)?;
        self.private_key(&session)?;
        self.public_key_in(&session)
    }

    fn sign_sha256(&self, message: &[u8]) -> Result<Vec<u8>, Refusal> {
        let session = self.session(false)?;
        let key = self.private_key(&session)?;
        let public = self.public_key_in(&session)?;
        let digest = Sha256::digest(message);
        let raw = session
            .sign(&Mechanism::Ecdsa, key, &digest)
            .map_err(token)?;
        let der = raw_signature_der(&raw)?;
        let signature = Signature::from_der(&der).map_err(|_| Refusal::Token)?;
        VerifyingKey::from(&public)
            .verify(message, &signature)
            .map_err(|_| Refusal::Token)?;
        Ok(der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_point_forms() {
        let key = SecretKey::random(&mut rand::rngs::OsRng).public_key();
        let point = key.to_sec1_bytes().to_vec();
        let mut wrapped = vec![0x04, 0x41];
        wrapped.extend_from_slice(&point);
        assert_eq!(ec_point_public_key(&wrapped).unwrap(), key);
        assert_eq!(ec_point_public_key(&point).unwrap(), key);
        assert!(ec_point_public_key(&wrapped[..66]).is_err());
        // A compressed point is not what the token is asked to hold.
        let compressed = p256::EncodedPoint::from(key).compress();
        assert!(ec_point_public_key(compressed.as_bytes()).is_err());
    }

    #[test]
    fn raw_signature_is_reencoded() {
        let key = SecretKey::random(&mut rand::rngs::OsRng);
        let signature: Signature = SigningKey::from(key.clone()).sign(b"tbs");
        let der = raw_signature_der(&signature.to_bytes()).unwrap();
        assert_eq!(der, signature.to_der().as_bytes());
        assert!(raw_signature_der(&signature.to_bytes()[..63]).is_err());
        assert!(raw_signature_der(&[0u8; 64]).is_err());
    }

    /// A SoftHSM2 token prepared by `tests/lab_signer_pkcs11.sh`, which runs
    /// these tests with `--ignored`.
    fn token_config(key_label: &str) -> Pkcs11Config {
        let get = |name: &str| {
            std::env::var(name).unwrap_or_else(|_| panic!("{name}: run tests/lab_signer_pkcs11.sh"))
        };
        Pkcs11Config {
            module: PathBuf::from(get("TRUST_TEST_PKCS11_MODULE")),
            token_label: get("TRUST_TEST_PKCS11_TOKEN"),
            key_label: key_label.to_owned(),
            pin: get("TRUST_TEST_PKCS11_PIN"),
        }
    }

    #[test]
    #[ignore = "needs a SoftHSM2 token: tests/lab_signer_pkcs11.sh"]
    fn token_key_is_generated_protected_and_signs() {
        let key = Pkcs11Key::open(&token_config("rust-test-ca")).unwrap();
        // No key yet under that label.
        assert!(matches!(key.public_key(), Err(Refusal::KeyFile)));
        let public = key.generate().unwrap();
        assert_eq!(key.public_key().unwrap(), public);
        // Never twice under one label.
        assert!(matches!(key.generate(), Err(Refusal::KeyExists)));
        // The private value cannot be read, nor wrapped out under a key the
        // caller controls.
        let session = key.session(true).unwrap();
        let private = key.private_key(&session).unwrap();
        if let Ok(read) = session.get_attributes(private, &[AttributeType::Value]) {
            assert!(read
                .iter()
                .all(|attribute| !matches!(attribute, Attribute::Value(_))));
        }
        let wrapping = session
            .generate_key(
                &Mechanism::AesKeyGen,
                &[
                    Attribute::Token(false),
                    Attribute::ValueLen(32.into()),
                    Attribute::Wrap(true),
                    Attribute::Encrypt(true),
                ],
            )
            .unwrap();
        assert!(session
            .wrap_key(&Mechanism::AesKeyWrapPad, wrapping, private)
            .is_err());
        drop(session);
        let der = key.sign_sha256(b"exact TBS bytes").unwrap();
        let signature = Signature::from_der(&der).unwrap();
        let verifier = VerifyingKey::from(&public);
        assert!(verifier.verify(b"exact TBS bytes", &signature).is_ok());
        assert!(verifier.verify(b"other bytes", &signature).is_err());
        // The SPKI the signer compares with the attested issuer key.
        assert_eq!(
            crate::spki_der(&key).unwrap(),
            crate::spki_der(&public_key_holder(public)).unwrap()
        );
    }

    struct PublicOnly(PublicKey);
    impl P256Key for PublicOnly {
        fn public_key(&self) -> Result<PublicKey, Refusal> {
            Ok(self.0)
        }
        fn sign_sha256(&self, _: &[u8]) -> Result<Vec<u8>, Refusal> {
            Err(Refusal::Token)
        }
    }
    fn public_key_holder(public: PublicKey) -> PublicOnly {
        PublicOnly(public)
    }

    #[test]
    #[ignore = "needs a SoftHSM2 token: tests/lab_signer_pkcs11.sh"]
    fn extractable_key_is_refused() {
        let config = token_config("rust-test-extractable");
        let key = Pkcs11Key::open(&config).unwrap();
        let session = key.session(true).unwrap();
        let label = config.key_label.as_bytes().to_vec();
        session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &[
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::EcParams(P256_EC_PARAMS.to_vec()),
                    Attribute::Label(label.clone()),
                ],
                &[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(false),
                    Attribute::Extractable(true),
                    Attribute::Sign(true),
                    Attribute::Label(label),
                ],
            )
            .unwrap();
        drop(session);
        assert!(matches!(key.public_key(), Err(Refusal::KeyNotProtected)));
        assert!(matches!(
            key.sign_sha256(b"tbs"),
            Err(Refusal::KeyNotProtected)
        ));
    }

    #[test]
    #[ignore = "needs a SoftHSM2 token: tests/lab_signer_pkcs11.sh"]
    fn wrong_pin_or_token_is_refused() {
        let mut config = token_config("rust-test-ca");
        config.token_label = "no-such-token".into();
        assert!(matches!(Pkcs11Key::open(&config), Err(Refusal::Token)));
        let mut config = token_config("rust-test-pin");
        config.pin = "not-the-pin".into();
        let key = Pkcs11Key::open(&config).unwrap();
        assert!(matches!(key.public_key(), Err(Refusal::Token)));
        assert!(matches!(key.sign_sha256(b"tbs"), Err(Refusal::Token)));
    }
}
