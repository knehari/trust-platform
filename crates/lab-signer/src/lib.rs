//! Laboratory signer for approved certificate applications (ADR-0017,
//! Proposed). It is the only process that reads a CA private key, and it is
//! never part of the API build.
//!
//! It signs a TBS only when, independently of the caller:
//! - the signing intent exists for its CA, is still signable (APPROVED
//!   application, ACTIVE CA, active profile revision, UNCONFIRMED intent in
//!   SIGNING) and was never claimed;
//! - the TBS digest is the durable intent's;
//! - its key file holds the key of the CA's registered issuer certificate;
//! - the stored CSR verifies again (proof of possession, exact CN) and its
//!   key is the application's;
//! - the TBS is exactly the server leaf the application allows
//!   (`trust_pki_core::application_leaf::check_server_leaf_tbs`);
//! - the database accepts its single claim of the intent.
//!
//! Only then does it sign, once. A compromised API therefore cannot use it
//! as a signing oracle, nor get one intent signed twice.

use std::time::SystemTime;

use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePrivateKey,
    SecretKey,
};
use sha2::{Digest, Sha256};
use trust_pki_core::{
    application_leaf::{check_server_leaf_tbs, LeafError, LeafFacts},
    csr::verify_pkcs10_p256,
};
use x509_cert::{
    der::{
        asn1::{BitString, ObjectIdentifier},
        Any, Decode, Encode,
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    Certificate, TbsCertificate,
};

/// Largest TBS the signer accepts.
pub const MAX_TBS_BYTES: usize = 16 * 1024;

/// What the signer's read-only view returns for an intent.
#[derive(Debug, Clone)]
pub struct IntentRecord {
    pub ca_id: String,
    pub tbs_sha256: Vec<u8>,
    pub serial: Vec<u8>,
    pub csr_der: Vec<u8>,
    pub spki_sha256: Vec<u8>,
    pub subject_cn: String,
    pub dns_names: Vec<String>,
    pub validity_days: i32,
    pub issuer_certificate_der: Vec<u8>,
    pub issuer_spki_sha256: Vec<u8>,
    pub signable: bool,
    pub claimed: bool,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Why the signer refused. Every refusal happens before any signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    BadRequest,
    UnknownIntent,
    OtherCa,
    NotSignable,
    AlreadyClaimed,
    TbsDigest,
    KeyFile,
    KeyNotTheCa,
    Csr,
    Tbs(LeafError),
    ClaimRefused,
    Database,
}

impl Refusal {
    pub fn code(&self) -> String {
        match self {
            Refusal::Tbs(error) => format!("Tbs{error:?}"),
            other => format!("{other:?}"),
        }
    }
}

/// The signer's access to the database: read one intent, claim it once.
pub trait IntentStore {
    fn intent(&mut self, intent_id: &str) -> Result<Option<IntentRecord>, Refusal>;
    fn claim(&mut self, intent_id: &str, tbs_sha256: &[u8]) -> Result<(), Refusal>;
}

/// The DER SubjectPublicKeyInfo of a P-256 key, named-curve form, as in the
/// registered issuer certificate.
pub fn spki_der(key: &SecretKey) -> Result<Vec<u8>, Refusal> {
    let point = key.public_key().to_encoded_point(false);
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: Some(Any::from(ObjectIdentifier::new_unwrap(
                "1.2.840.10045.3.1.7",
            ))),
        },
        subject_public_key: BitString::from_bytes(point.as_bytes())
            .map_err(|_| Refusal::KeyFile)?,
    }
    .to_der()
    .map_err(|_| Refusal::KeyFile)
}

/// Reads a P-256 key from PEM: SEC1 (`EC PRIVATE KEY`, as `openssl ecparam
/// -genkey` writes) or PKCS#8.
pub fn parse_key_pem(pem: &str) -> Result<SecretKey, Refusal> {
    SecretKey::from_sec1_pem(pem)
        .or_else(|_| SecretKey::from_pkcs8_pem(pem))
        .map_err(|_| Refusal::KeyFile)
}

/// Decides and, when everything holds, signs `tbs_der` for `intent_id`.
pub fn sign_intent<S: IntentStore>(
    store: &mut S,
    ca_id: &str,
    key: &SecretKey,
    intent_id: &str,
    tbs_der: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, Refusal> {
    if tbs_der.is_empty() || tbs_der.len() > MAX_TBS_BYTES {
        return Err(Refusal::BadRequest);
    }
    let record = store.intent(intent_id)?.ok_or(Refusal::UnknownIntent)?;
    if record.ca_id != ca_id {
        return Err(Refusal::OtherCa);
    }
    if record.claimed {
        return Err(Refusal::AlreadyClaimed);
    }
    if !record.signable {
        return Err(Refusal::NotSignable);
    }
    if sha256(tbs_der)[..] != record.tbs_sha256[..] {
        return Err(Refusal::TbsDigest);
    }
    // The key must be the one the approvers attested for this CA.
    if sha256(&spki_der(key)?)[..] != record.issuer_spki_sha256[..] {
        return Err(Refusal::KeyNotTheCa);
    }
    let issuer =
        Certificate::from_der(&record.issuer_certificate_der).map_err(|_| Refusal::Database)?;
    if sha256(
        &issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| Refusal::Database)?,
    )[..]
        != record.issuer_spki_sha256[..]
    {
        return Err(Refusal::KeyNotTheCa);
    }
    // The CSR again: proof of possession and the exact approved CN.
    let csr = verify_pkcs10_p256(&record.csr_der, &record.subject_cn).map_err(|_| Refusal::Csr)?;
    if sha256(
        &csr.subject_public_key()
            .to_der()
            .map_err(|_| Refusal::Csr)?,
    )[..]
        != record.spki_sha256[..]
    {
        return Err(Refusal::Csr);
    }
    let tbs = TbsCertificate::from_der(tbs_der).map_err(|_| Refusal::BadRequest)?;
    if tbs.to_der().map_err(|_| Refusal::BadRequest)? != tbs_der {
        return Err(Refusal::BadRequest);
    }
    let validity_days = u32::try_from(record.validity_days).map_err(|_| Refusal::Database)?;
    let facts = LeafFacts {
        subject_cn: &record.subject_cn,
        dns_names: &record.dns_names,
        subject_public_key: csr.subject_public_key(),
        validity_days,
        serial: &record.serial,
    };
    check_server_leaf_tbs(&issuer, &facts, &tbs, now).map_err(Refusal::Tbs)?;
    // The database records the single claim; a second one is refused.
    store.claim(intent_id, &record.tbs_sha256)?;
    let signature: Signature = SigningKey::from(key.clone()).sign(tbs_der);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// The signer process: PostgreSQL access and the Unix socket protocol.
pub mod service {
    use std::{
        error::Error,
        fs,
        io::{self, BufRead, BufReader, Write},
        os::unix::net::{UnixListener, UnixStream},
        path::PathBuf,
        time::{Duration, SystemTime},
    };

    use base64::{engine::general_purpose::STANDARD, Engine};
    use postgres::{Client, NoTls};
    use serde::Deserialize;

    use crate::{parse_key_pem, sign_intent, IntentRecord, IntentStore, Refusal};

    const MAX_REQUEST_BYTES: u64 = 64 * 1024;

    pub struct PgIntentStore<'a> {
        pub db: &'a mut Client,
    }

    impl IntentStore for PgIntentStore<'_> {
        fn intent(&mut self, intent_id: &str) -> Result<Option<IntentRecord>, Refusal> {
            let row = self
                .db
                .query_opt(
                    "SELECT ca_id, tbs_sha256, serial, csr_der, spki_sha256, subject_cn, dns_names, \
                     validity_days, issuer_certificate_der, issuer_spki_sha256, signable, claimed \
                     FROM lab_signer_intent WHERE intent_id = $1",
                    &[&intent_id],
                )
                .map_err(|_| Refusal::Database)?;
            Ok(row.map(|row| IntentRecord {
                ca_id: row.get(0),
                tbs_sha256: row.get(1),
                serial: row.get(2),
                csr_der: row.get(3),
                spki_sha256: row.get(4),
                subject_cn: row.get(5),
                dns_names: row.get(6),
                validity_days: row.get(7),
                issuer_certificate_der: row.get(8),
                issuer_spki_sha256: row.get(9),
                signable: row.get(10),
                claimed: row.get(11),
            }))
        }

        fn claim(&mut self, intent_id: &str, tbs_sha256: &[u8]) -> Result<(), Refusal> {
            self.db
                .execute(
                    "SELECT claim_lab_signing_intent($1::text::uuid, $2)",
                    &[&intent_id, &tbs_sha256],
                )
                .map(|_| ())
                .map_err(|_| Refusal::ClaimRefused)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SignRequest {
        intent_id: String,
        tbs_der_base64: String,
    }

    pub struct Config {
        pub database_url: String,
        pub ca_id: String,
        pub key_file: PathBuf,
    }

    pub fn log(value: serde_json::Value) {
        // Never logs keys, TBS bytes or signatures.
        let _ = writeln!(io::stderr().lock(), "{value}");
    }

    /// Answers one request on one connection.
    pub fn handle(config: &Config, stream: UnixStream) -> io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut line = String::new();
        BufReader::new(io::Read::take(&stream, MAX_REQUEST_BYTES)).read_line(&mut line)?;
        let outcome = answer(config, &line);
        let (reply, intent) = match &outcome {
            Ok((intent, signature)) => (
                serde_json::json!({"signature_der_base64": STANDARD.encode(signature)}),
                intent.clone(),
            ),
            Err((intent, refusal)) => {
                (serde_json::json!({"error": refusal.code()}), intent.clone())
            }
        };
        log(serde_json::json!({
            "event": "lab_signer_request", "intent_id": intent,
            "outcome": outcome.as_ref().map(|_| "signed".to_owned()).unwrap_or_else(|(_, r)| r.code()),
        }));
        let mut writer = &stream;
        writeln!(writer, "{reply}")
    }

    fn answer(config: &Config, line: &str) -> Result<(String, Vec<u8>), (String, Refusal)> {
        let request: SignRequest =
            serde_json::from_str(line.trim()).map_err(|_| (String::new(), Refusal::BadRequest))?;
        let intent = request.intent_id.clone();
        let fail = |refusal| (intent.clone(), refusal);
        let tbs = STANDARD
            .decode(request.tbs_der_base64.trim())
            .map_err(|_| fail(Refusal::BadRequest))?;
        let pem = fs::read_to_string(&config.key_file).map_err(|_| fail(Refusal::KeyFile))?;
        let key = parse_key_pem(&pem).map_err(fail)?;
        let mut db =
            Client::connect(&config.database_url, NoTls).map_err(|_| fail(Refusal::Database))?;
        let mut store = PgIntentStore { db: &mut db };
        let signature = sign_intent(
            &mut store,
            &config.ca_id,
            &key,
            &request.intent_id,
            &tbs,
            SystemTime::now(),
        )
        .map_err(fail)?;
        Ok((intent, signature))
    }

    /// The login must hold `trust_lab_signer` and read no table directly.
    pub fn restricted_login(url: &str) -> Result<bool, Box<dyn Error>> {
        let mut db = Client::connect(url, NoTls)?;
        Ok(db
            .query_one(
                "SELECT pg_has_role(current_user, 'trust_lab_signer', 'member') \
                 AND management_application_issuance_version() = 1 \
                 AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = current_user \
                     AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb)) \
                 AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'm', 'f') \
                     AND has_table_privilege(current_user, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'))",
                &[],
            )?
            .get(0))
    }

    /// Serves requests one at a time until the listener fails.
    pub fn serve(config: &Config, listener: &UnixListener) {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(error) = handle(config, stream) {
                        log(
                            serde_json::json!({"event": "lab_signer_io_error", "kind": format!("{:?}", error.kind())}),
                        );
                    }
                }
                Err(error) => log(
                    serde_json::json!({"event": "lab_signer_accept_error", "kind": format!("{:?}", error.kind())}),
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;
    use trust_pki_core::application_leaf::build_server_leaf_tbs;
    use x509_cert::{
        der::asn1::OctetString,
        ext::{pkix::BasicConstraints, Extension},
        name::Name,
        request::{CertReq, CertReqInfo, Version as ReqVersion},
        serial_number::SerialNumber,
        time::Validity,
        Version,
    };

    struct FakeStore {
        record: Option<IntentRecord>,
        claims: Vec<String>,
        refuse_claim: bool,
    }

    impl IntentStore for FakeStore {
        fn intent(&mut self, intent_id: &str) -> Result<Option<IntentRecord>, Refusal> {
            Ok(self
                .record
                .clone()
                .filter(|_| intent_id == "intent-1")
                .map(|mut record| {
                    record.claimed = self.claims.iter().any(|claim| claim == intent_id);
                    record
                }))
        }
        fn claim(&mut self, intent_id: &str, _tbs_sha256: &[u8]) -> Result<(), Refusal> {
            if self.refuse_claim || self.claims.iter().any(|claim| claim == intent_id) {
                return Err(Refusal::ClaimRefused);
            }
            self.claims.push(intent_id.to_owned());
            Ok(())
        }
    }

    fn ecdsa() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        }
    }

    fn spki(key: &SecretKey) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_der(&spki_der(key).unwrap()).unwrap()
    }

    /// A self-signed CA root for `key`, like scripts/lab/create-lab-root.sh.
    fn root(key: &SecretKey) -> Certificate {
        let name = Name::from_str("CN=Test Issuing CA").unwrap();
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1]).unwrap(),
            signature: ecdsa(),
            issuer: name.clone(),
            validity: Validity::from_now(Duration::from_secs(365 * 86400)).unwrap(),
            subject: name,
            subject_public_key_info: spki(key),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![Extension {
                extn_id: ObjectIdentifier::new_unwrap("2.5.29.19"),
                critical: true,
                extn_value: OctetString::new(
                    BasicConstraints {
                        ca: true,
                        path_len_constraint: None,
                    }
                    .to_der()
                    .unwrap(),
                )
                .unwrap(),
            }]),
        };
        let signature: Signature = SigningKey::from(key.clone()).sign(&tbs.to_der().unwrap());
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: ecdsa(),
            signature: BitString::from_bytes(signature.to_der().as_bytes()).unwrap(),
        }
    }

    fn csr(cn: &str, key: &SecretKey) -> Vec<u8> {
        let info = CertReqInfo {
            version: ReqVersion::V1,
            subject: Name::from_str(&format!("CN={cn}")).unwrap(),
            public_key: spki(key),
            attributes: Default::default(),
        };
        let signature: Signature = SigningKey::from(key.clone()).sign(&info.to_der().unwrap());
        CertReq {
            info,
            algorithm: ecdsa(),
            signature: BitString::from_bytes(signature.to_der().as_bytes()).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    struct Fixture {
        ca_key: SecretKey,
        store: FakeStore,
        tbs_der: Vec<u8>,
        issuer: Certificate,
    }

    fn fixture() -> Fixture {
        let ca_key = SecretKey::random(&mut rand::rngs::OsRng);
        let subject_key = SecretKey::random(&mut rand::rngs::OsRng);
        let issuer = root(&ca_key);
        let names = vec!["www.lab.invalid".to_owned(), "api.lab.invalid".to_owned()];
        let csr_der = csr("www.lab.invalid", &subject_key);
        let subject_spki = spki(&subject_key);
        let facts = LeafFacts {
            subject_cn: "www.lab.invalid",
            dns_names: &names,
            subject_public_key: &subject_spki,
            validity_days: 30,
            serial: &[0x55, 0x01],
        };
        let tbs_der = build_server_leaf_tbs(&issuer, &facts, SystemTime::now())
            .unwrap()
            .to_der()
            .unwrap();
        let record = IntentRecord {
            ca_id: "ca-1".into(),
            tbs_sha256: Sha256::digest(&tbs_der).to_vec(),
            serial: vec![0x55, 0x01],
            csr_der,
            spki_sha256: Sha256::digest(subject_spki.to_der().unwrap()).to_vec(),
            subject_cn: "www.lab.invalid".into(),
            dns_names: names,
            validity_days: 30,
            issuer_certificate_der: issuer.to_der().unwrap(),
            issuer_spki_sha256: Sha256::digest(spki_der(&ca_key).unwrap()).to_vec(),
            signable: true,
            claimed: false,
        };
        Fixture {
            ca_key,
            store: FakeStore {
                record: Some(record),
                claims: vec![],
                refuse_claim: false,
            },
            tbs_der,
            issuer,
        }
    }

    fn sign(f: &mut Fixture) -> Result<Vec<u8>, Refusal> {
        let key = f.ca_key.clone();
        let tbs = f.tbs_der.clone();
        sign_intent(
            &mut f.store,
            "ca-1",
            &key,
            "intent-1",
            &tbs,
            SystemTime::now(),
        )
    }

    #[test]
    fn signs_a_valid_intent_once_with_a_signature_the_issuer_key_verifies() {
        let mut f = fixture();
        let signature = sign(&mut f).unwrap();
        let point = f
            .issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap();
        assert!(trust_pki_crypto_verify(point, &f.tbs_der, &signature));
        assert_eq!(sign(&mut f).unwrap_err(), Refusal::AlreadyClaimed);
    }

    fn trust_pki_crypto_verify(point: &[u8], message: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::{signature::Verifier, VerifyingKey};
        let key = VerifyingKey::from_sec1_bytes(point).unwrap();
        key.verify(message, &Signature::from_der(signature).unwrap())
            .is_ok()
    }

    #[test]
    fn every_independent_check_refuses_before_any_claim() {
        let edit = |change: &dyn Fn(&mut Fixture)| {
            let mut f = fixture();
            change(&mut f);
            let result = sign(&mut f);
            assert!(
                f.store.claims.is_empty(),
                "a refused request claimed the intent"
            );
            result.unwrap_err()
        };
        assert_eq!(edit(&|f| f.store.record = None), Refusal::UnknownIntent);
        assert_eq!(
            edit(&|f| f.store.record.as_mut().unwrap().ca_id = "ca-2".into()),
            Refusal::OtherCa
        );
        assert_eq!(
            edit(&|f| f.store.record.as_mut().unwrap().signable = false),
            Refusal::NotSignable
        );
        assert_eq!(edit(&|f| f.tbs_der.push(0)), Refusal::TbsDigest);
        assert_eq!(
            edit(&|f| f.ca_key = SecretKey::random(&mut rand::rngs::OsRng)),
            Refusal::KeyNotTheCa
        );
        assert_eq!(
            edit(&|f| f.store.record.as_mut().unwrap().subject_cn = "api.lab.invalid".into()),
            Refusal::Csr
        );
        assert_eq!(
            edit(&|f| f.store.record.as_mut().unwrap().spki_sha256 = vec![0; 32]),
            Refusal::Csr
        );
        // The TBS digest matches a forged intent, but the TBS is not the
        // application's leaf: other names, other serial.
        assert_eq!(
            edit(&|f| f
                .store
                .record
                .as_mut()
                .unwrap()
                .dns_names
                .push("evil.lab.invalid".into())),
            Refusal::Tbs(LeafError::Extensions)
        );
        assert_eq!(
            edit(&|f| f.store.record.as_mut().unwrap().serial = vec![0x55, 0x02]),
            Refusal::Tbs(LeafError::Serial)
        );
        assert_eq!(
            edit(&|f| f.store.record.as_mut().unwrap().validity_days = 31),
            Refusal::Tbs(LeafError::Validity)
        );
    }

    #[test]
    fn a_refused_claim_means_no_signature() {
        let mut f = fixture();
        f.store.refuse_claim = true;
        assert_eq!(sign(&mut f).unwrap_err(), Refusal::ClaimRefused);
    }

    #[test]
    fn keys_load_from_openssl_style_pem() {
        let key = SecretKey::random(&mut rand::rngs::OsRng);
        let sec1 = key.to_sec1_pem(p256::pkcs8::LineEnding::LF).unwrap();
        assert_eq!(parse_key_pem(&sec1).unwrap().to_bytes(), key.to_bytes());
        assert_eq!(
            parse_key_pem("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----")
                .unwrap_err(),
            Refusal::KeyFile
        );
    }
}
