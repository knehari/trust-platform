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
//!
//! CRLs (ADR-0018, Proposed) follow the same rule: the CRL intent exists for
//! its CA, is journaled, is the CA's latest and was never claimed; the TBS
//! digest is the intent's; the key is the CA's; the TBS is exactly the CRL
//! the database's own revocation entries describe
//! (`trust_pki_core::application_crl::check_crl_tbs`); then one claim.

use std::time::SystemTime;

pub mod audit;

use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePrivateKey,
    SecretKey,
};
use sha2::{Digest, Sha256};
use trust_pki_core::{
    application_crl::{check_crl_tbs, parse_utc_seconds, CrlEntry, CrlError, CrlFacts},
    application_leaf::{check_server_leaf_tbs, optional_extensions_valid, LeafError, LeafFacts},
    authorization::{
        officer_decision_claim, revocation_decision_claim, void_confirmation_claim,
        OfficerDecision, RevocationDecision, VoidConfirmation,
    },
    csr::verify_pkcs10_p256_possession,
    ra_request::{
        ra_issuance_message, ra_issuance_message_v2, ra_revocation_message, RaIssuanceRequest,
        RaIssuanceRequestV2, RaRevocationRequest,
    },
};
use x509_cert::{
    crl::TbsCertList,
    der::{
        asn1::{BitString, ObjectIdentifier},
        Any, Decode, Encode,
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    Certificate, TbsCertificate,
};

/// Largest TBS the signer accepts.
pub const MAX_TBS_BYTES: usize = 16 * 1024;
/// Largest CRL TBS the signer accepts.
pub const MAX_CRL_TBS_BYTES: usize = 512 * 1024;

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
    /// The CRL distribution point snapshotted with the intent (migration 0032).
    pub crl_distribution_point: Option<String>,
}

/// An RA's signed request (migrations 0038 and 0041).
#[derive(Debug, Clone)]
pub struct RaProof {
    pub ra_id: String,
    pub request_id: String,
    /// 1, or 2 when the RA set the subject and optional extensions.
    pub version: i16,
    pub signed_at_unix: i64,
    pub signature: Vec<u8>,
    pub public_key_sec1: Vec<u8>,
    pub enabled: bool,
}

/// A registration officer's signed decision (migration 0041).
#[derive(Debug, Clone)]
pub struct OfficerProof {
    pub decision: String,
    pub key_id: String,
    pub issued_at: String,
    pub signature: Vec<u8>,
    pub public_key_sec1: Vec<u8>,
    pub key_active: bool,
}

/// What `lab_signer_authorization` returns for an intent: the facts the
/// proof covers beyond the intent record, and the proof itself.
#[derive(Debug, Clone)]
pub struct AuthorizationRecord {
    pub application_id: String,
    pub profile_id: String,
    pub revision: i32,
    pub optional_extensions: Vec<String>,
    pub ra: Option<RaProof>,
    pub officer: Option<OfficerProof>,
}

/// Lowercase hyphenated UUID text to its 16 bytes.
fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if text.len() != 36 || hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn signed_by(public_key_sec1: &[u8], message: &[u8], signature_der: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(public_key_sec1),
        Signature::from_der(signature_der),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

/// Checks that a key the API cannot register signed exactly these facts
/// (ADR-0028): an enabled RA's request, or an active officer's approval. The
/// signed bytes are rebuilt here from the intent's facts, so a database row
/// claiming an approval proves nothing by itself.
pub fn verify_authorization(
    record: &IntentRecord,
    authorization: &AuthorizationRecord,
) -> Result<(), Refusal> {
    if !optional_extensions_valid(&authorization.optional_extensions) {
        return Err(Refusal::Unauthorized);
    }
    let csr_sha256 = sha256(&record.csr_der);
    match (&authorization.ra, &authorization.officer) {
        (Some(ra), None) => {
            if !ra.enabled {
                return Err(Refusal::Unauthorized);
            }
            let (Some(ca_id), Some(request_id), Ok(validity_days)) = (
                uuid_bytes(&record.ca_id),
                uuid_bytes(&ra.request_id),
                u32::try_from(record.validity_days),
            ) else {
                return Err(Refusal::Unauthorized);
            };
            let base = RaIssuanceRequest {
                ra_id: &ra.ra_id,
                ca_id,
                profile_id: &authorization.profile_id,
                request_id,
                csr_sha256,
                dns_names: &record.dns_names,
                validity_days,
                signed_at_unix: ra.signed_at_unix,
            };
            let message = match ra.version {
                // Version 1: the subject is the first name, and no extension.
                1 if record.dns_names.first() == Some(&record.subject_cn)
                    && authorization.optional_extensions.is_empty() =>
                {
                    ra_issuance_message(&base)
                }
                2 => ra_issuance_message_v2(&RaIssuanceRequestV2 {
                    base,
                    subject_cn: &record.subject_cn,
                    extensions: &authorization.optional_extensions,
                }),
                _ => return Err(Refusal::Unauthorized),
            }
            .map_err(|_| Refusal::Unauthorized)?;
            if !signed_by(&ra.public_key_sec1, &message, &ra.signature) {
                return Err(Refusal::AuthorizationSignature);
            }
            Ok(())
        }
        (None, Some(officer)) => {
            if officer.decision != "approve" || !officer.key_active {
                return Err(Refusal::Unauthorized);
            }
            let claim = officer_decision_claim(&OfficerDecision {
                decision: &officer.decision,
                ca_id: &record.ca_id,
                application_id: &authorization.application_id,
                profile_id: &authorization.profile_id,
                revision: authorization.revision,
                csr_sha256: &csr_sha256,
                subject_cn: &record.subject_cn,
                dns_names: &record.dns_names,
                validity_days: record.validity_days,
                extensions: &authorization.optional_extensions,
                key_id: &officer.key_id,
                issued_at: &officer.issued_at,
            })
            .map_err(|_| Refusal::Unauthorized)?;
            if !signed_by(
                &officer.public_key_sec1,
                claim.as_bytes(),
                &officer.signature,
            ) {
                return Err(Refusal::AuthorizationSignature);
            }
            Ok(())
        }
        // No proof, or two: never signed.
        _ => Err(Refusal::Unauthorized),
    }
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
    Crl(CrlError),
    ClaimRefused,
    Database,
    /// No acceptable authorization proof for the intent (ADR-0028).
    Unauthorized,
    /// A proof whose signature does not verify with the registered key.
    AuthorizationSignature,
    /// Audit checkpoints (ADR-0023): no audit key or state file configured.
    AuditNotConfigured,
    AuditKeyFile,
    /// The audit key is a CA key; the two roles never share a key.
    AuditKeyIsCaKey,
    /// The state file names another audit key.
    AuditKeyChanged,
    /// The state file is unreadable or damaged; never treated as absent.
    AuditStateFile,
    /// The database no longer holds the last checkpoint this signer signed.
    AuditRollback,
    /// A link or event does not recompute.
    AuditChain,
    /// A stored checkpoint is not this key's signature over the chain.
    AuditCheckpointSignature,
}

impl Refusal {
    pub fn code(&self) -> String {
        match self {
            Refusal::Tbs(error) => format!("Tbs{error:?}"),
            Refusal::Crl(error) => format!("Crl{error:?}"),
            other => format!("{other:?}"),
        }
    }
}

/// The signer's access to the database: read one intent, claim it once.
pub trait IntentStore {
    fn intent(&mut self, intent_id: &str) -> Result<Option<IntentRecord>, Refusal>;
    fn authorization(&mut self, intent_id: &str) -> Result<Option<AuthorizationRecord>, Refusal>;
    fn claim(&mut self, intent_id: &str, tbs_sha256: &[u8]) -> Result<(), Refusal>;
}

/// What the signer's read-only views return for a CRL intent.
#[derive(Debug, Clone)]
pub struct CrlIntentRecord {
    pub ca_id: String,
    pub crl_number: i64,
    pub tbs_sha256: Option<Vec<u8>>,
    pub this_update: String,
    pub next_update: String,
    pub issuer_certificate_der: Vec<u8>,
    pub issuer_spki_sha256: Vec<u8>,
    pub signable: bool,
    pub claimed: bool,
    /// Serial, revocation instant (`YYYY-MM-DDTHH:MM:SSZ`) and reason code.
    pub entries: Vec<(Vec<u8>, String, i16)>,
}

/// The proof of one CRL entry, from `lab_signer_crl_entry_proof` (migration
/// 0042, ADR-0029).
#[derive(Debug, Clone)]
pub struct EntryProof {
    /// `revocation` or `void`.
    pub kind: String,
    pub serial: Vec<u8>,
    pub revoked_at: String,
    pub reason_code: i16,
    /// Recorded before proofs were required: listed without one.
    pub legacy: bool,
    pub ca_id: String,
    pub application_id: Option<String>,
    pub revocation_id: Option<String>,
    /// An RA's signed revocation.
    pub ra: Option<RaRevocationProof>,
    /// An officer's signed approval or void confirmation.
    pub officer: Option<EntryOfficerProof>,
    pub void_signer_claimed: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct RaRevocationProof {
    pub ra_id: String,
    pub request_id: String,
    pub reason: String,
    pub signed_at_unix: i64,
    pub signature: Vec<u8>,
    pub public_key_sec1: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EntryOfficerProof {
    pub decision: String,
    pub key_id: String,
    pub issued_at: String,
    pub signature: Vec<u8>,
    pub public_key_sec1: Vec<u8>,
    /// The key was active when the claim was issued. A key revoked later
    /// still covers what it signed: a CRL never drops a revocation.
    pub key_valid: bool,
}

/// Checks that every entry the CRL will list is backed by a signature of a key
/// the API cannot register (ADR-0029): an RA's signed revocation, an officer's
/// signed revocation approval, or the confirming officer's signed void. The
/// signed bytes are rebuilt from the entry's facts.
pub fn verify_entry_proofs(
    entries: &[(Vec<u8>, String, i16)],
    proofs: &[EntryProof],
) -> Result<(), Refusal> {
    let mut listed: Vec<(&[u8], &str, i16)> = entries
        .iter()
        .map(|(serial, at, reason)| (serial.as_slice(), at.as_str(), *reason))
        .collect();
    let mut proven: Vec<(&[u8], &str, i16)> = proofs
        .iter()
        .map(|proof| {
            (
                proof.serial.as_slice(),
                proof.revoked_at.as_str(),
                proof.reason_code,
            )
        })
        .collect();
    listed.sort_unstable();
    proven.sort_unstable();
    if listed != proven {
        return Err(Refusal::Unauthorized);
    }
    for proof in proofs {
        if !proof.legacy {
            verify_entry_proof(proof)?;
        }
    }
    Ok(())
}

fn verify_entry_proof(proof: &EntryProof) -> Result<(), Refusal> {
    match (proof.kind.as_str(), &proof.ra, &proof.officer) {
        ("revocation", Some(ra), None) => {
            let (Some(ca_id), Some(request_id), Ok(reason_code)) = (
                uuid_bytes(&proof.ca_id),
                uuid_bytes(&ra.request_id),
                u16::try_from(proof.reason_code),
            ) else {
                return Err(Refusal::Unauthorized);
            };
            let message = ra_revocation_message(&RaRevocationRequest {
                ra_id: &ra.ra_id,
                ca_id,
                request_id,
                serial: &proof.serial,
                reason_code,
                reason: &ra.reason,
                signed_at_unix: ra.signed_at_unix,
            })
            .map_err(|_| Refusal::Unauthorized)?;
            if !signed_by(&ra.public_key_sec1, &message, &ra.signature) {
                return Err(Refusal::AuthorizationSignature);
            }
            Ok(())
        }
        ("revocation", None, Some(officer)) => {
            let (Some(application_id), Some(revocation_id)) =
                (&proof.application_id, &proof.revocation_id)
            else {
                return Err(Refusal::Unauthorized);
            };
            if officer.decision != "approve" || !officer.key_valid {
                return Err(Refusal::Unauthorized);
            }
            let claim = revocation_decision_claim(&RevocationDecision {
                decision: &officer.decision,
                ca_id: &proof.ca_id,
                application_id,
                revocation_id,
                serial: &proof.serial,
                reason_code: proof.reason_code,
                key_id: &officer.key_id,
                issued_at: &officer.issued_at,
            })
            .map_err(|_| Refusal::Unauthorized)?;
            if !signed_by(
                &officer.public_key_sec1,
                claim.as_bytes(),
                &officer.signature,
            ) {
                return Err(Refusal::AuthorizationSignature);
            }
            Ok(())
        }
        ("void", None, Some(officer)) => {
            let (Some(application_id), Some(signer_claimed)) =
                (&proof.application_id, proof.void_signer_claimed)
            else {
                return Err(Refusal::Unauthorized);
            };
            if proof.reason_code != 0 || !officer.key_valid {
                return Err(Refusal::Unauthorized);
            }
            let claim = void_confirmation_claim(&VoidConfirmation {
                ca_id: &proof.ca_id,
                application_id,
                serial: &proof.serial,
                signer_claimed,
                key_id: &officer.key_id,
                issued_at: &officer.issued_at,
            })
            .map_err(|_| Refusal::Unauthorized)?;
            if !signed_by(
                &officer.public_key_sec1,
                claim.as_bytes(),
                &officer.signature,
            ) {
                return Err(Refusal::AuthorizationSignature);
            }
            Ok(())
        }
        // No proof, both, or an unknown kind: never listed by this signer.
        _ => Err(Refusal::Unauthorized),
    }
}

/// The signer's access for CRLs: read one intent and its entries, claim it.
pub trait CrlStore {
    fn crl_intent(&mut self, intent_id: &str) -> Result<Option<CrlIntentRecord>, Refusal>;
    fn crl_entry_proofs(&mut self, intent_id: &str) -> Result<Vec<EntryProof>, Refusal>;
    fn claim_crl(&mut self, intent_id: &str, tbs_sha256: &[u8]) -> Result<(), Refusal>;
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

/// The CA's registered issuer certificate, once the key is shown to be the
/// one the approvers attested for this CA.
fn ca_issuer(
    key: &SecretKey,
    issuer_certificate_der: &[u8],
    issuer_spki_sha256: &[u8],
) -> Result<Certificate, Refusal> {
    if sha256(&spki_der(key)?)[..] != issuer_spki_sha256[..] {
        return Err(Refusal::KeyNotTheCa);
    }
    let issuer = Certificate::from_der(issuer_certificate_der).map_err(|_| Refusal::Database)?;
    if sha256(
        &issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| Refusal::Database)?,
    )[..]
        != issuer_spki_sha256[..]
    {
        return Err(Refusal::KeyNotTheCa);
    }
    Ok(issuer)
}

/// Decides and, when everything holds, signs the CRL `tbs_der` for the CRL
/// intent `intent_id`.
pub fn sign_crl_intent<S: CrlStore>(
    store: &mut S,
    ca_id: &str,
    key: &SecretKey,
    intent_id: &str,
    tbs_der: &[u8],
) -> Result<Vec<u8>, Refusal> {
    if tbs_der.is_empty() || tbs_der.len() > MAX_CRL_TBS_BYTES {
        return Err(Refusal::BadRequest);
    }
    let record = store.crl_intent(intent_id)?.ok_or(Refusal::UnknownIntent)?;
    if record.ca_id != ca_id {
        return Err(Refusal::OtherCa);
    }
    if record.claimed {
        return Err(Refusal::AlreadyClaimed);
    }
    if !record.signable {
        return Err(Refusal::NotSignable);
    }
    if record.tbs_sha256.as_deref() != Some(&sha256(tbs_der)[..]) {
        return Err(Refusal::TbsDigest);
    }
    let issuer = ca_issuer(
        key,
        &record.issuer_certificate_der,
        &record.issuer_spki_sha256,
    )?;
    let tbs = TbsCertList::from_der(tbs_der).map_err(|_| Refusal::BadRequest)?;
    if tbs.to_der().map_err(|_| Refusal::BadRequest)? != tbs_der {
        return Err(Refusal::BadRequest);
    }
    let entries = record
        .entries
        .iter()
        .map(|(serial, revoked_at, reason)| {
            Ok(CrlEntry {
                serial: serial.clone(),
                revoked_at: parse_utc_seconds(revoked_at).map_err(Refusal::Crl)?,
                reason_code: u8::try_from(*reason).map_err(|_| Refusal::Database)?,
            })
        })
        .collect::<Result<Vec<_>, Refusal>>()?;
    let facts = CrlFacts {
        crl_number: u64::try_from(record.crl_number).map_err(|_| Refusal::Database)?,
        this_update: parse_utc_seconds(&record.this_update).map_err(Refusal::Crl)?,
        next_update: parse_utc_seconds(&record.next_update).map_err(Refusal::Crl)?,
        entries: &entries,
    };
    check_crl_tbs(&issuer, &facts, &tbs).map_err(Refusal::Crl)?;
    // Every entry is backed by a key the API cannot register.
    verify_entry_proofs(&record.entries, &store.crl_entry_proofs(intent_id)?)?;
    store.claim_crl(intent_id, &sha256(tbs_der))?;
    let signature: Signature = SigningKey::from(key.clone()).sign(tbs_der);
    Ok(signature.to_der().as_bytes().to_vec())
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
    let issuer = ca_issuer(
        key,
        &record.issuer_certificate_der,
        &record.issuer_spki_sha256,
    )?;
    // The CSR again: proof of possession of the key. Its subject is not the
    // certificate's: the authorization below binds the subject (ADR-0028).
    let csr = verify_pkcs10_p256_possession(&record.csr_der).map_err(|_| Refusal::Csr)?;
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
    let authorization = store
        .authorization(intent_id)?
        .ok_or(Refusal::Unauthorized)?;
    let facts = LeafFacts {
        subject_cn: &record.subject_cn,
        dns_names: &record.dns_names,
        subject_public_key: csr.subject_public_key(),
        validity_days,
        serial: &record.serial,
        crl_distribution_point: record.crl_distribution_point.as_deref(),
        client_auth: authorization
            .optional_extensions
            .iter()
            .any(|extension| extension == "client-auth"),
    };
    check_server_leaf_tbs(&issuer, &facts, &tbs, now).map_err(Refusal::Tbs)?;
    // A key the API cannot register signed these exact facts.
    verify_authorization(&record, &authorization)?;
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
    use postgres::Client;
    use serde::Deserialize;

    use crate::{
        audit::{
            decode_state, encode_state, hex, sign_audit_checkpoint, AuditLink, AuditStore,
            CheckpointState, LinkEvent, StoredCheckpoint,
        },
        parse_key_pem, sign_crl_intent, sign_intent, spki_der, AuthorizationRecord,
        CrlIntentRecord, CrlStore, EntryOfficerProof, EntryProof, IntentRecord, IntentStore,
        OfficerProof, RaProof, RaRevocationProof, Refusal,
    };

    const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

    pub struct PgIntentStore<'a> {
        pub db: &'a mut Client,
    }

    impl IntentStore for PgIntentStore<'_> {
        fn intent(&mut self, intent_id: &str) -> Result<Option<IntentRecord>, Refusal> {
            let row = self
                .db
                .query_opt(
                    "SELECT ca_id, tbs_sha256, serial, csr_der, spki_sha256, subject_cn, dns_names, \
                     validity_days, issuer_certificate_der, issuer_spki_sha256, signable, claimed, \
                     crl_distribution_point FROM lab_signer_intent WHERE intent_id = $1",
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
                crl_distribution_point: row.get(12),
            }))
        }

        fn authorization(
            &mut self,
            intent_id: &str,
        ) -> Result<Option<AuthorizationRecord>, Refusal> {
            let row = self
                .db
                .query_opt(
                    "SELECT application_id, profile_id, revision, optional_extensions, ra_id, \
                     ra_request_id, ra_message_version, ra_signed_at, ra_signature, ra_public_key, \
                     ra_enabled, officer_decision, officer_key_id, officer_issued_at, \
                     officer_signature, officer_public_key, officer_key_active \
                     FROM lab_signer_authorization WHERE intent_id = $1",
                    &[&intent_id],
                )
                .map_err(|_| Refusal::Database)?;
            Ok(row.map(|row| AuthorizationRecord {
                application_id: row.get(0),
                profile_id: row.get(1),
                revision: row.get(2),
                optional_extensions: row.get(3),
                ra: row.get::<_, Option<String>>(4).map(|ra_id| RaProof {
                    ra_id,
                    request_id: row.get(5),
                    version: row.get(6),
                    signed_at_unix: row.get(7),
                    signature: row.get(8),
                    public_key_sec1: row.get(9),
                    enabled: row.get(10),
                }),
                officer: row
                    .get::<_, Option<String>>(11)
                    .map(|decision| OfficerProof {
                        decision,
                        key_id: row.get(12),
                        issued_at: row.get(13),
                        signature: row.get(14),
                        public_key_sec1: row.get(15),
                        key_active: row.get(16),
                    }),
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

    impl CrlStore for PgIntentStore<'_> {
        fn crl_intent(&mut self, intent_id: &str) -> Result<Option<CrlIntentRecord>, Refusal> {
            let Some(row) = self
                .db
                .query_opt(
                    "SELECT ca_id, crl_number, tbs_sha256, this_update, next_update, \
                     issuer_certificate_der, issuer_spki_sha256, signable, claimed \
                     FROM lab_signer_crl_intent WHERE intent_id = $1",
                    &[&intent_id],
                )
                .map_err(|_| Refusal::Database)?
            else {
                return Ok(None);
            };
            let entries = self
                .db
                .query(
                    "SELECT serial, revoked_at, reason_code FROM lab_signer_crl_entry \
                     WHERE intent_id = $1 ORDER BY serial",
                    &[&intent_id],
                )
                .map_err(|_| Refusal::Database)?
                .into_iter()
                .map(|entry| (entry.get(0), entry.get(1), entry.get(2)))
                .collect();
            Ok(Some(CrlIntentRecord {
                ca_id: row.get(0),
                crl_number: row.get(1),
                tbs_sha256: row.get(2),
                this_update: row.get(3),
                next_update: row.get(4),
                issuer_certificate_der: row.get(5),
                issuer_spki_sha256: row.get(6),
                signable: row.get(7),
                claimed: row.get(8),
                entries,
            }))
        }

        fn crl_entry_proofs(&mut self, intent_id: &str) -> Result<Vec<EntryProof>, Refusal> {
            Ok(self
                .db
                .query(
                    "SELECT kind, serial, revoked_at, reason_code, legacy, ca_id, application_id, \
                     revocation_id, ra_id, ra_request_id, ra_reason, ra_signed_at, ra_signature, \
                     ra_public_key, officer_decision, officer_key_id, officer_issued_at, \
                     officer_signature, officer_public_key, officer_key_valid, void_signer_claimed \
                     FROM lab_signer_crl_entry_proof WHERE intent_id = $1",
                    &[&intent_id],
                )
                .map_err(|_| Refusal::Database)?
                .into_iter()
                .map(|row| EntryProof {
                    kind: row.get(0),
                    serial: row.get(1),
                    revoked_at: row.get(2),
                    reason_code: row.get(3),
                    legacy: row.get(4),
                    ca_id: row.get(5),
                    application_id: row.get(6),
                    revocation_id: row.get(7),
                    ra: row
                        .get::<_, Option<String>>(8)
                        .map(|ra_id| RaRevocationProof {
                            ra_id,
                            request_id: row.get(9),
                            reason: row.get(10),
                            signed_at_unix: row.get(11),
                            signature: row.get(12),
                            public_key_sec1: row.get(13),
                        }),
                    officer: row
                        .get::<_, Option<String>>(14)
                        .map(|decision| EntryOfficerProof {
                            decision,
                            key_id: row.get(15),
                            issued_at: row.get(16),
                            signature: row.get(17),
                            public_key_sec1: row.get(18),
                            key_valid: row.get(19),
                        }),
                    void_signer_claimed: row.get(20),
                })
                .collect())
        }

        fn claim_crl(&mut self, intent_id: &str, tbs_sha256: &[u8]) -> Result<(), Refusal> {
            self.db
                .execute(
                    "SELECT claim_lab_crl_intent($1::text::uuid, $2)",
                    &[&intent_id, &tbs_sha256],
                )
                .map(|_| ())
                .map_err(|_| Refusal::ClaimRefused)
        }
    }

    impl AuditStore for PgIntentStore<'_> {
        fn latest_checkpoint(&mut self) -> Result<Option<StoredCheckpoint>, Refusal> {
            Ok(self
                .db
                .query_opt(
                    "SELECT seq, chain_hash, key_id, signed_at_unix, signature \
                     FROM lab_signer_audit_checkpoint_latest()",
                    &[],
                )
                .map_err(|_| Refusal::Database)?
                .map(|row| StoredCheckpoint {
                    seq: row.get(0),
                    chain_hash: row.get(1),
                    key_id: row.get(2),
                    signed_at_unix: row.get(3),
                    signature: row.get(4),
                }))
        }

        fn links(&mut self, after: u64, max: i32) -> Result<Vec<AuditLink>, Refusal> {
            let after = i64::try_from(after).map_err(|_| Refusal::AuditChain)?;
            Ok(self
                .db
                .query(
                    "SELECT seq, event_sha256, previous_hash, chain_hash, event_id, ca_id, request_id, \
                     actor_id, event_type, decision, policy_version, recorded_at_micros \
                     FROM lab_signer_audit_links($1, $2)",
                    &[&after, &max],
                )
                .map_err(|_| Refusal::Database)?
                .into_iter()
                .map(|row| AuditLink {
                    seq: row.get(0),
                    event_sha256: row.get(1),
                    previous_hash: row.get(2),
                    chain_hash: row.get(3),
                    event: row.get::<_, Option<Vec<u8>>>(4).map(|event_id| LinkEvent {
                        event_id,
                        ca_id: row.get(5),
                        request_id: row.get(6),
                        actor_id: row.get(7),
                        event_type: row.get(8),
                        decision: row.get(9),
                        policy_version: row.get(10),
                        recorded_at_micros: row.get(11),
                    }),
                })
                .collect())
        }

        fn record_checkpoint(
            &mut self,
            seq: u64,
            chain_hash: &[u8; 32],
            key_id: &[u8; 32],
            signed_at_unix: i64,
            signature: &[u8],
        ) -> Result<(), Refusal> {
            let seq = i64::try_from(seq).map_err(|_| Refusal::AuditChain)?;
            self.db
                .execute(
                    "SELECT lab_signer_record_audit_checkpoint($1, $2, $3, $4, $5)",
                    &[
                        &seq,
                        &chain_hash.as_slice(),
                        &key_id.as_slice(),
                        &signed_at_unix,
                        &signature,
                    ],
                )
                .map(|_| ())
                .map_err(|_| Refusal::Database)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SignRequest {
        /// `certificate` (the default), `crl` or `audit_checkpoint`.
        #[serde(default)]
        kind: Option<String>,
        /// Required for `certificate` and `crl`; absent for `audit_checkpoint`.
        #[serde(default)]
        intent_id: Option<String>,
        #[serde(default)]
        tbs_der_base64: Option<String>,
    }

    pub struct Config {
        pub database_url: String,
        pub ca_id: String,
        pub key_file: PathBuf,
        /// The P-256 audit key (ADR-0023); without it, checkpoints are refused.
        pub audit_key_file: Option<PathBuf>,
        /// Where the signer remembers its last checkpoint, outside the database.
        pub audit_state_file: Option<PathBuf>,
    }

    fn read_state(path: &std::path::Path) -> Result<Option<CheckpointState>, Refusal> {
        match fs::read_to_string(path) {
            Ok(text) => decode_state(&text).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Refusal::AuditStateFile),
        }
    }

    /// Written to a temporary file, flushed, then renamed over the state.
    fn write_state(path: &std::path::Path, state: &CheckpointState) -> Result<(), Refusal> {
        let temporary = path.with_extension("tmp");
        let write = || -> io::Result<()> {
            let mut file = fs::File::create(&temporary)?;
            file.write_all(encode_state(state).as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, path)
        };
        write().map_err(|_| Refusal::AuditStateFile)
    }

    /// One checkpoint request: verify the chain after the remembered state,
    /// sign its head with the audit key, record it, then remember it.
    fn checkpoint(config: &Config) -> Result<serde_json::Value, Refusal> {
        let (Some(key_file), Some(state_file)) = (&config.audit_key_file, &config.audit_state_file)
        else {
            return Err(Refusal::AuditNotConfigured);
        };
        let pem = fs::read_to_string(key_file).map_err(|_| Refusal::AuditKeyFile)?;
        let key = parse_key_pem(&pem).map_err(|_| Refusal::AuditKeyFile)?;
        // Never the CA key (when the CA key exists yet).
        if let Ok(ca_pem) = fs::read_to_string(&config.key_file) {
            if let Ok(ca_key) = parse_key_pem(&ca_pem) {
                if spki_der(&ca_key)? == spki_der(&key).map_err(|_| Refusal::AuditKeyFile)? {
                    return Err(Refusal::AuditKeyIsCaKey);
                }
            }
        }
        let state = read_state(state_file)?;
        let mut db =
            trust_db_connect::connect(&config.database_url).map_err(|_| Refusal::Database)?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| Refusal::Database)?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| Refusal::Database)?;
        let outcome = sign_audit_checkpoint(
            &mut PgIntentStore { db: &mut db },
            &key,
            state.as_ref(),
            now,
        )?;
        if outcome.state.seq > 0 && state.as_ref() != Some(&outcome.state) {
            write_state(state_file, &outcome.state)?;
        }
        Ok(serde_json::json!({
            "checkpoint_seq": outcome.state.seq,
            "chain_hash_hex": hex(&outcome.state.chain_hash),
            "signed": outcome.signed,
        }))
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
            Ok((intent, reply)) => (reply.clone(), intent.clone()),
            Err((intent, refusal)) => {
                (serde_json::json!({"error": refusal.code()}), intent.clone())
            }
        };
        log(serde_json::json!({
            "event": "lab_signer_request", "intent_id": intent,
            "outcome": outcome.as_ref().map(|_| "signed".to_owned()).unwrap_or_else(|(_, r)| r.code()),
            // Only sequence numbers for checkpoints; never keys or signatures.
            "checkpoint_seq": reply.get("checkpoint_seq"),
        }));
        let mut writer = &stream;
        writeln!(writer, "{reply}")
    }

    fn answer(
        config: &Config,
        line: &str,
    ) -> Result<(String, serde_json::Value), (String, Refusal)> {
        let request: SignRequest =
            serde_json::from_str(line.trim()).map_err(|_| (String::new(), Refusal::BadRequest))?;
        if request.kind.as_deref() == Some("audit_checkpoint") {
            if request.intent_id.is_some() || request.tbs_der_base64.is_some() {
                return Err((String::new(), Refusal::BadRequest));
            }
            return checkpoint(config)
                .map(|reply| (String::new(), reply))
                .map_err(|refusal| (String::new(), refusal));
        }
        let (Some(intent_id), Some(tbs_der_base64)) = (request.intent_id, request.tbs_der_base64)
        else {
            return Err((String::new(), Refusal::BadRequest));
        };
        let intent = intent_id.clone();
        let fail = |refusal| (intent.clone(), refusal);
        let tbs = STANDARD
            .decode(tbs_der_base64.trim())
            .map_err(|_| fail(Refusal::BadRequest))?;
        let pem = fs::read_to_string(&config.key_file).map_err(|_| fail(Refusal::KeyFile))?;
        let key = parse_key_pem(&pem).map_err(fail)?;
        let mut db =
            trust_db_connect::connect(&config.database_url).map_err(|_| fail(Refusal::Database))?;
        let mut store = PgIntentStore { db: &mut db };
        let signature = match request.kind.as_deref() {
            None | Some("certificate") => sign_intent(
                &mut store,
                &config.ca_id,
                &key,
                &intent_id,
                &tbs,
                SystemTime::now(),
            ),
            Some("crl") => sign_crl_intent(&mut store, &config.ca_id, &key, &intent_id, &tbs),
            Some(_) => Err(Refusal::BadRequest),
        }
        .map_err(fail)?;
        Ok((
            intent,
            serde_json::json!({"signature_der_base64": STANDARD.encode(signature)}),
        ))
    }

    /// The login must hold `trust_lab_signer` and read no table directly.
    pub fn restricted_login(url: &str) -> Result<bool, Box<dyn Error>> {
        let mut db = trust_db_connect::connect(url)?;
        Ok(db
            .query_one(
                "SELECT pg_has_role(current_user, 'trust_lab_signer', 'member') \
                 AND management_application_issuance_version() = 1 \
                 AND management_revocation_crl_version() = 1 \
                 AND management_crl_publication_version() = 1 \
                 AND management_audit_checkpoint_version() = 1 \
                 AND management_authorization_proofs_version() = 1 \
                 AND management_revocation_proofs_version() = 1 \
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
        authorization: Option<AuthorizationRecord>,
        claims: Vec<String>,
        refuse_claim: bool,
    }

    const CA: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const APPLICATION: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const RA_REQUEST: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

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
        fn authorization(
            &mut self,
            intent_id: &str,
        ) -> Result<Option<AuthorizationRecord>, Refusal> {
            Ok(self
                .authorization
                .clone()
                .filter(|_| intent_id == "intent-1"))
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
        officer_key: SecretKey,
    }

    fn sign_der(key: &SecretKey, message: &[u8]) -> Vec<u8> {
        let signature: Signature = SigningKey::from(key.clone()).sign(message);
        signature.to_der().as_bytes().to_vec()
    }

    fn public_sec1(key: &SecretKey) -> Vec<u8> {
        key.public_key().to_sec1_bytes().to_vec()
    }

    impl Fixture {
        fn authorization(&mut self) -> &mut AuthorizationRecord {
            self.store.authorization.as_mut().unwrap()
        }
        fn officer(&mut self) -> &mut OfficerProof {
            self.authorization().officer.as_mut().unwrap()
        }
        /// Signs the officer claim again over the current facts, with `key`.
        fn officer_signs(&mut self, key: &SecretKey) {
            let record = self.store.record.clone().unwrap();
            let authorization = self.store.authorization.clone().unwrap();
            let officer = authorization.officer.clone().unwrap();
            let claim = officer_decision_claim(&OfficerDecision {
                decision: &officer.decision,
                ca_id: &record.ca_id,
                application_id: &authorization.application_id,
                profile_id: &authorization.profile_id,
                revision: authorization.revision,
                csr_sha256: &sha256(&record.csr_der),
                subject_cn: &record.subject_cn,
                dns_names: &record.dns_names,
                validity_days: record.validity_days,
                extensions: &authorization.optional_extensions,
                key_id: &officer.key_id,
                issued_at: &officer.issued_at,
            })
            .unwrap();
            self.officer().signature = sign_der(key, claim.as_bytes());
        }
        /// Replaces the officer's approval by an RA request of `version`.
        fn ra_signs(&mut self, version: i16, key: &SecretKey) {
            let record = self.store.record.clone().unwrap();
            let authorization = self.authorization();
            authorization.officer = None;
            let base = RaIssuanceRequest {
                ra_id: "lab-ra",
                ca_id: uuid_bytes(CA).unwrap(),
                profile_id: &authorization.profile_id,
                request_id: uuid_bytes(RA_REQUEST).unwrap(),
                csr_sha256: sha256(&record.csr_der),
                dns_names: &record.dns_names,
                validity_days: 30,
                signed_at_unix: 1_790_000_000,
            };
            let message = if version == 1 {
                ra_issuance_message(&base)
            } else {
                ra_issuance_message_v2(&RaIssuanceRequestV2 {
                    base,
                    subject_cn: &record.subject_cn,
                    extensions: &authorization.optional_extensions,
                })
            }
            .unwrap();
            authorization.ra = Some(RaProof {
                ra_id: "lab-ra".into(),
                request_id: RA_REQUEST.into(),
                version,
                signed_at_unix: 1_790_000_000,
                signature: sign_der(key, &message),
                public_key_sec1: public_sec1(key),
                enabled: true,
            });
        }
    }

    fn fixture() -> Fixture {
        fixture_with("www.lab.invalid", "www.lab.invalid", &[])
    }

    /// A signable intent for `subject_cn`, from a CSR whose subject is
    /// `csr_cn`, approved by an officer with `extensions`.
    fn fixture_with(csr_cn: &str, subject_cn: &str, extensions: &[&str]) -> Fixture {
        let ca_key = SecretKey::random(&mut rand::rngs::OsRng);
        let subject_key = SecretKey::random(&mut rand::rngs::OsRng);
        let officer_key = SecretKey::random(&mut rand::rngs::OsRng);
        let issuer = root(&ca_key);
        let names = vec!["www.lab.invalid".to_owned(), "api.lab.invalid".to_owned()];
        let csr_der = csr(csr_cn, &subject_key);
        let subject_spki = spki(&subject_key);
        let extensions: Vec<String> = extensions.iter().map(|e| (*e).to_owned()).collect();
        let facts = LeafFacts {
            subject_cn,
            dns_names: &names,
            subject_public_key: &subject_spki,
            validity_days: 30,
            serial: &[0x55, 0x01],
            crl_distribution_point: None,
            client_auth: extensions.iter().any(|e| e == "client-auth"),
        };
        let tbs_der = build_server_leaf_tbs(&issuer, &facts, SystemTime::now())
            .unwrap()
            .to_der()
            .unwrap();
        let record = IntentRecord {
            ca_id: CA.into(),
            tbs_sha256: Sha256::digest(&tbs_der).to_vec(),
            serial: vec![0x55, 0x01],
            csr_der,
            spki_sha256: Sha256::digest(subject_spki.to_der().unwrap()).to_vec(),
            subject_cn: subject_cn.into(),
            dns_names: names,
            validity_days: 30,
            issuer_certificate_der: issuer.to_der().unwrap(),
            issuer_spki_sha256: Sha256::digest(spki_der(&ca_key).unwrap()).to_vec(),
            signable: true,
            claimed: false,
            crl_distribution_point: None,
        };
        let mut fixture = Fixture {
            ca_key,
            store: FakeStore {
                record: Some(record),
                authorization: Some(AuthorizationRecord {
                    application_id: APPLICATION.into(),
                    profile_id: "tls-server".into(),
                    revision: 1,
                    optional_extensions: extensions,
                    ra: None,
                    officer: Some(OfficerProof {
                        decision: "approve".into(),
                        key_id: "lab-ra-officer".into(),
                        issued_at: "2026-11-11T10:00:00.000Z".into(),
                        signature: vec![],
                        public_key_sec1: public_sec1(&officer_key),
                        key_active: true,
                    }),
                }),
                claims: vec![],
                refuse_claim: false,
            },
            tbs_der,
            issuer,
            officer_key: officer_key.clone(),
        };
        fixture.officer_signs(&officer_key);
        fixture
    }

    fn sign(f: &mut Fixture) -> Result<Vec<u8>, Refusal> {
        let key = f.ca_key.clone();
        let tbs = f.tbs_der.clone();
        sign_intent(&mut f.store, CA, &key, "intent-1", &tbs, SystemTime::now())
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
        // The subject is no longer the CSR's (ADR-0028): a forged subject
        // fails on the TBS, and the authorization covers it anyway.
        assert_eq!(
            edit(&|f| f.store.record.as_mut().unwrap().subject_cn = "api.lab.invalid".into()),
            Refusal::Tbs(LeafError::Subject)
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
        // The intent was journaled under a CRL distribution point the TBS
        // does not carry.
        assert_eq!(
            edit(
                &|f| f.store.record.as_mut().unwrap().crl_distribution_point =
                    Some("http://crl.lab.invalid/latest.crl".into())
            ),
            Refusal::Tbs(LeafError::Extensions)
        );
    }

    #[test]
    fn the_authorization_proof_is_verified_before_any_claim() {
        let refused = |change: &dyn Fn(&mut Fixture)| {
            let mut f = fixture();
            change(&mut f);
            let result = sign(&mut f);
            assert!(
                f.store.claims.is_empty(),
                "a refused request claimed the intent"
            );
            result.unwrap_err()
        };
        let other = SecretKey::random(&mut rand::rngs::OsRng);
        // No proof, or a row naming an approval nobody signed.
        assert_eq!(
            refused(&|f| f.store.authorization = None),
            Refusal::Unauthorized
        );
        assert_eq!(
            refused(&|f| f.authorization().officer = None),
            Refusal::Unauthorized
        );
        assert_eq!(
            refused(&|f| f.officer().signature = vec![]),
            Refusal::AuthorizationSignature
        );
        // Signed by a key other than the registered one.
        assert_eq!(
            refused(&|f| f.officer_signs(&other)),
            Refusal::AuthorizationSignature
        );
        // A revoked officer key, or a rejection.
        assert_eq!(
            refused(&|f| f.officer().key_active = false),
            Refusal::Unauthorized
        );
        assert_eq!(
            refused(&|f| {
                f.officer().decision = "reject".into();
                let key = f.officer_key.clone();
                f.officer_signs(&key);
            }),
            Refusal::Unauthorized
        );
        // The officer signed other facts: another profile revision, or
        // another instant than the one recorded.
        assert_eq!(
            refused(&|f| f.authorization().revision = 2),
            Refusal::AuthorizationSignature
        );
        assert_eq!(
            refused(&|f| f.officer().issued_at = "2026-11-11T10:00:01.000Z".into()),
            Refusal::AuthorizationSignature
        );
        // Two proofs at once, or an RA that was disabled.
        assert_eq!(
            refused(&|f| {
                let officer = f.authorization().officer.clone();
                f.ra_signs(2, &SecretKey::random(&mut rand::rngs::OsRng));
                f.authorization().officer = officer;
            }),
            Refusal::Unauthorized
        );
        assert_eq!(
            refused(&|f| {
                f.ra_signs(2, &SecretKey::random(&mut rand::rngs::OsRng));
                f.authorization().ra.as_mut().unwrap().enabled = false;
            }),
            Refusal::Unauthorized
        );
        // An extension outside the catalogue never reaches the signature.
        assert_eq!(
            refused(&|f| f.authorization().optional_extensions = vec!["code-signing".into()]),
            Refusal::Unauthorized
        );
        // The extension is authorized but the TBS does not carry it.
        assert_eq!(
            refused(&|f| {
                f.authorization().optional_extensions = vec!["client-auth".into()];
                let key = f.officer_key.clone();
                f.officer_signs(&key);
            }),
            Refusal::Tbs(LeafError::Extensions)
        );
    }

    #[test]
    fn an_ra_request_authorizes_in_v1_and_v2() {
        let ra_key = SecretKey::random(&mut rand::rngs::OsRng);
        for version in [1, 2] {
            let mut f = fixture();
            f.ra_signs(version, &ra_key);
            assert!(sign(&mut f).is_ok(), "version {version}");
        }
        // Another RA key, or a request altered after signing.
        let mut f = fixture();
        f.ra_signs(2, &ra_key);
        f.authorization().ra.as_mut().unwrap().public_key_sec1 =
            public_sec1(&SecretKey::random(&mut rand::rngs::OsRng));
        assert_eq!(sign(&mut f).unwrap_err(), Refusal::AuthorizationSignature);
        let mut f = fixture();
        f.ra_signs(2, &ra_key);
        f.authorization().ra.as_mut().unwrap().signed_at_unix += 1;
        assert_eq!(sign(&mut f).unwrap_err(), Refusal::AuthorizationSignature);
        assert!(f.store.claims.is_empty());
    }

    #[test]
    fn the_ra_may_correct_the_subject_and_add_client_auth() {
        let ra_key = SecretKey::random(&mut rand::rngs::OsRng);
        // The CSR says "typo.lab.invalid"; the certificate's subject is the
        // one the RA signed in a v2 request, with client authentication.
        let mut f = fixture_with("typo.lab.invalid", "www.lab.invalid", &["client-auth"]);
        f.ra_signs(2, &ra_key);
        assert!(sign(&mut f).is_ok());
        // A v1 request cannot: it binds neither the subject nor an extension.
        let mut f = fixture_with("typo.lab.invalid", "www.lab.invalid", &["client-auth"]);
        f.ra_signs(1, &ra_key);
        assert_eq!(sign(&mut f).unwrap_err(), Refusal::Unauthorized);
        let mut f = fixture_with("www.lab.invalid", "api.lab.invalid", &[]);
        f.ra_signs(1, &ra_key);
        assert_eq!(sign(&mut f).unwrap_err(), Refusal::Unauthorized);
        // An officer approval binds them as well.
        let mut f = fixture_with("typo.lab.invalid", "www.lab.invalid", &["client-auth"]);
        assert!(sign(&mut f).is_ok());
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

    struct FakeCrlStore {
        record: Option<CrlIntentRecord>,
        proofs: Vec<EntryProof>,
        claims: Vec<String>,
    }

    impl CrlStore for FakeCrlStore {
        fn crl_intent(&mut self, intent_id: &str) -> Result<Option<CrlIntentRecord>, Refusal> {
            Ok(self
                .record
                .clone()
                .filter(|_| intent_id == "crl-1")
                .map(|mut record| {
                    record.claimed = self.claims.iter().any(|claim| claim == intent_id);
                    record
                }))
        }
        fn crl_entry_proofs(&mut self, intent_id: &str) -> Result<Vec<EntryProof>, Refusal> {
            Ok(if intent_id == "crl-1" {
                self.proofs.clone()
            } else {
                vec![]
            })
        }
        fn claim_crl(&mut self, intent_id: &str, _tbs_sha256: &[u8]) -> Result<(), Refusal> {
            if self.claims.iter().any(|claim| claim == intent_id) {
                return Err(Refusal::ClaimRefused);
            }
            self.claims.push(intent_id.to_owned());
            Ok(())
        }
    }

    struct CrlFixture {
        ca_key: SecretKey,
        store: FakeCrlStore,
        tbs_der: Vec<u8>,
        issuer: Certificate,
        officer_key: SecretKey,
    }

    const REVOCATION: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    /// An officer's signed approval of the revocation of `serial`.
    fn revocation_proof(
        key: &SecretKey,
        serial: &[u8],
        revoked_at: &str,
        reason_code: i16,
    ) -> EntryProof {
        let issued_at = "2026-11-07T09:59:00.000Z";
        let claim = revocation_decision_claim(&RevocationDecision {
            decision: "approve",
            ca_id: CA,
            application_id: APPLICATION,
            revocation_id: REVOCATION,
            serial,
            reason_code,
            key_id: "officer-1",
            issued_at,
        })
        .unwrap();
        EntryProof {
            kind: "revocation".into(),
            serial: serial.to_vec(),
            revoked_at: revoked_at.into(),
            reason_code,
            legacy: false,
            ca_id: CA.into(),
            application_id: Some(APPLICATION.into()),
            revocation_id: Some(REVOCATION.into()),
            ra: None,
            officer: Some(EntryOfficerProof {
                decision: "approve".into(),
                key_id: "officer-1".into(),
                issued_at: issued_at.into(),
                signature: sign_der(key, claim.as_bytes()),
                public_key_sec1: public_sec1(key),
                key_valid: true,
            }),
            void_signer_claimed: None,
        }
    }

    /// The confirming officer's signed void of `serial`.
    fn void_proof(key: &SecretKey, serial: &[u8], voided_at: &str) -> EntryProof {
        let issued_at = "2026-11-07T10:59:00.000Z";
        let claim = void_confirmation_claim(&VoidConfirmation {
            ca_id: CA,
            application_id: APPLICATION,
            serial,
            signer_claimed: true,
            key_id: "officer-2",
            issued_at,
        })
        .unwrap();
        EntryProof {
            kind: "void".into(),
            serial: serial.to_vec(),
            revoked_at: voided_at.into(),
            reason_code: 0,
            legacy: false,
            ca_id: CA.into(),
            application_id: Some(APPLICATION.into()),
            revocation_id: None,
            ra: None,
            officer: Some(EntryOfficerProof {
                decision: "approve".into(),
                key_id: "officer-2".into(),
                issued_at: issued_at.into(),
                signature: sign_der(key, claim.as_bytes()),
                public_key_sec1: public_sec1(key),
                key_valid: true,
            }),
            void_signer_claimed: Some(true),
        }
    }

    fn crl_fixture() -> CrlFixture {
        use trust_pki_core::application_crl::build_crl_tbs;
        let ca_key = SecretKey::random(&mut rand::rngs::OsRng);
        let issuer = root(&ca_key);
        let at = |text: &str| parse_utc_seconds(text).unwrap();
        let entries = vec![
            (vec![0x41, 0x01], "2026-11-07T10:00:00Z".to_owned(), 1i16),
            (vec![0x42, 0x02], "2026-11-07T11:00:00Z".to_owned(), 0i16),
        ];
        let crl_entries: Vec<CrlEntry> = entries
            .iter()
            .map(|(serial, revoked_at, reason)| CrlEntry {
                serial: serial.clone(),
                revoked_at: at(revoked_at),
                reason_code: *reason as u8,
            })
            .collect();
        let tbs_der = build_crl_tbs(
            &issuer,
            &CrlFacts {
                crl_number: 3,
                this_update: at("2026-11-08T00:00:00Z"),
                next_update: at("2026-11-15T00:00:00Z"),
                entries: &crl_entries,
            },
        )
        .unwrap()
        .to_der()
        .unwrap();
        let officer_key = SecretKey::random(&mut rand::rngs::OsRng);
        let proofs = vec![
            revocation_proof(&officer_key, &[0x41, 0x01], "2026-11-07T10:00:00Z", 1),
            void_proof(&officer_key, &[0x42, 0x02], "2026-11-07T11:00:00Z"),
        ];
        let record = CrlIntentRecord {
            ca_id: CA.into(),
            crl_number: 3,
            tbs_sha256: Some(Sha256::digest(&tbs_der).to_vec()),
            this_update: "2026-11-08T00:00:00Z".into(),
            next_update: "2026-11-15T00:00:00Z".into(),
            issuer_certificate_der: issuer.to_der().unwrap(),
            issuer_spki_sha256: Sha256::digest(spki_der(&ca_key).unwrap()).to_vec(),
            signable: true,
            claimed: false,
            entries,
        };
        CrlFixture {
            ca_key,
            store: FakeCrlStore {
                record: Some(record),
                proofs,
                claims: vec![],
            },
            tbs_der,
            issuer,
            officer_key,
        }
    }

    fn record(f: &mut CrlFixture) -> &mut CrlIntentRecord {
        f.store.record.as_mut().unwrap()
    }

    fn sign_crl(f: &mut CrlFixture) -> Result<Vec<u8>, Refusal> {
        let key = f.ca_key.clone();
        let tbs = f.tbs_der.clone();
        sign_crl_intent(&mut f.store, CA, &key, "crl-1", &tbs)
    }

    #[test]
    fn every_crl_entry_needs_a_signed_proof_before_any_claim() {
        let refused = |change: &dyn Fn(&mut CrlFixture)| {
            let mut f = crl_fixture();
            change(&mut f);
            let result = sign_crl(&mut f);
            assert!(
                f.store.claims.is_empty(),
                "a refused CRL request claimed the intent"
            );
            result.unwrap_err()
        };
        let other = SecretKey::random(&mut rand::rngs::OsRng);
        // An entry without a proof, or a proof for nothing listed.
        assert_eq!(
            refused(&|f| {
                f.store.proofs.pop();
            }),
            Refusal::Unauthorized
        );
        assert_eq!(
            refused(&|f| {
                let key = f.officer_key.clone();
                f.store
                    .proofs
                    .push(void_proof(&key, &[0x43], "2026-11-07T12:00:00Z"));
            }),
            Refusal::Unauthorized
        );
        // Signed by another key, or for another reason or serial.
        assert_eq!(
            refused(&|f| f.store.proofs[0] =
                revocation_proof(&other, &[0x41, 0x01], "2026-11-07T10:00:00Z", 1)
                    .with_key(&f.officer_key)),
            Refusal::AuthorizationSignature
        );
        assert_eq!(
            refused(&|f| f.store.proofs[0].officer.as_mut().unwrap().issued_at =
                "2026-11-07T09:59:01.000Z".into()),
            Refusal::AuthorizationSignature
        );
        assert_eq!(
            refused(&|f| f.store.proofs[1].void_signer_claimed = Some(false)),
            Refusal::AuthorizationSignature
        );
        // A rejection, a key not active when it signed, no officer at all.
        assert_eq!(
            refused(&|f| f.store.proofs[0].officer.as_mut().unwrap().decision = "reject".into()),
            Refusal::Unauthorized
        );
        assert_eq!(
            refused(&|f| f.store.proofs[1].officer.as_mut().unwrap().key_valid = false),
            Refusal::Unauthorized
        );
        assert_eq!(
            refused(&|f| f.store.proofs[0].officer = None),
            Refusal::Unauthorized
        );
        // A void listed with a reason code.
        assert_eq!(
            refused(&|f| f.store.proofs[1].kind = "revocation".into()),
            Refusal::Unauthorized
        );
    }

    impl EntryProof {
        /// The same proof, claiming to be signed by `key`'s public key.
        fn with_key(mut self, key: &SecretKey) -> Self {
            self.officer.as_mut().unwrap().public_key_sec1 = public_sec1(key);
            self
        }
    }

    #[test]
    fn legacy_entries_and_ra_revocations_are_listed() {
        // Recorded before proofs were required: listed without one.
        let mut f = crl_fixture();
        f.store.proofs[0].officer = None;
        f.store.proofs[0].legacy = true;
        assert!(sign_crl(&mut f).is_ok());
        // An RA's signed revocation, checked with the RA's key.
        let ra_key = SecretKey::random(&mut rand::rngs::OsRng);
        let ra = |reason: &str| {
            let message = ra_revocation_message(&RaRevocationRequest {
                ra_id: "lab-ra",
                ca_id: uuid_bytes(CA).unwrap(),
                request_id: uuid_bytes(RA_REQUEST).unwrap(),
                serial: &[0x41, 0x01],
                reason_code: 1,
                reason,
                signed_at_unix: 1_794_000_000,
            })
            .unwrap();
            RaRevocationProof {
                ra_id: "lab-ra".into(),
                request_id: RA_REQUEST.into(),
                reason: "key compromise".into(),
                signed_at_unix: 1_794_000_000,
                signature: sign_der(&ra_key, &message),
                public_key_sec1: public_sec1(&ra_key),
            }
        };
        let mut f = crl_fixture();
        f.store.proofs[0].officer = None;
        f.store.proofs[0].ra = Some(ra("key compromise"));
        assert!(sign_crl(&mut f).is_ok());
        let mut f = crl_fixture();
        f.store.proofs[0].officer = None;
        f.store.proofs[0].ra = Some(ra("another reason"));
        assert_eq!(
            sign_crl(&mut f).unwrap_err(),
            Refusal::AuthorizationSignature
        );
        assert!(f.store.claims.is_empty());
    }

    #[test]
    fn signs_a_crl_intent_once_under_the_issuer_key() {
        let mut f = crl_fixture();
        let signature = sign_crl(&mut f).unwrap();
        let point = f
            .issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap();
        assert!(trust_pki_crypto_verify(point, &f.tbs_der, &signature));
        assert_eq!(sign_crl(&mut f).unwrap_err(), Refusal::AlreadyClaimed);
    }

    #[test]
    fn every_crl_check_refuses_before_any_claim() {
        let edit = |change: &dyn Fn(&mut CrlFixture)| {
            let mut f = crl_fixture();
            change(&mut f);
            let result = sign_crl(&mut f);
            assert!(
                f.store.claims.is_empty(),
                "a refused CRL request claimed the intent"
            );
            result.unwrap_err()
        };
        assert_eq!(edit(&|f| f.store.record = None), Refusal::UnknownIntent);
        assert_eq!(edit(&|f| record(f).ca_id = "ca-2".into()), Refusal::OtherCa);
        assert_eq!(edit(&|f| record(f).signable = false), Refusal::NotSignable);
        assert_eq!(edit(&|f| record(f).tbs_sha256 = None), Refusal::TbsDigest);
        assert_eq!(edit(&|f| f.tbs_der.push(0)), Refusal::TbsDigest);
        assert_eq!(
            edit(&|f| f.ca_key = SecretKey::random(&mut rand::rngs::OsRng)),
            Refusal::KeyNotTheCa
        );
        // The digest is the intent's, but the TBS is not what the database's
        // entries, number or instants describe.
        assert_eq!(
            edit(&|f| {
                record(f).entries.pop();
            }),
            Refusal::Crl(CrlError::Mismatch)
        );
        assert_eq!(
            edit(&|f| record(f).entries[0].2 = 4),
            Refusal::Crl(CrlError::Mismatch)
        );
        assert_eq!(
            edit(&|f| record(f).crl_number = 4),
            Refusal::Crl(CrlError::Mismatch)
        );
        assert_eq!(
            edit(&|f| record(f).next_update = "2026-11-16T00:00:00Z".into()),
            Refusal::Crl(CrlError::Mismatch)
        );
        assert_eq!(
            edit(&|f| record(f).this_update = "2026-11-08 00:00:00".into()),
            Refusal::Crl(CrlError::Times)
        );
        assert_eq!(
            edit(&|f| record(f).entries[1].2 = 2),
            Refusal::Crl(CrlError::Reason)
        );
        // A certificate TBS presented as a CRL is not even parsed as one.
        assert_eq!(
            edit(&|f| {
                f.tbs_der = fixture().tbs_der;
                record(f).tbs_sha256 = Some(Sha256::digest(&f.tbs_der).to_vec());
            }),
            Refusal::BadRequest
        );
    }
}
