//! CRL v2 (RFC 5280 section 5) TBSCertList builder and independent lab verifier.
//!
//! Lab only. The builder produces the exact TBS bytes that are journaled
//! before signing; the verifier re-parses the finished CRL, requires
//! canonical DER, rebuilds the expected TBS from the reservation and checks
//! the ECDSA P-256/SHA-256 signature with the issuer certificate's key.
//! Nothing here is a production CRL publication path.

use crate::revocation::RevocationReason;
use crate::serial::SerialNumber;
use sha2::{Digest, Sha256};
use x509_cert::{
    crl::{RevokedCert, TbsCertList},
    der::{
        asn1::{GeneralizedTime, ObjectIdentifier, OctetString, Uint, UtcTime},
        DateTime, Decode, Encode,
    },
    ext::{
        pkix::{
            crl::{BaseCrlNumber, CrlNumber},
            AuthorityKeyIdentifier, BasicConstraints, CrlReason, KeyUsage, KeyUsages,
            SubjectKeyIdentifier,
        },
        Extension,
    },
    serial_number::SerialNumber as X509Serial,
    spki::AlgorithmIdentifierOwned,
    time::Time,
    Certificate, Version,
};

#[cfg(feature = "lab-software")]
use x509_cert::crl::CertificateList;

const INVALIDITY_DATE_OID: &str = "2.5.29.24";
const EXPIRED_CERTS_ON_CRL_OID: &str = "2.5.29.60";
const CRL_NUMBER_OID: &str = "2.5.29.20";
const DELTA_CRL_INDICATOR_OID: &str = "2.5.29.27";
const REASON_CODE_OID: &str = "2.5.29.21";
const SUBJECT_KEY_IDENTIFIER_OID: &str = "2.5.29.14";
const AUTHORITY_KEY_IDENTIFIER_OID: &str = "2.5.29.35";
const KEY_USAGE_OID: &str = "2.5.29.15";
const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";
const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const P256_CURVE_OID: &str = "1.2.840.10045.3.1.7";
/// CRL numbers stay below 2^63 so they fit a signed 64-bit database column.
const MAX_CRL_NUMBER: u64 = 1 << 63;
/// Earliest instant the builder encodes (1970-01-01T00:00:00Z).
pub const MIN_CRL_TIME_UNIX: i64 = 0;
/// Latest instant the builder encodes (9999-12-31T23:59:59Z, the last
/// four-digit GeneralizedTime year).
pub const MAX_CRL_TIME_UNIX: i64 = 253_402_300_799;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlError {
    Encoding,
    JournalFailure,
    ReplayedOrAmbiguousIntent,
    SigningFailure,
    AssemblyFailure,
    VerificationFailure,
    PersistenceFailure,
    /// The CRL was signed and independently verified, but storing it failed;
    /// the number is quarantined. Keep these bytes and hand them to
    /// `crl_orchestrator::reconcile_crl` instead of losing the number.
    VerifiedButNotStored(Vec<u8>),
    /// Nothing was signed and nothing can be signed for this reservation
    /// (abandoned, superseded by a higher number, stale or past nextUpdate):
    /// reserve a new CRL number. Unlike `ReplayedOrAmbiguousIntent`, no
    /// reconciliation is needed.
    ReserveAgain,
    /// The plan's issuer, the verifier's issuer or the signer key reference
    /// do not belong together; refused before any intent or signature.
    IssuerMismatch,
    /// A revocation is missing from the CRL without an expiry that the
    /// certificate itself confirms (migration 0032); nothing was signed.
    UnexplainedOmission,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlEntry {
    pub serial: SerialNumber,
    pub revoked_at_unix: i64,
    pub reason: RevocationReason,
    pub invalidity_at_unix: Option<i64>,
}

/// A certificate taken off the CRL since the base CRL (a released hold): a
/// delta CRL lists it with reason removeFromCRL (RFC 5280 5.3.1), dated
/// when it was released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedEntry {
    pub serial: SerialNumber,
    pub released_at_unix: i64,
}

/// One revokedCertificates element, complete or delta: reason code 8
/// (removeFromCRL) for a released entry.
struct Listed<'a> {
    serial: &'a SerialNumber,
    at_unix: i64,
    reason_code: i16,
    invalidity_at_unix: Option<i64>,
}

/// reasonCode removeFromCRL, valid only in a delta CRL.
const REMOVE_FROM_CRL: i16 = 8;

/// A reserved CRL: number, times and the frozen entry set. Sealed: the fields
/// are private and only [`CrlReservation::new`] (used by the store from the
/// database snapshot, and by lab examples and tests) builds one, so a
/// reservation cannot be edited between reserve and sign. Entries are kept
/// sorted by serial content bytes, the order the builder signs and
/// `crl_entry_encoding` (migration 0015) hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlReservation {
    ca_id: String,
    crl_number: u64,
    this_update_unix: i64,
    next_update_unix: i64,
    entries: Vec<CrlEntry>,
    expired_certs_on_crl_since_unix: Option<i64>,
    /// Delta CRLs (RFC 5280 5.2.4) only: the complete CRL this one updates,
    /// and the entries removed since it.
    base_crl_number: Option<u64>,
    released: Vec<ReleasedEntry>,
    /// Complete CRLs only: where the delta CRLs are (freshestCRL, 5.2.6).
    freshest_crl_url: Option<String>,
}

fn encodable(unix_seconds: i64) -> bool {
    (MIN_CRL_TIME_UNIX..=MAX_CRL_TIME_UNIX).contains(&unix_seconds)
}

impl CrlReservation {
    /// Fails closed with `CrlError::Encoding` on an empty CA id, a CRL number
    /// outside 1..2^63, `next_update <= this_update`, any time outside
    /// 1970-01-01 .. 9999-12-31 or duplicate serials.
    pub fn new(
        ca_id: impl Into<String>,
        crl_number: u64,
        this_update_unix: i64,
        next_update_unix: i64,
        mut entries: Vec<CrlEntry>,
        expired_certs_on_crl_since_unix: Option<i64>,
    ) -> Result<Self, CrlError> {
        let ca_id = ca_id.into();
        if ca_id.is_empty()
            || crl_number == 0
            || crl_number >= MAX_CRL_NUMBER
            || next_update_unix <= this_update_unix
            || !encodable(this_update_unix)
            || !encodable(next_update_unix)
            || !expired_certs_on_crl_since_unix.is_none_or(encodable)
            || entries.iter().any(|e| {
                !encodable(e.revoked_at_unix) || !e.invalidity_at_unix.is_none_or(encodable)
            })
        {
            return Err(CrlError::Encoding);
        }
        entries.sort_by(|a, b| a.serial.cmp(&b.serial));
        if entries
            .windows(2)
            .any(|pair| pair[0].serial == pair[1].serial)
        {
            return Err(CrlError::Encoding);
        }
        Ok(Self {
            ca_id,
            crl_number,
            this_update_unix,
            next_update_unix,
            entries,
            expired_certs_on_crl_since_unix,
            base_crl_number: None,
            released: Vec::new(),
            freshest_crl_url: None,
        })
    }

    /// Advertises where delta CRLs are published (freshestCRL, RFC 5280
    /// 5.2.6, non-critical). Relying parties such as OpenSSL look for a
    /// delta only when the complete CRL or the certificate carries it. Fails
    /// closed on a delta CRL (5.2.6: it MUST NOT appear there) and on a URL
    /// `x509_extensions::freshest_crl` refuses.
    pub fn with_freshest_crl(mut self, url: &str) -> Result<Self, CrlError> {
        if self.base_crl_number.is_some() {
            return Err(CrlError::Encoding);
        }
        crate::x509_extensions::freshest_crl(url).map_err(|_| CrlError::Encoding)?;
        self.freshest_crl_url = Some(url.to_owned());
        Ok(self)
    }

    pub fn freshest_crl_url(&self) -> Option<&str> {
        self.freshest_crl_url.as_deref()
    }

    /// A delta CRL (RFC 5280 5.2.4) updating the complete CRL
    /// `base_crl_number`: `entries` are the revocations and holds added since
    /// it, `released` the entries removed since it. Same checks as `new`,
    /// and fails closed unless 1 <= base < crl_number, the released entries
    /// are encodable and unique, and no serial is both revoked and released.
    /// It never carries ExpiredCertsOnCRL.
    pub fn new_delta(
        ca_id: impl Into<String>,
        crl_number: u64,
        base_crl_number: u64,
        this_update_unix: i64,
        next_update_unix: i64,
        entries: Vec<CrlEntry>,
        mut released: Vec<ReleasedEntry>,
    ) -> Result<Self, CrlError> {
        let mut reservation = Self::new(
            ca_id,
            crl_number,
            this_update_unix,
            next_update_unix,
            entries,
            None,
        )?;
        if base_crl_number == 0
            || base_crl_number >= crl_number
            || released.iter().any(|r| !encodable(r.released_at_unix))
        {
            return Err(CrlError::Encoding);
        }
        released.sort_by(|a, b| a.serial.cmp(&b.serial));
        if released
            .windows(2)
            .any(|pair| pair[0].serial == pair[1].serial)
            || released.iter().any(|r| {
                reservation
                    .entries
                    .binary_search_by(|e| e.serial.cmp(&r.serial))
                    .is_ok()
            })
        {
            return Err(CrlError::Encoding);
        }
        reservation.base_crl_number = Some(base_crl_number);
        reservation.released = released;
        Ok(reservation)
    }

    /// The complete CRL a delta CRL updates; None for a complete CRL.
    pub fn base_crl_number(&self) -> Option<u64> {
        self.base_crl_number
    }

    /// Delta CRLs: entries removed since the base, sorted by serial.
    pub fn released(&self) -> &[ReleasedEntry] {
        &self.released
    }

    /// Every revokedCertificates element in serial order: the entries, and
    /// for a delta CRL the released entries with reason removeFromCRL.
    fn listed(&self) -> Vec<Listed<'_>> {
        let mut listed: Vec<Listed<'_>> = self
            .entries
            .iter()
            .map(|e| Listed {
                serial: &e.serial,
                at_unix: e.revoked_at_unix,
                reason_code: e.reason.code(),
                invalidity_at_unix: e.invalidity_at_unix,
            })
            .chain(self.released.iter().map(|r| Listed {
                serial: &r.serial,
                at_unix: r.released_at_unix,
                reason_code: REMOVE_FROM_CRL,
                invalidity_at_unix: None,
            }))
            .collect();
        listed.sort_by(|a, b| a.serial.cmp(b.serial));
        listed
    }

    pub fn ca_id(&self) -> &str {
        &self.ca_id
    }

    pub fn crl_number(&self) -> u64 {
        self.crl_number
    }

    pub fn this_update_unix(&self) -> i64 {
        self.this_update_unix
    }

    pub fn next_update_unix(&self) -> i64 {
        self.next_update_unix
    }

    /// Sorted by serial content bytes.
    pub fn entries(&self) -> &[CrlEntry] {
        &self.entries
    }

    pub fn expired_certs_on_crl_since_unix(&self) -> Option<i64> {
        self.expired_certs_on_crl_since_unix
    }

    /// SHA-256 over the entries in serial order, each encoded exactly like
    /// `crl_entry_encoding` in migration 0015 (PostgreSQL send functions,
    /// big-endian): `int4(len(serial)) || serial || int8(revoked_at) ||
    /// int2(reason) || int8(invalidity_at or -1)`, times in whole epoch
    /// seconds. Passed to `record_crl_intent`, which refuses the intent unless
    /// it equals the digest of the reserved snapshot.
    /// A delta CRL's released entries take part in serial order with
    /// reason 8 (removeFromCRL) and their release time; a complete CRL's
    /// digest is unchanged.
    pub fn entries_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for entry in self.listed() {
            let serial = entry.serial.as_der_content();
            // Serials are at most 20 octets, so the length always fits.
            let len = i32::try_from(serial.len()).unwrap_or(i32::MAX);
            hasher.update(len.to_be_bytes());
            hasher.update(serial);
            hasher.update(entry.at_unix.to_be_bytes());
            hasher.update(entry.reason_code.to_be_bytes());
            hasher.update(entry.invalidity_at_unix.unwrap_or(-1).to_be_bytes());
        }
        hasher.finalize().into()
    }
}

/// Wraps exactly the journaled TBS bytes with the signature.
pub trait CrlAssembler {
    fn assemble(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>, CrlError>;
}

/// Independent check of a finished CRL against its reservation.
pub trait CrlVerifier {
    fn verify(&self, reservation: &CrlReservation, crl_der: &[u8]) -> Result<(), CrlError>;

    /// The trusted issuer certificate this verifier checks against.
    fn issuer(&self) -> &Certificate;
}

/// UTCTime for 1970 (unix epoch; earlier instants are rejected) through 2049,
/// GeneralizedTime from 2050 (RFC 5280 section 4.1.2.5). x509-cert's
/// `TryFrom<SystemTime>` always yields GeneralizedTime, so it is not used.
pub fn rfc5280_time(unix_seconds: i64) -> Result<Time, CrlError> {
    let seconds = u64::try_from(unix_seconds).map_err(|_| CrlError::Encoding)?;
    let duration = std::time::Duration::from_secs(seconds);
    let date_time = DateTime::from_unix_duration(duration).map_err(|_| CrlError::Encoding)?;
    if date_time.year() <= 2049 {
        UtcTime::from_date_time(date_time)
            .map(Time::UtcTime)
            .map_err(|_| CrlError::Encoding)
    } else {
        Ok(Time::GeneralTime(GeneralizedTime::from_date_time(
            date_time,
        )))
    }
}

fn generalized_time_extension(oid: &str, unix_seconds: i64) -> Result<Extension, CrlError> {
    let seconds = u64::try_from(unix_seconds).map_err(|_| CrlError::Encoding)?;
    let date_time = DateTime::from_unix_duration(std::time::Duration::from_secs(seconds))
        .map_err(|_| CrlError::Encoding)?;
    extension_from_der(
        oid,
        GeneralizedTime::from_date_time(date_time)
            .to_der()
            .map_err(|_| CrlError::Encoding)?,
    )
}

fn extension_from_der(oid: &str, der: Vec<u8>) -> Result<Extension, CrlError> {
    Ok(Extension {
        extn_id: ObjectIdentifier::new(oid).map_err(|_| CrlError::Encoding)?,
        critical: false,
        extn_value: OctetString::new(der).map_err(|_| CrlError::Encoding)?,
    })
}

fn ecdsa_sha256_identifier() -> Result<AlgorithmIdentifierOwned, CrlError> {
    use trust_pki_crypto::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};
    crate::agile_x509_identifier::signature_algorithm_identifier(AlgorithmSuite {
        scheme: SignatureScheme::Ecdsa,
        key: KeyParameter::P256,
        digest: Digest::Sha256,
    })
    .map_err(|_| CrlError::Encoding)
}

fn crl_reason(reason: RevocationReason) -> CrlReason {
    match reason {
        RevocationReason::Unspecified => CrlReason::Unspecified,
        RevocationReason::KeyCompromise => CrlReason::KeyCompromise,
        RevocationReason::CaCompromise => CrlReason::CaCompromise,
        RevocationReason::AffiliationChanged => CrlReason::AffiliationChanged,
        RevocationReason::Superseded => CrlReason::Superseded,
        RevocationReason::CessationOfOperation => CrlReason::CessationOfOperation,
        RevocationReason::CertificateHold => CrlReason::CertificateHold,
        RevocationReason::PrivilegeWithdrawn => CrlReason::PrivilegeWithdrawn,
        RevocationReason::AaCompromise => CrlReason::AaCompromise,
    }
}

fn revoked_cert(entry: &Listed<'_>) -> Result<RevokedCert, CrlError> {
    let mut extensions = Vec::new();
    // RFC 5280 5.3.1: reasonCode unspecified SHOULD be omitted.
    if entry.reason_code != RevocationReason::Unspecified.code() {
        let reason = if entry.reason_code == REMOVE_FROM_CRL {
            CrlReason::RemoveFromCRL
        } else {
            crl_reason(
                RevocationReason::from_code(entry.reason_code).map_err(|_| CrlError::Encoding)?,
            )
        };
        extensions.push(extension_from_der(
            REASON_CODE_OID,
            reason.to_der().map_err(|_| CrlError::Encoding)?,
        )?);
    }
    if let Some(invalidity) = entry.invalidity_at_unix {
        extensions.push(generalized_time_extension(INVALIDITY_DATE_OID, invalidity)?);
    }
    Ok(RevokedCert {
        serial_number: X509Serial::new(entry.serial.as_der_content())
            .map_err(|_| CrlError::Encoding)?,
        revocation_date: rfc5280_time(entry.at_unix)?,
        crl_entry_extensions: if extensions.is_empty() {
            None
        } else {
            Some(extensions)
        },
    })
}

/// The single extension `oid` of `issuer`; none or several fail closed.
fn single_extension<'a>(issuer: &'a Certificate, oid: &str) -> Result<&'a Extension, CrlError> {
    let mut found = issuer
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|e| e.extn_id.to_string() == oid);
    match (found.next(), found.next()) {
        (Some(extension), None) => Ok(extension),
        _ => Err(CrlError::Encoding),
    }
}

/// The issuer may sign this CRL with the only lab CRL algorithm: it is a CA
/// (exactly one basicConstraints with cA = TRUE), valid at thisUpdate
/// (notBefore <= thisUpdate <= notAfter), has keyUsage with cRLSign (RFC 5280
/// 4.2.1.3; an absent keyUsage is not read as "any usage") and an
/// id-ecPublicKey key on the named curve P-256. Nothing is inferred from the
/// signature algorithm the TBS will carry.
fn check_issuer(issuer: &Certificate, this_update_unix: i64) -> Result<(), CrlError> {
    let constraints = single_extension(issuer, BASIC_CONSTRAINTS_OID)?;
    let constraints = BasicConstraints::from_der(constraints.extn_value.as_bytes())
        .map_err(|_| CrlError::Encoding)?;
    if !constraints.ca {
        return Err(CrlError::Encoding);
    }
    let validity = &issuer.tbs_certificate.validity;
    let unix =
        |t: &Time| i64::try_from(t.to_unix_duration().as_secs()).map_err(|_| CrlError::Encoding);
    if this_update_unix < unix(&validity.not_before)?
        || this_update_unix > unix(&validity.not_after)?
    {
        return Err(CrlError::Encoding);
    }
    let usage = single_extension(issuer, KEY_USAGE_OID)?;
    let KeyUsage(flags) =
        KeyUsage::from_der(usage.extn_value.as_bytes()).map_err(|_| CrlError::Encoding)?;
    if !flags.contains(KeyUsages::CRLSign) {
        return Err(CrlError::Encoding);
    }
    let algorithm = &issuer.tbs_certificate.subject_public_key_info.algorithm;
    let curve = algorithm
        .parameters
        .as_ref()
        .ok_or(CrlError::Encoding)?
        .decode_as::<ObjectIdentifier>()
        .map_err(|_| CrlError::Encoding)?;
    if algorithm.oid.to_string() != EC_PUBLIC_KEY_OID || curve.to_string() != P256_CURVE_OID {
        return Err(CrlError::Encoding);
    }
    Ok(())
}

/// Everything `build_tbs_cert_list` requires of an issuer at `at_unix`
/// (CA, valid, cRLSign, P-256, one non-empty SKI); used before registering
/// it as a CA's issuer certificate.
pub fn check_crl_issuer(issuer: &Certificate, at_unix: i64) -> Result<(), CrlError> {
    check_issuer(issuer, at_unix)?;
    issuer_key_identifier(issuer).map(|_| ())
}

/// RFC 5280 5.2.1: the CRL's AKI keyIdentifier is the issuer certificate's
/// subjectKeyIdentifier, whatever method produced it. Fails closed when the
/// issuer has no SKI, more than one, or an empty one: the key identifier is
/// never recomputed from the public key.
fn issuer_key_identifier(issuer: &Certificate) -> Result<OctetString, CrlError> {
    let ski = single_extension(issuer, SUBJECT_KEY_IDENTIFIER_OID)?;
    let SubjectKeyIdentifier(id) = SubjectKeyIdentifier::from_der(ski.extn_value.as_bytes())
        .map_err(|_| CrlError::Encoding)?;
    if id.as_bytes().is_empty() {
        return Err(CrlError::Encoding);
    }
    Ok(id)
}

/// A positive CRL number (or base CRL number) as a DER INTEGER.
fn uint(number: u64) -> Result<Uint, CrlError> {
    let bytes = number.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .ok_or(CrlError::Encoding)?;
    Uint::new(&bytes[first..]).map_err(|_| CrlError::Encoding)
}

/// Issuer name and authority key identifier come from `issuer`, which must
/// pass `check_issuer`. Entries are sorted by serial bytes; duplicate serials,
/// a non-increasing validity window or an out-of-range CRL number are
/// rejected.
pub fn build_tbs_cert_list(
    issuer: &Certificate,
    reservation: &CrlReservation,
) -> Result<Vec<u8>, CrlError> {
    if reservation.crl_number == 0
        || reservation.crl_number >= MAX_CRL_NUMBER
        || reservation.next_update_unix <= reservation.this_update_unix
    {
        return Err(CrlError::Encoding);
    }
    check_issuer(issuer, reservation.this_update_unix)?;
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(issuer_key_identifier(issuer)?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    let number = CrlNumber(uint(reservation.crl_number)?);
    let mut crl_extensions = vec![
        extension_from_der(
            AUTHORITY_KEY_IDENTIFIER_OID,
            aki.to_der().map_err(|_| CrlError::Encoding)?,
        )?,
        extension_from_der(
            CRL_NUMBER_OID,
            number.to_der().map_err(|_| CrlError::Encoding)?,
        )?,
    ];
    if let Some(since) = reservation.expired_certs_on_crl_since_unix {
        crl_extensions.push(generalized_time_extension(EXPIRED_CERTS_ON_CRL_OID, since)?);
    }
    if let Some(url) = &reservation.freshest_crl_url {
        if reservation.base_crl_number.is_some() {
            return Err(CrlError::Encoding);
        }
        crl_extensions
            .push(crate::x509_extensions::freshest_crl(url).map_err(|_| CrlError::Encoding)?);
    }
    // RFC 5280 5.2.4: the delta CRL indicator is critical and carries the
    // base CRL number, which precedes this CRL's number.
    if let Some(base) = reservation.base_crl_number {
        if base == 0
            || base >= reservation.crl_number
            || reservation.expired_certs_on_crl_since_unix.is_some()
        {
            return Err(CrlError::Encoding);
        }
        let mut indicator = extension_from_der(
            DELTA_CRL_INDICATOR_OID,
            BaseCrlNumber(uint(base)?)
                .to_der()
                .map_err(|_| CrlError::Encoding)?,
        )?;
        indicator.critical = true;
        crl_extensions.push(indicator);
    } else if !reservation.released.is_empty() {
        return Err(CrlError::Encoding);
    }

    // Defence in depth (see builder_rejects_invalid_reservations): the
    // sealed constructors already sort and de-duplicate.
    let listed = reservation.listed();
    if listed
        .windows(2)
        .any(|pair| pair[0].serial == pair[1].serial)
    {
        return Err(CrlError::Encoding);
    }
    let revoked = listed
        .iter()
        .map(revoked_cert)
        .collect::<Result<Vec<_>, _>>()?;

    TbsCertList {
        version: Version::V2,
        signature: ecdsa_sha256_identifier()?,
        issuer: issuer.tbs_certificate.subject.clone(),
        this_update: rfc5280_time(reservation.this_update_unix)?,
        next_update: Some(rfc5280_time(reservation.next_update_unix)?),
        revoked_certificates: if revoked.is_empty() {
            None
        } else {
            Some(revoked)
        },
        crl_extensions: Some(crl_extensions),
    }
    .to_der()
    .map_err(|_| CrlError::Encoding)
}

/// Assembles a CRL from EXACTLY the bytes previously journaled.
/// An entry left out of a CRL (`crl_pruned_entries`, migration 0032) is
/// only acceptable if the stored certificate itself shows it expired before
/// thisUpdate: same serial, notAfter equal to the stored `not_after` (whole
/// seconds) and earlier than thisUpdate. Anything else (no certificate, no
/// stored expiry, a stored expiry earlier than the real one) fails closed.
pub fn check_pruned_entry(
    serial_der_content: &[u8],
    stored_not_after_unix: Option<i64>,
    certificate_der: Option<&[u8]>,
    this_update_unix: i64,
) -> Result<(), CrlError> {
    let fail = CrlError::UnexplainedOmission;
    let (Some(stored), Some(der)) = (stored_not_after_unix, certificate_der) else {
        return Err(fail);
    };
    let certificate = Certificate::from_der(der).map_err(|_| fail.clone())?;
    let not_after = i64::try_from(
        certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    )
    .map_err(|_| fail.clone())?;
    if certificate.tbs_certificate.serial_number.as_bytes() != serial_der_content
        || not_after != stored
        || not_after >= this_update_unix
    {
        return Err(fail);
    }
    Ok(())
}

/// What a distribution point learns from a stored CRL it re-checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedCrl {
    pub crl_number: u64,
    pub this_update_unix: i64,
    pub next_update_unix: Option<i64>,
}

/// Re-checks a stored CRL before it is served (RFC 5280 6.3.3 from the
/// publisher's side): canonical DER, ECDSA P-256/SHA-256 in both algorithm
/// fields, issued by `issuer` (the CA's registered issuer certificate) and
/// signed by its key, with exactly one CRL number, no critical extension
/// and no delta CRL indicator (a complete CRL). Content was checked
/// against the reservation before storage (`LabCrlVerifier`); this only
/// guards against a stored CRL altered or substituted afterwards.
pub fn verify_published_crl(
    issuer: &Certificate,
    crl_der: &[u8],
) -> Result<PublishedCrl, CrlError> {
    match verify_published(issuer, crl_der)? {
        (published, None) => Ok(published),
        (_, Some(_)) => Err(CrlError::VerificationFailure),
    }
}

/// The entries of a published complete CRL, after `verify_published_crl`
/// accepted it against `issuer`: what a restore from an older backup
/// re-applies (migration 0060). Fails closed on a delta CRL, a
/// removeFromCRL or unknown entry extension, a reason or date it cannot
/// represent, or a serial listed twice. Entries keep the CRL's order.
pub fn published_crl_entries(
    issuer: &Certificate,
    crl_der: &[u8],
) -> Result<(PublishedCrl, Vec<CrlEntry>), CrlError> {
    let published = verify_published_crl(issuer, crl_der)?;
    let fail = CrlError::VerificationFailure;
    let crl = x509_cert::crl::CertificateList::from_der(crl_der).map_err(|_| fail.clone())?;
    let unix = |time: &Time| i64::try_from(time.to_unix_duration().as_secs()).ok();
    let mut entries: Vec<CrlEntry> = Vec::new();
    for revoked in crl.tbs_cert_list.revoked_certificates.iter().flatten() {
        let mut reason = RevocationReason::Unspecified;
        let mut invalidity_at_unix = None;
        for extension in revoked.crl_entry_extensions.iter().flatten() {
            match extension.extn_id.to_string().as_str() {
                REASON_CODE_OID => {
                    let code = CrlReason::from_der(extension.extn_value.as_bytes())
                        .map_err(|_| fail.clone())?;
                    if code == CrlReason::RemoveFromCRL {
                        return Err(fail);
                    }
                    reason = RevocationReason::from_code(code as i16).map_err(|_| fail.clone())?;
                }
                INVALIDITY_DATE_OID => {
                    let time = GeneralizedTime::from_der(extension.extn_value.as_bytes())
                        .map_err(|_| fail.clone())?;
                    invalidity_at_unix = Some(
                        i64::try_from(time.to_unix_duration().as_secs())
                            .map_err(|_| fail.clone())?,
                    );
                }
                _ => return Err(fail),
            }
        }
        let serial = SerialNumber::from_positive_der_content(revoked.serial_number.as_bytes())
            .map_err(|_| fail.clone())?;
        if entries.iter().any(|e| e.serial == serial) {
            return Err(fail);
        }
        entries.push(CrlEntry {
            serial,
            revoked_at_unix: unix(&revoked.revocation_date).ok_or_else(|| fail.clone())?,
            reason,
            invalidity_at_unix,
        });
    }
    Ok((published, entries))
}

/// A stored delta CRL, re-checked like `verify_published_crl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedDeltaCrl {
    pub crl: PublishedCrl,
    pub base_crl_number: u64,
}

/// `verify_published_crl` for a delta CRL (RFC 5280 5.2.4): exactly one
/// delta CRL indicator, critical, naming a base CRL number below this
/// CRL's number; no other critical extension.
pub fn verify_published_delta_crl(
    issuer: &Certificate,
    crl_der: &[u8],
) -> Result<PublishedDeltaCrl, CrlError> {
    match verify_published(issuer, crl_der)? {
        (crl, Some(base_crl_number)) if base_crl_number < crl.crl_number => Ok(PublishedDeltaCrl {
            crl,
            base_crl_number,
        }),
        _ => Err(CrlError::VerificationFailure),
    }
}

/// A CRL number or base CRL number INTEGER as u64 below 2^63.
fn number_from(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut buffer = [0u8; 8];
    buffer[8 - bytes.len()..].copy_from_slice(bytes);
    Some(u64::from_be_bytes(buffer)).filter(|n| *n < MAX_CRL_NUMBER)
}

/// The checks shared by complete and delta CRLs; also returns the base CRL
/// number when the CRL is a delta.
fn verify_published(
    issuer: &Certificate,
    crl_der: &[u8],
) -> Result<(PublishedCrl, Option<u64>), CrlError> {
    let fail = CrlError::VerificationFailure;
    let crl = x509_cert::crl::CertificateList::from_der(crl_der).map_err(|_| fail.clone())?;
    if crl.to_der().map_err(|_| fail.clone())? != crl_der {
        return Err(fail);
    }
    let identifier = ecdsa_sha256_identifier().map_err(|_| fail.clone())?;
    let tbs = &crl.tbs_cert_list;
    if crl.signature_algorithm != identifier
        || tbs.signature != identifier
        || tbs.issuer != issuer.tbs_certificate.subject
    {
        return Err(fail);
    }
    // RFC 5280 5.2 and 5.3: a critical extension may be one a relying party
    // does not understand. The only critical one the lab issues is the delta
    // CRL indicator (5.2.4), which must be critical and appear at most once.
    let entry_extensions = tbs
        .revoked_certificates
        .iter()
        .flatten()
        .flat_map(|entry| entry.crl_entry_extensions.iter().flatten());
    if entry_extensions.into_iter().any(|e| e.critical) {
        return Err(fail);
    }
    let mut base = None;
    for extension in tbs.crl_extensions.iter().flatten() {
        if extension.extn_id.to_string() == DELTA_CRL_INDICATOR_OID {
            let number = BaseCrlNumber::from_der(extension.extn_value.as_bytes())
                .map_err(|_| fail.clone())?;
            if !extension.critical || base.is_some() {
                return Err(fail);
            }
            base = Some(number_from(number.0.as_bytes()).ok_or_else(|| fail.clone())?);
        } else if extension.critical {
            return Err(fail);
        }
    }
    let tbs_der = tbs.to_der().map_err(|_| fail.clone())?;
    let sec1 = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| fail.clone())?;
    let signature = crl.signature.as_bytes().ok_or_else(|| fail.clone())?;
    trust_pki_crypto::verify_p256_ecdsa_sha256(sec1, &tbs_der, signature)
        .map_err(|_| fail.clone())?;
    let mut numbers = tbs
        .crl_extensions
        .iter()
        .flatten()
        .filter(|e| e.extn_id.to_string() == CRL_NUMBER_OID);
    let number = match (numbers.next(), numbers.next()) {
        (Some(extension), None) => {
            CrlNumber::from_der(extension.extn_value.as_bytes()).map_err(|_| fail.clone())?
        }
        _ => return Err(fail),
    };
    let crl_number = number_from(number.0.as_bytes()).ok_or_else(|| fail.clone())?;
    let unix = |time: &Time| i64::try_from(time.to_unix_duration().as_secs()).ok();
    Ok((
        PublishedCrl {
            crl_number,
            this_update_unix: unix(&tbs.this_update).ok_or_else(|| fail.clone())?,
            next_update_unix: match &tbs.next_update {
                Some(time) => Some(unix(time).ok_or(fail)?),
                None => None,
            },
        },
        base,
    ))
}

#[cfg(feature = "lab-software")]
pub struct LabCrlAssembler;

#[cfg(feature = "lab-software")]
impl CrlAssembler for LabCrlAssembler {
    fn assemble(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>, CrlError> {
        let tbs = TbsCertList::from_der(tbs_der).map_err(|_| CrlError::AssemblyFailure)?;
        // Refuse non-canonical input: the signature must cover these bytes.
        if tbs.to_der().map_err(|_| CrlError::AssemblyFailure)? != tbs_der
            || tbs.signature != ecdsa_sha256_identifier().map_err(|_| CrlError::AssemblyFailure)?
        {
            return Err(CrlError::AssemblyFailure);
        }
        CertificateList {
            signature_algorithm: tbs.signature.clone(),
            tbs_cert_list: tbs,
            signature: x509_cert::der::asn1::BitString::from_bytes(signature)
                .map_err(|_| CrlError::AssemblyFailure)?,
        }
        .to_der()
        .map_err(|_| CrlError::AssemblyFailure)
    }
}

/// The issuer certificate MUST come from a trusted service-side record.
#[cfg(feature = "lab-software")]
pub struct LabCrlVerifier {
    issuer: Certificate,
}

#[cfg(feature = "lab-software")]
impl LabCrlVerifier {
    pub fn new(issuer: Certificate) -> Self {
        Self { issuer }
    }

    fn check(&self, reservation: &CrlReservation, crl_der: &[u8]) -> Result<(), CrlError> {
        let fail = CrlError::VerificationFailure;
        let crl = CertificateList::from_der(crl_der).map_err(|_| fail.clone())?;
        // Canonical DER only; also rejects trailing bytes.
        if crl.to_der().map_err(|_| fail.clone())? != crl_der {
            return Err(fail);
        }
        let tbs_der = crl.tbs_cert_list.to_der().map_err(|_| fail.clone())?;
        let identifier = ecdsa_sha256_identifier().map_err(|_| fail.clone())?;
        if crl.signature_algorithm != identifier || crl.tbs_cert_list.signature != identifier {
            return Err(fail);
        }
        // Every field (version, issuer, AKI, number, times, entries, reasons,
        // extensions) must equal what the reservation dictates.
        let expected = build_tbs_cert_list(&self.issuer, reservation).map_err(|_| fail.clone())?;
        if expected != tbs_der {
            return Err(fail);
        }
        // id-ecPublicKey on P-256 was enforced by check_issuer, through
        // build_tbs_cert_list above.
        let spki = &self.issuer.tbs_certificate.subject_public_key_info;
        let sec1 = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| fail.clone())?;
        let signature = crl.signature.as_bytes().ok_or_else(|| fail.clone())?;
        trust_pki_crypto::verify_p256_ecdsa_sha256(sec1, &tbs_der, signature).map_err(|_| fail)
    }
}

#[cfg(feature = "lab-software")]
impl CrlVerifier for LabCrlVerifier {
    fn verify(&self, reservation: &CrlReservation, crl_der: &[u8]) -> Result<(), CrlError> {
        self.check(reservation, crl_der)
    }

    fn issuer(&self) -> &Certificate {
        &self.issuer
    }
}

#[cfg(all(test, feature = "lab-software"))]
mod tests {
    use super::*;
    use crate::lab_ca::EphemeralLabCa;
    use crate::orchestrator::ExternalSigner;
    use crate::x509_extensions;
    use std::str::FromStr;
    use x509_cert::{
        der::{asn1::BitString, Any},
        ext::pkix::{KeyUsage, KeyUsages},
        name::Name,
    };

    const THIS_UPDATE: i64 = 1_800_000_000; // 2027-01-15
    const NEXT_UPDATE: i64 = THIS_UPDATE + 7 * 24 * 3600;

    fn serial(bytes: &[u8]) -> SerialNumber {
        SerialNumber::from_positive_der_content(bytes).unwrap()
    }

    fn reservation(entries: Vec<CrlEntry>) -> CrlReservation {
        CrlReservation::new("lab-root", 1, THIS_UPDATE, NEXT_UPDATE, entries, None).unwrap()
    }

    fn with(
        r: &CrlReservation,
        crl_number: u64,
        this_update: i64,
        next_update: i64,
        expired: Option<i64>,
    ) -> CrlReservation {
        CrlReservation::new(
            r.ca_id(),
            crl_number,
            this_update,
            next_update,
            r.entries().to_vec(),
            expired,
        )
        .unwrap()
    }

    fn entry(s: &[u8], reason: RevocationReason, invalidity: Option<i64>) -> CrlEntry {
        CrlEntry {
            serial: serial(s),
            revoked_at_unix: THIS_UPDATE - 100,
            reason,
            invalidity_at_unix: invalidity,
        }
    }

    fn sign(ca: &mut EphemeralLabCa, tbs: &[u8]) -> Vec<u8> {
        let key_ref = ca.lab_signer_key_ref().to_owned();
        ca.sign_once(&key_ref, "crl-test", tbs).unwrap()
    }

    fn issue(ca: &mut EphemeralLabCa, r: &CrlReservation) -> Vec<u8> {
        let tbs = build_tbs_cert_list(&root(ca), r).unwrap();
        let sig = sign(ca, &tbs);
        LabCrlAssembler.assemble(&tbs, &sig).unwrap()
    }

    /// Re-signs a mutated TBS with the real CA so only the content check can fail.
    fn resigned(
        ca: &mut EphemeralLabCa,
        crl: &[u8],
        mutate: impl FnOnce(&mut TbsCertList),
    ) -> Vec<u8> {
        let mut list = CertificateList::from_der(crl).unwrap();
        mutate(&mut list.tbs_cert_list);
        let tbs = list.tbs_cert_list.to_der().unwrap();
        list.signature = BitString::from_bytes(&sign(ca, &tbs)).unwrap();
        list.to_der().unwrap()
    }

    fn as_revoked(e: &CrlEntry) -> RevokedCert {
        revoked_cert(&Listed {
            serial: &e.serial,
            at_unix: e.revoked_at_unix,
            reason_code: e.reason.code(),
            invalidity_at_unix: e.invalidity_at_unix,
        })
        .unwrap()
    }

    fn ext_value<'a>(exts: &'a [Extension], oid: &str) -> Option<&'a [u8]> {
        exts.iter()
            .find(|e| e.extn_id.to_string() == oid)
            .map(|e| e.extn_value.as_bytes())
    }

    fn ca() -> EphemeralLabCa {
        EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap()
    }

    /// The lab root with a validity widened to 2020..2049 so that the fixed
    /// 2027 test dates fall inside it (the lab root itself is valid for
    /// 7 days from now). Only the certificate fields change; the CA key, and
    /// therefore every CRL signature, is the lab root's.
    fn root(ca: &EphemeralLabCa) -> Certificate {
        let mut cert = ca.root_certificate().clone();
        cert.tbs_certificate.validity.not_before = rfc5280_time(1_577_836_800).unwrap();
        cert.tbs_certificate.validity.not_after = rfc5280_time(2_524_607_999).unwrap();
        cert
    }

    #[test]
    fn rfc5280_time_switches_at_2050() {
        assert!(matches!(rfc5280_time(2_524_607_999), Ok(Time::UtcTime(_))));
        assert!(matches!(
            rfc5280_time(2_524_608_000),
            Ok(Time::GeneralTime(_))
        ));
        assert!(matches!(
            rfc5280_time(253_402_300_799),
            Ok(Time::GeneralTime(_))
        ));
        assert_eq!(rfc5280_time(-1), Err(CrlError::Encoding));
    }

    #[test]
    fn pruned_entries_must_be_confirmed_by_the_certificate() {
        let ca = ca();
        let root = root(&ca);
        let der = root.to_der().unwrap();
        let serial = root.tbs_certificate.serial_number.as_bytes().to_vec();
        let not_after = root
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64;
        assert_eq!(
            check_pruned_entry(&serial, Some(not_after), Some(&der), not_after + 1),
            Ok(())
        );
        for (serial, stored, der, this_update) in [
            // Recorded expiry earlier than the certificate's real one.
            (
                &serial[..],
                Some(not_after - 86_400),
                Some(&der[..]),
                not_after + 1,
            ),
            // Not yet expired at thisUpdate.
            (&serial[..], Some(not_after), Some(&der[..]), not_after),
            // Another certificate's DER.
            (&[0x7f][..], Some(not_after), Some(&der[..]), not_after + 1),
            // No stored expiry, no certificate, garbage.
            (&serial[..], None, Some(&der[..]), not_after + 1),
            (&serial[..], Some(not_after), None, not_after + 1),
            (
                &serial[..],
                Some(not_after),
                Some(&[0x30, 0x00][..]),
                not_after + 1,
            ),
        ] {
            assert_eq!(
                check_pruned_entry(serial, stored, der, this_update),
                Err(CrlError::UnexplainedOmission)
            );
        }
    }

    #[test]
    fn published_crl_is_rechecked_against_the_registered_issuer() {
        let mut ca = ca();
        let r = reservation(vec![entry(&[0x01], RevocationReason::KeyCompromise, None)]);
        let der = issue(&mut ca, &r);
        assert_eq!(
            verify_published_crl(&root(&ca), &der).unwrap(),
            PublishedCrl {
                crl_number: 1,
                this_update_unix: THIS_UPDATE,
                next_update_unix: Some(NEXT_UPDATE),
            }
        );
        // Altered content, even re-signed by another CA, is refused.
        let mut other = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let foreign = issue(&mut other, &r);
        assert_eq!(
            verify_published_crl(&root(&ca), &foreign),
            Err(CrlError::VerificationFailure)
        );
        let mut flipped = der.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            verify_published_crl(&root(&ca), &flipped),
            Err(CrlError::VerificationFailure)
        );
        let mut trailing = der.clone();
        trailing.push(0);
        assert_eq!(
            verify_published_crl(&root(&ca), &trailing),
            Err(CrlError::VerificationFailure)
        );
        let renumbered = resigned(&mut ca, &der, |tbs| {
            tbs.crl_extensions
                .as_mut()
                .unwrap()
                .retain(|e| e.extn_id.to_string() != CRL_NUMBER_OID);
        });
        assert_eq!(
            verify_published_crl(&root(&ca), &renumbered),
            Err(CrlError::VerificationFailure)
        );
    }

    fn released(s: &[u8]) -> ReleasedEntry {
        ReleasedEntry {
            serial: serial(s),
            released_at_unix: THIS_UPDATE - 50,
        }
    }

    fn delta() -> CrlReservation {
        CrlReservation::new_delta(
            "lab-root",
            3,
            2,
            THIS_UPDATE,
            NEXT_UPDATE,
            vec![entry(&[0x03], RevocationReason::Superseded, None)],
            vec![released(&[0x02])],
        )
        .unwrap()
    }

    /// RFC 5280 5.2.4: a delta CRL carries a critical delta CRL indicator
    /// with its base CRL number, lists what was added since the base, and
    /// lists released holds with reason removeFromCRL (5.3.1).
    #[test]
    fn delta_crl_names_its_base_and_lists_releases() {
        let mut ca = ca();
        let r = delta();
        let der = issue(&mut ca, &r);
        LabCrlVerifier::new(root(&ca)).verify(&r, &der).unwrap();
        let crl = CertificateList::from_der(&der).unwrap();
        let extensions = crl.tbs_cert_list.crl_extensions.clone().unwrap();
        let indicator = extensions
            .iter()
            .find(|e| e.extn_id.to_string() == DELTA_CRL_INDICATOR_OID)
            .unwrap();
        assert!(indicator.critical);
        assert_eq!(
            BaseCrlNumber::from_der(indicator.extn_value.as_bytes())
                .unwrap()
                .0
                .as_bytes(),
            &[2]
        );
        let listed = crl.tbs_cert_list.revoked_certificates.clone().unwrap();
        assert_eq!(listed.len(), 2);
        let reason = |i: usize| {
            CrlReason::from_der(
                ext_value(
                    listed[i].crl_entry_extensions.as_ref().unwrap(),
                    REASON_CODE_OID,
                )
                .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(listed[0].serial_number.as_bytes(), &[0x02]);
        assert_eq!(reason(0), CrlReason::RemoveFromCRL);
        assert_eq!(listed[1].serial_number.as_bytes(), &[0x03]);
        assert_eq!(reason(1), CrlReason::Superseded);

        // Served only as a delta, never as the complete CRL.
        assert_eq!(
            verify_published_delta_crl(&root(&ca), &der).unwrap(),
            PublishedDeltaCrl {
                crl: PublishedCrl {
                    crl_number: 3,
                    this_update_unix: THIS_UPDATE,
                    next_update_unix: Some(NEXT_UPDATE),
                },
                base_crl_number: 2,
            }
        );
        assert_eq!(
            verify_published_crl(&root(&ca), &der),
            Err(CrlError::VerificationFailure)
        );
        let complete = issue(&mut ca, &reservation(vec![]));
        assert_eq!(
            verify_published_delta_crl(&root(&ca), &complete),
            Err(CrlError::VerificationFailure)
        );
        // A non-critical indicator, or a base not below the number, is refused.
        let soft = resigned(&mut ca, &der, |tbs| {
            for e in tbs.crl_extensions.as_mut().unwrap() {
                if e.extn_id.to_string() == DELTA_CRL_INDICATOR_OID {
                    e.critical = false;
                }
            }
        });
        assert_eq!(
            verify_published_delta_crl(&root(&ca), &soft),
            Err(CrlError::VerificationFailure)
        );
        let late_base = resigned(&mut ca, &der, |tbs| {
            for e in tbs.crl_extensions.as_mut().unwrap() {
                if e.extn_id.to_string() == DELTA_CRL_INDICATOR_OID {
                    e.extn_value = OctetString::new(vec![0x02, 0x01, 0x03]).unwrap();
                }
            }
        });
        assert_eq!(
            verify_published_delta_crl(&root(&ca), &late_base),
            Err(CrlError::VerificationFailure)
        );
        // The independent verifier refuses a delta whose release was dropped.
        let dropped = resigned(&mut ca, &der, |tbs| {
            tbs.revoked_certificates.as_mut().unwrap().remove(0);
        });
        assert_eq!(
            LabCrlVerifier::new(root(&ca)).verify(&r, &dropped),
            Err(CrlError::VerificationFailure)
        );
    }

    #[test]
    fn freshest_crl_is_advertised_on_complete_crls_only() {
        let mut ca = ca();
        let url = "http://crl.lab.invalid/delta/lab-root.crl";
        let r = reservation(vec![]).with_freshest_crl(url).unwrap();
        assert_eq!(r.freshest_crl_url(), Some(url));
        let der = issue(&mut ca, &r);
        LabCrlVerifier::new(root(&ca)).verify(&r, &der).unwrap();
        verify_published_crl(&root(&ca), &der).unwrap();
        let crl = CertificateList::from_der(&der).unwrap();
        let freshest = crl
            .tbs_cert_list
            .crl_extensions
            .unwrap()
            .into_iter()
            .find(|e| e.extn_id.to_string() == "2.5.29.46")
            .unwrap();
        assert!(!freshest.critical);
        // The plain reservation's CRL differs: the extension is signed.
        assert_ne!(
            build_tbs_cert_list(&root(&ca), &r).unwrap(),
            build_tbs_cert_list(&root(&ca), &reservation(vec![])).unwrap()
        );
        assert_eq!(delta().with_freshest_crl(url), Err(CrlError::Encoding));
        for bad in [
            "https://crl.lab.invalid/d.crl",
            "http://",
            "ldap://x/y",
            "http://a b/c",
        ] {
            assert_eq!(
                reservation(vec![]).with_freshest_crl(bad),
                Err(CrlError::Encoding),
                "{bad}"
            );
        }
    }

    #[test]
    fn delta_reservation_rejects_invalid_input() {
        let new = |number: u64, base: u64, entries: Vec<CrlEntry>, rel: Vec<ReleasedEntry>| {
            CrlReservation::new_delta(
                "lab-root",
                number,
                base,
                THIS_UPDATE,
                NEXT_UPDATE,
                entries,
                rel,
            )
        };
        let reject = Err(CrlError::Encoding);
        assert_eq!(new(3, 0, vec![], vec![]), reject);
        assert_eq!(new(3, 3, vec![], vec![]), reject);
        assert_eq!(new(3, 4, vec![], vec![]), reject);
        assert_eq!(
            new(3, 2, vec![], vec![released(&[1]), released(&[1])]),
            reject
        );
        assert_eq!(
            new(
                3,
                2,
                vec![entry(&[1], RevocationReason::KeyCompromise, None)],
                vec![released(&[1])]
            ),
            reject
        );
        let mut late = released(&[1]);
        late.released_at_unix = MAX_CRL_TIME_UNIX + 1;
        assert_eq!(new(3, 2, vec![], vec![late]), reject);
        // A complete CRL's digest ignores the delta fields; a delta's covers
        // its releases (reason 8).
        let complete = reservation(vec![entry(&[0x03], RevocationReason::Superseded, None)]);
        assert_ne!(delta().entries_sha256(), complete.entries_sha256());
        let plain = new(
            3,
            2,
            vec![entry(&[0x03], RevocationReason::Superseded, None)],
            vec![],
        )
        .unwrap();
        assert_eq!(plain.entries_sha256(), complete.entries_sha256());
        assert_eq!(plain.base_crl_number(), Some(2));
        assert_eq!(complete.base_crl_number(), None);
    }

    #[test]
    fn published_crl_entries_are_read_back_after_verification() {
        let mut ca = ca();
        let r = reservation(vec![
            entry(
                &[0x01],
                RevocationReason::KeyCompromise,
                Some(THIS_UPDATE - 500),
            ),
            entry(&[0x02], RevocationReason::CertificateHold, None),
            entry(&[0x03], RevocationReason::Unspecified, None),
        ]);
        let der = issue(&mut ca, &r);
        let (published, entries) = published_crl_entries(&root(&ca), &der).unwrap();
        assert_eq!(published.crl_number, 1);
        assert_eq!(entries, r.entries().to_vec());
        // Not signed by this CA, a delta, or an entry it cannot represent:
        // nothing is returned.
        let other = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        assert_eq!(
            published_crl_entries(&root(&other), &der),
            Err(CrlError::VerificationFailure)
        );
        let delta_der = issue(&mut ca, &delta());
        assert_eq!(
            published_crl_entries(&root(&ca), &delta_der),
            Err(CrlError::VerificationFailure)
        );
        let removed = resigned(&mut ca, &der, |tbs| {
            let list = tbs.revoked_certificates.as_mut().unwrap();
            list[0].crl_entry_extensions = Some(vec![extension_from_der(
                REASON_CODE_OID,
                CrlReason::RemoveFromCRL.to_der().unwrap(),
            )
            .unwrap()]);
        });
        assert_eq!(
            published_crl_entries(&root(&ca), &removed),
            Err(CrlError::VerificationFailure)
        );
        let unknown = resigned(&mut ca, &der, |tbs| {
            let list = tbs.revoked_certificates.as_mut().unwrap();
            list[0].crl_entry_extensions = Some(vec![extension_from_der(
                "1.3.6.1.4.1.55555.98",
                vec![0x05, 0x00],
            )
            .unwrap()]);
        });
        assert_eq!(
            published_crl_entries(&root(&ca), &unknown),
            Err(CrlError::VerificationFailure)
        );
        let doubled = resigned(&mut ca, &der, |tbs| {
            let list = tbs.revoked_certificates.as_mut().unwrap();
            let first = list[0].clone();
            list.push(first);
        });
        assert_eq!(
            published_crl_entries(&root(&ca), &doubled),
            Err(CrlError::VerificationFailure)
        );
    }

    /// RFC 5280 5.2: a CRL with an unrecognised critical extension must not
    /// be used to decide revocation status, and a delta CRL (5.2.4) is not a
    /// complete CRL; neither may be served as the CA's CRL.
    #[test]
    fn published_crl_with_an_unknown_critical_extension_is_refused() {
        let mut ca = ca();
        let r = reservation(vec![entry(&[0x01], RevocationReason::KeyCompromise, None)]);
        let der = issue(&mut ca, &r);
        for (oid, value) in [
            // Delta CRL indicator, BaseCRLNumber 1.
            ("2.5.29.27", vec![0x02, 0x01, 0x01]),
            // Some critical extension nobody here understands.
            ("1.3.6.1.4.1.55555.99", vec![0x05, 0x00]),
        ] {
            let marked = resigned(&mut ca, &der, |tbs| {
                tbs.crl_extensions.as_mut().unwrap().push(Extension {
                    extn_id: ObjectIdentifier::new(oid).unwrap(),
                    critical: true,
                    extn_value: OctetString::new(value).unwrap(),
                });
            });
            assert_eq!(
                verify_published_crl(&root(&ca), &marked),
                Err(CrlError::VerificationFailure),
                "{oid}"
            );
        }
    }

    #[test]
    fn empty_crl_has_no_revoked_list_and_verifies() {
        let mut ca = ca();
        let r = reservation(vec![]);
        let der = issue(&mut ca, &r);
        let list = CertificateList::from_der(&der).unwrap();
        assert!(list.tbs_cert_list.revoked_certificates.is_none());
        assert_eq!(list.tbs_cert_list.version, Version::V2);
        assert!(matches!(list.tbs_cert_list.this_update, Time::UtcTime(_)));
        LabCrlVerifier::new(root(&ca)).verify(&r, &der).unwrap();
    }

    #[test]
    fn entries_are_sorted_and_reason_rules_hold() {
        let mut ca = ca();
        let invalidity = THIS_UPDATE - 5000;
        let r = reservation(vec![
            entry(&[0x03], RevocationReason::Unspecified, None),
            entry(&[0x01], RevocationReason::KeyCompromise, Some(invalidity)),
        ]);
        let der = issue(&mut ca, &r);
        LabCrlVerifier::new(root(&ca)).verify(&r, &der).unwrap();
        let list = CertificateList::from_der(&der).unwrap();
        let revoked = list.tbs_cert_list.revoked_certificates.unwrap();
        assert_eq!(revoked[0].serial_number.as_bytes(), &[0x01]);
        assert_eq!(revoked[1].serial_number.as_bytes(), &[0x03]);
        let first = revoked[0].crl_entry_extensions.as_ref().unwrap();
        assert_eq!(ext_value(first, "2.5.29.21"), Some(&[0x0a, 0x01, 0x01][..]));
        let expected = GeneralizedTime::from_date_time(
            DateTime::from_unix_duration(std::time::Duration::from_secs(invalidity as u64))
                .unwrap(),
        )
        .to_der()
        .unwrap();
        assert_eq!(ext_value(first, "2.5.29.24"), Some(expected.as_slice()));
        assert!(first.iter().all(|e| !e.critical));
        assert!(revoked[1].crl_entry_extensions.is_none());
    }

    #[test]
    fn reason_codes_are_pinned_and_encoded_verbatim() {
        let table = [
            (RevocationReason::Unspecified, 0i16),
            (RevocationReason::KeyCompromise, 1),
            (RevocationReason::CaCompromise, 2),
            (RevocationReason::AffiliationChanged, 3),
            (RevocationReason::Superseded, 4),
            (RevocationReason::CessationOfOperation, 5),
            (RevocationReason::CertificateHold, 6),
            (RevocationReason::PrivilegeWithdrawn, 9),
            (RevocationReason::AaCompromise, 10),
        ];
        let mut ca = ca();
        for (reason, code) in table {
            assert_eq!(reason.code(), code);
            let der = issue(&mut ca, &reservation(vec![entry(&[0x07], reason, None)]));
            let list = CertificateList::from_der(&der).unwrap();
            let revoked = list.tbs_cert_list.revoked_certificates.unwrap();
            match &revoked[0].crl_entry_extensions {
                None => assert_eq!(code, 0),
                Some(exts) => assert_eq!(
                    ext_value(exts, "2.5.29.21"),
                    Some(&[0x0a, 0x01, code as u8][..])
                ),
            }
        }
    }

    #[test]
    fn crl_extensions_are_aki_and_number() {
        let mut ca = ca();
        let der = issue(&mut ca, &reservation(vec![]));
        let list = CertificateList::from_der(&der).unwrap();
        let exts = list.tbs_cert_list.crl_extensions.unwrap();
        assert_eq!(exts.len(), 2);
        let root_exts = ca
            .root_certificate()
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap();
        let ski = ext_value(root_exts, "2.5.29.14").unwrap();
        let aki = AuthorityKeyIdentifier::from_der(ext_value(&exts, "2.5.29.35").unwrap()).unwrap();
        assert_eq!(aki.key_identifier.unwrap().as_bytes(), &ski[2..]);
        let number = CrlNumber::from_der(ext_value(&exts, "2.5.29.20").unwrap()).unwrap();
        assert_eq!(number.0.as_bytes(), &[0x01]);
        assert!(exts.iter().all(|e| !e.critical));

        let r = with(
            &reservation(vec![]),
            300,
            THIS_UPDATE,
            NEXT_UPDATE,
            Some(THIS_UPDATE - 86_400),
        );
        let der = issue(&mut ca, &r);
        LabCrlVerifier::new(root(&ca)).verify(&r, &der).unwrap();
        let exts = CertificateList::from_der(&der)
            .unwrap()
            .tbs_cert_list
            .crl_extensions
            .unwrap();
        assert_eq!(exts.len(), 3);
        let value = ext_value(&exts, "2.5.29.60").unwrap();
        assert_eq!(value[0], 0x18); // GeneralizedTime
        let number = CrlNumber::from_der(ext_value(&exts, "2.5.29.20").unwrap()).unwrap();
        assert_eq!(number.0.as_bytes(), &[0x01, 0x2c]);
    }

    #[test]
    fn reservation_constructor_rejects_invalid_input() {
        let new = |number: u64, this: i64, next: i64, entries: Vec<CrlEntry>, expired| {
            CrlReservation::new("lab-root", number, this, next, entries, expired)
        };
        let reject = Err(CrlError::Encoding);
        assert_eq!(
            CrlReservation::new("", 1, THIS_UPDATE, NEXT_UPDATE, vec![], None),
            reject
        );
        assert_eq!(new(0, THIS_UPDATE, NEXT_UPDATE, vec![], None), reject);
        assert_eq!(new(1 << 63, THIS_UPDATE, NEXT_UPDATE, vec![], None), reject);
        assert!(new((1 << 63) - 1, THIS_UPDATE, NEXT_UPDATE, vec![], None).is_ok());
        assert_eq!(new(1, THIS_UPDATE, THIS_UPDATE, vec![], None), reject);
        assert_eq!(new(1, -1, NEXT_UPDATE, vec![], None), reject);
        assert_eq!(
            new(1, THIS_UPDATE, MAX_CRL_TIME_UNIX + 1, vec![], None),
            reject
        );
        assert!(new(1, MIN_CRL_TIME_UNIX, MAX_CRL_TIME_UNIX, vec![], None).is_ok());
        assert_eq!(new(1, THIS_UPDATE, NEXT_UPDATE, vec![], Some(-1)), reject);
        let duplicate = vec![
            entry(&[0x01], RevocationReason::Unspecified, None),
            entry(&[0x01], RevocationReason::KeyCompromise, None),
        ];
        assert_eq!(new(1, THIS_UPDATE, NEXT_UPDATE, duplicate, None), reject);
        // invalidity dates the builder could never encode (finding I2)
        for bad in [-1, -86_400, MAX_CRL_TIME_UNIX + 1] {
            let entries = vec![entry(&[0x01], RevocationReason::KeyCompromise, Some(bad))];
            assert_eq!(new(1, THIS_UPDATE, NEXT_UPDATE, entries, None), reject);
        }
        let mut revoked = entry(&[0x01], RevocationReason::KeyCompromise, None);
        revoked.revoked_at_unix = -1;
        assert_eq!(
            new(1, THIS_UPDATE, NEXT_UPDATE, vec![revoked], None),
            reject
        );
    }

    /// The builder keeps its own checks for a reservation that bypassed the
    /// constructor (only possible inside this module).
    #[test]
    fn builder_rejects_invalid_reservations() {
        let ca = ca();
        let issuer = &root(&ca);
        let raw = |crl_number: u64, next_update_unix: i64, entries: Vec<CrlEntry>| CrlReservation {
            ca_id: "lab-root".to_owned(),
            crl_number,
            this_update_unix: THIS_UPDATE,
            next_update_unix,
            entries,
            expired_certs_on_crl_since_unix: None,
            base_crl_number: None,
            released: Vec::new(),
            freshest_crl_url: None,
        };
        let reject = Err(CrlError::Encoding);
        assert_eq!(
            build_tbs_cert_list(issuer, &raw(0, NEXT_UPDATE, vec![])),
            reject
        );
        assert_eq!(
            build_tbs_cert_list(issuer, &raw(1 << 63, NEXT_UPDATE, vec![])),
            reject
        );
        assert_eq!(
            build_tbs_cert_list(issuer, &raw(1, THIS_UPDATE, vec![])),
            reject
        );
        let duplicate = vec![
            entry(&[0x01], RevocationReason::Unspecified, None),
            entry(&[0x01], RevocationReason::KeyCompromise, None),
        ];
        assert_eq!(
            build_tbs_cert_list(issuer, &raw(1, NEXT_UPDATE, duplicate)),
            reject
        );
        let bad_invalidity = vec![entry(&[0x01], RevocationReason::KeyCompromise, Some(-1))];
        assert_eq!(
            build_tbs_cert_list(issuer, &raw(1, NEXT_UPDATE, bad_invalidity)),
            reject
        );
    }

    #[test]
    fn constructor_sorts_entries_by_serial_bytes() {
        let r = reservation(vec![
            entry(&[0x03], RevocationReason::Unspecified, None),
            entry(&[0x01, 0x00], RevocationReason::CertificateHold, None),
            entry(&[0x01], RevocationReason::KeyCompromise, None),
        ]);
        let order: Vec<&[u8]> = r
            .entries()
            .iter()
            .map(|e| e.serial.as_der_content())
            .collect();
        assert_eq!(order, vec![&[0x01][..], &[0x01, 0x00][..], &[0x03][..]]);
    }

    /// Vectors computed by PostgreSQL 16 with `crl_entry_encoding` (0015):
    ///   SELECT encode(sha256(string_agg(crl_entry_encoding(s, to_timestamp(r),
    ///     c::smallint, to_timestamp(i)), '\x'::bytea ORDER BY s)), 'hex')
    ///   FROM (VALUES ('\x03'::bytea, 1799999900::bigint, 0, NULL::bigint),
    ///                ('\x0100'::bytea, 1799999900, 6, NULL),
    ///                ('\x01'::bytea, 1799999900, 1, 1799995000)) v(s,r,c,i);
    #[test]
    fn entries_sha256_matches_postgres_crl_entry_encoding() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        assert_eq!(
            hex(&reservation(vec![]).entries_sha256()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let r = reservation(vec![
            entry(&[0x03], RevocationReason::Unspecified, None),
            entry(&[0x01, 0x00], RevocationReason::CertificateHold, None),
            entry(
                &[0x01],
                RevocationReason::KeyCompromise,
                Some(1_799_995_000),
            ),
        ]);
        assert_eq!(
            hex(&r.entries_sha256()),
            "089e0132bf631aaf500e8cd97e70fdacee1067316196347e430d786b16e17fce"
        );
        // any change to the entry set changes the digest
        let fewer = reservation(r.entries()[..2].to_vec());
        assert_ne!(fewer.entries_sha256(), r.entries_sha256());
    }

    #[test]
    fn verifier_rejects_every_deviation() {
        let mut ca = ca();
        let r = reservation(vec![
            entry(&[0x01], RevocationReason::KeyCompromise, None),
            entry(&[0x03], RevocationReason::Superseded, None),
        ]);
        let good = issue(&mut ca, &r);
        let verifier = LabCrlVerifier::new(root(&ca));
        verifier.verify(&r, &good).unwrap();
        let reject = Err(CrlError::VerificationFailure);

        // signed by a different key
        let mut other = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let tbs = build_tbs_cert_list(&root(&ca), &r).unwrap();
        let forged = LabCrlAssembler
            .assemble(&tbs, &sign(&mut other, &tbs))
            .unwrap();
        assert_eq!(verifier.verify(&r, &forged), reject);

        // trailing bytes
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(verifier.verify(&r, &trailing), reject);

        // reservation mismatches against an otherwise valid CRL
        let other_number = with(&r, 2, THIS_UPDATE, NEXT_UPDATE, None);
        assert_eq!(verifier.verify(&other_number, &good), reject);
        let other_this = with(&r, 1, THIS_UPDATE + 1, NEXT_UPDATE, None);
        assert_eq!(verifier.verify(&other_this, &good), reject);
        let other_next = with(&r, 1, THIS_UPDATE, NEXT_UPDATE + 1, None);
        assert_eq!(verifier.verify(&other_next, &good), reject);
        let expired = with(&r, 1, THIS_UPDATE, NEXT_UPDATE, Some(THIS_UPDATE));
        assert_eq!(verifier.verify(&expired, &good), reject);
        let fewer_entries = reservation(r.entries()[..1].to_vec());
        assert_eq!(verifier.verify(&fewer_entries, &good), reject);

        // validly signed but wrong content
        let bad_issuer = resigned(&mut ca, &good, |t| {
            t.issuer = Name::from_str("CN=Other Issuer").unwrap();
        });
        assert_eq!(verifier.verify(&r, &bad_issuer), reject);
        let bad_aki = resigned(&mut ca, &good, |t| {
            let exts = t.crl_extensions.as_mut().unwrap();
            exts[0] = x509_extensions::authority_key_identifier(&[7u8; 20]).unwrap();
        });
        assert_eq!(verifier.verify(&r, &bad_aki), reject);
        let bad_number = resigned(&mut ca, &good, |t| {
            let exts = t.crl_extensions.as_mut().unwrap();
            exts[1] = extension_from_der(CRL_NUMBER_OID, vec![0x02, 0x01, 0x02]).unwrap();
        });
        assert_eq!(verifier.verify(&r, &bad_number), reject);
        let bad_this = resigned(&mut ca, &good, |t| {
            t.this_update = rfc5280_time(THIS_UPDATE + 1).unwrap();
        });
        assert_eq!(verifier.verify(&r, &bad_this), reject);
        let bad_next = resigned(&mut ca, &good, |t| {
            t.next_update = Some(rfc5280_time(NEXT_UPDATE + 1).unwrap());
        });
        assert_eq!(verifier.verify(&r, &bad_next), reject);
        let added = resigned(&mut ca, &good, |t| {
            let list = t.revoked_certificates.as_mut().unwrap();
            list.push(as_revoked(&entry(
                &[0x09],
                RevocationReason::Unspecified,
                None,
            )));
        });
        assert_eq!(verifier.verify(&r, &added), reject);
        let removed = resigned(&mut ca, &good, |t| {
            t.revoked_certificates.as_mut().unwrap().pop();
        });
        assert_eq!(verifier.verify(&r, &removed), reject);
        let other_reason = resigned(&mut ca, &good, |t| {
            t.revoked_certificates.as_mut().unwrap()[0] =
                as_revoked(&entry(&[0x01], RevocationReason::Superseded, None));
        });
        assert_eq!(verifier.verify(&r, &other_reason), reject);
        let v1 = resigned(&mut ca, &good, |t| t.version = Version::V1);
        assert_eq!(verifier.verify(&r, &v1), reject);
        let bad_algorithm = resigned(&mut ca, &good, |t| {
            t.signature.oid = ObjectIdentifier::new("1.2.840.10045.4.3.3").unwrap();
        });
        assert_eq!(verifier.verify(&r, &bad_algorithm), reject);
    }

    /// The issuer certificate with extension `oid` removed and, if given,
    /// `replacement` appended. Its own signature is not re-made: only the CRL
    /// builder and verifier read these fields.
    fn issuer_with(cert: &Certificate, oid: &str, replacement: Option<Extension>) -> Certificate {
        let mut cert = cert.clone();
        let exts = cert.tbs_certificate.extensions.as_mut().unwrap();
        exts.retain(|e| e.extn_id.to_string() != oid);
        exts.extend(replacement);
        cert
    }

    fn aki_key_id(tbs_der: &[u8]) -> Vec<u8> {
        let tbs = TbsCertList::from_der(tbs_der).unwrap();
        let exts = tbs.crl_extensions.unwrap();
        AuthorityKeyIdentifier::from_der(ext_value(&exts, "2.5.29.35").unwrap())
            .unwrap()
            .key_identifier
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// Regression: the AKI was a hash of the issuer key, which differs from
    /// the issuer's SKI whenever the issuer used another key-id method
    /// (RFC 5280 4.2.1.1 / 4.2.1.2), so path builders could not match it.
    #[test]
    fn aki_is_the_issuer_subject_key_identifier() {
        let ca = ca();
        let r = reservation(vec![]);
        let ski = [0x5a; 20];
        let issuer = issuer_with(
            &root(&ca),
            "2.5.29.14",
            Some(x509_extensions::subject_key_identifier(&ski).unwrap()),
        );
        assert_eq!(aki_key_id(&build_tbs_cert_list(&issuer, &r).unwrap()), ski);
    }

    #[test]
    fn issuer_without_subject_key_identifier_is_refused() {
        let ca = ca();
        let issuer = issuer_with(&root(&ca), "2.5.29.14", None);
        assert_eq!(
            build_tbs_cert_list(&issuer, &reservation(vec![])),
            Err(CrlError::Encoding)
        );
    }

    fn key_usage(usages: KeyUsage) -> Extension {
        Extension {
            extn_id: ObjectIdentifier::new("2.5.29.15").unwrap(),
            critical: true,
            extn_value: OctetString::new(usages.to_der().unwrap()).unwrap(),
        }
    }

    /// Regression: issuers that may not sign CRLs (RFC 5280 4.2.1.3: no
    /// keyUsage cRLSign) or whose key is not a P-256 key were accepted by the
    /// builder and, with a valid signature, by the verifier.
    #[test]
    fn issuer_must_hold_crl_sign_and_a_p256_key() {
        let mut ca = ca();
        let r = reservation(vec![]);
        let good = issue(&mut ca, &r);
        let root = &root(&ca);
        let cert_sign_only = issuer_with(
            root,
            "2.5.29.15",
            Some(key_usage(KeyUsage(KeyUsages::KeyCertSign.into()))),
        );
        let no_key_usage = issuer_with(root, "2.5.29.15", None);
        let mut p384 = root.clone();
        p384.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters =
            Some(Any::encode_from(&ObjectIdentifier::new("1.3.132.0.34").unwrap()).unwrap());
        let mut two_key_usages = root.clone();
        two_key_usages
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(key_usage(KeyUsage(KeyUsages::CRLSign.into())));
        for issuer in [cert_sign_only, no_key_usage, p384, two_key_usages] {
            assert_eq!(build_tbs_cert_list(&issuer, &r), Err(CrlError::Encoding));
            assert_eq!(
                LabCrlVerifier::new(issuer).verify(&r, &good),
                Err(CrlError::VerificationFailure)
            );
        }
        LabCrlVerifier::new(root.clone()).verify(&r, &good).unwrap();
    }

    /// Issuer with a fixed subject and SKI; only those two fields, its P-256
    /// key parameters and keyUsage reach the TBS builder.
    fn golden_issuer() -> Certificate {
        let mut issuer = issuer_with(
            &root(&ca()),
            "2.5.29.14",
            Some(x509_extensions::subject_key_identifier(&[0x5a; 20]).unwrap()),
        );
        issuer.tbs_certificate.subject = Name::from_str("CN=Golden Lab Root").unwrap();
        issuer
    }

    fn golden_reservation() -> CrlReservation {
        let at = |s: &[u8], reason, revoked, invalidity| CrlEntry {
            serial: serial(s),
            revoked_at_unix: revoked,
            reason,
            invalidity_at_unix: invalidity,
        };
        CrlReservation::new(
            "golden",
            258,
            THIS_UPDATE,
            NEXT_UPDATE,
            vec![
                at(
                    &[0x00, 0x80, 0x01],
                    RevocationReason::CertificateHold,
                    THIS_UPDATE - 60,
                    None,
                ),
                at(
                    &[0x01],
                    RevocationReason::KeyCompromise,
                    THIS_UPDATE - 120,
                    Some(THIS_UPDATE - 3600),
                ),
                at(
                    &[0x7f],
                    RevocationReason::Unspecified,
                    THIS_UPDATE - 180,
                    None,
                ),
            ],
            Some(1_700_000_000),
        )
        .unwrap()
    }

    /// TBSCertList for `golden_reservation`, decoded with `openssl asn1parse`
    /// when frozen: v2, ecdsa-with-SHA256, CN=Golden Lab Root,
    /// 270115080000Z / 270122080000Z, entries in serial-byte order
    /// 00 80 01 (hold, reasonCode 6), 01 (keyCompromise + invalidityDate
    /// 20270115070000Z), 7f (unspecified: no reasonCode); non-critical AKI
    /// keyIdentifier 5a x 20, CRL Number 258, ExpiredCertsOnCRL
    /// 20231114221320Z. Any byte change in the builder must be deliberate.
    const GOLDEN_TBS_HEX: &str = concat!(
        "3082010b020101300a06082a8648ce3d040302301a3118301606035504030c0f",
        "476f6c64656e204c616220526f6f74170d3237303131353038303030305a170d",
        "3237303132323038303030305a307430220203008001170d3237303131353037",
        "353930305a300c300a0603551d1504030a0106303a020101170d323730313135",
        "3037353830305a3026300a0603551d1504030a010130180603551d180411180f",
        "32303237303131353037303030305a301202017f170d32373031313530373537",
        "30305aa04a3048301f0603551d230418301680145a5a5a5a5a5a5a5a5a5a5a5a",
        "5a5a5a5a5a5a5a5a300b0603551d1404040202010230180603551d3c0411180f",
        "32303233313131343232313332305a",
    );

    #[test]
    fn tbs_matches_the_golden_vector() {
        let tbs = build_tbs_cert_list(&golden_issuer(), &golden_reservation()).unwrap();
        let hex: String = tbs.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, GOLDEN_TBS_HEX);
    }

    /// RFC 5280 4.1.2.2: a serial whose first content octet has the high bit
    /// set is encoded with a leading 00 and stays positive in the CRL.
    #[test]
    fn high_bit_serial_is_encoded_positive_and_verifies() {
        let mut ca = ca();
        let r = reservation(vec![entry(
            &[0x00, 0x80, 0x01],
            RevocationReason::KeyCompromise,
            None,
        )]);
        let der = issue(&mut ca, &r);
        let list = CertificateList::from_der(&der).unwrap();
        let revoked = list.tbs_cert_list.revoked_certificates.unwrap();
        assert_eq!(revoked[0].serial_number.as_bytes(), &[0x00, 0x80, 0x01]);
        LabCrlVerifier::new(root(&ca)).verify(&r, &der).unwrap();
    }

    /// Regression: an expired or not-yet-valid issuer, or one without
    /// basicConstraints cA=TRUE, was accepted by the builder and the verifier.
    #[test]
    fn issuer_must_be_a_ca_valid_at_this_update() {
        let mut ca = ca();
        let r = reservation(vec![]);
        let good = issue(&mut ca, &r);
        let valid = root(&ca);
        let mut expired = valid.clone();
        expired.tbs_certificate.validity.not_after = rfc5280_time(THIS_UPDATE - 1).unwrap();
        let mut not_yet = valid.clone();
        not_yet.tbs_certificate.validity.not_before = rfc5280_time(THIS_UPDATE + 1).unwrap();
        let no_constraints = issuer_with(&valid, "2.5.29.19", None);
        let not_ca = issuer_with(
            &valid,
            "2.5.29.19",
            Some(Extension {
                extn_id: ObjectIdentifier::new("2.5.29.19").unwrap(),
                critical: true,
                extn_value: OctetString::new(
                    x509_cert::ext::pkix::BasicConstraints {
                        ca: false,
                        path_len_constraint: None,
                    }
                    .to_der()
                    .unwrap(),
                )
                .unwrap(),
            }),
        );
        for issuer in [expired, not_yet, no_constraints, not_ca] {
            assert_eq!(build_tbs_cert_list(&issuer, &r), Err(CrlError::Encoding));
            assert_eq!(
                LabCrlVerifier::new(issuer).verify(&r, &good),
                Err(CrlError::VerificationFailure)
            );
        }
        // boundaries: thisUpdate equal to notBefore or notAfter is accepted
        let mut edge = valid.clone();
        edge.tbs_certificate.validity.not_before = rfc5280_time(THIS_UPDATE).unwrap();
        edge.tbs_certificate.validity.not_after = rfc5280_time(THIS_UPDATE).unwrap();
        assert!(build_tbs_cert_list(&edge, &r).is_ok());
    }
}
