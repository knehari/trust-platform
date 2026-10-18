//! CRL v2 (RFC 5280 section 5) TBSCertList builder and independent lab verifier.
//!
//! Lab only. The builder produces the exact TBS bytes that are journaled
//! before signing; the verifier re-parses the finished CRL, requires
//! canonical DER, rebuilds the expected TBS from the reservation and checks
//! the ECDSA P-256/SHA-256 signature with the issuer certificate's key.
//! Nothing here is a production CRL publication path.

use crate::revocation::RevocationReason;
use crate::serial::SerialNumber;
use crate::x509_extensions;
use sha2::{Digest, Sha256};
use x509_cert::{
    crl::{RevokedCert, TbsCertList},
    der::{
        asn1::{GeneralizedTime, ObjectIdentifier, OctetString, Uint, UtcTime},
        DateTime, Encode,
    },
    ext::{
        pkix::{crl::CrlNumber, CrlReason},
        Extension,
    },
    serial_number::SerialNumber as X509Serial,
    spki::AlgorithmIdentifierOwned,
    time::Time,
    Certificate, Version,
};

#[cfg(feature = "lab-software")]
use x509_cert::{crl::CertificateList, der::Decode};

const INVALIDITY_DATE_OID: &str = "2.5.29.24";
const EXPIRED_CERTS_ON_CRL_OID: &str = "2.5.29.60";
const CRL_NUMBER_OID: &str = "2.5.29.20";
const REASON_CODE_OID: &str = "2.5.29.21";
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlEntry {
    pub serial: SerialNumber,
    pub revoked_at_unix: i64,
    pub reason: RevocationReason,
    pub invalidity_at_unix: Option<i64>,
}

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
        })
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
    pub fn entries_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for entry in &self.entries {
            let serial = entry.serial.as_der_content();
            // Serials are at most 20 octets, so the length always fits.
            let len = i32::try_from(serial.len()).unwrap_or(i32::MAX);
            hasher.update(len.to_be_bytes());
            hasher.update(serial);
            hasher.update(entry.revoked_at_unix.to_be_bytes());
            hasher.update(entry.reason.code().to_be_bytes());
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

fn revoked_cert(entry: &CrlEntry) -> Result<RevokedCert, CrlError> {
    let mut extensions = Vec::new();
    // RFC 5280 5.3.1: reasonCode unspecified SHOULD be omitted.
    if entry.reason != RevocationReason::Unspecified {
        extensions.push(extension_from_der(
            REASON_CODE_OID,
            crl_reason(entry.reason)
                .to_der()
                .map_err(|_| CrlError::Encoding)?,
        )?);
    }
    if let Some(invalidity) = entry.invalidity_at_unix {
        extensions.push(generalized_time_extension(INVALIDITY_DATE_OID, invalidity)?);
    }
    Ok(RevokedCert {
        serial_number: X509Serial::new(entry.serial.as_der_content())
            .map_err(|_| CrlError::Encoding)?,
        revocation_date: rfc5280_time(entry.revoked_at_unix)?,
        crl_entry_extensions: if extensions.is_empty() {
            None
        } else {
            Some(extensions)
        },
    })
}

/// Issuer name and authority key identifier come from `issuer`. Entries are
/// sorted by serial bytes; duplicate serials, a non-increasing validity
/// window or an out-of-range CRL number are rejected.
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
    let key_id = x509_extensions::key_identifier(&issuer.tbs_certificate.subject_public_key_info)
        .map_err(|_| CrlError::Encoding)?;
    let number_bytes = reservation.crl_number.to_be_bytes();
    let first = number_bytes
        .iter()
        .position(|b| *b != 0)
        .ok_or(CrlError::Encoding)?;
    let number = CrlNumber(Uint::new(&number_bytes[first..]).map_err(|_| CrlError::Encoding)?);
    let mut crl_extensions = vec![
        x509_extensions::authority_key_identifier(&key_id).map_err(|_| CrlError::Encoding)?,
        extension_from_der(
            CRL_NUMBER_OID,
            number.to_der().map_err(|_| CrlError::Encoding)?,
        )?,
    ];
    if let Some(since) = reservation.expired_certs_on_crl_since_unix {
        crl_extensions.push(generalized_time_extension(EXPIRED_CERTS_ON_CRL_OID, since)?);
    }

    let mut entries: Vec<&CrlEntry> = reservation.entries.iter().collect();
    entries.sort_by(|a, b| a.serial.cmp(&b.serial));
    if entries
        .windows(2)
        .any(|pair| pair[0].serial == pair[1].serial)
    {
        return Err(CrlError::Encoding);
    }
    let revoked = entries
        .into_iter()
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
        let spki = &self.issuer.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid.to_string() != "1.2.840.10045.2.1" {
            return Err(fail);
        }
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
}

#[cfg(all(test, feature = "lab-software"))]
mod tests {
    use super::*;
    use crate::lab_ca::EphemeralLabCa;
    use crate::orchestrator::ExternalSigner;
    use std::str::FromStr;
    use x509_cert::{der::asn1::BitString, ext::pkix::AuthorityKeyIdentifier, name::Name};

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
        let tbs = build_tbs_cert_list(ca.root_certificate(), r).unwrap();
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

    fn ext_value<'a>(exts: &'a [Extension], oid: &str) -> Option<&'a [u8]> {
        exts.iter()
            .find(|e| e.extn_id.to_string() == oid)
            .map(|e| e.extn_value.as_bytes())
    }

    fn ca() -> EphemeralLabCa {
        EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap()
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
    fn empty_crl_has_no_revoked_list_and_verifies() {
        let mut ca = ca();
        let r = reservation(vec![]);
        let der = issue(&mut ca, &r);
        let list = CertificateList::from_der(&der).unwrap();
        assert!(list.tbs_cert_list.revoked_certificates.is_none());
        assert_eq!(list.tbs_cert_list.version, Version::V2);
        assert!(matches!(list.tbs_cert_list.this_update, Time::UtcTime(_)));
        LabCrlVerifier::new(ca.root_certificate().clone())
            .verify(&r, &der)
            .unwrap();
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
        LabCrlVerifier::new(ca.root_certificate().clone())
            .verify(&r, &der)
            .unwrap();
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
        LabCrlVerifier::new(ca.root_certificate().clone())
            .verify(&r, &der)
            .unwrap();
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
        let issuer = ca.root_certificate();
        let raw = |crl_number: u64, next_update_unix: i64, entries: Vec<CrlEntry>| CrlReservation {
            ca_id: "lab-root".to_owned(),
            crl_number,
            this_update_unix: THIS_UPDATE,
            next_update_unix,
            entries,
            expired_certs_on_crl_since_unix: None,
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
        let verifier = LabCrlVerifier::new(ca.root_certificate().clone());
        verifier.verify(&r, &good).unwrap();
        let reject = Err(CrlError::VerificationFailure);

        // signed by a different key
        let mut other = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let tbs = build_tbs_cert_list(ca.root_certificate(), &r).unwrap();
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
            list.push(revoked_cert(&entry(&[0x09], RevocationReason::Unspecified, None)).unwrap());
        });
        assert_eq!(verifier.verify(&r, &added), reject);
        let removed = resigned(&mut ca, &good, |t| {
            t.revoked_certificates.as_mut().unwrap().pop();
        });
        assert_eq!(verifier.verify(&r, &removed), reject);
        let other_reason = resigned(&mut ca, &good, |t| {
            t.revoked_certificates.as_mut().unwrap()[0] =
                revoked_cert(&entry(&[0x01], RevocationReason::Superseded, None)).unwrap();
        });
        assert_eq!(verifier.verify(&r, &other_reason), reject);
        let v1 = resigned(&mut ca, &good, |t| t.version = Version::V1);
        assert_eq!(verifier.verify(&r, &v1), reject);
        let bad_algorithm = resigned(&mut ca, &good, |t| {
            t.signature.oid = ObjectIdentifier::new("1.2.840.10045.4.3.3").unwrap();
        });
        assert_eq!(verifier.verify(&r, &bad_algorithm), reject);
    }
}
