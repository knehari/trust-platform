//! CRLs of lifecycle-managed laboratory CAs (ADR-0018, Proposed).
//!
//! One deterministic shape, rebuilt from the database's facts by the CRL
//! orchestrator, by the laboratory signer before it signs, and checked
//! again before the CRL is stored:
//! - a v2 CRL, ecdsa-with-SHA256 without parameters, issued by exactly the
//!   CA's registered issuer certificate (its subject as issuer);
//! - thisUpdate and nextUpdate exactly the intent's, in whole seconds;
//! - one entry per revoked serial, ordered by serial content octets, with
//!   its revocation date and, unless unspecified, a non-critical reasonCode
//!   from the laboratory's closed list;
//! - exactly two CRL extensions: authorityKeyIdentifier (the issuer's key
//!   identifier) and cRLNumber.
//!
//! Nothing here holds or uses a private key; signature verification uses
//! the reviewed verifier of `trust-pki-crypto`.

use std::time::SystemTime;

use crate::{application_leaf::issuer_key_identifier, x509_extensions};
use x509_cert::{
    crl::{CertificateList, RevokedCert, TbsCertList},
    der::{
        asn1::{BitString, ObjectIdentifier, OctetString, Uint},
        Decode, Encode,
    },
    ext::{
        pkix::{CrlNumber, CrlReason},
        Extension,
    },
    serial_number::SerialNumber,
    spki::AlgorithmIdentifierOwned,
    time::Time,
    Certificate, Version,
};

const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const CRL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.20");
const REASON_CODE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlError {
    Encoding,
    Issuer,
    Times,
    Entries,
    Reason,
    Mismatch,
    SignatureAlgorithm,
    Signature,
    TbsMismatch,
}

/// One revocation, from the database's records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlEntry {
    /// Positive DER content octets of the serial.
    pub serial: Vec<u8>,
    pub revoked_at: SystemTime,
    pub reason_code: u8,
}

/// What a CRL intent fixes, from trusted records.
pub struct CrlFacts<'a> {
    pub crl_number: u64,
    pub this_update: SystemTime,
    pub next_update: SystemTime,
    pub entries: &'a [CrlEntry],
}

fn ecdsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ECDSA_SHA256,
        parameters: None,
    }
}

fn reason(code: u8) -> Result<CrlReason, CrlError> {
    // The closed list of migration 0030; 0 carries no extension.
    Ok(match code {
        1 => CrlReason::KeyCompromise,
        3 => CrlReason::AffiliationChanged,
        4 => CrlReason::Superseded,
        5 => CrlReason::CessationOfOperation,
        9 => CrlReason::PrivilegeWithdrawn,
        _ => return Err(CrlError::Reason),
    })
}

fn extension<T: Encode>(oid: ObjectIdentifier, value: &T) -> Result<Extension, CrlError> {
    Ok(Extension {
        extn_id: oid,
        critical: false,
        extn_value: OctetString::new(value.to_der().map_err(|_| CrlError::Encoding)?)
            .map_err(|_| CrlError::Encoding)?,
    })
}

fn time(at: SystemTime) -> Result<Time, CrlError> {
    let seconds = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| CrlError::Times)?;
    if seconds.subsec_nanos() != 0 {
        return Err(CrlError::Times);
    }
    Time::try_from(at).map_err(|_| CrlError::Times)
}

/// Builds the TBS of the CRL these facts describe.
pub fn build_crl_tbs(issuer: &Certificate, facts: &CrlFacts<'_>) -> Result<TbsCertList, CrlError> {
    if facts.crl_number == 0 || facts.next_update <= facts.this_update {
        return Err(CrlError::Times);
    }
    let mut entries = facts.entries.to_vec();
    entries.sort_by(|a, b| a.serial.cmp(&b.serial));
    if entries
        .windows(2)
        .any(|pair| pair[0].serial == pair[1].serial)
    {
        return Err(CrlError::Entries);
    }
    let revoked = entries
        .iter()
        .map(|entry| {
            if entry.serial.is_empty() || entry.serial.len() > 20 || entry.serial[0] & 0x80 != 0 {
                return Err(CrlError::Entries);
            }
            if entry.revoked_at > facts.this_update {
                return Err(CrlError::Entries);
            }
            Ok(RevokedCert {
                serial_number: SerialNumber::new(&entry.serial).map_err(|_| CrlError::Entries)?,
                revocation_date: time(entry.revoked_at)?,
                crl_entry_extensions: match entry.reason_code {
                    0 => None,
                    code => Some(vec![extension(REASON_CODE, &reason(code)?)?]),
                },
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let number = Uint::new(&facts.crl_number.to_be_bytes()).map_err(|_| CrlError::Encoding)?;
    let key_id = issuer_key_identifier(issuer).map_err(|_| CrlError::Issuer)?;
    Ok(TbsCertList {
        version: Version::V2,
        signature: ecdsa_sha256(),
        issuer: issuer.tbs_certificate.subject.clone(),
        this_update: time(facts.this_update)?,
        next_update: Some(time(facts.next_update)?),
        revoked_certificates: if revoked.is_empty() {
            None
        } else {
            Some(revoked)
        },
        crl_extensions: Some(vec![
            x509_extensions::authority_key_identifier(&key_id).map_err(|_| CrlError::Issuer)?,
            extension(CRL_NUMBER, &CrlNumber(number))?,
        ]),
    })
}

/// The signer's gate: the TBS is exactly the CRL the facts describe.
pub fn check_crl_tbs(
    issuer: &Certificate,
    facts: &CrlFacts<'_>,
    tbs: &TbsCertList,
) -> Result<(), CrlError> {
    if tbs != &build_crl_tbs(issuer, facts)? {
        return Err(CrlError::Mismatch);
    }
    Ok(())
}

/// Assembles a CRL from exactly the journaled TBS and a signature.
pub fn assemble_crl(tbs_der: &[u8], signature_der: &[u8]) -> Result<Vec<u8>, CrlError> {
    CertificateList {
        tbs_cert_list: TbsCertList::from_der(tbs_der).map_err(|_| CrlError::Encoding)?,
        signature_algorithm: ecdsa_sha256(),
        signature: BitString::from_bytes(signature_der).map_err(|_| CrlError::Encoding)?,
    }
    .to_der()
    .map_err(|_| CrlError::Encoding)
}

/// Verifies an assembled CRL before it is stored: canonical DER, exactly the
/// journaled TBS, the facts, and a signature under the issuer's P-256 key.
pub fn verify_crl(
    issuer: &Certificate,
    facts: &CrlFacts<'_>,
    journaled_tbs_der: &[u8],
    crl_der: &[u8],
) -> Result<CertificateList, CrlError> {
    let crl = CertificateList::from_der(crl_der).map_err(|_| CrlError::Encoding)?;
    if crl.to_der().map_err(|_| CrlError::Encoding)? != crl_der {
        return Err(CrlError::Encoding);
    }
    let tbs_der = crl.tbs_cert_list.to_der().map_err(|_| CrlError::Encoding)?;
    if tbs_der != journaled_tbs_der {
        return Err(CrlError::TbsMismatch);
    }
    if crl.signature_algorithm != ecdsa_sha256() {
        return Err(CrlError::SignatureAlgorithm);
    }
    check_crl_tbs(issuer, facts, &crl.tbs_cert_list)?;
    let issuer_key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(CrlError::Issuer)?;
    let signature = crl.signature.as_bytes().ok_or(CrlError::Signature)?;
    trust_pki_crypto::verify_p256_ecdsa_sha256(issuer_key, &tbs_der, signature)
        .map_err(|_| CrlError::Signature)?;
    Ok(crl)
}

/// Parses `YYYY-MM-DDTHH:MM:SSZ`, the database's rendering of an instant.
pub fn parse_utc_seconds(text: &str) -> Result<SystemTime, CrlError> {
    let date_time = x509_cert::der::DateTime::new(
        text.get(0..4)
            .and_then(|v| v.parse().ok())
            .ok_or(CrlError::Times)?,
        text.get(5..7)
            .and_then(|v| v.parse().ok())
            .ok_or(CrlError::Times)?,
        text.get(8..10)
            .and_then(|v| v.parse().ok())
            .ok_or(CrlError::Times)?,
        text.get(11..13)
            .and_then(|v| v.parse().ok())
            .ok_or(CrlError::Times)?,
        text.get(14..16)
            .and_then(|v| v.parse().ok())
            .ok_or(CrlError::Times)?,
        text.get(17..19)
            .and_then(|v| v.parse().ok())
            .ok_or(CrlError::Times)?,
    )
    .map_err(|_| CrlError::Times)?;
    let expected = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date_time.year(),
        date_time.month(),
        date_time.day(),
        date_time.hour(),
        date_time.minutes(),
        date_time.seconds()
    );
    if expected != text {
        return Err(CrlError::Times);
    }
    Ok(date_time.to_system_time())
}

#[cfg(all(test, feature = "lab-software"))]
mod tests {
    use super::*;
    use crate::lab_ca::EphemeralLabCa;
    use crate::orchestrator::ExternalSigner;
    use std::time::Duration;
    use trust_pki_crypto::{lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider};

    fn facts_at(now: SystemTime, entries: &[CrlEntry]) -> CrlFacts<'_> {
        CrlFacts {
            crl_number: 7,
            this_update: now,
            next_update: now + Duration::from_secs(7 * 86400),
            entries,
        }
    }

    fn whole_second(at: SystemTime) -> SystemTime {
        let seconds = at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn a_built_crl_passes_the_gate_and_verifies_once_signed() {
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let issuer = ca.root_certificate().clone();
        let now = whole_second(SystemTime::now());
        let entries = vec![
            CrlEntry {
                serial: vec![0x42, 0x01],
                revoked_at: now - Duration::from_secs(60),
                reason_code: 1,
            },
            CrlEntry {
                serial: vec![0x41, 0x01],
                revoked_at: now - Duration::from_secs(30),
                reason_code: 0,
            },
        ];
        let facts = facts_at(now, &entries);
        let tbs = build_crl_tbs(&issuer, &facts).unwrap();
        // Ordered by serial; the unspecified reason carries no extension.
        let revoked = tbs.revoked_certificates.as_ref().unwrap();
        assert_eq!(revoked[0].serial_number.as_bytes(), &[0x41, 0x01]);
        assert!(revoked[0].crl_entry_extensions.is_none());
        assert_eq!(
            revoked[1].crl_entry_extensions.as_ref().unwrap()[0].extn_id,
            REASON_CODE
        );
        assert_eq!(check_crl_tbs(&issuer, &facts, &tbs), Ok(()));
        let tbs_der = tbs.to_der().unwrap();
        let key_ref = ca.lab_signer_key_ref().to_owned();
        let signature = ca.sign_once(&key_ref, "crl-test", &tbs_der).unwrap();
        let der = assemble_crl(&tbs_der, &signature).unwrap();
        assert!(verify_crl(&issuer, &facts, &tbs_der, &der).is_ok());

        let other = EphemeralP256Signer::generate("other").unwrap();
        let forged = other
            .sign(
                other.key_ref(),
                SignatureAlgorithm::EcdsaP256Sha256,
                &tbs_der,
            )
            .unwrap();
        let forged_der = assemble_crl(&tbs_der, &forged).unwrap();
        assert_eq!(
            verify_crl(&issuer, &facts, &tbs_der, &forged_der).unwrap_err(),
            CrlError::Signature
        );
        assert_eq!(
            verify_crl(&issuer, &facts, &tbs_der[1..], &der).unwrap_err(),
            CrlError::TbsMismatch
        );
        // The same signed CRL against other facts: one entry fewer.
        let fewer = facts_at(now, &entries[..1]);
        assert_eq!(
            verify_crl(&issuer, &fewer, &tbs_der, &der).unwrap_err(),
            CrlError::Mismatch
        );
    }

    #[test]
    fn the_gate_refuses_every_departure_from_the_facts() {
        let ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let issuer = ca.root_certificate().clone();
        let now = whole_second(SystemTime::now());
        let entries = vec![CrlEntry {
            serial: vec![0x41],
            revoked_at: now,
            reason_code: 4,
        }];
        let facts = facts_at(now, &entries);
        let good = build_crl_tbs(&issuer, &facts).unwrap();
        let refuse = |edit: &dyn Fn(&mut TbsCertList)| {
            let mut tbs = good.clone();
            edit(&mut tbs);
            check_crl_tbs(&issuer, &facts, &tbs).unwrap_err()
        };
        assert_eq!(refuse(&|t| t.version = Version::V1), CrlError::Mismatch);
        assert_eq!(
            refuse(&|t| t.revoked_certificates = None),
            CrlError::Mismatch
        );
        assert_eq!(refuse(&|t| t.next_update = None), CrlError::Mismatch);
        assert_eq!(
            refuse(&|t| t
                .crl_extensions
                .as_mut()
                .unwrap()
                .pop()
                .map(|_| ())
                .unwrap()),
            CrlError::Mismatch
        );
        assert_eq!(
            refuse(&|t| t.signature.oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3")),
            CrlError::Mismatch
        );
        // Facts the laboratory never signs.
        let bad = |entries: &[CrlEntry], number: u64| {
            build_crl_tbs(
                &issuer,
                &CrlFacts {
                    crl_number: number,
                    ..facts_at(now, entries)
                },
            )
            .unwrap_err()
        };
        let entry = |serial: Vec<u8>, at: SystemTime, code: u8| CrlEntry {
            serial,
            revoked_at: at,
            reason_code: code,
        };
        assert_eq!(bad(&[entry(vec![0x41], now, 2)], 1), CrlError::Reason);
        assert_eq!(bad(&[entry(vec![0x41], now, 6)], 1), CrlError::Reason);
        assert_eq!(
            bad(&[entry(vec![0x41], now, 0), entry(vec![0x41], now, 1)], 1),
            CrlError::Entries
        );
        assert_eq!(bad(&[entry(vec![0x81], now, 0)], 1), CrlError::Entries);
        assert_eq!(
            bad(&[entry(vec![0x41], now + Duration::from_secs(1), 0)], 1),
            CrlError::Entries
        );
        assert_eq!(
            bad(
                &[entry(
                    vec![0x41],
                    now + Duration::from_millis(1) - Duration::from_secs(1),
                    0
                )],
                1
            ),
            CrlError::Times
        );
        assert_eq!(bad(&[], 0), CrlError::Times);
        assert!(build_crl_tbs(
            &issuer,
            &CrlFacts {
                next_update: now,
                ..facts_at(now, &[])
            }
        )
        .is_err());
        // An empty CRL has no revokedCertificates field at all.
        assert!(build_crl_tbs(&issuer, &facts_at(now, &[]))
            .unwrap()
            .revoked_certificates
            .is_none());
    }

    #[test]
    fn database_instants_parse_exactly() {
        let at = parse_utc_seconds("2026-11-08T01:02:03Z").unwrap();
        assert_eq!(
            at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            1794099723
        );
        for bad in [
            "2026-11-08 01:02:03Z",
            "2026-11-08T01:02:03",
            "2026-13-08T01:02:03Z",
            "2026-11-08T01:02:03.5Z",
        ] {
            assert_eq!(
                parse_utc_seconds(bad).unwrap_err(),
                CrlError::Times,
                "{bad}"
            );
        }
    }
}
