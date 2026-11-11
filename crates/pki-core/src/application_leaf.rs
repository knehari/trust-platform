//! Server certificates for approved applications (ADR-0017, Proposed).
//!
//! One deterministic shape, built by the issuance orchestrator and checked
//! again, independently, by the laboratory signer before it signs and by the
//! orchestrator before it persists:
//! - X.509 v3, ecdsa-with-SHA256 without parameters, issued by exactly the
//!   CA's registered issuer certificate (its subject as issuer, its key
//!   identifier as authority key identifier);
//! - the subject `CN=<approved name>` and the key of the verified CSR;
//! - the reserved serial, and a validity of exactly the approved days that
//!   starts now and ends no later than the issuer certificate;
//! - exactly these extensions: basicConstraints (critical, not a CA),
//!   keyUsage (critical, digitalSignature), extendedKeyUsage serverAuth,
//!   subjectAltName with exactly the approved DNS names in order,
//!   subjectKeyIdentifier and authorityKeyIdentifier, then, when the CA
//!   publishes its CRLs (ADR-0019), cRLDistributionPoints with exactly the
//!   one URL its signing intent was journaled under.
//!
//! Nothing here holds or uses a private key. It builds and checks
//! structures; signature verification uses the reviewed verifier of
//! `trust-pki-crypto`.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use crate::x509_extensions;
use x509_cert::{
    der::{
        asn1::{BitString, Ia5String, ObjectIdentifier, OctetString},
        Decode, Encode,
    },
    ext::{
        pkix::{
            crl::{dp::DistributionPoint, CrlDistributionPoints},
            name::{DistributionPointName, GeneralName},
            BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
        },
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
    Certificate, TbsCertificate, Version,
};

const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// The optional extensions a profile may allow and an authorization may add
/// (ADR-0028). A closed catalogue: the CA encodes each one itself and never
/// copies an extension from the CSR.
pub const OPTIONAL_EXTENSIONS: [&str; 1] = ["client-auth"];

/// Whether `names` are distinct, known optional extensions, in catalogue
/// order (the canonical order every signed claim uses).
pub fn optional_extensions_valid(names: &[String]) -> bool {
    let mut position = 0;
    names.iter().all(|name| {
        match OPTIONAL_EXTENSIONS[position..]
            .iter()
            .position(|known| known == name)
        {
            Some(offset) => {
                position += offset + 1;
                true
            }
            None => false,
        }
    })
}
/// How far the start of validity may be from the checking clock.
pub const START_SKEW: Duration = Duration::from_secs(5 * 60);
const DAY: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafError {
    Encoding,
    Version,
    SignatureAlgorithm,
    Issuer,
    Subject,
    SubjectKey,
    Serial,
    Validity,
    Extensions,
    Signature,
    TbsMismatch,
}

/// What the approved application allows, from trusted records.
pub struct LeafFacts<'a> {
    pub subject_cn: &'a str,
    pub dns_names: &'a [String],
    pub subject_public_key: &'a SubjectPublicKeyInfoOwned,
    pub validity_days: u32,
    /// Positive DER content octets of the reserved serial.
    pub serial: &'a [u8],
    /// The CRL URL the signing intent was journaled under, when the CA
    /// publishes its CRLs.
    pub crl_distribution_point: Option<&'a str>,
    /// `client-auth`: id-kp-clientAuth is added to the extended key usage
    /// beside serverAuth, when the authorization asked for it (ADR-0028).
    pub client_auth: bool,
}

/// An http(s) URL of printable ASCII without spaces, as the database builds.
fn valid_distribution_point(url: &str) -> bool {
    (url.starts_with("http://") || url.starts_with("https://"))
        && url.len() <= 300
        && url.bytes().all(|b| b.is_ascii_graphic())
}

fn ecdsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ECDSA_SHA256,
        parameters: None,
    }
}

fn extension<T: Encode>(
    oid: ObjectIdentifier,
    critical: bool,
    value: &T,
) -> Result<Extension, LeafError> {
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value.to_der().map_err(|_| LeafError::Encoding)?)
            .map_err(|_| LeafError::Encoding)?,
    })
}

/// The issuer's key identifier: its own subjectKeyIdentifier when it has a
/// 20-byte one (as OpenSSL writes), otherwise derived from its key.
pub(crate) fn issuer_key_identifier(issuer: &Certificate) -> Result<[u8; 20], LeafError> {
    let declared = issuer
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|extension| extension.extn_id == SUBJECT_KEY_ID)
        .and_then(|extension| OctetString::from_der(extension.extn_value.as_bytes()).ok())
        .and_then(|id| <[u8; 20]>::try_from(id.as_bytes()).ok());
    match declared {
        Some(id) => Ok(id),
        None => x509_extensions::key_identifier(&issuer.tbs_certificate.subject_public_key_info)
            .map_err(|_| LeafError::Issuer),
    }
}

/// The exact extensions a leaf for these facts carries, in order.
fn expected_extensions(
    issuer: &Certificate,
    facts: &LeafFacts<'_>,
) -> Result<Vec<Extension>, LeafError> {
    let names = facts
        .dns_names
        .iter()
        .map(|name| {
            Ia5String::new(name)
                .map(GeneralName::DnsName)
                .map_err(|_| LeafError::Subject)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let subject_key_id = x509_extensions::key_identifier(facts.subject_public_key)
        .map_err(|_| LeafError::SubjectKey)?;
    Ok([
        extension(
            BASIC_CONSTRAINTS,
            true,
            &BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
        )?,
        extension(
            KEY_USAGE,
            true,
            &KeyUsage(KeyUsages::DigitalSignature.into()),
        )?,
        extension(
            EXTENDED_KEY_USAGE,
            false,
            &ExtendedKeyUsage(if facts.client_auth {
                vec![SERVER_AUTH, CLIENT_AUTH]
            } else {
                vec![SERVER_AUTH]
            }),
        )?,
        extension(SUBJECT_ALT_NAME, false, &SubjectAltName(names))?,
        x509_extensions::subject_key_identifier(&subject_key_id)
            .map_err(|_| LeafError::Extensions)?,
        x509_extensions::authority_key_identifier(&issuer_key_identifier(issuer)?)
            .map_err(|_| LeafError::Extensions)?,
    ]
    .into_iter()
    .chain(match facts.crl_distribution_point {
        None => None,
        Some(url) => Some(extension(
            CRL_DISTRIBUTION_POINTS,
            false,
            &CrlDistributionPoints(vec![DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::UniformResourceIdentifier(
                        Ia5String::new(url).map_err(|_| LeafError::Extensions)?,
                    ),
                ])),
                reasons: None,
                crl_issuer: None,
            }]),
        )?),
    })
    .collect())
}

fn subject_name(common_name: &str) -> Result<Name, LeafError> {
    if common_name.is_empty() || common_name.contains([',', '+', '=', '"', '\\', '<', '>', ';']) {
        return Err(LeafError::Subject);
    }
    Name::from_str(&format!("CN={common_name}")).map_err(|_| LeafError::Subject)
}

fn checked_facts(facts: &LeafFacts<'_>) -> Result<(), LeafError> {
    if facts.validity_days == 0
        || facts.validity_days > 825
        || facts.dns_names.is_empty()
        || !facts.dns_names.iter().any(|name| name == facts.subject_cn)
    {
        return Err(LeafError::Validity);
    }
    if facts.serial.is_empty() || facts.serial.len() > 20 || facts.serial[0] & 0x80 != 0 {
        return Err(LeafError::Serial);
    }
    if facts
        .crl_distribution_point
        .is_some_and(|url| !valid_distribution_point(url))
    {
        return Err(LeafError::Extensions);
    }
    Ok(())
}

/// Builds the TBS of the leaf for `facts`, valid from `not_before`.
pub fn build_server_leaf_tbs(
    issuer: &Certificate,
    facts: &LeafFacts<'_>,
    not_before: SystemTime,
) -> Result<TbsCertificate, LeafError> {
    checked_facts(facts)?;
    let not_after = not_before + Duration::from_secs(u64::from(facts.validity_days) * DAY);
    if not_after > issuer.tbs_certificate.validity.not_after.to_system_time() {
        return Err(LeafError::Validity);
    }
    let validity = Validity {
        not_before: x509_cert::time::Time::try_from(not_before).map_err(|_| LeafError::Validity)?,
        not_after: x509_cert::time::Time::try_from(not_after).map_err(|_| LeafError::Validity)?,
    };
    Ok(TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(facts.serial).map_err(|_| LeafError::Serial)?,
        signature: ecdsa_sha256(),
        issuer: issuer.tbs_certificate.subject.clone(),
        validity,
        subject: subject_name(facts.subject_cn)?,
        subject_public_key_info: facts.subject_public_key.clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(expected_extensions(issuer, facts)?),
    })
}

/// Checks a TBS against the facts, independently of how it was built: the
/// gate the signer applies before signing. `now` bounds the start of
/// validity to [now - START_SKEW, now + START_SKEW].
pub fn check_server_leaf_tbs(
    issuer: &Certificate,
    facts: &LeafFacts<'_>,
    tbs: &TbsCertificate,
    now: SystemTime,
) -> Result<(), LeafError> {
    checked_facts(facts)?;
    if tbs.version != Version::V3
        || tbs.issuer_unique_id.is_some()
        || tbs.subject_unique_id.is_some()
    {
        return Err(LeafError::Version);
    }
    if tbs.signature != ecdsa_sha256() {
        return Err(LeafError::SignatureAlgorithm);
    }
    if tbs.issuer != issuer.tbs_certificate.subject {
        return Err(LeafError::Issuer);
    }
    if tbs.subject != subject_name(facts.subject_cn)? {
        return Err(LeafError::Subject);
    }
    if &tbs.subject_public_key_info != facts.subject_public_key {
        return Err(LeafError::SubjectKey);
    }
    if tbs.serial_number.as_bytes() != facts.serial {
        return Err(LeafError::Serial);
    }
    let not_before = tbs.validity.not_before.to_system_time();
    let not_after = tbs.validity.not_after.to_system_time();
    if not_after.duration_since(not_before).ok()
        != Some(Duration::from_secs(u64::from(facts.validity_days) * DAY))
        || not_before > now + START_SKEW
        || not_before + START_SKEW < now
        || not_before < issuer.tbs_certificate.validity.not_before.to_system_time()
        || not_after > issuer.tbs_certificate.validity.not_after.to_system_time()
    {
        return Err(LeafError::Validity);
    }
    if tbs.extensions.as_deref() != Some(expected_extensions(issuer, facts)?.as_slice()) {
        return Err(LeafError::Extensions);
    }
    Ok(())
}

/// Assembles a certificate from exactly the journaled TBS and a signature.
pub fn assemble_certificate(tbs_der: &[u8], signature_der: &[u8]) -> Result<Vec<u8>, LeafError> {
    let tbs = TbsCertificate::from_der(tbs_der).map_err(|_| LeafError::Encoding)?;
    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_sha256(),
        signature: BitString::from_bytes(signature_der).map_err(|_| LeafError::Encoding)?,
    };
    certificate.to_der().map_err(|_| LeafError::Encoding)
}

/// Verifies an assembled certificate before it is persisted: its TBS is
/// exactly the journaled one, it passes `check_server_leaf_tbs`, and its
/// signature verifies under the issuer certificate's P-256 key.
pub fn verify_server_leaf(
    issuer: &Certificate,
    facts: &LeafFacts<'_>,
    journaled_tbs_der: &[u8],
    certificate_der: &[u8],
    now: SystemTime,
) -> Result<Certificate, LeafError> {
    let certificate = Certificate::from_der(certificate_der).map_err(|_| LeafError::Encoding)?;
    if certificate.to_der().map_err(|_| LeafError::Encoding)? != certificate_der {
        return Err(LeafError::Encoding);
    }
    let tbs_der = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| LeafError::Encoding)?;
    if tbs_der != journaled_tbs_der {
        return Err(LeafError::TbsMismatch);
    }
    if certificate.signature_algorithm != ecdsa_sha256() {
        return Err(LeafError::SignatureAlgorithm);
    }
    check_server_leaf_tbs(issuer, facts, &certificate.tbs_certificate, now)?;
    let issuer_key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(LeafError::Issuer)?;
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or(LeafError::Signature)?;
    trust_pki_crypto::verify_p256_ecdsa_sha256(issuer_key, &tbs_der, signature)
        .map_err(|_| LeafError::Signature)?;
    Ok(certificate)
}

#[cfg(all(test, feature = "lab-software"))]
mod tests {
    use super::*;
    use crate::lab_ca::EphemeralLabCa;
    use crate::orchestrator::ExternalSigner;
    use trust_pki_crypto::{lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider};

    fn subject_key() -> SubjectPublicKeyInfoOwned {
        let signer = EphemeralP256Signer::generate("leaf-subject").unwrap();
        SubjectPublicKeyInfoOwned::from_der(&signer.public_key_spki_der(signer.key_ref()).unwrap())
            .unwrap()
    }

    fn names() -> Vec<String> {
        vec!["www.lab.invalid".into(), "api.lab.invalid".into()]
    }

    #[test]
    fn optional_extensions_come_from_the_closed_catalogue_in_order() {
        assert!(optional_extensions_valid(&[]));
        assert!(optional_extensions_valid(&["client-auth".to_owned()]));
        for invalid in [
            vec!["client-auth".to_owned(), "client-auth".to_owned()],
            vec!["Client-Auth".to_owned()],
            vec!["1.3.6.1.5.5.7.3.2".to_owned()],
            vec!["ocsp-must-staple".to_owned()],
        ] {
            assert!(!optional_extensions_valid(&invalid), "{invalid:?}");
        }
    }

    #[test]
    fn client_auth_adds_the_usage_and_the_gate_requires_exactly_it() {
        let ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let issuer = ca.root_certificate().clone();
        let key = subject_key();
        let names = names();
        let facts = LeafFacts {
            subject_cn: "www.lab.invalid",
            dns_names: &names,
            subject_public_key: &key,
            validity_days: 1,
            serial: &[0x41, 0x03],
            crl_distribution_point: None,
            client_auth: true,
        };
        let now = SystemTime::now();
        let tbs = build_server_leaf_tbs(&issuer, &facts, now).unwrap();
        assert_eq!(check_server_leaf_tbs(&issuer, &facts, &tbs, now), Ok(()));
        let usage = tbs
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|extension| extension.extn_id == EXTENDED_KEY_USAGE)
            .unwrap();
        assert_eq!(
            ExtendedKeyUsage::from_der(usage.extn_value.as_bytes())
                .unwrap()
                .0,
            vec![SERVER_AUTH, CLIENT_AUTH]
        );
        // A TBS with clientAuth is refused for facts without it, and back.
        let without = LeafFacts {
            client_auth: false,
            ..facts_clone(&facts)
        };
        assert_eq!(
            check_server_leaf_tbs(&issuer, &without, &tbs, now).unwrap_err(),
            LeafError::Extensions
        );
        let plain = build_server_leaf_tbs(&issuer, &without, now).unwrap();
        assert_eq!(
            check_server_leaf_tbs(&issuer, &facts, &plain, now).unwrap_err(),
            LeafError::Extensions
        );
    }

    #[test]
    fn a_built_leaf_passes_the_signer_gate_and_verifies_once_signed() {
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let issuer = ca.root_certificate().clone();
        let key = subject_key();
        let names = names();
        let facts = LeafFacts {
            subject_cn: "www.lab.invalid",
            dns_names: &names,
            subject_public_key: &key,
            validity_days: 1,
            serial: &[0x41, 0x02],
            crl_distribution_point: None,
            client_auth: false,
        };
        let now = SystemTime::now();
        let tbs = build_server_leaf_tbs(&issuer, &facts, now).unwrap();
        assert_eq!(check_server_leaf_tbs(&issuer, &facts, &tbs, now), Ok(()));
        let tbs_der = tbs.to_der().unwrap();
        // Sign with the root's own key through the lab CA's signer route.
        let key_ref = ca.lab_signer_key_ref().to_owned();
        let signature = ca.sign_once(&key_ref, "leaf-test", &tbs_der).unwrap();
        let der = assemble_certificate(&tbs_der, &signature).unwrap();
        assert!(verify_server_leaf(&issuer, &facts, &tbs_der, &der, now).is_ok());

        // Another key's signature, a different journaled TBS, a later check.
        let other = EphemeralP256Signer::generate("other").unwrap();
        let forged = other
            .sign(
                other.key_ref(),
                SignatureAlgorithm::EcdsaP256Sha256,
                &tbs_der,
            )
            .unwrap();
        let forged_der = assemble_certificate(&tbs_der, &forged).unwrap();
        assert_eq!(
            verify_server_leaf(&issuer, &facts, &tbs_der, &forged_der, now).unwrap_err(),
            LeafError::Signature
        );
        assert_eq!(
            verify_server_leaf(&issuer, &facts, &tbs_der[1..], &der, now).unwrap_err(),
            LeafError::TbsMismatch
        );
        assert_eq!(
            check_server_leaf_tbs(&issuer, &facts, &tbs, now + Duration::from_secs(600))
                .unwrap_err(),
            LeafError::Validity
        );
        // A validity that starts in the future of the checking clock.
        assert_eq!(
            check_server_leaf_tbs(&issuer, &facts, &tbs, now - Duration::from_secs(600))
                .unwrap_err(),
            LeafError::Validity
        );
    }

    #[test]
    fn the_gate_refuses_every_departure_from_the_facts() {
        let ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let issuer = ca.root_certificate().clone();
        let key = subject_key();
        let names = names();
        let facts = LeafFacts {
            subject_cn: "www.lab.invalid",
            dns_names: &names,
            subject_public_key: &key,
            validity_days: 1,
            serial: &[0x41, 0x02],
            crl_distribution_point: None,
            client_auth: false,
        };
        let now = SystemTime::now();
        let good = build_server_leaf_tbs(&issuer, &facts, now).unwrap();
        let refuse = |edit: &dyn Fn(&mut TbsCertificate)| {
            let mut tbs = good.clone();
            edit(&mut tbs);
            check_server_leaf_tbs(&issuer, &facts, &tbs, now).unwrap_err()
        };
        assert_eq!(refuse(&|t| t.version = Version::V2), LeafError::Version);
        assert_eq!(
            refuse(&|t| t.signature.oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3")),
            LeafError::SignatureAlgorithm
        );
        assert_eq!(
            refuse(&|t| t.issuer = Name::from_str("CN=Other").unwrap()),
            LeafError::Issuer
        );
        assert_eq!(
            refuse(&|t| t.subject = Name::from_str("CN=api.lab.invalid").unwrap()),
            LeafError::Subject
        );
        assert_eq!(
            refuse(&|t| t.subject_public_key_info = subject_key()),
            LeafError::SubjectKey
        );
        assert_eq!(
            refuse(&|t| t.serial_number = SerialNumber::new(&[0x41, 0x03]).unwrap()),
            LeafError::Serial
        );
        assert_eq!(
            refuse(&|t| t.validity.not_after =
                x509_cert::time::Time::try_from(now + Duration::from_secs(3 * DAY)).unwrap()),
            LeafError::Validity
        );
        assert_eq!(
            refuse(&|t| t.extensions.as_mut().unwrap().pop().map(|_| ()).unwrap()),
            LeafError::Extensions
        );
        assert_eq!(
            refuse(&|t| t.extensions.as_mut().unwrap()[0] = extension(
                BASIC_CONSTRAINTS,
                true,
                &BasicConstraints {
                    ca: true,
                    path_len_constraint: None
                }
            )
            .unwrap()),
            LeafError::Extensions
        );
        let more_names = vec![
            "www.lab.invalid".into(),
            "api.lab.invalid".into(),
            "evil.lab.invalid".into(),
        ];
        let wider = LeafFacts {
            dns_names: &more_names,
            ..facts_clone(&facts)
        };
        let wider_tbs = build_server_leaf_tbs(&issuer, &wider, now).unwrap();
        assert_eq!(
            check_server_leaf_tbs(&issuer, &facts, &wider_tbs, now).unwrap_err(),
            LeafError::Extensions
        );
        // A validity beyond the issuer's is never built.
        let long = LeafFacts {
            validity_days: 825,
            ..facts_clone(&facts)
        };
        assert_eq!(
            build_server_leaf_tbs(&issuer, &long, now).unwrap_err(),
            LeafError::Validity
        );
        // A CN outside the names, or a CN that would inject an attribute.
        let outside = LeafFacts {
            subject_cn: "other.lab.invalid",
            ..facts_clone(&facts)
        };
        assert_eq!(
            build_server_leaf_tbs(&issuer, &outside, now).unwrap_err(),
            LeafError::Validity
        );
        let injected_names = vec!["a.lab.invalid,O=Evil".to_owned()];
        let injected = LeafFacts {
            subject_cn: "a.lab.invalid,O=Evil",
            dns_names: &injected_names,
            ..facts_clone(&facts)
        };
        assert_eq!(
            build_server_leaf_tbs(&issuer, &injected, now).unwrap_err(),
            LeafError::Subject
        );
    }

    fn facts_clone<'a>(facts: &LeafFacts<'a>) -> LeafFacts<'a> {
        LeafFacts {
            subject_cn: facts.subject_cn,
            dns_names: facts.dns_names,
            subject_public_key: facts.subject_public_key,
            validity_days: facts.validity_days,
            serial: facts.serial,
            crl_distribution_point: facts.crl_distribution_point,
            client_auth: facts.client_auth,
        }
    }

    #[test]
    fn the_distribution_point_is_exactly_the_journaled_one() {
        let ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let issuer = ca.root_certificate().clone();
        let key = subject_key();
        let names = names();
        let url = "http://127.0.0.1:8081/v1/public/crls/ca/latest.crl";
        let facts = LeafFacts {
            subject_cn: "www.lab.invalid",
            dns_names: &names,
            subject_public_key: &key,
            validity_days: 1,
            serial: &[0x41, 0x02],
            crl_distribution_point: Some(url),
            client_auth: false,
        };
        let now = SystemTime::now();
        let tbs = build_server_leaf_tbs(&issuer, &facts, now).unwrap();
        assert_eq!(check_server_leaf_tbs(&issuer, &facts, &tbs, now), Ok(()));
        let last = tbs.extensions.as_ref().unwrap().last().unwrap();
        assert_eq!(
            (last.extn_id, last.critical),
            (CRL_DISTRIBUTION_POINTS, false)
        );
        let points = CrlDistributionPoints::from_der(last.extn_value.as_bytes()).unwrap();
        assert_eq!(
            points.0[0].distribution_point,
            Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(Ia5String::new(url).unwrap())
            ]))
        );
        // Without the point, with another one, or with one missing from the TBS.
        let without = LeafFacts {
            crl_distribution_point: None,
            ..facts_clone(&facts)
        };
        assert_eq!(
            check_server_leaf_tbs(&issuer, &without, &tbs, now).unwrap_err(),
            LeafError::Extensions
        );
        let other = LeafFacts {
            crl_distribution_point: Some("http://evil.invalid/latest.crl"),
            ..facts_clone(&facts)
        };
        assert_eq!(
            check_server_leaf_tbs(&issuer, &other, &tbs, now).unwrap_err(),
            LeafError::Extensions
        );
        let bare = build_server_leaf_tbs(&issuer, &without, now).unwrap();
        assert_eq!(
            check_server_leaf_tbs(&issuer, &facts, &bare, now).unwrap_err(),
            LeafError::Extensions
        );
        for bad in [
            "ftp://crl.lab.invalid/x.crl",
            "http://a b",
            "http://é.invalid",
        ] {
            let invalid = LeafFacts {
                crl_distribution_point: Some(bad),
                ..facts_clone(&facts)
            };
            assert_eq!(
                build_server_leaf_tbs(&issuer, &invalid, now).unwrap_err(),
                LeafError::Extensions,
                "{bad}"
            );
        }
    }
}
