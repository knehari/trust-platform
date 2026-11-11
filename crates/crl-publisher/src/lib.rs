//! Laboratory CRL publisher (ADR-0030, Proposed).
//!
//! The management API no longer serves anything anonymous. This process
//! reads the latest published CRL of each publishing CA through its own login
//! (`trust_crl_publisher`, migration 0043: one view, no table), and writes it
//! to a static tree that a plain HTTP server, with no database access, serves
//! at the distribution point path certificates carry:
//! `<dir>/v1/public/crls/<ca_id>/latest.crl`, plus `<crl_number>.crl`.
//!
//! It publishes a CRL only if:
//! - its DER is canonical, signed with ECDSA P-256 / SHA-256 under the CA's
//!   registered issuer certificate, and names that certificate's subject;
//! - its CRL number is the one the database recorded;
//! - it is newer than the CRL already published there. A database rolled
//!   back to an older CRL never replaces a newer one on the public side.
//!
//! Files are written to a temporary name in the same directory, synced, then
//! renamed, so readers never see a partial CRL.
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use x509_cert::{
    crl::CertificateList,
    der::{Decode, Encode},
    Certificate,
};

const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const CRL_NUMBER: &str = "2.5.29.20";
/// The largest CRL the publisher accepts.
pub const MAX_CRL_BYTES: usize = 4 * 1024 * 1024;

/// One row of `crl_publisher_feed`.
#[derive(Debug, Clone)]
pub struct FeedEntry {
    pub ca_id: String,
    pub crl_number: i64,
    pub crl_der: Vec<u8>,
    pub issuer_certificate_der: Vec<u8>,
}

/// What happened to one CA's CRL in a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Written: this number is now public.
    Published(u64),
    /// The public tree already holds this number.
    Unchanged(u64),
    /// The public tree holds a newer number: the database is behind it.
    Rollback { public: u64, offered: u64 },
    /// Not published: the CRL does not verify, or the identifier is unsafe.
    Refused(&'static str),
}

fn valid_ca_id(text: &str) -> bool {
    text.len() == 36
        && text.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
        })
}

fn unsigned(bytes: &[u8]) -> Option<u64> {
    let bytes = match bytes {
        [0, rest @ ..] if !rest.is_empty() => rest,
        other => other,
    };
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

/// The CRL number of a DER CRL, if it carries exactly one.
pub fn crl_number(crl: &CertificateList) -> Option<u64> {
    let mut numbers = crl
        .tbs_cert_list
        .crl_extensions
        .as_deref()?
        .iter()
        .filter(|extension| extension.extn_id.to_string() == CRL_NUMBER);
    let extension = numbers.next()?;
    if numbers.next().is_some() {
        return None;
    }
    let number = x509_cert::der::asn1::UintRef::from_der(extension.extn_value.as_bytes()).ok()?;
    unsigned(number.as_bytes())
}

/// Checks one CRL before it is made public. Returns its number.
pub fn verify(entry: &FeedEntry) -> Result<u64, &'static str> {
    if entry.crl_der.is_empty() || entry.crl_der.len() > MAX_CRL_BYTES {
        return Err("size");
    }
    let crl = CertificateList::from_der(&entry.crl_der).map_err(|_| "encoding")?;
    if crl.to_der().map_err(|_| "encoding")? != entry.crl_der {
        return Err("encoding");
    }
    let issuer =
        Certificate::from_der(&entry.issuer_certificate_der).map_err(|_| "issuer certificate")?;
    if crl.signature_algorithm.oid.to_string() != ECDSA_WITH_SHA256
        || crl.tbs_cert_list.signature.oid.to_string() != ECDSA_WITH_SHA256
    {
        return Err("signature algorithm");
    }
    if crl.tbs_cert_list.issuer != issuer.tbs_certificate.subject {
        return Err("issuer");
    }
    let tbs = crl.tbs_cert_list.to_der().map_err(|_| "encoding")?;
    let point = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or("issuer key")?;
    let signature = crl.signature.as_bytes().ok_or("signature")?;
    trust_pki_crypto::verify_p256_ecdsa_sha256(point, &tbs, signature).map_err(|_| "signature")?;
    let number = crl_number(&crl).ok_or("crl number")?;
    if u64::try_from(entry.crl_number).ok() != Some(number) {
        return Err("crl number");
    }
    if crl.tbs_cert_list.next_update.is_none() {
        return Err("next update");
    }
    Ok(number)
}

/// Where a CA's latest CRL is served, under `root`.
pub fn ca_directory(root: &Path, ca_id: &str) -> PathBuf {
    root.join("v1").join("public").join("crls").join(ca_id)
}

fn write_atomically(directory: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = directory.join(format!(".{name}.tmp-{}", std::process::id()));
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, directory.join(name))
}

fn published_number(directory: &Path) -> Option<u64> {
    let bytes = fs::read(directory.join("latest.crl")).ok()?;
    crl_number(&CertificateList::from_der(&bytes).ok()?)
}

/// Publishes one feed entry under `root`.
pub fn publish(root: &Path, entry: &FeedEntry) -> std::io::Result<Outcome> {
    if !valid_ca_id(&entry.ca_id) {
        return Ok(Outcome::Refused("ca identifier"));
    }
    let number = match verify(entry) {
        Ok(number) => number,
        Err(reason) => return Ok(Outcome::Refused(reason)),
    };
    let directory = ca_directory(root, &entry.ca_id);
    match published_number(&directory) {
        Some(public) if public > number => {
            return Ok(Outcome::Rollback {
                public,
                offered: number,
            })
        }
        Some(public) if public == number => return Ok(Outcome::Unchanged(number)),
        _ => {}
    }
    fs::create_dir_all(&directory)?;
    write_atomically(&directory, &format!("{number}.crl"), &entry.crl_der)?;
    write_atomically(&directory, "latest.crl", &entry.crl_der)?;
    Ok(Outcome::Published(number))
}

/// The feed, read through the publisher's login.
pub fn feed(db: &mut postgres::Client) -> Result<Vec<FeedEntry>, postgres::Error> {
    Ok(db
        .query(
            "SELECT ca_id, crl_number, crl_der, issuer_certificate_der FROM crl_publisher_feed \
             ORDER BY ca_id",
            &[],
        )?
        .into_iter()
        .map(|row| FeedEntry {
            ca_id: row.get(0),
            crl_number: row.get(1),
            crl_der: row.get(2),
            issuer_certificate_der: row.get(3),
        })
        .collect())
}

/// One pass over the feed, with a JSON log line per CA.
pub fn publish_once(
    db: &mut postgres::Client,
    root: &Path,
) -> Result<Vec<(String, Outcome)>, Box<dyn std::error::Error>> {
    let mut outcomes = Vec::new();
    for entry in feed(db)? {
        let outcome = publish(root, &entry)?;
        let line = match &outcome {
            Outcome::Published(number) => Some(
                serde_json::json!({"event": "crl_published", "ca_id": entry.ca_id, "crl_number": number}),
            ),
            Outcome::Unchanged(_) => None,
            Outcome::Rollback { public, offered } => Some(
                serde_json::json!({"event": "crl_publication_refused", "ca_id": entry.ca_id, "reason": "rollback", "public": public, "offered": offered, "alert": true}),
            ),
            Outcome::Refused(reason) => Some(
                serde_json::json!({"event": "crl_publication_refused", "ca_id": entry.ca_id, "reason": reason, "alert": true}),
            ),
        };
        if let Some(line) = line {
            println!("{line}");
        }
        outcomes.push((entry.ca_id, outcome));
    }
    Ok(outcomes)
}

/// Whether `db` is a login limited to the publisher role: member of
/// `trust_crl_publisher`, no table privilege, no elevated attribute.
pub fn restricted_login(db: &mut postgres::Client) -> Result<bool, postgres::Error> {
    Ok(db
        .query_one(
            "SELECT pg_has_role(current_user, 'trust_crl_publisher', 'member') \
             AND management_crl_separate_publication_version() = 1 \
             AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = current_user \
                 AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb)) \
             AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'm', 'f') \
                 AND has_table_privilege(current_user, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'))",
            &[],
        )?
        .get(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{signature::Signer, Signature, SigningKey},
        SecretKey,
    };
    use std::{str::FromStr, time::Duration};
    use trust_pki_core::application_crl::{
        assemble_crl, build_crl_tbs, parse_utc_seconds, CrlEntry, CrlFacts,
    };
    use x509_cert::{
        der::asn1::{BitString, OctetString},
        ext::{pkix::BasicConstraints, Extension},
        name::Name,
        serial_number::SerialNumber,
        spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned},
        time::Validity,
        TbsCertificate, Version,
    };

    const CA: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

    fn ecdsa() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(ECDSA_WITH_SHA256),
            parameters: None,
        }
    }

    fn root(key: &SecretKey, cn: &str) -> Certificate {
        use p256::pkcs8::EncodePublicKey;
        let name = Name::from_str(&format!("CN={cn}")).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_der(
            key.public_key().to_public_key_der().unwrap().as_bytes(),
        )
        .unwrap();
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1]).unwrap(),
            signature: ecdsa(),
            issuer: name.clone(),
            validity: Validity::from_now(Duration::from_secs(86_400 * 365)).unwrap(),
            subject: name,
            subject_public_key_info: spki,
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

    fn crl(key: &SecretKey, issuer: &Certificate, number: u64) -> Vec<u8> {
        let entries = [CrlEntry {
            serial: vec![0x41, 0x01],
            revoked_at: parse_utc_seconds("2026-11-07T10:00:00Z").unwrap(),
            reason_code: 1,
        }];
        let tbs = build_crl_tbs(
            issuer,
            &CrlFacts {
                crl_number: number,
                this_update: parse_utc_seconds("2026-11-08T00:00:00Z").unwrap(),
                next_update: parse_utc_seconds("2026-11-15T00:00:00Z").unwrap(),
                entries: &entries,
            },
        )
        .unwrap()
        .to_der()
        .unwrap();
        let signature: Signature = SigningKey::from(key.clone()).sign(&tbs);
        assemble_crl(&tbs, signature.to_der().as_bytes()).unwrap()
    }

    struct Fixture {
        key: SecretKey,
        issuer: Certificate,
        root: PathBuf,
    }

    fn fixture(name: &str) -> Fixture {
        let key = SecretKey::random(&mut rand::rngs::OsRng);
        let issuer = root(&key, "Publisher Test CA");
        let root =
            std::env::temp_dir().join(format!("trust-crl-publisher-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        Fixture { key, issuer, root }
    }

    impl Fixture {
        fn entry(&self, number: u64) -> FeedEntry {
            FeedEntry {
                ca_id: CA.into(),
                crl_number: number as i64,
                crl_der: crl(&self.key, &self.issuer, number),
                issuer_certificate_der: self.issuer.to_der().unwrap(),
            }
        }
    }

    #[test]
    fn publishes_newer_crls_and_never_rolls_back() {
        let f = fixture("rollback");
        assert_eq!(
            publish(&f.root, &f.entry(3)).unwrap(),
            Outcome::Published(3)
        );
        let directory = ca_directory(&f.root, CA);
        assert_eq!(
            fs::read(directory.join("latest.crl")).unwrap(),
            f.entry(3).crl_der
        );
        assert!(directory.join("3.crl").exists());
        assert_eq!(
            publish(&f.root, &f.entry(3)).unwrap(),
            Outcome::Unchanged(3)
        );
        assert_eq!(
            publish(&f.root, &f.entry(4)).unwrap(),
            Outcome::Published(4)
        );
        // The database offers an older CRL: the public one stays.
        assert_eq!(
            publish(&f.root, &f.entry(2)).unwrap(),
            Outcome::Rollback {
                public: 4,
                offered: 2
            }
        );
        assert_eq!(published_number(&directory), Some(4));
        // No temporary file is left behind.
        assert!(fs::read_dir(&directory).unwrap().all(|file| !file
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
        let _ = fs::remove_dir_all(&f.root);
    }

    #[test]
    fn refuses_what_does_not_verify_under_the_issuer() {
        let f = fixture("refuse");
        let refused = |entry: FeedEntry| publish(&f.root, &entry).unwrap();
        // Another key signed it.
        let other = SecretKey::random(&mut rand::rngs::OsRng);
        let mut forged = f.entry(1);
        forged.crl_der = crl(&other, &f.issuer, 1);
        assert_eq!(refused(forged), Outcome::Refused("signature"));
        // Another CA's certificate, or another number than recorded.
        let mut other_issuer = f.entry(1);
        other_issuer.issuer_certificate_der = root(&f.key, "Another CA").to_der().unwrap();
        assert_eq!(refused(other_issuer), Outcome::Refused("issuer"));
        let mut renumbered = f.entry(1);
        renumbered.crl_number = 2;
        assert_eq!(refused(renumbered), Outcome::Refused("crl number"));
        // Altered bytes, garbage, or a path-like identifier.
        let mut altered = f.entry(1);
        let last = altered.crl_der.len() - 1;
        altered.crl_der[last] ^= 1;
        assert!(matches!(refused(altered), Outcome::Refused(_)));
        let mut garbage = f.entry(1);
        garbage.crl_der = vec![0x30, 0x00];
        assert_eq!(refused(garbage), Outcome::Refused("encoding"));
        let mut traversal = f.entry(1);
        traversal.ca_id = "../../etc/passwd-aaaaaaaaaaaaaaaaaaa".into();
        assert_eq!(refused(traversal), Outcome::Refused("ca identifier"));
        assert!(!f.root.exists(), "a refused CRL created files");
    }

    #[test]
    fn identifiers_and_numbers_are_strict() {
        assert!(valid_ca_id(CA));
        for bad in [
            "",
            "DDDDDDDD-dddd-4ddd-8ddd-dddddddddddd",
            "dddddddd-dddd-4ddd-8ddd-ddddddddddd/",
            "dddddddd_dddd_4ddd_8ddd_dddddddddddd",
        ] {
            assert!(!valid_ca_id(bad), "{bad}");
        }
        assert_eq!(unsigned(&[0x01, 0x00]), Some(256));
        assert_eq!(unsigned(&[0x00, 0xff]), Some(255));
        assert_eq!(unsigned(&[]), None);
        assert_eq!(unsigned(&[1; 9]), None);
    }
}
