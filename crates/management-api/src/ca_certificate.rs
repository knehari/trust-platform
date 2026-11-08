//! Verification of a proposed CA's self-signed issuer certificate
//! (ADR-0013, Proposed). This is the API's independent check before the
//! database records the certificate; the database does not parse X.509.
//!
//! Accepted, and nothing else (fail closed):
//! - one PEM `CERTIFICATE` block whose DER re-encodes to the same bytes;
//! - X.509 v3, `ecdsa-with-SHA256` without parameters in both algorithm
//!   fields, a P-256 `id-ecPublicKey` on the named curve with an
//!   uncompressed point;
//! - a subject of exactly one attribute, a UTF8String or PrintableString
//!   common name, and an issuer equal to the subject;
//! - only the basicConstraints, keyUsage, subjectKeyIdentifier and
//!   authorityKeyIdentifier extensions, each at most once; basicConstraints
//!   critical with `cA` set; keyUsage critical with keyCertSign and cRLSign;
//! - a validity window that has started (five minutes of clock skew) and not
//!   ended;
//! - a signature that verifies under the certificate's own key, with the
//!   reviewed verifier of `trust-pki-crypto`.
//!
//! This proves the submitter holds the private key for that public key at
//! signing time. It says nothing about custody, generation, ceremony or who
//! else holds the key.

use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};
use x509_cert::{
    der::{
        asn1::{ObjectIdentifier, PrintableStringRef, Utf8StringRef},
        Decode, DecodePem, Encode, Tag, Tagged,
    },
    ext::pkix::{BasicConstraints, KeyUsage, KeyUsages},
    Certificate, Version,
};

const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const AUTHORITY_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
/// Tolerated clock skew for a certificate whose validity starts later.
const NOT_BEFORE_SKEW: Duration = Duration::from_secs(5 * 60);
/// Bounds shared with the `ca_issuer_certificate` table.
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;

/// Why a certificate was refused. Each rule has its own reason so tests can
/// show that each rule, not only the signature, refuses.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RootRejection {
    Encoding,
    Version,
    SignatureAlgorithm,
    KeyAlgorithm,
    Subject,
    NotSelfIssued,
    Extensions,
    BasicConstraints,
    KeyUsage,
    Validity,
    Signature,
}

/// The facts of a verified root, as the database records them.
#[derive(Debug)]
pub(crate) struct VerifiedRoot {
    pub(crate) der: Vec<u8>,
    pub(crate) spki_sha256: [u8; 32],
    pub(crate) subject_cn: String,
    pub(crate) not_before: SystemTime,
    pub(crate) not_after: SystemTime,
}

/// Parses exactly one PEM certificate block, nothing before or after it
/// except whitespace.
pub(crate) fn certificate_der_from_pem(pem: &str) -> Result<Vec<u8>, RootRejection> {
    let trimmed = pem.trim();
    if trimmed.len() > 4 * MAX_CERTIFICATE_BYTES
        || trimmed.matches("-----BEGIN").count() != 1
        || !trimmed.starts_with("-----BEGIN CERTIFICATE-----")
        || !trimmed.ends_with("-----END CERTIFICATE-----")
    {
        return Err(RootRejection::Encoding);
    }
    let certificate = Certificate::from_pem(trimmed).map_err(|_| RootRejection::Encoding)?;
    certificate.to_der().map_err(|_| RootRejection::Encoding)
}

fn subject_common_name(certificate: &Certificate) -> Result<String, RootRejection> {
    let rdns = &certificate.tbs_certificate.subject.0;
    let [rdn] = rdns.as_slice() else {
        return Err(RootRejection::Subject);
    };
    let [attribute] = rdn.0.as_slice() else {
        return Err(RootRejection::Subject);
    };
    if attribute.oid != COMMON_NAME {
        return Err(RootRejection::Subject);
    }
    let value = &attribute.value;
    let name = match value.tag() {
        Tag::Utf8String => Utf8StringRef::try_from(value)
            .map_err(|_| RootRejection::Subject)?
            .as_str()
            .to_owned(),
        Tag::PrintableString => PrintableStringRef::try_from(value)
            .map_err(|_| RootRejection::Subject)?
            .as_str()
            .to_owned(),
        _ => return Err(RootRejection::Subject),
    };
    if name.is_empty() || name.chars().count() > 255 || name.chars().any(char::is_control) {
        return Err(RootRejection::Subject);
    }
    Ok(name)
}

fn check_extensions(certificate: &Certificate) -> Result<(), RootRejection> {
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_deref()
        .ok_or(RootRejection::Extensions)?;
    let mut seen: Vec<ObjectIdentifier> = Vec::new();
    let mut basic = None;
    let mut usage = None;
    for extension in extensions {
        if seen.contains(&extension.extn_id) {
            return Err(RootRejection::Extensions);
        }
        seen.push(extension.extn_id);
        let bytes = extension.extn_value.as_bytes();
        match extension.extn_id {
            BASIC_CONSTRAINTS => {
                let decoded = BasicConstraints::from_der(bytes)
                    .map_err(|_| RootRejection::BasicConstraints)?;
                basic = Some((extension.critical, decoded));
            }
            KEY_USAGE => {
                let decoded = KeyUsage::from_der(bytes).map_err(|_| RootRejection::KeyUsage)?;
                usage = Some((extension.critical, decoded));
            }
            SUBJECT_KEY_ID | AUTHORITY_KEY_ID => {}
            _ => return Err(RootRejection::Extensions),
        }
    }
    match basic {
        Some((true, constraints)) if constraints.ca => {}
        _ => return Err(RootRejection::BasicConstraints),
    }
    match usage {
        Some((true, usages))
            if usages.0.contains(KeyUsages::KeyCertSign)
                && usages.0.contains(KeyUsages::CRLSign) => {}
        _ => return Err(RootRejection::KeyUsage),
    }
    Ok(())
}

/// Verifies a self-signed P-256 root at time `now`. Structural rules run
/// before the signature, so each refusal names the first rule that failed.
pub(crate) fn verify_lab_root(der: &[u8], now: SystemTime) -> Result<VerifiedRoot, RootRejection> {
    if der.len() < 64 || der.len() > MAX_CERTIFICATE_BYTES {
        return Err(RootRejection::Encoding);
    }
    let certificate = Certificate::from_der(der).map_err(|_| RootRejection::Encoding)?;
    // Only canonical DER: the signed bytes are exactly the re-encoded TBS.
    if certificate.to_der().map_err(|_| RootRejection::Encoding)? != der {
        return Err(RootRejection::Encoding);
    }
    let tbs = &certificate.tbs_certificate;
    if tbs.version != Version::V3
        || tbs.issuer_unique_id.is_some()
        || tbs.subject_unique_id.is_some()
    {
        return Err(RootRejection::Version);
    }
    if certificate.signature_algorithm != tbs.signature
        || tbs.signature.oid != ECDSA_SHA256
        || tbs.signature.parameters.is_some()
    {
        return Err(RootRejection::SignatureAlgorithm);
    }
    let spki = &tbs.subject_public_key_info;
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
    let point = spki.subject_public_key.as_bytes().unwrap_or_default();
    if spki.algorithm.oid != EC_PUBLIC_KEY
        || curve != Some(PRIME256V1)
        || point.len() != 65
        || point[0] != 0x04
    {
        return Err(RootRejection::KeyAlgorithm);
    }
    let subject_cn = subject_common_name(&certificate)?;
    if tbs.issuer != tbs.subject {
        return Err(RootRejection::NotSelfIssued);
    }
    check_extensions(&certificate)?;
    let not_before = tbs.validity.not_before.to_system_time();
    let not_after = tbs.validity.not_after.to_system_time();
    if not_after <= not_before || not_before > now + NOT_BEFORE_SKEW || not_after <= now {
        return Err(RootRejection::Validity);
    }
    let signed = tbs.to_der().map_err(|_| RootRejection::Encoding)?;
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or(RootRejection::Signature)?;
    trust_pki_crypto::verify_p256_ecdsa_sha256(point, &signed, signature)
        .map_err(|_| RootRejection::Signature)?;
    let spki_der = spki.to_der().map_err(|_| RootRejection::Encoding)?;
    Ok(VerifiedRoot {
        der: der.to_vec(),
        spki_sha256: Sha256::digest(&spki_der).into(),
        subject_cn,
        not_before,
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_pki_core::lab_ca::EphemeralLabCa;
    use x509_cert::{
        der::{asn1::OctetString, flagset::FlagSet},
        ext::Extension,
    };

    const NOW_2027: u64 = 1_798_761_600; // 2027-01-01T00:00:00Z

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn vector(name: &str) -> Vec<u8> {
        let path = format!("{}/testdata/ca-root/{name}.crt", env!("CARGO_MANIFEST_DIR"));
        certificate_der_from_pem(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn fresh_root() -> Certificate {
        EphemeralLabCa::new("Sovereign Trust Lab Root")
            .unwrap()
            .root_certificate()
            .clone()
    }

    /// Re-encodes a modified certificate; its signature no longer verifies,
    /// so a structural rule must refuse it first.
    fn modified(edit: impl FnOnce(&mut Certificate)) -> Result<VerifiedRoot, RootRejection> {
        let mut certificate = fresh_root();
        edit(&mut certificate);
        verify_lab_root(&certificate.to_der().unwrap(), SystemTime::now())
    }

    fn replace_extension(
        certificate: &mut Certificate,
        oid: ObjectIdentifier,
        extension: Option<Extension>,
    ) {
        let extensions = certificate.tbs_certificate.extensions.as_mut().unwrap();
        extensions.retain(|existing| existing.extn_id != oid);
        extensions.extend(extension);
    }

    #[test]
    fn openssl_p256_root_verifies_with_its_facts() {
        let der = vector("openssl-p256-root");
        let root = verify_lab_root(&der, at(NOW_2027)).unwrap();
        assert_eq!(root.subject_cn, "Trust Lab OpenSSL Root");
        assert_eq!(root.der, der);
        let spki = Certificate::from_der(&der)
            .unwrap()
            .tbs_certificate
            .subject_public_key_info;
        assert_eq!(
            root.spki_sha256,
            <[u8; 32]>::from(Sha256::digest(spki.to_der().unwrap()))
        );
        assert!(root.not_before < at(NOW_2027) && root.not_after > at(NOW_2027));
    }

    #[test]
    fn rust_lab_root_verifies_now() {
        let root = verify_lab_root(&fresh_root().to_der().unwrap(), SystemTime::now()).unwrap();
        assert_eq!(root.subject_cn, "Sovereign Trust Lab Root");
    }

    #[test]
    fn openssl_vectors_outside_the_profile_are_refused() {
        for (name, reason) in [
            ("openssl-p384-root", RootRejection::KeyAlgorithm),
            ("openssl-rsa-root", RootRejection::SignatureAlgorithm),
            ("openssl-p256-not-ca", RootRejection::BasicConstraints),
            ("openssl-p256-no-crlsign", RootRejection::KeyUsage),
            ("openssl-p256-extra-subject", RootRejection::Subject),
            ("openssl-p256-issued-ca", RootRejection::NotSelfIssued),
        ] {
            assert_eq!(
                verify_lab_root(&vector(name), at(NOW_2027)).unwrap_err(),
                reason,
                "{name}"
            );
        }
    }

    #[test]
    fn validity_is_checked_against_the_given_time() {
        let der = vector("openssl-p256-root");
        let root = verify_lab_root(&der, at(NOW_2027)).unwrap();
        assert_eq!(
            verify_lab_root(&der, root.not_after).unwrap_err(),
            RootRejection::Validity
        );
        let early = root.not_before - NOT_BEFORE_SKEW - Duration::from_secs(1);
        assert_eq!(
            verify_lab_root(&der, early).unwrap_err(),
            RootRejection::Validity
        );
        assert!(verify_lab_root(&der, root.not_before - NOT_BEFORE_SKEW).is_ok());
    }

    #[test]
    fn a_tampered_or_resigned_certificate_is_refused() {
        let der = fresh_root().to_der().unwrap();
        // Flip one bit inside the serial number: the structure still parses.
        let mut tampered = der.clone();
        let serial = tampered
            .windows(3)
            .position(|w| w == [0x02, 0x01, 0x01])
            .unwrap();
        tampered[serial + 2] ^= 0x02;
        assert_eq!(
            verify_lab_root(&tampered, SystemTime::now()).unwrap_err(),
            RootRejection::Signature
        );
        // Another root's signature over this TBS.
        let other = fresh_root();
        let refused = modified(|certificate| certificate.signature = other.signature.clone());
        assert_eq!(refused.unwrap_err(), RootRejection::Signature);
    }

    #[test]
    fn each_structural_rule_refuses_on_its_own() {
        assert_eq!(
            modified(|c| c.tbs_certificate.version = Version::V2).unwrap_err(),
            RootRejection::Version
        );
        assert_eq!(
            modified(|c| {
                c.tbs_certificate.signature.oid =
                    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
                c.signature_algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
            })
            .unwrap_err(),
            RootRejection::SignatureAlgorithm
        );
        assert_eq!(
            modified(
                |c| c.signature_algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3")
            )
            .unwrap_err(),
            RootRejection::SignatureAlgorithm
        );
        assert_eq!(
            modified(|c| c.tbs_certificate.issuer = "CN=Other Root".parse().unwrap()).unwrap_err(),
            RootRejection::NotSelfIssued
        );
        assert_eq!(
            modified(|c| replace_extension(c, BASIC_CONSTRAINTS, None)).unwrap_err(),
            RootRejection::BasicConstraints
        );
        let non_critical_ca = Extension {
            extn_id: BASIC_CONSTRAINTS,
            critical: false,
            extn_value: OctetString::new(
                BasicConstraints {
                    ca: true,
                    path_len_constraint: None,
                }
                .to_der()
                .unwrap(),
            )
            .unwrap(),
        };
        assert_eq!(
            modified(|c| replace_extension(c, BASIC_CONSTRAINTS, Some(non_critical_ca)))
                .unwrap_err(),
            RootRejection::BasicConstraints
        );
        let sign_only = Extension {
            extn_id: KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(
                KeyUsage(FlagSet::from(KeyUsages::KeyCertSign))
                    .to_der()
                    .unwrap(),
            )
            .unwrap(),
        };
        assert_eq!(
            modified(|c| replace_extension(c, KEY_USAGE, Some(sign_only))).unwrap_err(),
            RootRejection::KeyUsage
        );
        let unknown = Extension {
            extn_id: ObjectIdentifier::new_unwrap("2.5.29.17"),
            critical: false,
            extn_value: OctetString::new(vec![0x30, 0x00]).unwrap(),
        };
        assert_eq!(
            modified(|c| replace_extension(c, unknown.extn_id, Some(unknown.clone()))).unwrap_err(),
            RootRejection::Extensions
        );
        assert_eq!(
            modified(|c| {
                let duplicate = c.tbs_certificate.extensions.as_ref().unwrap()[0].clone();
                c.tbs_certificate
                    .extensions
                    .as_mut()
                    .unwrap()
                    .push(duplicate);
            })
            .unwrap_err(),
            RootRejection::Extensions
        );
    }

    #[test]
    fn pem_input_is_one_certificate_block() {
        let pem = std::fs::read_to_string(format!(
            "{}/testdata/ca-root/openssl-p256-root.crt",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        assert!(certificate_der_from_pem(&pem).is_ok());
        assert_eq!(
            certificate_der_from_pem(&format!("{pem}{pem}")).unwrap_err(),
            RootRejection::Encoding
        );
        assert_eq!(
            certificate_der_from_pem(&pem.replace("CERTIFICATE", "PRIVATE KEY")).unwrap_err(),
            RootRejection::Encoding
        );
        assert_eq!(
            certificate_der_from_pem("").unwrap_err(),
            RootRejection::Encoding
        );
        // Non-canonical DER (a long-form length) is refused by the verifier.
        let der = vector("openssl-p256-root");
        let mut long_form = vec![0x30, 0x83, 0x00];
        long_form.extend_from_slice(&der[2..]);
        assert_eq!(
            verify_lab_root(&long_form, at(NOW_2027)).unwrap_err(),
            RootRejection::Encoding
        );
    }
}
