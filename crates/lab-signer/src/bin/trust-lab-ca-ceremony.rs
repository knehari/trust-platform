//! `trust-lab-ca-ceremony`: the laboratory CA key ceremony on a PKCS#11
//! token (ADR-0034, Proposed).
//!
//! `trust-lab-ca-ceremony "<display name>" [days]`, with the token named by
//! `TRUST_SIGNER_PKCS11_MODULE`, `_TOKEN_LABEL`, `_KEY_LABEL` and `_PIN`:
//! 1. generates a P-256 key pair inside the token, sensitive and not
//!    extractable, under a label no object uses yet;
//! 2. builds the self-signed root certificate that
//!    `scripts/lab/create-lab-root.sh` builds for a software key (subject
//!    `CN=<display name>`, basicConstraints critical CA, keyUsage critical
//!    keyCertSign and cRLSign, subject and authority key identifiers);
//! 3. has the token sign it, verifies the signature, and prints the PEM.
//!
//! The private key is never read, written or printed: only the certificate
//! leaves. The serial number comes from the token's generator. Lab only: no
//! dual control, witness or quorum, which a real ceremony requires.

use std::{env, process::ExitCode, str::FromStr, time::Duration};

use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
};
use trust_lab_signer::{
    ca_key::{CaKey, Pkcs11Config, Pkcs11Key},
    spki_der,
};
use trust_pki_core::x509_extensions::key_identifier;
use x509_cert::{
    der::{
        asn1::{BitString, ObjectIdentifier, OctetString},
        Decode, Encode, EncodePem,
    },
    ext::{
        pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages},
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
    Certificate, TbsCertificate, Version,
};

const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

fn extension(oid: &str, critical: bool, value: Vec<u8>) -> Result<Extension, String> {
    Ok(Extension {
        extn_id: ObjectIdentifier::new_unwrap(oid),
        critical,
        extn_value: OctetString::new(value).map_err(|error| error.to_string())?,
    })
}

fn display_name(raw: &str) -> Result<&str, String> {
    let valid = !raw.is_empty()
        && raw.len() <= 64
        && !raw.starts_with(' ')
        && !raw.ends_with(' ')
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '.' || c == '-');
    valid
        .then_some(raw)
        .ok_or_else(|| "display name: letters, digits, spaces, dots and hyphens only".into())
}

fn ceremony(name: &str, days: u64) -> Result<String, String> {
    let config = Pkcs11Config::from_env()?.ok_or("TRUST_SIGNER_PKCS11_MODULE is required")?;
    let key = Pkcs11Key::open(&config).map_err(|refusal| format!("token: {}", refusal.code()))?;
    let public = key
        .generate()
        .map_err(|refusal| format!("key generation: {}", refusal.code()))?;
    let spki = SubjectPublicKeyInfoOwned::from_der(
        &spki_der(&key).map_err(|refusal| format!("public key: {}", refusal.code()))?,
    )
    .map_err(|error| error.to_string())?;
    let key_id = key_identifier(&spki).map_err(|error| format!("{error:?}"))?;
    let mut serial = key
        .random(16)
        .map_err(|refusal| format!("serial: {}", refusal.code()))?;
    // Positive, 16 bytes, no leading zero octet (RFC 5280 §4.1.2.2).
    serial[0] = (serial[0] & 0x7f) | 0x40;
    let subject = Name::from_str(&format!("CN={name}")).map_err(|error| error.to_string())?;
    let algorithm = AlgorithmIdentifierOwned {
        oid: ECDSA_SHA256,
        parameters: None,
    };
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&serial).map_err(|error| error.to_string())?,
        signature: algorithm.clone(),
        issuer: subject.clone(),
        validity: Validity::from_now(Duration::from_secs(days * 86_400))
            .map_err(|error| error.to_string())?,
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            extension(
                "2.5.29.19",
                true,
                BasicConstraints {
                    ca: true,
                    path_len_constraint: None,
                }
                .to_der()
                .map_err(|error| error.to_string())?,
            )?,
            extension(
                "2.5.29.15",
                true,
                KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                    .to_der()
                    .map_err(|error| error.to_string())?,
            )?,
            extension(
                "2.5.29.14",
                false,
                OctetString::new(key_id.to_vec())
                    .and_then(|id| id.to_der())
                    .map_err(|error| error.to_string())?,
            )?,
            extension(
                "2.5.29.35",
                false,
                AuthorityKeyIdentifier {
                    key_identifier: Some(
                        OctetString::new(key_id.to_vec()).map_err(|error| error.to_string())?,
                    ),
                    authority_cert_issuer: None,
                    authority_cert_serial_number: None,
                }
                .to_der()
                .map_err(|error| error.to_string())?,
            )?,
        ]),
    };
    let tbs_der = tbs.to_der().map_err(|error| error.to_string())?;
    let signature_der = key
        .sign_sha256(&tbs_der)
        .map_err(|refusal| format!("signature: {}", refusal.code()))?;
    // Again, independently of the adapter's own check.
    let point = public.to_encoded_point(false);
    VerifyingKey::from_sec1_bytes(point.as_bytes())
        .and_then(|verifier| verifier.verify(&tbs_der, &Signature::from_der(&signature_der)?))
        .map_err(|_| "the token's signature does not verify".to_owned())?;
    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature_der).map_err(|error| error.to_string())?,
    };
    certificate
        .to_pem(x509_cert::der::pem::LineEnding::LF)
        .map_err(|error| error.to_string())
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let outcome = match &arguments[..] {
        [name] => display_name(name).and_then(|name| ceremony(name, 1825)),
        [name, days] => display_name(name).and_then(|name| {
            let days = days
                .parse::<u64>()
                .ok()
                .filter(|days| (1..=7300).contains(days))
                .ok_or("days: an integer from 1 to 7300")?;
            ceremony(name, days)
        }),
        _ => Err("usage: trust-lab-ca-ceremony \"<display name>\" [days]".into()),
    };
    match outcome {
        Ok(pem) => {
            print!("{pem}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("trust-lab-ca-ceremony: {message}");
            ExitCode::FAILURE
        }
    }
}
