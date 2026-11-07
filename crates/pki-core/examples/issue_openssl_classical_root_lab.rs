//! Emits disposable ECDSA P-384/P-521 and EdDSA X.509 roots for OpenSSL CI.
#![cfg(unix)]
use std::{env, fs};
use trust_pki_core::openssl_classical_x509_lab::issue_openssl_classical_root_lab;
use trust_pki_crypto::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};
use x509_cert::der::Encode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let suite = match args.next().as_deref() {
        Some("p384") => AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P384,
            digest: Digest::Sha384,
        },
        Some("p521") => AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P521,
            digest: Digest::Sha512,
        },
        Some("ed25519") => AlgorithmSuite {
            scheme: SignatureScheme::Ed25519,
            key: KeyParameter::Ed25519,
            digest: Digest::Intrinsic,
        },
        Some("ed448") => AlgorithmSuite {
            scheme: SignatureScheme::Ed448,
            key: KeyParameter::Ed448,
            digest: Digest::Intrinsic,
        },
        _ => return Err("expected p384, p521, ed25519 or ed448".into()),
    };
    let target = args.next().ok_or("DER output path required")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let cert = issue_openssl_classical_root_lab(suite)
        .map_err(|_| "unable to issue laboratory classical root")?;
    fs::write(target, cert.to_der()?)?;
    Ok(())
}
