//! Emits a disposable RSA PKCS#1 v1.5 certificate for OpenSSL verification.
//! Not a production CA; no persistent private key is generated.
use std::{env, fs};
use trust_pki_core::rsa_pkcs1_x509_lab::issue_rsa_pkcs1_root_lab;
use trust_pki_crypto::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};
use x509_cert::der::Encode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let digest = match args.next().as_deref() {
        Some("sha256") => Digest::Sha256,
        Some("sha384") => Digest::Sha384,
        Some("sha512") => Digest::Sha512,
        _ => return Err("expected sha256, sha384 or sha512".into()),
    };
    let output = args.next().ok_or("DER output path required")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let suite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPkcs1V15,
        key: KeyParameter::Rsa2048,
        digest,
    };
    let root = issue_rsa_pkcs1_root_lab(suite).map_err(|_| "lab root issuance failed")?;
    fs::write(output, root.to_der()?)?;
    Ok(())
}
