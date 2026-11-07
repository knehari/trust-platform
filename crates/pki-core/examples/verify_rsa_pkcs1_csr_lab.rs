//! Cross-provider RSA PKCS#1 PKCS#10 proof-of-possession check.
//! Use with disposable OpenSSL-generated CSR fixtures in CI only.
use std::{env, fs};
use trust_pki_core::csr::verify_pkcs10_rsa_pkcs1_lab;
use trust_pki_crypto::crypto_agility::{Digest, KeyParameter, SignatureScheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let path = args.next().ok_or("CSR DER path required")?;
    let digest = match args.next().as_deref() {
        Some("sha256") => Digest::Sha256,
        Some("sha384") => Digest::Sha384,
        Some("sha512") => Digest::Sha512,
        _ => return Err("expected sha256, sha384 or sha512".into()),
    };
    let key = match args.next().as_deref() {
        Some("2048") => KeyParameter::Rsa2048,
        Some("3072") => KeyParameter::Rsa3072,
        Some("4096") => KeyParameter::Rsa4096,
        _ => return Err("expected 2048, 3072 or 4096".into()),
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let csr = fs::read(path)?;
    let (_, suite) = verify_pkcs10_rsa_pkcs1_lab(&csr, "api.lab.invalid")
        .map_err(|_| "PKCS#10 proof-of-possession rejected")?;
    if suite.scheme != SignatureScheme::RsaPkcs1V15 || suite.digest != digest || suite.key != key {
        return Err("CSR signature algorithm or observed public key does not match".into());
    }
    Ok(())
}
