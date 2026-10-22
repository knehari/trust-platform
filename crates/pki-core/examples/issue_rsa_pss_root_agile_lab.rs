//! Disposable RSA-PSS SHA-384/512 X.509 root for OpenSSL CI interoperability.
//! Not a certificate authority or production key storage facility.
use std::{env, fs};
use trust_pki_core::rsa_pss_x509_lab::create_root_and_signer_for_digest;
use trust_pki_crypto::crypto_agility::Digest;
use x509_cert::der::Encode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let digest = match args.next().as_deref() {
        Some("sha384") => Digest::Sha384,
        Some("sha512") => Digest::Sha512,
        _ => return Err("expected sha384 or sha512".into()),
    };
    let path = args.next().ok_or("DER output path required")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let (root, _signer) =
        create_root_and_signer_for_digest(digest).map_err(|_| "lab issuance failed")?;
    fs::write(path, root.to_der()?)?;
    Ok(())
}
