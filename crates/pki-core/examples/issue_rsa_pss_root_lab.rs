//! CLI fixture for the CI OpenSSL cross-verification; not a CA service.
use std::{env, fs};
use trust_pki_core::rsa_pss_x509_lab::issue_ephemeral_rsa_pss_root;
use x509_cert::der::Encode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("output DER path required")?;
    let cert = issue_ephemeral_rsa_pss_root().map_err(|_| "RSA-PSS lab root issuance failed")?;
    fs::write(path, cert.to_der()?)?;
    Ok(())
}
