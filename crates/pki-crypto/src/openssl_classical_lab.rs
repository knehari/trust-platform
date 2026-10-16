//! OpenSSL 3 CLI based signer for isolated Linux laboratory tests.
//! NOT a production provider. It temporarily stores disposable private keys
//! on a 0700 workspace and deletes the workspace on Drop; no HSM guarantees.
//! Never feed production key material, untrusted filenames or large messages.
#![cfg(unix)]

use crate::crypto_agility::{validate_suite, AlgorithmSuite, Digest, KeyParameter, SignatureScheme};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
static WORKSPACE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenSslLabError {
    UnsupportedSuite,
    IoFailure,
    BackendFailure,
    InvalidKey,
    InvalidSignature,
    OversizeMessage,
}

#[derive(Debug)]
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn create(parent: &Path) -> Result<Self, OpenSslLabError> {
        for _ in 0..16 {
            let id = WORKSPACE_ID.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("trust-crypto-{}-{id}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(OpenSslLabError::IoFailure),
            }
        }
        Err(OpenSslLabError::IoFailure)
    }

    fn write(&self, name: &str, value: &[u8]) -> Result<PathBuf, OpenSslLabError> {
        let path = self.path.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| OpenSslLabError::IoFailure)?;
        file.write_all(value)
            .map_err(|_| OpenSslLabError::IoFailure)?;
        Ok(path)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn suite_kind(suite: AlgorithmSuite) -> Result<(&'static str, Option<&'static str>), OpenSslLabError> {
    validate_suite(suite).map_err(|_| OpenSslLabError::UnsupportedSuite)?;
    match (suite.scheme, suite.key, suite.digest) {
        (SignatureScheme::Ecdsa, KeyParameter::P384, Digest::Sha384) => {
            Ok(("EC", Some("ec_paramgen_curve:secp384r1")))
        }
        (SignatureScheme::Ecdsa, KeyParameter::P521, Digest::Sha512) => {
            Ok(("EC", Some("ec_paramgen_curve:secp521r1")))
        }
        (SignatureScheme::Ed25519, KeyParameter::Ed25519, Digest::Intrinsic) => {
            Ok(("ED25519", None))
        }
        (SignatureScheme::Ed448, KeyParameter::Ed448, Digest::Intrinsic) => {
            Ok(("ED448", None))
        }
        _ => Err(OpenSslLabError::UnsupportedSuite),
    }
}

fn checked_message(message: &[u8]) -> Result<(), OpenSslLabError> {
    if message.len() > MAX_MESSAGE_BYTES {
        Err(OpenSslLabError::OversizeMessage)
    } else {
        Ok(())
    }
}

fn public_der_to_pem(
    workspace: &Workspace,
    spki_der: &[u8],
) -> Result<PathBuf, OpenSslLabError> {
    let der = workspace.write("subject.spki", spki_der)?;
    let public = workspace.path.join("public.pem");
    let output = Command::new("openssl")
        .args(["pkey", "-pubin", "-inform", "DER", "-in"])
        .arg(&der)
        .args(["-pubout", "-out"])
        .arg(&public)
        .output()
        .map_err(|_| OpenSslLabError::BackendFailure)?;
    if !output.status.success() {
        return Err(OpenSslLabError::InvalidKey);
    }
    Ok(public)
}

fn verify_in_workspace(
    suite: AlgorithmSuite,
    workspace: &Workspace,
    public_pem: &Path,
    message: &[u8],
    signature: &[u8],
) -> Result<(), OpenSslLabError> {
    checked_message(message)?;
    suite_kind(suite)?;
    let data = workspace.write("payload.bin", message)?;
    let signed = workspace.write("signature.bin", signature)?;
    let mut cmd = Command::new("openssl");
    match suite.digest {
        Digest::Sha384 | Digest::Sha512 => {
            let digest = if suite.digest == Digest::Sha384 { "-sha384" } else { "-sha512" };
            cmd.args(["dgst", digest, "-verify"])
                .arg(public_pem)
                .arg("-signature")
                .arg(&signed)
                .arg(&data);
        }
        Digest::Intrinsic => {
            cmd.args(["pkeyutl", "-verify", "-pubin", "-inkey"])
                .arg(public_pem)
                .args(["-rawin", "-in"])
                .arg(&data)
                .arg("-sigfile")
                .arg(&signed);
        }
        Digest::Sha256 => return Err(OpenSslLabError::UnsupportedSuite),
    }
    let result = cmd.output().map_err(|_| OpenSslLabError::BackendFailure)?;
    if result.status.success() {
        Ok(())
    } else {
        Err(OpenSslLabError::InvalidSignature)
    }
}

/// Verify with a caller-supplied, parsed SPKI (rather than a private-key handle).
/// Correct ASN.1 algorithm and curve validation must precede this method at
/// the X.509 trust boundary. This does not validate certificate path trust.
pub fn verify_openssl_spki_lab(
    suite: AlgorithmSuite,
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), OpenSslLabError> {
    checked_message(message)?;
    suite_kind(suite)?;
    let work = Workspace::create(&std::env::temp_dir())?;
    let public = public_der_to_pem(&work, spki_der)?;
    verify_in_workspace(suite, &work, &public, message, signature)
}

/// One disposable private key generated by OpenSSL in a 0700 directory.
/// Linux laboratory only: subprocess signing is NOT a production key boundary.
pub struct OpenSslClassicalLabKey {
    suite: AlgorithmSuite,
    workspace: Workspace,
    private: PathBuf,
    spki_der: Vec<u8>,
}

impl OpenSslClassicalLabKey {
    pub fn generate(suite: AlgorithmSuite) -> Result<Self, OpenSslLabError> {
        let (algorithm, curve) = suite_kind(suite)?;
        let workspace = Workspace::create(&std::env::temp_dir())?;
        let mut cmd = Command::new("openssl");
        cmd.args(["genpkey", "-algorithm", algorithm]);
        if let Some(curve) = curve {
            cmd.args(["-pkeyopt", curve]);
        }
        let output = cmd.output().map_err(|_| OpenSslLabError::BackendFailure)?;
        if !output.status.success() || output.stdout.is_empty() {
            return Err(OpenSslLabError::BackendFailure);
        }
        let private = workspace.write("private.pem", &output.stdout)?;
        let key_output = Command::new("openssl")
            .args(["pkey", "-in"])
            .arg(&private)
            .args(["-pubout", "-outform", "DER"])
            .output()
            .map_err(|_| OpenSslLabError::BackendFailure)?;
        if !key_output.status.success() || key_output.stdout.is_empty() {
            return Err(OpenSslLabError::InvalidKey);
        }
        Ok(Self {
            suite,
            workspace,
            private,
            spki_der: key_output.stdout,
        })
    }

    pub fn suite(&self) -> AlgorithmSuite {
        self.suite
    }

    pub fn public_spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    pub fn sign(&self, suite: AlgorithmSuite, message: &[u8]) -> Result<Vec<u8>, OpenSslLabError> {
        if suite != self.suite {
            return Err(OpenSslLabError::UnsupportedSuite);
        }
        checked_message(message)?;
        let work = Workspace::create(&self.workspace.path)?;
        let input = work.write("message.bin", message)?;
        let signed = work.path.join("signed.bin");
        let mut cmd = Command::new("openssl");
        match suite.digest {
            Digest::Sha384 | Digest::Sha512 => {
                let digest = if suite.digest == Digest::Sha384 { "-sha384" } else { "-sha512" };
                cmd.args(["dgst", digest, "-sign"])
                    .arg(&self.private)
                    .arg("-out")
                    .arg(&signed)
                    .arg(&input);
            }
            Digest::Intrinsic => {
                cmd.args(["pkeyutl", "-sign", "-inkey"])
                    .arg(&self.private)
                    .args(["-rawin", "-in"])
                    .arg(&input)
                    .arg("-out")
                    .arg(&signed);
            }
            Digest::Sha256 => return Err(OpenSslLabError::UnsupportedSuite),
        }
        let output = cmd.output().map_err(|_| OpenSslLabError::BackendFailure)?;
        if !output.status.success() {
            return Err(OpenSslLabError::BackendFailure);
        }
        fs::read(&signed).map_err(|_| OpenSslLabError::IoFailure)
    }

    pub fn verify(
        &self,
        suite: AlgorithmSuite,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), OpenSslLabError> {
        if suite != self.suite {
            return Err(OpenSslLabError::UnsupportedSuite);
        }
        verify_openssl_spki_lab(suite, &self.spki_der, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASES: [AlgorithmSuite; 4] = [
        AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P384,
            digest: Digest::Sha384,
        },
        AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P521,
            digest: Digest::Sha512,
        },
        AlgorithmSuite {
            scheme: SignatureScheme::Ed25519,
            key: KeyParameter::Ed25519,
            digest: Digest::Intrinsic,
        },
        AlgorithmSuite {
            scheme: SignatureScheme::Ed448,
            key: KeyParameter::Ed448,
            digest: Digest::Intrinsic,
        },
    ];

    #[test]
    fn real_four_algorithm_sign_verify_and_no_downgrade() {
        for suite in CASES {
            let key = OpenSslClassicalLabKey::generate(suite).unwrap();
            let sig = key.sign(suite, b"x509-tbs").unwrap();
            assert!(!sig.is_empty());
            assert_eq!(key.verify(suite, b"x509-tbs", &sig), Ok(()));
            assert_eq!(
                key.verify(suite, b"tampered-tbs", &sig),
                Err(OpenSslLabError::InvalidSignature)
            );
            assert_eq!(
                key.sign(CASES[0], b"x509-tbs").is_err(),
                suite != CASES[0]
            );
            let mut damaged = sig;
            damaged[0] ^= 1;
            assert_eq!(
                key.verify(suite, b"x509-tbs", &damaged),
                Err(OpenSslLabError::InvalidSignature)
            );
        }
    }
}
