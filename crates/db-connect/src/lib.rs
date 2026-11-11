//! PostgreSQL connections for the platform's processes (ADR-0031, Proposed).
//!
//! When `TRUST_DATABASE_CA_FILE` names a PEM file, every connection:
//! - requires TLS (`sslmode=require` is forced; a URL asking for
//!   `sslmode=disable` is refused), so there is no plaintext fallback;
//! - verifies the server certificate against the certificates in that file
//!   only, never the system roots, and its name against the URL's host (an
//!   IP address must be in the certificate's IP SANs).
//!
//! Without it, connections stay plaintext, as for CI's loopback test
//! databases. The laboratory stack always sets it.
//!
//! Mutual TLS (ADR-0036, Proposed): when `TRUST_DATABASE_CLIENT_CERT_DIR`
//! is also set, every connection presents the client certificate of its own
//! login, `<dir>/<user>.crt` with the key `<dir>/<user>.key`. The server
//! then requires both that certificate (`clientcert=verify-full`: issued by
//! the service CA, common name equal to the login) and the login's password.
//! A missing or unusable certificate for the login is an error; a connection
//! never proceeds without it.
use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use postgres::{config::SslMode, Client, Config, NoTls};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore,
};
use tokio_postgres_rustls::MakeRustlsConnect;

/// The environment variable naming the trusted CA file.
pub const CA_FILE_ENV: &str = "TRUST_DATABASE_CA_FILE";
/// The environment variable naming the directory of per-login client
/// certificates (ADR-0036).
pub const CLIENT_CERT_DIR_ENV: &str = "TRUST_DATABASE_CLIENT_CERT_DIR";

#[derive(Debug)]
pub enum Error {
    /// The CA file is unreadable, empty or not PEM certificates.
    CaFile,
    /// TLS is required but the URL disables it.
    PlaintextRequested,
    /// Mutual TLS is configured but the login's certificate or key is
    /// missing, unreadable or does not match; or it is configured without a
    /// CA file, or the URL names no user.
    ClientCert,
    Postgres(postgres::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CaFile => write!(f, "{CA_FILE_ENV} is not a readable PEM CA file"),
            Error::PlaintextRequested => {
                write!(f, "TLS is required but the URL sets sslmode=disable")
            }
            Error::ClientCert => write!(
                f,
                "{CLIENT_CERT_DIR_ENV}: no usable <user>.crt and <user>.key for this login"
            ),
            // The server's own message (e.g. "connection requires a valid
            // client certificate"), not only "db error".
            Error::Postgres(error) => match error.as_db_error() {
                Some(db) => write!(f, "{error}: {}", db.message()),
                None => write!(f, "{error}"),
            },
        }
    }
}

impl std::error::Error for Error {}

impl From<postgres::Error> for Error {
    fn from(error: postgres::Error) -> Self {
        Error::Postgres(error)
    }
}

/// The trusted roots: exactly the certificates in `pem`.
fn roots(pem: &[u8]) -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    let mut count = 0;
    for certificate in CertificateDer::pem_slice_iter(pem) {
        roots
            .add(certificate.map_err(|_| Error::CaFile)?)
            .map_err(|_| Error::CaFile)?;
        count += 1;
    }
    if count == 0 {
        return Err(Error::CaFile);
    }
    Ok(roots)
}

fn builder(
    pem: &[u8],
) -> Result<rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>, Error> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::CaFile)?
            .with_root_certificates(roots(pem)?),
    )
}

/// A client TLS configuration that trusts exactly the certificates in `pem`.
pub fn client_config(pem: &[u8]) -> Result<ClientConfig, Error> {
    Ok(builder(pem)?.with_no_client_auth())
}

/// The same, presenting the client certificate chain `cert_pem` with its
/// private key `key_pem` (PKCS#8, SEC1 or PKCS#1 PEM).
pub fn client_config_with_cert(
    pem: &[u8],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<ClientConfig, Error> {
    let chain = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::ClientCert)?;
    if chain.is_empty() {
        return Err(Error::ClientCert);
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| Error::ClientCert)?;
    // rustls refuses a key that does not match the certificate.
    builder(pem)?
        .with_client_auth_cert(chain, key)
        .map_err(|_| Error::ClientCert)
}

/// The process's policy: the CA file's contents and, for mutual TLS, the
/// client certificate directory.
struct Policy {
    ca_pem: Vec<u8>,
    client_cert_dir: Option<PathBuf>,
}

fn policy_from_env() -> Result<Option<&'static Policy>, Error> {
    static POLICY: OnceLock<Result<Option<Policy>, Error>> = OnceLock::new();
    let policy = POLICY.get_or_init(|| {
        let client_cert_dir = std::env::var_os(CLIENT_CERT_DIR_ENV).map(PathBuf::from);
        match std::env::var_os(CA_FILE_ENV) {
            // Client certificates without a verified server make no sense.
            None if client_cert_dir.is_some() => Err(Error::ClientCert),
            None => Ok(None),
            Some(path) => {
                let ca_pem = std::fs::read(path).map_err(|_| Error::CaFile)?;
                roots(&ca_pem)?;
                Ok(Some(Policy {
                    ca_pem,
                    client_cert_dir,
                }))
            }
        }
    });
    match policy {
        Ok(policy) => Ok(policy.as_ref()),
        Err(Error::ClientCert) => Err(Error::ClientCert),
        Err(_) => Err(Error::CaFile),
    }
}

/// Whether connections from this process require TLS.
pub fn tls_required() -> bool {
    matches!(policy_from_env(), Ok(Some(_)))
}

/// Whether connections from this process present a client certificate.
pub fn client_cert_required() -> bool {
    matches!(policy_from_env(), Ok(Some(policy)) if policy.client_cert_dir.is_some())
}

/// The login's certificate and key under `dir`. The login name must be a
/// plain identifier, so it cannot name a path outside `dir`.
fn login_files(dir: &std::path::Path, user: &str) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let plain = !user.is_empty()
        && user.len() <= 63
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !plain {
        return Err(Error::ClientCert);
    }
    let read = |extension: &str| {
        std::fs::read(dir.join(format!("{user}.{extension}"))).map_err(|_| Error::ClientCert)
    };
    Ok((read("crt")?, read("key")?))
}

/// Connects with `config`, under the TLS policy above. A configured but
/// unusable CA file, or a missing client certificate under mutual TLS, is
/// an error, never a fallback.
pub fn connect_config(config: &mut Config) -> Result<Client, Error> {
    let Some(policy) = policy_from_env()? else {
        return Ok(config.connect(NoTls)?);
    };
    let tls = match &policy.client_cert_dir {
        None => client_config(&policy.ca_pem)?,
        Some(dir) => {
            let user = config.get_user().ok_or(Error::ClientCert)?;
            let (cert_pem, key_pem) = login_files(dir, user)?;
            client_config_with_cert(&policy.ca_pem, &cert_pem, &key_pem)?
        }
    };
    connect_tls(config, tls)
}

/// Connects with TLS required and verified against `tls`'s roots.
pub fn connect_tls(config: &mut Config, tls: ClientConfig) -> Result<Client, Error> {
    if config.get_ssl_mode() == SslMode::Disable {
        return Err(Error::PlaintextRequested);
    }
    config.ssl_mode(SslMode::Require);
    Ok(config.connect(MakeRustlsConnect::new(tls))?)
}

/// Connects to `url` under the TLS policy above.
pub fn connect(url: &str) -> Result<Client, Error> {
    let mut config: Config = url.parse()?;
    connect_config(&mut config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ca_file_must_hold_certificates() {
        assert!(matches!(client_config(b""), Err(Error::CaFile)));
        assert!(matches!(
            client_config(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
            Err(Error::CaFile)
        ));
        assert!(matches!(
            client_config(b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"),
            Err(Error::CaFile)
        ));
    }

    #[test]
    fn client_certificates_must_be_usable_and_named_by_a_plain_login() {
        let dir = std::env::temp_dir();
        for user in ["", "../etc/passwd", "a/b", "a.b", &"x".repeat(64)] {
            assert!(matches!(login_files(&dir, user), Err(Error::ClientCert)));
        }
        assert!(matches!(
            login_files(&dir, "no_such_login_here"),
            Err(Error::ClientCert)
        ));
        assert!(matches!(
            client_config_with_cert(b"", b"", b""),
            Err(Error::CaFile) | Err(Error::ClientCert)
        ));
    }

    #[test]
    fn tls_never_falls_back_to_plaintext() {
        let mut config: Config = "postgresql://u@db/x?sslmode=disable".parse().unwrap();
        let tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
        assert!(matches!(
            connect_tls(&mut config, tls),
            Err(Error::PlaintextRequested)
        ));
    }
}
