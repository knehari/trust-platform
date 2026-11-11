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
use std::sync::{Arc, OnceLock};

use postgres::{config::SslMode, Client, Config, NoTls};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer},
    ClientConfig, RootCertStore,
};
use tokio_postgres_rustls::MakeRustlsConnect;

/// The environment variable naming the trusted CA file.
pub const CA_FILE_ENV: &str = "TRUST_DATABASE_CA_FILE";

#[derive(Debug)]
pub enum Error {
    /// The CA file is unreadable, empty or not PEM certificates.
    CaFile,
    /// TLS is required but the URL disables it.
    PlaintextRequested,
    Postgres(postgres::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CaFile => write!(f, "{CA_FILE_ENV} is not a readable PEM CA file"),
            Error::PlaintextRequested => {
                write!(f, "TLS is required but the URL sets sslmode=disable")
            }
            Error::Postgres(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<postgres::Error> for Error {
    fn from(error: postgres::Error) -> Self {
        Error::Postgres(error)
    }
}

/// A client TLS configuration that trusts exactly the certificates in `pem`.
pub fn client_config(pem: &[u8]) -> Result<ClientConfig, Error> {
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
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::CaFile)?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn tls_from_env() -> Result<Option<ClientConfig>, Error> {
    static TLS: OnceLock<Result<Option<ClientConfig>, ()>> = OnceLock::new();
    TLS.get_or_init(|| match std::env::var_os(CA_FILE_ENV) {
        None => Ok(None),
        Some(path) => std::fs::read(path)
            .ok()
            .and_then(|pem| client_config(&pem).ok())
            .map(Some)
            .ok_or(()),
    })
    .clone()
    .map_err(|()| Error::CaFile)
}

/// Whether connections from this process require TLS.
pub fn tls_required() -> bool {
    matches!(tls_from_env(), Ok(Some(_)))
}

/// Connects with `config`, under the TLS policy above. A configured but
/// unusable CA file is an error, never a plaintext fallback.
pub fn connect_config(config: &mut Config) -> Result<Client, Error> {
    match tls_from_env()? {
        Some(tls) => connect_tls(config, tls),
        None => Ok(config.connect(NoTls)?),
    }
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
