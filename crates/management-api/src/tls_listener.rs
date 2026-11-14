//! HTTPS for the management API (ADR-0032, Proposed).
//!
//! When `TRUST_API_TLS_CERT_FILE` and `TRUST_API_TLS_KEY_FILE` are both set,
//! the API serves TLS 1.2+ only (rustls, the ring provider already locked),
//! with the certificate chain and key from those PEM files. Setting only one
//! of them is a startup error, never a silent plaintext fallback.
//!
//! Handshakes run concurrently, each bounded in time, with a cap on how many
//! may be in flight, so a slow or silent client cannot hold the accept loop.
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

pub(crate) const CERT_ENV: &str = "TRUST_API_TLS_CERT_FILE";
pub(crate) const KEY_ENV: &str = "TRUST_API_TLS_KEY_FILE";
/// How long a client has to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// How many handshakes may be in progress at once.
const MAX_PENDING_HANDSHAKES: usize = 64;

/// The TLS configuration from the environment: `None` for plain HTTP (tests,
/// local development), an error when it is incomplete or unreadable.
pub(crate) fn config_from_env() -> Result<Option<ServerConfig>, String> {
    match (std::env::var_os(CERT_ENV), std::env::var_os(KEY_ENV)) {
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            let certificate = std::fs::read(cert).map_err(|_| format!("{CERT_ENV} unreadable"))?;
            let key = std::fs::read(key).map_err(|_| format!("{KEY_ENV} unreadable"))?;
            server_config(&certificate, &key).map(Some)
        }
        _ => Err(format!("set both {CERT_ENV} and {KEY_ENV}, or neither")),
    }
}

/// A TLS 1.2+ server configuration for a PEM chain and a PEM private key.
pub(crate) fn server_config(
    certificate_pem: &[u8],
    key_pem: &[u8],
) -> Result<ServerConfig, String> {
    let chain = CertificateDer::pem_slice_iter(certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "the certificate file is not PEM".to_owned())?;
    if chain.is_empty() {
        return Err("the certificate file holds no certificate".to_owned());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| "the key file holds no private key".to_owned())?;
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| "no TLS protocol version".to_owned())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|_| "the key does not match the certificate".to_owned())
}

/// Accepts TCP connections and hands axum only completed TLS sessions.
pub(crate) struct TlsListener {
    sessions: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    pub(crate) fn new(tcp: TcpListener, config: ServerConfig) -> io::Result<Self> {
        let local = tcp.local_addr()?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (sender, sessions) = mpsc::channel(MAX_PENDING_HANDSHAKES);
        let pending = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
        tokio::spawn(async move {
            loop {
                let Ok(permit) = pending.clone().acquire_owned().await else {
                    return;
                };
                let (stream, peer) = match tcp.accept().await {
                    Ok(accepted) => accepted,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let (acceptor, sender) = (acceptor.clone(), sender.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Ok(Ok(session)) =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                    {
                        let _ = sender.send((session, peer)).await;
                    }
                });
            }
        });
        Ok(Self { sessions, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Some(session) = self.sessions.recv().await {
                return session;
            }
            // The accept task ended: nothing more will come.
            std::future::pending::<()>().await;
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_or_invalid_material_is_refused() {
        assert!(server_config(b"", b"").is_err());
        assert!(server_config(
            b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
            b""
        )
        .is_err());
    }
}
