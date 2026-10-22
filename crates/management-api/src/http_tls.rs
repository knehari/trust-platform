//! HTTP transport for the lab APIs that carry bearer tokens (management read
//! API, revocation API, CA-admin API). LAB ONLY.
//!
//! With `TRUST_HTTP_TLS_CERT_FILE` and `TRUST_HTTP_TLS_KEY_FILE` (PEM: the
//! server certificate chain and its private key) the API serves TLS 1.3 only,
//! through rustls with the ring provider. Without them it serves plaintext
//! HTTP only on a loopback address (a local client or a TLS-terminating proxy
//! on the same host). Plaintext on any other address needs the explicit lab
//! opt-out `TRUST_HTTP_TLS=disable-lab`, which the caller logs; otherwise the
//! API refuses to start. The CRL distribution point does not use this: CRLs
//! are signed objects served over plain HTTP (RFC 5280 section 4.2.1.13).
//!
//! Handshakes run off the accept loop, at most `MAX_HANDSHAKES` at a time and
//! each within `HANDSHAKE_TIMEOUT`, so a slow or silent client cannot hold up
//! the others; connections beyond the limit are closed.
use axum::{serve::Listener, Router};
use rustls::{
    crypto::ring,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use std::{io, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

pub const MODE_ENV: &str = "TRUST_HTTP_TLS";
pub const CERT_FILE_ENV: &str = "TRUST_HTTP_TLS_CERT_FILE";
pub const KEY_FILE_ENV: &str = "TRUST_HTTP_TLS_KEY_FILE";
const DISABLE_LAB: &str = "disable-lab";
const MAX_HANDSHAKES: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub enum HttpTls {
    /// TLS 1.3 with the configured certificate chain and key.
    Enabled(Arc<ServerConfig>),
    /// Plaintext, allowed on a loopback address only.
    LoopbackOnly,
    /// Plaintext on any address: disposable lab networks only.
    DisabledForLab,
}

/// Reads the settings; files are loaded here, so a bad file fails at startup.
pub fn from_settings(
    mode: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<HttpTls, String> {
    let cert_file = cert_file.filter(|path| !path.is_empty());
    let key_file = key_file.filter(|path| !path.is_empty());
    match (mode, cert_file, key_file) {
        (Some(DISABLE_LAB), None, None) => Ok(HttpTls::DisabledForLab),
        (Some(DISABLE_LAB), _, _) => Err(format!(
            "{MODE_ENV}={DISABLE_LAB} cannot be combined with {CERT_FILE_ENV}/{KEY_FILE_ENV}"
        )),
        (Some(_), _, _) => Err(format!("{MODE_ENV} must be unset or {DISABLE_LAB}")),
        (None, Some(cert), Some(key)) => Ok(HttpTls::Enabled(Arc::new(server_config(
            Path::new(cert),
            Path::new(key),
        )?))),
        (None, None, None) => Ok(HttpTls::LoopbackOnly),
        (None, _, _) => Err(format!("{CERT_FILE_ENV} and {KEY_FILE_ENV} go together")),
    }
}

pub fn from_env() -> Result<HttpTls, String> {
    from_settings(
        std::env::var(MODE_ENV).ok().as_deref(),
        std::env::var(CERT_FILE_ENV).ok().as_deref(),
        std::env::var(KEY_FILE_ENV).ok().as_deref(),
    )
}

fn server_config(cert_file: &Path, key_file: &Path) -> Result<ServerConfig, String> {
    let chain = CertificateDer::pem_file_iter(cert_file)
        .map_err(|_| format!("cannot read {CERT_FILE_ENV}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("invalid PEM in {CERT_FILE_ENV}"))?;
    if chain.is_empty() {
        return Err(format!("{CERT_FILE_ENV} contains no certificate"));
    }
    let key = PrivateKeyDer::from_pem_file(key_file)
        .map_err(|_| format!("cannot read a private key from {KEY_FILE_ENV}"))?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "TLS 1.3 unavailable".to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|_| format!("{KEY_FILE_ENV} does not match {CERT_FILE_ENV}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Whether plaintext may be served on this bound address.
pub fn plaintext_allowed(tls: &HttpTls, local: SocketAddr) -> bool {
    match tls {
        HttpTls::Enabled(_) => false,
        HttpTls::LoopbackOnly => local.ip().is_loopback(),
        HttpTls::DisabledForLab => true,
    }
}

/// Refuses a bound listener the policy does not allow plaintext on.
pub fn check_bind(tls: &HttpTls, listener: &TcpListener) -> io::Result<()> {
    let local = listener.local_addr()?;
    if matches!(tls, HttpTls::Enabled(_)) || plaintext_allowed(tls, local) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "refusing plaintext HTTP on {local}: set {CERT_FILE_ENV} and {KEY_FILE_ENV}, \
             bind a loopback address, or set {MODE_ENV}={DISABLE_LAB} (lab only)"
        ),
    ))
}

/// Serves `router` on an already bound listener under the transport policy.
pub async fn serve(listener: TcpListener, router: Router, tls: HttpTls) -> io::Result<()> {
    check_bind(&tls, &listener)?;
    let local = listener.local_addr()?;
    match tls {
        HttpTls::Enabled(config) => {
            axum::serve(TlsListener::new(listener, config, local), router).await
        }
        _ => axum::serve(listener, router).await,
    }
}

/// A listener yielding only connections whose TLS handshake completed.
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    fn new(listener: TcpListener, config: Arc<ServerConfig>, local: SocketAddr) -> Self {
        let (sender, ready) = mpsc::channel(MAX_HANDSHAKES);
        let acceptor = TlsAcceptor::from(config);
        let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        tokio::spawn(async move {
            while !sender.is_closed() {
                let (stream, peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    // Out of file descriptors and the like: back off briefly.
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                // Over the limit: close the connection rather than queue it.
                let Ok(permit) = handshakes.clone().try_acquire_owned() else {
                    continue;
                };
                let (acceptor, sender) = (acceptor.clone(), sender.clone());
                tokio::spawn(async move {
                    let handshake =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream));
                    if let Ok(Ok(stream)) = handshake.await {
                        drop(permit);
                        let _ = sender.send((stream, peer)).await;
                    }
                });
            }
        });
        Self { ready, local }
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(connection) => connection,
            // The accept task only ends once this listener is gone.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs};

    fn temp_file(name: &str, contents: &str) -> String {
        let path = env::temp_dir().join(format!("trust-http-tls-{}-{name}", std::process::id()));
        fs::write(&path, contents).expect("write temp file");
        path.to_string_lossy().into_owned()
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:8081".parse().expect("address")
    }

    fn any() -> SocketAddr {
        "0.0.0.0:8081".parse().expect("address")
    }

    #[test]
    fn plaintext_is_refused_off_loopback_unless_lab_opt_out() {
        let default = from_settings(None, None, None).expect("defaults");
        assert!(plaintext_allowed(&default, loopback()));
        assert!(plaintext_allowed(
            &default,
            "[::1]:8081".parse().expect("address")
        ));
        assert!(!plaintext_allowed(&default, any()));
        assert!(!plaintext_allowed(
            &default,
            "10.0.0.5:8081".parse().expect("address")
        ));
        let lab = from_settings(Some("disable-lab"), None, None).expect("lab opt-out");
        assert!(plaintext_allowed(&lab, any()));
    }

    #[test]
    fn bad_settings_fail_closed() {
        assert!(from_settings(Some("verify-full"), None, None).is_err());
        assert!(from_settings(Some(""), None, None).is_err());
        assert!(from_settings(None, Some("/nonexistent/cert.pem"), None).is_err());
        assert!(from_settings(None, None, Some("/nonexistent/key.pem")).is_err());
        assert!(from_settings(Some("disable-lab"), Some("/x"), Some("/y")).is_err());
        assert!(from_settings(
            None,
            Some("/nonexistent/cert.pem"),
            Some("/nonexistent/key.pem")
        )
        .is_err());
        let empty = temp_file("empty.pem", "");
        let garbage = temp_file("garbage.pem", "-----BEGIN CERTIFICATE-----\nnot base64\n");
        assert!(from_settings(None, Some(&empty), Some(&empty)).is_err());
        assert!(from_settings(None, Some(&garbage), Some(&garbage)).is_err());
        let _ = fs::remove_file(empty);
        let _ = fs::remove_file(garbage);
    }

    #[tokio::test]
    async fn refuses_to_serve_plaintext_on_a_non_loopback_address() {
        let listener = TcpListener::bind("0.0.0.0:0").await.expect("bind");
        let tls = from_settings(None, None, None).expect("defaults");
        let error = serve(listener, Router::new(), tls)
            .await
            .expect_err("plaintext off loopback must be refused");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    /// End to end over TLS 1.3, with a certificate made by
    /// tests/http_tls.sh (TRUST_HTTP_TLS_TEST_DIR: ca.pem, server.pem,
    /// server.key for "localhost"). Skipped without it.
    #[tokio::test]
    async fn serves_tls13_only_with_the_configured_certificate() {
        let Ok(dir) = env::var("TRUST_HTTP_TLS_TEST_DIR") else {
            if env::var("TRUST_REQUIRE_HTTP_TLS_TEST").is_ok() {
                panic!("TRUST_HTTP_TLS_TEST_DIR is required");
            }
            eprintln!("skipped: TRUST_HTTP_TLS_TEST_DIR not set");
            return;
        };
        use axum::routing::get;
        use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsConnector;

        let path = |name: &str| format!("{dir}/{name}");
        let tls = from_settings(None, Some(&path("server.pem")), Some(&path("server.key")))
            .expect("TLS settings");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let router = Router::new().route("/ping", get(|| async { "pong" }));
        tokio::spawn(serve(listener, router, tls));

        // A client trusting the test CA gets the response over TLS 1.3.
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_file_iter(path("ca.pem")).expect("CA file") {
            roots.add(certificate.expect("CA PEM")).expect("CA");
        }
        let client = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let mut stream = connector
            .connect(ServerName::try_from("localhost").expect("name"), tcp)
            .await
            .expect("TLS handshake");
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        stream
            .write_all(b"GET /ping HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
            .await
            .expect("request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("response");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("pong"), "{response}");

        // A client offering only TLS 1.2 is refused.
        let mut roots12 = RootCertStore::empty();
        for certificate in CertificateDer::pem_file_iter(path("ca.pem")).expect("CA file") {
            roots12.add(certificate.expect("CA PEM")).expect("CA");
        }
        let client12 = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2")
            .with_root_certificates(roots12)
            .with_no_client_auth();
        let tcp = TcpStream::connect(addr).await.expect("connect");
        assert!(
            TlsConnector::from(Arc::new(client12))
                .connect(ServerName::try_from("localhost").expect("name"), tcp)
                .await
                .is_err(),
            "a TLS 1.2 client must be refused"
        );

        // A plaintext request on the TLS port gets no HTTP response.
        let mut plain = TcpStream::connect(addr).await.expect("connect");
        plain
            .write_all(b"GET /ping HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .expect("request");
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut answer)).await;
        assert!(!String::from_utf8_lossy(&answer).contains("pong"));
        assert!(!answer.starts_with(b"HTTP/"));
    }
}
