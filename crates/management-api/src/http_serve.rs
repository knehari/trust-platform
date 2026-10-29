//! Connection handling shared by the lab HTTP services (the token APIs and
//! the CRL distribution point). LAB ONLY.
//!
//! `axum::serve` sets no timer on its HTTP/1 connections, so hyper's
//! header-read timeout never applies, and it accepts any number of
//! connections: a client sending a request header one byte at a time, or
//! opening idle connections, holds sockets and memory for as long as it
//! likes. `serve` here bounds both:
//! * at most `Limits::max_connections` connections at once, and at most
//!   `Limits::max_per_address` from one client address (IPv4 address or
//!   IPv6 /64; the reverse proxies in `Limits::trusted_proxies` are only
//!   bound by the total, they carry many clients); beyond that a new
//!   connection is closed as soon as it is accepted, so one client cannot
//!   take the connections the others need;
//! * a request header must arrive within `Limits::header_read_timeout`,
//!   for the first request and every later one on a kept-alive connection,
//!   or the connection is closed;
//! * a request, its body included, must be answered within
//!   `Limits::request_timeout`, or it gets 408 and the connection is
//!   closed: a body sent byte by byte cannot hold the connection either.
//!   The bound is above the database statement timeouts, so it only ends
//!   requests that wait on the client (or hang).
//!
//! HTTP/1.1 only, as the TLS listener advertises with ALPN. Each request
//! carries its client address as `ConnectInfo<ClientAddr>`.
use crate::rate_limit::{ClientAddr, IpNet};
use axum::{body::Body, extract::ConnectInfo, serve::Listener, Router};
use hyper::{body::Incoming, server::conn::http1, Request};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Semaphore;
use tower::ServiceExt;

/// Connections served at once, per process.
pub const MAX_CONNECTIONS: usize = 1024;
/// Connections served at once from one client address, per process.
pub const MAX_CONNECTIONS_PER_ADDRESS: usize = 64;
/// Time allowed to receive a complete request header.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed to receive a request body and answer the request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_connections: usize,
    pub max_per_address: usize,
    pub header_read_timeout: Duration,
    pub request_timeout: Duration,
    /// Exempt from `max_per_address` (TRUST_HTTP_TRUSTED_PROXIES).
    pub trusted_proxies: Vec<IpNet>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            max_per_address: MAX_CONNECTIONS_PER_ADDRESS,
            header_read_timeout: HEADER_READ_TIMEOUT,
            request_timeout: REQUEST_TIMEOUT,
            trusted_proxies: Vec::new(),
        }
    }
}

/// Serves `router` on `listener` within `limits`. Runs until the listener
/// fails for good (it never does for the listeners used here).
pub async fn serve<L>(mut listener: L, router: Router, limits: Limits) -> io::Result<()>
where
    L: Listener<Addr = SocketAddr>,
{
    let router = router.layer(axum::middleware::from_fn_with_state(
        limits.request_timeout,
        request_deadline,
    ));
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    let per_address = Arc::new(PerAddress {
        limit: limits.max_per_address,
        open: Mutex::new(HashMap::new()),
    });
    let header_read_timeout = limits.header_read_timeout;
    loop {
        let (io, addr) = listener.accept().await;
        // Over the limit: close at once rather than queue.
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            drop(io);
            continue;
        };
        // A trusted proxy carries many clients: only the total binds it.
        let ip = addr.ip();
        let address_slot = if limits.trusted_proxies.iter().any(|net| net.contains(ip)) {
            None
        } else {
            match per_address
                .clone()
                .take(crate::rate_limit::peer_key(Some(ip)))
            {
                Some(slot) => Some(slot),
                None => {
                    drop(io);
                    continue;
                }
            }
        };
        let service = router
            .clone()
            .map_request(move |mut request: Request<Incoming>| {
                request
                    .extensions_mut()
                    .insert(ConnectInfo(ClientAddr(addr)));
                request.map(Body::new)
            });
        let service = TowerToHyperService::new(service);
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout)
                .serve_connection(TokioIo::new(io), service)
                .with_upgrades()
                .await;
            drop(address_slot);
            drop(permit);
        });
    }
}

/// Open connections per client address key (`rate_limit::peer_key`).
struct PerAddress {
    limit: usize,
    open: Mutex<HashMap<String, usize>>,
}

impl PerAddress {
    /// One more connection for `key`, or None at its limit (or if the count
    /// cannot be read: refused, never unbounded).
    fn take(self: Arc<Self>, key: String) -> Option<AddressSlot> {
        let mut open = self.open.lock().ok()?;
        let count = open.entry(key.clone()).or_insert(0);
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        drop(open);
        Some(AddressSlot { owner: self, key })
    }
}

/// Released when the connection ends.
struct AddressSlot {
    owner: Arc<PerAddress>,
    key: String,
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        if let Ok(mut open) = self.owner.open.lock() {
            if let Some(count) = open.get_mut(&self.key) {
                *count -= 1;
                if *count == 0 {
                    open.remove(&self.key);
                }
            }
        }
    }
}

/// Answers 408 (and closes the connection) once the request, its body
/// included, has run for `deadline`.
async fn request_deadline(
    axum::extract::State(deadline): axum::extract::State<Duration>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match tokio::time::timeout(deadline, next.run(request)).await {
        Ok(response) => response,
        Err(_) => (
            axum::http::StatusCode::REQUEST_TIMEOUT,
            [(axum::http::header::CONNECTION, "close")],
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::ConnectInfo, routing::get};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{timeout, Instant},
    };

    async fn start(limits: Limits) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let router =
            Router::new()
                .route(
                    "/peer",
                    get(|ConnectInfo(peer): ConnectInfo<ClientAddr>| async move {
                        peer.0.ip().to_string()
                    }),
                )
                .route(
                    "/echo",
                    axum::routing::post(|body: String| async move { body }),
                )
                .route(
                    "/hang",
                    get(|| async {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        "late"
                    }),
                );
        tokio::spawn(serve(listener, router, limits));
        addr
    }

    async fn get_peer(addr: SocketAddr) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"GET /peer HTTP/1.1\r\nhost: lab\r\nconnection: close\r\n\r\n")
            .await
            .expect("request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("response");
        String::from_utf8_lossy(&response).into_owned()
    }

    /// Whether the server closes the connection within `within`.
    async fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
        let mut buffer = [0u8; 1024];
        let deadline = Instant::now() + within;
        loop {
            match timeout(deadline - Instant::now(), stream.read(&mut buffer)).await {
                Err(_) => return false,
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                // A 408 or similar before closing is fine.
                Ok(Ok(_)) => continue,
            }
        }
    }

    #[tokio::test]
    async fn a_slow_request_header_is_cut_off() {
        let addr = start(Limits {
            max_connections: 8,
            header_read_timeout: Duration::from_millis(300),
            request_timeout: Duration::from_secs(30),
            ..Limits::default()
        })
        .await;
        let mut slow = TcpStream::connect(addr).await.expect("connect");
        slow.write_all(b"GET /peer HTTP/1.1\r\nhost: lab\r\n")
            .await
            .expect("partial header");
        assert!(
            closed_within(&mut slow, Duration::from_secs(3)).await,
            "a connection that never finishes its header stays open"
        );
        // A connection that says nothing at all is cut off too.
        let mut silent = TcpStream::connect(addr).await.expect("connect");
        assert!(closed_within(&mut silent, Duration::from_secs(3)).await);
        // Normal requests are served, with the client address.
        assert!(get_peer(addr).await.ends_with("127.0.0.1"));
    }

    /// A body sent too slowly, or a handler that hangs, ends with 408 and
    /// a closed connection.
    #[tokio::test]
    async fn slow_bodies_and_hung_requests_end_with_408() {
        let addr = start(Limits {
            max_connections: 8,
            header_read_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_millis(400),
            ..Limits::default()
        })
        .await;
        let read_all = |mut stream: TcpStream| async move {
            let mut response = Vec::new();
            let read = timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
            (
                read.is_ok(),
                String::from_utf8_lossy(&response).into_owned(),
            )
        };
        let mut slow = TcpStream::connect(addr).await.expect("connect");
        slow.write_all(
            b"POST /echo HTTP/1.1\r\nhost: lab\r\ncontent-length: 100\r\n\r\nten bytes.",
        )
        .await
        .expect("partial body");
        let (closed, response) = read_all(slow).await;
        assert!(closed, "a slow body held the connection");
        assert!(response.starts_with("HTTP/1.1 408"), "{response}");
        let mut hung = TcpStream::connect(addr).await.expect("connect");
        hung.write_all(b"GET /hang HTTP/1.1\r\nhost: lab\r\n\r\n")
            .await
            .expect("request");
        let (closed, response) = read_all(hung).await;
        assert!(closed, "a hung request held the connection");
        assert!(response.starts_with("HTTP/1.1 408"), "{response}");
        // A complete body in time is served.
        let mut quick = TcpStream::connect(addr).await.expect("connect");
        quick
            .write_all(b"POST /echo HTTP/1.1\r\nhost: lab\r\nconnection: close\r\ncontent-length: 5\r\n\r\nhello")
            .await
            .expect("request");
        let (_, response) = read_all(quick).await;
        assert!(
            response.starts_with("HTTP/1.1 200") && response.ends_with("hello"),
            "{response}"
        );
    }

    /// One address cannot take every connection: past its own limit its
    /// new connections are closed, while another address is still served.
    #[tokio::test]
    async fn one_address_cannot_take_every_connection() {
        let addr = start(Limits {
            max_connections: 8,
            max_per_address: 2,
            ..Limits::default()
        })
        .await;
        let from = |source: &'static str| async move {
            let socket = tokio::net::TcpSocket::new_v4().expect("socket");
            socket
                .bind(format!("{source}:0").parse().expect("source"))
                .expect("bind source");
            socket.connect(addr).await.expect("connect")
        };
        let first = from("127.0.0.1").await;
        let second = from("127.0.0.1").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut third = from("127.0.0.1").await;
        assert!(
            closed_within(&mut third, Duration::from_secs(2)).await,
            "a connection beyond the address's limit was kept"
        );
        // Another address still gets in, and the first one does again once
        // its connections end.
        let mut other = from("127.0.0.2").await;
        other
            .write_all(b"GET /peer HTTP/1.1\r\nhost: lab\r\nconnection: close\r\n\r\n")
            .await
            .expect("request");
        let mut response = Vec::new();
        other.read_to_end(&mut response).await.expect("response");
        assert!(String::from_utf8_lossy(&response).ends_with("127.0.0.2"));
        drop(first);
        drop(second);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(get_peer(addr).await.starts_with("HTTP/1.1 200"));
    }

    /// A trusted reverse proxy is bound by the total only.
    #[tokio::test]
    async fn trusted_proxies_are_bound_by_the_total_only() {
        let addr = start(Limits {
            max_connections: 4,
            max_per_address: 1,
            trusted_proxies: crate::rate_limit::trusted_proxies(Some("127.0.0.1"))
                .expect("proxies"),
            ..Limits::default()
        })
        .await;
        let held: Vec<TcpStream> = vec![
            TcpStream::connect(addr).await.expect("connect"),
            TcpStream::connect(addr).await.expect("connect"),
        ];
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(get_peer(addr).await.starts_with("HTTP/1.1 200"));
        drop(held);
    }

    #[tokio::test]
    async fn connections_beyond_the_limit_are_closed() {
        let addr = start(Limits {
            max_connections: 2,
            header_read_timeout: Duration::from_secs(30),
            ..Limits::default()
        })
        .await;
        let first = TcpStream::connect(addr).await.expect("connect");
        let second = TcpStream::connect(addr).await.expect("connect");
        // Let the server accept both before the third arrives.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut third = TcpStream::connect(addr).await.expect("connect");
        assert!(
            closed_within(&mut third, Duration::from_secs(2)).await,
            "a connection beyond the limit was kept"
        );
        drop(first);
        drop(second);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(get_peer(addr).await.starts_with("HTTP/1.1 200"));
    }
}
