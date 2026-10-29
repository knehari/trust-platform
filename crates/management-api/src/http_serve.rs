//! Connection handling shared by the lab HTTP services (the token APIs and
//! the CRL distribution point). LAB ONLY.
//!
//! `axum::serve` sets no timer on its HTTP/1 connections, so hyper's
//! header-read timeout never applies, and it accepts any number of
//! connections: a client sending a request header one byte at a time, or
//! opening idle connections, holds sockets and memory for as long as it
//! likes. `serve` here bounds both:
//! * at most `Limits::max_connections` connections at once; beyond that a
//!   new connection is closed as soon as it is accepted;
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
use crate::rate_limit::ClientAddr;
use axum::{body::Body, extract::ConnectInfo, serve::Listener, Router};
use hyper::{body::Incoming, server::conn::http1, Request};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tower::ServiceExt;

/// Connections served at once, per process.
pub const MAX_CONNECTIONS: usize = 1024;
/// Time allowed to receive a complete request header.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed to receive a request body and answer the request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_connections: usize,
    pub header_read_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            header_read_timeout: HEADER_READ_TIMEOUT,
            request_timeout: REQUEST_TIMEOUT,
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
    loop {
        let (io, addr) = listener.accept().await;
        // Over the limit: close at once rather than queue.
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            drop(io);
            continue;
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
                .header_read_timeout(limits.header_read_timeout)
                .serve_connection(TokioIo::new(io), service)
                .with_upgrades()
                .await;
            drop(permit);
        });
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

    #[tokio::test]
    async fn connections_beyond_the_limit_are_closed() {
        let addr = start(Limits {
            max_connections: 2,
            header_read_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
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
