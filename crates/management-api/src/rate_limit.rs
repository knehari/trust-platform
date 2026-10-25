//! Per-identity request budget for the lab write APIs (revocation and CA
//! administration). LAB ONLY.
//!
//! Counted per verified token identity (issuer, subject), in fixed windows,
//! after authentication and before any database access. The concurrency
//! semaphore bounds load; this bounds what one identity (or a stolen token)
//! can do. It is per process and in memory: several replicas each allow the
//! budget, and a restart resets it. The write APIs therefore also consume a
//! `SharedBudget` in the database (migration 0062) on every request that
//! reaches it, which holds across replicas and restarts.
//!
//! In front of both, `limit_peers` counts every request per client address,
//! before the token is read: what a client can cost (token verification, a
//! JWKS refresh) is bounded before any identity is known.
use axum::{
    extract::{rejection::ExtensionRejection, ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Requests one identity may make per window.
pub const REQUESTS_PER_MINUTE: u32 = 60;
/// Requests one client address may make per minute, authenticated or not.
/// Several identities can share an address (NAT, a proxy), so it is ten
/// times the per-identity budget.
pub const PEER_REQUESTS_PER_MINUTE: u32 = 600;
/// Identities tracked at once; past this, expired windows are dropped and,
/// if none are, new identities are refused (fail closed).
const MAX_TRACKED: usize = 10_000;

/// The per-identity budget kept in the database for one write API (migration
/// 0062), shared by all its replicas: `limit` requests per `window_seconds`.
#[derive(Clone, Copy)]
pub struct SharedBudget {
    pub scope: &'static str,
    pub limit: u32,
    pub window_seconds: u32,
}

impl SharedBudget {
    pub fn per_minute(scope: &'static str) -> Self {
        Self {
            scope,
            limit: REQUESTS_PER_MINUTE,
            window_seconds: 60,
        }
    }
}

pub struct RateLimiter {
    limit: u32,
    window: Duration,
    windows: Mutex<HashMap<(String, String), (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn per_minute() -> Self {
        Self::new(REQUESTS_PER_MINUTE, Duration::from_secs(60))
    }

    /// The per-client-address limiter used by `limit_peers`.
    pub fn peers_per_minute() -> Self {
        Self::new(PEER_REQUESTS_PER_MINUTE, Duration::from_secs(60))
    }

    /// Counts one request for (issuer, subject); false once the window's
    /// budget is spent, or if the limiter cannot decide.
    pub fn allow(&self, issuer: &str, subject: &str) -> bool {
        self.allow_at(issuer, subject, Instant::now())
    }

    fn allow_at(&self, issuer: &str, subject: &str, now: Instant) -> bool {
        let Ok(mut windows) = self.windows.lock() else {
            return false;
        };
        let key = (issuer.to_owned(), subject.to_owned());
        if !windows.contains_key(&key) && windows.len() >= MAX_TRACKED {
            let window = self.window;
            windows.retain(|_, (start, _)| now.duration_since(*start) < window);
            if windows.len() >= MAX_TRACKED {
                return false;
            }
        }
        let entry = windows.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= self.limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// The key a client address is counted under: the IPv4 address, or the /64
/// prefix of an IPv6 address (one host usually holds a whole /64; an
/// IPv4-mapped address counts as IPv4). Forwarded headers are not trusted,
/// so behind a reverse proxy every client shares the proxy's budget.
/// Without a known address (in-process tests only: `http_tls::serve`
/// always provides it) all requests share one key.
pub fn peer_key(addr: Option<IpAddr>) -> String {
    match addr.map(|ip| ip.to_canonical()) {
        Some(IpAddr::V4(ip)) => ip.to_string(),
        Some(IpAddr::V6(ip)) => {
            let s = ip.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        None => "unknown".to_owned(),
    }
}

/// Middleware: counts the request against its client address and answers
/// 429 once the address's budget is spent, before the handler (and so
/// before the token) runs.
pub async fn limit_peers(
    State(peers): State<Arc<RateLimiter>>,
    client: Result<ConnectInfo<crate::http_tls::ClientAddr>, ExtensionRejection>,
    request: Request,
    next: Next,
) -> Response {
    let addr = client.ok().map(|ConnectInfo(addr)| addr.0.ip());
    if !peers.allow("peer", &peer_key(addr)) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_per_identity_and_window() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        assert!(limiter.allow_at("iss", "a", start));
        assert!(limiter.allow_at("iss", "a", start));
        assert!(!limiter.allow_at("iss", "a", start));
        // Another subject, or the same subject at another issuer.
        assert!(limiter.allow_at("iss", "b", start));
        assert!(limiter.allow_at("other", "a", start));
        // A new window restores the budget.
        assert!(limiter.allow_at("iss", "a", start + Duration::from_secs(60)));
    }

    #[test]
    fn client_addresses_are_keyed_by_host_or_ipv6_prefix() {
        let key = |text: &str| peer_key(Some(text.parse().unwrap()));
        assert_eq!(key("192.0.2.7"), "192.0.2.7");
        assert_eq!(key("::ffff:192.0.2.7"), "192.0.2.7");
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::9"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(peer_key(None), "unknown");
    }

    #[test]
    fn too_many_identities_fail_closed() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let start = Instant::now();
        for i in 0..MAX_TRACKED {
            assert!(limiter.allow_at("iss", &i.to_string(), start));
        }
        assert!(!limiter.allow_at("iss", "one-more", start));
        // Expired windows make room again.
        assert!(limiter.allow_at("iss", "one-more", start + Duration::from_secs(61)));
    }
}
