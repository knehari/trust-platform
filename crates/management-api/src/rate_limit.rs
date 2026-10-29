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
    net::{IpAddr, SocketAddr},
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

/// Fixed windows per key: (window start, requests counted in it).
type Windows = Mutex<HashMap<(String, String), (Instant, u32)>>;

pub struct RateLimiter {
    limit: u32,
    window: Duration,
    windows: Windows,
    /// For `allow_peer` only: once `windows` is full, new addresses are
    /// counted here under their /48 (IPv6) or /24 (IPv4), also bounded.
    overflow: Windows,
    /// For `limit_peers` only: reverse proxies whose X-Forwarded-For is
    /// read (`TRUSTED_PROXIES_ENV`); empty, the header is ignored.
    trusted_proxies: Vec<IpNet>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            windows: Mutex::new(HashMap::new()),
            overflow: Mutex::new(HashMap::new()),
            trusted_proxies: Vec::new(),
        }
    }

    /// The same limiter, reading X-Forwarded-For from these proxies only.
    pub fn trusting(mut self, proxies: Vec<IpNet>) -> Self {
        self.trusted_proxies = proxies;
        self
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

    /// Counts one request for a client address (`limit_peers`). When the
    /// table is full of addresses still in their window (a flood from many
    /// addresses, such as the /64s of one IPv6 /48), a new address is
    /// counted under its aggregate prefix instead (IPv6 /48, IPv4 /24): the
    /// flood then spends its own prefix's budget and other prefixes keep
    /// theirs. Only when the prefix table is full too is the request
    /// refused.
    pub fn allow_peer(&self, addr: Option<IpAddr>) -> bool {
        self.allow_peer_at(addr, Instant::now())
    }

    fn allow_peer_at(&self, addr: Option<IpAddr>, now: Instant) -> bool {
        match self.count(&self.windows, ("peer".into(), peer_key(addr)), now) {
            Count::Full => {
                let key = ("prefix".into(), aggregate_key(addr));
                matches!(self.count(&self.overflow, key, now), Count::Allowed)
            }
            outcome => matches!(outcome, Count::Allowed),
        }
    }

    fn allow_at(&self, issuer: &str, subject: &str, now: Instant) -> bool {
        let key = (issuer.to_owned(), subject.to_owned());
        matches!(self.count(&self.windows, key, now), Count::Allowed)
    }

    fn count(&self, table: &Windows, key: (String, String), now: Instant) -> Count {
        let Ok(mut windows) = table.lock() else {
            return Count::Refused;
        };
        if !windows.contains_key(&key) && windows.len() >= MAX_TRACKED {
            let window = self.window;
            windows.retain(|_, (start, _)| now.duration_since(*start) < window);
            if windows.len() >= MAX_TRACKED {
                return Count::Full;
            }
        }
        let entry = windows.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= self.limit {
            return Count::Refused;
        }
        entry.1 += 1;
        Count::Allowed
    }
}

/// The TCP peer of a request, as `ConnectInfo<ClientAddr>` (inserted by
/// `http_serve::serve` for every request).
#[derive(Clone, Copy, Debug)]
pub struct ClientAddr(pub SocketAddr);

/// Comma-separated IP addresses or CIDR prefixes of the reverse proxies in
/// front of a service. Unset or empty: forwarded headers are never read.
pub const TRUSTED_PROXIES_ENV: &str = "TRUST_HTTP_TRUSTED_PROXIES";

/// An IP prefix (an address is a /32 or /128).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::str::FromStr for IpNet {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let invalid = || format!("{TRUSTED_PROXIES_ENV}: invalid address or prefix {text:?}");
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| invalid())?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) if prefix.bytes().all(|b| b.is_ascii_digit()) && !prefix.is_empty() => {
                prefix.parse::<u8>().map_err(|_| invalid())?
            }
            Some(_) => return Err(invalid()),
            None => max,
        };
        if prefix > max {
            return Err(invalid());
        }
        Ok(Self { addr, prefix })
    }
}

/// Parses `TRUSTED_PROXIES_ENV`; any invalid entry refuses the whole
/// setting (the service does not start).
pub fn trusted_proxies(setting: Option<&str>) -> Result<Vec<IpNet>, String> {
    setting
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::parse)
        .collect()
}

pub fn trusted_proxies_from_env() -> Result<Vec<IpNet>, String> {
    trusted_proxies(std::env::var(TRUSTED_PROXIES_ENV).ok().as_deref())
}

/// The address a request is counted under. The TCP peer, unless the peer is
/// a trusted proxy: then the X-Forwarded-For entries (all header lines, in
/// order) are read from the right, skipping trusted proxies, and the first
/// other address is the client. Entries left of it were supplied by the
/// client and are ignored. No header, only trusted hops, or any malformed
/// entry on the way: the proxy's own address (its clients then share its
/// budget, they never get a budget of their choosing).
pub fn client_ip(peer: IpAddr, forwarded: &[&str], trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(peer) {
        return peer;
    }
    let entries: Vec<&str> = forwarded.iter().flat_map(|line| line.split(',')).collect();
    for entry in entries.iter().rev() {
        let Ok(ip) = entry.trim().parse::<IpAddr>() else {
            return peer;
        };
        if !is_trusted(ip) {
            return ip.to_canonical();
        }
    }
    peer
}

enum Count {
    Allowed,
    Refused,
    /// The table is full of keys still in their window.
    Full,
}

/// The coarser key a new address is counted under once the address table is
/// full: the IPv4 /24 or the IPv6 /48.
fn aggregate_key(addr: Option<IpAddr>) -> String {
    match addr.map(|ip| ip.to_canonical()) {
        Some(IpAddr::V4(ip)) => {
            let o = ip.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Some(IpAddr::V6(ip)) => {
            let s = ip.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        None => "unknown".to_owned(),
    }
}

/// The key a client address is counted under: the IPv4 address, or the /64
/// prefix of an IPv6 address (one host usually holds a whole /64; an
/// IPv4-mapped address counts as IPv4). Forwarded headers are read only
/// from trusted proxies (`client_ip`).
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
    client: Result<ConnectInfo<ClientAddr>, ExtensionRejection>,
    request: Request,
    next: Next,
) -> Response {
    let forwarded: Vec<&str> = request
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .map(|value| value.to_str().unwrap_or("\u{0}"))
        .collect();
    let addr = client
        .ok()
        .map(|ConnectInfo(addr)| client_ip(addr.0.ip(), &forwarded, &peers.trusted_proxies));
    if !peers.allow_peer(addr) {
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
    fn trusted_proxy_settings_parse_strictly() {
        let nets = trusted_proxies(Some(" 10.0.0.0/8, 192.0.2.1 ,2001:db8::/32,")).unwrap();
        assert_eq!(nets.len(), 3);
        assert!(nets[0].contains("10.200.0.1".parse().unwrap()));
        assert!(!nets[0].contains("11.0.0.1".parse().unwrap()));
        assert!(nets[1].contains("::ffff:192.0.2.1".parse().unwrap()));
        assert!(nets[2].contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!nets[2].contains("10.0.0.1".parse().unwrap()));
        assert!(trusted_proxies(None).unwrap().is_empty());
        assert!(trusted_proxies(Some("")).unwrap().is_empty());
        for bad in [
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/-1",
            "proxy.lab",
            "10.0.0.0/8/8",
            "2001:db8::/129",
            "10.0.0.1, nope",
        ] {
            assert!(trusted_proxies(Some(bad)).is_err(), "{bad}");
        }
        assert!(
            trusted_proxies(Some("0.0.0.0/0")).unwrap()[0].contains("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn forwarded_addresses_count_only_behind_trusted_proxies() {
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        let trusted = trusted_proxies(Some("10.0.0.0/8")).unwrap();
        // Not from a trusted proxy: the header is the client's own claim.
        assert_eq!(
            client_ip(ip("203.0.113.9"), &["198.51.100.1"], &trusted),
            ip("203.0.113.9")
        );
        assert_eq!(
            client_ip(ip("10.0.0.2"), &["198.51.100.1"], &[]),
            ip("10.0.0.2")
        );
        // From a trusted proxy: the rightmost address it did not add itself.
        assert_eq!(
            client_ip(ip("10.0.0.2"), &["198.51.100.1"], &trusted),
            ip("198.51.100.1")
        );
        assert_eq!(
            client_ip(
                ip("10.0.0.2"),
                &["6.6.6.6, 198.51.100.1, 10.0.0.7"],
                &trusted
            ),
            ip("198.51.100.1"),
            "a client-supplied entry left of the real client is ignored"
        );
        assert_eq!(
            client_ip(
                ip("10.0.0.2"),
                &["6.6.6.6", "198.51.100.1 , 10.0.0.7"],
                &trusted
            ),
            ip("198.51.100.1"),
            "several header lines are read in order"
        );
        // No header, only trusted hops, or anything malformed: the proxy's
        // own address (all such clients share its budget).
        assert_eq!(client_ip(ip("10.0.0.2"), &[], &trusted), ip("10.0.0.2"));
        assert_eq!(
            client_ip(ip("10.0.0.2"), &["10.0.0.7"], &trusted),
            ip("10.0.0.2")
        );
        for bad in [
            "198.51.100.1, garbage",
            "",
            " , ",
            "198.51.100.1:443",
            "\u{0}",
        ] {
            assert_eq!(
                client_ip(ip("10.0.0.2"), &[bad], &trusted),
                ip("10.0.0.2"),
                "{bad:?}"
            );
        }
    }

    /// One IPv6 /48 holds 65,536 /64s: filling the table from them must not
    /// lock every other client out. Once the table is full, a new address
    /// is counted under its /48 (IPv4: /24) instead, so the flood only
    /// spends its own prefix's budget.
    #[test]
    fn a_full_address_table_does_not_lock_out_other_prefixes() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        let ip = |text: String| -> Option<IpAddr> { Some(text.parse().unwrap()) };
        for i in 0..MAX_TRACKED {
            assert!(limiter.allow_peer_at(ip(format!("2001:db8:1:{i:x}::1")), start));
        }
        // Another prefix still gets its budget, then is refused as usual.
        for _ in 0..2 {
            assert!(limiter.allow_peer_at(ip("2001:db8:2::1".into()), start));
        }
        assert!(!limiter.allow_peer_at(ip("2001:db8:2::1".into()), start));
        assert!(limiter.allow_peer_at(ip("192.0.2.7".into()), start));
        // The flooding /48 shares one budget for its new /64s.
        assert!(limiter.allow_peer_at(ip("2001:db8:1:ffff::1".into()), start));
        assert!(limiter.allow_peer_at(ip("2001:db8:1:fffe::1".into()), start));
        assert!(!limiter.allow_peer_at(ip("2001:db8:1:fffd::1".into()), start));
        // Addresses already tracked keep their own budget.
        assert!(limiter.allow_peer_at(ip("2001:db8:1:0::1".into()), start));
        assert!(!limiter.allow_peer_at(ip("2001:db8:1:0::1".into()), start));
        // Expired windows make room again.
        let later = start + Duration::from_secs(61);
        assert!(limiter.allow_peer_at(ip("2001:db8:3::1".into()), later));
    }

    /// Both tables full of live windows: refused, never unlimited.
    #[test]
    fn a_full_prefix_table_fails_closed() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        let start = Instant::now();
        let v4 = |a: usize, b: usize| -> Option<IpAddr> {
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                (a >> 8) as u8,
                a as u8,
                b as u8,
            )))
        };
        for i in 0..MAX_TRACKED {
            assert!(limiter.allow_peer_at(v4(i % 40, i / 40), start));
        }
        for i in 40..MAX_TRACKED + 40 {
            assert!(limiter.allow_peer_at(v4(i, 1), start), "prefix {i}");
        }
        assert!(!limiter.allow_peer_at(v4(MAX_TRACKED + 41, 1), start));
        assert!(limiter.allow_peer_at(v4(MAX_TRACKED + 41, 1), start + Duration::from_secs(61)));
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
