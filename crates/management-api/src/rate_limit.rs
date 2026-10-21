//! Per-identity request budget for the lab write APIs (revocation and CA
//! administration). LAB ONLY.
//!
//! Counted per verified token identity (issuer, subject), in fixed windows,
//! after authentication and before any database access. The concurrency
//! semaphore bounds load; this bounds what one identity (or a stolen token)
//! can do. It is per process and in memory: several replicas each allow the
//! budget, and a restart resets it.
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Requests one identity may make per window.
pub const REQUESTS_PER_MINUTE: u32 = 60;
/// Identities tracked at once; past this, expired windows are dropped and,
/// if none are, new identities are refused (fail closed).
const MAX_TRACKED: usize = 10_000;

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
