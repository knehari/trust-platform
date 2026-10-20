//! Cross-check of the database clock against the Rust core's clock (ADR-0006
//! acceptance condition 6, proposed; lab only). PostgreSQL's clock decides
//! CRL thisUpdate, intent ordering and publication deadlines; a database
//! clock that drifts or is set wrongly would sign misdated CRLs. The Rust
//! core therefore brackets each database reading between two readings of
//! its own clock and refuses to go on when they disagree beyond a bound.
//!
//! This detects disagreement between two clocks; it does not authenticate
//! time. Both hosts still need an authenticated source (NTS, or a trusted
//! time-stamping service) with drift alerting: a deployment matter. The
//! clock source is injectable so such an adapter, or a test, can supply it.

use std::time::{SystemTime, UNIX_EPOCH};

/// Microseconds since the Unix epoch.
pub type ClockSource = fn() -> i64;

/// Default bound on |database - host| plus the reading's uncertainty.
pub const DEFAULT_MAX_CLOCK_SKEW_US: i64 = 2_000_000;

/// The host's system clock, in microseconds since the Unix epoch (0 before
/// 1970, which any bound then refuses).
pub fn system_clock_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

/// One database clock reading bracketed by two host readings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockReading {
    /// Database minus the midpoint of the host bracket.
    pub skew_us: i64,
    /// Half the bracket: the database read could be anywhere within it.
    pub uncertainty_us: i64,
}

impl ClockReading {
    pub fn bracket(host_before_us: i64, database_us: i64, host_after_us: i64) -> Self {
        let span = host_after_us.saturating_sub(host_before_us).max(0);
        let midpoint = host_before_us.saturating_add(span / 2);
        Self {
            skew_us: database_us.saturating_sub(midpoint),
            uncertainty_us: span - span / 2,
        }
    }

    /// The clocks provably agree within `max_skew_us`.
    pub fn within(&self, max_skew_us: i64) -> bool {
        self.skew_us
            .saturating_abs()
            .saturating_add(self.uncertainty_us)
            <= max_skew_us
    }
}

/// A CRL thisUpdate (whole seconds, truncated from the database clock when
/// the CRL was reserved between `host_before_us` and `host_after_us`) agrees
/// with the host clock within `max_skew_us`: the reservation instant lies in
/// [thisUpdate, thisUpdate + 1 s) and must be within the bound of the
/// bracket.
pub fn this_update_plausible(
    this_update_unix: i64,
    host_before_us: i64,
    host_after_us: i64,
    max_skew_us: i64,
) -> bool {
    let earliest = this_update_unix.saturating_mul(1_000_000);
    let latest = earliest.saturating_add(999_999);
    earliest <= host_after_us.saturating_add(max_skew_us)
        && latest >= host_before_us.saturating_sub(max_skew_us)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bracket_measures_skew_and_uncertainty() {
        let reading = ClockReading::bracket(1_000_000, 1_500_000, 1_200_000);
        assert_eq!(
            reading,
            ClockReading {
                skew_us: 400_000,
                uncertainty_us: 100_000
            }
        );
        assert!(reading.within(500_000));
        assert!(!reading.within(499_999));
        let behind = ClockReading::bracket(10_000_000, 4_000_000, 10_000_000);
        assert_eq!(behind.skew_us, -6_000_000);
        assert!(!behind.within(DEFAULT_MAX_CLOCK_SKEW_US));
        // A host clock that went backwards gives no negative uncertainty.
        assert_eq!(ClockReading::bracket(5, 5, 3).uncertainty_us, 0);
    }

    #[test]
    fn this_update_is_checked_against_the_bracket() {
        let second = 1_800_000_000;
        let at = second * 1_000_000 + 400_000;
        assert!(this_update_plausible(second, at, at + 10_000, 0));
        // Database one minute ahead or behind.
        assert!(!this_update_plausible(
            second + 60,
            at,
            at,
            DEFAULT_MAX_CLOCK_SKEW_US
        ));
        assert!(!this_update_plausible(
            second - 60,
            at,
            at,
            DEFAULT_MAX_CLOCK_SKEW_US
        ));
        assert!(this_update_plausible(
            second + 2,
            at,
            at,
            DEFAULT_MAX_CLOCK_SKEW_US
        ));
        assert!(!this_update_plausible(
            second + 3,
            at,
            at,
            DEFAULT_MAX_CLOCK_SKEW_US
        ));
    }
}
