//! Lab-only scheduled CRL housekeeping for one CA (ADR-0006 part C).
//!
//! Retires reservations older than `--reserved-older-than` seconds (default
//! 3600; never signed), quarantines intents older than `--intent-older-than`
//! seconds (default 3600) and reports whether a CRL is due and how many
//! status changes are past their publication deadline.
//!
//! Exit status: 0 nothing to do, 2 attention needed (alert), 1 error.
//! The database URL is read from TRUST_DATABASE_URL; the connection is the
//! lab NoTls adapter, for a loopback or private lab database only.
//! Usage:
//!   TRUST_DATABASE_URL=postgresql://... cargo run -p trust-pki-core \
//!     --features postgres-store --example crl_housekeeping -- <ca-uuid> \
//!     [--reserved-older-than SECONDS] [--intent-older-than SECONDS]

use std::{env, process::ExitCode};
use trust_pki_core::revocation_store::PgRevocationStore;

fn seconds(args: &[String], flag: &str) -> Result<i64, String> {
    match args.iter().position(|a| a == flag) {
        None => Ok(3600),
        Some(i) => args
            .get(i + 1)
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v >= 0)
            .ok_or_else(|| format!("{flag} needs a non-negative number of seconds")),
    }
}

fn run() -> Result<bool, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let ca_id = args.first().filter(|a| !a.starts_with("--")).ok_or(
        "usage: crl_housekeeping <ca-uuid> [--reserved-older-than S] [--intent-older-than S]",
    )?;
    let reserved = seconds(&args, "--reserved-older-than")?;
    let intent = seconds(&args, "--intent-older-than")?;
    let url = env::var("TRUST_DATABASE_URL").map_err(|_| "TRUST_DATABASE_URL is not set")?;
    let mut store = PgRevocationStore::connect_lab(&url)
        .map_err(|e| format!("database connection failed: {e:?}"))?;
    let report = store
        .crl_housekeeping(ca_id, reserved, intent)
        .map_err(|e| format!("housekeeping failed: {e:?}"))?;
    println!(
        "ca={ca_id} abandoned={} quarantined={} crl_due={} overdue_changes={}",
        report.abandoned, report.quarantined, report.crl_due, report.overdue_changes
    );
    Ok(report.needs_attention())
}

fn main() -> ExitCode {
    match run() {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(2),
        Err(message) => {
            eprintln!("crl_housekeeping: {message}");
            ExitCode::FAILURE
        }
    }
}
