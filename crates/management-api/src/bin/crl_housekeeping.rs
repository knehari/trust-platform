//! Lab-only scheduled CRL housekeeping for one CA (ADR-0006 part C).
//!
//! Retires reservations older than `--reserved-older-than` seconds (default
//! 3600; never signed), quarantines intents older than `--intent-older-than`
//! seconds (default 3600) and reports whether a CRL is due and how many
//! status changes are past their publication deadline, and whether the
//! database clock agrees with this host's (ADR-0006 condition 6). It also reports
//! schema changes not yet acknowledged by a reviewed migration (0026,
//! database-wide).
//!
//! `--all` instead of a CA covers every CA with a registered issuer
//! certificate (migration 0033); a CA that fails is reported and the others
//! still run.
//!
//! Exit status: 0 nothing to do, 2 attention needed (alert), 1 error (on
//! any CA; an error outranks an alert).
//! The database URL is read from TRUST_DATABASE_URL and must be a
//! non-privileged login holding trust_crl_operator (migration 0023).
//! The database connection follows the management API's policy: TLS 1.3
//! with certificate and host name verification against
//! TRUST_DATABASE_CA_FILE by default; plaintext only with the explicit lab
//! opt-out TRUST_DATABASE_TLS=disable-lab (reported on stderr).
//! Usage:
//!   TRUST_DATABASE_URL=postgresql://... TRUST_DATABASE_CA_FILE=ca.pem \
//!     cargo run -p trust-management-api --bin crl_housekeeping -- <ca-uuid>|--all \
//!     [--reserved-older-than SECONDS] [--intent-older-than SECONDS]

#![forbid(unsafe_code)]

// The management API's PostgreSQL TLS policy (verify-full by default).
#[allow(dead_code)]
#[path = "../database.rs"]
mod database;

use std::{env, process::ExitCode};
use trust_pki_core::revocation_store::PgRevocationStore;

const NAME: &str = "crl_housekeeping";
/// One CA's housekeeping is a few statements; bound each one.
const STATEMENT_TIMEOUT_MS: u64 = 60_000;

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

/// The worst outcome over all CAs: an error outranks an alert.
enum Outcome {
    Quiet,
    Attention,
    Failed,
}

fn run() -> Result<Outcome, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let target = args.first().filter(|a| !a.starts_with("--") || *a == "--all").ok_or(
        "usage: crl_housekeeping <ca-uuid>|--all [--reserved-older-than S] [--intent-older-than S]",
    )?;
    let reserved = seconds(&args, "--reserved-older-than")?;
    let intent = seconds(&args, "--intent-older-than")?;
    let url = env::var("TRUST_DATABASE_URL").map_err(|_| "TRUST_DATABASE_URL is not set")?;
    let tls = database::tls_from_settings(
        env::var(database::TLS_MODE_ENV).ok().as_deref(),
        env::var(database::CA_FILE_ENV).ok().as_deref(),
    )?;
    if matches!(tls, database::DatabaseTls::DisabledForLab) {
        eprintln!("{NAME}: database TLS disabled (lab opt-out)");
    }
    let client = database::connect_client(&url, &tls, STATEMENT_TIMEOUT_MS)
        .map_err(|()| "database unavailable (connection or TLS failed)".to_owned())?;
    // Refuses a privileged login (superuser, owner role member): run it with
    // a login granted trust_crl_operator only.
    let mut store = PgRevocationStore::from_service_client(client)
        .map_err(|e| format!("database connection refused: {e:?}"))?;
    let cas = if target == "--all" {
        store
            .crl_issuing_cas()
            .map_err(|e| format!("CA list failed: {e:?}"))?
    } else {
        vec![target.clone()]
    };
    let mut outcome = Outcome::Quiet;
    for ca_id in &cas {
        // One CA failing must not hide the others.
        match store.crl_housekeeping(ca_id, reserved, intent) {
            Ok(report) => {
                println!(
                    "ca={ca_id} abandoned={} quarantined={} crl_due={} overdue_changes={} \
                     overdue_precautionary_holds={} open_breakglass_uses={} \
                     overdue_breakglass_uses={} purged_challenges={} clock_skew_us={} \
                     clock_uncertainty_us={} \
                     clock_ok={}",
                    report.abandoned,
                    report.quarantined,
                    report.crl_due,
                    report.overdue_changes,
                    report.overdue_precautionary_holds,
                    report.open_breakglass_uses,
                    report.overdue_breakglass_uses,
                    report.purged_challenges,
                    report.clock.skew_us,
                    report.clock.uncertainty_us,
                    report.clock_within_bound
                );
                if report.needs_attention() && !matches!(outcome, Outcome::Failed) {
                    outcome = Outcome::Attention;
                }
            }
            Err(e) => {
                eprintln!("crl_housekeeping: ca={ca_id} failed: {e:?}");
                outcome = Outcome::Failed;
            }
        }
    }
    let schema_changes = store
        .unreviewed_schema_changes()
        .map_err(|e| format!("schema-change report failed: {e:?}"))?;
    println!(
        "cas={} unreviewed_schema_changes={schema_changes}",
        cas.len()
    );
    if schema_changes > 0 && matches!(outcome, Outcome::Quiet) {
        outcome = Outcome::Attention;
    }
    Ok(outcome)
}

fn main() -> ExitCode {
    match run() {
        Ok(Outcome::Quiet) => ExitCode::SUCCESS,
        Ok(Outcome::Attention) => ExitCode::from(2),
        Ok(Outcome::Failed) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("crl_housekeeping: {message}");
            ExitCode::FAILURE
        }
    }
}
