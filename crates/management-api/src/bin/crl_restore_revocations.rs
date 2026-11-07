//! Lab-only maintenance: re-applies the revocations a published CRL lists
//! after the revocation database was restored from an older backup
//! (migration 0060, `docs/operations/lab-revocation-backup-restore.md`).
//!
//! The CRL (DER, from the distribution point or a relying party's copy) is
//! verified against the CA's registered issuer certificate in the Rust core
//! before anything is sent; the database cannot verify its signature. The
//! database then re-applies missing revocations, makes holds definitive
//! where the CRL says so, keeps the CRL as evidence, raises the CRL number
//! floor to its number and audits the run. It never releases a hold and
//! never changes a definitive revocation; those, and certificates the
//! database does not know (issued after the backup), are reported.
//!
//! One line per certificate: `serial=<hex> outcome=<OUTCOME>`.
//! Exit status: 0 nothing left to do, 2 an operator must act on at least
//! one certificate (CONFLICT, UNKNOWN_CERTIFICATE, HOLD_NOT_ON_CRL), 1
//! error (nothing was changed). The login must be a superuser: the SQL
//! function has no grant. The connection follows the management API's
//! policy: TLS 1.3 verified against TRUST_DATABASE_CA_FILE by default;
//! plaintext only with TRUST_DATABASE_TLS=disable-lab (reported on stderr).
//! Usage:
//!   TRUST_DATABASE_URL=postgresql://... TRUST_DATABASE_CA_FILE=ca.pem \
//!     cargo run -p trust-management-api --bin crl_restore_revocations -- \
//!     <ca-uuid> <crl.der> --reason "restore of <backup> on <date>"

#![forbid(unsafe_code)]

// The management API's PostgreSQL TLS policy (verify-full by default).
#[allow(dead_code)]
#[path = "../database.rs"]
mod database;

use std::{env, fs, process::ExitCode};
use trust_pki_core::revocation_store::PgRevocationStore;

const NAME: &str = "crl_restore_revocations";
/// A CRL of a lab CA is small; bound the statement anyway.
const STATEMENT_TIMEOUT_MS: u64 = 120_000;
/// Larger files are refused before parsing.
const MAX_CRL_BYTES: u64 = 16 * 1024 * 1024;

fn run() -> Result<bool, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let usage = "usage: crl_restore_revocations <ca-uuid> <crl.der> --reason TEXT";
    let (ca_id, path) = match (args.first(), args.get(1)) {
        (Some(ca), Some(path)) if !ca.starts_with("--") && !path.starts_with("--") => (ca, path),
        _ => return Err(usage.to_owned()),
    };
    let reason = args
        .iter()
        .position(|a| a == "--reason")
        .and_then(|i| args.get(i + 1))
        .filter(|r| !r.trim().is_empty())
        .ok_or(usage)?;
    let canonical = uuid::Uuid::parse_str(ca_id)
        .ok()
        .filter(|u| u.hyphenated().to_string() == *ca_id)
        .ok_or("the CA id must be a canonical lowercase UUID")?;
    let size = fs::metadata(path)
        .map_err(|e| format!("cannot read {path}: {e}"))?
        .len();
    if size == 0 || size > MAX_CRL_BYTES {
        return Err(format!(
            "{path} is empty or larger than {MAX_CRL_BYTES} bytes"
        ));
    }
    let crl_der = fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
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
    let mut store = PgRevocationStore::from_superuser_client(client)
        .map_err(|e| format!("database session refused: {e:?}"))?;
    let outcomes = store
        .restore_revocations_from_crl(&canonical.hyphenated().to_string(), &crl_der, reason)
        .map_err(|e| format!("restore refused, nothing changed: {e:?}"))?;
    let mut attention = false;
    for (serial, outcome) in &outcomes {
        let hex: String = serial
            .as_der_content()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        println!("serial={hex} outcome={}", outcome.label());
        attention |= outcome.needs_attention();
    }
    println!("ca={ca_id} certificates={}", outcomes.len());
    Ok(attention)
}

fn main() -> ExitCode {
    match run() {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(2),
        Err(message) => {
            eprintln!("{NAME}: {message}");
            ExitCode::FAILURE
        }
    }
}
