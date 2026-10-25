//! Lab-only: stores a quarantined CRL (RECONCILIATION_REQUIRED, migration
//! 0021) from its DER, after the signer produced and verified it but the
//! database write failed (`CrlError::VerifiedButNotStored`).
//!
//! Never signs. The CRL is verified again, in the Rust core, against the
//! reservation rebuilt from the database snapshot and against the CA's
//! issuer certificate given as a file (the trusted service-side record, as
//! for signing); the database then requires the TBS hash journaled before
//! signing and the CA's registered issuer certificate (0022), and records a
//! `crl.reconciled` audit event with `--actor`. Works for complete and
//! delta CRLs (0059).
//!
//! Exit status: 0 stored; 1 refused or error (nothing stored): altered or
//! foreign DER, another issuer, a CRL number that is not quarantined after
//! an intent, or a database failure.
//! The database URL is read from TRUST_DATABASE_URL and must be a
//! non-privileged login holding trust_crl_signer. The connection follows
//! the management API's policy: TLS 1.3 verified against
//! TRUST_DATABASE_CA_FILE by default; plaintext only with
//! TRUST_DATABASE_TLS=disable-lab (reported on stderr).
//! Usage:
//!   TRUST_DATABASE_URL=postgresql://... cargo run -p trust-pki-core \
//!     --features postgres-store,lab-software --example crl_reconcile -- \
//!     <ca-uuid> <issuer.der> <crl.der> --actor NAME

// The management API's PostgreSQL TLS policy (verify-full by default).
#[allow(dead_code)]
#[path = "../../management-api/src/database.rs"]
mod database;

use std::{env, fs, process::ExitCode};
use trust_pki_core::{
    crl::{verify_published_crl, verify_published_delta_crl, LabCrlVerifier},
    crl_orchestrator::reconcile_crl,
    revocation_store::PgRevocationStore,
};
use x509_cert::{der::Decode, Certificate};

const NAME: &str = "crl_reconcile";
const STATEMENT_TIMEOUT_MS: u64 = 60_000;
/// Larger files are refused before parsing.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

fn read(path: &str) -> Result<Vec<u8>, String> {
    let size = fs::metadata(path)
        .map_err(|e| format!("cannot read {path}: {e}"))?
        .len();
    if size == 0 || size > MAX_FILE_BYTES {
        return Err(format!("{path} is empty or too large"));
    }
    fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn run() -> Result<u64, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let usage = "usage: crl_reconcile <ca-uuid> <issuer.der> <crl.der> --actor NAME";
    let [ca_id, issuer_path, crl_path] = [0, 1, 2].map(|i| args.get(i).cloned());
    let (Some(ca_id), Some(issuer_path), Some(crl_path)) = (ca_id, issuer_path, crl_path) else {
        return Err(usage.to_owned());
    };
    let actor = args
        .iter()
        .position(|a| a == "--actor")
        .and_then(|i| args.get(i + 1))
        .filter(|a| !a.trim().is_empty())
        .ok_or(usage)?;
    let issuer = Certificate::from_der(&read(&issuer_path)?)
        .map_err(|_| format!("{issuer_path} is not a DER certificate"))?;
    let crl_der = read(&crl_path)?;
    // Its number, from a CRL that verifies against this issuer at all.
    let number = verify_published_crl(&issuer, &crl_der)
        .map(|crl| crl.crl_number)
        .or_else(|_| verify_published_delta_crl(&issuer, &crl_der).map(|d| d.crl.crl_number))
        .map_err(|_| format!("{crl_path} does not verify against {issuer_path}"))?;

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
    // Refuses a privileged login before reading anything: reconciliation
    // runs as the CRL signer.
    let mut store = PgRevocationStore::from_service_client(client)
        .map_err(|e| format!("database connection refused: {e:?}"))?;
    let (operation_ref, status) = store
        .crl_publication_state(&ca_id, number)
        .map_err(|e| format!("cannot read the CRL's publication row: {e:?}"))?
        .ok_or_else(|| format!("CRL {number} is not reserved for CA {ca_id}"))?;
    if status != "RECONCILIATION_REQUIRED" {
        return Err(format!("CRL {number} is {status}, not quarantined"));
    }
    let reservation = store
        .load_reservation(&ca_id, number)
        .map_err(|e| format!("cannot rebuild the reservation: {e:?}"))?;
    reconcile_crl(
        &mut store,
        &LabCrlVerifier::new(issuer),
        &reservation,
        &operation_ref,
        actor,
        &crl_der,
    )
    .map_err(|e| format!("refused, nothing stored: {e:?}"))?;
    Ok(number)
}

fn main() -> ExitCode {
    match run() {
        Ok(number) => {
            println!("{NAME}: CRL {number} stored");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{NAME}: {message}");
            ExitCode::FAILURE
        }
    }
}
