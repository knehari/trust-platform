//! Lab-only offline audit of a CA's signed evidence (ADR-0007 §7,
//! migration 0041).
//!
//! Re-verifies every change of the CA that carries signatures (status
//! changes, precautionary holds, rejections and withdrawals, CA
//! administration) against the enrolled keys and the claims rebuilt from
//! their challenges, and prints one line per change. The database cannot
//! verify ECDSA, so this is what exposes an assertion stored without the
//! Rust core.
//!
//! Exit status: 0 all evidence verifies, 3 at least one change fails, 1
//! error. The database URL is read from TRUST_DATABASE_URL and must be a
//! non-privileged login holding trust_audit_verifier. The relying party is
//! TRUST_WEBAUTHN_RP_ID and TRUST_WEBAUTHN_ORIGIN, as for the revocation API.
//! The database connection follows the management API's policy: TLS 1.3
//! with certificate and host name verification against
//! TRUST_DATABASE_CA_FILE by default; plaintext only with the explicit lab
//! opt-out TRUST_DATABASE_TLS=disable-lab (reported on stderr).
//! Usage:
//!   TRUST_DATABASE_URL=postgresql://... TRUST_DATABASE_CA_FILE=ca.pem \
//!   TRUST_WEBAUTHN_RP_ID=... TRUST_WEBAUTHN_ORIGIN=https://... \
//!     cargo run -p trust-management-api --bin signed_evidence_audit -- <ca-uuid>

#![forbid(unsafe_code)]

// The management API's PostgreSQL TLS policy (verify-full by default).
#[allow(dead_code)]
#[path = "../database.rs"]
mod database;

use std::{env, process::ExitCode};
use trust_pki_core::{
    revocation_store::{AdminFamily, EvidenceFamily, PgRevocationStore},
    webauthn::RelyingParty,
};

const NAME: &str = "signed_evidence_audit";
/// Re-verification reads a few rows per change; bound each statement.
const STATEMENT_TIMEOUT_MS: u64 = 60_000;

fn run() -> Result<bool, String> {
    let ca_id = env::args()
        .nth(1)
        .ok_or("usage: signed_evidence_audit <ca-uuid>")?;
    let url = env::var("TRUST_DATABASE_URL").map_err(|_| "TRUST_DATABASE_URL is not set")?;
    let rp_id = env::var("TRUST_WEBAUTHN_RP_ID").map_err(|_| "TRUST_WEBAUTHN_RP_ID is not set")?;
    let origin =
        env::var("TRUST_WEBAUTHN_ORIGIN").map_err(|_| "TRUST_WEBAUTHN_ORIGIN is not set")?;
    let tls = database::tls_from_settings(
        env::var(database::TLS_MODE_ENV).ok().as_deref(),
        env::var(database::CA_FILE_ENV).ok().as_deref(),
    )?;
    if matches!(tls, database::DatabaseTls::DisabledForLab) {
        eprintln!("{NAME}: database TLS disabled (lab opt-out)");
    }
    let client = database::connect_client(&url, &tls, STATEMENT_TIMEOUT_MS)
        .map_err(|()| "database unavailable (connection or TLS failed)".to_owned())?;
    // Refuses a privileged login: an auditor that could also act is not one.
    let mut store = PgRevocationStore::from_service_client(client)
        .map_err(|e| format!("database connection refused: {e:?}"))?;
    let findings = store
        .audit_signed_evidence(
            &ca_id,
            &RelyingParty {
                rp_id: &rp_id,
                origin: &origin,
            },
        )
        .map_err(|e| format!("evidence index unavailable: {e:?}"))?;
    let mut all_ok = true;
    for finding in &findings {
        let family = match finding.family {
            EvidenceFamily::StatusChange => "status_change",
            EvidenceFamily::Admin(AdminFamily::CaAdmin) => "ca_admin",
            EvidenceFamily::Admin(AdminFamily::Credential) => "officer_credential",
            EvidenceFamily::Admin(AdminFamily::AdminCredential) => "admin_credential",
        };
        match &finding.result {
            Ok(()) => println!("family={family} change={} verified", finding.change_id),
            Err(e) => {
                all_ok = false;
                println!("family={family} change={} FAILED {e:?}", finding.change_id);
            }
        }
    }
    println!(
        "ca={ca_id} changes={} all_verified={all_ok}",
        findings.len()
    );
    Ok(all_ok)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(3),
        Err(message) => {
            eprintln!("signed_evidence_audit: {message}");
            ExitCode::from(1)
        }
    }
}
