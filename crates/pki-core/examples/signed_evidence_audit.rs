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
//! error. The database URL is read from TRUST_DATABASE_URL (lab NoTls
//! adapter, loopback or private lab database only) and must be a
//! non-privileged login holding trust_audit_verifier. The relying party is
//! TRUST_WEBAUTHN_RP_ID and TRUST_WEBAUTHN_ORIGIN, as for the revocation API.
//! Usage:
//!   TRUST_DATABASE_URL=postgresql://... TRUST_WEBAUTHN_RP_ID=... \
//!   TRUST_WEBAUTHN_ORIGIN=https://... cargo run -p trust-pki-core \
//!     --features postgres-store --example signed_evidence_audit -- <ca-uuid>

use std::{env, process::ExitCode};
use trust_pki_core::{
    revocation_store::{AdminFamily, EvidenceFamily, PgRevocationStore},
    webauthn::RelyingParty,
};

fn run() -> Result<bool, String> {
    let ca_id = env::args()
        .nth(1)
        .ok_or("usage: signed_evidence_audit <ca-uuid>")?;
    let url = env::var("TRUST_DATABASE_URL").map_err(|_| "TRUST_DATABASE_URL is not set")?;
    let rp_id = env::var("TRUST_WEBAUTHN_RP_ID").map_err(|_| "TRUST_WEBAUTHN_RP_ID is not set")?;
    let origin =
        env::var("TRUST_WEBAUTHN_ORIGIN").map_err(|_| "TRUST_WEBAUTHN_ORIGIN is not set")?;
    // Refuses a privileged login: an auditor that could also act is not one.
    let mut store = PgRevocationStore::connect_lab_service(&url)
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
