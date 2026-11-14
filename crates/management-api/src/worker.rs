//! The dedicated background worker (ADR-0037, Proposed):
//! `trust-management-api --worker`.
//!
//! It runs the platform's periodic tasks outside the API process, through
//! its own database login, a direct member of `trust_worker` (migration
//! 0044) and of nothing else:
//! - sealing committed audit events into the chain (ADR-0022);
//! - renewing due CRLs as the system principal `crl-renewer` (ADR-0021,
//!   ADR-0027), which the database accepts only from a worker login;
//! - asking the signer to sign audit checkpoints (ADR-0023).
//!
//! It serves nothing on the network and needs no OIDC configuration.
//!
//! Configuration (environment):
//! - `TRUST_WORKER_DATABASE_URL`: the worker login (TLS and client
//!   certificates as for every service, ADR-0031, ADR-0036);
//! - `TRUST_SIGNER_SOCKET`: the signer's socket, for CRL renewal and
//!   checkpoints;
//! - `TRUST_CRL_RENEWAL_INTERVAL_SECONDS` (5–86400),
//!   `TRUST_AUDIT_SEAL_INTERVAL_SECONDS` (5–86400) and
//!   `TRUST_AUDIT_CHECKPOINT_INTERVAL_SECONDS` (30–86400): each task runs
//!   only when its interval is set; at least one must be.
use std::{env, error::Error, path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::Semaphore;

use crate::{audit_chain, crl_publication, query_db, write_log};

/// Connections the worker uses at once: its tasks run one pass at a time.
const WORKER_DATABASE_SLOTS: usize = 2;

/// What the background tasks need: the worker's login and the signer.
#[derive(Clone)]
pub(crate) struct WorkerContext {
    pub database_url: String,
    pub database_slots: Arc<Semaphore>,
    pub signer_socket: Option<PathBuf>,
}

/// The environment variables of the background tasks. The API refuses them
/// (they belong to the worker), so a stale configuration cannot silently
/// stop sealing or renewal.
pub(crate) const TASK_INTERVALS: [&str; 3] = [
    "TRUST_CRL_RENEWAL_INTERVAL_SECONDS",
    "TRUST_AUDIT_SEAL_INTERVAL_SECONDS",
    "TRUST_AUDIT_CHECKPOINT_INTERVAL_SECONDS",
];

/// The login holds `trust_worker` directly, no other platform role, no
/// attribute and no table, and the database is at migration 0044.
pub(crate) fn restricted_worker_login(db: &mut postgres::Client) -> Result<bool, postgres::Error> {
    Ok(db
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_auth_members m \
                 JOIN pg_roles w ON w.oid = m.roleid AND w.rolname = 'trust_worker' \
                 JOIN pg_roles s ON s.oid = m.member AND s.rolname = session_user) \
             AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname IN \
                 ('trust_api_reader', 'trust_profile_writer', 'trust_lab_signer', 'trust_crl_publisher') \
                 AND pg_has_role(current_user, r.oid, 'member')) \
             AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = current_user \
                 AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb)) \
             AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'm', 'f', 'v') \
                 AND has_table_privilege(current_user, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) \
             AND management_dedicated_worker_version() = 1",
            &[],
        )?
        .get(0))
}

fn interval(name: &str, minimum: u64) -> Result<Option<Duration>, String> {
    let Some(raw) = env::var(name).ok().filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    raw.parse::<u64>()
        .ok()
        .filter(|seconds| (minimum..=86_400).contains(seconds))
        .map(|seconds| Some(Duration::from_secs(seconds)))
        .ok_or_else(|| format!("{name} must be {minimum} to 86400"))
}

/// Runs the configured tasks until the process is stopped.
pub(crate) async fn run() -> Result<(), Box<dyn Error>> {
    let database_url = env::var("TRUST_WORKER_DATABASE_URL")
        .map_err(|_| "the worker needs TRUST_WORKER_DATABASE_URL")?;
    let signer_socket = env::var("TRUST_SIGNER_SOCKET")
        .ok()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    let renewal = interval("TRUST_CRL_RENEWAL_INTERVAL_SECONDS", 5)?;
    let sealing = interval("TRUST_AUDIT_SEAL_INTERVAL_SECONDS", 5)?;
    let checkpoints = interval("TRUST_AUDIT_CHECKPOINT_INTERVAL_SECONDS", 30)?;
    if renewal.is_none() && sealing.is_none() && checkpoints.is_none() {
        return Err("the worker has no task: set at least one *_INTERVAL_SECONDS".into());
    }
    if (renewal.is_some() || checkpoints.is_some()) && signer_socket.is_none() {
        return Err("CRL renewal and audit checkpoints need TRUST_SIGNER_SOCKET".into());
    }
    let context = WorkerContext {
        database_url,
        database_slots: Arc::new(Semaphore::new(WORKER_DATABASE_SLOTS)),
        signer_socket,
    };
    let restricted = query_db(
        context.database_url.clone(),
        context.database_slots.clone(),
        restricted_worker_login,
    )
    .await
    .map_err(|_| "worker database unavailable or older than migration 0044")?;
    if !restricted {
        return Err("the worker login is not limited to a direct trust_worker membership".into());
    }
    if let Some(every) = renewal {
        crl_publication::spawn_renewer(context.clone(), every);
    }
    if let Some(every) = sealing {
        audit_chain::spawn_sealer(context.clone(), every);
    }
    if let (Some(every), Some(socket)) = (checkpoints, context.signer_socket.clone()) {
        audit_chain::spawn_checkpointer(socket, every);
    }
    write_log(serde_json::json!({
        "event": "worker_started",
        "crl_renewal_interval_seconds": renewal.map(|d| d.as_secs()),
        "audit_seal_interval_seconds": sealing.map(|d| d.as_secs()),
        "audit_checkpoint_interval_seconds": checkpoints.map(|d| d.as_secs()),
        "database_tls": trust_db_connect::tls_required(),
        "database_client_cert": trust_db_connect::client_cert_required(),
    }));
    // The tasks run on their own threads; this task only keeps the runtime.
    std::future::pending::<()>().await;
    Ok(())
}
