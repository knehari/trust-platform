//! Operational metrics of the background worker (ADR-0038, Proposed), in the
//! Prometheus text exposition format (version 0.0.4).
//!
//! Two sources, both aggregated, none secret:
//! - the database (`operational_metrics_lab()`, migration 0045): certificates
//!   in force and expiring, CRL freshness and unpublished revocations,
//!   operations awaiting reconciliation, the audit chain's state;
//! - the worker's own counters: passes of each task and their outcomes, and
//!   the time of each task's last success.
//!
//! Metric names come from a fixed list; a database row with an unknown name
//! is dropped, never rendered. The only label value from the database is a CA
//! identifier, which must be a canonical UUID.
use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// The database metrics the worker exposes, with their help text. Each is a
/// gauge named `trust_<name>`.
const DATABASE_METRICS: [(&str, &str); 10] = [
    (
        "certificates_valid",
        "Certificates in force (not expired, not revoked), per CA.",
    ),
    (
        "certificates_expiring_30d",
        "Certificates in force that expire within 30 days, per CA.",
    ),
    (
        "issuance_reconciliation_required",
        "Certificate signing outcomes awaiting reconciliation, per CA.",
    ),
    (
        "issuance_unconfirmed_stale",
        "Certificate signing intents unconfirmed for more than 5 minutes, per CA.",
    ),
    (
        "crl_reconciliation_required",
        "CRL signing outcomes awaiting reconciliation, per CA.",
    ),
    (
        "crl_next_update_seconds",
        "Seconds until the latest published CRL's nextUpdate (negative once expired), per CA.",
    ),
    (
        "crl_unpublished_entries",
        "Revocations not yet listed in a published CRL, per CA.",
    ),
    (
        "audit_unsealed_events",
        "Committed audit events not yet sealed into the chain.",
    ),
    (
        "audit_chain_head_seq",
        "Sequence number of the audit chain's head.",
    ),
    (
        "audit_checkpoint_age_seconds",
        "Seconds since the latest signed audit checkpoint.",
    ),
];

/// The worker's tasks.
#[derive(Clone, Copy)]
pub(crate) enum Task {
    Seal = 0,
    CrlRenewal = 1,
    Checkpoint = 2,
}
const TASK_NAMES: [&str; 3] = ["audit_seal", "crl_renewal", "audit_checkpoint"];

/// CRL renewal outcomes, as `renew_due_crls` reports them.
pub(crate) const RENEWAL_STATUSES: [&str; 4] = [
    "PUBLISHED",
    "ALREADY_PUBLISHED",
    "RECONCILIATION_REQUIRED",
    "REFUSED",
];
/// Checkpoint outcomes, as the worker logs them.
pub(crate) const CHECKPOINT_STATUSES: [&str; 4] = ["SIGNED", "UNCHANGED", "REFUSED", "UNAVAILABLE"];

#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);

/// Counters since the worker started.
pub(crate) struct WorkerMetrics {
    passes_ok: [AtomicU64; 3],
    passes_failed: [AtomicU64; 3],
    last_success_unix: [AtomicU64; 3],
    renewals: [AtomicU64; 4],
    checkpoints: [AtomicU64; 4],
    sealed_events: AtomicU64,
}

pub(crate) static METRICS: WorkerMetrics = WorkerMetrics::new();

impl WorkerMetrics {
    pub(crate) const fn new() -> Self {
        Self {
            passes_ok: [ZERO; 3],
            passes_failed: [ZERO; 3],
            last_success_unix: [ZERO; 3],
            renewals: [ZERO; 4],
            checkpoints: [ZERO; 4],
            sealed_events: ZERO,
        }
    }

    /// One pass of `task`, successful or not.
    pub(crate) fn pass(&self, task: Task, ok: bool) {
        let index = task as usize;
        if ok {
            self.passes_ok[index].fetch_add(1, Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            self.last_success_unix[index].store(now, Ordering::Relaxed);
        } else {
            self.passes_failed[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn renewal(&self, status: &str) {
        if let Some(index) = RENEWAL_STATUSES.iter().position(|known| *known == status) {
            self.renewals[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn checkpoint(&self, status: &str) {
        if let Some(index) = CHECKPOINT_STATUSES
            .iter()
            .position(|known| *known == status)
        {
            self.checkpoints[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn sealed(&self, events: u64) {
        self.sealed_events.fetch_add(events, Ordering::Relaxed);
    }
}

/// A canonical, lowercase UUID: the only database text rendered as a label.
fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
        })
}

fn number(value: f64) -> String {
    if value.is_finite() {
        format!("{value}")
    } else if value.is_nan() {
        "NaN".to_owned()
    } else if value > 0.0 {
        "+Inf".to_owned()
    } else {
        "-Inf".to_owned()
    }
}

/// The exposition text. `database` is `None` when the database could not be
/// read; `trust_metrics_database_up` then says 0 and the database metrics are
/// absent, never stale.
pub(crate) fn render(
    metrics: &WorkerMetrics,
    database: Option<&[(String, Option<String>, f64)]>,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP trust_metrics_database_up Whether the worker could read the database metrics."
    );
    let _ = writeln!(out, "# TYPE trust_metrics_database_up gauge");
    let _ = writeln!(
        out,
        "trust_metrics_database_up {}",
        u8::from(database.is_some())
    );
    if let Some(rows) = database {
        for (name, help) in DATABASE_METRICS {
            let _ = writeln!(out, "# HELP trust_{name} {help}");
            let _ = writeln!(out, "# TYPE trust_{name} gauge");
            for (metric, ca_id, value) in rows.iter().filter(|(metric, _, _)| metric == name) {
                match ca_id {
                    Some(ca) if canonical_uuid(ca) => {
                        let _ =
                            writeln!(out, "trust_{metric}{{ca_id=\"{ca}\"}} {}", number(*value));
                    }
                    Some(_) => {}
                    None => {
                        let _ = writeln!(out, "trust_{metric} {}", number(*value));
                    }
                }
            }
        }
    }
    let _ = writeln!(
        out,
        "# HELP trust_worker_task_passes_total Passes of each worker task, by result."
    );
    let _ = writeln!(out, "# TYPE trust_worker_task_passes_total counter");
    for (index, task) in TASK_NAMES.iter().enumerate() {
        for (result, counter) in [
            ("ok", &metrics.passes_ok[index]),
            ("error", &metrics.passes_failed[index]),
        ] {
            let _ = writeln!(
                out,
                "trust_worker_task_passes_total{{task=\"{task}\",result=\"{result}\"}} {}",
                counter.load(Ordering::Relaxed)
            );
        }
    }
    let _ = writeln!(out, "# HELP trust_worker_task_last_success_timestamp_seconds Unix time of each task's last successful pass (0: none yet).");
    let _ = writeln!(
        out,
        "# TYPE trust_worker_task_last_success_timestamp_seconds gauge"
    );
    for (index, task) in TASK_NAMES.iter().enumerate() {
        let _ = writeln!(
            out,
            "trust_worker_task_last_success_timestamp_seconds{{task=\"{task}\"}} {}",
            metrics.last_success_unix[index].load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        out,
        "# HELP trust_crl_renewals_total CRL renewals attempted by the worker, by outcome."
    );
    let _ = writeln!(out, "# TYPE trust_crl_renewals_total counter");
    for (index, status) in RENEWAL_STATUSES.iter().enumerate() {
        let _ = writeln!(
            out,
            "trust_crl_renewals_total{{status=\"{status}\"}} {}",
            metrics.renewals[index].load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        out,
        "# HELP trust_audit_checkpoints_total Audit checkpoint requests to the signer, by outcome."
    );
    let _ = writeln!(out, "# TYPE trust_audit_checkpoints_total counter");
    for (index, status) in CHECKPOINT_STATUSES.iter().enumerate() {
        let _ = writeln!(
            out,
            "trust_audit_checkpoints_total{{status=\"{status}\"}} {}",
            metrics.checkpoints[index].load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        out,
        "# HELP trust_audit_events_sealed_total Audit events the worker sealed into the chain."
    );
    let _ = writeln!(out, "# TYPE trust_audit_events_sealed_total counter");
    let _ = writeln!(
        out,
        "trust_audit_events_sealed_total {}",
        metrics.sealed_events.load(Ordering::Relaxed)
    );
    out
}

/// The database metrics, read through the worker's login.
pub(crate) fn read_database_metrics(
    db: &mut postgres::Client,
) -> Result<Vec<(String, Option<String>, f64)>, postgres::Error> {
    Ok(db
        .query(
            "SELECT metric, ca_id, value FROM operational_metrics_lab()",
            &[],
        )?
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_known_metrics_and_drops_the_rest() {
        let metrics = WorkerMetrics::new();
        metrics.pass(Task::Seal, true);
        metrics.pass(Task::CrlRenewal, false);
        metrics.renewal("PUBLISHED");
        metrics.renewal("NOT_A_STATUS");
        metrics.checkpoint("SIGNED");
        metrics.sealed(3);
        let ca = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_owned();
        let rows = vec![
            ("certificates_valid".to_owned(), Some(ca.clone()), 2.0),
            ("crl_next_update_seconds".to_owned(), Some(ca.clone()), -1.5),
            ("audit_unsealed_events".to_owned(), None, 0.0),
            // Neither an unknown metric nor a label that is not a UUID is
            // rendered.
            ("secret_metric".to_owned(), None, 1.0),
            (
                "certificates_valid".to_owned(),
                Some("x\"} 1\ninjected".to_owned()),
                9.0,
            ),
        ];
        let text = render(&metrics, Some(&rows));
        assert!(text.contains("trust_metrics_database_up 1\n"));
        assert!(text.contains(&format!("trust_certificates_valid{{ca_id=\"{ca}\"}} 2\n")));
        assert!(text.contains(&format!(
            "trust_crl_next_update_seconds{{ca_id=\"{ca}\"}} -1.5\n"
        )));
        assert!(text.contains("trust_audit_unsealed_events 0\n"));
        assert!(!text.contains("secret_metric"));
        assert!(!text.contains("injected"));
        assert!(
            text.contains("trust_worker_task_passes_total{task=\"audit_seal\",result=\"ok\"} 1\n")
        );
        assert!(text
            .contains("trust_worker_task_passes_total{task=\"crl_renewal\",result=\"error\"} 1\n"));
        assert!(text.contains("trust_crl_renewals_total{status=\"PUBLISHED\"} 1\n"));
        assert!(text.contains("trust_audit_checkpoints_total{status=\"SIGNED\"} 1\n"));
        assert!(text.contains("trust_audit_events_sealed_total 3\n"));
        assert!(text.contains(
            "trust_worker_task_last_success_timestamp_seconds{task=\"crl_renewal\"} 0\n"
        ));
        // Every sample line is a known family, and every family is typed.
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let family = line.split(['{', ' ']).next().unwrap();
            let family = family.trim_end_matches("_total");
            assert!(
                text.contains(&format!("# TYPE {family} "))
                    || text.contains(&format!("# TYPE {family}_total ")),
                "untyped sample: {line}"
            );
        }
    }

    #[test]
    fn without_the_database_only_the_worker_counters_remain() {
        let text = render(&WorkerMetrics::new(), None);
        assert!(text.contains("trust_metrics_database_up 0\n"));
        assert!(!text.contains("trust_certificates_valid"));
        assert!(text.contains("trust_audit_events_sealed_total 0\n"));
    }

    #[test]
    fn non_finite_values_use_the_format_spelling() {
        assert_eq!(number(f64::NAN), "NaN");
        assert_eq!(number(f64::INFINITY), "+Inf");
        assert_eq!(number(f64::NEG_INFINITY), "-Inf");
        assert_eq!(number(42.0), "42");
    }
}
