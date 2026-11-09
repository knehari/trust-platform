//! Periodic sealing of committed audit events into the tamper-evident chain
//! of migration 0036 (ADR-0022, Proposed). The database computes the links;
//! `lab_verify_audit_chain` recomputes them independently.
use axum::http::StatusCode;

use crate::{query_db, write_log, AppState};

/// Events sealed per statement; each statement commits on its own.
const SEAL_BATCH: i32 = 1_000;
/// Statements per pass, so one pass stays bounded; the next tick continues.
const SEAL_BATCHES_PER_PASS: usize = 50;

/// What one sealing pass did: events sealed, and the head afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealPass {
    pub sealed: i64,
    pub head_seq: i64,
    pub head_hash: String,
}

/// Seals committed events not yet sealed, oldest first, through the writer
/// login, in bounded batches.
pub(crate) async fn seal_pending_events(state: &AppState) -> Result<SealPass, StatusCode> {
    let writer_url = state
        .writer_database_url
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let pass = query_db(writer_url, state.database_slots.clone(), |db| {
        let mut pass = SealPass {
            sealed: 0,
            head_seq: 0,
            head_hash: String::new(),
        };
        for _ in 0..SEAL_BATCHES_PER_PASS {
            let row = db.query_one(
                "SELECT sealed, head_seq, head_hash FROM seal_audit_events_lab($1)",
                &[&SEAL_BATCH],
            )?;
            let sealed: i32 = row.get(0);
            pass.sealed += i64::from(sealed);
            pass.head_seq = row.get(1);
            pass.head_hash = row.get(2);
            if sealed < SEAL_BATCH {
                break;
            }
        }
        Ok(pass)
    })
    .await?;
    if pass.sealed > 0 {
        write_log(serde_json::json!({
            "event": "audit_chain_sealed", "sealed": pass.sealed,
            "head_seq": pass.head_seq, "head_hash": pass.head_hash,
        }));
    }
    Ok(pass)
}

/// Runs a sealing pass shortly after startup, then every `interval`, on its
/// own thread. A failed pass is logged and retried at the next tick.
pub(crate) fn spawn_sealer(state: AppState, interval: std::time::Duration) {
    let runtime = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2));
        loop {
            if runtime.block_on(seal_pending_events(&state)).is_err() {
                write_log(
                    serde_json::json!({"event": "audit_chain_sealed", "status": "UNAVAILABLE"}),
                );
            }
            std::thread::sleep(interval);
        }
    });
}
