//! Periodic sealing of committed audit events into the tamper-evident chain
//! of migration 0036 (ADR-0022, Proposed). The database computes the links;
//! `lab_verify_audit_chain` recomputes them independently.
use axum::http::StatusCode;

use crate::{query_db, worker::WorkerContext, write_log};

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

/// Seals committed events not yet sealed, oldest first, through the worker
/// login (migration 0044, ADR-0037), in bounded batches.
pub(crate) async fn seal_pending_events(context: &WorkerContext) -> Result<SealPass, StatusCode> {
    let pass = query_db(
        context.database_url.clone(),
        context.database_slots.clone(),
        |db| {
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
        },
    )
    .await?;
    if pass.sealed > 0 {
        write_log(serde_json::json!({
            "event": "audit_chain_sealed", "sealed": pass.sealed,
            "head_seq": pass.head_seq, "head_hash": pass.head_hash,
        }));
    }
    Ok(pass)
}

/// Long enough for the signer to recompute the links since its last
/// checkpoint; the API never holds a database connection meanwhile.
const CHECKPOINT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The signer's answer to a checkpoint request (ADR-0023).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CheckpointReply {
    /// The checkpoint now current; `signed` is false when nothing was new.
    Current { seq: u64, signed: bool },
    /// The signer refused, with its code (for example `AuditRollback`).
    Refused(String),
}

/// Asks the laboratory signer to verify the chain since its last checkpoint
/// and sign the new head. `None` when the signer is unreachable.
pub(crate) fn request_checkpoint(socket: &std::path::Path) -> Option<CheckpointReply> {
    use std::io::{BufRead, BufReader, Write};
    let stream = std::os::unix::net::UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(CHECKPOINT_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(CHECKPOINT_TIMEOUT)).ok()?;
    writeln!(
        &stream,
        "{}",
        serde_json::json!({"kind": "audit_checkpoint"})
    )
    .ok()?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).ok()?;
    let reply: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if let Some(code) = reply["error"].as_str() {
        return Some(CheckpointReply::Refused(code.to_owned()));
    }
    Some(CheckpointReply::Current {
        seq: reply["checkpoint_seq"].as_u64()?,
        signed: reply["signed"].as_bool()?,
    })
}

/// One checkpoint request, logged. A refusal is logged as an alert: the
/// database no longer extends what the signer signed, or the chain is broken.
pub(crate) fn checkpoint_pass(socket: &std::path::Path) -> Option<CheckpointReply> {
    let reply = request_checkpoint(socket);
    write_log(match &reply {
        Some(CheckpointReply::Current { seq, signed }) => serde_json::json!({
            "event": "audit_checkpoint", "status": if *signed { "SIGNED" } else { "UNCHANGED" },
            "checkpoint_seq": seq,
        }),
        Some(CheckpointReply::Refused(code)) => serde_json::json!({
            "event": "audit_checkpoint", "status": "REFUSED", "alert": true, "reason": code,
        }),
        None => serde_json::json!({"event": "audit_checkpoint", "status": "UNAVAILABLE"}),
    });
    reply
}
