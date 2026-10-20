//! Lab-only audit chain sealing and external anchoring (migration 0027,
//! ADR-0006 condition 5, proposed).
//!
//! `seal`: seals every unsealed audit record (login holding
//! trust_audit_sealer).
//! `verify <checkpoint-file>`: loads the whole chain (login holding
//! trust_audit_verifier), re-encodes every record, checks it against every
//! checkpoint already in the file, then appends the new head. The file is
//! the external anchor: keep it on another system or append-only storage,
//! and publish its last line out of band. A superuser who rewrites the
//! database cannot rewrite it.
//!
//! Exit status: 0 verified; 2 records older than `--unsealed-older-than`
//! seconds (default 3600) are not sealed yet; 3 the chain does not verify
//! (tampering or loss: investigate, do not append); 1 error.
//! The database URL is read from TRUST_DATABASE_URL; the connection is the
//! lab NoTls adapter, for a loopback or private lab database only.
//! Usage:
//!   TRUST_DATABASE_URL=postgresql://... cargo run -p trust-pki-core \
//!     --features postgres-store --example audit_chain_anchor -- seal
//!   TRUST_DATABASE_URL=postgresql://... cargo run -p trust-pki-core \
//!     --features postgres-store --example audit_chain_anchor -- \
//!     verify <checkpoint-file> [--unsealed-older-than SECONDS]

use postgres::{Client, NoTls};
use std::{
    env, fs,
    io::{ErrorKind, Write},
    process::ExitCode,
};
use trust_pki_core::{
    audit_chain::{verify_sealed_chain, Checkpoint},
    audit_chain_store::{load_entries, seal, unsealed},
};

enum Outcome {
    Verified,
    Unsealed,
    Tampered,
}

fn read_checkpoints(path: &str) -> Result<Vec<Checkpoint>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read {path}: {e}")),
    };
    // Fail closed: an unreadable anchor is not an empty one.
    text.lines()
        .enumerate()
        .map(|(i, line)| {
            Checkpoint::parse_line(line)
                .ok_or_else(|| format!("{path}:{}: not a checkpoint line", i + 1))
        })
        .collect()
}

fn run() -> Result<Outcome, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let url = env::var("TRUST_DATABASE_URL").map_err(|_| "TRUST_DATABASE_URL is not set")?;
    let mut client =
        Client::connect(&url, NoTls).map_err(|e| format!("database connection failed: {e}"))?;
    match args.first().map(String::as_str) {
        Some("seal") => {
            let mut total = 0;
            loop {
                let sealed =
                    seal(&mut client, 10_000).map_err(|e| format!("seal failed: {e:?}"))?;
                total += sealed;
                if sealed == 0 {
                    break;
                }
            }
            println!("sealed={total}");
            Ok(Outcome::Verified)
        }
        Some("verify") => {
            let path = args.get(1).ok_or("verify needs a checkpoint file")?;
            let older_than = match args.iter().position(|a| a == "--unsealed-older-than") {
                None => 3600,
                Some(i) => args
                    .get(i + 1)
                    .and_then(|v| v.parse::<i64>().ok())
                    .filter(|v| *v >= 0)
                    .ok_or("--unsealed-older-than needs a non-negative number of seconds")?,
            };
            let checkpoints = read_checkpoints(path)?;
            let entries = load_entries(&mut client).map_err(|e| format!("load failed: {e:?}"))?;
            let chain = match verify_sealed_chain(entries, &checkpoints) {
                Ok(chain) => chain,
                Err(error) => {
                    println!("tampered={error:?}");
                    return Ok(Outcome::Tampered);
                }
            };
            let last = checkpoints.last().map_or(0, |c| c.sequence);
            if chain.sequence() > last {
                let line = Checkpoint {
                    sequence: chain.sequence(),
                    head: chain.head(),
                }
                .to_line();
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| format!("cannot open {path}: {e}"))?;
                writeln!(file, "{line}")
                    .and_then(|()| file.sync_all())
                    .map_err(|e| format!("cannot append to {path}: {e}"))?;
                println!("{line}");
            }
            let pending =
                unsealed(&mut client, older_than).map_err(|e| format!("count failed: {e:?}"))?;
            println!("verified={} unsealed={pending}", chain.sequence());
            Ok(if pending > 0 {
                Outcome::Unsealed
            } else {
                Outcome::Verified
            })
        }
        _ => Err("usage: audit_chain_anchor seal | verify <checkpoint-file> \
                  [--unsealed-older-than S]"
            .into()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(Outcome::Verified) => ExitCode::SUCCESS,
        Ok(Outcome::Unsealed) => ExitCode::from(2),
        Ok(Outcome::Tampered) => ExitCode::from(3),
        Err(message) => {
            eprintln!("audit_chain_anchor: {message}");
            ExitCode::FAILURE
        }
    }
}
