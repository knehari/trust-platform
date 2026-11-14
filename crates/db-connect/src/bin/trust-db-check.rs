//! `trust-db-check <url>`: connects under the platform's TLS policy
//! (`TRUST_DATABASE_CA_FILE`, ADR-0031) and prints whether the session is
//! encrypted, with which protocol. Exits 1 when the connection fails, and 2
//! when TLS is required by `--require-tls` but the session is plaintext.
use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(url) = args.next() else {
        eprintln!("usage: trust-db-check <postgres-url> [--require-tls]");
        return ExitCode::FAILURE;
    };
    let require = args.any(|argument| argument == "--require-tls");
    let mut db = match trust_db_connect::connect(&url) {
        Ok(db) => db,
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"connected": false, "error": error.to_string()})
            );
            return ExitCode::FAILURE;
        }
    };
    let row = match db.query_one(
        "SELECT ssl, coalesce(version, '') FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        &[],
    ) {
        Ok(row) => row,
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"connected": true, "error": error.to_string()})
            );
            return ExitCode::FAILURE;
        }
    };
    let (ssl, version): (bool, String) = (row.get(0), row.get(1));
    println!(
        "{}",
        serde_json::json!({"connected": true, "tls": ssl, "protocol": version})
    );
    if require && !ssl {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}
