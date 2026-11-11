//! `trust-crl-publisher`: publishes the latest verified CRL of each CA to a
//! static tree (ADR-0030). Environment:
//! - `TRUST_PUBLISHER_DATABASE_URL`: a login granted only `trust_crl_publisher`;
//! - `TRUST_PUBLISHER_DIR`: the root a static HTTP server serves read-only;
//! - `TRUST_PUBLISHER_INTERVAL_SECONDS` (default 10).
//!
//! `--once` runs a single pass and exits.
use std::{env, path::PathBuf, process::ExitCode, thread, time::Duration};

use postgres::{Client, NoTls};

fn main() -> ExitCode {
    let (Ok(url), Ok(dir)) = (
        env::var("TRUST_PUBLISHER_DATABASE_URL"),
        env::var("TRUST_PUBLISHER_DIR"),
    ) else {
        eprintln!("set TRUST_PUBLISHER_DATABASE_URL and TRUST_PUBLISHER_DIR");
        return ExitCode::FAILURE;
    };
    let root = PathBuf::from(dir);
    let once = env::args().any(|argument| argument == "--once");
    let interval = env::var("TRUST_PUBLISHER_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=3600).contains(seconds))
        .unwrap_or(10);
    loop {
        match Client::connect(&url, NoTls) {
            Ok(mut db) => match trust_crl_publisher::restricted_login(&mut db) {
                Ok(true) => {
                    if let Err(error) = trust_crl_publisher::publish_once(&mut db, &root) {
                        println!(
                            "{}",
                            serde_json::json!({"event": "crl_publisher_error", "kind": error.to_string()})
                        );
                    }
                }
                _ => {
                    // Never run with a login that can read or write more.
                    println!(
                        "{}",
                        serde_json::json!({"event": "crl_publisher_refused_login", "alert": true})
                    );
                    return ExitCode::FAILURE;
                }
            },
            Err(_) => println!(
                "{}",
                serde_json::json!({"event": "crl_publisher_database_unavailable"})
            ),
        }
        if once {
            return ExitCode::SUCCESS;
        }
        thread::sleep(Duration::from_secs(interval));
    }
}
