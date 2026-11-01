//! Lab-only timing of history pages through the API router, against a
//! disposable scale fixture (docs/operations/lab-history-time-window.md).
//! Skipped unless `TRUST_API_TIMING_DATABASE_URL` names the reader login of
//! such a database; run with `--nocapture` to read the JSON lines:
//!
//! ```sh
//! TRUST_API_TIMING_DATABASE_URL=postgresql://scale_reader:…@127.0.0.1:55442/scale_1m \
//! TRUST_API_TIMING_CLIENTS=1,10,50 \
//!   cargo test -p trust-management-api --release --bin trust-management-api \
//!   history_timing -- --nocapture
//! ```
//!
//! The authority, issuer and subject are those of
//! tests/management_history_scale_seed.sql. Each request opens its own
//! database connection, as the API does; the API's slot limits are raised to
//! the number of clients so that the database, not the 503 bound, is measured.

use super::*;
use axum::{body::Body, http::Request};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::{
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
    RsaPrivateKey,
};
use serde_json::json;
use tower::ServiceExt;

const CA: &str = "dddddddd-0000-4000-8000-0000000000a1";

/// (case, query string, cursor position). `{interval}` is a time after the
/// authority's first signing time, so that notAfter cutoffs select the same
/// rows whatever the fixture's origin (2025-01-01T17:30, 2025-03-14 and
/// 2024-12-01 with the default origin).
const CASES: [(&str, &str, &str); 17] = [
    ("page1", "", "first"),
    ("middle", "", "middle"),
    ("end", "", "end"),
    ("oldest-page1", "&order=oldest", "first"),
    ("CN-strong", "&cn=svc-", "first"),
    ("CN-medium", "&cn=app-", "first"),
    ("CN-null", "&cn=zzz-", "first"),
    ("SAN-strong", "&san_dns=pool-7.lab.invalid", "first"),
    ("SAN-medium", "&san_dns=grp-3.lab.invalid", "first"),
    ("SAN-null", "&san_dns=absent.lab.invalid", "first"),
    ("NA-strong", "&not_after_before={366 days 17:30}", "first"),
    ("NA-medium", "&not_after_before={438 days}", "first"),
    ("NA-null", "&not_after_before={335 days}", "first"),
    ("ALL-strong", "&cn=app-&san_dns=pool-7.lab.invalid", "first"),
    ("ALL-medium", "&cn=app-&san_dns=grp-3.lab.invalid", "first"),
    (
        "ALL-null",
        "&cn=app-&san_dns=absent.lab.invalid&not_after_before={438 days}",
        "first",
    ),
    ("SAN-medium-middle", "&san_dns=grp-3.lab.invalid", "middle"),
];

fn app_and_token(database_url: String, slots: usize) -> (Router, String) {
    let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let public = private.to_public_key();
    let jwks = serde_json::from_value(json!({"keys":[{
        "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"timing",
        "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
    }]}))
    .unwrap();
    let verifier =
        OidcVerifier::from_jwks("https://issuer.scale.invalid", "trust-api", jwks).unwrap();
    let signer =
        EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
            .unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some("timing".into());
    let now = jsonwebtoken::get_current_timestamp();
    let token = encode(
        &header,
        &json!({
            "iss":"https://issuer.scale.invalid", "aud":"trust-api", "sub":"reader",
            "nbf":now-1, "exp":now+3600, "roles":["trust-ca-reader"], "ca_ids":[CA]
        }),
        &signer,
    )
    .unwrap();
    let app = router(AppState {
        verifier,
        database_url,
        database_slots: Arc::new(Semaphore::new(slots)),
        http_data_slots: Arc::new(Semaphore::new(slots)),
        readiness_slots: Arc::new(Semaphore::new(1)),
        readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
    });
    (app, token)
}

async fn get(app: &Router, token: &str, path: &str) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cursor = response
        .headers()
        .get("x-next-cursor")
        .map(|value| value.to_str().unwrap().replace('|', "%7C"));
    (status, cursor)
}

/// The cursor that starts a page in the middle or near the end of the
/// filtered history, read with one unsliced statement through the view.
fn cursor_for(database_url: &str, query: &str, position: &str) -> Option<String> {
    if position == "first" {
        return None;
    }
    let mut db = Client::connect(database_url, NoTls).unwrap();
    let mut filter = String::new();
    for part in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part.split_once('=').unwrap();
        filter.push_str(&match key {
            "cn" => format!(" AND lower(subject_cn) LIKE '{value}%'"),
            "san_dns" => format!(" AND '{value}' = ANY(san_dns)"),
            "not_after_before" => format!(" AND not_after < '{value}'"),
            _ => unreachable!("{key}"),
        });
    }
    let count: i64 = db
        .query_one(
            &format!("SELECT count(*) FROM management_certificate WHERE ca_id='{CA}'{filter}"),
            &[],
        )
        .unwrap()
        .get(0);
    let offset = if position == "middle" {
        count / 2
    } else {
        (count - 50).max(0)
    };
    let row = db
        .query_one(
            &format!(
                "SELECT signed_at || '%7C' || request_id FROM management_certificate \
                 WHERE ca_id='{CA}'{filter} ORDER BY signed_at DESC, request_id DESC \
                 OFFSET {offset} LIMIT 1"
            ),
            &[],
        )
        .unwrap();
    Some(row.get(0))
}

fn percentile(sorted: &[f64], fraction: f64) -> Option<f64> {
    let last = sorted.len().checked_sub(1)?;
    Some(sorted[(last as f64 * fraction).round() as usize])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_timing() {
    let Ok(database_url) = env::var("TRUST_API_TIMING_DATABASE_URL") else {
        eprintln!("SKIP: history timing needs TRUST_API_TIMING_DATABASE_URL (lab scale fixture)");
        return;
    };
    // Optional comma-separated subset of the cases.
    let only = env::var("TRUST_API_TIMING_CASES").unwrap_or_default();
    let url = database_url.clone();
    let first: String = tokio::task::spawn_blocking(move || {
        let mut db = Client::connect(&url, NoTls).unwrap();
        db.query_one(
            &format!("SELECT min(signed_at) FROM management_certificate WHERE ca_id='{CA}'"),
            &[],
        )
        .unwrap()
        .get(0)
    })
    .await
    .unwrap();
    let mut paths = Vec::new();
    for (name, query, position) in CASES {
        if !only.is_empty() && !only.split(',').any(|case| case == name) {
            continue;
        }
        let query = match query.split_once('{') {
            Some((head, rest)) => {
                let (interval, tail) = rest.split_once('}').unwrap();
                let url = database_url.clone();
                let sql = format!(
                    "SELECT to_char(('{first}'::timestamptz + interval '{interval}') AT TIME ZONE 'UTC', \
                     'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')"
                );
                let cutoff: String = tokio::task::spawn_blocking(move || {
                    Client::connect(&url, NoTls)
                        .unwrap()
                        .query_one(&sql, &[])
                        .unwrap()
                        .get(0)
                })
                .await
                .unwrap();
                format!("{head}{cutoff}{tail}")
            }
            None => query.to_owned(),
        };
        let url = database_url.clone();
        let cursor_query = query.clone();
        let cursor = tokio::task::spawn_blocking(move || cursor_for(&url, &cursor_query, position))
            .await
            .unwrap();
        let mut parts: Vec<String> = query
            .split('&')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
        parts.extend(cursor.map(|cursor| format!("before={cursor}")));
        paths.push((
            name,
            format!("/v1/cas/{CA}/certificates?{}", parts.join("&")),
        ));
    }
    let (app, token) = app_and_token(database_url.clone(), MAX_DATABASE_REQUESTS);
    for (name, path) in &paths {
        get(&app, &token, path).await; // warm-up
        let mut times = Vec::new();
        let mut statuses = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            let (status, _) = get(&app, &token, path).await;
            statuses.push(status.as_u16());
            times.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        times.sort_by(f64::total_cmp);
        println!(
            "{}",
            json!({"case": name, "median_ms": times[2], "min_ms": times[0], "max_ms": times[4],
                   "statuses": statuses, "path": path})
        );
    }
    let clients: Vec<usize> = env::var("TRUST_API_TIMING_CLIENTS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|count| count.trim().parse().ok())
        .collect();
    // The load mix of scripts/lab/history_scale_load.py: page 1, middle
    // cursor, CN medium, SAN strong, notAfter medium, combined medium.
    let mix: Vec<String> = [
        "page1",
        "middle",
        "CN-medium",
        "SAN-strong",
        "NA-medium",
        "ALL-medium",
    ]
    .iter()
    .filter_map(|case| paths.iter().find(|(name, _)| name == case))
    .map(|(_, path)| path.clone())
    .collect();
    let mix = Arc::new(mix);
    for count in clients {
        let (app, token) = app_and_token(database_url.clone(), count);
        let stop = Instant::now() + Duration::from_secs(60);
        let mut tasks = Vec::new();
        for client in 0..count {
            let (app, token, mix) = (app.clone(), token.clone(), mix.clone());
            tasks.push(tokio::spawn(async move {
                // Fixed per-client sequence (linear congruential, seed 42).
                let mut state = 42_u64 + client as u64;
                let mut results = Vec::new();
                while Instant::now() < stop {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let path = &mix[((state >> 33) % mix.len() as u64) as usize];
                    let started = Instant::now();
                    let (status, _) = get(&app, &token, path).await;
                    results.push((status, started.elapsed().as_secs_f64() * 1000.0));
                }
                results
            }));
        }
        let mut latencies = Vec::new();
        let mut failures = 0;
        for task in tasks {
            for (status, millis) in task.await.unwrap() {
                if status == StatusCode::OK {
                    latencies.push(millis);
                } else {
                    failures += 1;
                }
            }
        }
        latencies.sort_by(f64::total_cmp);
        println!(
            "{}",
            json!({
                "clients": count, "pages": latencies.len(), "pages_per_s": latencies.len() as f64 / 60.0,
                "p50_ms": percentile(&latencies, 0.5), "p95_ms": percentile(&latencies, 0.95),
                "max_ms": latencies.last(), "over_3s": latencies.iter().filter(|ms| **ms > 3000.0).count(),
                "non_200": failures
            })
        );
    }
}
