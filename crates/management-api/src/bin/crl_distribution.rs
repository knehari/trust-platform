//! Lab-only, read-only CRL distribution point (RFC 5280 4.2.1.13, RFC 2585
//! 4.2): `GET /crl/<ca-uuid>.crl` returns the CA's latest stored complete
//! CRL as `application/pkix-crl`, and `GET /delta/<ca-uuid>.crl` its latest
//! stored delta CRL (migration 0059, RFC 5280 5.2.4; the URL the CA's
//! complete CRLs advertise as freshestCRL). The two never mix: a delta is
//! never served at the CDP, where a relying party would take it for the
//! complete CRL. Unauthenticated by design: relying parties fetch
//! CRLs anonymously. LAB ONLY: not a production publication service.
//!
//! * The database login must hold only `trust_crl_publisher` (migration
//!   0030): it can read the latest stored CRL and nothing else. A privileged
//!   or table-reading login is refused at start.
//! * Every CRL is re-checked before it is served
//!   (`trust_pki_core::crl::verify_published_crl`, or
//!   `verify_published_delta_crl` for a delta): canonical DER, issued and
//!   signed by the CA's registered issuer certificate, and the number and
//!   times the database reports. A CRL altered in the database is never
//!   served (503).
//! * Cache headers follow nextUpdate (at most one hour); a CRL past its
//!   nextUpdate is still served, uncached, so relying parties see it is
//!   stale rather than nothing.
//! * Each client address (IPv4, or IPv6 /64) may make 600 requests per
//!   minute (`rate_limit::limit_peers`, 429), so one client cannot hold the
//!   request slots the others need. Forwarded headers are not trusted.
//!
//! The database connection follows the management API's policy: TLS 1.3
//! with certificate and host name verification against
//! TRUST_DATABASE_CA_FILE by default; plaintext only with the explicit lab
//! opt-out TRUST_DATABASE_TLS=disable-lab (logged). Environment:
//! TRUST_CRL_DATABASE_URL, TRUST_DATABASE_TLS, TRUST_DATABASE_CA_FILE,
//! TRUST_CRL_BIND (default 127.0.0.1:8082).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

// The management API's PostgreSQL TLS policy (verify-full by default).
#[allow(dead_code)]
#[path = "../database.rs"]
mod database;

// Connection limits and the per-client-address request budget, shared
// with the token APIs.
#[path = "../http_serve.rs"]
mod http_serve;
#[allow(dead_code)]
#[path = "../rate_limit.rs"]
mod rate_limit;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use postgres::Client;
use std::{
    collections::HashMap,
    env,
    io::{self, Write},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use trust_pki_core::crl::{verify_published_crl, verify_published_delta_crl, PublishedCrl};
use x509_cert::{der::Decode, Certificate};

const MAX_CONCURRENT_REQUESTS: usize = 16;
const MAX_CACHE_SECONDS: i64 = 3600;
const STATEMENT_TIMEOUT_MS: u64 = 3_000;

/// A stored CRL as `published_crl` returns it.
#[derive(Clone)]
struct StoredCrl {
    crl_number: i64,
    this_update_unix: i64,
    next_update_unix: Option<i64>,
    crl_der: Vec<u8>,
    issuer_certificate_der: Vec<u8>,
}

/// Complete CRLs at the CDP, delta CRLs at the freshestCRL location.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Complete,
    Delta,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Complete => "crl",
            Kind::Delta => "delta",
        }
    }
}

trait CrlSource: Send + Sync + 'static {
    /// The latest stored CRL of that kind of `ca_id` (a canonical UUID).
    fn latest(&self, ca_id: &str, kind: Kind) -> Result<Option<StoredCrl>, ()>;
}

/// One lazily (re)connected session; a failed query drops it.
struct PgSource {
    url: String,
    tls: database::DatabaseTls,
    client: Mutex<Option<Client>>,
}

impl CrlSource for PgSource {
    fn latest(&self, ca_id: &str, kind: Kind) -> Result<Option<StoredCrl>, ()> {
        let mut slot = self.client.lock().map_err(|_| ())?;
        if slot.is_none() {
            let mut client = database::connect_client(&self.url, &self.tls, STATEMENT_TIMEOUT_MS)?;
            client
                .batch_execute("SET default_transaction_read_only = on")
                .map_err(|_| ())?;
            *slot = Some(client);
        }
        let client = slot.as_mut().ok_or(())?;
        let result = client.query(
            match kind {
                Kind::Complete => {
                    "SELECT crl_number, this_update_unix, next_update_unix, crl_der,
                            issuer_certificate_der
                     FROM published_crl($1::text::uuid)"
                }
                Kind::Delta => {
                    "SELECT crl_number, this_update_unix, next_update_unix, crl_der,
                            issuer_certificate_der
                     FROM published_delta_crl($1::text::uuid)"
                }
            },
            &[&ca_id],
        );
        match result {
            Ok(rows) => Ok(rows.first().map(|row| StoredCrl {
                crl_number: row.get(0),
                this_update_unix: row.get(1),
                next_update_unix: row.get(2),
                crl_der: row.get(3),
                issuer_certificate_der: row.get(4),
            })),
            Err(_) => {
                *slot = None;
                Err(())
            }
        }
    }
}

#[derive(Clone)]
struct AppState {
    source: Arc<dyn CrlSource>,
    slots: Arc<Semaphore>,
    now_unix: fn() -> i64,
    /// CRLs that re-verified, with when they were read (per CA).
    verified: Arc<Mutex<HashMap<String, (i64, StoredCrl)>>>,
    reuse_seconds: i64,
    /// Per client address, before anything else (`limit_peers`).
    peers: Arc<rate_limit::RateLimiter>,
}

/// How long a verified CRL is reused without asking the database again
/// (never past its nextUpdate): a flood of requests then costs neither
/// database queries nor signature checks. A CRL stored meanwhile is served
/// at most this much later, and a CRL altered in the database is noticed
/// (logged and refused) at most this much later; the copy served meanwhile
/// is the one that verified. TRUST_CRL_REUSE_SECONDS overrides it (0
/// disables reuse, at most MAX_CRL_REUSE_SECONDS).
const CRL_REUSE_SECONDS: i64 = 30;
const MAX_CRL_REUSE_SECONDS: i64 = 300;
/// CAs whose verified CRL is kept at once (the map is emptied when full).
const MAX_REUSED_CRLS: usize = 1024;

impl AppState {
    fn new(source: Arc<dyn CrlSource>, slots: usize, now_unix: fn() -> i64) -> Self {
        Self {
            source,
            slots: Arc::new(Semaphore::new(slots)),
            now_unix,
            verified: Arc::new(Mutex::new(HashMap::new())),
            reuse_seconds: CRL_REUSE_SECONDS,
            peers: Arc::new(rate_limit::RateLimiter::peers_per_minute()),
        }
    }
}

fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn write_log(value: serde_json::Value) {
    // Never log request bodies or database errors.
    let _ = writeln!(io::stderr().lock(), "{value}");
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/crl/{file}", get(serve_crl))
        .route("/delta/{file}", get(serve_delta))
        .layer(axum::middleware::from_fn_with_state(
            state.peers.clone(),
            rate_limit::limit_peers,
        ))
        .with_state(state)
}

/// `<canonical lowercase uuid>.crl`, nothing else.
fn ca_from_path(file: &str) -> Option<&str> {
    let stem = file.strip_suffix(".crl")?;
    let uuid = uuid::Uuid::parse_str(stem).ok()?;
    (uuid.hyphenated().to_string() == stem).then_some(stem)
}

fn http_date(unix: i64) -> Option<HeaderValue> {
    let seconds = u64::try_from(unix).ok()?;
    let text = httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(seconds));
    HeaderValue::from_str(&text).ok()
}

fn cache_control(now: i64, next_update: Option<i64>) -> HeaderValue {
    match next_update {
        Some(next) if next > now => HeaderValue::from_str(&format!(
            "public, max-age={}",
            (next - now).min(MAX_CACHE_SECONDS)
        ))
        .unwrap_or(HeaderValue::from_static("no-cache")),
        _ => HeaderValue::from_static("no-cache"),
    }
}

/// RFC 9110 13.1.2: weak comparison of the entity tags in If-None-Match.
fn etag_matches(if_none_match: &str, etag: &str) -> bool {
    if_none_match.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

/// Whether the client's copy is current (RFC 9110 13.1.2, 13.1.3,
/// 13.2.2): If-None-Match decides when present; otherwise If-Modified-Since
/// against thisUpdate. An unparsable date is ignored, as RFC 9110 requires.
fn not_modified(request: &HeaderMap, etag: &str, this_update_unix: i64) -> bool {
    if let Some(value) = request.get(header::IF_NONE_MATCH) {
        return value
            .to_str()
            .map(|value| etag_matches(value, etag))
            .unwrap_or(false);
    }
    request
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok())
        .and_then(|since| since.duration_since(UNIX_EPOCH).ok())
        .and_then(|since| i64::try_from(since.as_secs()).ok())
        .is_some_and(|since| this_update_unix <= since)
}

/// The CA's latest stored CRL, served only if it re-verifies against the
/// registered issuer certificate and agrees with its stored metadata.
async fn fetch_verified(
    state: &AppState,
    ca_id: &str,
    kind: Kind,
) -> Result<StoredCrl, StatusCode> {
    let source = state.source.clone();
    let lookup = ca_id.to_owned();
    let stored = match tokio::task::spawn_blocking(move || source.latest(&lookup, kind)).await {
        Ok(Ok(Some(stored))) => stored,
        Ok(Ok(None)) => return Err(StatusCode::NOT_FOUND),
        _ => {
            write_log(serde_json::json!({"event":"crl_source_unavailable","ca_id":ca_id}));
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let checked: Option<PublishedCrl> = Certificate::from_der(&stored.issuer_certificate_der)
        .ok()
        .and_then(|issuer| match kind {
            Kind::Complete => verify_published_crl(&issuer, &stored.crl_der).ok(),
            Kind::Delta => verify_published_delta_crl(&issuer, &stored.crl_der)
                .ok()
                .map(|delta| delta.crl),
        });
    let consistent = checked.is_some_and(|crl| {
        i64::try_from(crl.crl_number).ok() == Some(stored.crl_number)
            && crl.this_update_unix == stored.this_update_unix
            && crl.next_update_unix == stored.next_update_unix
    });
    if !consistent {
        // Fail closed: never publish a CRL that does not re-verify.
        write_log(serde_json::json!({
            "event":"crl_refused_verification_failed",
            "ca_id":ca_id,
            "kind":kind.label(),
            "crl_number":stored.crl_number
        }));
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(stored)
}

async fn serve_crl(
    State(state): State<AppState>,
    Path(file): Path<String>,
    request: HeaderMap,
) -> Response {
    serve(state, file, request, Kind::Complete).await
}

async fn serve_delta(
    State(state): State<AppState>,
    Path(file): Path<String>,
    request: HeaderMap,
) -> Response {
    serve(state, file, request, Kind::Delta).await
}

async fn serve(state: AppState, file: String, request: HeaderMap, kind: Kind) -> Response {
    let Some(ca_id) = ca_from_path(&file).map(str::to_owned) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(_permit) = state.slots.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let now = (state.now_unix)();
    let key = format!("{}:{ca_id}", kind.label());
    let reused = state.verified.lock().ok().and_then(|cache| {
        cache
            .get(&key)
            .filter(|(read_at, crl)| {
                now - *read_at < state.reuse_seconds
                    && crl.next_update_unix.is_none_or(|next| now < next)
            })
            .map(|(_, crl)| crl.clone())
    });
    let stored = match reused {
        Some(stored) => stored,
        None => match fetch_verified(&state, &ca_id, kind).await {
            Ok(stored) => {
                if let Ok(mut cache) = state.verified.lock() {
                    if cache.len() >= MAX_REUSED_CRLS {
                        cache.clear();
                    }
                    cache.insert(key, (now, stored.clone()));
                }
                stored
            }
            Err(status) => return status.into_response(),
        },
    };
    let etag = format!("\"{}\"", stored.crl_number);
    // Only after the CRL re-verified: a 304 never vouches for a tampered CRL.
    let mut response = if not_modified(&request, &etag, stored.this_update_unix) {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        response
    } else {
        Response::new(Body::from(stored.crl_der))
    };
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pkix-crl"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        cache_control((state.now_unix)(), stored.next_update_unix),
    );
    if let Ok(etag) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, etag);
    }
    if let Some(value) = http_date(stored.this_update_unix) {
        headers.insert(header::LAST_MODIFIED, value);
    }
    if let Some(value) = stored.next_update_unix.and_then(http_date) {
        headers.insert(header::EXPIRES, value);
    }
    response
}

/// The login may only publish: member of trust_crl_publisher, no elevated
/// attribute, not the owner role, no table privilege in `public`.
fn publisher_only(client: &mut Client) -> Result<bool, postgres::Error> {
    client
        .query_one(
            "SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_crl_publisher')
                         THEN pg_has_role(session_user, 'trust_crl_publisher', 'member')
                         ELSE false END
                AND NOT CASE WHEN EXISTS (SELECT 1 FROM pg_roles
                                          WHERE rolname = 'trust_revocation_owner')
                             THEN pg_has_role(session_user, 'trust_revocation_owner', 'member')
                             ELSE false END
                AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = session_user
                    AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb))
                AND NOT EXISTS (SELECT 1 FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'm', 'f', 'v')
                      AND has_table_privilege(session_user, c.oid,
                          'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))",
            &[],
        )
        .map(|row| row.get(0))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::var("TRUST_CRL_DATABASE_URL")?;
    let tls = database::tls_from_settings(
        env::var(database::TLS_MODE_ENV).ok().as_deref(),
        env::var(database::CA_FILE_ENV).ok().as_deref(),
    )?;
    if matches!(tls, database::DatabaseTls::DisabledForLab) {
        write_log(serde_json::json!({"event":"crl_database_tls_disabled_lab"}));
    }
    let (check_url, check_tls) = (url.clone(), tls.clone());
    let isolated = tokio::task::spawn_blocking(move || {
        database::connect_client(&check_url, &check_tls, STATEMENT_TIMEOUT_MS)
            .map_err(|()| "CRL database unavailable (connection or TLS failed)")
            .and_then(|mut client| {
                publisher_only(&mut client).map_err(|_| "CRL database login check failed")
            })
    })
    .await??;
    if !isolated {
        return Err("CRL database login must hold only trust_crl_publisher".into());
    }
    // Reverse proxies whose X-Forwarded-For is read (none by default).
    let trusted_proxies = rate_limit::trusted_proxies_from_env()?;
    let reuse_seconds = match env::var("TRUST_CRL_REUSE_SECONDS") {
        Ok(value) => value
            .parse::<i64>()
            .ok()
            .filter(|seconds| (0..=MAX_CRL_REUSE_SECONDS).contains(seconds))
            .ok_or("TRUST_CRL_REUSE_SECONDS must be 0 to 300")?,
        Err(_) => CRL_REUSE_SECONDS,
    };
    let state = AppState {
        reuse_seconds,
        peers: Arc::new(rate_limit::RateLimiter::peers_per_minute().trusting(trusted_proxies)),
        ..AppState::new(
            Arc::new(PgSource {
                url,
                tls,
                client: Mutex::new(None),
            }),
            MAX_CONCURRENT_REQUESTS,
            system_now,
        )
    };
    let bind = env::var("TRUST_CRL_BIND").unwrap_or_else(|_| "127.0.0.1:8082".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    write_log(serde_json::json!({"event":"crl_distribution_started","bind":bind}));
    serve_on(listener, state).await?;
    Ok(())
}

/// Serves the distribution point within the connection limits, with each
/// request's client address (`ConnectInfo<ClientAddr>`) for the
/// per-address budget.
async fn serve_on(listener: tokio::net::TcpListener, state: AppState) -> io::Result<()> {
    http_serve::serve(listener, router(state), http_serve::Limits::default()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use trust_pki_core::{
        crl::{build_tbs_cert_list, CrlAssembler, CrlReservation, LabCrlAssembler},
        lab_ca::EphemeralLabCa,
        orchestrator::ExternalSigner,
    };
    use x509_cert::der::Encode;

    const CA: &str = "5eedc0de-0000-4000-8000-000000000030";

    struct Fixed(Result<Option<StoredCrl>, ()>);

    impl CrlSource for Fixed {
        fn latest(&self, ca_id: &str, kind: Kind) -> Result<Option<StoredCrl>, ()> {
            assert_eq!(ca_id, CA);
            assert_eq!(kind, Kind::Complete);
            self.0.clone()
        }
    }

    /// A real CRL signed by an ephemeral lab CA, as the database stores it.
    fn stored() -> StoredCrl {
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let issuer = ca.root_certificate().clone();
        // The fresh lab root is valid from now on; thisUpdate must be within it.
        let this_update = system_now() + 1;
        let reservation =
            CrlReservation::new(CA, 7, this_update, this_update + 86_400, vec![], None).unwrap();
        let tbs = build_tbs_cert_list(&issuer, &reservation).unwrap();
        let key_ref = ca.lab_signer_key_ref().to_owned();
        let signature = ca
            .sign_once(&key_ref, "crl-distribution-test", &tbs)
            .unwrap();
        StoredCrl {
            crl_number: 7,
            this_update_unix: this_update,
            next_update_unix: Some(this_update + 86_400),
            crl_der: LabCrlAssembler.assemble(&tbs, &signature).unwrap(),
            issuer_certificate_der: issuer.to_der().unwrap(),
        }
    }

    async fn get(source: Result<Option<StoredCrl>, ()>, path: &str, now: fn() -> i64) -> Response {
        router(AppState::new(Arc::new(Fixed(source)), 1, now))
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn serves_a_verified_crl_with_cache_headers() {
        let crl = stored();
        let response = get(Ok(Some(crl.clone())), &format!("/crl/{CA}.crl"), system_now).await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        assert_eq!(headers[header::CONTENT_TYPE], "application/pkix-crl");
        assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=3600");
        assert_eq!(headers[header::ETAG], "\"7\"");
        assert!(headers.contains_key(header::LAST_MODIFIED));
        assert!(headers.contains_key(header::EXPIRES));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), crl.crl_der.as_slice());
    }

    #[tokio::test]
    async fn stale_crl_is_served_uncached() {
        fn later() -> i64 {
            system_now() + 2 * 86_400
        }
        let response = get(Ok(Some(stored())), &format!("/crl/{CA}.crl"), later).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
    }

    #[tokio::test]
    async fn altered_or_inconsistent_crls_are_never_served() {
        let mut flipped = stored();
        let last = flipped.crl_der.len() - 1;
        flipped.crl_der[last] ^= 1;
        let mut renumbered = stored();
        renumbered.crl_number = 8;
        let mut retimed = stored();
        retimed.next_update_unix = None;
        let mut foreign = stored();
        foreign.issuer_certificate_der = stored().issuer_certificate_der;
        for crl in [flipped, renumbered, retimed, foreign] {
            let response = get(Ok(Some(crl)), &format!("/crl/{CA}.crl"), system_now).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        let response = get(Err(()), &format!("/crl/{CA}.crl"), system_now).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn only_canonical_paths_are_answered() {
        let response = get(Ok(None), &format!("/crl/{CA}.crl"), system_now).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        for path in [
            format!("/crl/{}.crl", CA.to_uppercase()),
            format!("/crl/{CA}"),
            format!("/crl/{}.crl", CA.replace('-', "")),
            "/crl/..%2Fetc%2Fpasswd.crl".to_owned(),
            format!("/crl/{CA}.crl.der"),
        ] {
            let response = get(Ok(Some(stored())), &path, system_now).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    async fn conditional(
        crl: StoredCrl,
        header_name: header::HeaderName,
        value: &str,
    ) -> (StatusCode, HeaderMap, usize) {
        let response = router(AppState::new(Arc::new(Fixed(Ok(Some(crl)))), 1, system_now))
            .oneshot(
                Request::get(format!("/crl/{CA}.crl"))
                    .header(header_name, value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, body.len())
    }

    #[tokio::test]
    async fn conditional_requests_follow_rfc_9110() {
        let crl = stored();
        let this_update =
            httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(crl.this_update_unix as u64));
        let earlier = httpdate::fmt_http_date(
            UNIX_EPOCH + Duration::from_secs(crl.this_update_unix as u64 - 1),
        );
        for (name, value) in [
            (header::IF_NONE_MATCH, "\"7\""),
            (header::IF_NONE_MATCH, "W/\"7\""),
            (header::IF_NONE_MATCH, "\"3\", \"7\""),
            (header::IF_NONE_MATCH, "*"),
            (header::IF_MODIFIED_SINCE, this_update.as_str()),
        ] {
            let (status, headers, length) = conditional(crl.clone(), name.clone(), value).await;
            assert_eq!(status, StatusCode::NOT_MODIFIED, "{name}: {value}");
            assert_eq!(length, 0);
            assert_eq!(headers[header::ETAG], "\"7\"");
            assert!(headers.contains_key(header::CACHE_CONTROL));
            assert!(headers.contains_key(header::EXPIRES));
        }
        for (name, value) in [
            (header::IF_NONE_MATCH, "\"6\""),
            (header::IF_MODIFIED_SINCE, earlier.as_str()),
            (header::IF_MODIFIED_SINCE, "not a date"),
        ] {
            let (status, _, length) = conditional(crl.clone(), name.clone(), value).await;
            assert_eq!(status, StatusCode::OK, "{name}: {value}");
            assert_eq!(length, crl.crl_der.len());
        }
        // If-None-Match decides over If-Modified-Since.
        let response = router(AppState::new(
            Arc::new(Fixed(Ok(Some(crl.clone())))),
            1,
            system_now,
        ))
        .oneshot(
            Request::get(format!("/crl/{CA}.crl"))
                .header(header::IF_NONE_MATCH, "\"6\"")
                .header(header::IF_MODIFIED_SINCE, this_update.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // A tampered CRL is refused even to a client that holds it.
        let mut flipped = crl;
        let last = flipped.crl_der.len() - 1;
        flipped.crl_der[last] ^= 1;
        let (status, _, _) = conditional(flipped, header::IF_NONE_MATCH, "\"7\"").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn cache_lifetime_follows_next_update() {
        assert_eq!(cache_control(100, Some(160)), "public, max-age=60");
        assert_eq!(cache_control(100, Some(100_000)), "public, max-age=3600");
        assert_eq!(cache_control(100, Some(100)), "no-cache");
        assert_eq!(cache_control(100, None), "no-cache");
    }

    /// Answers by kind: what the database would return for each endpoint.
    struct ByKind {
        complete: StoredCrl,
        delta: StoredCrl,
    }

    impl CrlSource for ByKind {
        fn latest(&self, _ca_id: &str, kind: Kind) -> Result<Option<StoredCrl>, ()> {
            Ok(Some(match kind {
                Kind::Complete => self.complete.clone(),
                Kind::Delta => self.delta.clone(),
            }))
        }
    }

    /// A complete CRL 7 and a delta CRL 8 on it, signed by one lab CA.
    fn stored_pair() -> (StoredCrl, StoredCrl) {
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
        let issuer = ca.root_certificate().clone();
        let this_update = system_now() + 1;
        let key_ref = ca.lab_signer_key_ref().to_owned();
        let mut sign = |reservation: &CrlReservation| {
            let tbs = build_tbs_cert_list(&issuer, reservation).unwrap();
            let signature = ca
                .sign_once(&key_ref, "crl-distribution-test", &tbs)
                .unwrap();
            StoredCrl {
                crl_number: i64::try_from(reservation.crl_number()).unwrap(),
                this_update_unix: this_update,
                next_update_unix: Some(this_update + 86_400),
                crl_der: LabCrlAssembler.assemble(&tbs, &signature).unwrap(),
                issuer_certificate_der: issuer.to_der().unwrap(),
            }
        };
        let complete = CrlReservation::new(CA, 7, this_update, this_update + 86_400, vec![], None)
            .unwrap()
            .with_freshest_crl("http://crl.lab.invalid/delta/test.crl")
            .unwrap();
        let delta =
            CrlReservation::new_delta(CA, 8, 7, this_update, this_update + 86_400, vec![], vec![])
                .unwrap();
        (sign(&complete), sign(&delta))
    }

    async fn get_from(source: impl CrlSource, path: &str) -> Response {
        router(AppState::new(Arc::new(source), 1, system_now))
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// The delta CRL is served at /delta, the complete CRL at /crl, and a
    /// CRL of the wrong kind is never served at either (503).
    #[tokio::test]
    async fn delta_and_complete_crls_are_served_apart() {
        let (complete, delta) = stored_pair();
        let both = || ByKind {
            complete: complete.clone(),
            delta: delta.clone(),
        };
        let response = get_from(both(), &format!("/crl/{CA}.crl")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::ETAG], "\"7\"");
        let response = get_from(both(), &format!("/delta/{CA}.crl")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::ETAG], "\"8\"");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/pkix-crl"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), delta.crl_der.as_slice());

        // The database answering with the wrong kind is refused, both ways.
        let swapped = ByKind {
            complete: delta.clone(),
            delta: complete.clone(),
        };
        let response = get_from(swapped, &format!("/crl/{CA}.crl")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let swapped = ByKind {
            complete: delta.clone(),
            delta: complete.clone(),
        };
        let response = get_from(swapped, &format!("/delta/{CA}.crl")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let response = get_from(both(), "/delta/not-a-ca.crl").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A source that counts its lookups.
    struct Counting(StoredCrl, std::sync::atomic::AtomicUsize);

    impl CrlSource for Counting {
        fn latest(&self, _ca_id: &str, _kind: Kind) -> Result<Option<StoredCrl>, ()> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(self.0.clone()))
        }
    }

    /// A verified CRL is reused for CRL_REUSE_SECONDS: repeated requests
    /// neither query the database nor re-verify; after that, or for a CRL
    /// that failed verification, the source is asked again.
    #[tokio::test]
    async fn verified_crls_are_reused_briefly() {
        let counting = Arc::new(Counting(stored(), std::sync::atomic::AtomicUsize::new(0)));
        let state = AppState::new(counting.clone(), 1, system_now);
        let path = format!("/crl/{CA}.crl");
        for _ in 0..3 {
            let response = router(state.clone())
                .oneshot(Request::get(&path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        assert_eq!(counting.1.load(std::sync::atomic::Ordering::SeqCst), 1);

        fn later() -> i64 {
            system_now() + CRL_REUSE_SECONDS + 1
        }
        let response = router(AppState {
            now_unix: later,
            ..state
        })
        .oneshot(Request::get(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(counting.1.load(std::sync::atomic::Ordering::SeqCst), 2);

        let mut flipped = stored();
        let last = flipped.crl_der.len() - 1;
        flipped.crl_der[last] ^= 1;
        let tampered = Arc::new(Counting(flipped, std::sync::atomic::AtomicUsize::new(0)));
        let state = AppState::new(tampered.clone(), 1, system_now);
        for _ in 0..2 {
            let response = router(state.clone())
                .oneshot(Request::get(&path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        assert_eq!(tampered.1.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// Requests are counted per client address over a real socket: an
    /// address that spent its budget gets 429, another address does not.
    #[tokio::test]
    async fn requests_are_limited_per_client_address() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, TcpSocket},
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = AppState {
            peers: Arc::new(rate_limit::RateLimiter::new(2, Duration::from_secs(60))),
            ..AppState::new(Arc::new(Fixed(Ok(None))), 1, system_now)
        };
        tokio::spawn(serve_on(listener, state));
        // A malformed file name: 404 without touching the source.
        let status_from = |source: &'static str| async move {
            let socket = TcpSocket::new_v4().unwrap();
            socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
            let mut stream = socket.connect(addr).await.unwrap();
            stream
                .write_all(
                    b"GET /crl/not-a-ca.crl HTTP/1.1\r\nhost: cdp\r\nconnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            String::from_utf8_lossy(&response)[9..12].to_owned()
        };
        assert_eq!(status_from("127.0.0.1").await, "404");
        assert_eq!(status_from("127.0.0.1").await, "404");
        assert_eq!(status_from("127.0.0.1").await, "429");
        assert_eq!(status_from("127.0.0.2").await, "404");
    }
}
