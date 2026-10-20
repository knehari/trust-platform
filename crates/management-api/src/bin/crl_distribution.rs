//! Lab-only, read-only CRL distribution point (RFC 5280 4.2.1.13, RFC 2585
//! 4.2): `GET /crl/<ca-uuid>.crl` returns the CA's latest stored CRL as
//! `application/pkix-crl`. Unauthenticated by design: relying parties fetch
//! CRLs anonymously. LAB ONLY: not a production publication service.
//!
//! * The database login must hold only `trust_crl_publisher` (migration
//!   0030): it can read the latest stored CRL and nothing else. A privileged
//!   or table-reading login is refused at start.
//! * Every CRL is re-checked before it is served
//!   (`trust_pki_core::crl::verify_published_crl`): canonical DER, issued and
//!   signed by the CA's registered issuer certificate, and the number and
//!   times the database reports. A CRL altered in the database is never
//!   served (503).
//! * Cache headers follow nextUpdate (at most one hour); a CRL past its
//!   nextUpdate is still served, uncached, so relying parties see it is
//!   stale rather than nothing.
//!
//! The database connection is the lab NoTls adapter, for a loopback or
//! private lab database only. Environment: TRUST_CRL_DATABASE_URL,
//! TRUST_CRL_BIND (default 127.0.0.1:8082).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use postgres::{Client, NoTls};
use std::{
    env,
    io::{self, Write},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use trust_pki_core::crl::verify_published_crl;
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

trait CrlSource: Send + Sync + 'static {
    /// The latest stored CRL of `ca_id` (a canonical UUID), if any.
    fn latest(&self, ca_id: &str) -> Result<Option<StoredCrl>, ()>;
}

/// One lazily (re)connected session; a failed query drops it.
struct PgSource {
    url: String,
    client: Mutex<Option<Client>>,
}

impl CrlSource for PgSource {
    fn latest(&self, ca_id: &str) -> Result<Option<StoredCrl>, ()> {
        let mut slot = self.client.lock().map_err(|_| ())?;
        if slot.is_none() {
            let mut client = Client::connect(&self.url, NoTls).map_err(|_| ())?;
            client
                .batch_execute(&format!(
                    "SET statement_timeout = {STATEMENT_TIMEOUT_MS}; \
                     SET default_transaction_read_only = on"
                ))
                .map_err(|_| ())?;
            *slot = Some(client);
        }
        let client = slot.as_mut().ok_or(())?;
        let result = client.query(
            "SELECT crl_number, this_update_unix, next_update_unix, crl_der,
                    issuer_certificate_der
             FROM published_crl($1::text::uuid)",
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

async fn serve_crl(State(state): State<AppState>, Path(file): Path<String>) -> Response {
    let Some(ca_id) = ca_from_path(&file).map(str::to_owned) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(_permit) = state.slots.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let source = state.source.clone();
    let lookup = ca_id.clone();
    let stored = match tokio::task::spawn_blocking(move || source.latest(&lookup)).await {
        Ok(Ok(Some(stored))) => stored,
        Ok(Ok(None)) => return StatusCode::NOT_FOUND.into_response(),
        _ => {
            write_log(serde_json::json!({"event":"crl_source_unavailable","ca_id":ca_id}));
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let checked = Certificate::from_der(&stored.issuer_certificate_der)
        .ok()
        .and_then(|issuer| verify_published_crl(&issuer, &stored.crl_der).ok());
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
            "crl_number":stored.crl_number
        }));
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let mut response = Response::new(Body::from(stored.crl_der));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pkix-crl"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        cache_control((state.now_unix)(), stored.next_update_unix),
    );
    if let Ok(etag) = HeaderValue::from_str(&format!("\"{}\"", stored.crl_number)) {
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
            "SELECT pg_has_role(session_user, 'trust_crl_publisher', 'member')
                AND NOT pg_has_role(session_user, 'trust_revocation_owner', 'member')
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
    let check_url = url.clone();
    let isolated = tokio::task::spawn_blocking(move || {
        Client::connect(&check_url, NoTls).and_then(|mut client| publisher_only(&mut client))
    })
    .await?
    .map_err(|_| "CRL database unavailable")?;
    if !isolated {
        return Err("CRL database login must hold only trust_crl_publisher".into());
    }
    let state = AppState {
        source: Arc::new(PgSource {
            url,
            client: Mutex::new(None),
        }),
        slots: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        now_unix: system_now,
    };
    let bind = env::var("TRUST_CRL_BIND").unwrap_or_else(|_| "127.0.0.1:8082".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    write_log(serde_json::json!({"event":"crl_distribution_started","bind":bind}));
    axum::serve(listener, router(state)).await?;
    Ok(())
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
        fn latest(&self, ca_id: &str) -> Result<Option<StoredCrl>, ()> {
            assert_eq!(ca_id, CA);
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
        router(AppState {
            source: Arc::new(Fixed(source)),
            slots: Arc::new(Semaphore::new(1)),
            now_unix: now,
        })
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

    #[test]
    fn cache_lifetime_follows_next_update() {
        assert_eq!(cache_control(100, Some(160)), "public, max-age=60");
        assert_eq!(cache_control(100, Some(100_000)), "public, max-age=3600");
        assert_eq!(cache_control(100, Some(100)), "no-cache");
        assert_eq!(cache_control(100, None), "no-cache");
    }
}
