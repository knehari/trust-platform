mod auth;
mod database;

use auth::{Claims, OidcVerifier};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use database::Database;
use postgres::Client;
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::{self, Write},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Semaphore};

const MAX_DATABASE_REQUESTS: usize = 8;
const MAX_HTTP_DATA_REQUESTS: usize = 16;
const DATABASE_STATEMENT_TIMEOUT_MS: u64 = 3_000;
const READINESS_CACHE_AGE: Duration = Duration::from_secs(1);
const HISTORY_PAGE_SIZE: usize = 100;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct AppState {
    verifier: OidcVerifier,
    database: Database,
    database_slots: Arc<Semaphore>,
    http_data_slots: Arc<Semaphore>,
    readiness_slots: Arc<Semaphore>,
    readiness_cache: Arc<Mutex<ReadinessCache>>,
}

#[derive(Default)]
struct ReadinessCache {
    checked_at: Option<Instant>,
    available: bool,
}

#[derive(Serialize)]
struct Ca {
    ca_id: String,
    parent_ca_id: Option<String>,
    display_name: String,
    policy_version: String,
    created_at: String,
}
#[derive(Serialize)]
struct Certificate {
    ca_id: String,
    serial_hex: String,
    fingerprint_sha256: String,
    request_id: String,
    state: String,
    signed_at: String,
    published_at: Option<String>,
}
#[derive(Serialize)]
struct Audit {
    event_id: String,
    ca_id: String,
    event_type: String,
    decision: String,
    policy_version: Option<String>,
    recorded_at: String,
}

#[derive(Deserialize)]
struct PaginationQuery {
    before: Option<String>,
}

#[derive(Deserialize)]
struct CaPaginationQuery {
    after: Option<String>,
}

fn parse_history_cursor(raw: Option<String>) -> Result<Option<(String, String)>, StatusCode> {
    let Some(raw) = raw else { return Ok(None) };
    let (timestamp, id) = raw.split_once('|').ok_or(StatusCode::BAD_REQUEST)?;
    let bytes = timestamp.as_bytes();
    let valid_timestamp = bytes.len() == 24
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'.'
        && bytes[23] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 23) || byte.is_ascii_digit()
        });
    if !valid_timestamp
        || uuid::Uuid::parse_str(id)
            .map(|uuid| uuid.to_string() != id)
            .unwrap_or(true)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Some((timestamp.to_owned(), id.to_owned())))
}

fn history_headers(next_cursor: Option<String>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(cursor) = next_cursor {
        headers.insert(
            "x-next-cursor",
            HeaderValue::from_str(&cursor).expect("canonical cursor is ASCII"),
        );
    }
    headers
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = env::var("TRUST_OIDC_ISSUER")?;
    let audience = env::var("TRUST_OIDC_AUDIENCE")?;
    let database = Database::new(
        env::var("TRUST_DATABASE_URL")?,
        database::tls_from_settings(
            env::var(database::TLS_MODE_ENV).ok().as_deref(),
            env::var(database::CA_FILE_ENV).ok().as_deref(),
        )?,
        // One idle session per database slot plus the readiness probe's slot.
        MAX_DATABASE_REQUESTS + 1,
    );
    if matches!(database.tls, database::DatabaseTls::DisabledForLab) {
        write_log(serde_json::json!({"event":"management_database_tls_disabled_lab"}));
    }
    let verifier = OidcVerifier::discover(&issuer, &audience).await?;
    let database_slots = Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS));
    let safe_db_role = query_db(
        database.clone(),
        database_slots.clone(),
        restricted_reader_role,
    )
    .await
    .map_err(|_| "management database unavailable")?;
    if !safe_db_role {
        return Err("management database login lacks read-only role isolation".into());
    }
    query_db(database.clone(), database_slots.clone(), |db| {
        db.query("SELECT 1 FROM management_reader_scope LIMIT 1", &[])
            .map(|_| ())
    })
    .await
    .map_err(|_| "management reader grants unavailable")?;
    let app = router(AppState {
        verifier,
        database,
        database_slots,
        http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
        readiness_slots: Arc::new(Semaphore::new(1)),
        readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
    });
    let bind = env::var("TRUST_API_BIND").unwrap_or_else(|_| "127.0.0.1:8081".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    write_log(serde_json::json!({"event":"management_api_started","bind":bind}));
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    let data_routes = Router::new()
        .route("/v1/cas", get(list_cas))
        .route("/v1/cas/{ca_id}", get(get_ca))
        .route("/v1/cas/{ca_id}/certificates", get(list_certificates))
        .route("/v1/cas/{ca_id}/audit", get(list_audit))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            limit_data_requests,
        ));
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/ready", get(ready))
        .merge(data_routes)
        .layer(middleware::from_fn(log_request))
        .with_state(state)
}

async fn limit_data_requests(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Acquire before token parsing or a JWKS refresh, and reject instead of
    // queuing requests. The owned permit also covers the database read.
    let _permit = state
        .http_data_slots
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(next.run(request).await)
}

fn write_log(value: serde_json::Value) {
    // Never include Authorization, URLs, query strings, response bodies or DB errors.
    let _ = writeln!(io::stderr().lock(), "{value}");
}

async fn log_request(request: Request<Body>, next: Next) -> Response {
    let id = format!(
        "{}-{}",
        std::process::id(),
        NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
    );
    let method = request.method().as_str().to_owned();
    let started = Instant::now();
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&id).expect("generated request ID is ASCII"),
    );
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_millis())
        .unwrap_or(0);
    write_log(serde_json::json!({
        "event":"request_complete",
        "request_id":id,
        "method":method,
        "status":response.status().as_u16(),
        "duration_ms":started.elapsed().as_millis(),
        "timestamp_ms":timestamp_ms,
    }));
    response
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"up"}))
}

async fn ready(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    // A public health probe cannot consume the eight slots reserved for
    // authenticated reads or cause unbounded parallel database connections.
    if state.database_slots.available_permits() == 0 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let mut cache = state
        .readiness_cache
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let available = if cache
        .checked_at
        .is_some_and(|checked_at| checked_at.elapsed() < READINESS_CACHE_AGE)
    {
        cache.available
    } else {
        let checked = query_db(state.database, state.readiness_slots, |db| {
            if !restricted_reader_role(db)? {
                return Ok(false);
            }
            // Parse and authorize every view used by the read routes without
            // scanning or returning any CA, certificate, audit or grant rows.
            db.query(
                "SELECT 1 FROM management_ca, management_certificate, \
                 management_audit, management_reader_scope LIMIT 0",
                &[],
            )?;
            Ok(true)
        })
        .await;
        cache.available = matches!(checked, Ok(true));
        cache.checked_at = Some(Instant::now());
        cache.available
    };
    if !available || state.database_slots.available_permits() == 0 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(serde_json::json!({"status":"ready"})))
}

fn restricted_reader_role(db: &mut Client) -> Result<bool, postgres::Error> {
    db.query_one(
        "SELECT pg_has_role(current_user,'trust_api_reader','member') \
         AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname=current_user \
             AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb)) \
         AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
             WHERE n.nspname='public' AND c.relkind IN ('r','p','m','f') \
             AND has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))",
        &[],
    )
    .map(|row| row.get::<_, bool>(0))
}

async fn authorize(headers: &HeaderMap, verifier: &OidcVerifier) -> Result<Claims, StatusCode> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = raw
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = verifier
        .verify(token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !claims.roles.iter().any(|role| role == "trust-ca-reader") {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(claims)
}

fn scoped_ca_id(raw: &str, claims: &Claims) -> Result<String, StatusCode> {
    let canonical = uuid::Uuid::parse_str(raw)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string();
    if !claims.ca_ids.iter().any(|scope| scope == &canonical) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(canonical)
}

async fn query_db<T: Send + 'static>(
    database: Database,
    slots: Arc<Semaphore>,
    query: impl FnMut(&mut Client) -> Result<T, postgres::Error> + Send + 'static,
) -> Result<T, StatusCode> {
    // Acquire before scheduling blocking work, and keep the permit until the
    // PostgreSQL connection (including a slow connect or query) is dropped.
    let permit = slots
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        database
            .run(DATABASE_STATEMENT_TIMEOUT_MS, query)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
}

async fn list_cas(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<CaPaginationQuery>,
) -> Result<(HeaderMap, Json<Vec<Ca>>), StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let after = page
        .after
        .map(|value| {
            uuid::Uuid::parse_str(&value)
                .ok()
                .filter(|id| id.to_string() == value)
                .map(|_| value)
                .ok_or(StatusCode::BAD_REQUEST)
        })
        .transpose()?;
    let ids: Vec<String> = claims
        .ca_ids
        .iter()
        .filter_map(|id| uuid::Uuid::parse_str(id).ok().map(|u| u.to_string()))
        .take(1024)
        .collect();
    let issuer = claims.iss;
    let subject = claims.sub;
    let rows = query_db(state.database, state.database_slots, move |db| {
        db.query(
            "SELECT c.ca_id,c.parent_ca_id,c.display_name,c.policy_version,c.created_at \
         FROM management_ca c JOIN management_reader_scope g ON g.ca_id=c.ca_id \
         WHERE c.ca_id=ANY($1::text[]) AND g.issuer=$2 AND g.subject=$3 \
         AND ($4::text IS NULL OR (c.display_name,c.ca_id) > ( \
           SELECT anchor.display_name,anchor.ca_id FROM management_ca anchor \
           JOIN management_reader_scope anchor_grant ON anchor_grant.ca_id=anchor.ca_id \
           WHERE anchor.ca_id=$4 AND anchor.ca_id=ANY($1::text[]) \
           AND anchor_grant.issuer=$2 AND anchor_grant.subject=$3)) \
         ORDER BY c.display_name,c.ca_id LIMIT 101",
            &[&ids, &issuer, &subject, &after],
        )
    })
    .await?;
    let has_more = rows.len() > HISTORY_PAGE_SIZE;
    let items: Vec<Ca> = rows
        .into_iter()
        .take(HISTORY_PAGE_SIZE)
        .map(|r| Ca {
            ca_id: r.get(0),
            parent_ca_id: r.get(1),
            display_name: r.get(2),
            policy_version: r.get(3),
            created_at: r.get(4),
        })
        .collect();
    let next = has_more.then(|| {
        items
            .last()
            .expect("nonempty page has a final item")
            .ca_id
            .clone()
    });
    Ok((history_headers(next), Json(items)))
}

async fn get_ca(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Result<Json<Ca>, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let issuer = claims.iss;
    let subject = claims.sub;
    let row = query_db(state.database, state.database_slots, move |db| {
        db.query_opt(
            "SELECT c.ca_id,c.parent_ca_id,c.display_name,c.policy_version,c.created_at \
         FROM management_ca c JOIN management_reader_scope g ON g.ca_id=c.ca_id \
         WHERE c.ca_id=$1 AND g.issuer=$2 AND g.subject=$3",
            &[&ca_id, &issuer, &subject],
        )
    })
    .await?
    .ok_or(StatusCode::FORBIDDEN)?;
    Ok(Json(Ca {
        ca_id: row.get(0),
        parent_ca_id: row.get(1),
        display_name: row.get(2),
        policy_version: row.get(3),
        created_at: row.get(4),
    }))
}

async fn list_certificates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Query(page): Query<PaginationQuery>,
) -> Result<(HeaderMap, Json<Vec<Certificate>>), StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let cursor = parse_history_cursor(page.before)?;
    let (before_time, before_id) = cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
    let issuer = claims.iss;
    let subject = claims.sub;
    let rows = query_db(state.database, state.database_slots, move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer,&subject,&ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        db.query(
            "SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at \
             FROM management_certificate WHERE ca_id=$1 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$2 AND subject=$3 AND ca_id=$1) \
             AND ($4::text IS NULL OR (signed_at, request_id) < ($4, $5)) \
             ORDER BY signed_at DESC, request_id DESC LIMIT 101",
            &[&ca_id, &issuer, &subject, &before_time, &before_id]
        ).map(Some)
    }).await?.ok_or(StatusCode::FORBIDDEN)?;
    let has_more = rows.len() > HISTORY_PAGE_SIZE;
    let items: Vec<Certificate> = rows
        .into_iter()
        .take(HISTORY_PAGE_SIZE)
        .map(|r| Certificate {
            ca_id: r.get(0),
            serial_hex: r.get(1),
            fingerprint_sha256: r.get(2),
            request_id: r.get(3),
            state: r.get(4),
            signed_at: r.get(5),
            published_at: r.get(6),
        })
        .collect();
    let next = has_more.then(|| {
        let last = items.last().expect("nonempty page has a final item");
        format!("{}|{}", last.signed_at, last.request_id)
    });
    Ok((history_headers(next), Json(items)))
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Query(page): Query<PaginationQuery>,
) -> Result<(HeaderMap, Json<Vec<Audit>>), StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let cursor = parse_history_cursor(page.before)?;
    let (before_time, before_id) = cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
    let issuer = claims.iss;
    let subject = claims.sub;
    let rows = query_db(state.database, state.database_slots, move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer,&subject,&ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        db.query(
            "SELECT event_id,ca_id,event_type,decision,policy_version,recorded_at \
             FROM management_audit WHERE ca_id=$1 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$2 AND subject=$3 AND ca_id=$1) \
             AND ($4::text IS NULL OR (recorded_at, event_id) < ($4, $5)) \
             ORDER BY recorded_at DESC, event_id DESC LIMIT 101",
            &[&ca_id, &issuer, &subject, &before_time, &before_id]
        ).map(Some)
    }).await?.ok_or(StatusCode::FORBIDDEN)?;
    let has_more = rows.len() > HISTORY_PAGE_SIZE;
    let items: Vec<Audit> = rows
        .into_iter()
        .take(HISTORY_PAGE_SIZE)
        .map(|r| Audit {
            event_id: r.get(0),
            ca_id: r.get(1),
            event_type: r.get(2),
            decision: r.get(3),
            policy_version: r.get(4),
            recorded_at: r.get(5),
        })
        .collect();
    let next = has_more.then(|| {
        let last = items.last().expect("nonempty page has a final item");
        format!("{}|{}", last.recorded_at, last.event_id)
    });
    Ok((history_headers(next), Json(items)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use http_body_util::BodyExt;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rsa::{
        pkcs8::{EncodePrivateKey, LineEnding},
        traits::PublicKeyParts,
        RsaPrivateKey,
    };
    use serde_json::json;
    use std::collections::HashSet;
    use tower::ServiceExt;

    /// Returns the database URL in `var`, or `None` to skip a database test.
    /// Under `TRUST_REQUIRE_DATABASE=1` a missing URL fails instead, so a CI
    /// job cannot pass by silently skipping its PostgreSQL coverage.
    fn test_database_url(var: &str) -> Option<String> {
        match env::var(var) {
            Ok(url) if !url.is_empty() => Some(url),
            _ => {
                assert_ne!(
                    env::var("TRUST_REQUIRE_DATABASE").as_deref(),
                    Ok("1"),
                    "{var} is required when TRUST_REQUIRE_DATABASE=1"
                );
                eprintln!("SKIP: {var} not configured");
                None
            }
        }
    }

    async fn history_page(
        app: &Router,
        token: &str,
        path: &str,
    ) -> (StatusCode, Option<String>, Vec<serde_json::Value>) {
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
            .map(|value| value.to_str().unwrap().to_owned());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let items = if status == StatusCode::OK {
            serde_json::from_slice(&body).unwrap()
        } else {
            Vec::new()
        };
        (status, cursor, items)
    }

    #[tokio::test]
    async fn history_pagination_reads_all_scoped_rows() {
        // CI runs this test with a dedicated seeded database.
        let Some(database_url) = test_database_url("TRUST_API_PAGINATION_DATABASE_URL") else {
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"pagination-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier =
            OidcVerifier::from_jwks("https://issuer.example.test", "trust-api", jwks).unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("pagination-test".into());
        let now = jsonwebtoken::get_current_timestamp();
        let token = encode(
            &header,
            &json!({
                "iss":"https://issuer.example.test", "aud":"trust-api", "sub":"operator",
                "nbf":now-1, "exp":now+60, "roles":["trust-ca-reader"],
                "ca_ids":["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]
            }),
            &signer,
        )
        .unwrap();
        let app = router(AppState {
            verifier,
            database: Database::lab_plaintext(database_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
        });
        let mut valid_cursor = None;
        for (suffix, id_field) in [("certificates", "request_id"), ("audit", "event_id")] {
            let base = format!("/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/{suffix}");
            let (status, cursor, first) = history_page(&app, &token, &base).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(first.len(), 100);
            let cursor = cursor.expect("102 rows require another page");
            valid_cursor = Some(cursor.clone());
            let (status, next, second) = history_page(
                &app,
                &token,
                &format!("{base}?before={}", cursor.replace('|', "%7C")),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(second.len(), 2);
            assert!(next.is_none());
            let ids: HashSet<&str> = first
                .iter()
                .chain(&second)
                .map(|item| item[id_field].as_str().unwrap())
                .collect();
            assert_eq!(ids.len(), 102);
            let (status, _, _) =
                history_page(&app, &token, &format!("{base}?before=invalid")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (status, _, _) = history_page(
            &app,
            &token,
            &format!(
                "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/audit?before={}",
                valid_cursor.unwrap().replace('|', "%7C")
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ca_pagination_reads_all_scoped_rows() {
        // CI runs this test with a dedicated seeded database.
        let Some(database_url) = test_database_url("TRUST_API_CA_PAGINATION_DATABASE_URL") else {
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"ca-page-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier =
            OidcVerifier::from_jwks("https://issuer.example.test", "trust-api", jwks).unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("ca-page-test".into());
        let now = jsonwebtoken::get_current_timestamp();
        let mut ca_ids: Vec<String> = (1..=102)
            .map(|n| format!("55555555-5555-4555-8555-{n:012x}"))
            .collect();
        ca_ids.push("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".into());
        let token = encode(
            &header,
            &json!({
                "iss":"https://issuer.example.test", "aud":"trust-api", "sub":"ca-page-operator",
                "nbf":now-1, "exp":now+60, "roles":["trust-ca-reader"],
                "ca_ids":ca_ids
            }),
            &signer,
        )
        .unwrap();
        let app = router(AppState {
            verifier,
            database: Database::lab_plaintext(database_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
        });
        let (status, cursor, first) = history_page(&app, &token, "/v1/cas").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first.len(), 100);
        let cursor = cursor.expect("102 CAs require another page");
        let (status, next, second) =
            history_page(&app, &token, &format!("/v1/cas?after={cursor}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second.len(), 2);
        assert!(next.is_none());
        let ids: HashSet<&str> = first
            .iter()
            .chain(&second)
            .map(|item| item["ca_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 102);
        assert_eq!(first[99]["ca_id"].as_str(), Some(cursor.as_str()));
        assert!(!ids.contains("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"));
        let (status, _, _) =
            history_page(&app, &token, "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = history_page(&app, &token, "/v1/cas?after=invalid").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    #[test]
    fn scope_rejects_other_and_invalid_ca() {
        let claims = Claims {
            iss: "https://issuer.example.test".into(),
            sub: "operator".into(),
            roles: vec!["trust-ca-reader".into()],
            ca_ids: vec!["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".into()],
        };
        assert_eq!(
            scoped_ca_id("ffffffff-ffff-4fff-8fff-ffffffffffff", &claims),
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            scoped_ca_id("../../ca", &claims),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[tokio::test]
    async fn database_capacity_rejects_excess_work_before_connecting() {
        let Some(url) = test_database_url("TRUST_API_TEST_DATABASE_URL") else {
            return;
        };
        let slots = Arc::new(Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let busy = query_db(Database::lab_plaintext(url.clone()), slots.clone(), |db| {
            db.query_one("SELECT 1", &[])
                .map(|row| row.get::<_, i32>(0))
        })
        .await;
        assert_eq!(busy, Err(StatusCode::SERVICE_UNAVAILABLE));
        drop(held);
        let available = query_db(Database::lab_plaintext(url), slots, |db| {
            db.query_one("SELECT 1", &[])
                .map(|row| row.get::<_, i32>(0))
        })
        .await;
        assert_eq!(available, Ok(1));
    }

    #[tokio::test]
    async fn database_query_timeout_releases_capacity() {
        let Some(url) = test_database_url("TRUST_API_TEST_DATABASE_URL") else {
            return;
        };
        let slots = Arc::new(Semaphore::new(1));
        let slow = query_db(Database::lab_plaintext(url.clone()), slots.clone(), |db| {
            db.query_one("SELECT pg_sleep(5)", &[]).map(|_| ())
        })
        .await;
        assert_eq!(slow, Err(StatusCode::SERVICE_UNAVAILABLE));
        let recovered = query_db(Database::lab_plaintext(url), slots, |db| {
            db.query_one("SELECT 1", &[])
                .map(|row| row.get::<_, i32>(0))
        })
        .await;
        assert_eq!(recovered, Ok(1));
    }

    #[tokio::test]
    async fn http_contract_rejects_missing_role_and_wrong_scope() {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"http-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier =
            OidcVerifier::from_jwks("https://issuer.example.test", "trust-api", jwks).unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("http-test".into());
        let now = jsonwebtoken::get_current_timestamp();
        let mut claims = json!({
            "iss":"https://issuer.example.test", "aud":"trust-api", "sub":"operator",
            "nbf":now-1, "exp":now+60, "roles":[],
            "ca_ids":["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]
        });
        // The JWT/HTTP checks run without a database; the database reads below
        // run only when the URL is configured (required in strict CI).
        let database_url = test_database_url("TRUST_API_TEST_DATABASE_URL").unwrap_or_default();
        let state = AppState {
            verifier,
            database: Database::lab_plaintext(database_url.clone()),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
        };
        let app = router(state.clone());
        let held_http = state
            .http_data_slots
            .clone()
            .acquire_many_owned(MAX_HTTP_DATA_REQUESTS as u32)
            .await
            .unwrap();
        for uri in [
            "/v1/cas",
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates",
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/audit",
        ] {
            let overloaded = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(overloaded.headers().contains_key("x-request-id"));
        }
        let live_while_busy = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live_while_busy.status(), StatusCode::OK);
        assert_eq!(
            state.database_slots.available_permits(),
            MAX_DATABASE_REQUESTS
        );
        drop(held_http);
        let readiness = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        if !database_url.is_empty() {
            assert_eq!(readiness.status(), StatusCode::OK);
            let body = readiness.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                json!({"status":"ready"})
            );
        }
        assert_eq!(
            state.database_slots.available_permits(),
            MAX_DATABASE_REQUESTS
        );
        let refresh_in_progress = state.readiness_cache.try_lock().unwrap();
        let concurrent_probe = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(concurrent_probe.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(refresh_in_progress);
        let unavailable_app = router(AppState {
            database: Database::lab_plaintext(
                "host=/nonexistent/trust-db-socket port=55432 user=missing dbname=missing",
            ),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            ..state.clone()
        });
        let liveness = unavailable_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(liveness.status(), StatusCode::OK);
        let unavailable = unavailable_app
            .oneshot(
                Request::builder()
                    .uri("/v1/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        let held = state
            .database_slots
            .clone()
            .acquire_many_owned(MAX_DATABASE_REQUESTS as u32)
            .await
            .unwrap();
        let saturated = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(held);
        if !database_url.is_empty() {
            let recovered = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/ready")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(recovered.status(), StatusCode::OK);
        }
        let no_token = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/cas")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_token.status(), StatusCode::UNAUTHORIZED);
        let first_request_id = no_token
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!first_request_id.is_empty());
        let no_role_token = encode(&header, &claims, &signer).unwrap();
        let no_role = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/cas")
                    .header("authorization", format!("Bearer {no_role_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_role.status(), StatusCode::FORBIDDEN);
        assert_ne!(
            no_role
                .headers()
                .get("x-request-id")
                .unwrap()
                .to_str()
                .unwrap(),
            first_request_id
        );
        claims["roles"] = json!(["trust-ca-reader"]);
        let token = encode(&header, &claims, &signer).unwrap();
        let other_ca = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other_ca.status(), StatusCode::FORBIDDEN);
        if !database_url.is_empty() {
            let mut unprovisioned = claims.clone();
            unprovisioned["sub"] = json!("unprovisioned-operator");
            unprovisioned["ca_ids"] = json!(["ffffffff-ffff-4fff-8fff-ffffffffffff"]);
            let unprovisioned_token = encode(&header, &unprovisioned, &signer).unwrap();
            let unprovisioned_list = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/cas")
                        .header("authorization", format!("Bearer {unprovisioned_token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(unprovisioned_list.status(), StatusCode::OK);
            let denied_body = unprovisioned_list
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&denied_body).unwrap(),
                json!([])
            );
            let unprovisioned_detail = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff")
                        .header("authorization", format!("Bearer {unprovisioned_token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(unprovisioned_detail.status(), StatusCode::FORBIDDEN);
            for suffix in ["certificates", "audit"] {
                let denied = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(format!(
                                "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/{suffix}"
                            ))
                            .header("authorization", format!("Bearer {unprovisioned_token}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(denied.status(), StatusCode::FORBIDDEN);
            }
            let mut ungranted_ca = claims.clone();
            ungranted_ca["ca_ids"] = json!(["ffffffff-ffff-4fff-8fff-ffffffffffff"]);
            let ungranted_token = encode(&header, &ungranted_ca, &signer).unwrap();
            let ungranted_list = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/cas")
                        .header("authorization", format!("Bearer {ungranted_token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let ungranted_body = ungranted_list
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&ungranted_body).unwrap(),
                json!([])
            );
            let scoped = app
                .oneshot(
                    Request::builder()
                        .uri("/v1/cas")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(scoped.status(), StatusCode::OK);
            let body = scoped.into_body().collect().await.unwrap().to_bytes();
            let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(listed.as_array().unwrap().len(), 1);
            assert!(listed
                .as_array()
                .unwrap()
                .iter()
                .all(|ca| ca["ca_id"] == "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"));
        }
    }
}
