mod auth;
mod profile_proposal;

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
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use postgres::{Client, NoTls, Row};
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
    database_url: String,
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
    subject_cn: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    san_dns: Option<Vec<String>>,
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

#[derive(Serialize)]
struct ProfileDraft {
    ca_id: String,
    profile_id: String,
    revision: i32,
    display_name: String,
    policy_version: String,
    max_validity_days: i32,
    max_dns_sans: i32,
    proposed_dns_zones: Vec<String>,
    proposed_signature_suites: Vec<String>,
    created_by: String,
    created_at: String,
    status: &'static str,
    proposal_warnings: Vec<&'static str>,
    snapshot_sha256: String,
}

#[derive(Deserialize)]
struct ProfileDraftQuery {
    after: Option<String>,
    profile_id: Option<String>,
    order: Option<String>,
    q: Option<String>,
    policy_version: Option<String>,
    from: Option<String>,
    until: Option<String>,
    min_validity_days: Option<i32>,
    min_dns_sans: Option<i32>,
}

fn profile_draft_cursor(raw: Option<String>) -> Result<Option<(String, i32)>, StatusCode> {
    let Some(raw) = raw else { return Ok(None) };
    let (profile_id, revision) = raw.split_once('|').ok_or(StatusCode::BAD_REQUEST)?;
    if !valid_profile_id(profile_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let revision = valid_profile_revision(revision)?;
    Ok(Some((profile_id.to_owned(), revision)))
}

fn valid_profile_id(raw: &str) -> bool {
    (2..=64).contains(&raw.len())
        && raw.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
        && raw
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn valid_profile_revision(raw: &str) -> Result<i32, StatusCode> {
    let revision = raw.parse::<i32>().map_err(|_| StatusCode::BAD_REQUEST)?;
    if !(1..=1_000_000).contains(&revision) || revision.to_string() != raw {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(revision)
}

#[derive(Deserialize)]
struct PaginationQuery {
    before: Option<String>,
    cn: Option<String>,
    san_dns: Option<String>,
    not_after_before: Option<String>,
    from: Option<String>,
    until: Option<String>,
    event_type: Option<String>,
    decision: Option<String>,
    policy_version: Option<String>,
    order: Option<String>,
}

fn history_order(raw: Option<&str>) -> Result<(&'static str, &'static str), StatusCode> {
    match raw.unwrap_or("newest") {
        "newest" => Ok(("<", "DESC")),
        "oldest" => Ok((">", "ASC")),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

fn literal_prefix(raw: Option<String>) -> Result<Option<String>, StatusCode> {
    let Some(raw) = raw else { return Ok(None) };
    let cn = raw.trim();
    if !(2..=255).contains(&cn.chars().count()) || cn.chars().any(char::is_control) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let escaped = cn
        .to_lowercase()
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    Ok(Some(format!("{escaped}%")))
}

fn exact_san_dns(raw: Option<String>) -> Result<Option<String>, StatusCode> {
    let Some(raw) = raw else { return Ok(None) };
    let dns = raw.trim();
    if dns.is_empty()
        || dns.len() > 253
        || !dns
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'*'))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Some(dns.to_ascii_lowercase()))
}

struct AuditFilters {
    from: Option<String>,
    until: Option<String>,
    event_type: Option<String>,
    decision: Option<String>,
    policy_version: Option<String>,
}

fn audit_filters(page: &PaginationQuery) -> Result<AuditFilters, StatusCode> {
    let from = page.from.as_deref().map(valid_utc_timestamp).transpose()?;
    let until = page.until.as_deref().map(valid_utc_timestamp).transpose()?;
    if from
        .as_ref()
        .zip(until.as_ref())
        .is_some_and(|(from, until)| from >= until)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let event_type = page
        .event_type
        .as_ref()
        .map(|value| value.trim().to_owned());
    let decision = page.decision.as_ref().map(|value| value.trim().to_owned());
    let policy_version = page
        .policy_version
        .as_ref()
        .map(|value| value.trim().to_owned());
    if event_type.as_ref().is_some_and(|value| {
        value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
    }) || decision.as_ref().is_some_and(|value| {
        value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
    }) || policy_version.as_ref().is_some_and(|value| {
        value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
    }) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(AuditFilters {
        from,
        until,
        event_type,
        decision,
        policy_version,
    })
}

fn valid_utc_timestamp(raw: &str) -> Result<String, StatusCode> {
    let bytes = raw.as_bytes();
    let valid = bytes.len() == 24
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
    if !valid {
        return Err(StatusCode::BAD_REQUEST);
    }
    let part = |start: usize, end: usize| raw[start..end].parse::<u32>().unwrap_or(0);
    let year = part(0, 4);
    let month = part(5, 7);
    let day = part(8, 10);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0
        || day == 0
        || day > days
        || part(11, 13) > 23
        || part(14, 16) > 59
        || part(17, 19) > 59
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(raw.to_owned())
}

#[derive(Deserialize)]
struct CaPaginationQuery {
    after: Option<String>,
    q: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CaCursor {
    display_name: String,
    ca_id: String,
}

fn parse_ca_cursor(raw: Option<String>) -> Result<Option<CaCursor>, StatusCode> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.len() > 4096 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let cursor: CaCursor = serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !(1..=255).contains(&cursor.display_name.chars().count())
        || uuid::Uuid::parse_str(&cursor.ca_id)
            .map(|id| id.to_string() != cursor.ca_id)
            .unwrap_or(true)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Some(cursor))
}

fn encode_ca_cursor(ca: &Ca) -> String {
    let cursor = CaCursor {
        display_name: ca.display_name.clone(),
        ca_id: ca.ca_id.clone(),
    };
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor).expect("CA cursor is serializable"))
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
    let database_url = env::var("TRUST_DATABASE_URL")?;
    let verifier = OidcVerifier::discover(&issuer, &audience).await?;
    let database_slots = Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS));
    let safe_db_role = query_db(
        database_url.clone(),
        database_slots.clone(),
        restricted_reader_role,
    )
    .await
    .map_err(|_| "management database unavailable")?;
    if !safe_db_role {
        return Err("management database login lacks read-only role isolation".into());
    }
    query_db(database_url.clone(), database_slots.clone(), |db| {
        db.query("SELECT 1 FROM management_reader_scope LIMIT 1", &[])
            .map(|_| ())
    })
    .await
    .map_err(|_| "management reader grants unavailable")?;
    let app = router(AppState {
        verifier,
        database_url,
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
        .route("/v1/cas/{ca_id}/profile-drafts", get(list_profile_drafts))
        .route(
            "/v1/cas/{ca_id}/profile-drafts/{profile_id}/{revision}",
            get(get_profile_draft_revision),
        )
        .route("/v1/cas/{ca_id}/certificates", get(list_certificates))
        .route(
            "/v1/cas/{ca_id}/certificates/by-serial/{serial_hex}",
            get(get_certificate_by_serial),
        )
        .route(
            "/v1/cas/{ca_id}/certificates/{request_id}",
            get(get_certificate),
        )
        .route("/v1/cas/{ca_id}/audit", get(list_audit))
        .route("/v1/cas/{ca_id}/audit/{event_id}", get(get_audit_event))
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
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
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
        let checked = query_db(state.database_url, state.readiness_slots, |db| {
            if !restricted_reader_role(db)? {
                return Ok(false);
            }
            // Parse and authorize every view used by the read routes without
            // scanning or returning any CA, certificate, audit or grant rows.
            db.query(
                "SELECT 1 FROM management_ca, management_certificate, \
                 management_audit, management_reader_scope, management_profile_draft LIMIT 0",
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

fn canonical_serial_hex(raw: &str) -> Result<String, StatusCode> {
    if raw.len() > 61 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let digits = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    let hex = if digits.contains(':') {
        let pairs: Vec<&str> = digits.split(':').collect();
        if pairs.is_empty()
            || pairs
                .iter()
                .any(|pair| pair.len() != 2 || !pair.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        pairs.concat()
    } else {
        digits.to_owned()
    };
    if hex.is_empty() || hex.len() > 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let magnitude = hex.trim_start_matches('0');
    if magnitude.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut canonical = if magnitude.len() % 2 == 0 {
        magnitude.to_ascii_lowercase()
    } else {
        format!("0{}", magnitude.to_ascii_lowercase())
    };
    if u8::from_str_radix(&canonical[..2], 16).unwrap() >= 0x80 {
        canonical.insert_str(0, "00");
    }
    if canonical.len() > 40 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(canonical)
}

async fn query_db<T: Send + 'static>(
    url: String,
    slots: Arc<Semaphore>,
    query: impl FnOnce(&mut Client) -> Result<T, postgres::Error> + Send + 'static,
) -> Result<T, StatusCode> {
    // Acquire before scheduling blocking work, and keep the permit until the
    // PostgreSQL connection (including a slow connect or query) is dropped.
    let permit = slots
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut config: postgres::Config =
            url.parse().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        config.connect_timeout(Duration::from_secs(3));
        // Apply the limit at session startup so every management read, including
        // startup checks, is bounded even after the connection succeeds.
        config.options(&format!(
            "-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MS}"
        ));
        let mut db = config
            .connect(NoTls)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        query(&mut db).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
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
    let search = literal_prefix(page.q)?;
    let after = parse_ca_cursor(page.after)?;
    let (after_name, after_id) = after.map_or((None, None), |cursor| {
        (Some(cursor.display_name), Some(cursor.ca_id))
    });
    let ids: Vec<String> = claims
        .ca_ids
        .iter()
        .filter_map(|id| uuid::Uuid::parse_str(id).ok().map(|u| u.to_string()))
        .take(1024)
        .collect();
    let issuer = claims.iss;
    let subject = claims.sub;
    let rows = query_db(state.database_url, state.database_slots, move |db| {
        db.query(
            "SELECT c.ca_id,c.parent_ca_id,c.display_name,c.policy_version,c.created_at \
         FROM management_ca c JOIN management_reader_scope g ON g.ca_id=c.ca_id \
         WHERE c.ca_id=ANY($1::text[]) AND g.issuer=$2 AND g.subject=$3 \
         AND ($4::text IS NULL OR (c.display_name,c.ca_id) > ($4,$5)) \
         AND ($6::text IS NULL OR lower(c.display_name) LIKE $6 ESCAPE '\\' OR lower(c.policy_version) LIKE $6 ESCAPE '\\') \
         ORDER BY c.display_name,c.ca_id LIMIT 101",
            &[&ids, &issuer, &subject, &after_name, &after_id, &search],
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
    let next =
        has_more.then(|| encode_ca_cursor(items.last().expect("nonempty page has a final item")));
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
    let row = query_db(state.database_url, state.database_slots, move |db| {
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

async fn list_profile_drafts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Query(page): Query<ProfileDraftQuery>,
) -> Result<(HeaderMap, Json<Vec<ProfileDraft>>), StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    if page
        .profile_id
        .as_deref()
        .is_some_and(|id| !valid_profile_id(id))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (comparison, direction) = history_order(Some(page.order.as_deref().unwrap_or("oldest")))?;
    let search = literal_prefix(page.q)?;
    let policy_version = page.policy_version.map(|value| value.trim().to_owned());
    if policy_version.as_ref().is_some_and(|value| {
        value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
    }) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let from = page.from.as_deref().map(valid_utc_timestamp).transpose()?;
    let until = page.until.as_deref().map(valid_utc_timestamp).transpose()?;
    if from
        .as_ref()
        .zip(until.as_ref())
        .is_some_and(|(start, end)| start >= end)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if page
        .min_validity_days
        .is_some_and(|value| !(1..=825).contains(&value))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if page
        .min_dns_sans
        .is_some_and(|value| !(1..=100).contains(&value))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if direction == "DESC" && page.profile_id.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (after_id, after_revision) = profile_draft_cursor(page.after)?
        .map_or((None, None), |(id, revision)| (Some(id), Some(revision)));
    if let (Some(filter), Some(cursor_id)) = (page.profile_id.as_deref(), after_id.as_deref()) {
        if filter != cursor_id {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let profile_id = page.profile_id;
    let issuer = claims.iss;
    let subject = claims.sub;
    let rows = query_db(state.database_url, state.database_slots, move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer, &subject, &ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        let query = format!("SELECT ca_id,profile_id,revision,display_name,policy_version,max_validity_days,max_dns_sans,\
             proposed_dns_zones,proposed_signature_suites,created_by,created_at \
             FROM management_profile_draft WHERE ca_id=$1 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$2 AND subject=$3 AND ca_id=$1) \
             AND ($4::text IS NULL OR (profile_id,revision){comparison}($4,$5)) \
             AND ($6::text IS NULL OR profile_id=$6) \
             AND ($7::text IS NULL OR lower(profile_id) LIKE $7 ESCAPE '\\' \
                 OR lower(display_name) LIKE $7 ESCAPE '\\' \
                 OR lower(policy_version) LIKE $7 ESCAPE '\\') \
             AND ($8::text IS NULL OR policy_version=$8) \
             AND ($9::text IS NULL OR created_at >= $9) \
             AND ($10::text IS NULL OR created_at < $10) \
             AND ($11::integer IS NULL OR max_validity_days >= $11) \
             AND ($12::integer IS NULL OR max_dns_sans >= $12) \
             ORDER BY profile_id {direction},revision {direction} LIMIT 101");
        db.query(
            &query,
            &[&ca_id, &issuer, &subject, &after_id, &after_revision, &profile_id, &search, &policy_version, &from, &until, &page.min_validity_days, &page.min_dns_sans],
        ).map(Some)
    }).await?.ok_or(StatusCode::FORBIDDEN)?;
    let has_more = rows.len() > HISTORY_PAGE_SIZE;
    let items: Vec<ProfileDraft> = rows
        .into_iter()
        .take(HISTORY_PAGE_SIZE)
        .map(profile_draft_from_row)
        .collect();
    let next = has_more.then(|| {
        let last = items.last().expect("nonempty page has a final item");
        format!("{}|{}", last.profile_id, last.revision)
    });
    Ok((history_headers(next), Json(items)))
}

fn profile_draft_from_row(row: Row) -> ProfileDraft {
    let display_name: String = row.get(3);
    let policy_version: String = row.get(4);
    let proposed_dns_zones: Vec<String> = row.get(7);
    let proposed_signature_suites: Vec<String> = row.get(8);
    let proposal_warnings = profile_proposal::syntax_warnings(
        &display_name,
        &policy_version,
        &proposed_dns_zones,
        &proposed_signature_suites,
    );
    let mut draft = ProfileDraft {
        ca_id: row.get(0),
        profile_id: row.get(1),
        revision: row.get(2),
        display_name,
        policy_version,
        max_validity_days: row.get(5),
        max_dns_sans: row.get(6),
        proposed_dns_zones,
        proposed_signature_suites,
        created_by: row.get(9),
        created_at: row.get(10),
        status: "DRAFT",
        proposal_warnings,
        snapshot_sha256: String::new(),
    };
    draft.snapshot_sha256 = profile_proposal::snapshot_sha256(&draft);
    draft
}

async fn get_profile_draft_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((ca_id, profile_id, revision)): Path<(String, String, String)>,
) -> Result<Json<ProfileDraft>, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    if !valid_profile_id(&profile_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let revision = valid_profile_revision(&revision)?;
    let issuer = claims.iss;
    let subject = claims.sub;
    let row = query_db(state.database_url, state.database_slots, move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer, &subject, &ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        db.query_opt(
            "SELECT ca_id,profile_id,revision,display_name,policy_version,max_validity_days,max_dns_sans,\
             proposed_dns_zones,proposed_signature_suites,created_by,created_at \
             FROM management_profile_draft WHERE ca_id=$1 AND profile_id=$2 AND revision=$3 \
             AND EXISTS (SELECT 1 FROM management_reader_scope WHERE issuer=$4 AND subject=$5 AND ca_id=$1)",
            &[&ca_id, &profile_id, &revision, &issuer, &subject],
        ).map(Some)
    }).await?.ok_or(StatusCode::FORBIDDEN)?
      .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(profile_draft_from_row(row)))
}

async fn list_certificates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Query(page): Query<PaginationQuery>,
) -> Result<(HeaderMap, Json<Vec<Certificate>>), StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let (comparison, direction) = history_order(page.order.as_deref())?;
    let cursor = parse_history_cursor(page.before)?;
    let cn_prefix = literal_prefix(page.cn)?;
    let san_dns = exact_san_dns(page.san_dns)?;
    let not_after_before = page
        .not_after_before
        .as_deref()
        .map(valid_utc_timestamp)
        .transpose()?;
    let (before_time, before_id) = cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
    let issuer = claims.iss;
    let subject = claims.sub;
    let rows = query_db(state.database_url, state.database_slots, move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer,&subject,&ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        let mut query = format!("SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at,subject_cn,not_before,not_after,san_dns \
             FROM management_certificate WHERE ca_id=$1 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$2 AND subject=$3 AND ca_id=$1) \
             AND ($4::text IS NULL OR (signed_at, request_id) {comparison} ($4, $5))");
        let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> =
            vec![&ca_id, &issuer, &subject, &before_time, &before_id];
        if let Some(prefix) = cn_prefix.as_ref() {
            query.push_str(&format!(" AND lower(subject_cn) LIKE ${} ESCAPE '\\'", params.len() + 1));
            params.push(prefix);
        }
        if let Some(dns) = san_dns.as_ref() {
            query.push_str(&format!(" AND EXISTS (SELECT 1 FROM unnest(san_dns) AS entry(name) WHERE lower(entry.name) = ${})", params.len() + 1));
            params.push(dns);
        }
        if let Some(cutoff) = not_after_before.as_ref() {
            query.push_str(&format!(" AND not_after < ${}", params.len() + 1));
            params.push(cutoff);
        }
        query.push_str(&format!(" ORDER BY signed_at {direction}, request_id {direction} LIMIT 101"));
        db.query(&query, &params).map(Some)
    }).await?.ok_or(StatusCode::FORBIDDEN)?;
    let has_more = rows.len() > HISTORY_PAGE_SIZE;
    let items: Vec<Certificate> = rows
        .into_iter()
        .take(HISTORY_PAGE_SIZE)
        .map(certificate_from_row)
        .collect();
    let next = has_more.then(|| {
        let last = items.last().expect("nonempty page has a final item");
        format!("{}|{}", last.signed_at, last.request_id)
    });
    Ok((history_headers(next), Json(items)))
}

fn certificate_from_row(row: Row) -> Certificate {
    Certificate {
        ca_id: row.get(0),
        serial_hex: row.get(1),
        fingerprint_sha256: row.get(2),
        request_id: row.get(3),
        state: row.get(4),
        signed_at: row.get(5),
        published_at: row.get(6),
        subject_cn: row.get(7),
        not_before: row.get(8),
        not_after: row.get(9),
        san_dns: row.get(10),
    }
}

async fn get_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((ca_id, request_id)): Path<(String, String)>,
) -> Result<Json<Certificate>, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let request_id = uuid::Uuid::parse_str(&request_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string();
    let issuer = claims.iss;
    let subject = claims.sub;
    let row = query_db(state.database_url, state.database_slots, move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer, &subject, &ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        db.query_opt(
            "SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at,subject_cn,not_before,not_after,san_dns \
             FROM management_certificate WHERE ca_id=$1 AND request_id=$2 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$3 AND subject=$4 AND ca_id=$1)",
            &[&ca_id, &request_id, &issuer, &subject],
        ).map(Some)
    }).await?.ok_or(StatusCode::FORBIDDEN)?
      .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(certificate_from_row(row)))
}

async fn get_certificate_by_serial(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((ca_id, serial_hex)): Path<(String, String)>,
) -> Result<Json<Certificate>, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let serial_hex = canonical_serial_hex(&serial_hex)?;
    let issuer = claims.iss;
    let subject = claims.sub;
    let row = query_db(state.database_url, state.database_slots, move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer, &subject, &ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        db.query_opt(
            "SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at,subject_cn,not_before,not_after,san_dns \
             FROM management_certificate WHERE ca_id=$1 AND serial_hex=$2 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$3 AND subject=$4 AND ca_id=$1)",
            &[&ca_id, &serial_hex, &issuer, &subject],
        ).map(Some)
    }).await?.ok_or(StatusCode::FORBIDDEN)?
      .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(certificate_from_row(row)))
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
    Query(page): Query<PaginationQuery>,
) -> Result<(HeaderMap, Json<Vec<Audit>>), StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let (comparison, direction) = history_order(page.order.as_deref())?;
    let filters = audit_filters(&page)?;
    let cursor = parse_history_cursor(page.before)?;
    let (before_time, before_id) = cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
    let issuer = claims.iss;
    let subject = claims.sub;
    let rows = query_db(state.database_url, state.database_slots, move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer,&subject,&ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        let query = format!("SELECT event_id,ca_id,event_type,decision,policy_version,recorded_at \
             FROM management_audit WHERE ca_id=$1 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$2 AND subject=$3 AND ca_id=$1) \
             AND ($4::text IS NULL OR (recorded_at, event_id) {comparison} ($4, $5)) \
             AND ($6::text IS NULL OR recorded_at >= $6) \
             AND ($7::text IS NULL OR recorded_at < $7) \
             AND ($8::text IS NULL OR event_type = $8) \
             AND ($9::text IS NULL OR decision = $9) \
             AND ($10::text IS NULL OR policy_version = $10) \
             ORDER BY recorded_at {direction}, event_id {direction} LIMIT 101");
        db.query(
            &query,
            &[&ca_id, &issuer, &subject, &before_time, &before_id, &filters.from, &filters.until, &filters.event_type, &filters.decision, &filters.policy_version]
        ).map(Some)
    }).await?.ok_or(StatusCode::FORBIDDEN)?;
    let has_more = rows.len() > HISTORY_PAGE_SIZE;
    let items: Vec<Audit> = rows
        .into_iter()
        .take(HISTORY_PAGE_SIZE)
        .map(audit_from_row)
        .collect();
    let next = has_more.then(|| {
        let last = items.last().expect("nonempty page has a final item");
        format!("{}|{}", last.recorded_at, last.event_id)
    });
    Ok((history_headers(next), Json(items)))
}

fn audit_from_row(row: Row) -> Audit {
    Audit {
        event_id: row.get(0),
        ca_id: row.get(1),
        event_type: row.get(2),
        decision: row.get(3),
        policy_version: row.get(4),
        recorded_at: row.get(5),
    }
}

async fn get_audit_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((ca_id, event_id)): Path<(String, String)>,
) -> Result<Json<Audit>, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let event_id = uuid::Uuid::parse_str(&event_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string();
    let issuer = claims.iss;
    let subject = claims.sub;
    let row = query_db(state.database_url, state.database_slots, move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer, &subject, &ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        db.query_opt(
            "SELECT event_id,ca_id,event_type,decision,policy_version,recorded_at \
             FROM management_audit WHERE ca_id=$1 AND event_id=$2 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$3 AND subject=$4 AND ca_id=$1)",
            &[&ca_id, &event_id, &issuer, &subject],
        ).map(Some)
    }).await?.ok_or(StatusCode::FORBIDDEN)?
      .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(audit_from_row(row)))
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

    #[test]
    fn utc_filter_timestamp_checks_calendar_date() {
        for valid in ["2028-02-29T00:00:00.000Z", "2026-12-31T23:59:59.999Z"] {
            assert_eq!(valid_utc_timestamp(valid), Ok(valid.to_owned()));
        }
        for invalid in [
            "2027-02-29T00:00:00.000Z",
            "2026-04-31T00:00:00.000Z",
            "2026-13-01T00:00:00.000Z",
            "2026-01-01T24:00:00.000Z",
            "2026-01-01T00:60:00.000Z",
        ] {
            assert_eq!(valid_utc_timestamp(invalid), Err(StatusCode::BAD_REQUEST));
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
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
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

    async fn detail_response(
        app: &Router,
        token: &str,
        path: &str,
    ) -> (StatusCode, serde_json::Value) {
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
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value = if status == StatusCode::OK {
            serde_json::from_slice(&body).unwrap()
        } else {
            serde_json::Value::Null
        };
        (status, value)
    }

    #[tokio::test]
    async fn history_pagination_reads_all_scoped_rows() {
        let database_url = match env::var("TRUST_API_PAGINATION_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("SKIP: pagination PostgreSQL fixture not configured; CI runs this test with a dedicated seeded database");
                return;
            }
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
            database_url,
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
        });
        let draft_base = "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/profile-drafts";
        let (status, cursor, first) = history_page(&app, &token, draft_base).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first.len(), 100);
        assert!(first.iter().all(|row| row["status"] == "DRAFT"));
        assert!(first
            .iter()
            .all(|row| row["proposal_warnings"] == json!([])));
        assert!(first.iter().all(|row| row["snapshot_sha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)));
        let (status, next, second) = history_page(
            &app,
            &token,
            &format!("{draft_base}?after={}", cursor.unwrap().replace('|', "%7C")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second.len(), 100);
        let (status, last_cursor, last) = history_page(
            &app,
            &token,
            &format!("{draft_base}?after={}", next.unwrap().replace('|', "%7C")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(last.len(), 3);
        assert!(last_cursor.is_none());
        let filtered_base = format!("{draft_base}?profile_id=server-999");
        let (status, oldest_cursor, oldest) = history_page(&app, &token, &filtered_base).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(oldest.len(), 100);
        assert_eq!(oldest[0]["revision"], 1);
        assert_eq!(oldest[99]["revision"], 100);
        let (status, oldest_next, oldest_last) = history_page(
            &app,
            &token,
            &format!(
                "{filtered_base}&after={}",
                oldest_cursor.unwrap().replace('|', "%7C")
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(oldest_last.len(), 1);
        assert_eq!(oldest_last[0]["revision"], 101);
        assert!(oldest_next.is_none());
        let newest_base = format!("{filtered_base}&order=newest");
        let (status, newest_cursor, newest) = history_page(&app, &token, &newest_base).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(newest.len(), 100);
        assert_eq!(newest[0]["revision"], 101);
        assert_eq!(newest[99]["revision"], 2);
        let (status, newest_next, newest_last) = history_page(
            &app,
            &token,
            &format!(
                "{newest_base}&after={}",
                newest_cursor.unwrap().replace('|', "%7C")
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(newest_last.len(), 1);
        assert_eq!(newest_last[0]["revision"], 1);
        assert!(newest_next.is_none());
        let (status, filtered_cursor, filtered) =
            history_page(&app, &token, &format!("{draft_base}?profile_id=server-101")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(filtered_cursor.is_none());
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["profile_id"], "server-101");
        let (status, _, missing) = history_page(
            &app,
            &token,
            &format!("{draft_base}?profile_id=missing-profile"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(missing.is_empty());
        let (status, search_cursor, search_page) =
            history_page(&app, &token, &format!("{draft_base}?q=Synthetic%20server")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(search_page.len(), 100);
        assert!(search_page.iter().all(|row| row["display_name"]
            .as_str()
            .is_some_and(|name| name.starts_with("Synthetic server"))));
        let (status, _, search_tail) = history_page(
            &app,
            &token,
            &format!(
                "{draft_base}?q=Synthetic%20server&after={}",
                search_cursor.unwrap().replace('|', "%7C")
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(search_tail.len(), 2);
        let (status, policy_cursor, policy_page) =
            history_page(&app, &token, &format!("{draft_base}?policy_version=v1")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(policy_page.len(), 100);
        assert!(policy_page.iter().all(|row| row["policy_version"] == "v1"));
        let (status, _, policy_tail) = history_page(
            &app,
            &token,
            &format!(
                "{draft_base}?policy_version=v1&after={}",
                policy_cursor.unwrap().replace('|', "%7C")
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(policy_tail.len(), 3);
        let (_, _, other_policy) =
            history_page(&app, &token, &format!("{draft_base}?policy_version=v101")).await;
        assert_eq!(other_policy.len(), 1);
        let range = "from=2020-01-01T00%3A00%3A00.000Z&until=2090-01-01T00%3A00%3A00.000Z";
        let (status, range_cursor, range_page) =
            history_page(&app, &token, &format!("{draft_base}?{range}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(range_page.len(), 100);
        let (status, _, range_tail) = history_page(
            &app,
            &token,
            &format!(
                "{draft_base}?{range}&after={}",
                range_cursor.unwrap().replace('|', "%7C")
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(range_tail.len(), 100);
        let (_, _, old_range) = history_page(
            &app,
            &token,
            &format!("{draft_base}?until=2020-01-01T00%3A00%3A00.000Z"),
        )
        .await;
        assert!(old_range.is_empty());
        let (status, validity_cursor, validity_page) =
            history_page(&app, &token, &format!("{draft_base}?min_validity_days=90")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(validity_page.len(), 100);
        let (status, _, validity_tail) = history_page(
            &app,
            &token,
            &format!(
                "{draft_base}?min_validity_days=90&after={}",
                validity_cursor.unwrap().replace('|', "%7C")
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(validity_tail.len(), 100);
        let (_, _, high_validity) =
            history_page(&app, &token, &format!("{draft_base}?min_validity_days=91")).await;
        assert!(high_validity.is_empty());
        let (status, san_cursor, san_page) =
            history_page(&app, &token, &format!("{draft_base}?min_dns_sans=5")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(san_page.len(), 100);
        let (status, _, san_tail) = history_page(
            &app,
            &token,
            &format!(
                "{draft_base}?min_dns_sans=5&after={}",
                san_cursor.unwrap().replace('|', "%7C")
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(san_tail.len(), 100);
        let (_, _, high_san) =
            history_page(&app, &token, &format!("{draft_base}?min_dns_sans=6")).await;
        assert!(high_san.is_empty());
        let (_, _, literal_wildcard) =
            history_page(&app, &token, &format!("{draft_base}?q=%25%25")).await;
        assert!(literal_wildcard.is_empty());
        let (_, _, hidden_search) =
            history_page(&app, &token, &format!("{draft_base}?q=Hidden")).await;
        assert!(hidden_search.is_empty());
        for query in [
            "profile_id=Server-001".to_owned(),
            "profile_id=x".to_owned(),
            "profile_id=server-101&after=server-001%7C1".to_owned(),
            "profile_id=server-999&order=invalid".to_owned(),
            "order=newest".to_owned(),
            "q=x".to_owned(),
            "policy_version=%0A".to_owned(),
            "from=2026-02-30T00%3A00%3A00.000Z".to_owned(),
            "from=2090-01-01T00%3A00%3A00.000Z&until=2020-01-01T00%3A00%3A00.000Z".to_owned(),
            "min_validity_days=0".to_owned(),
            "min_validity_days=826".to_owned(),
            "min_dns_sans=0".to_owned(),
            "min_dns_sans=101".to_owned(),
        ] {
            assert_eq!(
                history_page(&app, &token, &format!("{draft_base}?{query}"))
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        let (status, _, _) =
            history_page(&app, &token, &format!("{draft_base}?after=invalid")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = history_page(
            &app,
            &token,
            "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/profile-drafts",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let exact = format!("{draft_base}/server-001/1");
        let (status, revision) = detail_response(&app, &token, &exact).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(revision["profile_id"], "server-001");
        assert_eq!(revision["revision"], 1);
        assert_eq!(revision["snapshot_sha256"], first[0]["snapshot_sha256"]);
        for bad in [
            format!("{draft_base}/server-001/0"),
            format!("{draft_base}/server-001/01"),
            format!("{draft_base}/Server-001/1"),
        ] {
            assert_eq!(
                detail_response(&app, &token, &bad).await.0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            detail_response(&app, &token, &format!("{draft_base}/server-001/2"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            detail_response(
                &app,
                &token,
                "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/profile-drafts/hidden-server/1"
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
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
            let (status, oldest_cursor, oldest_first) =
                history_page(&app, &token, &format!("{base}?order=oldest")).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(oldest_first.len(), 100);
            assert!(oldest_first[0][id_field]
                .as_str()
                .unwrap()
                .ends_with("000000000001"));
            let (status, next, oldest_second) = history_page(
                &app,
                &token,
                &format!(
                    "{base}?order=oldest&before={}",
                    oldest_cursor.unwrap().replace('|', "%7C")
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(oldest_second.len(), 2);
            assert!(next.is_none());
            let ids: HashSet<&str> = oldest_first
                .iter()
                .chain(&oldest_second)
                .map(|item| item[id_field].as_str().unwrap())
                .collect();
            assert_eq!(ids.len(), 102);
            let (status, _, _) = history_page(&app, &token, &format!("{base}?order=invalid")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
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
        let allowed = "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates/11111111-1111-4111-8111-000000000001";
        let (status, certificate) = detail_response(&app, &token, allowed).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            certificate["request_id"],
            "11111111-1111-4111-8111-000000000001"
        );
        assert_eq!(certificate["ca_id"], "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
        assert_eq!(certificate["subject_cn"], "paged-0001.lab.invalid");
        assert!(certificate["not_before"].is_null());
        assert!(certificate["not_after"].is_null());
        assert!(certificate["san_dns"].is_null());
        let search = "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates?cn=PAGED-006";
        let (status, cursor, matches) = history_page(&app, &token, search).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(matches.len(), 7);
        assert!(cursor.is_none());
        assert!(matches.iter().all(|item| item["subject_cn"]
            .as_str()
            .unwrap()
            .starts_with("paged-006")));
        let (status, _, none) = history_page(
            &app,
            &token,
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates?cn=paged%25",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(none.is_empty());
        let (status, _, _) = history_page(
            &app,
            &token,
            "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/certificates?cn=paged",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = history_page(
            &app,
            &token,
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates?cn=x",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let cert_base = "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates";
        let (status, _, san_matches) = history_page(
            &app,
            &token,
            &format!("{cert_base}?san_dns=PAGED-0102.LAB.INVALID"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(san_matches.len(), 1);
        assert_eq!(
            san_matches[0]["request_id"],
            "11111111-1111-4111-8111-000000000066"
        );
        let (status, _, combined) = history_page(
            &app,
            &token,
            &format!("{cert_base}?cn=PAGED-0&san_dns=paged-0102.lab.invalid"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(combined.len(), 1);
        let (status, _, expiring) = history_page(
            &app,
            &token,
            &format!("{cert_base}?not_after_before=2028-01-01T00%3A00%3A00.000Z"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(expiring.len(), 1);
        assert_eq!(
            expiring[0]["request_id"],
            "11111111-1111-4111-8111-000000000066"
        );
        let (status, _, combined_expiry) = history_page(
            &app,
            &token,
            &format!("{cert_base}?san_dns=paged-0102.lab.invalid&not_after_before=2028-01-01T00%3A00%3A00.000Z"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(combined_expiry.len(), 1);
        let (status, _, earlier) = history_page(
            &app,
            &token,
            &format!("{cert_base}?not_after_before=2027-10-01T00%3A00%3A00.000Z"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(earlier.is_empty());
        let (status, _, _) = history_page(
            &app,
            &token,
            &format!("{cert_base}?not_after_before=2027-02-29T00%3A00%3A00.000Z"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = history_page(
            &app,
            &token,
            "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/certificates?not_after_before=2028-01-01T00%3A00%3A00.000Z",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, no_san) = history_page(
            &app,
            &token,
            &format!("{cert_base}?san_dns=paged-0001.lab.invalid"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(no_san.is_empty());
        let (status, _, _) =
            history_page(&app, &token, &format!("{cert_base}?san_dns=%.lab.invalid")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = history_page(
            &app,
            &token,
            "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/certificates?san_dns=paged-0102.lab.invalid",
        ).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(certificate.get("certificate_der").is_none());
        let audit_base = "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/audit";
        let (status, _, events) = history_page(
            &app,
            &token,
            &format!("{audit_base}?from=2026-10-02T00%3A00%3A00.000Z"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(events.is_empty());
        let (status, _, events) = history_page(
            &app,
            &token,
            &format!(
                "{audit_base}?event_type=certificate.signed&until=2026-10-02T00%3A00%3A00.000Z"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(events.len(), 100);
        let (status, _, events) =
            history_page(&app, &token, &format!("{audit_base}?event_type=other")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(events.is_empty());
        let (status, _, events) =
            history_page(&app, &token, &format!("{audit_base}?decision=allow")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(events.len(), 100);
        let (status, _, events) =
            history_page(&app, &token, &format!("{audit_base}?decision=deny")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(events.is_empty());
        let (status, _, _) =
            history_page(&app, &token, &format!("{audit_base}?decision=%0A")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, events) =
            history_page(&app, &token, &format!("{audit_base}?policy_version=v1")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(events.len(), 100);
        let (status, _, events) =
            history_page(&app, &token, &format!("{audit_base}?policy_version=v2")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(events.is_empty());
        let (status, _, _) =
            history_page(&app, &token, &format!("{audit_base}?policy_version=%0A")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = history_page(
            &app,
            &token,
            &format!(
                "{audit_base}?from=2026-10-02T00%3A00%3A00.000Z&until=2026-10-01T00%3A00%3A00.000Z"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let serial_base = "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates/by-serial";
        let (status, by_serial) =
            detail_response(&app, &token, &format!("{serial_base}/010001")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(by_serial["request_id"], certificate["request_id"]);
        assert_eq!(by_serial["subject_cn"], "paged-0001.lab.invalid");
        for serial in [
            "10001",
            "0x10001",
            "0X10001",
            "01:00:01",
            "0x01:00:01",
            "00010001",
        ] {
            let (status, alias) =
                detail_response(&app, &token, &format!("{serial_base}/{serial}")).await;
            assert_eq!(status, StatusCode::OK, "serial {serial}");
            assert_eq!(alias["request_id"], certificate["request_id"]);
            assert_eq!(alias["serial_hex"], "010001");
        }
        let (status, uppercase) =
            detail_response(&app, &token, &format!("{serial_base}/01000A")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(uppercase["serial_hex"], "01000a");
        for serial in [
            "0",
            "00",
            "0x",
            "zz",
            "1::2",
            "1:00",
            "01:",
            "0xGG",
            "00000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffff",
        ] {
            let (status, _) =
                detail_response(&app, &token, &format!("{serial_base}/{serial}")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "serial {serial}");
        }
        let (status, _) = detail_response(&app, &token, &format!("{serial_base}/010067")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        for serial in ["80", "ff", "0001"] {
            let (status, _) =
                detail_response(&app, &token, &format!("{serial_base}/{serial}")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "serial {serial}");
        }
        let (status, _) = detail_response(
            &app,
            &token,
            "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/certificates/by-serial/010001",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = detail_response(&app, &token, "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates/11111111-1111-4111-8111-000000000999").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = detail_response(&app, &token, "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/certificates/11111111-1111-4111-8111-000000000001").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = detail_response(
            &app,
            &token,
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates/invalid",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let unprovisioned = encode(
            &header,
            &json!({
                "iss":"https://issuer.example.test", "aud":"trust-api", "sub":"unprovisioned",
                "nbf":now-1, "exp":now+60, "roles":["trust-ca-reader"],
                "ca_ids":["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]
            }),
            &signer,
        )
        .unwrap();
        let (status, _) = detail_response(&app, &unprovisioned, allowed).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) =
            detail_response(&app, &unprovisioned, &format!("{serial_base}/010001")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let allowed_event = "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/audit/33333333-3333-4333-8333-000000000001";
        let (status, event) = detail_response(&app, &token, allowed_event).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(event["event_id"], "33333333-3333-4333-8333-000000000001");
        assert_eq!(event["ca_id"], "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
        assert!(event.get("actor_id").is_none());
        let (status, _) = detail_response(&app, &token, "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/audit/33333333-3333-4333-8333-000000000999").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = detail_response(&app, &token, "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/audit/44444444-4444-4444-8444-444444444444").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = detail_response(
            &app,
            &token,
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/audit/invalid",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = detail_response(&app, &unprovisioned, allowed_event).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ca_pagination_reads_all_scoped_rows() {
        let database_url = match env::var("TRUST_API_CA_PAGINATION_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("SKIP: CA pagination fixture not configured; CI runs this test with a dedicated seeded database");
                return;
            }
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
            database_url,
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
        });
        let (status, cursor, first) = history_page(&app, &token, "/v1/cas").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first.len(), 100);
        let cursor = cursor.expect("102 CAs require another page");
        let anchor = parse_ca_cursor(Some(cursor.clone())).unwrap().unwrap();
        let (status, next, second) =
            history_page(&app, &token, &format!("/v1/cas?after={cursor}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second.len(), 2);
        assert!(next.is_none());
        let (status, search_cursor, first_matches) =
            history_page(&app, &token, "/v1/cas?q=SAME%20NAME").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first_matches.len(), 100);
        let (status, _, second_matches) = history_page(
            &app,
            &token,
            &format!("/v1/cas?q=SAME%20NAME&after={}", search_cursor.unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second_matches.len(), 2);
        let (status, _, policy_matches) = history_page(&app, &token, "/v1/cas?q=v1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(policy_matches.len(), 100);
        let (status, _, wildcard_matches) = history_page(&app, &token, "/v1/cas?q=%25%25").await;
        assert_eq!(status, StatusCode::OK);
        assert!(wildcard_matches.is_empty());
        let ids: HashSet<&str> = first
            .iter()
            .chain(&second)
            .map(|item| item["ca_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 102);
        assert_eq!(first[99]["ca_id"].as_str(), Some(anchor.ca_id.as_str()));
        assert_eq!(
            first[99]["display_name"].as_str(),
            Some(anchor.display_name.as_str())
        );
        assert!(!ids.contains("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"));
        let (status, _, _) =
            history_page(&app, &token, "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = history_page(&app, &token, "/v1/cas?after=invalid").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let admin_url = env::var("TRUST_API_CA_PAGINATION_ADMIN_URL")
            .expect("CA pagination fixture requires an owner login for revocation regression");
        let anchor_id = anchor.ca_id;
        let deleted = query_db(admin_url, Arc::new(Semaphore::new(1)), move |admin| {
            admin.execute(
                "DELETE FROM management_reader_grant WHERE issuer=$1 AND subject=$2 AND ca_id::text=$3",
                &[&"https://issuer.example.test", &"ca-page-operator", &anchor_id],
            )
        })
        .await
        .unwrap();
        assert_eq!(deleted, 1);
        let (status, next, after_revocation) =
            history_page(&app, &token, &format!("/v1/cas?after={cursor}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(after_revocation, second);
        assert!(next.is_none());
    }
    #[test]
    fn ca_cursor_round_trips_long_escaped_name() {
        let ca = Ca {
            ca_id: "55555555-5555-4555-8555-000000000064".into(),
            parent_ca_id: None,
            display_name: "\n".repeat(255),
            policy_version: "v1".into(),
            created_at: "2026-10-01T12:00:00.000Z".into(),
        };
        let cursor = encode_ca_cursor(&ca);
        assert!(cursor.len() <= 4096);
        let parsed = parse_ca_cursor(Some(cursor)).unwrap().unwrap();
        assert_eq!(parsed.display_name, ca.display_name);
        assert_eq!(parsed.ca_id, ca.ca_id);
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

    #[test]
    fn profile_draft_cursor_rejects_malformed_positions() {
        assert_eq!(
            profile_draft_cursor(Some("server-lab|2".into())).unwrap(),
            Some(("server-lab".into(), 2))
        );
        for invalid in [
            "server-lab",
            "Server|1",
            "server|0",
            "server|1000001",
            "server|x",
            "server|1|2",
            "../x|1",
        ] {
            assert!(profile_draft_cursor(Some(invalid.into())).is_err());
        }
    }

    #[tokio::test]
    async fn database_capacity_rejects_excess_work_before_connecting() {
        let Ok(url) = env::var("TRUST_API_TEST_DATABASE_URL") else {
            return; // The CI integration job supplies a disposable PostgreSQL database.
        };
        let slots = Arc::new(Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let busy = query_db(url.clone(), slots.clone(), |db| {
            db.query_one("SELECT 1", &[])
                .map(|row| row.get::<_, i32>(0))
        })
        .await;
        assert_eq!(busy, Err(StatusCode::SERVICE_UNAVAILABLE));
        drop(held);
        let available = query_db(url, slots, |db| {
            db.query_one("SELECT 1", &[])
                .map(|row| row.get::<_, i32>(0))
        })
        .await;
        assert_eq!(available, Ok(1));
    }

    #[tokio::test]
    async fn database_query_timeout_releases_capacity() {
        let Ok(url) = env::var("TRUST_API_TEST_DATABASE_URL") else {
            return; // The CI integration job supplies a disposable PostgreSQL database.
        };
        let slots = Arc::new(Semaphore::new(1));
        let slow = query_db(url.clone(), slots.clone(), |db| {
            db.query_one("SELECT pg_sleep(5)", &[]).map(|_| ())
        })
        .await;
        assert_eq!(slow, Err(StatusCode::SERVICE_UNAVAILABLE));
        let recovered = query_db(url, slots, |db| {
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
        let database_url = env::var("TRUST_API_TEST_DATABASE_URL").unwrap_or_default();
        let state = AppState {
            verifier,
            database_url: database_url.clone(),
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
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/profile-drafts/server-001/1",
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/audit",
        ] {
            let overloaded = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(overloaded.headers().contains_key("x-request-id"));
            assert_eq!(
                overloaded.headers().get("cache-control").unwrap(),
                "no-store"
            );
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
            live_while_busy.headers().get("cache-control").unwrap(),
            "no-store"
        );
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
            database_url:
                "host=/nonexistent/trust-db-socket port=55432 user=missing dbname=missing".into(),
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
        assert_eq!(
            no_token
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
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
