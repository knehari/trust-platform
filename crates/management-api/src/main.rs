mod auth;
mod ca_certificate;
mod ca_decision;
mod ca_operation;
mod ca_proposal;
mod certificate_application;
mod certificate_issuance;
mod certificate_revocation;
mod crl_publication;
mod profile_activation;
mod profile_decision;
mod profile_lifecycle;
mod profile_proposal;

use auth::{Claims, OidcVerifier};
use axum::{
    body::Body,
    extract::DefaultBodyLimit,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use postgres::{types::ToSql, Client, IsolationLevel, NoTls, Row, Transaction};
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
/// Every view and column the read routes use, including the history window
/// columns of migration 0017, the SAN view of 0018, the lowered CN of 0019
/// and the bounds view of 0020; LIMIT 0 reads no row.
const MANAGEMENT_VIEWS_CHECK: &str =
    "SELECT c.signed_at_window, c.subject_cn_lower, c.revoked_at, c.revocation_reason, a.recorded_at_window, s.signed_at_window, \
     b.newest_signed_window \
     , p.lifecycle_status, p.approval_count, p.activated_at, k.lifecycle_status, k.spki_sha256, k.approval_count, k.activated_at, k.change_status, management_ca.operational_state, ap.status, ap.certificate_sha256, ap.open_revocation_id, ap.revoked_at, crl.crl_number, cs.renewal_due, pub.crl_number \
     FROM management_ca, management_certificate c, management_audit a, management_reader_scope, management_profile_draft p, \
     management_certificate_san s, management_history_bounds b, management_ca_proposal k, management_certificate_application ap, management_certificate_crl crl, management_crl_status cs, public_crl_latest pub LIMIT 0";
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct AppState {
    verifier: OidcVerifier,
    database_url: String,
    /// Login holding only `trust_profile_writer` (migration 0022). Without
    /// it, the profile write routes answer 503.
    writer_database_url: Option<String>,
    database_slots: Arc<Semaphore>,
    http_data_slots: Arc<Semaphore>,
    readiness_slots: Arc<Semaphore>,
    readiness_cache: Arc<Mutex<ReadinessCache>>,
    /// Unix socket of the laboratory signer (ADR-0017). Without it, the
    /// issuance route answers 503.
    signer_socket: Option<std::path::PathBuf>,
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
    /// ACTIVE, SUSPENDED or RETIRED for a CA activated through the CA
    /// lifecycle (migration 0028); null for a CA the owner created directly.
    operational_state: Option<String>,
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
    /// When an approved revocation was recorded (migration 0033), UTC, or
    /// null. It reaches relying parties through the next published CRL.
    revoked_at: Option<String>,
    /// RFC 5280 CRLReason code of that revocation, or null.
    revocation_reason: Option<i16>,
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
    submitted_at: Option<String>,
    approval_count: i32,
    decided_at: Option<String>,
    activated_at: Option<String>,
    ended_at: Option<String>,
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

/// A trimmed, lowercased search prefix of 2–255 characters without control
/// characters.
fn lowercase_prefix(raw: Option<String>) -> Result<Option<String>, StatusCode> {
    let Some(raw) = raw else { return Ok(None) };
    let prefix = raw.trim();
    if !(2..=255).contains(&prefix.chars().count()) || prefix.chars().any(char::is_control) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Some(prefix.to_lowercase()))
}

/// A `LIKE` pattern matching the literal prefix.
fn literal_prefix(raw: Option<String>) -> Result<Option<String>, StatusCode> {
    let Some(prefix) = lowercase_prefix(raw)? else {
        return Ok(None);
    };
    let escaped = prefix
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
        value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control)
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
    // A real calendar time: the cursor time also anchors the page's slices.
    valid_utc_timestamp(timestamp)?;
    if uuid::Uuid::parse_str(id)
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

/// A history listing read in time slices. PostgreSQL does not push
/// `ORDER BY … LIMIT` into a `security_barrier` view, so one query would scan
/// the whole authority; a leakproof range on the view's millisecond window
/// column reaches its index instead. Slices are taken outward from an anchor
/// (the cursor, or a start point when there is none) and partition the
/// history, so concatenating their ordered rows keeps the page order. When
/// they do not fill the page, the unsliced statement reads it instead.
struct HistorySlices<'a> {
    window: &'static str,
    /// Projection, mandatory CA and grant predicates, cursor and filters.
    select: String,
    order: String,
    /// `$1` is the CA, `$2` and `$3` the reader's issuer and subject.
    params: Vec<&'a (dyn ToSql + Sync)>,
    newest: bool,
    /// UTC timestamp text in the views' format.
    anchor: String,
    /// With a cursor the first slice starts at the anchor; without one it is
    /// open on the far side, so rows beyond the start point are not missed.
    from_cursor: bool,
}

/// Width of a first slice, in seconds; later slices grow fourfold.
const HISTORY_SLICE_SECONDS: i64 = 3_600;
/// Bounded slices read before falling back to the unsliced statement (1, 4,
/// 16 and 64 hours from the anchor). Each slice joins and sorts all its
/// rows, so a sparse or empty filter, or an anchor far from the authority's
/// rows, ends in that fallback: such a page costs what one statement did,
/// plus these four small slices.
const HISTORY_BOUNDED_SLICES: u32 = 4;

impl HistorySlices<'_> {
    /// Predicates for rows whose distance from the anchor is in
    /// `[inner, outer)`; `None` leaves that side open. Placeholders start at
    /// `$first` (the anchor), followed by the offsets in seconds.
    fn range(&self, first: usize, inner: Option<i64>, outer: Option<i64>) -> (String, Vec<f64>) {
        let (sign, inner_op, outer_op) = if self.newest {
            ("-", "<=", ">")
        } else {
            ("+", ">=", "<")
        };
        let mut sql = String::new();
        let mut offsets = Vec::new();
        for (offset, op) in [(inner, inner_op), (outer, outer_op)] {
            if let Some(offset) = offset {
                offsets.push(offset as f64);
                sql.push_str(&format!(
                    " AND {} {op} ${first}::text::timestamp {sign} ${}::float8 * interval '1 second'",
                    self.window,
                    first + offsets.len()
                ));
            }
        }
        (sql, offsets)
    }

    /// The page's rows at a distance in `[inner, outer)`, at most `limit`.
    fn slice(
        &self,
        db: &mut Transaction<'_>,
        deadline: Instant,
        inner: Option<i64>,
        outer: Option<i64>,
        limit: usize,
    ) -> Result<Vec<Row>, postgres::Error> {
        let (range, offsets) = self.range(self.params.len() + 1, inner, outer);
        let sql = format!("{}{range}{} LIMIT {limit}", self.select, self.order);
        let mut params = self.params.clone();
        if !offsets.is_empty() {
            params.push(&self.anchor);
            params.extend(offsets.iter().map(|offset| offset as &(dyn ToSql + Sync)));
        }
        statement_budget(db, deadline)?;
        db.query(&sql, &params)
    }

    /// Up to `HISTORY_PAGE_SIZE + 1` rows in page order.
    fn read(
        &self,
        db: &mut Transaction<'_>,
        deadline: Instant,
    ) -> Result<Vec<Row>, postgres::Error> {
        let mut rows = Vec::new();
        let mut inner = self.from_cursor.then_some(0_i64);
        let mut width = HISTORY_SLICE_SECONDS;
        for _ in 0..HISTORY_BOUNDED_SLICES {
            let outer = inner.unwrap_or(0) + width;
            let limit = HISTORY_PAGE_SIZE + 1 - rows.len();
            rows.extend(self.slice(db, deadline, inner, Some(outer), limit)?);
            if rows.len() > HISTORY_PAGE_SIZE {
                return Ok(rows);
            }
            inner = Some(outer);
            width *= 4;
        }
        // The bounded slices did not fill the page: read it again with the
        // unsliced statement. Its plan is the one used before slicing (a
        // window bound on the remaining rows would cost a per-row time
        // computation in that scan).
        self.slice(db, deadline, None, None, HISTORY_PAGE_SIZE + 1)
    }
}

/// Gives the next statement what is left of the page's time budget (at
/// least 1 ms, so an exhausted budget fails it instead of running on).
fn statement_budget(db: &mut Transaction<'_>, deadline: Instant) -> Result<(), postgres::Error> {
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .max(1)
        .to_string();
    db.execute(
        "SELECT set_config('statement_timeout', $1, true)",
        &[&remaining],
    )?;
    Ok(())
}

/// A read-only transaction with one snapshot for all the slices of a page.
fn history_transaction(db: &mut Client) -> Result<Transaction<'_>, postgres::Error> {
    db.build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
}

/// Where the slices of a page start: the cursor's time, or, for a first
/// page, the authority's own newest (newest first) or oldest (oldest first)
/// signing or recording time, from `management_history_bounds` (0020). An
/// authority with no rows yet starts at the current time.
fn history_anchor(
    tx: &mut Transaction<'_>,
    scope: [&String; 3],
    cursor_time: Option<&String>,
    newest: bool,
    audit: bool,
) -> Result<String, postgres::Error> {
    if let Some(time) = cursor_time {
        return Ok(time.clone());
    }
    let bound = match (audit, newest) {
        (false, true) => "newest_signed_window",
        (false, false) => "oldest_signed_window",
        (true, true) => "newest_recorded_window",
        (true, false) => "oldest_recorded_window",
    };
    let row = tx.query_opt(
        &format!(
            "SELECT to_char(COALESCE({bound}, now() AT TIME ZONE 'UTC'), 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
             FROM management_history_bounds WHERE ca_id=$1 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$2 AND subject=$3 AND ca_id=$1)"
        ),
        &[scope[0], scope[1], scope[2]],
    )?;
    match row {
        Some(row) => Ok(row.get(0)),
        None => Ok(tx
            .query_one(
                "SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')",
                &[],
            )?
            .get(0)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = env::var("TRUST_OIDC_ISSUER")?;
    let audience = env::var("TRUST_OIDC_AUDIENCE")?;
    // The OAuth client of the human console. Tokens issued to any other
    // client of the issuer (workloads included) are refused.
    let client_id = env::var("TRUST_OIDC_CLIENT_ID")?;
    let database_url = env::var("TRUST_DATABASE_URL")?;
    let verifier = OidcVerifier::discover(&issuer, &audience, &client_id).await?;
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
    query_db(database_url.clone(), database_slots.clone(), |db| {
        db.query(MANAGEMENT_VIEWS_CHECK, &[]).map(|_| ())
    })
    .await
    .map_err(|_| "management views unavailable or older than migration 0033")?;
    let isolated = query_db(
        database_url.clone(),
        database_slots.clone(),
        reader_isolation_active,
    )
    .await
    .map_err(|_| "management views lack per-principal isolation (migration 0021)")?;
    if !isolated {
        return Err("management views return rows without a declared reader principal".into());
    }
    // Optional second login for the profile write routes (migration 0022).
    let writer_database_url = env::var("TRUST_WRITER_DATABASE_URL")
        .ok()
        .filter(|url| !url.is_empty());
    if let Some(url) = &writer_database_url {
        let restricted = query_db(
            url.clone(),
            database_slots.clone(),
            profile_lifecycle::restricted_writer_role,
        )
        .await
        .map_err(|_| "profile writer database unavailable or older than migration 0022")?;
        if !restricted {
            return Err("profile writer login is not limited to trust_profile_writer".into());
        }
    }
    let app = router(AppState {
        verifier,
        database_url,
        writer_database_url,
        database_slots,
        http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
        readiness_slots: Arc::new(Semaphore::new(1)),
        readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
        signer_socket: env::var("TRUST_SIGNER_SOCKET")
            .ok()
            .filter(|path| !path.is_empty())
            .map(std::path::PathBuf::from),
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
        .route(
            "/v1/cas/{ca_id}/profile-drafts",
            get(list_profile_drafts).post(profile_lifecycle::create_profile_draft),
        )
        .route(
            "/v1/cas/{ca_id}/profile-drafts/{profile_id}/{revision}",
            get(get_profile_draft_revision),
        )
        .route(
            "/v1/cas/{ca_id}/profile-drafts/{profile_id}/{revision}/submission",
            axum::routing::post(profile_lifecycle::submit_profile_draft),
        )
        .route(
            "/v1/cas/{ca_id}/profile-drafts/{profile_id}/{revision}/decision-claims",
            axum::routing::post(profile_decision::prepare_decision),
        )
        .route(
            "/v1/cas/{ca_id}/profile-drafts/{profile_id}/{revision}/decisions",
            axum::routing::post(profile_decision::record_decision),
        )
        .route(
            "/v1/cas/{ca_id}/profile-drafts/{profile_id}/{revision}/activation",
            axum::routing::post(profile_activation::activate_revision),
        )
        .route(
            "/v1/cas/{ca_id}/profile-drafts/{profile_id}/{revision}/retirement",
            axum::routing::post(profile_activation::retire_revision),
        )
        .route(
            "/v1/ca-proposals",
            get(ca_proposal::list_ca_proposals).post(ca_proposal::propose_ca),
        )
        .route(
            "/v1/ca-proposals/{ca_id}/issuer-certificate",
            axum::routing::post(ca_proposal::register_issuer_certificate),
        )
        .route(
            "/v1/ca-proposals/{ca_id}/decision-claims",
            axum::routing::post(ca_decision::prepare_ca_decision),
        )
        .route(
            "/v1/ca-proposals/{ca_id}/decisions",
            axum::routing::post(ca_decision::record_ca_decision),
        )
        .route(
            "/v1/ca-proposals/{ca_id}/activation",
            axum::routing::post(ca_decision::activate_ca),
        )
        .route(
            "/v1/ca-proposals/{ca_id}/suspension",
            axum::routing::post(ca_operation::suspend_ca),
        )
        .route(
            "/v1/ca-proposals/{ca_id}/change-requests",
            axum::routing::post(ca_operation::request_change),
        )
        .route(
            "/v1/ca-proposals/{ca_id}/change-requests/{request_id}/decision-claims",
            axum::routing::post(ca_operation::prepare_change_decision),
        )
        .route(
            "/v1/ca-proposals/{ca_id}/change-requests/{request_id}/decisions",
            axum::routing::post(ca_operation::record_change_decision),
        )
        .route(
            "/v1/ca-proposals/{ca_id}/change-requests/{request_id}/application",
            axum::routing::post(ca_operation::apply_change),
        )
        .route(
            "/v1/cas/{ca_id}/certificate-applications",
            get(certificate_application::list_applications)
                .post(certificate_application::submit_application),
        )
        .route(
            "/v1/cas/{ca_id}/certificate-applications/{application_id}/decision",
            axum::routing::post(certificate_application::decide_application),
        )
        .route(
            "/v1/cas/{ca_id}/certificate-applications/{application_id}/issuance",
            axum::routing::post(certificate_issuance::issue_application),
        )
        .route(
            "/v1/cas/{ca_id}/certificate-applications/{application_id}/revocation-requests",
            axum::routing::post(certificate_revocation::request_revocation),
        )
        .route(
            "/v1/cas/{ca_id}/certificate-applications/{application_id}/revocation-requests/{revocation_id}/decision",
            axum::routing::post(certificate_revocation::decide_revocation),
        )
        .route(
            "/v1/cas/{ca_id}/crls",
            get(crl_publication::list_crls).post(crl_publication::publish_crl),
        )
        .route(
            "/v1/cas/{ca_id}/crls/{crl_number}",
            get(crl_publication::read_crl),
        )
        .route(
            "/v1/cas/{ca_id}/crl-status",
            get(crl_publication::crl_status),
        )
        .route(
            "/v1/public/crls/{ca_id}/latest.crl",
            get(crl_publication::public_latest_crl),
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
        .layer(DefaultBodyLimit::max(
            profile_lifecycle::MAX_WRITE_BODY_BYTES,
        ))
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
            db.query(MANAGEMENT_VIEWS_CHECK, &[])?;
            reader_isolation_active(db)
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
         AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname='trust_profile_writer' \
             AND pg_has_role(current_user,r.oid,'member')) \
         AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname=current_user \
             AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb)) \
         AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
             WHERE n.nspname='public' AND c.relkind IN ('r','p','m','f') \
             AND has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))",
        &[],
    )
    .map(|row| row.get::<_, bool>(0))
}

/// Verifies the bearer token only: 401 when it is missing or invalid.
async fn authenticate(headers: &HeaderMap, verifier: &OidcVerifier) -> Result<Claims, StatusCode> {
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
    Ok(claims)
}

/// Read routes: a verified token with the reader role (403 without it).
async fn authorize(headers: &HeaderMap, verifier: &OidcVerifier) -> Result<Claims, StatusCode> {
    let claims = authenticate(headers, verifier).await?;
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

/// Runs `query` on a connection that declares the verified OIDC principal to
/// PostgreSQL (migration 0021). Every management view then returns only the
/// rows of authorities granted to that principal, and nothing at all on a
/// connection that declares none. The API's own CA predicates and grant checks
/// stay in every query: the database filter is a second, independent layer.
async fn query_db_as<T: Send + 'static>(
    url: String,
    slots: Arc<Semaphore>,
    principal: (String, String),
    query: impl FnOnce(&mut Client) -> Result<T, postgres::Error> + Send + 'static,
) -> Result<T, StatusCode> {
    query_db(url, slots, move |db| {
        // Session settings: each request opens its own connection and drops it.
        db.execute(
            "SELECT set_config('trust.reader_issuer', $1, false), \
             set_config('trust.reader_subject', $2, false)",
            &[&principal.0, &principal.1],
        )?;
        query(db)
    })
    .await
}

/// Whether every management view filters by principal: migration 0021's
/// marker exists and a connection without a principal sees no rows.
fn reader_isolation_active(db: &mut Client) -> Result<bool, postgres::Error> {
    Ok(db
        .query_one(
            "SELECT management_reader_isolation_version() = 1 \
             AND NOT EXISTS (SELECT 1 FROM management_ca) \
             AND NOT EXISTS (SELECT 1 FROM management_certificate) \
             AND NOT EXISTS (SELECT 1 FROM management_audit) \
             AND NOT EXISTS (SELECT 1 FROM management_reader_scope) \
             AND NOT EXISTS (SELECT 1 FROM management_certificate_san) \
             AND NOT EXISTS (SELECT 1 FROM management_history_bounds) \
             AND NOT EXISTS (SELECT 1 FROM management_profile_draft) \
             AND management_ca_proposal_version() = 1 \
             AND management_ca_activation_version() = 1 \
             AND management_ca_operation_version() = 1 \
             AND management_certificate_application_version() = 1 \
             AND management_application_issuance_version() = 1 \
             AND management_revocation_crl_version() = 1 \
             AND management_crl_publication_version() = 1 \
             AND management_certificate_revocation_version() = 1 \
             AND NOT EXISTS (SELECT 1 FROM management_certificate_crl) \
             AND NOT EXISTS (SELECT 1 FROM management_crl_status) \
             AND NOT EXISTS (SELECT 1 FROM management_ca_proposal)",
            &[],
        )?
        .get(0))
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
    let rows = query_db_as(state.database_url, state.database_slots, (issuer.clone(), subject.clone()), move |db| {
        db.query(
            "SELECT c.ca_id,c.parent_ca_id,c.display_name,c.policy_version,c.created_at,c.operational_state \
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
            operational_state: r.get(5),
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
    let row = query_db_as(
        state.database_url,
        state.database_slots,
        (issuer.clone(), subject.clone()),
        move |db| {
            db.query_opt(
                "SELECT c.ca_id,c.parent_ca_id,c.display_name,c.policy_version,c.created_at,c.operational_state \
         FROM management_ca c JOIN management_reader_scope g ON g.ca_id=c.ca_id \
         WHERE c.ca_id=$1 AND g.issuer=$2 AND g.subject=$3",
                &[&ca_id, &issuer, &subject],
            )
        },
    )
    .await?
    .ok_or(StatusCode::FORBIDDEN)?;
    Ok(Json(Ca {
        ca_id: row.get(0),
        parent_ca_id: row.get(1),
        display_name: row.get(2),
        policy_version: row.get(3),
        created_at: row.get(4),
        operational_state: row.get(5),
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
    // Characters, not bytes: drafts store up to 128 characters of any script.
    if policy_version.as_ref().is_some_and(|value| {
        value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control)
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
    let rows = query_db_as(state.database_url, state.database_slots, (issuer.clone(), subject.clone()), move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer, &subject, &ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        let query = format!("SELECT ca_id,profile_id,revision,display_name,policy_version,max_validity_days,max_dns_sans,\
             proposed_dns_zones,proposed_signature_suites,created_by,created_at,lifecycle_status,submitted_at,approval_count,decided_at,activated_at,ended_at \
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
        status: match row.get::<_, &str>(11) {
            "DRAFT" => "DRAFT",
            "SUBMITTED" => "SUBMITTED",
            "APPROVED" => "APPROVED",
            "REJECTED" => "REJECTED",
            "ACTIVE" => "ACTIVE",
            "SUPERSEDED" => "SUPERSEDED",
            "RETIRED" => "RETIRED",
            _ => "UNKNOWN",
        },
        submitted_at: row.get(12),
        approval_count: row.get(13),
        decided_at: row.get(14),
        activated_at: row.get(15),
        ended_at: row.get(16),
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
    let row = query_db_as(state.database_url, state.database_slots, (issuer.clone(), subject.clone()), move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer, &subject, &ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        db.query_opt(
            "SELECT ca_id,profile_id,revision,display_name,policy_version,max_validity_days,max_dns_sans,\
             proposed_dns_zones,proposed_signature_suites,created_by,created_at,lifecycle_status,submitted_at,approval_count,decided_at,activated_at,ended_at \
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
    let cn_prefix = lowercase_prefix(page.cn)?;
    let san_dns = exact_san_dns(page.san_dns)?;
    let not_after_before = page
        .not_after_before
        .as_deref()
        .map(valid_utc_timestamp)
        .transpose()?;
    let (before_time, before_id) = cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
    let issuer = claims.iss;
    let subject = claims.sub;
    let rows = query_db_as(state.database_url, state.database_slots, (issuer.clone(), subject.clone()), move |db| {
        let deadline = Instant::now() + Duration::from_millis(DATABASE_STATEMENT_TIMEOUT_MS);
        // One snapshot for every slice of the page, as for a single statement.
        let mut tx = history_transaction(db)?;
        let granted: bool = tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer,&subject,&ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        let mut select = format!("SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at,subject_cn,not_before,not_after,san_dns,revoked_at,revocation_reason \
             FROM management_certificate WHERE ca_id=$1 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$2 AND subject=$3 AND ca_id=$1) \
             AND ($4::text IS NULL OR (signed_at, request_id) {comparison} ($4, $5))");
        let mut params: Vec<&(dyn ToSql + Sync)> =
            vec![&ca_id, &issuer, &subject, &before_time, &before_id];
        if let Some(prefix) = cn_prefix.as_ref() {
            // starts_with (^@) is leakproof and, on the "C"-collated stored
            // column of 0019, an index range: it reaches the index through the
            // barrier, where lower() and LIKE did not.
            select.push_str(&format!(" AND subject_cn_lower ^@ ${}", params.len() + 1));
            params.push(prefix);
        }
        if let Some(cutoff) = not_after_before.as_ref() {
            select.push_str(&format!(" AND not_after < ${}", params.len() + 1));
            params.push(cutoff);
        }
        let newest = direction == "DESC";
        let order = format!(" ORDER BY signed_at {direction}, request_id {direction}");
        if let Some(dns) = san_dns.as_ref() {
            let rows = read_san_page(&mut tx, deadline, SanPage {
                ca_id: &ca_id,
                issuer: &issuer,
                subject: &subject,
                comparison,
                order: &order,
                newest,
                cursor: before_time.clone().zip(before_id.clone()),
                dns,
                select: &select,
                params: &params,
            })?;
            tx.commit()?;
            return Ok(Some(rows));
        }
        let anchor = history_anchor(&mut tx, [&ca_id, &issuer, &subject], before_time.as_ref(), newest, false)?;
        let slices = HistorySlices {
            window: "signed_at_window",
            select,
            order,
            params,
            newest,
            anchor,
            from_cursor: before_time.is_some(),
        };
        let rows = slices.read(&mut tx, deadline)?;
        tx.commit()?;
        Ok(Some(rows))
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

/// A certificate page filtered on one DNS SAN.
struct SanPage<'a> {
    ca_id: &'a String,
    issuer: &'a String,
    subject: &'a String,
    /// `<` (newest first) or `>` (oldest first).
    comparison: &'static str,
    order: &'a str,
    newest: bool,
    cursor: Option<(String, String)>,
    /// Lowercase ASCII DNS name.
    dns: &'a String,
    /// The certificate query with its scope, cursor, CN and notAfter
    /// predicates, and its parameters.
    select: &'a str,
    params: &'a [&'a (dyn ToSql + Sync)],
}

/// Reads a SAN-filtered page in two steps (migration 0018). Step one lists,
/// in page order, the request ids whose certificate carries the name, from
/// the indexed `management_certificate_san` view, in time slices like any
/// history page. Step two reads those certificates from
/// `management_certificate` with the page's other predicates. Both views
/// stay `security_barrier`, every statement keeps the CA predicate and the
/// server-owned grant, and the SAN view carries the certificate's own time
/// text, so the two steps share one order and one cursor. When the other
/// filters drop rows, step one continues after its last id.
fn read_san_page(
    db: &mut Transaction<'_>,
    deadline: Instant,
    page: SanPage<'_>,
) -> Result<Vec<Row>, postgres::Error> {
    let mut rows: Vec<Row> = Vec::new();
    let mut after = page.cursor.clone();
    loop {
        let (time, id) = after.clone().unzip();
        let anchor = history_anchor(
            db,
            [page.ca_id, page.issuer, page.subject],
            time.as_ref(),
            page.newest,
            false,
        )?;
        let matches = HistorySlices {
            window: "signed_at_window",
            select: format!(
                "SELECT request_id, signed_at FROM management_certificate_san WHERE ca_id=$1 AND EXISTS \
                 (SELECT 1 FROM management_reader_scope WHERE issuer=$2 AND subject=$3 AND ca_id=$1) \
                 AND ($4::text IS NULL OR (signed_at, request_id) {} ($4, $5)) AND san_dns=$6",
                page.comparison
            ),
            order: page.order.to_owned(),
            params: vec![page.ca_id, page.issuer, page.subject, &time, &id, page.dns],
            newest: page.newest,
            anchor,
            from_cursor: time.is_some(),
        }
        .read(db, deadline)?;
        let ids: Vec<String> = matches.iter().map(|row| row.get(0)).collect();
        if ids.is_empty() {
            return Ok(rows);
        }
        let mut params = page.params.to_vec();
        params.push(&ids);
        let sql = format!(
            "{} AND request_id = ANY(${}){} LIMIT {}",
            page.select,
            params.len(),
            page.order,
            HISTORY_PAGE_SIZE + 1 - rows.len()
        );
        statement_budget(db, deadline)?;
        rows.extend(db.query(&sql, &params)?);
        if rows.len() > HISTORY_PAGE_SIZE || matches.len() <= HISTORY_PAGE_SIZE {
            return Ok(rows);
        }
        let last = matches.last().expect("a full batch has a last id");
        after = Some((last.get(1), last.get(0)));
    }
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
        revoked_at: row.get(11),
        revocation_reason: row.get(12),
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
    let row = query_db_as(state.database_url, state.database_slots, (issuer.clone(), subject.clone()), move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer, &subject, &ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        db.query_opt(
            "SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at,subject_cn,not_before,not_after,san_dns,revoked_at,revocation_reason \
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
    let row = query_db_as(state.database_url, state.database_slots, (issuer.clone(), subject.clone()), move |db| {
        let granted: bool = db.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer, &subject, &ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        db.query_opt(
            "SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at,subject_cn,not_before,not_after,san_dns,revoked_at,revocation_reason \
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
    let rows = query_db_as(state.database_url, state.database_slots, (issuer.clone(), subject.clone()), move |db| {
        let deadline = Instant::now() + Duration::from_millis(DATABASE_STATEMENT_TIMEOUT_MS);
        let mut tx = history_transaction(db)?;
        let granted: bool = tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=$1 AND subject=$2 AND ca_id=$3)",
            &[&issuer,&subject,&ca_id],
        )?.get(0);
        if !granted { return Ok(None); }
        let select = format!("SELECT event_id,ca_id,event_type,decision,policy_version,recorded_at \
             FROM management_audit WHERE ca_id=$1 AND EXISTS \
             (SELECT 1 FROM management_reader_scope WHERE issuer=$2 AND subject=$3 AND ca_id=$1) \
             AND ($4::text IS NULL OR (recorded_at, event_id) {comparison} ($4, $5)) \
             AND ($6::text IS NULL OR recorded_at >= $6) \
             AND ($7::text IS NULL OR recorded_at < $7) \
             AND ($8::text IS NULL OR event_type = $8) \
             AND ($9::text IS NULL OR decision = $9) \
             AND ($10::text IS NULL OR policy_version = $10)");
        let newest = direction == "DESC";
        let anchor = history_anchor(&mut tx, [&ca_id, &issuer, &subject], before_time.as_ref(), newest, true)?;
        let slices = HistorySlices {
            window: "recorded_at_window",
            select,
            order: format!(" ORDER BY recorded_at {direction}, event_id {direction}"),
            params: vec![&ca_id, &issuer, &subject, &before_time, &before_id, &filters.from, &filters.until, &filters.event_type, &filters.decision, &filters.policy_version],
            newest,
            anchor,
            from_cursor: before_time.is_some(),
        };
        let rows = slices.read(&mut tx, deadline)?;
        tx.commit()?;
        Ok(Some(rows))
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
    let row = query_db_as(state.database_url, state.database_slots, (issuer.clone(), subject.clone()), move |db| {
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
mod history_timing;

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

    /// Profile write routes against PostgreSQL (migration 0022). CI seeds a
    /// reader grant and a profile-editor grant for `operator` on CA E, and
    /// provides a login holding only trust_profile_writer.
    #[tokio::test]
    async fn profile_writes_are_granted_idempotent_serialized_and_submitted_once() {
        let (Ok(reader_url), Ok(writer_url)) = (
            env::var("TRUST_API_TEST_DATABASE_URL"),
            env::var("TRUST_API_WRITER_TEST_DATABASE_URL"),
        ) else {
            eprintln!("SKIP: profile write routes need TRUST_API_TEST_DATABASE_URL and TRUST_API_WRITER_TEST_DATABASE_URL; CI sets both");
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"write-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("write-test".into());
        let token = |sub: &str, roles: serde_json::Value, ca: &str| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles, "ca_ids":[ca]}),
                &signer,
            )
            .unwrap()
        };
        const CA: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let editor = token(
            "operator",
            json!(["trust-profile-editor", "trust-ca-reader"]),
            CA,
        );
        let reader_only = token("operator", json!(["trust-ca-reader"]), CA);
        let ungranted_editor = token("someone-else", json!(["trust-profile-editor"]), CA);
        let ungranted_ca = token(
            "operator",
            json!(["trust-profile-editor"]),
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
        );
        let state = AppState {
            verifier,
            database_url: reader_url,
            writer_database_url: Some(writer_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
        };
        let app = router(state.clone());
        let post = |token: &str, path: &str, key: Option<String>, body: String| {
            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json");
            if let Some(key) = key {
                request = request.header("idempotency-key", key);
            }
            let app = app.clone();
            let request = request.body(Body::from(body)).unwrap();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let replayed = response.headers().contains_key("idempotent-replayed");
                let body = response.into_body().collect().await.unwrap().to_bytes();
                let value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                (status, replayed, value)
            }
        };
        // A fresh profile per run, so the test can repeat on one database.
        let profile = format!("http-{}", &random_uuid().simple().to_string()[..12]);
        let base = format!("/v1/cas/{CA}/profile-drafts");
        let draft = |name: &str, zone: &str| {
            json!({"profile_id":profile, "display_name":name, "policy_version":"v1",
                   "max_validity_days":90, "max_dns_sans":5,
                   "proposed_dns_zones":[zone], "proposed_signature_suites":["P256-SHA256"]})
            .to_string()
        };
        let key = || Some(random_uuid().to_string());

        // Refusals before any write: no editor role, a CA outside the token
        // scope, a CA in scope without a database grant, an editor without a
        // grant, and malformed requests.
        assert_eq!(
            post(
                &editor,
                "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/profile-drafts",
                key(),
                draft("A", "lab.invalid")
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(&reader_only, &base, key(), draft("A", "lab.invalid"))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                &ungranted_ca,
                "/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff/profile-drafts",
                key(),
                draft("A", "lab.invalid")
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(&ungranted_editor, &base, key(), draft("A", "lab.invalid"))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(&editor, &base, None, draft("A", "lab.invalid"))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post(
                &editor,
                &base,
                Some("not-a-uuid".into()),
                draft("A", "lab.invalid")
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let mut extra: serde_json::Value =
            serde_json::from_str(&draft("A", "lab.invalid")).unwrap();
        extra["status"] = json!("APPROVED");
        assert_eq!(
            post(&editor, &base, key(), extra.to_string()).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post(&editor, &base, key(), "x".repeat(17 * 1024)).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let text_body = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&base)
                    .header("authorization", format!("Bearer {editor}"))
                    .header("content-type", "text/plain")
                    .header("idempotency-key", random_uuid().to_string())
                    .body(Body::from(draft("A", "lab.invalid")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(text_body.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let without_writer = router(AppState {
            writer_database_url: None,
            ..state.clone()
        });
        let unavailable = without_writer
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&base)
                    .header("authorization", format!("Bearer {editor}"))
                    .header("content-type", "application/json")
                    .header("idempotency-key", random_uuid().to_string())
                    .body(Body::from(draft("A", "lab.invalid")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Concurrent creations get distinct, dense revisions.
        let created = futures_join_all((0..6).map(|index| {
            post(
                &editor,
                &base,
                key(),
                draft(&format!("Concurrent {index}"), "lab.invalid"),
            )
        }))
        .await;
        let mut revisions: Vec<i64> = created
            .iter()
            .map(|(status, replayed, body)| {
                assert_eq!(*status, StatusCode::CREATED);
                assert!(!replayed);
                assert_eq!(body["status"], "DRAFT");
                body["revision"].as_i64().unwrap()
            })
            .collect();
        revisions.sort_unstable();
        assert_eq!(revisions, vec![1, 2, 3, 4, 5, 6]);

        // Replay returns the recorded revision; the key cannot be reused.
        let replay_key = key();
        let first = post(
            &editor,
            &base,
            replay_key.clone(),
            draft("Replayed", "lab.invalid"),
        )
        .await;
        assert_eq!((first.0, first.1), (StatusCode::CREATED, false));
        let again = post(
            &editor,
            &base,
            replay_key.clone(),
            draft("Replayed", "lab.invalid"),
        )
        .await;
        assert_eq!((again.0, again.1), (StatusCode::OK, true));
        assert_eq!(again.2["revision"], first.2["revision"]);
        assert_eq!(again.2["snapshot_sha256"], first.2["snapshot_sha256"]);
        assert_eq!(
            post(&editor, &base, replay_key, draft("Changed", "lab.invalid"))
                .await
                .0,
            StatusCode::CONFLICT
        );
        let latest = first.2["revision"].as_i64().unwrap();
        assert_eq!(latest, 7);
        let digest = first.2["snapshot_sha256"].as_str().unwrap().to_owned();

        // Submission: stale revision, altered digest, unknown revision.
        let submit = |revision: i64| format!("{base}/{profile}/{revision}/submission");
        let body = |digest: &str| json!({"snapshot_sha256": digest}).to_string();
        assert_eq!(
            post(
                &editor,
                &submit(6),
                key(),
                body(created[0].2["snapshot_sha256"].as_str().unwrap())
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(&editor, &submit(latest), key(), body(&"0".repeat(64)))
                .await
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(&editor, &submit(99), key(), body(&digest)).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post(&reader_only, &submit(latest), key(), body(&digest))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let submit_key = key();
        let submitted = post(&editor, &submit(latest), submit_key.clone(), body(&digest)).await;
        assert_eq!((submitted.0, submitted.1), (StatusCode::CREATED, false));
        assert_eq!(submitted.2["status"], "SUBMITTED");
        let replayed = post(&editor, &submit(latest), submit_key, body(&digest)).await;
        assert_eq!((replayed.0, replayed.1), (StatusCode::OK, true));
        assert_eq!(replayed.2["submitted_at"], submitted.2["submitted_at"]);
        assert_eq!(
            post(&editor, &submit(latest), key(), body(&digest)).await.0,
            StatusCode::CONFLICT
        );

        // Readers see the state; a revision with syntax warnings cannot be
        // submitted and stays a DRAFT.
        let (status, detail) =
            detail_response(&app, &editor, &format!("{base}/{profile}/{latest}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(detail["status"], "SUBMITTED");
        assert_eq!(detail["submitted_at"], submitted.2["submitted_at"]);
        let warned = post(&editor, &base, key(), draft("Warned", "Not_A_Zone")).await;
        assert_eq!(warned.0, StatusCode::CREATED);
        assert_eq!(warned.2["proposal_warnings"], json!(["invalid_dns_zone"]));
        let warned_revision = warned.2["revision"].as_i64().unwrap();
        let warned_digest = warned.2["snapshot_sha256"].as_str().unwrap().to_owned();
        assert_eq!(
            post(
                &editor,
                &submit(warned_revision),
                key(),
                body(&warned_digest)
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let (_, detail) = detail_response(
            &app,
            &editor,
            &format!("{base}/{profile}/{warned_revision}"),
        )
        .await;
        assert_eq!(detail["status"], "DRAFT");
        assert_eq!(detail["submitted_at"], serde_json::Value::Null);
    }

    /// Public keys of the deterministic approver test keys ([0x11; 32],
    /// [0x22; 32], [0x33; 32]); CI registers them for approver-http-1,
    /// approver-http-2 and operator (migration 0023), and [0x44; 32],
    /// [0x55; 32] for ca-approver-http-1 and -2 (migration 0027).
    const APPROVER_TEST_KEYS: [(u8, &str); 5] = [
        (0x11, "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"),
        (0x22, "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285"),
        (0x33, "0451a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d0110522712b0b5a7cff081685486984a94e6831edac46e7360fa9d834a7a81a1"),
        (0x44, "045b36890dacbd7c9a96bb74a1ee28b3d2d75b72e09a20ef25cf8e6fd8a9f0350d0e14bed8d4682a34d83538bdff5b96e89a6666ec0db5745d02fa1210072df75a"),
        (0x55, "0457e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34c5ab3770ba573bdff5414065640ffb5b346dfa84dec4db4d68e5f59cc471c2ec"),
    ];

    #[test]
    fn approver_test_keys_match_the_ci_registration() {
        use p256::ecdsa::SigningKey;
        for (scalar, expected) in APPROVER_TEST_KEYS {
            let key = SigningKey::from_slice(&[scalar; 32]).unwrap();
            let point = key.verifying_key().to_encoded_point(false);
            let hex: String = point
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(hex, expected);
        }
    }

    /// Signed decisions against PostgreSQL (migration 0023). CI seeds the
    /// grants and keys named above.
    #[tokio::test]
    async fn profile_decisions_need_two_distinct_signed_approvals() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let (Ok(reader_url), Ok(writer_url)) = (
            env::var("TRUST_API_TEST_DATABASE_URL"),
            env::var("TRUST_API_WRITER_TEST_DATABASE_URL"),
        ) else {
            eprintln!("SKIP: profile decisions need TRUST_API_TEST_DATABASE_URL and TRUST_API_WRITER_TEST_DATABASE_URL; CI sets both");
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"decision-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("decision-test".into());
        const CA: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let token = |sub: &str, roles: serde_json::Value| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles, "ca_ids":[CA]}),
                &signer,
            )
            .unwrap()
        };
        let editor = token(
            "operator",
            json!(["trust-profile-editor", "trust-ca-reader"]),
        );
        let author_as_approver = token("operator", json!(["trust-policy-approver"]));
        let approver_1 = token("approver-http-1", json!(["trust-policy-approver"]));
        let approver_2 = token("approver-http-2", json!(["trust-policy-approver"]));
        let key_1 = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let key_2 = SigningKey::from_slice(&[0x22; 32]).unwrap();
        let sign = |key: &SigningKey, text: &str| {
            let signature: Signature = key.sign(text.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())
        };
        let app = router(AppState {
            verifier,
            database_url: reader_url,
            writer_database_url: Some(writer_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
        });
        let post = |token: &str, path: String, body: serde_json::Value, key: bool| {
            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json");
            if key {
                request = request.header("idempotency-key", random_uuid().to_string());
            }
            let request = request.body(Body::from(body.to_string())).unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
                )
            }
        };
        let base = format!("/v1/cas/{CA}/profile-drafts");
        // Two submitted revisions authored and submitted by "operator".
        let mut profiles = Vec::new();
        for _ in 0..2 {
            let profile = format!("decide-{}", &random_uuid().simple().to_string()[..12]);
            let (status, draft) = post(
                &editor,
                base.clone(),
                json!({"profile_id":profile, "display_name":"Decision", "policy_version":"v1",
                       "max_validity_days":90, "max_dns_sans":5,
                       "proposed_dns_zones":["lab.invalid"], "proposed_signature_suites":["P256-SHA256"]}),
                true,
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            let (status, _) = post(
                &editor,
                format!("{base}/{profile}/1/submission"),
                json!({"snapshot_sha256": draft["snapshot_sha256"]}),
                true,
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            profiles.push(profile);
        }
        let claims = |profile: &str| format!("{base}/{profile}/1/decision-claims");
        let decisions = |profile: &str| format!("{base}/{profile}/1/decisions");
        let approve = json!({"decision":"approve"});

        // Refusals: an editor token, the author holding an approver grant.
        assert_eq!(
            post(&editor, claims(&profiles[0]), approve.clone(), false)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                &author_as_approver,
                claims(&profiles[0]),
                approve.clone(),
                false
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                &approver_1,
                claims(&profiles[0]),
                json!({"decision":"activate"}),
                false
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );

        // First approval, signed by approver 1's key over the exact claim.
        let (status, claim) = post(&approver_1, claims(&profiles[0]), approve.clone(), false).await;
        assert_eq!(status, StatusCode::OK);
        let text = claim["claim"].as_str().unwrap().to_owned();
        assert!(text.starts_with("trust-platform/profile-decision/v1;decision=approve;"));
        assert!(text.contains(";approver_subject=approver-http-1;"));
        let body = json!({"decision":"approve", "issued_at":claim["issued_at"], "signature_der_base64":sign(&key_1, &text)});
        let first = post(&approver_1, decisions(&profiles[0]), body.clone(), true).await;
        assert_eq!(first.0, StatusCode::CREATED);
        assert_eq!(
            (
                first.1["status"].as_str(),
                first.1["approval_count"].as_i64()
            ),
            (Some("SUBMITTED"), Some(1))
        );

        // Approver 2: a signature by another key, or over altered text, or
        // with another issue time, is refused and leaves nothing.
        let (_, claim_2) = post(&approver_2, claims(&profiles[0]), approve.clone(), false).await;
        let text_2 = claim_2["claim"].as_str().unwrap().to_owned();
        let attempt = |signature: String, issued_at: serde_json::Value| json!({"decision":"approve", "issued_at":issued_at, "signature_der_base64":signature});
        assert_eq!(
            post(
                &approver_2,
                decisions(&profiles[0]),
                attempt(sign(&key_1, &text_2), claim_2["issued_at"].clone()),
                true
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            post(
                &approver_2,
                decisions(&profiles[0]),
                attempt(
                    sign(&key_2, &text_2.replace("revision=1", "revision=2")),
                    claim_2["issued_at"].clone()
                ),
                true
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            post(
                &approver_2,
                decisions(&profiles[0]),
                attempt(sign(&key_2, &text_2), json!("2026-01-01T00:00:00.000Z")),
                true
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(
                &approver_2,
                decisions(&profiles[0]),
                attempt("not base64!".into(), claim_2["issued_at"].clone()),
                true
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let (_, detail) =
            detail_response(&app, &editor, &format!("{base}/{}/1", profiles[0])).await;
        assert_eq!(
            (detail["status"].as_str(), detail["approval_count"].as_i64()),
            (Some("SUBMITTED"), Some(1))
        );

        // Approver 1 cannot decide twice; approver 2's valid signature approves.
        assert_eq!(
            post(&approver_1, claims(&profiles[0]), approve.clone(), false)
                .await
                .0,
            StatusCode::CONFLICT
        );
        let second = post(
            &approver_2,
            decisions(&profiles[0]),
            attempt(sign(&key_2, &text_2), claim_2["issued_at"].clone()),
            true,
        )
        .await;
        assert_eq!(second.0, StatusCode::CREATED);
        assert_eq!(
            (
                second.1["status"].as_str(),
                second.1["approval_count"].as_i64()
            ),
            (Some("APPROVED"), Some(2))
        );
        let (_, detail) =
            detail_response(&app, &editor, &format!("{base}/{}/1", profiles[0])).await;
        assert_eq!(detail["status"], "APPROVED");
        assert!(detail["decided_at"].is_string());

        // One rejection ends the other revision.
        let (_, claim_r) = post(
            &approver_2,
            claims(&profiles[1]),
            json!({"decision":"reject"}),
            false,
        )
        .await;
        let text_r = claim_r["claim"].as_str().unwrap().to_owned();
        assert!(text_r.contains(";decision=reject;"));
        let rejected = post(&approver_2, decisions(&profiles[1]), json!({"decision":"reject", "issued_at":claim_r["issued_at"], "signature_der_base64":sign(&key_2, &text_r)}), true).await;
        assert_eq!(rejected.1["status"], "REJECTED");
        assert_eq!(
            post(&approver_1, claims(&profiles[1]), approve, false)
                .await
                .0,
            StatusCode::CONFLICT
        );
    }

    /// Activation and retirement against PostgreSQL (migration 0024). CI
    /// seeds the operator grant and CA E's declared capabilities in
    /// tests/management_profile_decision_api_seed.sql.
    #[tokio::test]
    async fn approved_revisions_activate_one_at_a_time_and_retire() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let (Ok(reader_url), Ok(writer_url)) = (
            env::var("TRUST_API_TEST_DATABASE_URL"),
            env::var("TRUST_API_WRITER_TEST_DATABASE_URL"),
        ) else {
            eprintln!("SKIP: profile activation needs TRUST_API_TEST_DATABASE_URL and TRUST_API_WRITER_TEST_DATABASE_URL; CI sets both");
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"activation-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("activation-test".into());
        const CA: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let token = |sub: &str, roles: serde_json::Value| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles, "ca_ids":[CA]}),
                &signer,
            )
            .unwrap()
        };
        let editor = token(
            "operator",
            json!(["trust-profile-editor", "trust-ca-reader"]),
        );
        let approvers = [
            (
                token("approver-http-1", json!(["trust-policy-approver"])),
                SigningKey::from_slice(&[0x11; 32]).unwrap(),
            ),
            (
                token("approver-http-2", json!(["trust-policy-approver"])),
                SigningKey::from_slice(&[0x22; 32]).unwrap(),
            ),
        ];
        let operator = token("operator-http", json!(["trust-ca-operator"]));
        let approver_as_operator = token("approver-http-1", json!(["trust-ca-operator"]));
        let app = router(AppState {
            verifier,
            database_url: reader_url,
            writer_database_url: Some(writer_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
        });
        let post = |token: &str, path: String, body: serde_json::Value, key: bool| {
            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json");
            if key {
                request = request.header("idempotency-key", random_uuid().to_string());
            }
            let request = request.body(Body::from(body.to_string())).unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body)
                        .unwrap_or(serde_json::Value::Null),
                )
            }
        };
        let base = format!("/v1/cas/{CA}/profile-drafts");
        // Records, submits and approves the next revision; returns its digest.
        let approved = |profile: String, suite: &'static str| {
            let (editor, base, approvers, post) =
                (editor.clone(), base.clone(), approvers.clone(), post);
            async move {
                let (status, draft) = post(
                    &editor,
                    base.clone(),
                    json!({"profile_id":profile, "display_name":"Activation",
                    "policy_version":"v1", "max_validity_days":90, "max_dns_sans":5,
                    "proposed_dns_zones":["lab.invalid"], "proposed_signature_suites":[suite]}),
                    true,
                )
                .await;
                assert_eq!(status, StatusCode::CREATED);
                let revision = draft["revision"].as_i64().unwrap();
                let digest = draft["snapshot_sha256"].as_str().unwrap().to_owned();
                assert_eq!(
                    post(
                        &editor,
                        format!("{base}/{profile}/{revision}/submission"),
                        json!({"snapshot_sha256":digest}),
                        true
                    )
                    .await
                    .0,
                    StatusCode::CREATED
                );
                for (token, key) in &approvers {
                    let (_, claim) = post(
                        token,
                        format!("{base}/{profile}/{revision}/decision-claims"),
                        json!({"decision":"approve"}),
                        false,
                    )
                    .await;
                    let text = claim["claim"].as_str().unwrap().to_owned();
                    let signature: Signature = key.sign(text.as_bytes());
                    let body = json!({"decision":"approve", "issued_at":claim["issued_at"],
                        "signature_der_base64": base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())});
                    assert_eq!(
                        post(
                            token,
                            format!("{base}/{profile}/{revision}/decisions"),
                            body,
                            true
                        )
                        .await
                        .0,
                        StatusCode::CREATED
                    );
                }
                (revision, digest)
            }
        };
        let profile = format!("act-{}", &random_uuid().simple().to_string()[..12]);
        let (first, first_digest) = approved(profile.clone(), "ecdsa-p256-sha256").await;
        let (second, second_digest) = approved(profile.clone(), "ecdsa-p256-sha256").await;
        let activate = |revision: i64| format!("{base}/{profile}/{revision}/activation");
        let retire = |revision: i64| format!("{base}/{profile}/{revision}/retirement");

        // Refusals: no operator role, an approver of the revision holding the
        // operator role, an altered digest, a declared suite outside the
        // catalogue (rolled back by the API).
        assert_eq!(
            post(
                &editor,
                activate(first),
                json!({"snapshot_sha256":first_digest}),
                true
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                &approver_as_operator,
                activate(first),
                json!({"snapshot_sha256":first_digest}),
                true
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                &operator,
                activate(first),
                json!({"snapshot_sha256":"0".repeat(64)}),
                true
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let uncatalogued = format!("cat-{}", &random_uuid().simple().to_string()[..12]);
        let (cat_revision, cat_digest) = approved(uncatalogued.clone(), "p256-sha256").await;
        assert_eq!(
            post(
                &operator,
                format!("{base}/{uncatalogued}/{cat_revision}/activation"),
                json!({"snapshot_sha256":cat_digest}),
                true
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let (_, detail) = detail_response(
            &app,
            &editor,
            &format!("{base}/{uncatalogued}/{cat_revision}"),
        )
        .await;
        assert_eq!(detail["status"], "APPROVED");

        // Activate revision 1, replay, then revision 2 supersedes it.
        let key = random_uuid().to_string();
        let activate_with = |revision: i64, digest: &str, key: &str| {
            let request = Request::builder()
                .method("POST")
                .uri(activate(revision))
                .header("authorization", format!("Bearer {operator}"))
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(json!({"snapshot_sha256":digest}).to_string()))
                .unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                )
            }
        };
        let (status, body) = activate_with(first, &first_digest, &key).await;
        assert_eq!(
            (status, body["status"].as_str()),
            (StatusCode::CREATED, Some("ACTIVE"))
        );
        assert!(body["superseded_revision"].is_null());
        assert_eq!(
            activate_with(first, &first_digest, &key).await.0,
            StatusCode::OK
        );
        let (status, body) = post(
            &operator,
            activate(second),
            json!({"snapshot_sha256":second_digest}),
            true,
        )
        .await;
        assert_eq!(
            (status, body["superseded_revision"].as_i64()),
            (StatusCode::CREATED, Some(first))
        );
        assert_eq!(
            post(
                &operator,
                activate(first),
                json!({"snapshot_sha256":first_digest}),
                true
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (_, detail) =
            detail_response(&app, &editor, &format!("{base}/{profile}/{first}")).await;
        assert_eq!(detail["status"], "SUPERSEDED");
        assert!(detail["ended_at"].is_string());

        // Retirement: only the active revision, once.
        assert_eq!(
            post(&operator, retire(first), json!({}), true).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(&operator, retire(second), json!({"reason":"x"}), true)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let (status, body) = post(&operator, retire(second), json!({}), true).await;
        assert_eq!(
            (status, body["status"].as_str()),
            (StatusCode::CREATED, Some("RETIRED"))
        );
        assert_eq!(
            post(&operator, retire(second), json!({}), true).await.0,
            StatusCode::CONFLICT
        );
        let (_, detail) =
            detail_response(&app, &editor, &format!("{base}/{profile}/{second}")).await;
        assert_eq!(detail["status"], "RETIRED");
        assert!(detail["activated_at"].is_string() && detail["ended_at"].is_string());
    }

    /// CA proposals and issuer certificates against PostgreSQL (migration
    /// 0026). CI seeds the `ca-admin-http` platform grant in
    /// tests/management_profile_decision_api_seed.sql.
    #[tokio::test]
    async fn ca_proposals_record_one_verified_root_per_key() {
        use trust_pki_core::lab_ca::EphemeralLabCa;
        use x509_cert::der::{pem::LineEnding as PemLineEnding, Encode, EncodePem};
        let (Ok(reader_url), Ok(writer_url)) = (
            env::var("TRUST_API_TEST_DATABASE_URL"),
            env::var("TRUST_API_WRITER_TEST_DATABASE_URL"),
        ) else {
            eprintln!("SKIP: CA proposals need TRUST_API_TEST_DATABASE_URL and TRUST_API_WRITER_TEST_DATABASE_URL; CI sets both");
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"ca-proposal-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("ca-proposal-test".into());
        let token = |sub: &str, roles: serde_json::Value| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles, "ca_ids":[]}),
                &signer,
            )
            .unwrap()
        };
        let admin = token("ca-admin-http", json!(["trust-ca-administrator"]));
        // The token role without the server-side platform grant.
        let ungranted = token("operator", json!(["trust-ca-administrator"]));
        let reader = token(
            "ca-admin-http",
            json!(["trust-ca-reader", "trust-ca-operator"]),
        );
        let app = router(AppState {
            verifier,
            database_url: reader_url,
            writer_database_url: Some(writer_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
        });
        let send = |method: &'static str,
                    token: &str,
                    path: String,
                    body: Option<serde_json::Value>,
                    key: Option<String>| {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"));
            if body.is_some() {
                request = request.header("content-type", "application/json");
            }
            if let Some(key) = key {
                request = request.header("idempotency-key", key);
            }
            let request = request
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                .unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body)
                        .unwrap_or(serde_json::Value::Null),
                )
            }
        };
        let key = || Some(random_uuid().to_string());
        let proposal = |name: &str| json!({"display_name":name, "policy_version":"v1", "suite_id":"ecdsa-p256-sha256"});
        const CN: &str = "Sovereign Trust Lab Root";

        // Proposal refusals: no role, no grant, an unproposable suite,
        // unknown fields, no idempotency key.
        let path = || "/v1/ca-proposals".to_owned();
        assert_eq!(
            send("POST", &reader, path(), Some(proposal(CN)), key())
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send("POST", &ungranted, path(), Some(proposal(CN)), key())
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send("POST", &admin, path(),
                Some(json!({"display_name":CN, "policy_version":"v1", "suite_id":"ecdsa-p384-sha384"})), key())
            .await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                path(),
                Some(
                    json!({"display_name":CN, "policy_version":"v1", "suite_id":"ecdsa-p256-sha256",
                            "ca_id":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"})
                ),
                key()
            )
            .await
            .0,
            // A chosen identifier that names an existing CA is refused.
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                path(),
                Some(
                    json!({"display_name":CN, "policy_version":"v1", "suite_id":"ecdsa-p256-sha256",
                            "ca_id":"not-a-uuid"})
                ),
                key()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let chosen = random_uuid().to_string();
        let (status, chosen_proposal) = send(
            "POST",
            &admin,
            path(),
            Some(json!({"display_name":"Chosen Root", "policy_version":"v1",
                        "suite_id":"ecdsa-p256-sha256", "ca_id": chosen})),
            key(),
        )
        .await;
        assert_eq!(
            (status, chosen_proposal["ca_id"].as_str()),
            (StatusCode::CREATED, Some(chosen.as_str()))
        );
        assert_eq!(
            send("POST", &admin, path(), Some(proposal(CN)), None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );

        // A proposal, and its replay.
        let operation = key();
        let (status, first) = send(
            "POST",
            &admin,
            path(),
            Some(proposal(CN)),
            operation.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(first["lifecycle_status"], "PROPOSED");
        let ca = first["ca_id"].as_str().unwrap().to_owned();
        let (status, replay) = send(
            "POST",
            &admin,
            path(),
            Some(proposal(CN)),
            operation.clone(),
        )
        .await;
        assert_eq!(
            (status, &replay["ca_id"]),
            (StatusCode::OK, &first["ca_id"])
        );
        assert_eq!(
            send("POST", &admin, path(), Some(proposal("Other")), operation)
                .await
                .0,
            StatusCode::CONFLICT
        );

        // Certificate refusals: each leaves the proposal PROPOSED.
        let certificate = |pem: String| Some(json!({"certificate_pem": pem}));
        let register = |ca: &str| format!("/v1/ca-proposals/{ca}/issuer-certificate");
        let vector = |name: &str| {
            std::fs::read_to_string(format!(
                "{}/testdata/ca-root/{name}.crt",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
        };
        let (status, refused) = send(
            "POST",
            &admin,
            register(&ca),
            certificate(vector("openssl-p384-root")),
            key(),
        )
        .await;
        assert_eq!(
            (status, refused["reason"].as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, Some("KeyAlgorithm"))
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                register(&ca),
                certificate(vector("openssl-p256-not-ca")),
                key()
            )
            .await
            .1["reason"],
            "BasicConstraints"
        );
        // A valid root whose CN is not the proposed name (refused by the database).
        assert_eq!(
            send(
                "POST",
                &admin,
                register(&ca),
                certificate(vector("openssl-p256-root")),
                key()
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let root = EphemeralLabCa::new(CN).unwrap().root_certificate().clone();
        let pem = root.to_pem(PemLineEnding::LF).unwrap();
        let mut tampered = root.clone();
        tampered.signature = EphemeralLabCa::new(CN)
            .unwrap()
            .root_certificate()
            .signature
            .clone();
        let (status, refused) = send(
            "POST",
            &admin,
            register(&ca),
            certificate(tampered.to_pem(PemLineEnding::LF).unwrap()),
            key(),
        )
        .await;
        assert_eq!(
            (status, refused["reason"].as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, Some("Signature"))
        );
        assert_eq!(
            send(
                "POST",
                &ungranted,
                register(&ca),
                certificate(pem.clone()),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                register(&random_uuid().to_string()),
                certificate(pem.clone()),
                key()
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );

        // Registration, replay, then no second certificate and no key reuse.
        let operation = key();
        let (status, registered) = send(
            "POST",
            &admin,
            register(&ca),
            certificate(pem.clone()),
            operation.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(registered["lifecycle_status"], "KEY_ATTESTED");
        let fingerprint = <sha2::Sha256 as sha2::Digest>::digest(root.to_der().unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(registered["certificate_sha256"], fingerprint.as_str());
        assert_eq!(
            send(
                "POST",
                &admin,
                register(&ca),
                certificate(pem.clone()),
                operation
            )
            .await
            .0,
            StatusCode::OK
        );
        let other_root = EphemeralLabCa::new(CN)
            .unwrap()
            .root_certificate()
            .to_pem(PemLineEnding::LF)
            .unwrap();
        assert_eq!(
            send(
                "POST",
                &admin,
                register(&ca),
                certificate(other_root),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (_, second) = send("POST", &admin, path(), Some(proposal(CN)), key()).await;
        assert_eq!(
            send(
                "POST",
                &admin,
                register(second["ca_id"].as_str().unwrap()),
                certificate(pem),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );

        // Listing: administrators with the grant see both; the role without
        // the grant sees nothing; other roles are refused.
        let (status, listed) = send("GET", &admin, path(), None, None).await;
        assert_eq!(status, StatusCode::OK);
        let states: HashSet<(String, String)> = listed
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["ca_id"] == ca.as_str() || item["ca_id"] == second["ca_id"])
            .map(|item| {
                (
                    item["ca_id"].as_str().unwrap().to_owned(),
                    item["lifecycle_status"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            states,
            HashSet::from([
                (ca.clone(), "KEY_ATTESTED".to_owned()),
                (
                    second["ca_id"].as_str().unwrap().to_owned(),
                    "PROPOSED".to_owned()
                ),
            ])
        );
        let (status, hidden) = send("GET", &ungranted, path(), None, None).await;
        assert_eq!((status, hidden), (StatusCode::OK, json!([])));
        assert_eq!(
            send("GET", &reader, path(), None, None).await.0,
            StatusCode::FORBIDDEN
        );
        // A proposal is not a CA.
        assert_eq!(
            send("GET", &reader, format!("/v1/cas/{ca}"), None, None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }

    /// Signed CA approval and activation against PostgreSQL (migration
    /// 0027). CI seeds the CA approvers and their keys ([0x44; 32],
    /// [0x55; 32]) in tests/management_profile_decision_api_seed.sql.
    #[tokio::test]
    async fn ca_proposals_are_approved_by_two_signers_then_activated() {
        use trust_pki_core::lab_ca::EphemeralLabCa;
        use x509_cert::der::{pem::LineEnding as PemLineEnding, Encode, EncodePem};
        let (Ok(reader_url), Ok(writer_url)) = (
            env::var("TRUST_API_TEST_DATABASE_URL"),
            env::var("TRUST_API_WRITER_TEST_DATABASE_URL"),
        ) else {
            eprintln!("SKIP: CA approval and activation need TRUST_API_TEST_DATABASE_URL and TRUST_API_WRITER_TEST_DATABASE_URL; CI sets both");
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"ca-activation-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("ca-activation-test".into());
        let token = |sub: &str, roles: serde_json::Value| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles, "ca_ids":[]}),
                &signer,
            )
            .unwrap()
        };
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let admin = token("ca-admin-http", json!(["trust-ca-administrator"]));
        let approver_1 = token(
            "ca-approver-http-1",
            json!(["trust-ca-approver", "trust-ca-administrator"]),
        );
        let approver_2 = token("ca-approver-http-2", json!(["trust-ca-approver"]));
        // A profile approver: the CA approver role without the platform grant.
        let profile_approver = token("approver-http-1", json!(["trust-ca-approver"]));
        let key_1 = SigningKey::from_slice(&[0x44; 32]).unwrap();
        let key_2 = SigningKey::from_slice(&[0x55; 32]).unwrap();
        // The token role without the server-side platform grant.
        let ungranted = token("operator", json!(["trust-ca-administrator"]));
        let app = router(AppState {
            verifier,
            database_url: reader_url,
            writer_database_url: Some(writer_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
        });
        let send = |method: &'static str,
                    token: &str,
                    path: String,
                    body: Option<serde_json::Value>,
                    key: Option<String>| {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"));
            if body.is_some() {
                request = request.header("content-type", "application/json");
            }
            if let Some(key) = key {
                request = request.header("idempotency-key", key);
            }
            let request = request
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                .unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body)
                        .unwrap_or(serde_json::Value::Null),
                )
            }
        };
        let key = || Some(random_uuid().to_string());
        const CN: &str = "Sovereign Trust Lab Root";
        let root = EphemeralLabCa::new(CN).unwrap().root_certificate().clone();
        let fingerprint = <sha2::Sha256 as sha2::Digest>::digest(root.to_der().unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let (status, proposal) = send(
            "POST",
            &admin,
            "/v1/ca-proposals".into(),
            Some(json!({"display_name":CN, "policy_version":"v1", "suite_id":"ecdsa-p256-sha256"})),
            key(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let ca = proposal["ca_id"].as_str().unwrap().to_owned();
        let base = format!("/v1/ca-proposals/{ca}");
        let claim_for = |token: String, decision: &'static str| {
            let (send, base) = (send, base.clone());
            async move {
                send(
                    "POST",
                    &token,
                    format!("{base}/decision-claims"),
                    Some(json!({"decision":decision})),
                    None,
                )
                .await
            }
        };
        // Before the certificate, nothing can be decided.
        assert_eq!(
            claim_for(approver_2.clone(), "approve").await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/issuer-certificate"),
                Some(json!({"certificate_pem": root.to_pem(PemLineEnding::LF).unwrap()})),
                key()
            )
            .await
            .0,
            StatusCode::CREATED
        );

        // Claim refusals: no approver role, the role without the grant.
        assert_eq!(
            claim_for(admin.clone(), "approve").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            claim_for(profile_approver.clone(), "approve").await.0,
            StatusCode::FORBIDDEN
        );
        let decide = |token: String,
                      signer: SigningKey,
                      claim: serde_json::Value,
                      operation: Option<String>| {
            let (send, base) = (send, base.clone());
            async move {
                let text = claim["claim"].as_str().unwrap().to_owned();
                let signature: Signature = signer.sign(text.as_bytes());
                send("POST", &token, format!("{base}/decisions"),
                    Some(json!({"decision": claim["decision"], "issued_at": claim["issued_at"],
                        "signature_der_base64": base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())})),
                    operation).await
            }
        };

        // The first approval, its replay, and a second decision by the same approver.
        let (status, claim_1) = claim_for(approver_1.clone(), "approve").await;
        assert_eq!(status, StatusCode::OK);
        assert!(claim_1["claim"]
            .as_str()
            .unwrap()
            .contains(&format!("certificate_sha256={fingerprint}")));
        let operation = key();
        let (status, first) = decide(
            approver_1.clone(),
            key_1.clone(),
            claim_1.clone(),
            operation.clone(),
        )
        .await;
        assert_eq!(
            (
                status,
                first["lifecycle_status"].as_str(),
                first["approval_count"].as_i64()
            ),
            (StatusCode::CREATED, Some("KEY_ATTESTED"), Some(1))
        );
        assert_eq!(
            decide(approver_1.clone(), key_1.clone(), claim_1, operation)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            claim_for(approver_1.clone(), "reject").await.0,
            StatusCode::CONFLICT
        );

        // A signature by another key, or over other text, is refused and leaves nothing.
        let (_, claim_2) = claim_for(approver_2.clone(), "approve").await;
        assert_eq!(
            decide(approver_2.clone(), key_1.clone(), claim_2.clone(), key())
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut altered = claim_2.clone();
        altered["claim"] = json!(claim_2["claim"]
            .as_str()
            .unwrap()
            .replace("decision=approve", "decision=reject"));
        assert_eq!(
            decide(approver_2.clone(), key_2.clone(), altered, key())
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        // Activation before approval is refused.
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                Some(json!({"certificate_sha256": fingerprint})),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (status, second) = decide(approver_2.clone(), key_2.clone(), claim_2, key()).await;
        assert_eq!(
            (
                status,
                second["lifecycle_status"].as_str(),
                second["approval_count"].as_i64()
            ),
            (StatusCode::CREATED, Some("APPROVED"), Some(2))
        );

        // Activation: an approver holding the administrator role, another
        // digest, unknown fields; then the activation and its replay.
        let activation = |digest: String| Some(json!({"certificate_sha256": digest}));
        assert_eq!(
            send(
                "POST",
                &approver_1,
                format!("{base}/activation"),
                activation(fingerprint.clone()),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                activation("0".repeat(64)),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                Some(json!({"certificate_sha256": fingerprint, "suite_id": "ecdsa-p384-sha384"})),
                key()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                "POST",
                &ungranted,
                format!("{base}/activation"),
                activation(fingerprint.clone()),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let operation = key();
        let (status, active) = send(
            "POST",
            &admin,
            format!("{base}/activation"),
            activation(fingerprint.clone()),
            operation.clone(),
        )
        .await;
        assert_eq!(
            (
                status,
                active["lifecycle_status"].as_str(),
                active["suite_id"].as_str()
            ),
            (
                StatusCode::CREATED,
                Some("ACTIVE"),
                Some("ecdsa-p256-sha256")
            )
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                activation(fingerprint.clone()),
                operation
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                activation(fingerprint),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );

        // Approvers list proposals too; the activated one shows its record.
        let (status, listed) =
            send("GET", &approver_2, "/v1/ca-proposals".into(), None, None).await;
        assert_eq!(status, StatusCode::OK);
        let item = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["ca_id"] == ca.as_str())
            .unwrap()
            .clone();
        assert_eq!(
            (
                item["lifecycle_status"].as_str(),
                item["approval_count"].as_i64()
            ),
            (Some("ACTIVE"), Some(2))
        );
        assert!(item["decided_at"].is_string() && item["activated_at"].is_string());
    }

    /// Certificate applications against PostgreSQL (migration 0029). The CA
    /// is created through the API; the owner login provisions the grants and
    /// the active profile revision, as only the owner can.
    #[tokio::test]
    async fn certificate_applications_need_a_verified_csr_an_active_profile_and_an_officer() {
        use trust_pki_core::lab_ca::EphemeralLabCa;
        use x509_cert::der::{pem::LineEnding as PemLineEnding, Encode, EncodePem};
        let (Ok(reader_url), Ok(writer_url), Ok(owner_url)) = (
            env::var("TRUST_API_TEST_DATABASE_URL"),
            env::var("TRUST_API_WRITER_TEST_DATABASE_URL"),
            env::var("TRUST_API_OWNER_TEST_DATABASE_URL"),
        ) else {
            eprintln!("SKIP: certificate applications need TRUST_API_TEST_DATABASE_URL, TRUST_API_WRITER_TEST_DATABASE_URL and TRUST_API_OWNER_TEST_DATABASE_URL (the owner provisions grants and the active profile); CI sets all three");
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"application-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("application-test".into());
        let token = |sub: &str, roles: serde_json::Value| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles, "ca_ids":[]}),
                &signer,
            )
            .unwrap()
        };
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let admin = token("ca-admin-http", json!(["trust-ca-administrator"]));
        let approver_1 = token(
            "ca-approver-http-1",
            json!(["trust-ca-approver", "trust-ca-administrator"]),
        );
        let approver_2 = token("ca-approver-http-2", json!(["trust-ca-approver"]));
        // A profile approver: the CA approver role without the platform grant.
        let profile_approver = token("approver-http-1", json!(["trust-ca-approver"]));
        let key_1 = SigningKey::from_slice(&[0x44; 32]).unwrap();
        let key_2 = SigningKey::from_slice(&[0x55; 32]).unwrap();
        // The token role without the server-side platform grant.
        let ungranted = token("operator", json!(["trust-ca-administrator"]));
        let app = router(AppState {
            verifier,
            database_url: reader_url,
            writer_database_url: Some(writer_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
        });
        let send = |method: &'static str,
                    token: &str,
                    path: String,
                    body: Option<serde_json::Value>,
                    key: Option<String>| {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"));
            if body.is_some() {
                request = request.header("content-type", "application/json");
            }
            if let Some(key) = key {
                request = request.header("idempotency-key", key);
            }
            let request = request
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                .unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body)
                        .unwrap_or(serde_json::Value::Null),
                )
            }
        };
        let key = || Some(random_uuid().to_string());
        const CN: &str = "Sovereign Trust Lab Root";
        let root = EphemeralLabCa::new(CN).unwrap().root_certificate().clone();
        let fingerprint = <sha2::Sha256 as sha2::Digest>::digest(root.to_der().unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let (status, proposal) = send(
            "POST",
            &admin,
            "/v1/ca-proposals".into(),
            Some(json!({"display_name":CN, "policy_version":"v1", "suite_id":"ecdsa-p256-sha256"})),
            key(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let ca = proposal["ca_id"].as_str().unwrap().to_owned();
        let base = format!("/v1/ca-proposals/{ca}");
        let claim_for = |token: String, decision: &'static str| {
            let (send, base) = (send, base.clone());
            async move {
                send(
                    "POST",
                    &token,
                    format!("{base}/decision-claims"),
                    Some(json!({"decision":decision})),
                    None,
                )
                .await
            }
        };
        // Before the certificate, nothing can be decided.
        assert_eq!(
            claim_for(approver_2.clone(), "approve").await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/issuer-certificate"),
                Some(json!({"certificate_pem": root.to_pem(PemLineEnding::LF).unwrap()})),
                key()
            )
            .await
            .0,
            StatusCode::CREATED
        );

        // Claim refusals: no approver role, the role without the grant.
        assert_eq!(
            claim_for(admin.clone(), "approve").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            claim_for(profile_approver.clone(), "approve").await.0,
            StatusCode::FORBIDDEN
        );
        let decide = |token: String,
                      signer: SigningKey,
                      claim: serde_json::Value,
                      operation: Option<String>| {
            let (send, base) = (send, base.clone());
            async move {
                let text = claim["claim"].as_str().unwrap().to_owned();
                let signature: Signature = signer.sign(text.as_bytes());
                send("POST", &token, format!("{base}/decisions"),
                    Some(json!({"decision": claim["decision"], "issued_at": claim["issued_at"],
                        "signature_der_base64": base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())})),
                    operation).await
            }
        };

        // The first approval, its replay, and a second decision by the same approver.
        let (status, claim_1) = claim_for(approver_1.clone(), "approve").await;
        assert_eq!(status, StatusCode::OK);
        assert!(claim_1["claim"]
            .as_str()
            .unwrap()
            .contains(&format!("certificate_sha256={fingerprint}")));
        let operation = key();
        let (status, first) = decide(
            approver_1.clone(),
            key_1.clone(),
            claim_1.clone(),
            operation.clone(),
        )
        .await;
        assert_eq!(
            (
                status,
                first["lifecycle_status"].as_str(),
                first["approval_count"].as_i64()
            ),
            (StatusCode::CREATED, Some("KEY_ATTESTED"), Some(1))
        );
        assert_eq!(
            decide(approver_1.clone(), key_1.clone(), claim_1, operation)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            claim_for(approver_1.clone(), "reject").await.0,
            StatusCode::CONFLICT
        );

        // A signature by another key, or over other text, is refused and leaves nothing.
        let (_, claim_2) = claim_for(approver_2.clone(), "approve").await;
        assert_eq!(
            decide(approver_2.clone(), key_1.clone(), claim_2.clone(), key())
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut altered = claim_2.clone();
        altered["claim"] = json!(claim_2["claim"]
            .as_str()
            .unwrap()
            .replace("decision=approve", "decision=reject"));
        assert_eq!(
            decide(approver_2.clone(), key_2.clone(), altered, key())
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        // Activation before approval is refused.
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                Some(json!({"certificate_sha256": fingerprint})),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (status, second) = decide(approver_2.clone(), key_2.clone(), claim_2, key()).await;
        assert_eq!(
            (
                status,
                second["lifecycle_status"].as_str(),
                second["approval_count"].as_i64()
            ),
            (StatusCode::CREATED, Some("APPROVED"), Some(2))
        );

        // Activation: an approver holding the administrator role, another
        // digest, unknown fields; then the activation and its replay.
        let activation = |digest: String| Some(json!({"certificate_sha256": digest}));
        assert_eq!(
            send(
                "POST",
                &approver_1,
                format!("{base}/activation"),
                activation(fingerprint.clone()),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                activation("0".repeat(64)),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                Some(json!({"certificate_sha256": fingerprint, "suite_id": "ecdsa-p384-sha384"})),
                key()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                "POST",
                &ungranted,
                format!("{base}/activation"),
                activation(fingerprint.clone()),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let operation = key();
        let (status, active) = send(
            "POST",
            &admin,
            format!("{base}/activation"),
            activation(fingerprint.clone()),
            operation.clone(),
        )
        .await;
        assert_eq!(
            (
                status,
                active["lifecycle_status"].as_str(),
                active["suite_id"].as_str()
            ),
            (
                StatusCode::CREATED,
                Some("ACTIVE"),
                Some("ecdsa-p256-sha256")
            )
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                activation(fingerprint.clone()),
                operation
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                activation(fingerprint),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );

        // The owner provisions what only the owner can: grants on the new CA
        // and an active profile revision (zones lab.invalid, 3 names, 90 days).
        let owner_ca = ca.clone();
        query_db(owner_url, Arc::new(Semaphore::new(1)), move |db| {
            db.batch_execute(&format!(
                "INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
                    ('https://issuer.example.test', 'requester-http', '{owner_ca}'),
                    ('https://issuer.example.test', 'officer-http', '{owner_ca}');
                 INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
                    ('https://issuer.example.test', 'requester-http', '{owner_ca}', 'certificate-requester'),
                    ('https://issuer.example.test', 'requester-http', '{owner_ca}', 'registration-officer'),
                    ('https://issuer.example.test', 'officer-http', '{owner_ca}', 'registration-officer');
                 INSERT INTO certificate_profile_draft (ca_id, profile_id, revision, display_name, policy_version,
                    max_validity_days, max_dns_sans, proposed_dns_zones, proposed_signature_suites, created_by)
                 VALUES ('{owner_ca}', 'server', 1, 'Server', 'v1', 90, 3, ARRAY['lab.invalid'],
                    ARRAY['ecdsa-p256-sha256'], 'owner-fixture');
                 WITH e AS (INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id,
                    revision, snapshot_sha256, policy_version, actor_issuer, actor_subject)
                    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'draft.submitted', '{owner_ca}', 'server',
                    1, profile_draft_snapshot_sha256('{owner_ca}', 'server', 1), 'v1', 'owner', 'owner') RETURNING event_id)
                 INSERT INTO certificate_profile_submission (ca_id, profile_id, revision, snapshot_sha256, event_id)
                    SELECT '{owner_ca}', 'server', 1, profile_draft_snapshot_sha256('{owner_ca}', 'server', 1), event_id FROM e;
                 WITH e AS (INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id,
                    revision, snapshot_sha256, policy_version, actor_issuer, actor_subject)
                    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'revision.activation', '{owner_ca}',
                    'server', 1, profile_draft_snapshot_sha256('{owner_ca}', 'server', 1), 'v1', 'owner', 'owner')
                    RETURNING event_id)
                 INSERT INTO certificate_profile_active (ca_id, profile_id, revision, activated_event_id)
                    SELECT '{owner_ca}', 'server', 1, event_id FROM e;"
            ))
        })
        .await
        .unwrap();
        let scoped = |sub: &str, roles: serde_json::Value| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles, "ca_ids":[ca.clone()]}),
                &signer,
            )
            .unwrap()
        };
        let requester = scoped(
            "requester-http",
            json!([
                "trust-certificate-requester",
                "trust-ca-reader",
                "trust-registration-officer"
            ]),
        );
        let officer = scoped(
            "officer-http",
            json!(["trust-registration-officer", "trust-ca-reader"]),
        );
        let outsider = scoped("ca-admin-http", json!(["trust-certificate-requester"]));

        // A CSR for `cn` signed by a fresh P-256 key; `forged` signs with another key.
        let csr = |cn: &str, forged: bool| {
            use x509_cert::{
                der::{asn1::BitString, DecodePem as _, EncodePem},
                request::{CertReq, CertReqInfo},
                spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned},
            };
            let key = SigningKey::random(&mut rand::rngs::OsRng);
            let point = key.verifying_key().to_encoded_point(false);
            let info = CertReqInfo {
                version: x509_cert::request::Version::V1,
                subject: format!("CN={cn}").parse().unwrap(),
                public_key: SubjectPublicKeyInfoOwned {
                    algorithm: AlgorithmIdentifierOwned {
                        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                        parameters: Some(x509_cert::der::Any::from(ObjectIdentifier::new_unwrap(
                            "1.2.840.10045.3.1.7",
                        ))),
                    },
                    subject_public_key: BitString::from_bytes(point.as_bytes()).unwrap(),
                },
                attributes: Default::default(),
            };
            let signing = if forged {
                SigningKey::random(&mut rand::rngs::OsRng)
            } else {
                key.clone()
            };
            let signature: Signature = signing.sign(&info.to_der().unwrap());
            let request = CertReq {
                info,
                algorithm: AlgorithmIdentifierOwned {
                    oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
                    parameters: None,
                },
                signature: BitString::from_bytes(signature.to_der().as_bytes()).unwrap(),
            };
            let pem = request.to_pem(PemLineEnding::LF).unwrap();
            assert!(CertReq::from_pem(&pem).is_ok());
            pem
        };
        let apps = format!("/v1/cas/{ca}/certificate-applications");
        let application = |pem: String, cn: &str, names: serde_json::Value, days: i64| {
            Some(
                json!({"profile_id":"server", "csr_pem": pem, "common_name": cn, "dns_names": names, "validity_days": days}),
            )
        };

        // Refusals: no role or grant, malformed request, CSR checks, policy.
        let good = csr("www.lab.invalid", false);
        assert_eq!(
            send(
                "POST",
                &outsider,
                apps.clone(),
                application(
                    good.clone(),
                    "www.lab.invalid",
                    json!(["www.lab.invalid"]),
                    30
                ),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                "POST",
                &officer,
                apps.clone(),
                application(
                    good.clone(),
                    "www.lab.invalid",
                    json!(["www.lab.invalid"]),
                    30
                ),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                "POST",
                &requester,
                apps.clone(),
                application(
                    good.clone(),
                    "www.lab.invalid",
                    json!(["www.lab.invalid", "*.lab.invalid"]),
                    30
                ),
                key()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                "POST",
                &requester,
                apps.clone(),
                application(
                    good.clone(),
                    "api.lab.invalid",
                    json!(["www.lab.invalid"]),
                    30
                ),
                key()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let (status, refused) = send(
            "POST",
            &requester,
            apps.clone(),
            application(
                good.clone(),
                "api.lab.invalid",
                json!(["api.lab.invalid"]),
                30,
            ),
            key(),
        )
        .await;
        assert_eq!(
            (status, refused["reason"].as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, Some("SubjectMismatch"))
        );
        let (status, refused) = send(
            "POST",
            &requester,
            apps.clone(),
            application(
                csr("www.lab.invalid", true),
                "www.lab.invalid",
                json!(["www.lab.invalid"]),
                30,
            ),
            key(),
        )
        .await;
        assert_eq!(
            (status, refused["reason"].as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, Some("InvalidSignature"))
        );
        let root_pem = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/ca-root/openssl-p256-root.crt"
        ))
        .unwrap();
        assert_eq!(
            send(
                "POST",
                &requester,
                apps.clone(),
                application(root_pem, "www.lab.invalid", json!(["www.lab.invalid"]), 30),
                key()
            )
            .await
            .1["reason"],
            "Encoding"
        );
        assert_eq!(
            send(
                "POST",
                &requester,
                apps.clone(),
                application(
                    good.clone(),
                    "www.example.com",
                    json!(["www.example.com"]),
                    30
                ),
                key()
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            send(
                "POST",
                &requester,
                apps.clone(),
                application(
                    good.clone(),
                    "www.lab.invalid",
                    json!(["www.lab.invalid"]),
                    91
                ),
                key()
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(send("POST", &requester, apps.clone(),
            Some(json!({"profile_id":"mail", "csr_pem": good.clone(), "common_name": "www.lab.invalid", "dns_names": ["www.lab.invalid"], "validity_days": 30})),
            key()).await.0, StatusCode::NOT_FOUND);

        // Submission and replay; the requester cannot decide; the officer does, once.
        let operation = key();
        let body = application(
            good.clone(),
            "www.lab.invalid",
            json!(["www.lab.invalid", "api.lab.invalid"]),
            90,
        );
        let (status, submitted) = send(
            "POST",
            &requester,
            apps.clone(),
            body.clone(),
            operation.clone(),
        )
        .await;
        assert_eq!(
            (
                status,
                submitted["status"].as_str(),
                submitted["revision"].as_i64()
            ),
            (StatusCode::CREATED, Some("SUBMITTED"), Some(1))
        );
        let id = submitted["application_id"].as_str().unwrap().to_owned();
        let (status, replay) = send("POST", &requester, apps.clone(), body, operation).await;
        assert_eq!(
            (status, replay["application_id"].as_str()),
            (StatusCode::OK, Some(id.as_str()))
        );
        let decision = format!("{apps}/{id}/decision");
        let decide =
            |decision: &str| Some(json!({"decision": decision, "reason": "names checked"}));
        assert_eq!(
            send(
                "POST",
                &requester,
                decision.clone(),
                decide("approve"),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send("POST", &officer, decision.clone(), decide("sign"), key())
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let (status, approved) =
            send("POST", &officer, decision.clone(), decide("approve"), key()).await;
        assert_eq!(
            (status, approved["status"].as_str()),
            (StatusCode::CREATED, Some("APPROVED"))
        );
        assert_eq!(
            send("POST", &officer, decision, decide("reject"), key())
                .await
                .0,
            StatusCode::CONFLICT
        );

        // Readers of the CA list applications without actor identities.
        let (status, listed) = send("GET", &officer, apps.clone(), None, None).await;
        assert_eq!(status, StatusCode::OK);
        let item = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["application_id"] == id.as_str())
            .unwrap()
            .clone();
        assert_eq!(
            (item["status"].as_str(), item["subject_cn"].as_str()),
            (Some("APPROVED"), Some("www.lab.invalid"))
        );
        assert!(item.get("requested_by").is_none() && item.get("actor_subject").is_none());

        // A suspended CA takes no application.
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("/v1/ca-proposals/{ca}/suspension"),
                Some(json!({"reason":"test"})),
                key()
            )
            .await
            .0,
            StatusCode::CREATED
        );
        assert_eq!(
            send(
                "POST",
                &requester,
                apps,
                application(
                    csr("x.lab.invalid", false),
                    "x.lab.invalid",
                    json!(["x.lab.invalid"]),
                    30
                ),
                key()
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    /// Issuance of approved applications (migration 0030), then their
    /// revocation and CRLs (migration 0031), against PostgreSQL, with the
    /// real laboratory signer in-process on a Unix socket and
    /// its own restricted login (TRUST_API_SIGNER_TEST_DATABASE_URL).
    #[tokio::test]
    async fn approved_applications_are_issued_revoked_and_published_through_the_lab_signer() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use x509_cert::der::{pem::LineEnding as PemLineEnding, DecodePem, Encode, EncodePem};
        let (Ok(reader_url), Ok(writer_url), Ok(owner_url), Ok(signer_url)) = (
            env::var("TRUST_API_TEST_DATABASE_URL"),
            env::var("TRUST_API_WRITER_TEST_DATABASE_URL"),
            env::var("TRUST_API_OWNER_TEST_DATABASE_URL"),
            env::var("TRUST_API_SIGNER_TEST_DATABASE_URL"),
        ) else {
            eprintln!("SKIP: issuance needs TRUST_API_TEST_DATABASE_URL, TRUST_API_WRITER_TEST_DATABASE_URL, TRUST_API_OWNER_TEST_DATABASE_URL and TRUST_API_SIGNER_TEST_DATABASE_URL; CI sets all four");
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"issuance-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("issuance-test".into());
        let token = |sub: &str, roles: serde_json::Value, ca_ids: serde_json::Value| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles,
                        "ca_ids":ca_ids}),
                &signer,
            )
            .unwrap()
        };
        let admin = token(
            "ca-admin-http",
            json!(["trust-ca-administrator"]),
            json!([]),
        );
        let approvers = [
            (
                token(
                    "ca-approver-http-1",
                    json!(["trust-ca-approver"]),
                    json!([]),
                ),
                SigningKey::from_slice(&[0x44; 32]).unwrap(),
            ),
            (
                token(
                    "ca-approver-http-2",
                    json!(["trust-ca-approver"]),
                    json!([]),
                ),
                SigningKey::from_slice(&[0x55; 32]).unwrap(),
            ),
        ];
        let key_dir = std::env::temp_dir().join(format!("trust-signer-test-{}", random_uuid()));
        std::fs::create_dir_all(&key_dir).unwrap();
        let socket = key_dir.join("signer.sock");
        let app = router(AppState {
            verifier,
            database_url: reader_url,
            writer_database_url: Some(writer_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: Some(socket.clone()),
        });
        let send =
            |method: &'static str, token: &str, path: String, body: Option<serde_json::Value>| {
                let mut request = Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"));
                if body.is_some() {
                    request = request
                        .header("content-type", "application/json")
                        .header("idempotency-key", random_uuid().to_string());
                }
                let request = request
                    .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                    .unwrap();
                let app = app.clone();
                async move {
                    let response = app.oneshot(request).await.unwrap();
                    let status = response.status();
                    let body = response.into_body().collect().await.unwrap().to_bytes();
                    (
                        status,
                        serde_json::from_slice::<serde_json::Value>(&body)
                            .unwrap_or(serde_json::Value::Null),
                    )
                }
            };

        // A CA whose key the lab signer reads, activated by two approvers.
        const CN: &str = "Sovereign Trust Issuance Test Root";
        let ca_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let root = lab_root(CN, &ca_key);
        let key_file = key_dir.join("ca.pem");
        std::fs::write(
            &key_file,
            ca_key
                .to_sec1_pem(p256::pkcs8::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let fingerprint = hex_bytes(&<sha2::Sha256 as sha2::Digest>::digest(
            root.to_der().unwrap(),
        ));
        let (status, proposal) = send(
            "POST",
            &admin,
            "/v1/ca-proposals".into(),
            Some(json!({"display_name":CN, "policy_version":"v1", "suite_id":"ecdsa-p256-sha256"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let ca = proposal["ca_id"].as_str().unwrap().to_owned();
        let base = format!("/v1/ca-proposals/{ca}");
        let (status, _) = send(
            "POST",
            &admin,
            format!("{base}/issuer-certificate"),
            Some(json!({"certificate_pem": root.to_pem(PemLineEnding::LF).unwrap()})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        for (approver, approver_key) in &approvers {
            let (status, claim) = send(
                "POST",
                approver,
                format!("{base}/decision-claims"),
                Some(json!({"decision":"approve"})),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let signature: Signature =
                approver_key.sign(claim["claim"].as_str().unwrap().as_bytes());
            let (status, _) = send("POST", approver, format!("{base}/decisions"),
                Some(json!({"decision": claim["decision"], "issued_at": claim["issued_at"],
                    "signature_der_base64": base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())})))
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let (status, _) = send(
            "POST",
            &admin,
            format!("{base}/activation"),
            Some(json!({"certificate_sha256": fingerprint})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // The owner provisions the grants and the active revision.
        let owner_ca = ca.clone();
        query_db(owner_url.clone(), Arc::new(Semaphore::new(1)), move |db| {
            db.batch_execute(&format!(
                "INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
                    ('https://issuer.example.test', 'requester-http', '{owner_ca}'),
                    ('https://issuer.example.test', 'officer-http', '{owner_ca}');
                 INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
                    ('https://issuer.example.test', 'requester-http', '{owner_ca}', 'certificate-requester'),
                    ('https://issuer.example.test', 'officer-http', '{owner_ca}', 'registration-officer');
                 INSERT INTO certificate_profile_draft (ca_id, profile_id, revision, display_name, policy_version,
                    max_validity_days, max_dns_sans, proposed_dns_zones, proposed_signature_suites, created_by)
                 VALUES ('{owner_ca}', 'server', 1, 'Server', 'v1', 90, 3, ARRAY['lab.invalid'],
                    ARRAY['ecdsa-p256-sha256'], 'owner-fixture');
                 WITH e AS (INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id,
                    revision, snapshot_sha256, policy_version, actor_issuer, actor_subject)
                    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'draft.submitted', '{owner_ca}', 'server',
                    1, profile_draft_snapshot_sha256('{owner_ca}', 'server', 1), 'v1', 'owner', 'owner') RETURNING event_id)
                 INSERT INTO certificate_profile_submission (ca_id, profile_id, revision, snapshot_sha256, event_id)
                    SELECT '{owner_ca}', 'server', 1, profile_draft_snapshot_sha256('{owner_ca}', 'server', 1), event_id FROM e;
                 WITH e AS (INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id,
                    revision, snapshot_sha256, policy_version, actor_issuer, actor_subject)
                    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'revision.activation', '{owner_ca}',
                    'server', 1, profile_draft_snapshot_sha256('{owner_ca}', 'server', 1), 'v1', 'owner', 'owner')
                    RETURNING event_id)
                 INSERT INTO certificate_profile_active (ca_id, profile_id, revision, activated_event_id)
                    SELECT '{owner_ca}', 'server', 1, event_id FROM e;
                 INSERT INTO ca_crl_distribution_point (ca_id, base_url)
                    VALUES ('{owner_ca}', 'http://crl.lab.invalid:8081');"
            ))
        })
        .await
        .unwrap();
        let requester = token(
            "requester-http",
            json!(["trust-certificate-requester", "trust-ca-reader"]),
            json!([ca.clone()]),
        );
        let officer = token(
            "officer-http",
            json!(["trust-registration-officer", "trust-ca-reader"]),
            json!([ca.clone()]),
        );

        // The lab signer on `socket`, reading `key_file` with its own login;
        // a previous signer's socket file is replaced.
        let start_signer = |key_file: std::path::PathBuf| {
            let (socket, signer_url, ca) = (socket.clone(), signer_url.clone(), ca.clone());
            std::thread::spawn(move || {
                assert!(trust_lab_signer::service::restricted_login(&signer_url).unwrap());
                let _ = std::fs::remove_file(&socket);
                let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
                let config = trust_lab_signer::service::Config {
                    database_url: signer_url,
                    ca_id: ca,
                    key_file,
                };
                (listener, config)
            })
            .join()
            .map(|(listener, config)| {
                std::thread::spawn(move || trust_lab_signer::service::serve(&config, &listener))
            })
            .unwrap()
        };
        start_signer(key_file.clone());

        let apps = format!("/v1/cas/{ca}/certificate-applications");
        // An application for `cn` with a fresh subject key, approved or not.
        let submit = |cn: &'static str| {
            let (send, apps, requester) = (send, apps.clone(), requester.clone());
            async move {
                let subject_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
                let (status, submitted) = send(
                    "POST",
                    &requester,
                    apps,
                    Some(
                        json!({"profile_id":"server", "csr_pem": lab_csr(cn, &subject_key),
                                "common_name": cn, "dns_names": [cn, format!("www.{cn}")],
                                "validity_days": 30}),
                    ),
                )
                .await;
                assert_eq!(status, StatusCode::CREATED);
                (
                    submitted["application_id"].as_str().unwrap().to_owned(),
                    subject_key,
                )
            }
        };
        let approve = |id: String| {
            let (send, apps, officer) = (send, apps.clone(), officer.clone());
            async move {
                let (status, _) = send(
                    "POST",
                    &officer,
                    format!("{apps}/{id}/decision"),
                    Some(json!({"decision":"approve", "reason":"checked"})),
                )
                .await;
                assert_eq!(status, StatusCode::CREATED);
            }
        };
        let issue = |token: String, id: String| {
            let (send, apps) = (send, apps.clone());
            async move {
                send(
                    "POST",
                    &token,
                    format!("{apps}/{id}/issuance"),
                    Some(json!({})),
                )
                .await
            }
        };
        let listed = |id: String| {
            let (send, apps, officer) = (send, apps.clone(), officer.clone());
            async move {
                let (_, listed) = send("GET", &officer, apps, None).await;
                listed
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|item| item["application_id"] == id.as_str())
                    .unwrap()
                    .clone()
            }
        };

        // Not approved yet: no issuance, and no intent was recorded.
        let (first, subject_key) = submit("app.lab.invalid").await;
        assert_eq!(
            issue(requester.clone(), first.clone()).await.0,
            StatusCode::CONFLICT
        );
        // Unknown fields in the body are refused.
        assert_eq!(
            send(
                "POST",
                &officer,
                format!("{apps}/{first}/issuance"),
                Some(json!({"tbs":"x"}))
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        approve(first.clone()).await;

        // The requester collects their certificate.
        let (status, issued) = issue(requester.clone(), first.clone()).await;
        assert_eq!(
            (status, issued["status"].as_str()),
            (StatusCode::CREATED, Some("ISSUED"))
        );
        let certificate =
            x509_cert::Certificate::from_pem(issued["certificate_pem"].as_str().unwrap()).unwrap();
        let tbs = &certificate.tbs_certificate;
        assert_eq!(tbs.issuer, root.tbs_certificate.subject);
        assert_eq!(tbs.subject.to_string(), "CN=app.lab.invalid");
        assert_eq!(
            Some(hex_bytes(tbs.serial_number.as_bytes()).as_str()),
            issued["serial_hex"].as_str()
        );
        assert_eq!(
            tbs.subject_public_key_info.subject_public_key.raw_bytes(),
            lab_spki(&subject_key).subject_public_key.raw_bytes()
        );
        // It names where the CA's CRLs are published (migration 0032).
        let distribution_point =
            format!("http://crl.lab.invalid:8081/v1/public/crls/{ca}/latest.crl");
        {
            use x509_cert::ext::pkix::{
                crl::CrlDistributionPoints,
                name::{DistributionPointName, GeneralName},
            };
            let extension = tbs
                .extensions
                .as_ref()
                .unwrap()
                .iter()
                .find(|extension| extension.extn_id.to_string() == "2.5.29.31")
                .unwrap();
            let points = <CrlDistributionPoints as x509_cert::der::Decode>::from_der(
                extension.extn_value.as_bytes(),
            )
            .unwrap();
            let Some(DistributionPointName::FullName(names)) = &points.0[0].distribution_point
            else {
                panic!("no full name");
            };
            assert_eq!(
                names,
                &vec![GeneralName::UniformResourceIdentifier(
                    x509_cert::der::asn1::Ia5String::new(&distribution_point).unwrap()
                )]
            );
        }
        // The CA key signed it: checked with the CA's public key alone.
        {
            use p256::ecdsa::{signature::Verifier, VerifyingKey};
            let verifying = VerifyingKey::from(ca_key.public_key());
            let signature = Signature::from_der(certificate.signature.raw_bytes()).unwrap();
            assert!(verifying.verify(&tbs.to_der().unwrap(), &signature).is_ok());
        }
        // Issued once: asking again returns the record, never a new signature.
        let (status, again) = issue(officer.clone(), first.clone()).await;
        assert_eq!(
            (
                status,
                again["status"].as_str(),
                again["certificate_pem"].is_null()
            ),
            (StatusCode::OK, Some("ISSUED"), true)
        );
        let item = listed(first.clone()).await;
        assert_eq!(
            (item["status"].as_str(), item["certificate_sha256"].as_str()),
            (Some("ISSUED"), issued["certificate_sha256"].as_str())
        );

        // A signer holding another key refuses before claiming: for the API
        // the outcome is ambiguous, and the request is never signed again.
        let other_key = key_dir.join("other.pem");
        std::fs::write(
            &other_key,
            p256::SecretKey::random(&mut rand::rngs::OsRng)
                .to_sec1_pem(p256::pkcs8::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        start_signer(other_key.clone());
        let (second, _) = submit("other.lab.invalid").await;
        approve(second.clone()).await;
        let (status, uncertain) = issue(officer.clone(), second.clone()).await;
        assert_eq!(
            (status, uncertain["status"].as_str()),
            (StatusCode::BAD_GATEWAY, Some("RECONCILIATION_REQUIRED"))
        );
        start_signer(key_file.clone());
        assert_eq!(
            issue(officer.clone(), second.clone()).await.0,
            StatusCode::CONFLICT
        );
        let item = listed(second).await;
        assert_eq!(
            (
                item["status"].as_str(),
                item["certificate_sha256"].is_null()
            ),
            (Some("RECONCILIATION_REQUIRED"), true)
        );

        // A signer that answers with another key's signature: the API's own
        // verification refuses the certificate, which is never stored.
        let _ = std::fs::remove_file(&socket);
        let liar = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let lying = std::thread::spawn(move || {
            use std::io::{BufRead, Write};
            let (stream, _) = liar.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(&stream)
                .read_line(&mut line)
                .unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            let tbs = base64::engine::general_purpose::STANDARD
                .decode(request["tbs_der_base64"].as_str().unwrap())
                .unwrap();
            let signature: Signature = SigningKey::random(&mut rand::rngs::OsRng).sign(&tbs);
            writeln!(
                &stream,
                "{}",
                json!({"signature_der_base64":
                base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())})
            )
            .unwrap();
        });
        let (third, _) = submit("third.lab.invalid").await;
        approve(third.clone()).await;
        let (status, refused) = issue(officer.clone(), third.clone()).await;
        lying.join().unwrap();
        assert_eq!(
            (
                status,
                refused["status"].as_str(),
                refused["certificate_pem"].is_null()
            ),
            (
                StatusCode::BAD_GATEWAY,
                Some("RECONCILIATION_REQUIRED"),
                true
            )
        );
        let item = listed(third).await;
        assert_eq!(
            (
                item["status"].as_str(),
                item["certificate_sha256"].is_null()
            ),
            (Some("RECONCILIATION_REQUIRED"), true)
        );

        // Revocation and CRLs (migration 0031), with the real signer again.
        start_signer(key_file.clone());
        let crls = format!("/v1/cas/{ca}/crls");
        let crl_der = |pem: &str| {
            let (label, der) = x509_cert::der::pem::decode_vec(pem.as_bytes()).unwrap();
            assert_eq!(label, "X509 CRL");
            der
        };
        let verifying = p256::ecdsa::VerifyingKey::from(ca_key.public_key());
        let crl_verifies = |der: &[u8]| {
            use p256::ecdsa::signature::Verifier;
            let crl =
                <x509_cert::crl::CertificateList as x509_cert::der::Decode>::from_der(der).unwrap();
            let signature = Signature::from_der(crl.signature.raw_bytes()).unwrap();
            verifying
                .verify(&crl.tbs_cert_list.to_der().unwrap(), &signature)
                .is_ok()
        };
        // Nothing is public before the first CRL; renewal is due.
        let public = |path: String| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let status = response.status();
                let content_type = response
                    .headers()
                    .get("content-type")
                    .map(|value| value.to_str().unwrap().to_owned());
                let body = response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec();
                (status, content_type, body)
            }
        };
        let public_path = format!("/v1/public/crls/{ca}/latest.crl");
        assert_eq!(public(public_path.clone()).await.0, StatusCode::NOT_FOUND);
        let (_, status_before) =
            send("GET", &officer, format!("/v1/cas/{ca}/crl-status"), None).await;
        assert_eq!(
            (
                status_before["distribution_point"].as_str(),
                status_before["latest_crl_number"].is_null(),
                status_before["renewal_due"].as_bool()
            ),
            (Some(distribution_point.as_str()), true, Some(true))
        );
        // A requester does not publish; an officer publishes an empty CRL.
        assert_eq!(
            send("POST", &requester, crls.clone(), Some(json!({})))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (status, empty) = send("POST", &officer, crls.clone(), Some(json!({}))).await;
        assert_eq!(
            (
                status,
                empty["crl_number"].as_i64(),
                empty["entry_count"].as_u64()
            ),
            (StatusCode::CREATED, Some(1), Some(0))
        );
        assert!(crl_verifies(&crl_der(empty["crl_pem"].as_str().unwrap())));

        // The requester asks, with a reason from the closed list only; an
        // officer approves; the requester cannot decide.
        let revocations = format!("{apps}/{first}/revocation-requests");
        assert_eq!(
            send(
                "POST",
                &requester,
                revocations.clone(),
                Some(json!({"reason_code": 6, "reason": "on hold"}))
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let (status, requested) = send(
            "POST",
            &requester,
            revocations.clone(),
            Some(json!({"reason_code": 1, "reason": "key leaked"})),
        )
        .await;
        assert_eq!(
            (status, requested["status"].as_str()),
            (StatusCode::CREATED, Some("REVOCATION_REQUESTED"))
        );
        let decision = format!(
            "{revocations}/{}/decision",
            requested["revocation_id"].as_str().unwrap()
        );
        assert_eq!(
            send(
                "POST",
                &requester,
                decision.clone(),
                Some(json!({"decision": "approve", "reason": "self"}))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let (status, decided) = send(
            "POST",
            &officer,
            decision.clone(),
            Some(json!({"decision": "approve", "reason": "confirmed"})),
        )
        .await;
        assert_eq!(
            (
                status,
                decided["status"].as_str(),
                decided["revoked_at"].is_string()
            ),
            (StatusCode::CREATED, Some("REVOKED"), true)
        );
        assert_eq!(
            send(
                "POST",
                &officer,
                decision,
                Some(json!({"decision": "reject", "reason": "again"}))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let item = listed(first.clone()).await;
        assert_eq!(
            (
                item["status"].as_str(),
                item["revocation_reason_code"].as_i64()
            ),
            (Some("REVOKED"), Some(1))
        );

        // The next CRL lists it, under the CA key, with its reason.
        let (status, published) = send("POST", &officer, crls.clone(), Some(json!({}))).await;
        assert_eq!(
            (
                status,
                published["crl_number"].as_i64(),
                published["entry_count"].as_u64()
            ),
            (StatusCode::CREATED, Some(2), Some(1))
        );
        let der = crl_der(published["crl_pem"].as_str().unwrap());
        assert!(crl_verifies(&der));
        let crl =
            <x509_cert::crl::CertificateList as x509_cert::der::Decode>::from_der(&der).unwrap();
        let entries = crl.tbs_cert_list.revoked_certificates.unwrap();
        assert_eq!(
            hex_bytes(entries[0].serial_number.as_bytes()),
            issued["serial_hex"].as_str().unwrap()
        );
        assert_eq!(crl.tbs_cert_list.issuer, root.tbs_certificate.subject);

        // Anyone fetches the latest CRL, without a token; other paths are 404.
        let (status, content_type, public_der) = public(public_path.clone()).await;
        assert_eq!(
            (status, content_type.as_deref(), public_der == der),
            (StatusCode::OK, Some("application/pkix-crl"), true)
        );
        assert_eq!(
            public(format!("/v1/public/crls/{}/latest.crl", random_uuid()))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            public("/v1/public/crls/not-a-uuid/latest.crl".into())
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let (_, status_after) =
            send("GET", &officer, format!("/v1/cas/{ca}/crl-status"), None).await;
        assert_eq!(
            (
                status_after["latest_crl_number"].as_i64(),
                status_after["renewal_due"].as_bool(),
                status_after["expired"].as_bool()
            ),
            (Some(2), Some(false), Some(false))
        );
        // Readers list the CRLs and fetch the exact DER.
        let (_, list) = send("GET", &officer, crls.clone(), None).await;
        assert_eq!(
            list.as_array()
                .unwrap()
                .iter()
                .map(|item| item["crl_number"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        let fetched = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{crls}/2"))
                    .header("authorization", format!("Bearer {officer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            fetched.headers()["content-type"].to_str().unwrap(),
            "application/pkix-crl"
        );
        assert_eq!(
            fetched
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
            der
        );

        // The same key again returns the CRL's record without a new
        // signature; unknown fields are refused.
        let post_with_key = |path: String, body: serde_json::Value, key: String| {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {officer}"))
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body.to_string()))
                .unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default(),
                )
            }
        };
        let key = random_uuid().to_string();
        let (status, fifth) = post_with_key(crls.clone(), json!({}), key.clone()).await;
        assert_eq!(
            (status, fifth["crl_number"].as_i64()),
            (StatusCode::CREATED, Some(3))
        );
        let (status, again) = post_with_key(crls.clone(), json!({}), key).await;
        assert_eq!(
            (
                status,
                again["crl_number"].as_i64(),
                again["crl_pem"].is_null()
            ),
            (StatusCode::OK, Some(3), true)
        );
        assert_eq!(
            send(
                "POST",
                &officer,
                crls.clone(),
                Some(json!({"crl_number": 9}))
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );

        // A signer holding another key: ambiguous, recorded as such, never
        // sent again under the same key, and the next CRL takes a new number.
        start_signer(other_key);
        let key = random_uuid().to_string();
        let (status, uncertain) = post_with_key(crls.clone(), json!({}), key.clone()).await;
        assert_eq!(
            (
                status,
                uncertain["status"].as_str(),
                uncertain["crl_number"].as_i64()
            ),
            (
                StatusCode::BAD_GATEWAY,
                Some("RECONCILIATION_REQUIRED"),
                Some(4)
            )
        );
        start_signer(key_file.clone());
        assert_eq!(
            post_with_key(crls.clone(), json!({}), key).await.0,
            StatusCode::CONFLICT
        );
        let owner = owner_url.clone();
        let ca_for_owner = ca.clone();
        let outcomes = query_db(owner, Arc::new(Semaphore::new(1)), move |db| {
            db.query(
                "SELECT string_agg(crl_number || ':' || outcome, ',' ORDER BY crl_number) \
                 FROM crl_signing_intent WHERE ca_id = $1::text::uuid",
                &[&ca_for_owner],
            )
            .map(|rows| rows[0].get::<_, String>(0))
        })
        .await
        .unwrap();
        assert_eq!(
            outcomes,
            "1:PUBLISHED,2:PUBLISHED,3:PUBLISHED,4:RECONCILIATION_REQUIRED"
        );

        // A signer that answers with another key's signature: the API's own
        // verification refuses the CRL, which is never stored.
        let _ = std::fs::remove_file(&socket);
        let liar_url = signer_url.clone();
        let liar = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let lying = std::thread::spawn(move || {
            use std::io::{BufRead, Write};
            let (stream, _) = liar.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(&stream)
                .read_line(&mut line)
                .unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["kind"].as_str(), Some("crl"));
            let tbs = base64::engine::general_purpose::STANDARD
                .decode(request["tbs_der_base64"].as_str().unwrap())
                .unwrap();
            // A faulty signer: it claims the intent like the real one, then
            // signs with the wrong key.
            let mut db = postgres::Client::connect(&liar_url, postgres::NoTls).unwrap();
            db.execute(
                "SELECT claim_lab_crl_intent($1::text::uuid, $2)",
                &[
                    &request["intent_id"].as_str().unwrap(),
                    &<sha2::Sha256 as sha2::Digest>::digest(&tbs).to_vec(),
                ],
            )
            .unwrap();
            let signature: Signature = SigningKey::random(&mut rand::rngs::OsRng).sign(&tbs);
            writeln!(
                &stream,
                "{}",
                json!({"signature_der_base64":
                base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())})
            )
            .unwrap();
        });
        let (status, refused) = send("POST", &officer, crls.clone(), Some(json!({}))).await;
        lying.join().unwrap();
        assert_eq!(
            (
                status,
                refused["crl_number"].as_i64(),
                refused["crl_pem"].is_null()
            ),
            (StatusCode::BAD_GATEWAY, Some(5), true)
        );
        start_signer(key_file);
        let (status, next) = send("POST", &officer, crls.clone(), Some(json!({}))).await;
        assert_eq!(
            (
                status,
                next["crl_number"].as_i64(),
                next["entry_count"].as_u64()
            ),
            (StatusCode::CREATED, Some(6), Some(1))
        );
        let (_, list) = send("GET", &officer, crls.clone(), None).await;
        assert_eq!(
            list.as_array()
                .unwrap()
                .iter()
                .map(|item| item["crl_number"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![6, 3, 2, 1]
        );
        let _ = std::fs::remove_dir_all(key_dir);
    }

    /// Suspension, reactivation and retirement against PostgreSQL
    /// (migration 0028), with the seeded CA approvers of migration 0027.
    #[tokio::test]
    async fn activated_cas_are_suspended_then_reactivated_or_retired_with_two_signers() {
        use trust_pki_core::lab_ca::EphemeralLabCa;
        use x509_cert::der::{pem::LineEnding as PemLineEnding, Encode, EncodePem};
        let (Ok(reader_url), Ok(writer_url)) = (
            env::var("TRUST_API_TEST_DATABASE_URL"),
            env::var("TRUST_API_WRITER_TEST_DATABASE_URL"),
        ) else {
            eprintln!("SKIP: CA suspension and retirement need TRUST_API_TEST_DATABASE_URL and TRUST_API_WRITER_TEST_DATABASE_URL; CI sets both");
            return;
        };
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"ca-operation-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("ca-operation-test".into());
        let token = |sub: &str, roles: serde_json::Value| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles, "ca_ids":[]}),
                &signer,
            )
            .unwrap()
        };
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let admin = token("ca-admin-http", json!(["trust-ca-administrator"]));
        let approver_1 = token(
            "ca-approver-http-1",
            json!(["trust-ca-approver", "trust-ca-administrator"]),
        );
        let approver_2 = token("ca-approver-http-2", json!(["trust-ca-approver"]));
        // A profile approver: the CA approver role without the platform grant.
        let profile_approver = token("approver-http-1", json!(["trust-ca-approver"]));
        let key_1 = SigningKey::from_slice(&[0x44; 32]).unwrap();
        let key_2 = SigningKey::from_slice(&[0x55; 32]).unwrap();
        // The token role without the server-side platform grant.
        let ungranted = token("operator", json!(["trust-ca-administrator"]));
        let app = router(AppState {
            verifier,
            database_url: reader_url,
            writer_database_url: Some(writer_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
        });
        let send = |method: &'static str,
                    token: &str,
                    path: String,
                    body: Option<serde_json::Value>,
                    key: Option<String>| {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"));
            if body.is_some() {
                request = request.header("content-type", "application/json");
            }
            if let Some(key) = key {
                request = request.header("idempotency-key", key);
            }
            let request = request
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                .unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body)
                        .unwrap_or(serde_json::Value::Null),
                )
            }
        };
        let key = || Some(random_uuid().to_string());
        const CN: &str = "Sovereign Trust Lab Root";
        let root = EphemeralLabCa::new(CN).unwrap().root_certificate().clone();
        let fingerprint = <sha2::Sha256 as sha2::Digest>::digest(root.to_der().unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let (status, proposal) = send(
            "POST",
            &admin,
            "/v1/ca-proposals".into(),
            Some(json!({"display_name":CN, "policy_version":"v1", "suite_id":"ecdsa-p256-sha256"})),
            key(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let ca = proposal["ca_id"].as_str().unwrap().to_owned();
        let base = format!("/v1/ca-proposals/{ca}");
        let claim_for = |token: String, decision: &'static str| {
            let (send, base) = (send, base.clone());
            async move {
                send(
                    "POST",
                    &token,
                    format!("{base}/decision-claims"),
                    Some(json!({"decision":decision})),
                    None,
                )
                .await
            }
        };
        // Before the certificate, nothing can be decided.
        assert_eq!(
            claim_for(approver_2.clone(), "approve").await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/issuer-certificate"),
                Some(json!({"certificate_pem": root.to_pem(PemLineEnding::LF).unwrap()})),
                key()
            )
            .await
            .0,
            StatusCode::CREATED
        );

        // Claim refusals: no approver role, the role without the grant.
        assert_eq!(
            claim_for(admin.clone(), "approve").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            claim_for(profile_approver.clone(), "approve").await.0,
            StatusCode::FORBIDDEN
        );
        let decide = |token: String,
                      signer: SigningKey,
                      claim: serde_json::Value,
                      operation: Option<String>| {
            let (send, base) = (send, base.clone());
            async move {
                let text = claim["claim"].as_str().unwrap().to_owned();
                let signature: Signature = signer.sign(text.as_bytes());
                send("POST", &token, format!("{base}/decisions"),
                    Some(json!({"decision": claim["decision"], "issued_at": claim["issued_at"],
                        "signature_der_base64": base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())})),
                    operation).await
            }
        };

        // The first approval, its replay, and a second decision by the same approver.
        let (status, claim_1) = claim_for(approver_1.clone(), "approve").await;
        assert_eq!(status, StatusCode::OK);
        assert!(claim_1["claim"]
            .as_str()
            .unwrap()
            .contains(&format!("certificate_sha256={fingerprint}")));
        let operation = key();
        let (status, first) = decide(
            approver_1.clone(),
            key_1.clone(),
            claim_1.clone(),
            operation.clone(),
        )
        .await;
        assert_eq!(
            (
                status,
                first["lifecycle_status"].as_str(),
                first["approval_count"].as_i64()
            ),
            (StatusCode::CREATED, Some("KEY_ATTESTED"), Some(1))
        );
        assert_eq!(
            decide(approver_1.clone(), key_1.clone(), claim_1, operation)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            claim_for(approver_1.clone(), "reject").await.0,
            StatusCode::CONFLICT
        );

        // A signature by another key, or over other text, is refused and leaves nothing.
        let (_, claim_2) = claim_for(approver_2.clone(), "approve").await;
        assert_eq!(
            decide(approver_2.clone(), key_1.clone(), claim_2.clone(), key())
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut altered = claim_2.clone();
        altered["claim"] = json!(claim_2["claim"]
            .as_str()
            .unwrap()
            .replace("decision=approve", "decision=reject"));
        assert_eq!(
            decide(approver_2.clone(), key_2.clone(), altered, key())
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        // Activation before approval is refused.
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                Some(json!({"certificate_sha256": fingerprint})),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (status, second) = decide(approver_2.clone(), key_2.clone(), claim_2, key()).await;
        assert_eq!(
            (
                status,
                second["lifecycle_status"].as_str(),
                second["approval_count"].as_i64()
            ),
            (StatusCode::CREATED, Some("APPROVED"), Some(2))
        );

        // Activation: an approver holding the administrator role, another
        // digest, unknown fields; then the activation and its replay.
        let activation = |digest: String| Some(json!({"certificate_sha256": digest}));
        assert_eq!(
            send(
                "POST",
                &approver_1,
                format!("{base}/activation"),
                activation(fingerprint.clone()),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                activation("0".repeat(64)),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                Some(json!({"certificate_sha256": fingerprint, "suite_id": "ecdsa-p384-sha384"})),
                key()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                "POST",
                &ungranted,
                format!("{base}/activation"),
                activation(fingerprint.clone()),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let operation = key();
        let (status, active) = send(
            "POST",
            &admin,
            format!("{base}/activation"),
            activation(fingerprint.clone()),
            operation.clone(),
        )
        .await;
        assert_eq!(
            (
                status,
                active["lifecycle_status"].as_str(),
                active["suite_id"].as_str()
            ),
            (
                StatusCode::CREATED,
                Some("ACTIVE"),
                Some("ecdsa-p256-sha256")
            )
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                activation(fingerprint.clone()),
                operation
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/activation"),
                activation(fingerprint),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );

        // Suspension: only administrators, only from ACTIVE.
        let reason = |text: &str| Some(json!({"reason": text}));
        assert_eq!(
            send(
                "POST",
                &approver_2,
                format!("{base}/suspension"),
                reason("x"),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/suspension"),
                reason(" padded"),
                key()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let operation = key();
        let (status, suspended) = send(
            "POST",
            &admin,
            format!("{base}/suspension"),
            reason("key review"),
            operation.clone(),
        )
        .await;
        assert_eq!(
            (status, suspended["operational_state"].as_str()),
            (StatusCode::CREATED, Some("SUSPENDED"))
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/suspension"),
                reason("key review"),
                operation
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/suspension"),
                reason("again"),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );

        // A change is requested, approved by two signers, then applied.
        let changes = format!("{base}/change-requests");
        let change =
            |action: &str| Some(json!({"action": action, "reason": format!("lab {action}")}));
        assert_eq!(
            send("POST", &admin, changes.clone(), change("suspend"), key())
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let (status, requested) =
            send("POST", &admin, changes.clone(), change("reactivate"), key()).await;
        assert_eq!(
            (status, requested["from_state"].as_str()),
            (StatusCode::CREATED, Some("SUSPENDED"))
        );
        let request = format!("{changes}/{}", requested["request_id"].as_str().unwrap());
        assert_eq!(
            send("POST", &admin, changes.clone(), change("retire"), key())
                .await
                .0,
            StatusCode::CONFLICT
        );
        let approve = |token: String, signer: SigningKey, request: String| async move {
            let (status, claim) = send(
                "POST",
                &token,
                format!("{request}/decision-claims"),
                Some(json!({"decision":"approve"})),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let text = claim["claim"].as_str().unwrap().to_owned();
            assert!(text.starts_with("trust-platform/ca-change-decision/v1;decision=approve;"));
            let signature: Signature = signer.sign(text.as_bytes());
            send("POST", &token, format!("{request}/decisions"),
                    Some(json!({"decision":"approve", "issued_at": claim["issued_at"],
                        "signature_der_base64": base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())})),
                    Some(random_uuid().to_string())).await
        };
        // The requester cannot decide; another key's signature is refused.
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{request}/decision-claims"),
                Some(json!({"decision":"approve"})),
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            approve(approver_1.clone(), key_2.clone(), request.clone())
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let (status, first) = approve(approver_1.clone(), key_1.clone(), request.clone()).await;
        assert_eq!(
            (status, first["request_status"].as_str()),
            (StatusCode::CREATED, Some("OPEN"))
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{request}/application"),
                Some(json!({})),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (_, second) = approve(approver_2.clone(), key_2.clone(), request.clone()).await;
        assert_eq!(
            (
                second["request_status"].as_str(),
                second["approval_count"].as_i64()
            ),
            (Some("APPROVED"), Some(2))
        );
        // An approver holding the administrator role cannot apply it.
        assert_eq!(
            send(
                "POST",
                &approver_1,
                format!("{request}/application"),
                Some(json!({})),
                key()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let (status, applied) = send(
            "POST",
            &admin,
            format!("{request}/application"),
            Some(json!({})),
            key(),
        )
        .await;
        assert_eq!(
            (status, applied["operational_state"].as_str()),
            (StatusCode::CREATED, Some("ACTIVE"))
        );

        // Retirement from ACTIVE, then nothing more.
        let (_, requested) = send("POST", &admin, changes.clone(), change("retire"), key()).await;
        let request = format!("{changes}/{}", requested["request_id"].as_str().unwrap());
        approve(approver_1.clone(), key_1.clone(), request.clone()).await;
        approve(approver_2.clone(), key_2.clone(), request.clone()).await;
        let (status, retired) = send(
            "POST",
            &admin,
            format!("{request}/application"),
            Some(json!({})),
            key(),
        )
        .await;
        assert_eq!(
            (
                status,
                retired["operational_state"].as_str(),
                retired["retired_revisions"].as_i64()
            ),
            (StatusCode::CREATED, Some("RETIRED"), Some(0))
        );
        assert_eq!(
            send(
                "POST",
                &admin,
                format!("{base}/suspension"),
                reason("x"),
                key()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send("POST", &admin, changes.clone(), change("reactivate"), key())
                .await
                .0,
            StatusCode::CONFLICT
        );
        let (_, listed) = send("GET", &approver_2, "/v1/ca-proposals".into(), None, None).await;
        let item = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["ca_id"] == ca.as_str())
            .unwrap()
            .clone();
        assert_eq!(item["lifecycle_status"], "RETIRED");
        assert!(item["change_request_id"].is_null() && item["state_changed_at"].is_string());
    }

    /// A compromised writer path records a certificate the API would refuse
    /// (the database does not parse X.509): activation must still refuse it.
    /// It leaves that forged record behind, which lab_verify_ca_lifecycle
    /// reports, so it runs only on a separate disposable database seeded like
    /// the API test database: set TRUST_API_FORGERY_TEST_DATABASE_URL (reader
    /// login) and TRUST_API_FORGERY_WRITER_TEST_DATABASE_URL.
    #[tokio::test]
    async fn activation_reverifies_a_certificate_recorded_without_the_api() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let (Ok(reader_url), Ok(writer_url)) = (
            env::var("TRUST_API_FORGERY_TEST_DATABASE_URL"),
            env::var("TRUST_API_FORGERY_WRITER_TEST_DATABASE_URL"),
        ) else {
            eprintln!("SKIP: forged-certificate activation needs TRUST_API_FORGERY_TEST_DATABASE_URL and TRUST_API_FORGERY_WRITER_TEST_DATABASE_URL (a separate disposable database); not set in CI");
            return;
        };
        // The writer login, used directly as a compromised API would: an
        // RSA root (refused by the API's verifier) recorded as a P-256 one.
        let pem = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/ca-root/openssl-rsa-root.crt"
        ))
        .unwrap();
        let der = ca_certificate::certificate_der_from_pem(&pem).unwrap();
        let fingerprint: String = <sha2::Sha256 as sha2::Digest>::digest(&der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let name = "Trust Lab RSA Root".to_string();
        let ca = query_db(writer_url.clone(), Arc::new(Semaphore::new(1)), move |db| {
            let op1 = random_uuid().to_string();
            let op2 = random_uuid().to_string();
            let spki: Vec<u8> = <sha2::Sha256 as sha2::Digest>::digest(op2.as_bytes()).to_vec();
            let ca: String = db
                .query_one(
                    "SELECT ca_id::text FROM propose_ca_lab('https://issuer.example.test', 'ca-admin-http', \
                     NULL, $1, 'v1', 'ecdsa-p256-sha256', $2::text::uuid, decode(repeat('01', 32), 'hex'))",
                    &[&name, &op1],
                )?
                .get(0);
            db.execute(
                "SELECT register_ca_issuer_certificate_lab('https://issuer.example.test', 'ca-admin-http', \
                 $1::text::uuid, $2, $3, $4, now() - interval '1 hour', now() + interval '1 year', 'p256', \
                 $5::text::uuid, decode(repeat('02', 32), 'hex'))",
                &[&ca, &der, &spki, &name, &op2],
            )?;
            Ok(ca)
        })
        .await
        .unwrap();
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"forgery-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("forgery-test".into());
        let token = |sub: &str, roles: serde_json::Value| {
            let now = jsonwebtoken::get_current_timestamp();
            encode(
                &header,
                &json!({"iss":"https://issuer.example.test", "aud":"trust-api", "sub":sub,
                        "iat":now, "azp":"trust-console", "exp":now+120, "roles":roles, "ca_ids":[]}),
                &signer,
            )
            .unwrap()
        };
        let app = router(AppState {
            verifier,
            database_url: reader_url,
            writer_database_url: Some(writer_url),
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
        });
        let post = |token: String, path: String, body: serde_json::Value, key: bool| {
            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json");
            if key {
                request = request.header("idempotency-key", random_uuid().to_string());
            }
            let request = request.body(Body::from(body.to_string())).unwrap();
            let app = app.clone();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default(),
                )
            }
        };
        let base = format!("/v1/ca-proposals/{ca}");
        for (subject, scalar) in [("ca-approver-http-1", 0x44u8), ("ca-approver-http-2", 0x55)] {
            let approver = token(subject, json!(["trust-ca-approver"]));
            let (_, claim) = post(
                approver.clone(),
                format!("{base}/decision-claims"),
                json!({"decision":"approve"}),
                false,
            )
            .await;
            let text = claim["claim"].as_str().unwrap().to_owned();
            let signature: Signature = SigningKey::from_slice(&[scalar; 32])
                .unwrap()
                .sign(text.as_bytes());
            let (status, _) = post(approver, format!("{base}/decisions"),
                json!({"decision":"approve", "issued_at":claim["issued_at"],
                       "signature_der_base64": base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())}),
                true).await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let admin = token("ca-admin-http", json!(["trust-ca-administrator"]));
        let (status, _) = post(
            admin,
            format!("{base}/activation"),
            json!({"certificate_sha256": fingerprint}),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn lab_spki(key: &p256::SecretKey) -> x509_cert::spki::SubjectPublicKeyInfoOwned {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        x509_cert::spki::SubjectPublicKeyInfoOwned {
            algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: x509_cert::spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                parameters: Some(x509_cert::der::Any::from(
                    x509_cert::spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"),
                )),
            },
            subject_public_key: x509_cert::der::asn1::BitString::from_bytes(
                key.public_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap(),
        }
    }

    /// A root like scripts/lab/create-lab-root.sh makes, for a key the test holds.
    fn lab_root(cn: &str, key: &p256::SecretKey) -> x509_cert::Certificate {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use x509_cert::der::{asn1::OctetString, Encode};
        use x509_cert::ext::{
            pkix::{BasicConstraints, KeyUsage, KeyUsages},
            Extension,
        };
        let ecdsa = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: x509_cert::spki::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let name: x509_cert::name::Name = format!("CN={cn}").parse().unwrap();
        let spki = lab_spki(key);
        let key_id = {
            use sha2::Digest;
            let hash = sha2::Sha256::digest(spki.subject_public_key.as_bytes().unwrap());
            OctetString::new(&hash[..20]).unwrap().to_der().unwrap()
        };
        let extension = |oid: &str, critical: bool, der: Vec<u8>| Extension {
            extn_id: x509_cert::spki::ObjectIdentifier::new_unwrap(oid),
            critical,
            extn_value: OctetString::new(der).unwrap(),
        };
        let tbs = x509_cert::TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01]).unwrap(),
            signature: ecdsa.clone(),
            issuer: name.clone(),
            validity: x509_cert::time::Validity::from_now(std::time::Duration::from_secs(
                365 * 86400,
            ))
            .unwrap(),
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                extension(
                    "2.5.29.19",
                    true,
                    BasicConstraints {
                        ca: true,
                        path_len_constraint: None,
                    }
                    .to_der()
                    .unwrap(),
                ),
                extension(
                    "2.5.29.15",
                    true,
                    KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                        .to_der()
                        .unwrap(),
                ),
                extension("2.5.29.14", false, key_id),
            ]),
        };
        let signature: Signature = SigningKey::from(key.clone()).sign(&tbs.to_der().unwrap());
        x509_cert::Certificate {
            tbs_certificate: tbs,
            signature_algorithm: ecdsa,
            signature: x509_cert::der::asn1::BitString::from_bytes(signature.to_der().as_bytes())
                .unwrap(),
        }
    }

    /// A PKCS#10 CSR for `cn` signed by `key`, as OpenSSL makes one.
    fn lab_csr(cn: &str, key: &p256::SecretKey) -> String {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use x509_cert::der::{Encode, EncodePem};
        let info = x509_cert::request::CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: format!("CN={cn}").parse().unwrap(),
            public_key: lab_spki(key),
            attributes: Default::default(),
        };
        let signature: Signature = SigningKey::from(key.clone()).sign(&info.to_der().unwrap());
        x509_cert::request::CertReq {
            info,
            algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: x509_cert::spki::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
                parameters: None,
            },
            signature: x509_cert::der::asn1::BitString::from_bytes(signature.to_der().as_bytes())
                .unwrap(),
        }
        .to_pem(x509_cert::der::pem::LineEnding::LF)
        .unwrap()
    }

    /// A random (version 4) UUID from the test RNG; the crate builds uuid
    /// without its `v4` feature.
    fn random_uuid() -> uuid::Uuid {
        uuid::Builder::from_random_bytes(rand::random()).into_uuid()
    }

    async fn futures_join_all<F>(futures: impl Iterator<Item = F>) -> Vec<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let handles: Vec<_> = futures.map(tokio::spawn).collect();
        let mut outputs = Vec::new();
        for handle in handles {
            outputs.push(handle.await.unwrap());
        }
        outputs
    }

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

    #[test]
    fn history_cursor_time_checks_calendar_date() {
        let id = "11111111-1111-4111-8111-000000000001";
        assert!(parse_history_cursor(Some(format!("2028-02-29T00:00:00.000Z|{id}"))).is_ok());
        // Before the slices, an impossible date only compared as text; it now
        // anchors a timestamp, so it must be refused as a bad request.
        for time in ["2027-02-29T00:00:00.000Z", "0000-01-01T00:00:00.000Z"] {
            assert_eq!(
                parse_history_cursor(Some(format!("{time}|{id}"))),
                Err(StatusCode::BAD_REQUEST)
            );
        }
    }

    #[test]
    fn history_slices_partition_distances() {
        let slices = HistorySlices {
            window: "signed_at_window",
            select: String::new(),
            order: String::new(),
            params: Vec::new(),
            newest: true,
            anchor: "2026-10-30T12:00:00.000Z".into(),
            from_cursor: true,
        };
        let (sql, offsets) = slices.range(6, Some(0), Some(3_600));
        assert_eq!(
            sql,
            " AND signed_at_window <= $6::text::timestamp - $7::float8 * interval '1 second' \
             AND signed_at_window > $6::text::timestamp - $8::float8 * interval '1 second'"
        );
        assert_eq!(offsets, [0.0, 3_600.0]);
        let oldest = HistorySlices {
            newest: false,
            ..slices
        };
        let (sql, offsets) = oldest.range(4, None, Some(60));
        assert_eq!(
            sql,
            " AND signed_at_window < $4::text::timestamp + $5::float8 * interval '1 second'"
        );
        assert_eq!(offsets, [60.0]);
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
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
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
                "nbf":now-1, "iat":now, "azp":"trust-console", "exp":now+60, "roles":["trust-ca-reader"],
                "ca_ids":["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]
            }),
            &signer,
        )
        .unwrap();
        let app = router(AppState {
            verifier,
            database_url,
            writer_database_url: None,
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
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
                "nbf":now-1, "iat":now, "azp":"trust-console", "exp":now+60, "roles":["trust-ca-reader"],
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
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
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
                "nbf":now-1, "iat":now, "azp":"trust-console", "exp":now+60, "roles":["trust-ca-reader"],
                "ca_ids":ca_ids
            }),
            &signer,
        )
        .unwrap();
        let app = router(AppState {
            verifier,
            database_url,
            writer_database_url: None,
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
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
    /// Every id of a history listing, following `x-next-cursor` to the end.
    async fn all_history_ids(
        app: &Router,
        token: &str,
        base: &str,
        id_field: &str,
    ) -> (Vec<String>, usize) {
        let separator = if base.contains('?') { '&' } else { '?' };
        let mut ids = Vec::new();
        let mut pages = 0;
        let mut cursor: Option<String> = None;
        loop {
            let path = match &cursor {
                Some(cursor) => format!("{base}{separator}before={}", cursor.replace('|', "%7C")),
                None => base.to_owned(),
            };
            let (status, next, items) = history_page(app, token, &path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(items.len() <= HISTORY_PAGE_SIZE);
            pages += 1;
            ids.extend(
                items
                    .iter()
                    .map(|item| item[id_field].as_str().unwrap().to_owned()),
            );
            match next {
                Some(next) => cursor = Some(next),
                None => return (ids, pages),
            }
        }
    }

    #[tokio::test]
    async fn history_slices_read_every_row_in_order() {
        let database_url = match env::var("TRUST_API_WINDOW_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("SKIP: sliced-history PostgreSQL fixture not configured; CI runs this test with tests/management_history_window_seed.sql");
                return;
            }
        };
        const CA: &str = "abababab-0000-4000-8000-0000000000ab";
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"window-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("window-test".into());
        let now = jsonwebtoken::get_current_timestamp();
        let token = encode(
            &header,
            &json!({
                "iss":"https://issuer.example.test", "aud":"trust-api", "sub":"operator",
                "nbf":now-1, "iat":now, "azp":"trust-console", "exp":now+120, "roles":["trust-ca-reader"], "ca_ids":[CA]
            }),
            &signer,
        )
        .unwrap();
        let app = router(AppState {
            verifier,
            database_url: database_url.clone(),
            writer_database_url: None,
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
        });
        // The expected order is one unsliced statement through the same views,
        // as the reader login (the full scan the slices replace).
        let cases = [
            ("certificates", "", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 ORDER BY signed_at DESC, request_id DESC", 376),
            ("certificates", "?order=oldest", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 ORDER BY signed_at, request_id", 376),
            ("certificates", "?cn=needle-", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND subject_cn LIKE 'needle-%' ORDER BY signed_at DESC, request_id DESC", 22),
            ("certificates", "?cn=needle-&order=oldest", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND subject_cn LIKE 'needle-%' ORDER BY signed_at, request_id", 22),
            ("certificates", "?cn=WILD_%25", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND lower(subject_cn) LIKE 'wild\\_\\%%' ESCAPE '\\' ORDER BY signed_at DESC, request_id DESC", 16),
            ("certificates", "?cn=wild_", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND lower(subject_cn) LIKE 'wild\\_%' ESCAPE '\\' ORDER BY signed_at DESC, request_id DESC", 16),
            ("certificates", "?cn=wildx&order=oldest", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND lower(subject_cn) LIKE 'wildx%' ORDER BY signed_at, request_id", 12),
            ("certificates", "?san_dns=grp.lab.invalid", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND EXISTS (SELECT 1 FROM unnest(san_dns) AS e(name) WHERE lower(e.name) = 'grp.lab.invalid') ORDER BY signed_at DESC, request_id DESC", 151),
            ("certificates", "?san_dns=GRP.lab.INVALID&order=oldest", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND EXISTS (SELECT 1 FROM unnest(san_dns) AS e(name) WHERE lower(e.name) = 'grp.lab.invalid') ORDER BY signed_at, request_id", 151),
            ("certificates", "?san_dns=rare.lab.invalid", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND EXISTS (SELECT 1 FROM unnest(san_dns) AS e(name) WHERE lower(e.name) = 'rare.lab.invalid') ORDER BY signed_at DESC, request_id DESC", 11),
            ("certificates", "?san_dns=host-7.lab.invalid", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND EXISTS (SELECT 1 FROM unnest(san_dns) AS e(name) WHERE lower(e.name) = 'host-7.lab.invalid') ORDER BY signed_at DESC, request_id DESC", 1),
            ("certificates", "?san_dns=absent.lab.invalid", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND EXISTS (SELECT 1 FROM unnest(san_dns) AS e(name) WHERE lower(e.name) = 'absent.lab.invalid') ORDER BY signed_at DESC, request_id DESC", 0),
            ("certificates", "?cn=hay-&san_dns=grp.lab.invalid", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND subject_cn LIKE 'hay-%' AND EXISTS (SELECT 1 FROM unnest(san_dns) AS e(name) WHERE lower(e.name) = 'grp.lab.invalid') ORDER BY signed_at DESC, request_id DESC", 130),
            ("certificates", "?cn=needle-&san_dns=grp.lab.invalid", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND subject_cn LIKE 'needle-%' AND EXISTS (SELECT 1 FROM unnest(san_dns) AS e(name) WHERE lower(e.name) = 'grp.lab.invalid') ORDER BY signed_at DESC, request_id DESC", 9),
            ("certificates", "?cn=needle-&san_dns=grp.lab.invalid&order=oldest", "request_id", "SELECT request_id FROM management_certificate WHERE ca_id=$1 AND subject_cn LIKE 'needle-%' AND EXISTS (SELECT 1 FROM unnest(san_dns) AS e(name) WHERE lower(e.name) = 'grp.lab.invalid') ORDER BY signed_at, request_id", 9),
            ("audit", "", "event_id", "SELECT event_id FROM management_audit WHERE ca_id=$1 ORDER BY recorded_at DESC, event_id DESC", 376),
            ("audit", "?order=oldest", "event_id", "SELECT event_id FROM management_audit WHERE ca_id=$1 ORDER BY recorded_at, event_id", 376),
            ("audit", "?event_type=certificate.revoked", "event_id", "SELECT event_id FROM management_audit WHERE ca_id=$1 AND event_type='certificate.revoked' ORDER BY recorded_at DESC, event_id DESC", 22),
        ];
        let queries: Vec<&'static str> = cases.iter().map(|case| case.3).collect();
        let expected: Vec<Vec<String>> = tokio::task::spawn_blocking(move || {
            let mut db = Client::connect(&database_url, NoTls).unwrap();
            // The views filter by the declared principal (0021), as for the API.
            db.execute(
                "SELECT set_config('trust.reader_issuer', 'https://issuer.example.test', false), \
                 set_config('trust.reader_subject', 'operator', false)",
                &[],
            )
            .unwrap();
            queries
                .iter()
                .map(|query| {
                    db.query(*query, &[&CA])
                        .unwrap()
                        .iter()
                        .map(|row| row.get(0))
                        .collect()
                })
                .collect()
        })
        .await
        .unwrap();
        for ((suffix, query, id_field, _, count), expected) in cases.into_iter().zip(expected) {
            let base = format!("/v1/cas/{CA}/{suffix}{query}");
            let (ids, pages) = all_history_ids(&app, &token, &base, id_field).await;
            assert_eq!(
                expected.len(),
                count,
                "{base}: fixture not loaded as expected"
            );
            assert_eq!(ids, expected, "{base}");
            assert_eq!(pages, count.div_ceil(HISTORY_PAGE_SIZE).max(1), "{base}");
        }
    }

    #[test]
    fn ca_cursor_round_trips_long_escaped_name() {
        let ca = Ca {
            ca_id: "55555555-5555-4555-8555-000000000064".into(),
            parent_ca_id: None,
            display_name: "\n".repeat(255),
            policy_version: "v1".into(),
            created_at: "2026-10-01T12:00:00.000Z".into(),
            operational_state: None,
        };
        let cursor = encode_ca_cursor(&ca);
        assert!(cursor.len() <= 4096);
        let parsed = parse_ca_cursor(Some(cursor)).unwrap().unwrap();
        assert_eq!(parsed.display_name, ca.display_name);
        assert_eq!(parsed.ca_id, ca.ca_id);
    }
    #[test]
    fn reader_isolation_gate_checks_every_management_view() {
        let Ok(url) = env::var("TRUST_API_TEST_DATABASE_URL") else {
            return; // CI supplies a disposable PostgreSQL database with migration 0021.
        };
        let mut db = Client::connect(&url, NoTls).expect("restricted reader connection");
        assert!(reader_isolation_active(&mut db).expect("isolation gate"));
        for view in [
            "management_ca",
            "management_certificate",
            "management_audit",
            "management_reader_scope",
            "management_certificate_san",
            "management_history_bounds",
            "management_profile_draft",
        ] {
            db.batch_execute(&format!("CREATE TEMP VIEW {view} AS SELECT 1 AS canary"))
                .expect("create unfiltered canary view");
            assert!(
                !reader_isolation_active(&mut db).expect("isolation gate"),
                "gate accepted unfiltered {view}"
            );
            db.batch_execute(&format!("DROP VIEW pg_temp.{view}"))
                .expect("remove canary view");
        }
    }

    #[test]
    fn scope_rejects_other_and_invalid_ca() {
        let claims = Claims {
            iss: "https://issuer.example.test".into(),
            sub: "operator".into(),
            azp: "trust-console".into(),
            iat: 0,
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
        let verifier = OidcVerifier::from_jwks(
            "https://issuer.example.test",
            "trust-api",
            "trust-console",
            jwks,
        )
        .unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("http-test".into());
        let now = jsonwebtoken::get_current_timestamp();
        let mut claims = json!({
            "iss":"https://issuer.example.test", "aud":"trust-api", "sub":"operator",
            "nbf":now-1, "iat":now, "azp":"trust-console", "exp":now+60, "roles":[],
            "ca_ids":["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]
        });
        let database_url = env::var("TRUST_API_TEST_DATABASE_URL").unwrap_or_default();
        let state = AppState {
            verifier,
            database_url: database_url.clone(),
            writer_database_url: None,
            database_slots: Arc::new(Semaphore::new(MAX_DATABASE_REQUESTS)),
            http_data_slots: Arc::new(Semaphore::new(MAX_HTTP_DATA_REQUESTS)),
            readiness_slots: Arc::new(Semaphore::new(1)),
            readiness_cache: Arc::new(Mutex::new(ReadinessCache::default())),
            signer_socket: None,
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
            signer_socket: None,
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
        // A workload token of the same issuer, with the reader role and the
        // CA in scope, is not a human session: 401 before any database read.
        let mut workload = claims.clone();
        workload["azp"] = json!("trust-lab-workload");
        let workload_token = encode(&header, &workload, &signer).unwrap();
        for uri in [
            "/v1/cas",
            "/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/certificates",
        ] {
            let refused = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("authorization", format!("Bearer {workload_token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        }
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
